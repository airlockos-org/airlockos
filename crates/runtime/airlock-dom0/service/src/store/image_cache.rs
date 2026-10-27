//! Admit Nix-produced build artifacts only inside explicit image preparation commands.
//! Normal deployment and artifact transfer keep their source-tree and channel verification paths.

use super::fs::*;
use airlock_nix_core::artifact::cache::{self, Fragment, Index};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
struct Manifest {
    // Explicit build-time format, separate from runtime admission protocols.
    schema: String,
    // Independently built Nix outputs keyed by the package they represent.
    fragments: BTreeMap<String, PathBuf>,
    // Common indexes have no VM identity and may be reused by multiple views.
    indexes: Vec<PathBuf>,
}

#[derive(Clone)]
pub(super) struct CachedFragment {
    /// Trusted Nix build output; its bytes are checked as they enter the pool.
    pub(super) path: PathBuf,
    /// Logical source and canonical content identity produced by the packing implementation.
    pub(super) identity: Fragment,
}

struct CachedIndex {
    // Immutable file whose hash must match before and after copying it into a view.
    path: PathBuf,
    // Content and logical layout identity checked against the newly assembled pool map.
    identity: Index,
}

struct Cache {
    // Complete package union for this preparation operation; missing entries are errors.
    fragments: BTreeMap<String, CachedFragment>,
    // Logical layout identity deduplicates equal closures from different VM configurations.
    indexes: BTreeMap<String, CachedIndex>,
}

thread_local! {
    static CACHE: std::cell::RefCell<Option<Cache>> = const { std::cell::RefCell::new(None) };
}

/// Keep the explicit cache scoped to one image command, including error and unwind paths.
pub(super) fn with(
    path: Option<&Path>,
    operation: impl FnOnce() -> Result<Value>,
) -> Result<Value> {
    let cache = if let Some(path) = path {
        let manifest: Manifest = read(path)?;
        ensure!(
            manifest.schema == "airlock.image-cache.v1",
            "unsupported image cache manifest"
        );
        let mut fragments = BTreeMap::new();
        for (logical, directory) in manifest.fragments {
            let identity = cache::fragment(&directory, &logical)?;
            fragments.insert(
                logical,
                CachedFragment {
                    path: directory.join("object.tar"),
                    identity,
                },
            );
        }
        let mut indexes = BTreeMap::new();
        for directory in manifest.indexes {
            let identity = cache::index(&directory)?;
            let key = identity.layout_sha256.clone();
            let item = CachedIndex {
                path: directory.join("store.erofs"),
                identity,
            };
            if let Some(old) = indexes.insert(key, item) {
                ensure!(
                    old.identity.sha256 == cache::index(&directory)?.sha256,
                    "conflicting cached indexes"
                );
            }
        }
        Some(Cache { fragments, indexes })
    } else {
        None
    };
    struct Reset(
        // Restore an outer preparation context instead of leaking cached trust to another command.
        Option<Cache>,
    );

    impl Drop for Reset {
        fn drop(&mut self) {
            CACHE.set(self.0.take());
        }
    }

    let _reset = Reset(CACHE.replace(cache));
    operation()
}

/// Return a declared immutable fragment; a configured cache never silently repacks missing packages.
pub(super) fn fragment(logical: &str) -> Result<Option<CachedFragment>> {
    CACHE.with_borrow(|cache| {
        cache
            .as_ref()
            .map(|cache| {
                cache
                    .fragments
                    .get(logical)
                    .cloned()
                    .with_context(|| format!("image cache lacks package {logical}"))
            })
            .transpose()
    })
}

/// Match the actual pool layout and verify metadata bytes before publishing a cached common index.
pub(super) fn index(key: &str, destination: &Path) -> Result<bool> {
    CACHE.with_borrow(|cache| {
        let Some(cache) = cache else {
            return Ok(false);
        };
        let item = cache
            .indexes
            .get(key)
            .context("image cache lacks logical index")?;
        ensure!(
            hash(&item.path)? == item.identity.sha256,
            "cached image index checksum mismatch"
        );
        std::fs::copy(&item.path, destination)?;
        ensure!(
            hash(destination)? == item.identity.sha256,
            "cached image index changed during reuse"
        );
        Ok(true)
    })
}
