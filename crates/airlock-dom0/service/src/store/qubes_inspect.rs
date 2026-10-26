//! Native requests used by the upstream Qubes pool, volume and database adapters.
//! Qubes owns its objects; Rust owns view policy, filesystem work and lifecycle decisions.

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fs,
    io::Read,
    num::NonZeroU64,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use crate::storage_plugin::Stats;
pub(super) use crate::storage_plugin::{Definition, ViewKind};

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "kebab-case")]
enum Request {
    PoolRoot {
        // Upstream pool root; Rust validates and creates its filesystem namespace.
        root: PathBuf,
        // Setup creates the namespace; loading a persisted pool only normalizes it.
        create: bool,
    },
    VolumeConfig {
        // Qubes VM owning a newly synthesized volume identifier, if needed.
        domain: Option<airlock_nix_core::identity::GuestName>,
        // Primitive upstream fields before Airlock's immutable-volume normalization.
        config: Value,
        // Upstream source objects cannot cross JSON and are forbidden for this driver.
        has_source: bool,
    },
    VolumeLifecycle {
        // Native lifecycle request; Qubes retains only object and callback dispatch.
        #[serde(flatten)]
        request: super::qubes_volume::Request,
    },
    AuthorizeInstall {
        // Explicit consuming VM; must agree with the fresh locked snapshot.
        domain: airlock_nix_core::identity::GuestName,
        // Exact immutable pool definition requested by the coordinator.
        pool: Value,
        // Complete proposed pair, reclassified before any Qubes mutation.
        volumes: Vec<Value>,
        // Fresh objects read while the adapter holds Qubes' database lock.
        snapshot: Value,
        // Exact state previously inspected by the Rust storage coordinator.
        expected: Value,
    },
    VerifyInstalled {
        // Same consuming VM checked before installation.
        domain: airlock_nix_core::identity::GuestName,
        // Same checked immutable pool definition.
        pool: Value,
        // Same complete pair checked before installation.
        volumes: Vec<Value>,
        // Original writable identities and definitions retained before mutation.
        before: Value,
        // Fresh snapshot inspected before database publication.
        after: Value,
    },
    RequireStopped {
        // Upstream VM class checked again before its database is saved.
        klass: String,
        // Current libvirt state observed within the upstream object lifetime.
        running: bool,
        // Explicit state distinguishes halted from paused, crashed and unknown.
        power_state: String,
    },
    PoolStats {
        // Pool namespace whose allocated blocks are being counted without following links.
        root: PathBuf,
        // Capacity queries stay constant-time; allocation queries explicitly walk the pool.
        include_usage: bool,
    },
    VerifyVolume {
        // Exact persisted Qubes view configuration to check without changing it.
        #[serde(flatten)]
        definition: Definition,
    },
    VolumeStats {
        // Persisted view configuration, independent of whether its device is attached.
        #[serde(flatten)]
        definition: Definition,
        // Upstream configured size used until an image has been materialized.
        fallback_size: u64,
    },
}

pub(super) fn absolute(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && !path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir)),
        "storage inspection requires an absolute path"
    );
    Ok(())
}

pub(crate) fn verify(definition: &Definition) -> Result<()> {
    match definition.view_kind {
        ViewKind::MetadataImage => {
            let path = definition
                .view_path
                .as_deref()
                .context("missing view_path")?;
            absolute(path)?;
            let metadata = fs::metadata(path).context("missing airlock closure view image")?;
            ensure!(
                metadata.is_file() && metadata.permissions().mode() & 0o222 == 0,
                "airlock closure view image is writable or not a regular file"
            );
        }
        ViewKind::ErofsBlobMap => {
            let map = definition
                .blob_map_path
                .as_deref()
                .context("missing blob_map_path")?;
            absolute(map)?;
            ensure!(
                fs::metadata(map)?.is_file(),
                "missing airlock closure blob map"
            );
            ensure!(
                definition.blob_logical_size.is_some(),
                "missing blob_logical_size"
            );
        }
    }

    if let Some(path) = &definition.manifest_path {
        absolute(path)?;
        ensure!(
            fs::metadata(path)?.is_file(),
            "missing airlock generation manifest"
        );
    }
    Ok(())
}

pub(crate) fn pool_stats(root: &Path, include_usage: bool) -> Result<Stats> {
    absolute(root)?;
    if !root.try_exists()? {
        return Ok(Stats {
            size: 0,
            usage: Some(0),
        });
    }
    ensure!(
        fs::symlink_metadata(root)?.is_dir(),
        "storage pool root is not a real directory"
    );
    let stat = rustix::fs::statvfs(root)?;
    let capacity = stat
        .f_blocks
        .checked_mul(stat.f_frsize)
        .context("pool capacity overflow")?;
    if !include_usage {
        return Ok(Stats {
            size: capacity,
            usage: None,
        });
    }

    let mut usage = 0u64;
    let mut pending = vec![(root.to_owned(), 0usize)];
    let mut count = 0usize;

    while let Some((directory, depth)) = pending.pop() {
        ensure!(
            depth <= 128,
            "storage accounting exceeded directory depth limit"
        );
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let entry = entry?;
            count += 1;
            ensure!(
                count <= 1_000_000,
                "storage accounting exceeded entry limit"
            );
            let metadata = match fs::symlink_metadata(entry.path()) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            usage = usage
                .checked_add(
                    metadata
                        .blocks()
                        .checked_mul(512)
                        .context("allocated block overflow")?,
                )
                .context("pool usage overflow")?;
            if metadata.is_dir() {
                pending.push((entry.path(), depth + 1));
            }
        }
    }

    Ok(Stats {
        size: capacity,
        usage: Some(usage),
    })
}

pub(super) fn run() -> Result<Value> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 1024 * 1024,
        "Qubes storage query exceeds limit"
    );

    let request = airlock_nix_core::state::parse_json(&bytes, Path::new("<qubes-storage-query>"))?;
    execute(request)
}

/// Run validated storage policy for both native CLI and loaded Qubes plugins.
pub(super) fn execute(request: Value) -> Result<Value> {
    let request: Request = serde_json::from_value(request)?;
    match request {
        Request::PoolRoot { root, create } => Ok(json!({"root": pool_root(&root, create)?})),
        Request::VolumeConfig {
            domain,
            config,
            has_source,
        } => super::qubes_volume::normalize(domain.as_ref(), config, has_source),
        Request::VolumeLifecycle { request } => super::qubes_volume::execute(request),
        Request::AuthorizeInstall {
            domain,
            pool,
            volumes,
            snapshot,
            expected,
        } => super::domain::authorize_install(&domain, &pool, &volumes, &snapshot, &expected),
        Request::VerifyInstalled {
            domain,
            pool,
            volumes,
            before,
            after,
        } => {
            super::domain::verify_installed(&domain, &pool, &volumes, &before, &after)?;
            Ok(json!({}))
        }
        Request::RequireStopped {
            klass,
            running,
            power_state,
        } => {
            require_stopped(&klass, running, &power_state)?;
            Ok(json!({}))
        }
        Request::PoolStats {
            root,
            include_usage,
        } => Ok(serde_json::to_value(pool_stats(&root, include_usage)?)?),
        Request::VerifyVolume { definition } => {
            verify(&definition)?;
            Ok(json!({"valid":true}))
        }
        Request::VolumeStats {
            definition,
            fallback_size,
        } => Ok(serde_json::to_value(volume_stats(
            &definition,
            fallback_size,
        )?)?),
    }
}

/// Normalize a root using the same checks for typed callbacks and serialized CLI requests.
pub(crate) fn pool_root(root: &Path, create: bool) -> Result<PathBuf> {
    let root = std::path::absolute(root)?;
    absolute(&root)?;
    if create {
        fs::create_dir_all(&root)?;
        ensure!(
            fs::symlink_metadata(&root)?.is_dir(),
            "storage pool root is not a real directory"
        );
    }
    Ok(root)
}

/// Observe one view's accounting without changing its attachment.
pub(crate) fn volume_stats(definition: &Definition, fallback_size: u64) -> Result<Stats> {
    let (size, usage) = match definition.view_kind {
        ViewKind::ErofsBlobMap => (
            definition
                .blob_logical_size
                .map(NonZeroU64::get)
                .unwrap_or(fallback_size),
            0,
        ),
        ViewKind::MetadataImage => match definition.view_path.as_deref() {
            Some(path) => {
                absolute(path)?;
                match fs::metadata(path) {
                    Ok(metadata) => {
                        ensure!(metadata.is_file(), "volume image is not a regular file");
                        (
                            metadata.len(),
                            metadata
                                .blocks()
                                .checked_mul(512)
                                .context("volume usage overflow")?,
                        )
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        (fallback_size, 0)
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            None => (fallback_size, 0),
        },
    };
    Ok(Stats {
        size,
        usage: Some(usage),
    })
}

/// Reject storage mutation unless Qubes reports an independent, stopped VM.
fn require_stopped(klass: &str, running: bool, power_state: &str) -> Result<()> {
    ensure!(
        klass == "StandaloneVM"
            && !running
            && airlock_deployment_core::inventory::PowerState::classify(power_state).is_halted(),
        "storage installation requires a stopped StandaloneVM"
    );
    Ok(())
}
