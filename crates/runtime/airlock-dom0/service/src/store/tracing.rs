//! Decode complete immutable references before maintenance can remove storage.
//! Wire records and filesystem checks establish the inputs to the verified tracer.

use super::{fs::*, root, views};
use airlock_deployment_core::retention::tracing::{Extent, Manifest};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::Value;
use std::{collections::BTreeSet, path::Path};

/// Required generation fields; unknown diagnostic fields remain forward compatible.
#[derive(Deserialize)]
struct GenerationReferences {
    // Effective immutable system, which must appear in the declared closure.
    system: String,
    // Complete store object list and canonical view identity.
    store: StoreReferences,
    // Explicit store-only or immutable root image reference.
    root: RootReferences,
}

#[derive(Deserialize)]
struct StoreReferences {
    // Required list: missing or wrongly typed data must never mean no references.
    paths: Vec<String>,
    // Expected distinct object count published by admission.
    object_count: usize,
    // Closure coordinate owning all three canonical files.
    closure_hash: String,
    // Canonical physical-location map, not a generation-local symlink.
    canonical_blob_map: String,
    // Immutable metadata image in that same view directory.
    canonical_metadata_image: String,
    // Complete object reference list in that same view directory.
    canonical_object_refs: String,
}

#[derive(Deserialize)]
struct RootReferences {
    // Empty only when this generation has no boot disk.
    source: String,
    // Mandatory field, including an explicit JSON null for store-only generations.
    #[serde(deserialize_with = "required_root_artifact")]
    artifact: Option<root::Descriptor>,
}

/// A custom field decoder keeps JSON null explicit; ordinary Option fields also accept omission.
fn required_root_artifact<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> std::result::Result<Option<root::Descriptor>, D::Error> {
    Option::deserialize(decoder)
}

/// Validate root presence independently of whether its generation will survive GC.
pub(super) fn root_digest(value: &Value) -> Result<Option<String>> {
    let root: RootReferences = serde_json::from_value(value["root"].clone())?;
    decoded_root_digest(root)
}

/// Interpret a required, decoded root field with explicit presence semantics.
fn decoded_root_digest(root: RootReferences) -> Result<Option<String>> {
    let Some(descriptor) = root.artifact else {
        ensure!(root.source.is_empty(), "generation root artifact missing");
        return Ok(None);
    };
    ensure!(!root.source.is_empty(), "root artifact lacks its source");
    descriptor.validate()?;
    Ok(Some(descriptor.sha256))
}

/// Decode a retained generation without silently skipping malformed reference fields.
pub(super) fn manifest(pool: &Path, value: &Value) -> Result<Manifest> {
    let decoded: GenerationReferences = serde_json::from_value(value.clone())?;
    let store = decoded.store;
    component(&store.closure_hash)?;
    let directory = pool.join("views/by-closure").join(&store.closure_hash);
    pool_path(pool, &directory)?;
    for (recorded, name) in [
        (&store.canonical_blob_map, "store.blob-map.json"),
        (&store.canonical_metadata_image, "store.erofs"),
        (&store.canonical_object_refs, "object-refs"),
    ] {
        ensure!(
            Path::new(recorded) == directory.join(name),
            "generation canonical view identity mismatch"
        );
        pool_path(pool, Path::new(recorded))?;
    }

    let objects: Vec<_> = store
        .paths
        .iter()
        .map(|path| Ok(entry(path)?.to_owned()))
        .collect::<Result<_>>()?;
    let names: BTreeSet<_> = objects.iter().cloned().collect();
    ensure!(
        !objects.is_empty()
            && names.len() == objects.len()
            && objects.len() == store.object_count
            && store.paths.contains(&decoded.system),
        "generation closure references are incomplete or inconsistent"
    );
    // The map and object list must agree. Otherwise a shortened list could keep
    // physical bytes while discarding metadata needed to use those same bytes.
    views::verify(pool, &value["store"])?;
    let map: Value = read(Path::new(&store.canonical_blob_map))?;
    let mapped: BTreeSet<_> = views::extents(&map)?
        .into_iter()
        .map(|e| e.object)
        .collect();
    let mut expected = names;
    expected.insert(".tar-eof".to_owned());
    ensure!(
        mapped == expected,
        "generation object list differs from its view"
    );
    Ok(Manifest {
        objects,
        view: directory
            .to_str()
            .context("non-UTF-8 canonical view")?
            .to_owned(),
        root: decoded_root_digest(decoded.root)?,
    })
}

/// The shared terminator intentionally has no Nix entry field in its on-disk schema.
pub(super) fn pending_object(value: &Value) -> Result<String> {
    match text(value, "schema")?.as_str() {
        "airlock.closure-store.object-tar-fragment.v1" => text(value, "entry"),
        "airlock.closure-store.tar-eof.v1" => Ok(".tar-eof".to_owned()),
        _ => anyhow::bail!("unsupported pending object reference"),
    }
}

/// Decode all physical pins with required identities and range coordinates.
pub(super) fn extents(values: &[Value]) -> Result<Vec<Extent>> {
    values
        .iter()
        .map(|value| {
            Ok(Extent {
                segment: text(value, "segment_id")?,
                offset: number(value, "offset")?,
                length: number(value, "length")?,
            })
        })
        .collect()
}
