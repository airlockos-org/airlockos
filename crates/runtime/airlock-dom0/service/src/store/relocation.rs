//! Reference changes consume checked relocation and repair requests under the pool admission lock.
//! Atomic record writes and truthful byte/hash observations remain filesystem adapter obligations.

use super::{fs::*, physical, records, segments, views};
use airlock_deployment_core::retention::relocation::{
    Entry, Identity, Location, MirrorPublication, MirrorRequest, MovePlan, Phase, Publication,
    PublishRequest, RefreshRequest, Snapshot, Transaction,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

/// Fingerprint the complete decoded record, including identity, location history and transaction fields.
fn revision(value: &Value) -> Result<String> {
    Ok(hex(&Sha256::digest(serde_json::to_vec(value)?)))
}

/// Bind physical coordinates to the original pool; recorded blob paths must agree with the segment.
fn location(root: &Path, extent: &segments::Extent) -> Result<Location> {
    ensure!(
        extent.segment_blob == segments::blob(root, &extent.segment_id)?,
        "relocation blob identity mismatch"
    );
    Ok(Location {
        pool: root
            .to_str()
            .context("non-UTF-8 relocation pool")?
            .to_owned(),
        segment: extent.segment_id.clone(),
        offset: extent.segment_offset,
        size: extent.size,
        digest: extent.sha256.clone(),
    })
}

/// Preserve full logical identity and the complete decoded-record fingerprint in one observation.
fn snapshot(root: &Path, name: &str, value: &Value, extent: &segments::Extent) -> Result<Snapshot> {
    component(name)?;
    let identity = if name == ".tar-eof" {
        ensure!(
            value["schema"] == "airlock.closure-store.tar-eof.v1",
            "invalid terminator snapshot"
        );
        Identity {
            name: name.to_owned(),
            path: String::new(),
            tree_hash: String::new(),
        }
    } else {
        ensure!(
            value["entry"] == name,
            "relocation object identity mismatch"
        );
        Identity {
            name: name.to_owned(),
            path: text(value, "path")?,
            tree_hash: text(value, "tree_hash")?,
        }
    };
    Ok(Snapshot {
        identity,
        location: location(root, extent)?,
        revision: revision(value)?,
    })
}

/// Capture the original checked record before the coordinator starts copying bytes.
pub(super) fn plan(
    root: &Path,
    name: &str,
    value: &Value,
    extent: &segments::Extent,
    transaction: &str,
) -> Result<MovePlan> {
    MovePlan::new(snapshot(root, name, value, extent)?, transaction.to_owned())
        .context("invalid relocation source")
}

/// Verify the actual appended bytes, then compare them with the captured original contents.
pub(super) fn copied(plan: MovePlan, extent: &segments::Extent) -> Result<PublishRequest> {
    let root = Path::new(&plan.source().location.pool);
    let checked = segments::check_extent(root, extent, true)?;
    plan.copied_extent(checked)
        .context("relocation replacement changes original contents or overlaps source")
}

/// Encode only the physical location preserved by the checked request.
fn extent(location: &Location) -> Result<segments::Extent> {
    let root = Path::new(&location.pool);
    Ok(segments::Extent {
        segment_id: location.segment.clone(),
        segment_blob: segments::blob(root, &location.segment)?,
        segment_offset: location.offset,
        size: location.size,
        sha256: location.digest.clone(),
    })
}

/// Read the original durable compaction intent rather than accepting a caller's execution flag.
fn transaction(request: &PublishRequest) -> Result<Transaction> {
    let root = Path::new(&request.source().location.pool);
    let id = component(request.transaction())?;
    let path = root.join("transactions").join(format!("{id}.json"));
    pool_path(root, &path)?;
    let value: Value = read(&path)?;
    ensure!(
        value["schema"] == "airlock.closure-store.transaction.v1" && value["type"] == "compaction",
        "relocation lacks a compaction transaction"
    );
    Ok(Transaction {
        pool: request.source().location.pool.clone(),
        id: text(&value, "id")?,
        phase: Phase::decode(&text(&value, "status")?)
            .context("unknown compaction transaction phase")?,
    })
}

/// Authenticate current source and durable attempt before handing publication to its private adapter.
pub(super) fn publish(request: PublishRequest) -> Result<()> {
    let source = request.source();
    let root = Path::new(&source.location.pool);
    let (value, old) = physical::object(root, &source.identity.name)?;
    let current = snapshot(root, &source.identity.name, &value, &old)?;
    let transaction = transaction(&request)?;
    let publication = request
        .confirm(&current, &transaction)
        .context("stale source or inactive compaction transaction")?;
    publish_checked(publication, value)
}

/// Publish canonical authority only after the proposed contents also pass mirror-repair preflight.
fn publish_checked(publication: Publication, mut value: Value) -> Result<()> {
    let request = publication.request();
    let source = request.source();
    let root = Path::new(&source.location.pool);
    let name = &source.identity.name;
    ensure!(
        revision(&value)? == source.revision,
        "publication record differs from checked source"
    );
    let replacement = extent(request.target())?;
    let old = extent(&source.location)?;
    let transaction = request.transaction();
    let mut history = value["locations"]
        .as_array()
        .cloned()
        .unwrap_or_else(|| vec![serde_json::to_value(old).expect("serializable extent")]);
    for location in &mut history {
        if location["status"] == "current" || location.get("status").is_none() {
            location["status"] = json!("retired");
            location["retired_at"] = json!(now());
            location["retired_by_transaction"] = json!(transaction);
        }
    }
    let mut new = serde_json::to_value(&replacement)?;
    new["status"] = json!("current");
    new["created_at"] = json!(now());
    new["transaction"] = json!(transaction);
    history.push(new);
    for (key, field) in serde_json::to_value(&replacement)?
        .as_object()
        .context("invalid replacement extent")?
    {
        value[key] = field.clone();
    }
    value["locations"] = json!(history);
    value["relocated_at"] = json!(now());
    value["relocated_by_transaction"] = json!(transaction);
    value["transaction"] = json!(transaction);
    let repair = prepare_mirror(snapshot(root, name, &value, &replacement)?)?;

    write(&segments::object_metadata(root, name)?, &value, 0o444)?;
    failpoint("compact-between-location-records")?;
    if let Some(repair) = repair {
        repair_mirror(repair)?;
    }
    Ok(())
}

/// Decode mirror coordinates without requiring retired backing bytes to still exist.
fn mirror_snapshot(root: &Path, name: &str, value: &Value) -> Result<Snapshot> {
    ensure!(
        value["schema"] == "airlock.closure-store.object.v2",
        "invalid logical object mirror"
    );
    let old: segments::Extent = serde_json::from_value(value["tar_fragment"].clone())?;
    snapshot(root, name, value, &old)
}

/// Preflight mirror identity and contents before any canonical publication.
fn prepare_mirror(canonical: Snapshot) -> Result<Option<MirrorRequest>> {
    if canonical.identity.name == ".tar-eof" {
        return Ok(None);
    }
    let root = Path::new(&canonical.location.pool);
    let path = root.join("objects/metadata").join(format!(
        "{name}.json",
        name = component(&canonical.identity.name)?
    ));
    pool_path(root, &path)?;
    if !path.try_exists()? {
        return Ok(None);
    }
    let mirror = mirror_snapshot(root, &canonical.identity.name, &read(&path)?)?;
    Ok(Some(MirrorRequest::new(canonical, mirror).context(
        "cannot repair changed object identity or contents",
    )?))
}

/// Consume canonical-to-mirror authority and refuse changed observations before updating the convenience copy.
fn repair_mirror(request: MirrorRequest) -> Result<bool> {
    let authority = request.canonical();
    let root = Path::new(&authority.location.pool);
    let name = &authority.identity.name;
    let (canonical, location) = physical::object(root, name)?;
    let current = snapshot(root, name, &canonical, &location)?;
    let path = root.join("objects/metadata").join(format!("{name}.json"));
    pool_path(root, &path)?;
    let object: Value = read(&path)?;
    let mirror = mirror_snapshot(root, name, &object)?;
    let publication = request
        .confirm(&current, &mirror)
        .context("canonical record or mirror changed before repair")?;
    write_mirror(publication, canonical, object)
}

/// Write only the confirmed original mirror, with payload fingerprints checked against the permission.
fn write_mirror(
    publication: MirrorPublication,
    canonical: Value,
    mut object: Value,
) -> Result<bool> {
    let request = publication.request();
    let authority = request.canonical();
    let root = Path::new(&authority.location.pool);
    let name = &authority.identity.name;
    ensure!(
        revision(&canonical)? == authority.revision
            && revision(&object)? == request.mirror().revision,
        "mirror payload differs from confirmed records"
    );
    if object["tar_fragment"] == canonical {
        return Ok(false);
    }
    object["tar_fragment"] = canonical;
    object["tree_materialized"] = json!(false);
    let path = root.join("objects/metadata").join(format!("{name}.json"));
    pool_path(root, &path)?;
    write(&path, &object, 0o644)?;
    Ok(true)
}

/// Recovery repairs only from the currently authenticated canonical record, without replaying a copy.
pub(super) fn reconcile(root: &Path, name: &str) -> Result<bool> {
    let (value, extent) = physical::object(root, name)?;
    match prepare_mirror(snapshot(root, name, &value, &extent)?)? {
        Some(request) => repair_mirror(request),
        None => Ok(false),
    }
}

/// Forward the checked map identity and complete replacement row without independently supplied coordinates.
fn refresh_entry(request: RefreshRequest) -> Result<(PathBuf, views::MapExtent)> {
    let path = PathBuf::from(request.map());
    let entry = request.apply();
    let extent = extent(&entry.location)?;
    Ok((
        path,
        views::MapExtent {
            logical_offset: entry.logical_offset,
            segment_id: extent.segment_id,
            segment_blob: extent.segment_blob,
            segment_offset: extent.segment_offset,
            length: extent.size,
            object: entry.object,
            object_sha256: extent.sha256,
        },
    ))
}

/// Refresh unpinned view placements while preserving each checked row's logical address and contents.
pub(super) fn refresh_maps(root: &Path) -> Result<Vec<PathBuf>> {
    let mut pinned = BTreeSet::new();
    for (_, reference) in records::running_refs(root)? {
        if matches!(
            reference["volume"].as_str(),
            Some("host-retained" | "builder-persistent")
        ) {
            let path = PathBuf::from(text(&reference, "blob_map")?);
            pool_path(root, &path)?;
            pinned.insert(path);
        }
    }
    let mut paths = Vec::new();
    for directory in children(&root.join("views/by-closure"))? {
        pool_path(root, &directory)?;
        paths.push(directory.join("store.blob-map.json"));
    }
    for manifest in records::manifests(root)? {
        paths.push(
            manifest
                .parent()
                .context("missing generation parent")?
                .join("store.blob-map.json"),
        );
    }
    let mut refreshed = Vec::new();
    for path in paths {
        // Generation-local maps intentionally link to canonical views.
        if path.is_symlink() {
            continue;
        }
        pool_path(root, &path)?;
        if !path.try_exists()? || pinned.contains(&path) {
            continue;
        }
        let mut map: Value = read(&path)?;
        let mut items = views::extents(&map)?;
        let mut segments = BTreeMap::new();
        let mut changed = false;
        let mut verified = true;
        for item in &mut items {
            let meta = segments::object_metadata(root, &item.object)?;
            if meta.try_exists()? {
                let (value, extent) = physical::object(root, &item.object)?;
                let original = Entry {
                    object: item.object.clone(),
                    logical_offset: item.logical_offset,
                    location: location(
                        root,
                        &segments::Extent {
                            segment_id: item.segment_id.clone(),
                            segment_blob: item.segment_blob.clone(),
                            segment_offset: item.segment_offset,
                            size: item.length,
                            sha256: item.object_sha256.clone(),
                        },
                    )?,
                };
                let request = RefreshRequest::new(
                    path.to_str().context("non-UTF-8 view path")?.to_owned(),
                    original,
                    snapshot(root, &item.object, &value, &extent)?,
                )
                .context("cannot refresh changed object identity or contents")?;
                let (target, replacement) = refresh_entry(request)?;
                ensure!(target == path, "refreshed entry names another view");
                changed |= (item.segment_id.as_str(), item.segment_offset)
                    != (replacement.segment_id.as_str(), replacement.segment_offset);
                *item = replacement;
            } else {
                verified = false;
            }
            // Unresolved entries keep their original placement and remain in the segment summary.
            let blob = segments::blob(root, &item.segment_id)?;
            ensure!(item.segment_blob == blob, "view blob identity mismatch");
            let meta: Value = read(&segments::metadata(root, &item.segment_id)?)?;
            segments.insert(item.segment_id.clone(), json!({"id":item.segment_id,"blob":blob,"size":fs::metadata(&blob)?.len(),"status":meta["status"]}));
        }
        let new_segments = json!(segments.values().collect::<Vec<_>>());
        changed |= map["segments"] != new_segments;
        if changed {
            map["segments"] = new_segments;
            map["segment_count"] = json!(segments.len());
            map["extents"] = serde_json::to_value(items)?;
            map["refreshed_at"] = json!(now());
            write(&path, &map, 0o444)?;
            refreshed.push(path.clone());
        }
        // Every replacement row above passed the relocation identity gate.
        // Reissue even after an interrupted publication whose map is already current.
        if verified {
            views::certify_map(&path, &map)?;
        }
    }
    Ok(refreshed)
}

#[cfg(test)]
mod tests;
