//! Segment deletion consumes a verified request and rechecks its named physical records.
//! The caller holds admission exclusion; the segment lock also excludes append/seal operations.

use super::{fs::*, segments};
use airlock_deployment_core::retention::segments::{Candidate, SegmentDeleteRequest, State};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
};

/// Required fields of a physical segment, not the maintenance report describing it.
#[derive(Deserialize)]
struct StoredSegment {
    // Exact supported on-disk segment record format.
    schema: String,
    // Filename identity, checked before any deletion request is constructed.
    id: String,
    // Recorded pool-owned file, which must agree with the filename identity.
    blob: PathBuf,
    // Lifecycle spelling published by creation or sealing.
    status: String,
    // Redundant lifecycle evidence; disagreement with status refuses cleanup.
    sealed: bool,
}

/// Read selection without treating an empty, malformed or redirected pointer as absence.
pub(super) fn current(root: &Path) -> Result<Option<String>> {
    let path = root.join("objects/current-segment");
    pool_path(root, &path)?;
    let id = match fs::read_to_string(&path) {
        Ok(id) => id.trim().to_owned(),
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    segments::segment_id(&id)?;
    Ok(Some(id))
}

/// Resolve the same pool and exact segment coordinate represented by the physical record.
pub(super) fn observe(root: &Path, id: &str) -> Result<Candidate> {
    let record: StoredSegment = read(&segments::metadata(root, id)?)?;
    ensure!(
        record.schema == "airlock.closure-store.segment.v1" && record.id == id,
        "segment record identity mismatch"
    );
    ensure!(
        record.blob == segments::blob(root, id)?,
        "segment record names another pool or blob"
    );
    Ok(Candidate {
        id: record.id,
        state: State::decode(&record.status, record.sealed)
            .context("unknown or contradictory segment lifecycle")?,
    })
}

/// A missing unpinned blob can be the interrupted first half of a previous deletion.
/// Referenced ranges are checked for existence before inventory reaches this point.
pub(super) fn bytes(root: &Path, id: &str) -> Result<u64> {
    match fs::metadata(segments::blob(root, id)?) {
        Ok(meta) => {
            ensure!(meta.is_file(), "segment blob is not a regular file");
            Ok(meta.len())
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error.into()),
    }
}

/// Unlink files only; a directory masquerading as a segment cannot cause recursive deletion.
fn unlink(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Consume exact checked pool/segment identities, revalidating lifecycle immediately before unlinking.
/// This external adapter relies on admission exclusion for the reference snapshot's freshness.
pub(super) fn execute(request: SegmentDeleteRequest<'_>) -> Result<u64> {
    let root = Path::new(request.pool());
    let _lock = PoolLock::acquire(&root.join("objects/segments.lock"))?;
    failpoint("gc-before-segment-delete")?;
    let observed = observe(root, request.id())?;
    let selected = current(root)?;
    ensure!(
        request.revalidate(&observed, &selected),
        "segment changed after deletion selection"
    );
    let reclaimed = bytes(root, request.id())?;

    unlink(&segments::blob(root, request.id())?)?;
    // Publish the blob unlink before removing its recovery evidence. With ordered
    // directory fsync, a power failure cannot persist metadata removal first.
    sync_dir(&root.join("objects/segments"))?;
    failpoint("gc-between-segment-files")?;
    unlink(&segments::metadata(root, request.id())?)?;
    sync_dir(&root.join("objects/segments"))?;
    failpoint("gc-after-segment-delete")?;
    Ok(reclaimed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use airlock_deployment_core::retention::{segments::SegmentIndex, tracing::Trace};
    use serde_json::{Value, json};

    /// One disposable pool coordinate and exact sealed segment record.
    fn fixture() -> Result<tempfile::TempDir> {
        let directory = tempfile::tempdir()?;
        fs::create_dir_all(directory.path().join("objects/segments"))?;
        write_segment(directory.path(), "000001")?;
        Ok(directory)
    }

    /// Publish ordinary test files; no device or real pool is touched.
    fn write_segment(root: &Path, id: &str) -> Result<()> {
        fs::write(segments::blob(root, id)?, b"segment payload")?;
        fs::write(
            segments::metadata(root, id)?,
            serde_json::to_vec(&json!({
                "schema":"airlock.closure-store.segment.v1", "id":id,
                "blob":segments::blob(root,id)?, "status":"sealed", "sealed":true,
            }))?,
        )?;
        Ok(())
    }

    /// Bind an original named target to its complete immutable trace and pool.
    fn permission<'a>(root: &Path, trace: &'a Trace) -> SegmentDeleteRequest<'a> {
        SegmentIndex::new(root.to_str().unwrap().into(), trace)
            .unwrap()
            .reclaim(
                Candidate {
                    id: "000001".into(),
                    state: State::Sealed,
                },
                &None,
            )
            .unwrap()
    }

    #[test]
    fn adapter_uses_only_the_requests_exact_pool_and_segment() -> Result<()> {
        let original = fixture()?;
        let other = fixture()?;
        write_segment(original.path(), "000002")?;
        let trace = Trace::new();
        assert_eq!(execute(permission(original.path(), &trace))?, 15);
        assert!(!segments::blob(original.path(), "000001")?.exists());
        assert!(!segments::metadata(original.path(), "000001")?.exists());
        assert!(segments::blob(original.path(), "000002")?.is_file());
        assert!(segments::blob(other.path(), "000001")?.is_file());
        Ok(())
    }

    #[test]
    fn adapter_rechecks_selection_and_physical_lifecycle_before_unlinking() -> Result<()> {
        for change in [
            "selected",
            "empty-selection",
            "open",
            "conflicting-state",
            "other-identity",
        ] {
            let pool = fixture()?;
            let root = pool.path();
            let trace = Trace::new();
            let request = permission(root, &trace);
            let path = segments::metadata(root, "000001")?;
            let mut value: Value = read(&path)?;
            match change {
                "selected" => fs::write(root.join("objects/current-segment"), "000001\n")?,
                "empty-selection" => fs::write(root.join("objects/current-segment"), "")?,
                "open" => {
                    value["status"] = json!("open");
                    value["sealed"] = json!(false);
                }
                "conflicting-state" => value["sealed"] = json!(false),
                "other-identity" => value["id"] = json!("000002"),
                _ => unreachable!(),
            }
            fs::write(&path, serde_json::to_vec(&value)?)?;
            assert!(
                execute(request).is_err(),
                "accepted changed observation: {change}"
            );
            assert_eq!(
                fs::read(segments::blob(root, "000001")?)?,
                b"segment payload"
            );
            assert!(path.is_file());
        }
        Ok(())
    }

    #[test]
    fn adapter_finishes_partial_unlink_and_refuses_directories() -> Result<()> {
        let pool = fixture()?;
        let root = pool.path();
        let trace = Trace::new();
        fs::remove_file(segments::blob(root, "000001")?)?;
        assert_eq!(execute(permission(root, &trace))?, 0);
        assert!(!segments::metadata(root, "000001")?.exists());

        write_segment(root, "000001")?;
        let blob = segments::blob(root, "000001")?;
        fs::remove_file(&blob)?;
        fs::create_dir(&blob)?;
        fs::write(blob.join("sentinel"), b"keep")?;
        assert!(execute(permission(root, &trace)).is_err());
        assert_eq!(fs::read(blob.join("sentinel"))?, b"keep");
        Ok(())
    }
}
