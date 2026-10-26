//! Ordinary pool files exercise checked publication without Qubes, mounts or live storage.

use super::*;

/// One original fragment, identical replacement bytes and an active compaction journal.
struct Fixture {
    // Disposable files retaining all tested paths until the adapter finishes.
    directory: tempfile::TempDir,
    // Original canonical extent before any copy or reference publication.
    source: segments::Extent,
    // Independently observed bytes in a different segment of the same pool.
    replacement: segments::Extent,
}

impl Fixture {
    /// Create a source record, convenience mirror and real replacement files with matching hashes.
    fn new() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        for path in [
            "objects/segments",
            "objects/blob-metadata",
            "objects/metadata",
            "transactions",
            "views/by-closure",
        ] {
            fs::create_dir_all(root.join(path))?;
        }
        let bytes = vec![b'x'; 1024];
        let digest = hex(&Sha256::digest(&bytes));
        let source = segments::Extent {
            segment_id: "000001".into(),
            segment_blob: segments::blob(root, "000001")?,
            segment_offset: 0,
            size: bytes.len() as u64,
            sha256: digest.clone(),
        };
        let replacement = segments::Extent {
            segment_id: "000002".into(),
            segment_blob: segments::blob(root, "000002")?,
            segment_offset: 0,
            size: bytes.len() as u64,
            sha256: digest,
        };
        for extent in [&source, &replacement] {
            fs::write(&extent.segment_blob, &bytes)?;
            write(
                &segments::metadata(root, &extent.segment_id)?,
                &json!({
                    "id":extent.segment_id, "blob":extent.segment_blob, "status":"sealed",
                }),
                0o600,
            )?;
        }
        let mut value = serde_json::to_value(&source)?;
        for (key, field) in json!({
            "schema":"airlock.closure-store.object-tar-fragment.v1", "entry":"object",
            "path":"/nix/store/object", "tree_hash":"tree", "transaction":"admission",
        })
        .as_object()
        .unwrap()
        {
            value[key] = field.clone();
        }
        write(&segments::object_metadata(root, "object")?, &value, 0o600)?;
        write(
            &root.join("objects/metadata/object.json"),
            &json!({
                "schema":"airlock.closure-store.object.v2", "entry":"object", "path":"/nix/store/object",
                "tree_hash":"tree", "tar_fragment":value, "tree_materialized":false,
            }),
            0o600,
        )?;
        write(
            &root.join("transactions/compaction.json"),
            &json!({
                "schema":"airlock.closure-store.transaction.v1", "id":"compaction", "type":"compaction", "status":"preparing",
            }),
            0o600,
        )?;
        Ok(Self {
            directory,
            source,
            replacement,
        })
    }

    /// Resolve the fixture's pool without any global environment override.
    fn root(&self) -> &Path {
        self.directory.path()
    }

    /// Capture and validate exactly the replacement used by production compaction.
    fn request(&self) -> Result<PublishRequest> {
        let value = read(&segments::object_metadata(self.root(), "object")?)?;
        copied(
            plan(self.root(), "object", &value, &self.source, "compaction")?,
            &self.replacement,
        )
    }
}

/// Copy validation must not silently replace a caller's backing file with another segment.
#[test]
fn copied_extent_cannot_substitute_its_backing_path() -> Result<()> {
    let fixture = Fixture::new()?;
    segments::with_verification(|| {
        fixture.request()?;
        let value = read(&segments::object_metadata(fixture.root(), "object")?)?;
        let mut replacement = fixture.replacement.clone();
        replacement.segment_blob = fixture.source.segment_blob.clone();
        let planned = plan(
            fixture.root(),
            "object",
            &value,
            &fixture.source,
            "compaction",
        )?;
        assert!(copied(planned, &replacement).is_err());
        Ok(json!({}))
    })?;
    Ok(())
}

#[test]
fn mirror_disagreement_refuses_before_canonical_publication() -> Result<()> {
    let fixture = Fixture::new()?;
    let request = fixture.request()?;
    let path = fixture.root().join("objects/metadata/object.json");
    let mut mirror: Value = read(&path)?;
    mirror["tar_fragment"]["sha256"] = json!("0".repeat(64));
    write(&path, &mirror, 0o600)?;
    let canonical_path = segments::object_metadata(fixture.root(), "object")?;
    let canonical_before = fs::read(&canonical_path)?;
    let mirror_before = fs::read(&path)?;
    assert!(publish(request).is_err());
    assert_eq!(fs::read(canonical_path)?, canonical_before);
    assert_eq!(fs::read(path)?, mirror_before);
    Ok(())
}

#[test]
fn replacement_bytes_must_independently_match_the_original_fragment_contents() -> Result<()> {
    for truthful_digest in [false, true] {
        let fixture = Fixture::new()?;
        let path = segments::object_metadata(fixture.root(), "object")?;
        let before = fs::read(&path)?;
        let value = read(&path)?;
        let plan = plan(
            fixture.root(),
            "object",
            &value,
            &fixture.source,
            "compaction",
        )?;
        fs::write(&fixture.replacement.segment_blob, vec![b'y'; 1024])?;
        let mut replacement = fixture.replacement.clone();
        if truthful_digest {
            replacement.sha256 = hash(&replacement.segment_blob)?;
        }
        // A false checksum fails byte verification; a truthful different checksum fails content equivalence.
        assert!(copied(plan, &replacement).is_err());
        assert_eq!(fs::read(path)?, before);
    }
    Ok(())
}

#[test]
fn stale_sources_and_inactive_journals_cannot_publish_replacements() -> Result<()> {
    for defect in [
        "source-revision",
        "aborted",
        "committed",
        "unknown",
        "attempt",
        "schema",
    ] {
        let fixture = Fixture::new()?;
        let request = fixture.request()?;
        let path = segments::object_metadata(fixture.root(), "object")?;
        let journal = fixture.root().join("transactions/compaction.json");
        if defect == "source-revision" {
            let mut value: Value = read(&path)?;
            value["changed"] = json!(true);
            write(&path, &value, 0o600)?;
        } else {
            let mut value: Value = read(&journal)?;
            match defect {
                "attempt" => value["id"] = json!("other"),
                "schema" => value["schema"] = json!("unknown"),
                phase => value["status"] = json!(phase),
            }
            write(&journal, &value, 0o600)?;
        }
        let before = fs::read(&path)?;
        assert!(publish(request).is_err(), "accepted {defect}");
        assert_eq!(fs::read(&path)?, before);
    }
    Ok(())
}

#[test]
fn a_checked_copy_cannot_be_replayed_over_the_new_source_record() -> Result<()> {
    let fixture = Fixture::new()?;
    let first = fixture.request()?;
    let stale = fixture.request()?;
    publish(first)?;
    let path = segments::object_metadata(fixture.root(), "object")?;
    let before = fs::read(&path)?;
    assert!(publish(stale).is_err());
    assert_eq!(fs::read(path)?, before);
    assert!(!reconcile(fixture.root(), "object")?);
    assert!(!reconcile(fixture.root(), "object")?);
    Ok(())
}

#[test]
fn recovery_repairs_only_current_authority_even_after_old_mirror_bytes_are_retired() -> Result<()> {
    let fixture = Fixture::new()?;
    let path = segments::object_metadata(fixture.root(), "object")?;
    let mut canonical: Value = read(&path)?;
    for (key, value) in serde_json::to_value(&fixture.replacement)?
        .as_object()
        .unwrap()
    {
        canonical[key] = value.clone();
    }
    // Model a completed canonical rename whose convenience mirror was not yet updated.
    write(&path, &canonical, 0o600)?;
    fs::remove_file(&fixture.source.segment_blob)?;
    assert!(reconcile(fixture.root(), "object")?);
    assert!(!reconcile(fixture.root(), "object")?);
    let mirror: Value = read(&fixture.root().join("objects/metadata/object.json"))?;
    assert_eq!(mirror["tar_fragment"], canonical);
    Ok(())
}

#[test]
fn changed_mirror_after_preflight_refuses_repair() -> Result<()> {
    let fixture = Fixture::new()?;
    let (value, extent) = physical::object(fixture.root(), "object")?;
    let request = prepare_mirror(snapshot(fixture.root(), "object", &value, &extent)?)?.unwrap();
    let path = fixture.root().join("objects/metadata/object.json");
    let mut mirror: Value = read(&path)?;
    mirror["changed"] = json!(true);
    write(&path, &mirror, 0o600)?;
    let before = fs::read(&path)?;
    assert!(repair_mirror(request).is_err());
    assert_eq!(fs::read(path)?, before);
    Ok(())
}

#[test]
fn pinned_maps_are_unchanged_and_unresolved_entries_keep_their_segment_summary() -> Result<()> {
    let fixture = Fixture::new()?;
    let view = fixture.root().join("views/by-closure/view");
    fs::create_dir(&view)?;
    let path = view.join("store.blob-map.json");
    write(
        &path,
        &json!({"segments":[], "segment_count":0, "extents":[{
            "logical_offset":8192, "segment_id":fixture.source.segment_id, "segment_blob":fixture.source.segment_blob,
            "segment_offset":0, "length":fixture.source.size, "object":"object", "object_sha256":fixture.source.sha256,
        }]}),
        0o600,
    )?;
    let running = fixture.root().join("running/domain/1/host-retained.json");
    write(
        &running,
        &json!({
            "schema":"airlock.closure-store.running-ref.v1", "status":"running", "domain":"domain", "generation":1,
            "volume":"host-retained", "blob_map":path,
        }),
        0o600,
    )?;
    let before = fs::read(&path)?;
    assert!(refresh_maps(fixture.root())?.is_empty());
    assert_eq!(fs::read(&path)?, before);

    fs::remove_file(running)?;
    fs::remove_file(segments::object_metadata(fixture.root(), "object")?)?;
    refresh_maps(fixture.root())?;
    let map: Value = read(&path)?;
    assert_eq!(map["segments"][0]["id"], "000001");
    assert_eq!(map["segment_count"], 1);
    assert_eq!(map["extents"][0]["logical_offset"], 8192);
    Ok(())
}
