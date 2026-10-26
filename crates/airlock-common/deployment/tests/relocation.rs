//! Relocation requests preserve immutable identity across publication, repair and map refresh.

use airlock_deployment_core::retention::relocation::{
    Entry, Identity, Location, MirrorRequest, MovePlan, Phase, RefreshRequest, Snapshot,
    Transaction,
    extent::{Backing, CheckedExtent},
};

/// Original immutable object at a named physical segment, with a complete record revision.
fn snapshot(segment: &str, revision: &str) -> Snapshot {
    Snapshot {
        identity: Identity {
            name: "object".into(),
            path: "/nix/store/object".into(),
            tree_hash: "tree".into(),
        },
        location: location(segment),
        revision: revision.repeat(64),
    }
}

/// Equivalent immutable contents at the beginning of one physical segment.
fn location(segment: &str) -> Location {
    Location {
        pool: "/pool".into(),
        segment: segment.into(),
        offset: 0,
        size: 1024,
        digest: "a".repeat(64),
    }
}

/// Durable source of publication authority; observed status is classified independently.
fn transaction(phase: Phase) -> Transaction {
    Transaction {
        pool: "/pool".into(),
        id: "compaction".into(),
        phase,
    }
}

#[test]
fn publication_preserves_source_target_pool_and_original_attempt() {
    let plan = MovePlan::new(snapshot("000001", "b"), "compaction".into()).unwrap();
    let request = plan.copied(location("000002")).unwrap();
    let publication = request
        .confirm(&snapshot("000001", "b"), &transaction(Phase::Preparing))
        .unwrap();
    let request = publication.request();
    assert_eq!(request.source().identity.path, "/nix/store/object");
    assert_eq!(request.source().location.segment, "000001");
    assert_eq!(request.target().pool, "/pool");
    assert_eq!(request.target().segment, "000002");
    assert_eq!(request.target().digest, request.source().location.digest);
    assert_eq!(request.transaction(), "compaction");
}

#[test]
fn replacement_cannot_change_content_pool_or_overwrite_original_bytes() {
    for defect in ["pool", "digest", "size", "overlap", "overflow", "empty"] {
        let plan = MovePlan::new(snapshot("000001", "b"), "compaction".into()).unwrap();
        let mut target = location("000002");
        match defect {
            "pool" => target.pool = "/other".into(),
            "digest" => target.digest = "c".repeat(64),
            "size" => target.size = 512,
            "overlap" => target.segment = "000001".into(),
            "overflow" => target.offset = u64::MAX,
            "empty" => target.segment.clear(),
            _ => unreachable!(),
        }
        assert!(plan.copied(target).is_none(), "accepted {defect}");
    }
    let mut adjacent = location("000001");
    adjacent.offset = 1024;
    assert!(
        MovePlan::new(snapshot("000001", "b"), "compaction".into())
            .unwrap()
            .copied(adjacent)
            .is_some()
    );
}

#[test]
fn fresh_confirmation_refuses_stale_sources_and_inactive_or_substituted_transactions() {
    for defect in [
        "revision",
        "name",
        "path",
        "tree",
        "location",
        "pool",
        "transaction",
        "committed",
        "aborted",
    ] {
        let request = MovePlan::new(snapshot("000001", "b"), "compaction".into())
            .unwrap()
            .copied(location("000002"))
            .unwrap();
        let mut current = snapshot("000001", "b");
        let mut transaction = transaction(Phase::Preparing);
        match defect {
            "revision" => current.revision = "c".repeat(64),
            "name" => current.identity.name = "other".into(),
            "path" => current.identity.path = "/nix/store/other".into(),
            "tree" => current.identity.tree_hash = "other".into(),
            "location" => current.location.segment = "000003".into(),
            "pool" => transaction.pool = "/other".into(),
            "transaction" => transaction.id = "other".into(),
            "committed" => transaction.phase = Phase::Committed,
            "aborted" => transaction.phase = Phase::Aborted,
            _ => unreachable!(),
        }
        assert!(
            request.confirm(&current, &transaction).is_none(),
            "accepted {defect}"
        );
    }
    assert!(Phase::decode("uncertain").is_none());
}

#[test]
fn mirror_repair_changes_only_placement_and_requires_unchanged_observations() {
    let request = MirrorRequest::new(snapshot("000002", "c"), snapshot("000001", "b")).unwrap();
    assert_eq!(request.canonical().location.segment, "000002");
    assert!(
        request
            .confirm(&snapshot("000002", "c"), &snapshot("000001", "b"))
            .is_some()
    );
    for (canonical_revision, mirror_revision) in [("d", "b"), ("c", "d")] {
        let request = MirrorRequest::new(snapshot("000002", "c"), snapshot("000001", "b")).unwrap();
        assert!(
            request
                .confirm(
                    &snapshot("000002", canonical_revision),
                    &snapshot("000001", mirror_revision)
                )
                .is_none()
        );
    }
    for defect in ["name", "path", "tree", "digest", "size", "pool"] {
        let mut mirror = snapshot("000001", "b");
        match defect {
            "name" => mirror.identity.name = "other".into(),
            "path" => mirror.identity.path = "/nix/store/other".into(),
            "tree" => mirror.identity.tree_hash = "other".into(),
            "digest" => mirror.location.digest = "d".repeat(64),
            "size" => mirror.location.size = 512,
            "pool" => mirror.location.pool = "/other".into(),
            _ => unreachable!(),
        }
        assert!(MirrorRequest::new(snapshot("000002", "c"), mirror).is_none());
    }
}

#[test]
fn map_refresh_preserves_logical_address_object_and_content_and_rejects_substitutions() {
    let request = RefreshRequest::new(
        "/pool/view/map".into(),
        Entry {
            object: "object".into(),
            logical_offset: 8192,
            location: location("000001"),
        },
        snapshot("000002", "c"),
    )
    .unwrap();
    assert_eq!(request.map(), "/pool/view/map");
    let output = request.apply();
    assert_eq!(output.object, "object");
    assert_eq!(output.logical_offset, 8192);
    assert_eq!(output.location.segment, "000002");
    assert_eq!(output.location.size, 1024);
    assert_eq!(output.location.digest, "a".repeat(64));
    for defect in ["object", "offset", "pool", "digest", "size"] {
        let mut row = Entry {
            object: "object".into(),
            logical_offset: 8192,
            location: location("000001"),
        };
        match defect {
            "object" => row.object = "other".into(),
            "offset" => row.logical_offset = u64::MAX,
            "pool" => row.location.pool = "/other".into(),
            "digest" => row.location.digest = "d".repeat(64),
            "size" => row.location.size = 512,
            _ => unreachable!(),
        }
        assert!(
            RefreshRequest::new("/pool/view/map".into(), row, snapshot("000002", "c")).is_none()
        );
    }
}

#[test]
fn shared_terminator_has_explicit_identity_and_follows_the_same_content_rules() {
    let source = Snapshot {
        identity: Identity {
            name: ".tar-eof".into(),
            path: String::new(),
            tree_hash: String::new(),
        },
        location: location("000001"),
        revision: "b".repeat(64),
    };
    let request = MovePlan::new(source, "compaction".into())
        .unwrap()
        .copied(location("000002"))
        .unwrap();
    assert_eq!(request.source().identity.name, ".tar-eof");
}

/// Exact canonical backing metadata, supplied independently of the claimed extent.
fn backing(length: u64) -> Backing {
    Backing {
        path: "/pool/objects/segments/000002.blob".into(),
        length,
        regular: true,
    }
}

/// Interior and maximum-number ranges keep their original read bounds and relocation identity.
#[test]
fn checked_extents_preserve_exact_read_and_relocation_coordinates() {
    for offset in [128, u64::MAX - 1024] {
        let mut claimed = location("000002");
        claimed.offset = offset;
        let checked = CheckedExtent::check(
            claimed,
            "/pool/objects/segments/000002.blob",
            backing(offset + 1024),
        )
        .unwrap();
        assert_eq!(checked.end(), offset + 1024);
        assert_eq!(checked.location().offset, offset);
        assert_eq!(checked.backing(), "/pool/objects/segments/000002.blob");
        let request = MovePlan::new(snapshot("000001", "b"), "compaction".into())
            .unwrap()
            .copied_extent(checked)
            .unwrap();
        let target = request.target();
        assert_eq!(target.pool, "/pool");
        assert_eq!(target.segment, "000002");
        assert_eq!(target.offset, offset);
        assert_eq!(target.size, 1024);
        assert_eq!(target.digest, "a".repeat(64));
    }
}

/// Invalid backing observations, range arithmetic and digest encodings fail closed.
#[test]
fn checked_extents_refuse_redirected_or_invalid_ranges() {
    for defect in [
        "backing",
        "directory",
        "zero",
        "past-end",
        "overflow",
        "short-digest",
        "uppercase-digest",
        "nonhex-digest",
        "unicode-digest",
    ] {
        let mut claimed = location("000002");
        let mut observed = backing(1024);
        match defect {
            "backing" => observed.path = "/other/000002.blob".into(),
            "directory" => observed.regular = false,
            "zero" => claimed.size = 0,
            "past-end" => claimed.offset = 1,
            "overflow" => {
                claimed.offset = u64::MAX;
                observed.length = u64::MAX;
            }
            "short-digest" => {
                claimed.digest.pop();
            }
            "uppercase-digest" => claimed.digest = "A".repeat(64),
            "nonhex-digest" => claimed.digest = "g".repeat(64),
            "unicode-digest" => claimed.digest = "é".repeat(32),
            _ => unreachable!(),
        }
        assert!(
            CheckedExtent::check(claimed, "/pool/objects/segments/000002.blob", observed).is_none(),
            "accepted {defect}"
        );
    }
}
