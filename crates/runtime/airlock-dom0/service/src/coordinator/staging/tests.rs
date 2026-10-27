//! Endpoint-registry validation is exercised independently of filesystem and Qubes execution.

use super::*;

/// Construct inert v3 intent with one complete (empty) storage namespace per endpoint.
fn record() -> Record {
    let operation = json!({"id":"100", "authority":{"kind":"review_not_required"}});
    serde_json::from_value(json!({
        "id":"101", "boot_id":"00000000-0000-0000-0000-000000000001",
        "release":"/candidate", "previous":"/baseline", "revision":"a".repeat(40),
        "phase":"preflight", "plan":Plan::default(),
        "native_coordinator":"airlock-dom0-service-v3", "operation":operation,
        "release_fingerprint":"a".repeat(64), "previous_fingerprint":"b".repeat(64),
        "guest_generations":[
            {"operation":operation,"release":"/candidate","fingerprint":"a".repeat(64),"entries":[]},
            {"operation":operation,"release":"/baseline","fingerprint":"b".repeat(64),"entries":[]},
        ],
    })).unwrap()
}

/// Rollback changes direction, without dropping or rewriting either original target snapshot.
#[test]
fn both_endpoints_survive_direction_changes() -> Result<()> {
    let mut r = record();
    let original = serde_json::to_value(retained_snapshots(&r)?)?;
    assert_eq!(
        current_snapshot(&r)?.target,
        target(&r.release, &"a".repeat(64).parse()?)?
    );
    std::mem::swap(&mut r.release, &mut r.previous);
    let JournalOrigin::Native(native) = &mut r.metadata.origin else {
        unreachable!()
    };
    std::mem::swap(
        &mut native.release_fingerprint,
        &mut native.previous_fingerprint,
    );
    assert_eq!(serde_json::to_value(retained_snapshots(&r)?)?, original);
    assert_eq!(
        current_snapshot(&r)?.target,
        target(&r.release, &"b".repeat(64).parse()?)?
    );
    Ok(())
}

/// A corrupted registry cannot supply another endpoint, operation, scope or missing current target.
#[test]
fn invalid_endpoint_registry_fails_closed() {
    for change in [
        "operation",
        "authority",
        "release",
        "fingerprint",
        "duplicate",
        "missing",
        "empty",
    ] {
        let mut r = record();
        let s = r.metadata.details.guest_generations.as_mut().unwrap();
        match change {
            "operation" => s[0].operation.id = "999".to_owned().try_into().unwrap(),
            "authority" => s[0].operation.authority = OperationAuthority::Administrative,
            "release" => s[0].release = "/foreign".parse().unwrap(),
            "fingerprint" => s[0].fingerprint = "c".repeat(64).parse().unwrap(),
            "duplicate" => s[1] = s[0].clone(),
            "missing" => {
                s.remove(0);
            }
            _ => s.clear(),
        }
        assert!(current_snapshot(&r).is_err(), "accepted {change}");
    }
}
