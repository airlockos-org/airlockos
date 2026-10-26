//! Job freshness includes durable approval state and every retained observation without JSON comparison.

use airlock_nix_core::job::JobSnapshot;
use serde_json::{Value, json};

/// A worker failure can still retain an earlier human approval and its protected review identity.
fn approved_failure() -> Value {
    json!({"request_id":"1".repeat(32), "status":"failed", "decision":"approved", "authorization_id":"a".repeat(64),
        "updated_at":1.5, "extension":{"progress":[1,2], "message":"retained"}})
}

/// Observed worker progress, authority and additional fields all invalidate a stale snapshot.
#[test]
fn job_equality_covers_identity_approval_phase_and_all_details() -> Result<(), serde_json::Error> {
    let original = approved_failure();
    let saved: JobSnapshot = serde_json::from_value(original.clone())?;
    assert_eq!(
        saved,
        serde_json::from_value::<JobSnapshot>(original.clone())?
    );
    for (field, value) in [
        ("request_id", json!("2".repeat(32))),
        ("authorization_id", json!("b".repeat(64))),
        ("status", json!("built")),
        ("decision", Value::Null),
        ("updated_at", json!(2.5)),
        ("extension", json!({"progress":[2,1], "message":"retained"})),
        ("new_detail", json!(true)),
    ] {
        let mut changed = original.clone();
        changed[field] = value;
        let current: JobSnapshot = serde_json::from_value(changed)?;
        assert_ne!(saved, current, "ignored {field}");
        assert_ne!(
            serde_json::to_value(&saved)?,
            serde_json::to_value(current)?
        );
    }
    Ok(())
}

/// Pending legacy omissions and explicit nulls normalize to the same validated state.
#[test]
fn canonical_job_state_preserves_legacy_optional_field_semantics() -> Result<(), serde_json::Error>
{
    let pending: JobSnapshot =
        serde_json::from_value(json!({"request_id":"1".repeat(32),"status":"queued"}))?;
    let explicit: JobSnapshot =
        serde_json::from_value(json!({"request_id":"1".repeat(32),"status":"queued",
        "decision":null,"authorization_id":null}))?;
    assert_eq!(pending, explicit);
    Ok(())
}
