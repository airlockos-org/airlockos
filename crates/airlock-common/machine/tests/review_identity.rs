//! Typed review equality retains protected source fields, baseline and unclassified metadata.

use airlock_machine_core::model::ReviewBinding;
use anyhow::Result;
use serde_json::{Value, json};

/// A guest review binds an immutable revision, lock and complete extension metadata.
fn binding() -> Value {
    json!({"revision":"a".repeat(40), "lock_hash":"b".repeat(64), "family":"guest",
        "target":"usr-home", "extension":{"nested":[1,2], "label":"retained"}})
}

/// Source, target, baseline and all extension differences prevent reuse of another review context.
#[test]
fn review_reuse_requires_the_complete_binding_and_original_baseline() -> Result<()> {
    let original = binding();
    let saved: ReviewBinding = serde_json::from_value(original.clone())?;
    let baseline = "c".repeat(64).parse()?;
    let unchanged: ReviewBinding = serde_json::from_value(original.clone())?;
    assert_eq!(saved, unchanged);
    assert!(saved.matches_context(&baseline, &unchanged, &baseline));
    assert!(!saved.matches_context(&baseline, &unchanged, &"d".repeat(64).parse()?));
    for (field, value) in [
        ("revision", json!("d".repeat(40))),
        ("lock_hash", json!("d".repeat(64))),
        ("target", json!("usr-other")),
        ("extension", json!({"nested":[2,1], "label":"retained"})),
        ("new_extension", json!(true)),
    ] {
        let mut changed = original.clone();
        changed[field] = value;
        let changed: ReviewBinding = serde_json::from_value(changed)?;
        assert_ne!(saved, changed, "ignored {field}");
        assert!(!saved.matches_context(&baseline, &changed, &baseline));
        assert_ne!(
            serde_json::to_value(&saved)?,
            serde_json::to_value(changed)?
        );
    }
    let mut machine = original;
    machine["family"] = json!("machine");
    machine["target"] = Value::Null;
    let machine: ReviewBinding = serde_json::from_value(machine)?;
    assert_ne!(saved, machine);
    assert!(!saved.matches_context(&baseline, &machine, &baseline));
    Ok(())
}

/// Flattened metadata must never shadow the actual source coordinates used by typed decisions.
#[test]
fn shadowing_extensions_cannot_make_different_protected_identities_equal() -> Result<()> {
    let mut left: ReviewBinding = serde_json::from_value(binding())?;
    let mut other = binding();
    other["revision"] = json!("d".repeat(40));
    let mut right: ReviewBinding = serde_json::from_value(other)?;
    left.extra.insert("revision".into(), json!("e".repeat(40)));
    right.extra.insert("revision".into(), json!("e".repeat(40)));
    assert_eq!(serde_json::to_value(&left)?, serde_json::to_value(&right)?);
    assert_ne!(left, right);
    let baseline = "c".repeat(64).parse()?;
    assert!(!left.matches_context(&baseline, &right, &baseline));
    Ok(())
}
