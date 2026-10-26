//! Snapshot freshness preserves every decoded field, literal path spelling and ordered resource list.

use super::*;
use serde_json::json;

/// A persisted snapshot includes both runtime evidence and opaque upstream configuration.
fn record() -> Value {
    json!({"domain":"usr-home", "klass":"StandaloneVM", "running":false, "power_state":"Halted",
    "features":{"generation":"1","extra":"retained"},
    "pools":{"file":{"driver":"file","extension":{"keep":true}}},
    "volumes":[
        {"name":"root","pool":"file","vid":"root","rw":true,"snap_on_start":false,
            "save_on_stop":true,"source":null,"generation":"1","closure_hash":"hash",
            "path":"/pool/root.img","blob_map_path":"/pool/root.map","size":4096,
            "config":{"driver_extra":{"keep":true}}},
        {"name":"private","pool":"file","vid":"private","rw":true,"snap_on_start":false,
            "save_on_stop":true,"source":null,"size":8192,"config":{}}
    ],
    "references":[
        {"domain":"usr-one","pool":"file","vid":"other-one","source":null},
        {"domain":"usr-two","pool":"file","vid":"other-two","source":{"pool":"base","vid":"parent"}}
    ]})
}

/// Snapshot-level observations and retained upstream metadata all participate in freshness checks.
#[test]
fn every_snapshot_observation_and_order_remains_significant() -> Result<()> {
    let original = record();
    let saved: Snapshot = serde_json::from_value(original.clone())?;
    for (field, changed) in [
        ("domain", json!("usr-other")),
        ("klass", json!("AppVM")),
        ("running", json!(true)),
        ("power_state", json!("Paused")),
        ("features", json!({"generation":"1","extra":"changed"})),
        (
            "pools",
            json!({"file":{"driver":"file","extension":{"keep":false}}}),
        ),
        ("references", json!([])),
    ] {
        let mut altered = original.clone();
        altered[field] = changed;
        let current: Snapshot = serde_json::from_value(altered)?;
        assert_ne!(saved, current, "ignored {field}");
    }
    for field in ["volumes", "references"] {
        let mut altered = original.clone();
        altered[field].as_array_mut().unwrap().reverse();
        assert_ne!(
            saved,
            serde_json::from_value::<Snapshot>(altered)?,
            "ignored {field} order"
        );
    }
    Ok(())
}

/// Every live or persisted volume field remains covered, including opaque driver extensions.
#[test]
fn complete_volume_identity_and_driver_metadata_are_compared() -> Result<()> {
    let original = record();
    let saved: Snapshot = serde_json::from_value(original.clone())?;
    for (field, changed) in [
        ("name", json!("store")),
        ("pool", json!("other")),
        ("vid", json!("other-root")),
        ("rw", json!(false)),
        ("snap_on_start", json!(true)),
        ("save_on_stop", json!(false)),
        ("source", json!({"pool":"base","vid":"derived"})),
        ("generation", json!("2")),
        ("closure_hash", json!("changed")),
        ("path", json!("/pool/other.img")),
        ("blob_map_path", json!("/pool/other.map")),
        ("size", json!(8192)),
        ("config", json!({"driver_extra":{"keep":false}})),
    ] {
        let mut altered = original.clone();
        altered["volumes"][0][field] = changed;
        let current: Snapshot = serde_json::from_value(altered)?;
        assert_ne!(saved, current, "ignored volume {field}");
        // Compatibility evidence only: production never serializes for equality.
        assert_ne!(
            serde_json::to_value(&saved)?,
            serde_json::to_value(current)?
        );
    }
    Ok(())
}

/// Path aliases must not hide a changed observation; legacy omitted power remains explicit absence.
#[test]
fn literal_paths_and_legacy_absence_preserve_serialized_comparison_semantics() -> Result<()> {
    let original = record();
    let saved: Snapshot = serde_json::from_value(original.clone())?;
    for (field, alias) in [
        ("path", "/pool/./root.img"),
        ("blob_map_path", "/pool//root.map"),
    ] {
        assert_eq!(
            PathBuf::from(original["volumes"][0][field].as_str().unwrap()),
            PathBuf::from(alias)
        );
        let mut altered = original.clone();
        altered["volumes"][0][field] = json!(alias);
        assert_ne!(saved, serde_json::from_value::<Snapshot>(altered)?);
    }
    let mut absent = original.clone();
    absent.as_object_mut().unwrap().remove("power_state");
    let mut null = absent.clone();
    null["power_state"] = Value::Null;
    assert_eq!(
        serde_json::from_value::<Snapshot>(absent)?,
        serde_json::from_value::<Snapshot>(null)?
    );
    assert_eq!(saved, serde_json::from_value::<Snapshot>(original)?);
    Ok(())
}
