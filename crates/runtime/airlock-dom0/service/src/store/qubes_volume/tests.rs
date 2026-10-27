//! Exercise storage invariants directly, with all filesystem work in temporary directories.

use super::{Request, execute, filtered_device, normalize};
use serde_json::json;
use std::{fs, os::unix::fs::symlink, path::Path};

/// Mapper paths belong to an attachment, never the persisted Qubes configuration.
#[test]
fn normalization_preserves_immutable_metadata_without_transient_devices() {
    let domain = "usr-home".parse().unwrap();
    let config = json!({"name":"store-data", "generation":3,
        "view_kind":"erofs-blob-map", "view_path":"/dev/mapper/stale",
        "blob_map_path":"/pool/map.json", "blob_logical_size":"4096"});
    let result = normalize(Some(&domain), config.clone(), false).unwrap();
    assert_eq!(
        result["config"]["vid"],
        "domains/usr-home-runtime-store/generations/3/store-data"
    );
    assert_eq!(result["fields"]["domain_name"], "usr-home-runtime-store");
    assert_eq!(result["config"]["save_on_stop"], true);
    assert!(result["fields"]["view_path"].is_null());
    assert!(result["persisted"].get("view_path").is_none());
    assert_eq!(result["persisted"]["generation"], "3");
    assert_eq!(result["persisted"]["blob_logical_size"], 4096);

    for field in ["rw", "snap_on_start"] {
        let mut invalid = config.clone();
        invalid[field] = json!(true);
        assert!(normalize(Some(&domain), invalid, false).is_err());
    }
    assert!(normalize(Some(&domain), config, true).is_err());
}

/// Resolve real temporary symlinks to catch mapper aliases of global backing bytes.
#[test]
fn filtered_devices_reject_backing_aliases_and_unfiltered_paths() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    fs::create_dir(root.join("mapper")).unwrap();
    fs::write(root.join("filtered"), "filtered extents").unwrap();
    fs::write(root.join("backing"), "global storage").unwrap();
    symlink("../filtered", root.join("mapper/safe")).unwrap();
    symlink("../backing", root.join("mapper/alias")).unwrap();
    let resolve = |path: &Path| fs::canonicalize(root.join(path.strip_prefix("/dev").unwrap()));
    let reply = |device: &str| json!({"device": device, "backing_paths":["/dev/backing"]});

    assert_eq!(
        filtered_device(reply("/dev/mapper/safe"), resolve).unwrap(),
        Path::new("/dev/mapper/safe")
    );
    assert!(
        filtered_device(reply("/dev/mapper/alias"), resolve)
            .unwrap_err()
            .to_string()
            .contains("backing storage")
    );
    for device in [
        "/dev/backing",
        "/dev/mapper/nested/device",
        "/dev/mapper/../backing",
    ] {
        assert!(
            filtered_device(reply(device), resolve).is_err(),
            "device: {device}"
        );
    }

    for malformed in [
        json!({"backing_paths":[]}),
        json!({"device":"/dev/mapper/safe"}),
        json!({"device":"/dev/mapper/safe", "backing_paths":[false]}),
    ] {
        assert!(filtered_device(malformed, resolve).is_err());
    }
}

/// An invalid view must fail before attachment or a running generation is recorded.
#[test]
fn failed_start_does_not_pin_a_generation() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("pool");
    let request: Request = serde_json::from_value(json!({
        "action":"start", "root":root, "domain":"usr-home", "generation":"1",
        "name":"store-data", "view_kind":"erofs-blob-map",
        "blob_map_path":directory.path().join("missing-map"), "blob_logical_size":4096
    }))
    .unwrap();
    assert!(execute(request).is_err());
    assert!(!root.join("running/usr-home").exists());
    assert!(!root.join("domains/usr-home").exists());
}
