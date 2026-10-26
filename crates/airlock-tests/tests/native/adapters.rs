//! Rust supplies Qubes-shaped Python objects, scenario data, assertions and native processes.

use crate::common;
use anyhow::Result;
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

/// Inspect native plugin properties against upstream-shaped Python objects.
fn adapter(directory: &Path, operation: &str, overrides: Value) -> Result<Value> {
    let modules = directory.join("python");
    if !modules.exists() {
        fs::create_dir(&modules)?;
        std::os::unix::fs::symlink(
            common::binary("AIRLOCK_QUBES_MODULE", "libairlock_qubes_native.so"),
            modules.join("airlock_qubes.so"),
        )?;
        std::os::unix::fs::symlink(
            common::binary(
                "AIRLOCK_QUBES_FIXTURE_MODULE",
                "examples/libqubes_objects.so",
            ),
            modules.join("qubes.so"),
        )?;
    }
    let mut request = json!({"pool":directory.join("pool with spaces"), "map":directory.join("map.json"), "operation":operation});
    request
        .as_object_mut()
        .unwrap()
        .extend(overrides.as_object().unwrap().clone());
    common::json(
        Command::new(common::binary(
            "AIRLOCK_QUBES_PROBE_BIN",
            "airlock-qubes-probe",
        ))
        .arg("storage-properties")
        .env("PYTHONPATH", modules)
        .env("AIRLOCK_QUBES_FIXTURE", "storage"),
        Some(serde_json::to_vec(&request)?),
    )
}

/// Native definition/accounting checks remain visible through the actual Python volume properties.
#[test]
fn qubes_properties_use_native_storage_checks() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path();
    let image = directory.join("metadata.img");
    fs::write(&image, b"immutable metadata")?;
    fs::set_permissions(&image, fs::Permissions::from_mode(0o444))?;
    let fields = json!({
        "fields": {
            "path": image,
            "view_kind": "metadata-image",
            "blob_map_path": null,
            "blob_logical_size": null,
            "manifest_path": null,
            "_size": 4096
        }
    });
    let reply = adapter(directory, "definition", fields.clone())?;
    let metadata = fs::metadata(&image)?;
    assert_eq!(
        reply["ok"],
        json!({"valid":true,"size":metadata.len(),"usage":metadata.blocks()*512})
    );
    let callbacks = adapter(directory, "callbacks", fields.clone())?;
    assert_eq!(callbacks["ok"]["same"], true);
    assert!(
        callbacks["ok"]["immutable"]
            .as_str()
            .unwrap()
            .contains("immutable")
    );
    fs::set_permissions(&image, fs::Permissions::from_mode(0o644))?;
    assert!(
        adapter(directory, "definition", fields)?["error"]
            .as_str()
            .unwrap()
            .contains("writable")
    );

    let map = directory.join("map.json");
    fs::write(&map, b"{}")?;
    let mut fields = json!({
        "fields": {
            "view_kind": "erofs-blob-map",
            "blob_map_path": map,
            "blob_logical_size": 4096,
            "manifest_path": null,
            "_size": 10
        }
    });
    assert_eq!(
        adapter(directory, "definition", fields.clone())?["ok"],
        json!({"valid":true,"size":4096,"usage":0})
    );
    fields["fields"]["blob_logical_size"] = json!(0);
    assert_eq!(
        adapter(directory, "definition", fields)?["exception"],
        "StoragePoolException"
    );

    let pool = directory.join("pool");
    let outside = directory.join("outside");
    fs::create_dir(&pool)?;
    fs::create_dir(&outside)?;
    fs::write(pool.join("value"), b"pool data")?;
    fs::write(outside.join("large"), b"outside data".repeat(10000))?;
    std::os::unix::fs::symlink(&outside, pool.join("link"))?;
    let expected = fs::read_dir(&pool)?
        .map(|entry| Ok(fs::symlink_metadata(entry?.path())?.blocks() * 512))
        .sum::<std::io::Result<u64>>()?;
    let reply = adapter(directory, "pool-accounting", json!({"pool":pool}))?;
    assert!(reply["ok"]["size"].as_u64().unwrap() > 0);
    assert_eq!(reply["ok"]["usage"], expected);
    let constructed = adapter(directory, "constructor", json!({}))?;
    assert_eq!(
        constructed["ok"]["vid"],
        "domains/usr-home-runtime-store/generations/3/store-data"
    );
    assert_eq!(constructed["ok"]["rw"], false);
    assert_eq!(constructed["ok"]["snap_on_start"], false);
    assert_eq!(constructed["ok"]["save_on_stop"], true);
    assert_eq!(constructed["ok"]["upstream_identity_preserved"], true);
    assert_eq!(constructed["ok"]["saved_transient_path"], false);
    assert!(constructed["ok"]["persisted"].get("view_path").is_none());
    assert_eq!(constructed["ok"]["persisted"]["generation"], "3");
    assert_eq!(constructed["ok"]["persisted"]["blob_logical_size"], 4096);
    for overrides in [
        json!({"rw":true}),
        json!({"snap_on_start":true}),
        json!({"source":"parent"}),
        json!({"generation":true}),
        json!({"blob_logical_size":0}),
        json!({"view_kind":"unknown"}),
    ] {
        let refused = adapter(directory, "constructor", json!({"constructor":overrides}))?;
        assert_eq!(refused["exception"], "StoragePoolException", "{overrides}");
    }
    let explicit_null = adapter(
        directory,
        "constructor",
        json!({"constructor":{"vid":null}}),
    )?;
    assert_eq!(explicit_null["ok"]["vid"], "store-data");
    assert!(
        explicit_null["ok"]["persisted"]
            .get("domain_name")
            .is_none()
    );

    Ok(())
}

/// Installation authorization compares a fresh locked snapshot and accepts stopped standalones only.
#[test]
fn qubes_installation_guard_uses_native_fresh_state() -> Result<()> {
    use airlock_tests::attachment::volume;

    let writable = ["root", "private"].map(|name| {
        volume(&json!({
            "name":name, "pool":"default", "vid":format!("usr-home/{name}"),
            "rw":true, "save_on_stop":true, "snap_on_start":false, "size":4096
        }))
    });
    let snapshot = json!({
        "klass":"StandaloneVM", "running":false, "power_state":"Halted", "domain":"usr-home",
        "features":{}, "pools":{}, "references":[], "volumes":writable,
    });
    let volumes = ["store", "store-data"].map(|name| {
        let mut definition = json!({
            "name":name, "pool":"airlock-closure", "vid":format!("domains/usr-home-runtime-store/generations/1/{name}"),
            "domain_name":"usr-home-runtime-store", "generation":"1", "closure_hash":"a".repeat(64),
            "manifest_path":"/pool/manifest.json", "rw":false, "snap_on_start":false,
            "save_on_stop":true, "source":null, "revisions_to_keep":0, "size":4096,
        });
        if name == "store" {
            definition["view_kind"] = json!("metadata-image");
            definition["view_path"] = json!("/pool/metadata.img");
        } else {
            definition["view_kind"] = json!("erofs-blob-map");
            definition["blob_map_path"] = json!("/pool/map.json");
            definition["blob_logical_size"] = json!(4096);
        }
        definition
    });
    let request = json!({
        "operation":"authorize-install", "domain":"usr-home", "snapshot":snapshot, "expected":snapshot,
        "pool":{"name":"airlock-closure", "driver":"airlock-closure", "root_dir":"/pool", "revisions_to_keep":0},
        "volumes":volumes,
    });
    let checked = airlock_dom0_service::storage_request(request.clone())?;
    assert_eq!(checked["volumes"], request["volumes"]);
    assert_eq!(checked["domain"], request["domain"]);
    let policy = airlock_dom0_service::storage_objects_policy();
    use airlock_qubes::storage::{Policy, Request};
    let mut worker = request.clone();
    worker["operation"] = json!("install");
    worker.as_object_mut().unwrap().remove("snapshot");
    let Request::Install(input) = airlock_dom0_service::storage_objects_request(worker.clone())?
    else {
        anyhow::bail!("installation decoded as a read-only request");
    };
    let installation = policy.authorize(input, &snapshot)?;
    assert_eq!(installation.plan().target(), "usr-home");
    assert_eq!(installation.pool().name(), "airlock-closure");
    assert_eq!(installation.pool().root(), "/pool");
    for damage in [
        "private",
        "unknown",
        "generation",
        "readonly",
        "extra-field",
        "target",
        "stale",
        "paused",
        "missing-power",
        "aliased",
    ] {
        let mut invalid = request.clone();
        match damage {
            "private" => invalid["volumes"][0]["name"] = json!("private"),
            "unknown" => invalid["volumes"][0]["name"] = json!("new-effect"),
            "generation" => invalid["volumes"][1]["generation"] = json!("2"),
            "readonly" => invalid["volumes"][0]["rw"] = json!(true),
            "extra-field" => invalid["volumes"][0]["unclassified"] = json!(true),
            "target" => invalid["domain"] = json!("other-vm"),
            "stale" => invalid["snapshot"]["running"] = json!(true),
            "paused" => {
                invalid["snapshot"]["power_state"] = json!("Paused");
                invalid["expected"] = invalid["snapshot"].clone();
            }
            "missing-power" => {
                invalid["snapshot"]
                    .as_object_mut()
                    .unwrap()
                    .remove("power_state");
                invalid["expected"] = invalid["snapshot"].clone();
            }
            _ => {
                invalid["snapshot"]["references"] = json!([{
                    "domain":"other-vm", "pool":"default", "vid":"usr-home/private", "source":null
                }]);
                invalid["expected"] = invalid["snapshot"].clone();
            }
        }
        assert!(
            airlock_dom0_service::storage_request(invalid).is_err(),
            "{damage}"
        );
    }

    let mut after = snapshot.clone();
    after["volumes"]
        .as_array_mut()
        .unwrap()
        .extend(volumes.iter().map(volume));
    let verification = json!({
        "operation":"verify-installed", "domain":"usr-home", "pool":request["pool"],
        "volumes":volumes, "before":snapshot, "after":after,
    });
    airlock_dom0_service::storage_request(verification.clone())?;
    policy.verify(&installation, &after)?;
    let mut replaced = verification;
    replaced["after"]["volumes"][1]["vid"] = json!("replacement-private");
    assert!(policy.verify(&installation, &replaced["after"]).is_err());
    assert!(airlock_dom0_service::storage_request(replaced).is_err());

    let mut stale = snapshot.clone();
    stale["features"]["external-change"] = json!("1");
    let Request::Install(input) = airlock_dom0_service::storage_objects_request(worker.clone())?
    else {
        unreachable!();
    };
    assert!(policy.authorize(input, &stale).is_err());
    worker["unclassified-effect"] = json!(true);
    assert!(airlock_dom0_service::storage_objects_request(worker).is_err());

    Ok(())
}

/// Offline image setup preserves Qubes identities and rejects adapter or snapshot failures.
#[test]
fn image_plan_and_reloaded_snapshot_are_checked() -> Result<()> {
    for scenario in [
        "", "inherit", "snapshot", "adapter", "existing", "volume", "property", "save", "reload",
    ] {
        let inherited = scenario == "inherit";
        let damage = if inherited { "" } else { scenario };
        let temporary = tempfile::tempdir()?;
        let directory = temporary.path();
        let tools = directory.join("tools");
        fs::create_dir(&tools)?;
        common::peer_link(&tools, "airlock-dom0-service")?;
        let modules = directory.join("python");
        fs::create_dir(&modules)?;
        std::os::unix::fs::symlink(
            common::binary(
                "AIRLOCK_QUBES_FIXTURE_MODULE",
                "examples/libqubes_objects.so",
            ),
            modules.join("qubes.so"),
        )?;
        let kernel = directory.join("kernel");
        fs::create_dir(&kernel)?;
        fs::write(kernel.join("vmlinuz"), b"kernel")?;
        let root_image = directory.join("root.img");
        fs::write(&root_image, b"fixture")?;
        let mut topology = json!({
            "schema":"airlock.qubes-topology.v1",
            "kernels": {
                "test-kernel": {
                    "source": kernel
                }
            },
            "prefs": {
                "default_netvm": null
            },
            "domains": {
                "usr-home": {
                    "class": "StandaloneVM",
                    "label": "green",
                    "netvm": null,
                    "prefs": {
                        "guivm": null,
                        "virt_mode": "hvm",
                        "autostart": false
                    },
                    "features": {
                        "qrexec": true
                    },
                    "services": {
                        "example": false
                    },
                    "devices": {
                        "pci": [
                            {
                                "backend": "dom0",
                                "id": "00_08.1"
                            }
                        ]
                    },
                    "backend": {
                        "type": "nix-closure",
                        "system": {
                            "source": "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-system"
                        },
                        "root": {
                            "source": "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-root/root.img"
                        },
                        "store": {
                            "source": "/nix/store/cccccccccccccccccccccccccccccccc-descriptors/usr-home",
                            "mode":"shared-closure", "mountpoint":"/nix/store",
                            "device":"/dev/xvde", "blobDevice":"/dev/xvdf", "viewBackend":"erofs-objectmap"
                        },
                        "kernel": {
                            "name": "test-kernel"
                        },
                        "state": {
                            "persistent_size": 33554432
                        }
                    }
                }
            }
        });
        if inherited {
            topology["domains"]["usr-home"]
                .as_object_mut()
                .unwrap()
                .remove("netvm");
            topology["domains"]["usr-home"]["prefs"]
                .as_object_mut()
                .unwrap()
                .remove("guivm");
        }
        let config = directory.join("topology.json");
        fs::write(&config, serde_json::to_vec(&topology)?)?;
        let output = directory.join("output");
        if damage == "existing" {
            fs::create_dir(&output)?;
            fs::write(output.join("keep"), b"existing")?;
        }
        let executable = std::env::var_os("AIRLOCK_IMAGE_BIN_DIR")
            .map(PathBuf::from)
            .map(|path| path.join("airlock-prepare-runtime"))
            .unwrap_or_else(|| {
                common::binary("AIRLOCK_PREPARE_RUNTIME_BIN", "airlock-prepare-runtime")
            });
        let result = common::run(
            Command::new(executable)
                .arg(&config)
                .arg(directory.join("pool"))
                .arg(&output)
                .env(
                    "PATH",
                    std::env::join_paths(
                        std::iter::once(tools)
                            .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
                    )?,
                )
                .env("PYTHONPATH", &modules)
                .env("AIRLOCK_QUBES_FIXTURE", "image")
                .env("PYTHONNOUSERSITE", "1")
                .env("PYTHONSAFEPATH", "1")
                .env("AIRLOCK_TEST_IMAGE_CLOSES", directory.join("closes.jsonl"))
                .env("AIRLOCK_TEST_IMAGE_PLAN", directory.join("plan.json"))
                .env("AIRLOCK_TEST_IMAGE_RELOAD", directory.join("reload.json"))
                .env("AIRLOCK_TEST_IMAGE_DAMAGE", damage)
                .env("AIRLOCK_TEST_IMAGE_ROOT", &root_image)
                .env("AIRLOCK_TEST_IMAGE_CALLS", directory.join("calls")),
            None,
        )?;
        if !damage.is_empty() {
            assert!(!result.status.success(), "{damage}");
            assert!(!output.join("receipt.json").exists());
            if matches!(
                damage,
                "adapter" | "volume" | "property" | "save" | "reload"
            ) {
                assert!(
                    String::from_utf8_lossy(&result.stderr)
                        .contains(&format!("upstream {damage} failed"))
                );
            }
            if matches!(
                damage,
                "snapshot" | "volume" | "property" | "save" | "reload"
            ) {
                let closes = fs::read_to_string(directory.join("closes.jsonl"))?;
                assert_eq!(
                    closes.lines().count(),
                    if damage == "snapshot" { 2 } else { 1 }
                );
            }
            if damage == "existing" {
                assert_eq!(fs::read(output.join("keep"))?, b"existing");
                assert!(!directory.join("calls").exists());
            }
            continue;
        }
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let plan: Value = serde_json::from_slice(&fs::read(directory.join("plan.json"))?)?;
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(directory.join("reload.json"))?)?,
            json!({"offline":true,"closed":true,"saved":true,"initial_offline":true})
        );
        let calls: Vec<Value> = fs::read_to_string(directory.join("calls"))?
            .lines()
            .map(serde_json::from_str)
            .collect::<std::result::Result<_, _>>()?;
        let verified = calls
            .iter()
            .find(|call| {
                call["args"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("verify-snapshot"))
            })
            .unwrap();
        assert_eq!(
            verified["request"]["source"],
            "/nix/store/cccccccccccccccccccccccccccccccc-descriptors/usr-home"
        );
        let snapshot = &verified["request"]["snapshot"];
        assert_eq!(snapshot["domain"], "usr-home");
        assert_eq!(snapshot["klass"], "StandaloneVM");
        assert_eq!(snapshot["running"], false);
        assert_eq!(snapshot["volumes"].as_array().unwrap().len(), 3);
        assert_eq!(
            snapshot["pools"]["airlock-closure"]["name"],
            "airlock-closure"
        );
        assert_eq!(
            fs::read_to_string(directory.join("closes.jsonl"))?
                .lines()
                .count(),
            2
        );
        let domain = &plan["domains"][0];
        assert_eq!(domain["uuid"], "738a6af9-8e51-590d-afe4-790b26fbca79");
        assert_eq!(domain["features"]["qrexec"], "1");
        assert_eq!(domain["features"]["service.example"], "");
        assert_eq!(domain["features"]["airlock-store-generation"], "7");
        assert_eq!(domain["netvm_inherited"], inherited);
        assert_eq!(domain["guivm_inherited"], inherited);
        if !inherited {
            assert_eq!(domain["features"]["fixture-root-ready"], "1");
            assert_eq!(domain["features"]["fixture-private-ready"], "33554432");
        }
        assert_eq!(domain["features"]["fixture-class"], "StandaloneVM");
        assert!(domain.get("devices").is_none());
        assert_eq!(
            fs::read(output.join("qubes/vm-kernels/test-kernel/vmlinuz"))?,
            b"kernel"
        );
        assert_eq!(
            fs::read_link(output.join("pool-selections/domains/usr-home-runtime-store/current"))?,
            Path::new("generations/7")
        );
        assert!(
            !fs::read_to_string(output.join("qubes/qubes.xml"))?.contains(output.to_str().unwrap())
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(output.join("receipt.json"))?)?["hardware_assignments"],
            "deferred-to-boot"
        );
    }
    Ok(())
}
