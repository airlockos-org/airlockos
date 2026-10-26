//! The native Qubes object worker installs exact native storage definitions and persists subsequent generation changes.

use crate::common::{self, peers::Peers, store::Store};
use anyhow::Result;
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
    process::Command,
};

/// Preserve the complete native-to-upstream-object-to-native round trip with all scenario decisions and assertions in Rust.
#[test]
fn storage_bridge_persists_volume_identity_across_generation_switches() -> Result<()> {
    let mut store = Store::new()?;
    let mut peers = Peers::new()?;
    let nix_root = peers.path("nix-root");
    let physical = nix_root.join("nix/store");
    fs::create_dir_all(physical.parent().unwrap())?;
    fs::rename(&store.physical, &physical)?;
    store.physical = physical;
    let root = format!("/nix/store/{hash}-root", hash = "f".repeat(32));
    let root_image = store
        .physical
        .join(root.rsplit('/').next().unwrap())
        .join("root.img");
    fs::create_dir_all(root_image.parent().unwrap())?;
    fs::copy(&store.root, root_image)?;
    let mut systems = Vec::new();
    let mut closures = Vec::new();
    for (index, (system_hash, unique_hash)) in [("b", "c"), ("d", "e")].into_iter().enumerate() {
        let system = format!("/nix/store/{hash}-system", hash = system_hash.repeat(32));
        let unique = format!("/nix/store/{hash}-unique", hash = unique_hash.repeat(32));
        for logical in [&system, &unique] {
            let directory = store.physical.join(logical.rsplit('/').next().unwrap());
            fs::create_dir(&directory)?;
            fs::write(directory.join("payload"), logical.repeat(32))?;
        }
        let closure = peers.path(format!("closure-{index}"));
        fs::create_dir(&closure)?;
        fs::write(
            closure.join("store-paths"),
            format!("{common}\n{system}\n{unique}\n", common = store.system),
        )?;
        fs::write(closure.join("manifest.json"), "{}")?;
        systems.push(system);
        closures.push(closure);
    }
    // Prepare real immutable builder generations, retaining the predecessor as an image does.
    let mut builder_specs = Vec::new();
    let mut builder_paths = std::collections::BTreeSet::new();
    for (index, closure) in closures.iter().enumerate() {
        builder_paths.extend(
            fs::read_to_string(closure.join("store-paths"))?
                .lines()
                .map(str::to_owned),
        );
        let source = peers.path(format!("builder-{index}"));
        fs::create_dir(&source)?;
        fs::write(source.join("manifest.json"), "{}")?;
        fs::write(
            source.join("store-paths"),
            builder_paths
                .iter()
                .map(|path| format!("{path}\n"))
                .collect::<String>(),
        )?;
        fs::write(
            source.join("registration"),
            builder_paths
                .iter()
                .map(|path| format!("{path}\n{hash}\n42\n\n0\n", hash = "0".repeat(64)))
                .collect::<String>(),
        )?;
        builder_specs.push(json!({"name":format!("builder-{index}"), "domain":"usr-assistant-build-store", "system":systems[index], "closure_source":source, "physical_store_root":store.physical, "root_source":"", "kernel_name":"", "builder":true}));
    }
    let specs = peers.path("builder-specs.json");
    fs::write(&specs, serde_json::to_vec(&builder_specs)?)?;
    common::run(
        store
            .command(&["image", "prepare-pool"])
            .arg(&store.pool)
            .arg(peers.path("builder-descriptors"))
            .arg(&specs)
            .arg(&store.pool),
        None,
    )?
    .checked()?;
    let descriptor = store.pool.join("builders/usr-assistant.json");
    let manifest = |generation| {
        store.pool.join(format!(
            "domains/usr-assistant-build-store/generations/{generation}/manifest.json"
        ))
    };
    let read =
        |path: &std::path::Path| -> Result<Value> { Ok(serde_json::from_slice(&fs::read(path)?)?) };
    let predecessor = read(&manifest(1))?;
    let mut identity = read(&descriptor)?;
    identity["predecessors"] = json!([{
        "generation":1, "closure_hash":predecessor["builder"]["closure_hash"],
        "registration_sha256":predecessor["builder"]["registration_sha256"]
    }]);
    let mut successor_manifest = read(&manifest(2))?;
    successor_manifest["builder"] = identity.clone();
    fs::write(manifest(2), serde_json::to_vec(&successor_manifest)?)?;
    fs::write(&descriptor, serde_json::to_vec(&identity)?)?;
    let withheld = peers.path("builder-withheld.json");
    fs::rename(&descriptor, &withheld)?;
    peers.rules(
        "systemctl",
        json!([
            {"prefix": ["show"], "stdout_file": "systemctl.state"},
            {"prefix": ["stop"], "write": {"systemctl.state": "inactive"}},
            {"prefix": ["start"], "write": {"systemctl.state": "active"}}
        ]),
    )?;
    fs::write(peers.path("systemctl.state"), "active")?;
    symlink(&store.service, peers.path("bin/airlock-dom0-service"))?;
    let modules = peers.path("python");
    fs::create_dir(&modules)?;
    symlink(
        common::binary("AIRLOCK_QUBES_MODULE", "libairlock_qubes_native.so"),
        modules.join("airlock_qubes.so"),
    )?;
    symlink(
        common::binary(
            "AIRLOCK_QUBES_FIXTURE_MODULE",
            "examples/libqubes_objects.so",
        ),
        modules.join("qubes.so"),
    )?;
    let command = |args: &[&str]| -> Result<Command> {
        let mut command = peers.command(&store.service)?;
        store.environment(&mut command);
        command
            .args(["storage", "domain"])
            .args(args)
            .env("PYTHONPATH", &modules)
            .env("AIRLOCK_QUBES_FIXTURE", "storage")
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .env("AIRLOCK_NIX_ROOT", &nix_root)
            .env("AIRLOCK_CLOSURE_STORE_VERIFY", "tree")
            .env("AIRLOCK_FAKE_QUBES_DOMAIN", "usr-assistant")
            .env("AIRLOCK_FAKE_QUBES_RUNNING", "0")
            .env("AIRLOCK_FAKE_QUBES_SAVE_JSON", peers.path("saved.json"))
            .env("AIRLOCK_FAKE_QUBES_STATE_JSON", peers.path("qubes.json"))
            .env("AIRLOCK_QUBES_STORAGE_STATE", peers.path("integration"));
        Ok(command)
    };
    let ensure = |index: usize| -> Result<Value> {
        let mut command = command(&["ensure-store", "usr-assistant"])?;
        command
            .arg(&closures[index])
            .arg(if index == 0 {
                "/approved"
            } else {
                "/approved-2"
            })
            .args([
                "--mode",
                "shared-closure",
                "--system",
                &systems[index],
                "--root",
                &root,
                "--kernel",
                if index == 0 { "kernel-a" } else { "kernel-b" },
                "--pool-root",
            ])
            .arg(&store.pool);
        let output = common::run(&mut command, None)?;
        anyhow::ensure!(
            output.status.success(),
            "storage ensure failed: {stdout}; {stderr}",
            stdout = String::from_utf8_lossy(&output.stdout),
            stderr = String::from_utf8_lossy(&output.stderr)
        );
        Ok(serde_json::from_slice(&output.stdout)?)
    };
    let first = ensure(0)?;
    assert_eq!(first["schema"], "airlock.nix-domain-storage.v1");
    assert_eq!(first["domain"], "usr-assistant");
    for field in [
        "pool_created",
        "volume_created",
        "view_created",
        "metadata_changed",
        "qubesd_restarted",
    ] {
        assert_eq!(first[field], true, "{field}");
    }
    assert_eq!(first["generation"], 1);
    assert_eq!(first["objects_total"], 3);
    assert_eq!(first["objects_admitted"], 0);
    assert_eq!(first["objects_reused"], 3);
    assert_eq!(
        PathBuf::from(first["metadata_image"].as_str().unwrap())
            .metadata()?
            .permissions()
            .mode()
            & 0o222,
        0
    );
    let saved = || -> Result<Value> {
        Ok(serde_json::from_slice(&fs::read(
            peers.path("qubes.json"),
        )?)?)
    };
    let state = saved()?;
    assert_eq!(
        state["pools"]["airlock-closure"]["driver"],
        "airlock-closure"
    );
    for (name, kind) in [
        ("store", "metadata-image"),
        ("store-data", "erofs-blob-map"),
    ] {
        let volume = &state["domains"]["usr-assistant"]["volume_config"][name];
        assert_eq!(volume["pool"], "airlock-closure");
        assert_eq!(volume["rw"], false);
        assert_eq!(volume["snap_on_start"], false);
        assert_eq!(volume["save_on_stop"], true);
        assert!(volume["source"].is_null());
        assert_eq!(volume["generation"], "1");
        assert_eq!(volume["view_kind"], kind);
    }
    let features = |receipt: &Value, source: &str| -> Result<()> {
        let mut state = saved()?;
        state["domains"]["usr-assistant"]["features"] = json!({"airlock-store-source": source, "airlock-store-mode": "shared-closure",
            "airlock-store-view-backend": receipt["view_backend"], "airlock-store-generation": receipt["generation"].to_string(),
            "airlock-store-closure-hash": receipt["closure_hash"], "airlock-store-view-image": receipt["view_image"], "airlock-store-blob-map": receipt["blob_map"]});
        fs::write(peers.path("qubes.json"), serde_json::to_vec(&state)?)?;
        Ok(())
    };
    features(&first, "/approved")?;
    let again = ensure(0)?;
    for field in [
        "volume_created",
        "view_created",
        "metadata_changed",
        "qubesd_restarted",
    ] {
        assert_eq!(again[field], false, "{field}");
    }

    // A builder-only attachment must report its actual daemon restart in the runtime receipt.
    fs::rename(&withheld, &descriptor)?;
    let pin = store
        .pool
        .join("running/usr-assistant-build-store/1/builder-persistent.json");
    let pinned = fs::read(&pin)?;
    let attached = ensure(0)?;
    assert_eq!(attached["metadata_changed"], true);
    assert_eq!(attached["qubesd_restarted"], true);
    assert_eq!(attached["qubesd_restart_required"], false);
    assert_eq!(
        attached["volumes_created"],
        json!(["builder-store", "builder-data"])
    );

    // Recreate the fresh-image boundary: successor already attached, predecessor still retained.
    fs::write(manifest(1), serde_json::to_vec(&predecessor)?)?;
    fs::create_dir_all(pin.parent().unwrap())?;
    fs::write(&pin, &pinned)?;
    let before = peers
        .calls()?
        .iter()
        .filter(|call| call["command"] == "systemctl")
        .count();
    let cleaned = ensure(0)?;
    assert_eq!(cleaned["qubesd_restarted"], false);
    assert_eq!(cleaned["metadata_changed"], false);
    assert_eq!(
        peers
            .calls()?
            .iter()
            .filter(|call| call["command"] == "systemctl")
            .count(),
        before
    );
    assert_eq!(read(&manifest(1))?["retention"]["retain"], false);
    assert!(!pin.exists());
    let successor = ensure(1)?;
    assert_eq!(successor["generation"], 2);
    assert_eq!(successor["objects_admitted"], 0);
    assert_eq!(successor["objects_reused"], 3);
    // Use actual admitted maps to verify the evidence helper's canonical-sharing proof.
    let evidence = peers.path("sharing.json");
    common::run(
        Command::new(common::binary(
            "AIRLOCK_TEST_REPORT_BIN",
            "airlock-test-report",
        ))
        .args([
            "sharing",
            "generation-reuse",
            "usr-assistant-1",
            "usr-assistant-2",
        ])
        .arg(first["blob_map"].as_str().unwrap())
        .arg(successor["blob_map"].as_str().unwrap())
        .arg(&evidence),
        None,
    )?
    .checked()?;
    let proof: Value = serde_json::from_slice(&fs::read(&evidence)?)?;
    assert_eq!(proof["common_object_count"], 1);
    assert_eq!(proof["left_unique_object_count"], 2);
    assert_eq!(proof["right_unique_object_count"], 2);
    assert_eq!(proof["same_canonical_segment_offset_and_hash"], true);

    let switch = || -> Result<Command> {
        let mut command = command(&["switch-store", "usr-assistant", "1", "--pool-root"])?;
        command.arg(&store.pool);
        Ok(command)
    };
    let running = common::run(switch()?.env("AIRLOCK_FAKE_QUBES_RUNNING", "1"), None)?;
    assert!(!running.status.success());
    assert!(String::from_utf8_lossy(&running.stdout).contains("domain is running"));
    // A failed first or second external call cannot reach database save. Retrying
    // starts from freshly loaded persisted state and must retain both writable disks.
    let before_failure = saved()?;
    for slot in ["store", "store-data"] {
        let failed = common::run(
            switch()?.env("AIRLOCK_FAKE_QUBES_INSTALL_FAIL_VOLUME", slot),
            None,
        )?;
        assert!(!failed.status.success());
        assert_eq!(saved()?, before_failure);
        assert_eq!(fs::read_to_string(peers.path("systemctl.state"))?, "active");
    }
    let switched = common::json(&mut switch()?, None)?;
    assert_eq!(switched["generation"], 1);
    assert_eq!(switched["engine_current_generation"], 1);
    assert_eq!(switched["system"], systems[0]);
    assert_eq!(switched["kernel_name"], "kernel-a");
    for slot in ["root", "private"] {
        assert_eq!(
            saved()?["domains"]["usr-assistant"]["volume_config"][slot],
            before_failure["domains"]["usr-assistant"]["volume_config"][slot]
        );
    }
    features(&successor, "/approved-2")?;
    let repaired = ensure(1)?;
    assert_eq!(repaired["generation"], 2);
    assert_eq!(repaired["engine_current_generation"], 2);
    assert_eq!(repaired["objects_admitted"], 0);
    assert_eq!(repaired["objects_reused"], 3);
    assert_eq!(repaired["metadata_changed"], true);
    assert_eq!(repaired["qubesd_restarted"], true);
    let state = saved()?;
    let volumes = &state["domains"]["usr-assistant"]["volume_config"];
    assert_eq!(volumes["store"]["generation"], "2");
    assert_eq!(volumes["store"]["view_path"], successor["view_image"]);
    assert_eq!(
        volumes["store-data"]["blob_map_path"],
        successor["blob_map"]
    );
    let actions = peers
        .calls()?
        .into_iter()
        .filter(|call| call["command"] == "systemctl")
        .filter_map(|call| call["args"][0].as_str().map(str::to_owned))
        .filter(|action| ["start", "stop"].contains(&action.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(actions, ["stop", "start"].repeat(5));
    Ok(())
}
