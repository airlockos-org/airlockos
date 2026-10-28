//! Build orchestration must stop before sending artifacts when preflight, the builder or closure metadata fails.

use crate::common::{self, peers::Peers};
use airlock_tests::repository::{Repository, git};
use anyhow::Result;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs, os::unix::fs::PermissionsExt};

/// Run the installed native worker with isolated source, store and manifest paths.
fn command(peers: &Peers) -> Result<std::process::Command> {
    let mut command = peers.command(
        common::binary("AIRLOCK_VM_SERVICE_BIN", "airlock-vm-service")
            .to_str()
            .unwrap(),
    )?;
    command
        .arg("worker")
        .arg("--repo")
        .arg(peers.path("repo"))
        .arg("--state")
        .arg(peers.path("state"))
        .arg("--cache")
        .arg(peers.path("cache"))
        .arg("--store")
        .arg(peers.path("store"))
        .arg("--offline-inputs")
        .arg(peers.path("inputs.json"));
    Ok(command)
}

/// Populate the separate outputs of a built guest bundle in the private store.
fn guest_outputs(peers: &Peers) -> Result<serde_json::Value> {
    let object = |name: &str| format!("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-{name}");
    let artifacts = json!({
        "domain": "usr-home", "system": object("test-system"),
        "root_source": format!("{root}/root.img", root = object("root")),
        "root_metadata": format!("{metadata}/root.json", metadata = object("root-metadata")),
        "closure_source": object("closure"), "kernel_name": "fixture-kernel"
    });
    let root = json!({
        "schema":"airlock.root-artifact.v1", "sha256":"a".repeat(64),
        "logical_bytes":4096, "payload_bytes":128,
        "format":"ext4", "boot_abi":"airlock.nix-closure-root.v1"
    });
    for (path, bytes) in [
        (
            object("guest-artifacts.json"),
            serde_json::to_vec(&artifacts)?,
        ),
        (
            artifacts["root_metadata"].as_str().unwrap().into(),
            serde_json::to_vec(&root)?,
        ),
        (
            artifacts["root_source"].as_str().unwrap().into(),
            vec![0; 4096],
        ),
        (
            format!("{closure}/store-paths", closure = object("closure")),
            format!("{system}\n", system = object("test-system")).into_bytes(),
        ),
    ] {
        let physical = peers.path("store").join(path.trim_start_matches('/'));
        fs::create_dir_all(physical.parent().unwrap())?;
        fs::write(physical, bytes)?;
    }
    Ok(root)
}

/// Fake only the build tools; Git identity, native failure propagation, metadata parsing and the sender barrier remain real.
fn setup(peers: &mut Peers, failure: &str) -> Result<()> {
    fs::create_dir(peers.path("store"))?;
    guest_outputs(peers)?;
    if failure == "closure" {
        fs::remove_file(
            peers.path("store/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-closure/store-paths"),
        )?;
    }

    peers.rules("make", json!([{"stdout": "path:/prepared-machine\n"}]))?;
    peers.rules(
        "stat",
        json!([{"contains": "%a", "stdout": "10000000\n"}, {"contains": "%S", "stdout": "4096\n"}]),
    )?;
    peers.rules("airlock-config-nix", json!([
        {"contains": "metadata", "exit": if failure == "preflight" {1} else {0}},
        {"contains": "path:/prepared-machine#nixosConfigurations.airlock-domain-usr-home.config.system.build.airlockGuestArtifacts", "exit": match failure {"build" => 23, "interrupt" => 130, _ => 0},
            "stdout": if failure == "json" {"{invalid"} else {"[{\"outputs\":{\"out\":\"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-guest-artifacts.json\"}}]"}},
        {"contains": "build", "exit": match failure {"build" => 23, "interrupt" => 130, _ => 0},
            "stdout": if failure == "json" {"{invalid"} else {"[{\"outputs\":{\"out\":\"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test-system\"}}]"}},
        {"contains": "path-info", "stdout": "[{\"path\":\"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test-system\"}]", "exit": 24}
    ]))?;
    peers.rules("airlock", json!([{"write": {"unexpected-send": "sent"}}]))
}

/// Preflight/build/interruption/JSON/closure failures cannot cross the artifact sender boundary, even with partial valid-looking output.
#[test]
fn assistant_admission_stops_before_sending_on_failure() -> Result<()> {
    let source = Repository::new()?;
    let machine = source.root.join("airlock-machine");
    for failure in [
        "store-missing",
        "store-file",
        "preflight",
        "build",
        "interrupt",
        "json",
        "closure",
    ] {
        let mut peers = Peers::new()?;
        setup(&mut peers, failure)?;
        if matches!(failure, "store-missing" | "store-file") {
            fs::remove_dir_all(peers.path("store"))?;
            if failure == "store-file" {
                fs::write(peers.path("store"), b"not a mounted store")?;
            }
        }

        let mut command = command(&peers)?;
        command
            .args(["build", "admit", "usr-home"])
            .env("AIRLOCK_MACHINE_REPO", &machine)
            .env("AIRLOCK_MACHINE_BUILD_STATE", peers.path("state"))
            .env("AIRLOCK_CONFIG_NIX_STORE_ROOT", peers.path("store"));
        let result = common::run(&mut command, None)?;
        assert!(!result.status.success(), "{failure}");
        assert!(!peers.path("unexpected-send").exists());
        if matches!(failure, "store-missing" | "store-file") {
            assert!(peers.calls()?.is_empty());
            assert!(
                String::from_utf8_lossy(&result.stderr)
                    .contains("private Nix store root is missing or not a directory")
            );
        }
        if failure != "closure" {
            assert!(!peers.calls()?.iter().any(|call| {
                call["args"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("path-info"))
            }));
        }
        if failure == "build" {
            assert_eq!(result.status.code(), Some(23));
        }
        if failure == "interrupt" {
            assert_eq!(result.status.code(), Some(130));
        }
    }
    Ok(())
}

/// Offline builds preserve protected mount permissions, pass exact pinned inputs and reject a changed lock.
#[test]
fn assistant_offline_build_binds_input_lock() -> Result<()> {
    let source = Repository::new()?;
    let machine = source.root.join("airlock-machine");
    let mut peers = Peers::new()?;
    setup(&mut peers, "")?;
    let input = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source";
    fs::create_dir_all(peers.path("store").join(input.trim_start_matches('/')))?;
    fs::set_permissions(peers.path("store"), fs::Permissions::from_mode(0o555))?;
    let hash = format!(
        "{hash:x}",
        hash = Sha256::digest(fs::read(machine.join("flake.lock"))?)
    );
    let mut manifest = json!({"schema": "airlock.sys-agent-offline-inputs.v1", "lock_hash": hash, "inputs": {"nixpkgs": input}});
    fs::write(peers.path("inputs.json"), serde_json::to_vec(&manifest)?)?;
    let execute = || -> Result<airlock_vm_service::support::Output> {
        let mut command = command(&peers)?;
        command
            .args(["build", "build", "--offline"])
            .env("AIRLOCK_MACHINE_REPO", &machine)
            .env("AIRLOCK_MACHINE_BUILD_STATE", peers.path("state"))
            .env("AIRLOCK_CONFIG_NIX_STORE_ROOT", peers.path("store"));
        common::run(&mut command, None)
    };
    assert_eq!(
        String::from_utf8(execute()?.checked()?)?.trim(),
        "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test-system"
    );
    let store_mode = fs::metadata(peers.path("store"))?.permissions().mode() & 0o777;
    fs::set_permissions(peers.path("store"), fs::Permissions::from_mode(0o755))?;
    assert_eq!(
        store_mode, 0o555,
        "preflight must preserve the builder service's protected mount hierarchy"
    );

    let calls = peers.calls()?;
    let args = calls
        .iter()
        .find(|call| call["args"].as_array().unwrap().contains(&json!("build")))
        .unwrap()["args"]
        .as_array()
        .unwrap();
    for option in [
        "--offline",
        "--no-write-lock-file",
        "--override-input",
        "nixpkgs",
        &format!("path:{input}"),
    ] {
        assert!(args.contains(&json!(option)));
    }
    manifest["lock_hash"] = json!("b".repeat(64));
    fs::write(peers.path("inputs.json"), serde_json::to_vec(&manifest)?)?;
    let count = calls
        .iter()
        .filter(|call| call["command"] == "airlock-config-nix")
        .count();
    let failure = execute()?;
    assert!(!failure.status.success());
    assert!(
        String::from_utf8_lossy(&failure.stderr).contains("differs from the image offline inputs")
    );
    assert_eq!(
        peers
            .calls()?
            .iter()
            .filter(|call| call["command"] == "airlock-config-nix")
            .count(),
        count
    );
    assert!(!git(&machine, &["rev-parse", "HEAD"])?.is_empty());
    Ok(())
}

/// The native store adapter preserves explicit overrides but refuses implicit fallback from a worker's pinned store.
#[test]
fn native_worker_store_selection_preserves_pinned_boundary() -> Result<()> {
    let mut peers = Peers::new()?;
    peers.rules("upstream-nix", json!([{"stdout":"selected\n"}]))?;
    let native = common::binary("AIRLOCK_VM_SERVICE_BIN", "airlock-vm-service");
    let execute = |pinned: bool, explicit: bool| -> Result<airlock_vm_service::support::Output> {
        let mut command = peers.command(native.to_str().unwrap())?;
        command
            .arg("nix")
            .arg("--executable")
            .arg(peers.path("bin/upstream-nix"))
            .arg("--root")
            .arg(peers.path("store"));
        if pinned {
            command.arg("--pinned");
        }
        command.arg("--");
        if explicit {
            command.args(["--store", "/explicit-alternate-store"]);
        }
        command.arg("--version");
        common::run(&mut command, None)
    };
    assert!(!execute(true, false)?.status.success());
    assert!(peers.calls()?.is_empty());
    execute(true, true)?.checked()?;
    let explicit = peers.calls()?;
    assert!(
        explicit[0]["args"]
            .as_array()
            .unwrap()
            .contains(&json!("/explicit-alternate-store"))
    );
    execute(false, false)?.checked()?;
    assert!(peers.path("store").is_dir());
    let calls = peers.calls()?;
    assert!(
        calls.last().unwrap()["args"]
            .as_array()
            .unwrap()
            .contains(&json!(peers.path("store")))
    );
    Ok(())
}

/// The real worker sends complete immutable artifacts and refuses a rootless or substituted receipt.
#[test]
fn assistant_admission_binds_boot_artifacts() -> Result<()> {
    let source = Repository::new()?;
    let machine = source.root.join("airlock-machine");
    let mut peers = Peers::new()?;
    setup(&mut peers, "")?;
    let root = guest_outputs(&peers)?;
    peers.rules(
        "installed-compiler",
        json!([{ "stdout": "path:/prepared-machine\n" }]),
    )?;
    let revision = git(&machine, &["rev-parse", "HEAD"])?;
    let lock = format!(
        "{digest:x}",
        digest = Sha256::digest(fs::read(machine.join("flake.lock"))?)
    );
    let mut receipt = json!({
        "schema":"airlock.closure-store.admission.v1", "status":"passed", "transport":"qrexec",
        "domain":"usr-home", "generation":2, "current_generation":1,
        "activated":false, "retained":true, "manifest":"/var/lib/airlock/generation.json",
        "system":"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test-system",
        "root_source":"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-root/root.img",
        "root_artifact":root, "kernel_name":"fixture-kernel", "closure_hash":"b".repeat(64),
        "source_revision":revision, "lock_hash":lock
    });
    let execute = |peers: &Peers| -> Result<airlock_vm_service::support::Output> {
        common::run(
            command(peers)?
                .arg("--compiler")
                .arg(peers.path("bin/installed-compiler"))
                .args(["build", "admit", "usr-home"])
                .env("AIRLOCK_MACHINE_REPO", &machine),
            None,
        )
    };
    peers.rules(
        "airlock",
        json!([{"stdout":serde_json::to_string(&receipt)?}]),
    )?;
    let accepted: airlock_nix_core::admission::AdmissionReceipt =
        serde_json::from_slice(&execute(&peers)?.checked()?)?;
    accepted.evidence()?;
    let calls = peers.calls()?;
    assert!(!calls.iter().any(|call| call["command"] == "make"));
    let send = calls
        .iter()
        .find(|call| call["command"] == "airlock")
        .unwrap();
    let args = send["args"].as_array().unwrap();
    for (flag, expected) in [
        ("--root-source", receipt["root_source"].as_str().unwrap()),
        (
            "--closure-source",
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-closure",
        ),
        ("--kernel-name", "fixture-kernel"),
    ] {
        let index = args.iter().position(|arg| arg == flag).unwrap();
        assert_eq!(args[index + 1], expected);
    }

    // A compiler cache miss must use the normal source-owned preparation path.
    peers.rules("installed-compiler", json!([{ "stdout": "" }]))?;
    receipt["root_artifact"] = serde_json::Value::Null;
    peers.rules(
        "airlock",
        json!([{"stdout":serde_json::to_string(&receipt)?}]),
    )?;
    assert!(!execute(&peers)?.status.success());
    assert!(peers.calls()?.iter().any(|call| call["command"] == "make"));

    // Malformed build metadata fails before another transfer, even if a sender would accept it.
    fs::write(
        peers.path("store/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-root-metadata/root.json"),
        "{}",
    )?;
    let before = peers.calls()?.len();
    assert!(!execute(&peers)?.status.success());
    assert!(
        !peers.calls()?[before..]
            .iter()
            .any(|call| call["command"] == "airlock")
    );
    Ok(())
}
