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

/// Fake only the build tools; Git identity, native failure propagation, metadata parsing and the sender barrier remain real.
fn setup(peers: &mut Peers, failure: &str) -> Result<()> {
    fs::create_dir(peers.path("store"))?;

    peers.rules("make", json!([{"stdout": "path:/prepared-machine\n"}]))?;
    peers.rules(
        "stat",
        json!([{"contains": "%a", "stdout": "10000000\n"}, {"contains": "%S", "stdout": "4096\n"}]),
    )?;
    peers.rules("airlock-config-nix", json!([
        {"contains": "metadata", "exit": if failure == "preflight" {1} else {0}},
        {"contains": "build", "exit": match failure {"build" => 23, "interrupt" => 130, _ => 0},
            "stdout": if failure == "json" {"{invalid"} else {"[{\"outputs\":{\"out\":\"/nix/store/test-system\"}}]"}},
        {"contains": "path-info", "stdout": "[{\"path\":\"/nix/store/test-system\"}]", "exit": 24}
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
            fs::remove_dir(peers.path("store"))?;
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
        "/nix/store/test-system"
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
