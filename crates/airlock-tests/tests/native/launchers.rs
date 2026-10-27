//! Fixed native launchers and RPC adapters retain literal arguments and independent admission checks.

use crate::common::{self, peers::Peers};
use anyhow::Result;
use serde_json::json;
use std::{fs, os::unix::fs::symlink};

/// A copied launcher uses its own contract even through an alias, preserving arguments, environment and exit status.
#[test]
fn native_launcher_preserves_contract_and_rejects_unauthorized_invocations() -> Result<()> {
    let mut peers = Peers::new()?;
    let launcher = peers.path("bin/fixed-operation");
    fs::copy(
        common::binary("AIRLOCK_EXEC_BIN", "airlock-exec"),
        &launcher,
    )?;
    let literal = "spaces ' ; $(never-execute)";
    peers.rules("operation", json!([{
        "args": [launcher, peers.path("bin").parent().unwrap(), literal, "--caller-option"],
        "env": {"AIRLOCK_TEST_PREFIX": "fixed:inherited", "AIRLOCK_TEST_FIXED": "fixed value", "AIRLOCK_TEST_REMOVED": null},
        "exit": 23
    }]))?;
    fs::write(
        peers.path("bin/fixed-operation.json"),
        serde_json::to_vec(&json!({
            "program": peers.path("bin/operation"),
            "args": ["@self@", "@prefix@", literal],
            "env": {"AIRLOCK_TEST_FIXED": "fixed value"},
            "prefix_env": {"AIRLOCK_TEST_PREFIX": "fixed"},
            "unset_env": ["AIRLOCK_TEST_REMOVED"],
            "callers": ["dom0"],
            "empty_service_argument": true,
            "argument_count": 1
        }))?,
    )?;
    let alias = peers.path("etc/qubes-rpc/airlock.Test");
    fs::create_dir_all(alias.parent().unwrap())?;
    symlink(&launcher, &alias)?;
    assert!(!alias.with_file_name("airlock.Test.json").exists());
    for (caller, service, arguments) in [
        ("", "", vec!["--caller-option"]),
        ("sys-gui", "", vec!["--caller-option"]),
        ("dom0", "unexpected", vec!["--caller-option"]),
        ("dom0", "", vec![]),
        ("dom0", "", vec!["--contract", "/other.json"]),
    ] {
        let output = common::run(
            peers
                .command(&alias)?
                .args(arguments)
                .env("QREXEC_REMOTE_DOMAIN", caller)
                .env("QREXEC_SERVICE_ARGUMENT", service),
            None,
        )?;
        assert!(!output.status.success());
        assert!(peers.calls()?.is_empty());
    }
    let output = common::run(
        peers
            .command(alias)?
            .arg("--caller-option")
            .env("QREXEC_REMOTE_DOMAIN", "dom0")
            .env("QREXEC_SERVICE_ARGUMENT", "")
            .env("AIRLOCK_TEST_PREFIX", "inherited")
            .env("AIRLOCK_TEST_FIXED", "caller value")
            .env("AIRLOCK_TEST_REMOVED", "secret"),
        None,
    )?;
    assert_eq!(
        output.status.code(),
        Some(23),
        "{stderr}",
        stderr = String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(peers.calls()?.len(), 1);
    Ok(())
}

/// The privileged receiver independently rejects a wrong caller, target and argument count before starting storage.
#[test]
fn admission_receiver_retains_independent_target_and_caller_checks() -> Result<()> {
    let mut peers = Peers::new()?;
    peers.rules("storage-receiver", json!([{
        "args": ["storage", "artifact", "receive-incremental", "--expected-domain", "usr-home", "--approved-by", "usr-assistant"]
    }]))?;
    for arguments in [
        vec!["usr-home", "wrong-caller"],
        vec!["other-vm", "usr-assistant"],
        vec!["usr-home"],
        vec!["usr-home", "usr-assistant", "extra"],
    ] {
        let output = common::run(
            peers
                .command(common::binary("AIRLOCK_DOM0_BIN", "airlock-dom0-service"))?
                .args([
                    "admission-adapter",
                    "receive",
                    "--caller",
                    "usr-assistant",
                    "--target",
                    "usr-home",
                    "--incremental",
                    "--service",
                ])
                .arg(peers.path("bin/storage-receiver"))
                .arg("--")
                .args(arguments),
            None,
        )?;
        assert!(!output.status.success());
        assert!(peers.calls()?.is_empty());
    }
    peers.run(
        peers
            .command(common::binary("AIRLOCK_DOM0_BIN", "airlock-dom0-service"))?
            .args([
                "admission-adapter",
                "receive",
                "--caller",
                "usr-assistant",
                "--target",
                "usr-home",
                "--incremental",
                "--service",
            ])
            .arg(peers.path("bin/storage-receiver"))
            .args(["--", "usr-home", "usr-assistant"]),
    )?;
    assert_eq!(peers.calls()?.len(), 1);
    Ok(())
}

/// LightDM-only arguments are removed while literal display arguments and the upstream X environment survive.
#[test]
fn login_xserver_retains_arguments_and_environment() -> Result<()> {
    let mut peers = Peers::new()?;
    peers.rules("display-probe", json!([{"args": ["-display", ":1"]}]))?;
    peers.rules("nested-xserver", json!([{
        "args": ["-sw-cursor", "-no-host-grab", "-output", "DUMMY0", ":0", "-auth", "literal auth path"],
        "env": {"DISPLAY": ":1", "XAUTHORITY": null, "LD_PRELOAD": "/fixture/preload.so"}
    }]))?;
    peers.run(
        peers
            .command(common::binary(
                "AIRLOCK_VM_SERVICE_BIN",
                "airlock-vm-service",
            ))?
            .args(["desktop", "login-xserver", "--probe"])
            .arg(peers.path("bin/display-probe"))
            .arg("--server")
            .arg(peers.path("bin/nested-xserver"))
            .args([
                "--preload",
                "/fixture/preload.so",
                "--",
                ":0",
                "vt7",
                "-logfile",
                "discarded path",
                "-seat",
                "seat0",
                "-novtswitch",
                "-auth",
                "literal auth path",
            ])
            .env("XAUTHORITY", "inherited"),
    )?;
    assert_eq!(peers.calls()?.len(), 2);
    Ok(())
}

/// Closure metadata preserves literal settings and counts the inventory without copying store objects.
#[test]
fn closure_manifest_preserves_settings_and_inventory() -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    let paths = root.join("store-paths");
    fs::write(&paths, "/nix/store/first\n/nix/store/second\n")?;
    let settings = json!({
        "name": "literal \"name\"", "root_paths": ["/nix/store/root"],
        "mountpoint": "/nix/store", "device": "/dev/xvde"
    });
    fs::write(root.join("settings.json"), serde_json::to_vec(&settings)?)?;
    let mut command = std::process::Command::new(common::binary(
        "AIRLOCK_PREPARE_BOOT_BIN",
        "airlock-prepare-boot",
    ));
    command
        .args(["manifest", "--out"])
        .arg(root.join("out"))
        .arg("--paths")
        .arg(&paths)
        .arg("--settings")
        .arg(root.join("settings.json"));
    common::run(&mut command, None)?.checked()?;
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("out/manifest.json"))?)?;
    assert_eq!(
        manifest,
        json!({
            "schema": "airlock.store-closure-manifest.v1", "name": settings["name"],
            "root_paths": settings["root_paths"], "store_paths_file": "store-paths", "object_count": 2,
            "mountpoint": settings["mountpoint"], "device": settings["device"], "read_only": true
        })
    );
    assert_eq!(fs::read(root.join("out/store-paths"))?, fs::read(paths)?);
    fs::write(root.join("settings.json"), "malformed")?;
    assert!(!common::run(&mut command, None)?.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&fs::read(root.join("out/manifest.json"))?)?,
        manifest
    );
    Ok(())
}

/// Read-only observation emits valid JSON and distinguishes an empty domain inventory from a failed query.
#[test]
fn observation_preserves_json_and_failed_probe_meaning() -> Result<()> {
    for failure in [false, true] {
        let mut peers = Peers::new()?;
        peers.rules(
            "hostname",
            json!([{"stdout": "host \"quoted\"\nsecond line\n"}]),
        )?;
        peers.rules("uname", json!([{"args": ["-r"], "stdout": "kernel\n"}, {"args": ["-m"], "stdout": "architecture\n"}]))?;
        peers.rules(
            "systemd-detect-virt",
            json!([{"stdout": "none\n", "exit": 1}]),
        )?;
        peers.rules("xl", json!([{"stdout": "xen_version : 4.19\n"}]))?;
        peers.rules("qvm-ls", json!([{"args": ["--raw-data", "--fields", "NAME", "--no-spinner"], "exit": i32::from(failure)}]))?;
        peers.rules("qvm-run", json!([{}]))?;
        peers.rules("systemctl", json!([{"args": ["is-active", "qubesd.service"], "stdout": "active\n"}, {"stdout": "inactive\n", "exit": 3}]))?;
        let report = peers.json(
            peers
                .command(common::binary(
                    "AIRLOCK_OBSERVE_BIN",
                    "airlock-observe-dom0",
                ))?
                .env("PATH", peers.path("bin")),
        )?;
        assert_eq!(report["schema"], "airlock.dom0-observation.v1");
        assert_eq!(report["host"]["hostname"], "host \"quoted\"\nsecond line");
        assert_eq!(report["xen"]["xen_version"], "4.19");
        assert_eq!(
            report["qubes"]["domains_count"],
            if failure {
                serde_json::Value::Null
            } else {
                json!(0)
            }
        );
        let services = report["services"].as_array().unwrap();
        assert_eq!(services.len(), 6);
        assert_eq!(
            services
                .iter()
                .filter(|service| service["active"] == true)
                .count(),
            1
        );
        assert_eq!(
            peers
                .calls()?
                .iter()
                .filter(|call| call["command"] == "systemctl")
                .count(),
            6
        );
    }
    Ok(())
}

/// An unauthenticated GUI session cannot open its login lock or invoke display-manager tools.
#[test]
fn gui_session_refuses_non_dom0_before_starting_services() -> Result<()> {
    let mut peers = Peers::new()?;
    peers.rules("systemctl", json!([{}]))?;
    peers.rules("journalctl", json!([{}]))?;
    let output = common::run(
        peers
            .command(common::binary(
                "AIRLOCK_VM_SERVICE_BIN",
                "airlock-vm-service",
            ))?
            .args(["desktop", "gui-session", "--systemctl"])
            .arg(peers.path("bin/systemctl"))
            .arg("--journalctl")
            .arg(peers.path("bin/journalctl"))
            .env("QREXEC_REMOTE_DOMAIN", "sys-gui"),
        None,
    )?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("only be started by dom0"));
    assert!(peers.calls()?.is_empty());
    Ok(())
}
