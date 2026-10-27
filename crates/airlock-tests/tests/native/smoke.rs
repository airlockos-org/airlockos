//! Exercise smoke phase failures through inert commands, without contacting a live Qubes host.

use crate::common::{self, peers::Peers};
use anyhow::{Context, Result};
use serde_json::json;
use std::{fs, process::Command};

/// Prepare only literal command replies and fixture-owned evidence for the initial closure phases.
fn closure_fixture() -> Result<Peers> {
    let mut peers = Peers::new()?;
    fs::write(peers.path("capabilities"), "control_d\n")?;
    for name in ["systemctl", "qvm-check", "qvm-shutdown", "qvm-volume"] {
        peers.rules(name, json!([{}]))?;
    }
    peers.rules("qvm-prefs", json!([{"stdout":"fixture-kernel\n"}]))?;
    peers.rules(
        "qvm-features",
        json!([
            {"argc":2,"stdout":"/fixture/source\n"},
            {"argc":1,"stdout":"retained features\n"}
        ]),
    )?;
    peers.rules(
        "qvm-ls",
        json!([{"stdout":"primary|AppVM\npeer|StandaloneVM\n"}]),
    )?;
    peers.rules("journalctl", json!([{"stdout":"retained journal\n"}]))?;
    peers.rules(
        "airlock-setup-config",
        json!([{"write":{"logs/setup-config.json":"{\"status\":\"passed\"}\n"}}]),
    )?;
    Ok(peers)
}

/// Confine every helper to the inert namespace and give the smoke command deterministic inputs.
fn closure_command(peers: &Peers) -> Result<Command> {
    let mut command = peers.command(common::binary("AIRLOCK_SMOKE_BIN", "airlock-smoke"))?;
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("AIRLOCK_NIX_CLOSURE_") {
            command.env_remove(key);
        }
    }
    command
        .arg("closure")
        .env("PATH", peers.path("bin"))
        .env("AIRLOCK_XEN_CAPABILITIES", peers.path("capabilities"))
        .env("AIRLOCK_LOG_DIR", peers.path("logs"))
        .env("AIRLOCK_NIX_CLOSURE_DOMAIN", "primary")
        .env("AIRLOCK_NIX_CLOSURE_PEER_DOMAIN", "peer")
        .env("AIRLOCK_NIX_CLOSURE_APPLY_MODE", "direct")
        .env("AIRLOCK_NIX_CLOSURE_APPLY_MESSAGE", "initial")
        .env("AIRLOCK_NIX_CLOSURE_APPLY_MESSAGE_GEN2", "second")
        .env("AIRLOCK_NIX_CLOSURE_REBOOT_PROBE", "0")
        .env("AIRLOCK_NIX_CLOSURE_GUI_PROBE", "0")
        .env("AIRLOCK_CONFIG_STAGING_VM", "source-initial")
        .env("AIRLOCK_CONFIG_VALIDATOR_VM", "source-peer")
        .env("AIRLOCK_CONFIG_VAULT_VM", "source-second")
        .env(
            "AIRLOCK_NIX_CLOSURE_DIRECT_PRIMARY_SOURCE_VM",
            "source-initial",
        )
        .env("AIRLOCK_NIX_CLOSURE_DIRECT_PEER_SOURCE_VM", "source-peer")
        .env("AIRLOCK_NIX_CLOSURE_DIRECT_GEN2_SOURCE_VM", "source-second")
        .env(
            "AIRLOCK_SETUP_CONFIG_COMMAND",
            peers.path("bin/airlock-setup-config"),
        );
    Ok(command)
}

/// Preparation and initial-generation failures retain evidence without advancing to later generations.
#[test]
fn closure_phase_failures_preserve_diagnostics_and_the_original_error() -> Result<()> {
    for (failure, expected) in [
        ("control-domain", "host is not a Xen control domain"),
        ("apply", "apply interrupted"),
        ("materialization", "primary is not a StandaloneVM"),
    ] {
        let mut peers = closure_fixture()?;
        match failure {
            "control-domain" => fs::write(peers.path("capabilities"), "not_control_d\n")?,
            "apply" => peers.rules(
                "airlock-setup-config",
                json!([{"exit":37,"stderr":"apply interrupted\n"}]),
            )?,
            _ => {}
        }
        let output = common::run(&mut closure_command(&peers)?, None)?;
        assert!(!output.status.success(), "{failure}");
        let record = peers.read("logs/nix-closure-domain-smoke.json")?;
        assert_eq!(record["status"], "failed");
        assert!(
            record["reason"].as_str().unwrap().contains(expected),
            "{record}"
        );
        assert_eq!(record["reboot_status"], "not-run");
        assert_eq!(record["shutdown_start_status"], "not-run");
        assert_eq!(record["gui_status"], "skipped");
        assert!(record["gen2_apply_result"].is_null());
        assert_eq!(
            fs::read_to_string(peers.path("logs/nix-closure-domain-journal.log"))?,
            "retained journal\n"
        );

        let calls = peers.calls()?;
        let setup = calls
            .iter()
            .position(|call| call["command"] == "airlock-setup-config");
        if failure == "control-domain" {
            assert!(setup.is_none());
            assert!(!calls.iter().any(|call| call["command"] == "qvm-shutdown"));
        } else {
            let setup = setup.context("initial setup was not invoked")?;
            for target in ["primary", "peer"] {
                assert!(calls[..setup].iter().any(|call| {
                    call["command"] == "qvm-shutdown" && call["args"] == json!(["--wait", target])
                }));
            }
            assert_eq!(
                calls
                    .iter()
                    .filter(|call| call["command"] == "airlock-setup-config")
                    .count(),
                1
            );
        }
        if failure == "materialization" {
            assert_eq!(record["apply_result"]["status"], "passed");
            assert_eq!(record["setup_result"]["status"], "passed");
        } else {
            assert!(record["apply_result"].is_null());
        }
    }
    Ok(())
}

/// Supply literal preflight replies and a candidate whose topology deliberately fails post-apply checks.
fn config_fixture() -> Result<Peers> {
    let mut peers = Peers::new()?;
    fs::write(peers.path("capabilities"), "control_d\n")?;
    fs::write(peers.path("candidate.rs"), "// fixture candidate\n")?;
    fs::create_dir(peers.path("logs"))?;
    fs::write(
        peers.path("logs/config-apply-topology.json"),
        r#"{"domains":{}}"#,
    )?;
    for name in [
        "systemctl",
        "qvm-check",
        "qvm-shutdown",
        "qvm-sync-appmenus",
        "runuser",
        "airlock-config-inputs-import",
        "airlock-config-bootstrap-current",
    ] {
        peers.rules(name, json!([{}]))?;
    }
    peers.rules(
        "qvm-ls",
        json!([{"stdout":"staging|StandaloneVM\nvalidator|StandaloneVM\nvault|StandaloneVM\n"}]),
    )?;
    peers.rules("qvm-prefs", json!([{}]))?;
    peers.rules("qvm-volume", json!([{"stdout":"rw False\n"}]))?;
    peers.rules(
        "qvm-features",
        json!([
            {"contains":"airlock-backend","stdout":"nix-closure\n"},
            {"contains":"airlock-store-device","stdout":"/dev/xvde\n"},
            {"contains":"airlock-store-read-only","stdout":"True\n"},
            {"argc":1,"stdout":"retained features\n"}
        ]),
    )?;
    let mut remote = Vec::new();
    for guest in ["vault", "staging", "validator"] {
        for (command, stdout) in [
            ("'uname' '-a'".to_owned(), "Linux fixture\n"),
            ("'id' '-un'".to_owned(), "user\n"),
            (
                "'airlock-vm-service' 'runtime' 'store-check'".to_owned(),
                "store_device=/dev/xvde\nstore_options=ro\n",
            ),
            (
                format!("'cat' '/home/user/.airlock-persistence-{guest}'"),
                "fixture-message\n",
            ),
        ] {
            remote.push(json!({"args":["-d",guest,format!("user:{command}")],"stdout":stdout}));
        }
    }
    remote.push(json!({"contains":"user:'git' '-C' '/home/user/airlock-config-vault' 'status' '--porcelain=v2' '--branch' '--untracked-files=all'","stdout":"# branch.oid abc123\n# branch.head main\n"}));
    remote.push(json!({"contains":"user:'git' '-C' '/home/user/airlock-config' 'status' '--porcelain=v2' '--branch' '--untracked-files=all'","stdout":"# branch.oid abc123\n# branch.head main\n"}));
    remote.push(json!({}));
    peers.rules("qrexec-client", json!(remote))?;
    peers.rules(
        "journalctl",
        json!([{"stdout":"retained config journal\n"}]),
    )?;
    peers.rules(
        "airlock-config-apply",
        json!([{
            "args":["--apply","--staging","staging","--validator","validator","--vault","vault"],
            "env":{"AIRLOCK_CONFIG_APPLY_STAGE":"fixture-stage","AIRLOCK_CONFIG_APPLY_NIX_OFFLINE":"1"},
            "write":{"logs/config-apply-topology.json":"{\"domains\":{}}\n"}
        }]),
    )?;
    Ok(peers)
}

/// Keep all effects in fixture commands and remove inherited configuration scenario overrides.
fn config_command(peers: &Peers, mode: &str) -> Result<Command> {
    let mut command = peers.command(common::binary("AIRLOCK_SMOKE_BIN", "airlock-smoke"))?;
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("AIRLOCK_CONFIG_") {
            command.env_remove(key);
        }
    }
    command
        .arg("config")
        .env("PATH", peers.path("bin"))
        .env("AIRLOCK_XEN_CAPABILITIES", peers.path("capabilities"))
        .env("AIRLOCK_LOG_DIR", peers.path("logs"))
        .env("AIRLOCK_CONFIG_VMS_SMOKE_MODE", mode)
        .env("AIRLOCK_CONFIG_STAGING_VM", "staging")
        .env("AIRLOCK_CONFIG_VALIDATOR_VM", "validator")
        .env("AIRLOCK_CONFIG_VAULT_VM", "vault")
        .env("AIRLOCK_CONFIG_CREATED_QUBE", "created")
        .env("AIRLOCK_QUBE_USER", "user")
        .env("AIRLOCK_CONFIG_APPLY_MESSAGE", "fixture-message")
        .env("AIRLOCK_CONFIG_APPLY_STAGE", "fixture-stage")
        .env("AIRLOCK_CONFIG_APPLY_NIX_OFFLINE", "1")
        .env("AIRLOCK_CONFIG_SMOKE_SOURCE", peers.path("candidate.rs"));
    Ok(command)
}

/// Each explicit mode stops at its boundary; full mode keeps preflight, stage, apply and checks ordered.
#[test]
fn config_modes_preserve_phase_boundaries_and_evidence() -> Result<()> {
    for mode in [
        "preflight",
        "stage-candidate",
        "apply-candidate",
        "post-apply",
        "full",
    ] {
        let peers = config_fixture()?;
        let output = common::run(&mut config_command(&peers, mode)?, None)?;
        let post_apply = matches!(mode, "post-apply" | "full");
        assert_eq!(
            output.status.success(),
            !post_apply,
            "{mode}: {stderr}",
            stderr = String::from_utf8_lossy(&output.stderr)
        );
        let record = peers.read("logs/config-vms-smoke.json")?;
        assert_eq!(record["mode"], mode);
        assert_eq!(record["config_apply_stage"], "fixture-stage");
        assert_eq!(
            record["status"],
            if post_apply { "failed" } else { "passed" }
        );
        assert_eq!(
            record["journal_log"],
            json!(peers.path("logs/config-vms-journal.log"))
        );
        assert_eq!(
            fs::read_to_string(peers.path("logs/config-vms-journal.log"))?,
            "retained config journal\n"
        );
        assert!(record["archive"].is_null());
        assert!(record["apply"].is_null());
        if post_apply {
            assert_eq!(
                record["reason"],
                "applied topology does not define a native closure VM: staging"
            );
            assert_eq!(record["applied_topology"], json!({"domains":{}}));
        } else {
            assert!(record["applied_topology"].is_null());
        }

        let calls = peers.calls()?;
        let preflight = calls
            .iter()
            .position(|call| call["command"] == "airlock-config-bootstrap-current");
        let stage = calls.iter().position(|call| {
            call["command"] == "qrexec-client"
                && call["args"][2] == "user:'tee' '/home/user/airlock-config/src/main.rs'"
        });
        let apply = calls
            .iter()
            .position(|call| call["command"] == "airlock-config-apply");
        assert_eq!(preflight.is_some(), matches!(mode, "preflight" | "full"));
        assert_eq!(stage.is_some(), matches!(mode, "stage-candidate" | "full"));
        assert_eq!(apply.is_some(), matches!(mode, "apply-candidate" | "full"));
        if mode == "full" {
            assert!(preflight < stage && stage < apply);
        }
        if preflight.is_some() {
            assert_eq!(record["staging_persistence"], "fixture-message");
            assert_eq!(record["vault_user"], "user");
            assert_eq!(
                record["validator_store_mount"],
                "store_device=/dev/xvde\nstore_options=ro"
            );
        }
        if stage.is_some() {
            let inputs = peers.read("logs/config-vms-config-staging-update.json")?;
            assert_eq!(
                inputs["inputs"],
                json!({"created":"created","message":"fixture-message","action":"switch"})
            );
            assert_eq!(inputs["commit_message"], "test runtime config changes");
        }
    }
    Ok(())
}

/// Validation, staging and apply failures preserve their original reason and still collect diagnostics.
#[test]
fn config_phase_failures_stop_mutation_and_retain_diagnostics() -> Result<()> {
    for (failure, mode, expected) in [
        (
            "mode",
            "unsupported",
            "unsupported AIRLOCK_CONFIG_VMS_SMOKE_MODE: unsupported",
        ),
        (
            "action",
            "full",
            "AIRLOCK_CONFIG_DOM0_SYSTEM_SWITCH_ACTION must be switch or boot",
        ),
        ("control-domain", "full", "host is not a Xen control domain"),
        (
            "source",
            "stage-candidate",
            "missing Rust candidate source for smoke update",
        ),
        ("apply", "apply-candidate", "apply interrupted"),
    ] {
        let mut peers = config_fixture()?;
        let mut command = config_command(&peers, mode)?;
        match failure {
            "action" => {
                command.env("AIRLOCK_CONFIG_DOM0_SYSTEM_SWITCH_ACTION", "invalid");
            }
            "control-domain" => fs::write(peers.path("capabilities"), "not_control_d\n")?,
            "source" => fs::remove_file(peers.path("candidate.rs"))?,
            "apply" => {
                peers.rules(
                    "airlock-config-apply",
                    json!([{"exit":37,"stderr":"apply interrupted\n"}]),
                )?;
                command = config_command(&peers, mode)?;
            }
            _ => {}
        }
        let output = common::run(&mut command, None)?;
        assert!(!output.status.success(), "{failure}");
        let record = peers.read("logs/config-vms-smoke.json")?;
        assert_eq!(record["status"], "failed");
        assert!(
            record["reason"].as_str().unwrap().contains(expected),
            "{record}"
        );
        assert_eq!(
            fs::read_to_string(peers.path("logs/config-vms-journal.log"))?,
            "retained config journal\n"
        );
        assert!(record["applied_topology"].is_null());
        assert!(record["archive"].is_null());
        let calls = peers.calls()?;
        assert_eq!(
            calls
                .iter()
                .any(|call| call["command"] == "airlock-config-apply"),
            failure == "apply"
        );
        assert!(!calls.iter().any(|call| call["command"] == "qrexec-client"));
        if matches!(failure, "mode" | "action" | "control-domain") {
            assert!(!calls.iter().any(|call| call["command"] == "qvm-check"));
        }
        if failure == "apply" {
            assert!(
                fs::read_to_string(peers.path("logs/config-vms-apply.log"))?
                    .contains("apply interrupted")
            );
        }
    }
    Ok(())
}
