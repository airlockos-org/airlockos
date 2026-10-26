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
