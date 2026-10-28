//! Enrollment failures and provider probes remain bounded and require the firewall to be healthy.

use crate::common;
use anyhow::Result;
use serde_json::{Value, json};
use std::{fs, process::Command};

/// Provide explicitly inert network executables while leaving all protocol and shell decisions in the real script.
fn fixture(config: Value) -> Result<tempfile::TempDir> {
    let temporary = tempfile::tempdir()?;
    let root = temporary.path();
    fs::create_dir(root.join("bin"))?;
    for name in [
        "ip",
        "getent",
        "curl",
        "tailscale",
        "timeout",
        "qvm-start",
        "qvm-check",
        "qvm-ls",
        "qrexec-client",
        "systemctl",
        "supervisor",
    ] {
        common::peer_link(&root.join("bin"), name)?;
    }
    let mut config = config;
    config["bash"] = json!(common::tool("bash")?);
    fs::write(root.join("network.json"), serde_json::to_vec(&config)?)?;
    Ok(temporary)
}

/// Configure only a child's finite tool namespace, without changing global test process environment.
fn command(temporary: &tempfile::TempDir, operation: &str) -> Result<Command> {
    let root = temporary.path();
    let mut command = if operation == "tailscale-up" {
        let mut command = Command::new(common::binary(
            "AIRLOCK_VM_SERVICE_BIN",
            "airlock-vm-service",
        ));
        command.args(["runtime", "tailscale-up"]);
        command
    } else {
        let mut command = Command::new(common::binary("AIRLOCK_DOM0_BIN", "airlock-dom0-service"));
        command.arg(operation);
        command
    };
    command
        .env(
            "AIRLOCK_VM_SERVICE",
            common::binary("AIRLOCK_VM_SERVICE_BIN", "airlock-vm-service"),
        )
        .env("AIRLOCK_TEST_NETWORK_ROOT", root)
        .env(
            "PATH",
            format!(
                "{bin}:{path}",
                bin = root.join("bin").display(),
                path = std::env::var("PATH")?
            ),
        );
    Ok(command)
}

/// Route, DNS, HTTPS and login failures identify the failing step without hanging or enrolling prematurely.
#[test]
fn development_enrollment_reports_each_network_failure() -> Result<()> {
    for (failure, message) in [
        ("route", "No network route"),
        ("dns", "DNS is not working"),
        ("https", "Cannot reach Tailscale"),
        ("login", "login timed out"),
        ("", "Starting Tailscale login"),
    ] {
        let fixture = fixture(json!({"failure": failure}))?;
        let output = common::run(
            command(&fixture, "tailscale-up")?
                .env("QREXEC_REMOTE_DOMAIN", "sys-gui")
                .env("QREXEC_SERVICE_ARGUMENT", ""),
            None,
        )?;
        let diagnostics = format!(
            "{stdout}{stderr}",
            stdout = String::from_utf8_lossy(&output.stdout),
            stderr = String::from_utf8_lossy(&output.stderr)
        );
        assert!(diagnostics.contains(message), "{failure}: {diagnostics}");
        assert_eq!(output.status.success(), failure.is_empty());
        assert_eq!(fixture.path().join("enrolled").exists(), failure.is_empty());
    }

    // A caller spelling cannot replace local privilege; sudo admits the one installed helper.
    let fixture = fixture(json!({}))?;
    let mut local = Command::new(common::binary(
        "AIRLOCK_VM_SERVICE_BIN",
        "airlock-vm-service",
    ));
    local
        .args(["runtime", "tailscale-up-local"])
        .env("QREXEC_REMOTE_DOMAIN", "sys-gui")
        .env("AIRLOCK_TEST_NETWORK_ROOT", fixture.path())
        .env(
            "PATH",
            format!(
                "{bin}:{path}",
                bin = fixture.path().join("bin").display(),
                path = std::env::var("PATH")?
            ),
        );

    let output = common::run(&mut local, None)?;
    assert_eq!(
        output.status.success(),
        rustix::process::geteuid().is_root()
    );
    assert_eq!(
        fixture.path().join("enrolled").exists(),
        rustix::process::geteuid().is_root()
    );
    if !rustix::process::geteuid().is_root() {
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("requires the installed privileged helper")
        );
        assert!(!fixture.path().join("calls.jsonl").exists());
    }
    Ok(())
}

/// A live network provider is not ready when its firewall is inactive, even if another requested unit is healthy.
#[test]
fn provider_readiness_checks_each_required_service() -> Result<()> {
    for healthy in [false, true] {
        let fixture = fixture(json!({"healthy": healthy}))?;
        let root = fixture.path();
        let topology = root.join("topology.json");
        fs::write(
            &topology,
            serde_json::to_vec(
                &json!({"domains": {"sys-net": {"prefs": {"provides_network": true}, "backend": {"system": {"source": "/nix/store/expected"}}}}}),
            )?,
        )?;
        let output = common::run(
            command(&fixture, "start-qube-ready")?
                .env(
                    "AIRLOCK_DOM0_SERVICE",
                    common::binary("AIRLOCK_DOM0_BIN", "airlock-dom0-service"),
                )
                .arg("sys-net")
                .arg(topology)
                .env("AIRLOCK_BOOT_SERVICE", root.join("bin/supervisor"))
                .env("AIRLOCK_QUBE_READY_TIMEOUT", "1")
                .env("AIRLOCK_BOOT_ATTEMPT_LOG_DIR", root.join("logs")),
            None,
        )?;
        assert_eq!(
            output.status.success(),
            healthy,
            "{errors}",
            errors = String::from_utf8_lossy(&output.stderr)
        );
        if !healthy {
            assert!(
                fs::read_to_string(root.join("logs/start-sys-net.log"))?
                    .contains("Network provider unhealthy: qubes-firewall.service")
            );
        }
    }
    Ok(())
}

/// A worker answering qrexec on the right system is still unready until its build store passes.
#[test]
fn worker_readiness_checks_the_build_store_before_success() -> Result<()> {
    for healthy in [false, true] {
        let fixture = fixture(json!({"healthy":healthy}))?;
        let root = fixture.path();
        let topology = root.join("topology.json");
        fs::write(
            &topology,
            serde_json::to_vec(&json!({"domains":{"sys-ctrl":{
                "features":{"airlock-role":"sys-ctrl"}, "backend":{"system":{"source":"/nix/store/expected"}}
            }}}))?,
        )?;
        let output = common::run(
            command(&fixture, "start-qube-ready")?
                .arg("sys-ctrl")
                .arg(topology)
                .env("AIRLOCK_BOOT_SERVICE", root.join("bin/supervisor"))
                .env("AIRLOCK_QUBE_READY_TIMEOUT", "1")
                .env("AIRLOCK_BOOT_ATTEMPT_LOG_DIR", root.join("logs")),
            None,
        )?;
        assert_eq!(
            output.status.success(),
            healthy,
            "{errors}",
            errors = String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            fs::read_to_string(root.join("logs/start-sys-ctrl.log"))?
                .contains("boot-health build-store --domain sys-ctrl")
        );
    }
    Ok(())
}
