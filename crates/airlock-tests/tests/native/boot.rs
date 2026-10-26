//! Boot supervision keeps interruption evidence, readiness and recovery gates separate in private state.

use crate::common::{self, peers::Peers};
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs, os::unix::fs::symlink, process::Command};

/// A fresh, complete observation keeps unrelated supervisor failure scenarios focused on their own boundary.
const INPUT_REPLY: &str = r#"{"schema":"airlock.input-receiver.v1","devices":[{"name":"dom0: Keyboard","keyboard":true,"pointer":false}]}"#;

/// One boot history, independent runtime publications and finite diagnostic helpers.
struct Boot {
    // Owns every state file and command receipt used by the production supervisor.
    peers: Peers,
}

impl Boot {
    /// Supply only inert diagnostic commands and a scenario-selected boot identity.
    fn new(id: &str) -> Result<Self> {
        let mut peers = Peers::new()?;
        for name in ["xl", "qvm-ls", "systemctl", "free", "journalctl"] {
            peers.rules(name, json!([{"echo_args":true}]))?;
        }
        peers.rules("qvm-check", json!([{}]))?;
        peers.rules("qvm-ls", json!([{"stdout":"7\n"}]))?;
        peers.rules("qrexec-client", json!([
            {"args":["-d","sys-gui","user:readlink -f /run/current-system"], "stdout":crate::coordinator::fixture::store("sys-gui-system", 1)},
            {"contains":"DEFAULT:QUBESRPC airlock.InputReceiverReady dom0", "stdout":INPUT_REPLY},
            {"prefix":["-d","sys-gui"], "stdout":""}
        ]))?;
        fs::write(
            peers.path("physical.json"),
            br#"[{"name":"Keyboard","keyboard":true,"pointer":false}]"#,
        )?;
        fs::write(peers.path("boot-id"), id)?;
        fs::create_dir_all(peers.path("generation/airlock"))?;
        fs::create_dir(peers.path("etc"))?;
        fs::write(
            peers.path("generation/airlock/boot-readiness.json"),
            serde_json::to_vec(&json!({
                "schema":"airlock.boot-readiness.v1", "desktop":true, "input_target":"sys-gui"
            }))?,
        )?;
        // Installed NixOS configuration passes through /etc/static into the
        // immutable generation. All acceptance scenarios exercise that boundary.
        symlink("../generation", peers.path("etc/static"))?;
        symlink(
            "etc/static/airlock/boot-readiness.json",
            peers.path("policy.json"),
        )?;
        fs::write(
            peers.path("topology.json"),
            serde_json::to_vec(&json!({
                "schema":"airlock.qubes-topology.v1", "domains":{"sys-gui":crate::coordinator::fixture::declaration("sys-gui", 1)}
            }))?,
        )?;
        Ok(Self { peers })
    }

    /// Build a supervisor operation with no writable host state exposed to the service.
    fn command(&self, args: &[&str]) -> Result<Command> {
        let mut command = self
            .peers
            .command(common::binary("AIRLOCK_DOM0_BIN", "airlock-dom0-service"))?;
        command
            .arg("--state")
            .arg(self.peers.path("machine"))
            .arg("boot-supervisor")
            .args(args)
            .env("PATH", self.peers.path("bin"))
            .env("AIRLOCK_BOOT_SETUP", crate::coordinator::fixture::SETUP);
        for (key, path) in [
            ("AIRLOCK_BOOT_ID_FILE", "boot-id"),
            ("AIRLOCK_INPUT_PHYSICAL", "physical.json"),
            ("AIRLOCK_BOOT_STATE_ROOT", "state"),
            ("AIRLOCK_BOOT_LOG_ROOT", "logs"),
            ("AIRLOCK_BOOT_RUN_ROOT", "run"),
            ("AIRLOCK_BOOT_DIAGNOSTIC_ROOT", "root"),
            ("AIRLOCK_BOOT_READINESS_POLICY", "policy.json"),
            ("AIRLOCK_BOOT_TOPOLOGY", "topology.json"),
        ] {
            command.env(key, self.peers.path(path));
        }
        common::namespace(&command, &self.peers.path(""))
    }

    /// Require the public supervisor command to finish successfully and decode its result.
    fn run(&self, args: &[&str]) -> Result<Value> {
        common::json(&mut self.command(args)?, None)
    }

    /// Read one historical boot without consulting mutable current-boot pointers.
    fn record(&self, id: &str) -> Result<Value> {
        self.peers.read(format!("state/{id}/state.json"))
    }
}

/// Reading panel progress preserves per-VM checkpoints and never performs another readiness probe.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_boot_guest_progress_is_read_only_and_retains_completed_guests() -> Result<()> {
    let boot = Boot::new("panel-boot")?;
    let mut home = crate::coordinator::fixture::declaration("usr-home", 1);
    home["prefs"]["guivm"] = json!("sys-gui");
    fs::write(
        boot.peers.path("topology.json"),
        serde_json::to_vec(&json!({
            "schema":"airlock.qubes-topology.v1", "domains":{
                "sys-gui":crate::coordinator::fixture::declaration("sys-gui",1),
                "usr-home":home,
                "sys-net":crate::coordinator::fixture::declaration("sys-net",1)
            }
        }))?,
    )?;
    boot.run(&["prepare"])?;
    boot.run(&["desktop-ready"])?;
    boot.run(&["guest", "usr-home", "starting", "Starting usr-home"])?;
    boot.run(&["guest", "usr-home", "ready", "usr-home is ready"])?;
    boot.run(&["guest", "sys-net", "starting", "Starting sys-net"])?;
    let before = fs::read(boot.peers.path("state/panel-boot/state.json"))?;
    let calls = boot.peers.calls()?;
    let status = boot.run(&["desktop-status"])?;
    let guests = status["guests"].as_array().unwrap();
    assert_eq!(status["status"], "working");
    assert_eq!(
        guests
            .iter()
            .find(|guest| guest["name"] == "usr-home")
            .unwrap(),
        &json!({"name":"usr-home","phase":"ready","applications":true})
    );
    assert_eq!(
        guests
            .iter()
            .find(|guest| guest["name"] == "sys-net")
            .unwrap()["phase"],
        "starting"
    );
    assert_eq!(
        fs::read(boot.peers.path("state/panel-boot/state.json"))?,
        before
    );
    assert_eq!(
        boot.peers.calls()?,
        calls,
        "status must not start guests or re-run probes"
    );
    Ok(())
}

/// Recover interrupted boots before a new attempt, retaining diagnostic copies and requiring acknowledgement.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_boot_interruption_recovers_evidence_before_another_attempt() -> Result<()> {
    let boot = Boot::new("first-boot")?;
    let console = boot.peers.path("root/var/log/airlock-xen-console");
    fs::create_dir_all(&console)?;
    fs::write(console.join("guest-sys-gui.log"), "last VM output\n")?;
    boot.run(&["prepare"])?;
    boot.run(&["stage", "gui", "waiting for sys-gui"])?;
    assert_eq!(boot.peers.read("state/in-progress.json")?["stage"], "gui");
    fs::write(boot.peers.path("boot-id"), "second-boot")?;
    boot.run(&["prepare"])?;
    let recovered = boot.record("first-boot")?;
    assert_eq!(recovered["status"], "interrupted");
    assert_eq!(recovered["recovered_by"], "second-boot");
    assert!(boot.peers.path("run/recovery-required.json").exists());
    let snapshots = fs::read_dir(boot.peers.path("logs/first-boot/snapshots"))?
        .collect::<std::io::Result<Vec<_>>>()?;
    let recovered = snapshots
        .iter()
        .find(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("recovered-on-")
        })
        .context("recovered snapshot")?
        .path();
    assert_eq!(
        fs::read(recovered.join("var/log/airlock-xen-console/guest-sys-gui.log"))?,
        b"last VM output\n"
    );
    assert!(fs::read_to_string(recovered.join("journal.txt"))?.contains("--boot first-boot"));
    assert!(!boot.peers.path("state/in-progress.json").exists());
    boot.run(&["recovery-ack"])?;
    assert_eq!(boot.record("second-boot")?["status"], "complete");
    Ok(())
}

/// Normal completion clears the in-progress marker; preparing the same boot does not rewrite either state.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_boot_completion_and_repeated_prepare_are_idempotent() -> Result<()> {
    for complete in [false, true] {
        let boot = Boot::new("same-boot")?;
        boot.run(&["prepare"])?;
        boot.run(&["stage", "network", "waiting"])?;
        assert!(boot.peers.path("state/in-progress.json").exists());
        if complete {
            boot.run(&["complete", "all VMs ready"])?;
        }
        let before = fs::read(boot.peers.path("state/same-boot/state.json"))?;
        boot.run(&["prepare"])?;
        assert_eq!(
            fs::read(boot.peers.path("state/same-boot/state.json"))?,
            before
        );
        assert_eq!(
            boot.peers.path("state/in-progress.json").exists(),
            !complete
        );
        if complete {
            assert_eq!(boot.record("same-boot")?["status"], "complete");
            assert_eq!(boot.record("same-boot")?["stage"], "ready");
        }
    }
    Ok(())
}

/// Concurrent failure handlers retain every event and snapshot while publishing one coherent marker.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_boot_concurrent_failures_preserve_all_evidence() -> Result<()> {
    let boot = Boot::new("concurrent-boot")?;
    boot.run(&["prepare"])?;
    let names: Vec<_> = (0..12)
        .map(|index| format!("unit:failed-{index}"))
        .collect();
    std::thread::scope(|scope| -> Result<()> {
        let tasks: Vec<_> = names
            .iter()
            .map(|name| scope.spawn(|| boot.run(&["fail", name, "failed"])))
            .collect();
        for task in tasks {
            task.join().unwrap()?;
        }
        Ok(())
    })?;
    let current = boot.record("concurrent-boot")?;
    assert_eq!(current, boot.peers.read("state/in-progress.json")?);
    assert_eq!(current["status"], "failed");
    let events = fs::read_to_string(boot.peers.path("logs/concurrent-boot/events.jsonl"))?;
    let actual: BTreeSet<_> = events
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|event| event["status"] == "failed")
        .map(|event| event["stage"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(actual, names.iter().cloned().collect());
    for name in names {
        assert!(
            boot.peers
                .path(format!(
                    "logs/concurrent-boot/snapshots/failure-{name}/journal.txt"
                ))
                .is_file()
        );
    }
    Ok(())
}

/// A usable degraded desktop permits the next boot, but a failed critical boot still requires recovery.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_boot_distinguishes_degradation_shutdown_and_interruption() -> Result<()> {
    for shutdown in [false, true] {
        let boot = Boot::new("desktop-boot")?;
        boot.run(&["prepare"])?;
        boot.run(&["desktop-ready"])?;
        boot.run(&["degraded"])?;
        assert!(!boot.peers.path("state/in-progress.json").exists());
        assert_eq!(
            boot.run(&["desktop-status"])?,
            json!({"boot_id":"desktop-boot", "guests":[{"name":"sys-gui","phase":"ready","applications":false}], "status":"degraded","desktop_ready":true,"stage":"services","detail":"background services could not start"})
        );
        if shutdown {
            boot.run(&["shutdown-requested"])?;
        }
        fs::write(boot.peers.path("boot-id"), "next-boot")?;
        boot.run(&["prepare"])?;
        assert!(!boot.peers.path("run/recovery-required.json").exists());
        let previous = boot.record("desktop-boot")?;
        assert_eq!(previous["status"], "degraded");
        assert_eq!(previous.get("shutdown_requested_at").is_some(), shutdown);
        assert!(
            boot.peers
                .path("logs/desktop-boot/snapshots/background-services-failed")
                .is_dir()
        );
    }
    for failed in [false, true] {
        let boot = Boot::new("first-boot")?;
        boot.run(&["prepare"])?;
        if failed {
            boot.run(&["fail", "gui", "GPU handoff failed"])?;
        }
        boot.run(&["shutdown-requested"])?;
        fs::write(boot.peers.path("boot-id"), "next-boot")?;
        boot.run(&["prepare"])?;
        assert_eq!(
            boot.peers.path("run/recovery-required.json").exists(),
            failed
        );
        let previous = boot.record("first-boot")?;
        assert!(previous.get("shutdown_requested_at").is_some());
        assert_ne!(previous["status"], "interrupted");
        if failed {
            assert_eq!(previous["detail"], "GPU handoff failed");
        }
    }
    Ok(())
}

/// Retry needs an active degraded desktop, while recovery acknowledgement does not erase the current gate.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_boot_retry_and_recovery_ack_have_distinct_authority() -> Result<()> {
    let boot = Boot::new("boot")?;
    boot.run(&["prepare"])?;
    assert!(
        !common::run(&mut boot.command(&["retry-services"])?, None)?
            .status
            .success()
    );
    boot.run(&["desktop-ready"])?;
    boot.run(&["degraded"])?;
    boot.run(&["retry-services"])?;
    assert_eq!(boot.record("boot")?["status"], "working");
    let calls = boot.peers.calls()?;
    let reset = calls
        .iter()
        .position(|call| call["command"] == "systemctl" && call["args"][0] == "reset-failed")
        .context("failed assistant job reset")?;
    let restart = calls
        .iter()
        .position(|call| call["command"] == "systemctl" && call["args"][1] == "restart")
        .context("background retry")?;
    assert!(reset < restart);

    boot.run(&["degraded"])?;
    boot.run(&["shutdown-requested"])?;
    assert!(
        !common::run(&mut boot.command(&["retry-services"])?, None)?
            .status
            .success()
    );

    let boot = Boot::new("interrupted")?;
    boot.run(&["prepare"])?;
    fs::write(boot.peers.path("boot-id"), "recovery")?;
    boot.run(&["prepare"])?;
    boot.run(&["prepare"])?;
    assert_eq!(boot.record("recovery")?["status"], "recovery-required");
    boot.run(&["recovery-ack"])?;
    assert!(boot.peers.path("run/recovery-required.json").exists());
    fs::remove_dir_all(boot.peers.path("run"))?;
    fs::write(boot.peers.path("boot-id"), "next-attempt")?;
    boot.run(&["prepare"])?;
    assert!(!boot.peers.path("run/recovery-required.json").exists());
    assert_eq!(
        boot.peers.read("state/in-progress.json")?["boot_id"],
        "next-attempt"
    );
    Ok(())
}

/// Damaged markers cannot be overwritten, and incomplete publication is resumed without resetting history.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_boot_rejects_damage_and_resumes_interrupted_publication() -> Result<()> {
    for damaged in [
        r#"{"boot_id":"../escape"}"#,
        r#"{"boot_id":"bad","boot_id":"other"}"#,
        r#"{"schema":"unknown","boot_id":"bad"}"#,
    ] {
        let boot = Boot::new("bad")?;
        fs::create_dir(boot.peers.path("state"))?;
        fs::write(boot.peers.path("state/in-progress.json"), damaged)?;
        assert!(
            !common::run(&mut boot.command(&["prepare"])?, None)?
                .status
                .success()
        );
        assert_eq!(
            fs::read_to_string(boot.peers.path("state/in-progress.json"))?,
            damaged
        );
        assert!(!boot.peers.path("state/bad/state.json").exists());
    }
    for recovering in [false, true] {
        let boot = Boot::new("first")?;
        boot.run(&["prepare"])?;
        if recovering {
            fs::write(boot.peers.path("boot-id"), "recovery")?;
            boot.run(&["prepare"])?;
        } else {
            fs::remove_file(boot.peers.path("state/in-progress.json"))?;
        }
        fs::remove_file(boot.peers.path("run/current.json"))?;
        boot.run(&["prepare"])?;
        assert_eq!(
            boot.record(if recovering { "recovery" } else { "first" })?["status"],
            if recovering {
                "recovery-required"
            } else {
                "working"
            }
        );
        assert_eq!(
            boot.peers.path("run/recovery-required.json").exists(),
            recovering
        );
        assert_eq!(
            boot.peers.path("state/in-progress.json").exists(),
            !recovering
        );
    }
    Ok(())
}

/// Failed diagnostics retain both streams and exit status; labels cannot escape the snapshot directory.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_boot_diagnostics_retain_failures_and_reject_path_escape() -> Result<()> {
    let mut boot = Boot::new("diagnostics")?;
    boot.peers.rules(
        "xl",
        json!([{"stdout":"partial-output\n","stderr":"failed-detail\n","exit":7}]),
    )?;
    boot.run(&["snapshot", "manual"])?;
    let result = fs::read_to_string(
        boot.peers
            .path("logs/diagnostics/snapshots/manual/xl-list.txt"),
    )?;
    for fragment in ["7", "partial-output", "failed-detail"] {
        assert!(result.contains(fragment));
    }
    for label in ["../escape", "/escape", ".."] {
        assert!(
            !common::run(&mut boot.command(&["snapshot", label])?, None)?
                .status
                .success()
        );
        assert!(!boot.peers.path("escape").exists());
    }
    Ok(())
}

/// Startup waits for qrexec and refuses a VM running a different immutable system generation.
#[test]
fn vm_startup_requires_qrexec_on_the_exact_declared_generation() -> Result<()> {
    for correct in [true, false] {
        let mut peers = Peers::new()?;
        for name in ["qvm-start", "qvm-check", "qvm-ls", "supervisor"] {
            peers.rules(name, json!([{}]))?;
        }
        peers.rules("qrexec-client",json!([{"stdout":if correct {"/nix/store/expected-system\n"} else {"/nix/store/wrong-system\n"}}]))?;
        fs::write(
            peers.path("topology.json"),
            serde_json::to_vec(
                &json!({"domains":{"usr-assistant":{"backend":{"system":{"source":"/nix/store/expected-system"}}}}}),
            )?,
        )?;
        let mut command =
            peers.command(common::binary("AIRLOCK_DOM0_BIN", "airlock-dom0-service"))?;
        command
            .arg("start-qube-ready")
            .env(
                "AIRLOCK_DOM0_SERVICE",
                common::binary("AIRLOCK_DOM0_BIN", "airlock-dom0-service"),
            )
            .arg("usr-assistant")
            .arg(peers.path("topology.json"))
            .env("AIRLOCK_BOOT_SERVICE", peers.path("bin/supervisor"))
            .env("AIRLOCK_BOOT_ATTEMPT_LOG_DIR", peers.path("logs"))
            .env("AIRLOCK_QUBE_READY_TIMEOUT", "1");
        let output = common::run(&mut command, None)?;
        assert_eq!(
            output.status.success(),
            correct,
            "{stderr}; {log}",
            stderr = String::from_utf8_lossy(&output.stderr),
            log = fs::read_to_string(peers.path("logs/start-usr-assistant.log"))?
        );
        let calls = peers.calls()?;
        assert!(calls.iter().any(|call| call["command"] == "qvm-start"
            && call["args"] == json!(["--skip-if-running", "--", "usr-assistant"])));
        assert!(calls.iter().any(|call| call["command"] == "qrexec-client"
            && call["args"]
                == json!([
                    "-d",
                    "usr-assistant",
                    "user:readlink -f /run/current-system"
                ])));
        assert_eq!(
            calls
                .iter()
                .any(|call| call["command"] == "supervisor" && call["args"][3] == "failed"),
            !correct
        );
    }
    Ok(())
}

/// The prepared startup wrapper finds its packaged supervisor even with an otherwise empty PATH.
#[test]
#[ignore = "requires an explicitly prepared runnable AIRLOCK_START_READY_PACKAGE and user namespaces"]
fn optional_packaged_startup_helper_has_complete_runtime_dependencies() -> Result<()> {
    let package = std::path::PathBuf::from(
        std::env::var_os("AIRLOCK_START_READY_PACKAGE")
            .context("prepare airlock-start-qube-ready explicitly")?,
    );
    let mut boot = Boot::new("packaged-boot")?;
    for name in ["qvm-start", "qvm-check", "qvm-ls"] {
        boot.peers.rules(name, json!([{}]))?;
    }
    boot.peers
        .rules("qrexec-client", json!([{"stdout":"/nix/store/expected\n"}]))?;
    fs::write(
        boot.peers.path("topology.json"),
        r#"{"domains":{"usr-assistant":{"backend":{"system":{"source":"/nix/store/expected"}}}}}"#,
    )?;
    let mut command = boot
        .peers
        .command(package.join("bin/airlock-start-qube-ready"))?;
    command
        .args(["usr-assistant", "/var/lib/airlock/topology.json"])
        .env("PATH", "/nonexistent")
        .env(
            "AIRLOCK_BOOT_ATTEMPT_LOG_DIR",
            boot.peers.path("start-logs"),
        );
    for (key, path) in [
        ("AIRLOCK_QVM_START", "bin/qvm-start"),
        ("AIRLOCK_QVM_CHECK", "bin/qvm-check"),
        ("AIRLOCK_QVM_LS", "bin/qvm-ls"),
        ("AIRLOCK_QREXEC_CLIENT", "bin/qrexec-client"),
        ("AIRLOCK_BOOT_ID_FILE", "boot-id"),
        ("AIRLOCK_INPUT_PHYSICAL", "physical.json"),
        ("AIRLOCK_BOOT_STATE_ROOT", "state"),
        ("AIRLOCK_BOOT_LOG_ROOT", "logs"),
        ("AIRLOCK_BOOT_RUN_ROOT", "run"),
        ("AIRLOCK_BOOT_DIAGNOSTIC_ROOT", "root"),
    ] {
        command.env(key, boot.peers.path(path));
    }
    command.env_remove("AIRLOCK_BOOT_SERVICE");
    common::run(
        &mut common::namespace(&command, &boot.peers.path(""))?,
        None,
    )?
    .checked()?;
    assert!(
        boot.record("packaged-boot")?["detail"]
            .as_str()
            .unwrap()
            .contains("qrexec-ready")
    );
    Ok(())
}

/// Desktop publication requires home and network health while an early assistant failure stays separate.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_desktop_readiness_requires_home_and_network() -> Result<()> {
    use crate::coordinator::fixture::{declaration, store};

    for failure in ["", "home", "network", "assistant"] {
        let mut boot = Boot::new("foreground")?;
        let mut home = declaration("usr-home", 1);
        home["features"]["airlock-boot-foreground"] = json!("1");
        home["netvm"] = json!("sys-net");
        let mut network = declaration("sys-net", 1);
        network["prefs"]["provides_network"] = json!(true);
        fs::write(
            boot.peers.path("topology.json"),
            serde_json::to_vec(&json!({"schema":"airlock.qubes-topology.v1","domains":{
                "sys-gui":declaration("sys-gui", 1), "usr-home":home, "sys-net":network,
                "usr-assistant":declaration("usr-assistant", 1)
            }}))?,
        )?;
        boot.peers.rules(
            "qvm-check",
            json!([
                {"args":["--running","usr-home"],"exit":if failure == "home" {1} else {0}},
                {"args":["--running","usr-assistant"],"exit":if failure == "assistant" {1} else {0}},
                {}
            ]),
        )?;
        boot.peers.rules("qrexec-client", json!([
            {"args":["-d","sys-gui","user:readlink -f /run/current-system"],"stdout":store("sys-gui-system",1)},
            {"args":["-d","usr-home","user:readlink -f /run/current-system"],"stdout":store("usr-home-system",1)},
            {"args":["-d","sys-net","user:readlink -f /run/current-system"],"stdout":store("sys-net-system",1)},
            {"contains":"DEFAULT:QUBESRPC airlock.InputReceiverReady dom0","stdout":INPUT_REPLY},
            {"prefix":["-d","sys-net"],"exit":if failure == "network" {1} else {0}},
            {"prefix":["-d","sys-gui"]}
        ]))?;
        boot.run(&["prepare"])?;
        if failure == "assistant" {
            boot.run(&["guest", "usr-assistant", "failed", "early startup failed"])?;
            assert_eq!(boot.record("foreground")?["status"], "working");
        }
        let output = common::run(&mut boot.command(&["desktop-ready"])?, None)?;
        let desktop_ready = failure.is_empty() || failure == "assistant";
        assert_eq!(
            output.status.success(),
            desktop_ready,
            "{failure}: {error}",
            error = String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(boot.record("foreground")?["desktop_ready"], desktop_ready);
        if failure == "assistant" {
            let output = common::run(&mut boot.command(&["complete", "all ready"])?, None)?;
            assert!(
                !output.status.success(),
                "assistant failure cannot become complete"
            );
            boot.run(&["degraded"])?;
            assert_eq!(boot.record("foreground")?["status"], "degraded");
        }
    }
    Ok(())
}

/// Final publication repeats observations rather than trusting earlier unit success or boot receipts.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_boot_acceptance_requires_fresh_complete_evidence() -> Result<()> {
    use crate::coordinator::fixture::{declaration, store};

    for failure in [
        "",
        "generation",
        "desktop",
        "input",
        "input-empty",
        "worker",
        "restart",
        "missing-policy",
        "unknown-policy",
        "missing-input-policy",
        "invalid-autostart",
        "invalid-worker-role",
        "failed-attempt",
        "failure-during-probe",
        "shutdown",
    ] {
        let mut boot = Boot::new("acceptance")?;
        let mut worker = declaration("sys-ctrl", 1);
        worker["features"]["airlock-role"] = if failure == "invalid-worker-role" {
            json!(true)
        } else {
            json!("sys-ctrl")
        };
        if failure == "invalid-autostart" {
            worker["prefs"]["autostart"] = json!("true");
        }
        fs::write(
            boot.peers.path("topology.json"),
            serde_json::to_vec(&json!({
                "schema":"airlock.qubes-topology.v1", "domains":{"sys-gui":declaration("sys-gui", 1), "sys-ctrl":worker}
            }))?,
        )?;
        boot.peers.rules("qrexec-client", json!([
            {"args":["-d","sys-gui","user:readlink -f /run/current-system"], "stdout":store("sys-gui-system", if failure == "generation" {2} else {1})},
            {"args":["-d","sys-ctrl","user:readlink -f /run/current-system"], "stdout":store("sys-ctrl-system", 1)},
            {"contains":"root:/run/current-system/sw/bin/airlock-vm-service boot-health desktop", "exit":if failure == "desktop" {1} else {0}},
            {"contains":"DEFAULT:QUBESRPC airlock.InputReceiverReady dom0", "exit":if failure == "input" {1} else {0}, "stdout":if failure == "input-empty" {r#"{"schema":"airlock.input-receiver.v1","devices":[]}"#} else {INPUT_REPLY}},
            {"contains":"root:/run/current-system/sw/bin/airlock-vm-service boot-health build-store --domain sys-ctrl", "exit":if failure == "worker" {1} else {0}, "write":{"worker-observed":""}}
        ]))?;
        // sys-ctrl sorts before sys-gui: change its instance after the GUI capability probe,
        // so its earlier successful generation/worker observations are stale at final acceptance.
        if failure == "restart" {
            boot.peers.rules("qrexec-client", json!([
                {"args":["-d","sys-gui","user:readlink -f /run/current-system"], "stdout":store("sys-gui-system", 1)},
                {"args":["-d","sys-ctrl","user:readlink -f /run/current-system"], "stdout":store("sys-ctrl-system", 1)},
                {"contains":"root:/run/current-system/sw/bin/airlock-vm-service boot-health desktop", "write":{"gui-observed":""}},
                {"contains":"DEFAULT:QUBESRPC airlock.InputReceiverReady dom0", "stdout":INPUT_REPLY},
                {"prefix":["-d"]}
            ]))?;
            boot.peers.rules("qvm-ls", json!([
                {"args":["--raw-data","--fields","XID","sys-ctrl"], "exists":"gui-observed", "stdout":"8\n"},
                {"stdout":"7\n"}
            ]))?;
        }
        boot.run(&["prepare"])?;
        if failure == "failure-during-probe" {
            let mut failed = boot.record("acceptance")?;
            failed["status"] = json!("failed");
            boot.peers.rules("qrexec-client", json!([
                {"args":["-d","sys-gui","user:readlink -f /run/current-system"], "stdout":store("sys-gui-system", 1)},
                {"args":["-d","sys-ctrl","user:readlink -f /run/current-system"], "stdout":store("sys-ctrl-system", 1)},
                {"contains":"root:/run/current-system/sw/bin/airlock-vm-service boot-health build-store --domain sys-ctrl", "write":{"state/acceptance/state.json":serde_json::to_string(&failed)?}},
                {"contains":"DEFAULT:QUBESRPC airlock.InputReceiverReady dom0", "stdout":INPUT_REPLY},
                {"prefix":["-d"]}
            ]))?;
        }
        match failure {
            "missing-policy" => fs::remove_file(boot.peers.path("policy.json"))?,
            "unknown-policy" => fs::write(
                boot.peers.path("policy.json"),
                br#"{"schema":"unknown","desktop":false,"input_target":null}"#,
            )?,
            "missing-input-policy" => fs::write(
                boot.peers.path("policy.json"),
                br#"{"schema":"airlock.boot-readiness.v1","desktop":true}"#,
            )?,
            "failed-attempt" => {
                boot.run(&["fail", "gui", "failed"])?;
            }
            "shutdown" => {
                boot.run(&["shutdown-requested"])?;
            }
            _ => {}
        }
        let output = common::run(&mut boot.command(&["complete"])?, None)?;
        assert_eq!(
            output.status.success(),
            failure.is_empty(),
            "{failure}: {stderr}; {stdout}",
            stderr = String::from_utf8_lossy(&output.stderr),
            stdout = String::from_utf8_lossy(&output.stdout)
        );
        assert_eq!(
            boot.peers.path("state/in-progress.json").exists(),
            !failure.is_empty(),
            "{failure}"
        );
        if failure.is_empty() {
            assert_eq!(boot.record("acceptance")?["status"], "complete");
            assert!(!boot.peers.calls()?.iter().any(|call| matches!(
                call["command"].as_str(),
                Some("qvm-start" | "qvm-shutdown")
            )));
        }
    }
    Ok(())
}

/// Explicit headless policy permits an empty required guest set without granting desktop readiness.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_boot_headless_acceptance_has_no_desktop_exemption_flag() -> Result<()> {
    let boot = Boot::new("headless")?;
    fs::write(
        boot.peers.path("policy.json"),
        br#"{"schema":"airlock.boot-readiness.v1","desktop":false,"input_target":null}"#,
    )?;
    fs::write(
        boot.peers.path("topology.json"),
        br#"{"schema":"airlock.qubes-topology.v1","domains":{}}"#,
    )?;
    boot.run(&["prepare"])?;
    assert!(
        !common::run(&mut boot.command(&["desktop-ready"])?, None)?
            .status
            .success()
    );
    assert!(boot.peers.path("state/in-progress.json").exists());
    boot.run(&["complete"])?;
    assert_eq!(boot.record("headless")?["desktop_ready"], false);
    assert!(!boot.peers.path("state/in-progress.json").exists());
    Ok(())
}
