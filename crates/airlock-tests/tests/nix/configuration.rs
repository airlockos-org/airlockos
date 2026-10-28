//! Evaluate subsystem contracts through the existing Rust fixture catalog in the opt-in Nix lane.

use super::*;

/// Borrow a string only where the evaluated contract requires text rather than another JSON type.
pub(super) fn text(value: &Value) -> &str {
    value.as_str().expect("configuration field must be text")
}

/// Compare literal membership in a list or substring membership in an emitted command.
fn contains(value: &Value, expected: &Value) -> bool {
    match value {
        Value::Array(values) => values.contains(expected),
        Value::String(value) => value.contains(text(expected)),
        _ => panic!("membership requires an evaluated list or string"),
    }
}

/// Require the evaluated field to be enabled or nonempty, preserving the contract's data type.
fn truth(value: &Value) -> bool {
    match value {
        Value::Bool(value) => *value,
        Value::Array(values) => !values.is_empty(),
        Value::Object(values) => !values.is_empty(),
        Value::String(value) => !value.is_empty(),
        _ => panic!("expected a boolean or collection"),
    }
}

/// Both GUI modes and ordinary guest sessions fail closed and reobserve storage before login.
#[test]
#[ignore = "requires explicitly prepared offline Nix sources"]
fn login_requires_successful_private_storage_and_live_mount_checks() -> Result<()> {
    let nix = context()?;
    let report = inspect(&nix, "gui_gpu_assignment/private_storage", json!({}))?;
    for profile in report.as_object().unwrap().values() {
        let expected = text(&profile["sessions"]["check"]);
        assert!(expected.ends_with("/bin/airlock-vm-service runtime private-storage-check"));
        for (name, service) in profile.as_object().unwrap() {
            for dependency in ["requires", "after"] {
                assert!(contains(
                    &service[dependency],
                    &json!("airlock-qubes-rw-init.service")
                ));
            }
            assert!(contains(&service["check"], &json!(expected)));
            if name == "display" {
                assert!(contains(
                    &service["requires"],
                    &json!("systemd-user-sessions.service")
                ));
            }
        }
    }
    Ok(())
}

/// Combine ordered commands only when an invariant spans the generated service command sequence.
fn join(value: &Value, separator: &str) -> String {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(text)
        .collect::<Vec<_>>()
        .join(separator)
}

/// Evaluate a machine-owned fixture using the prepared source snapshot and retain its diagnostics.
pub(super) fn inspect(nix: &Nix, fixture: &str, inputs: Value) -> Result<Value> {
    let mut arguments = json!({"root":nix.prepared.join("airlock-machine")});
    arguments
        .as_object_mut()
        .unwrap()
        .extend(inputs.as_object().context("fixture inputs")?.clone());
    nix.evaluate(&fixture.replace('/', "-"), fixture, arguments)?
        .value()
}

/// GPU lab wiring is opt-in, while the normal profile retains the same GUI and session.
#[test]
#[ignore = "requires explicitly prepared offline Nix sources"]
fn gpu_lab_does_not_change_the_normal_desktop() -> Result<()> {
    let nix = context()?;
    let report = inspect(&nix, "gpu_probe/gpu_lab", json!({}))?;
    assert_eq!(report["normalHasGpu"], false);
    assert_eq!(report["normalGui"], report["labGui"]);
    assert_eq!(report["normalSession"], "sys-gui");
    assert_eq!(report["labSession"], "sys-gui");
    assert_eq!(report["guiVm"], "sys-gui");
    assert_eq!(report["hostName"], "sys-gpu");
    assert_eq!(report["graphics"], true);
    let gpu = &report["gpu"];
    assert_eq!(gpu["class"], "StandaloneVM");
    assert!(gpu["netvm"].is_null());
    assert_eq!(gpu["devices"]["pci"], json!([]));
    assert_eq!(gpu["prefs"]["autostart"], false);
    assert!(gpu["prefs"]["guivm"].is_null());
    assert_eq!(gpu["prefs"]["virt_mode"], "hvm");
    assert_eq!(gpu["prefs"]["memory"], gpu["prefs"]["maxmem"]);
    Ok(())
}

/// Prepared VMs receive the corrected upstream memory reporter and its native regression check.
#[test]
#[ignore = "requires explicitly prepared offline Nix sources"]
fn guests_use_the_corrected_memory_reporter() -> Result<()> {
    let nix = context()?;
    let mut report = inspect(&nix, "memory_accounting_nix/patched_reporter", json!({}))?;
    assert_eq!(
        report.as_object_mut().unwrap().remove("nativeCheckEnabled"),
        Some(json!(true))
    );
    for patches in report.as_object().unwrap().values() {
        assert!(
            patches
                .as_array()
                .unwrap()
                .iter()
                .any(|patch| text(patch).ends_with("0001-account-for-per-cpu-free-pages.patch"))
        );
    }
    Ok(())
}

/// The network profile assigns DNS ownership once and keeps provider recovery enabled.
#[test]
#[ignore = "requires explicitly prepared offline Nix sources"]
fn network_configuration_has_one_dns_owner_and_recovers_services() -> Result<()> {
    let nix = context()?;
    let report = inspect(&nix, "network_reliability/network_recovery", json!({}))?;
    assert_eq!(report["firmware"], true);
    assert_eq!(report["netResolver"], true);
    assert_eq!(report["fwResolver"], false);
    assert!(
        !report["fwCommands"]
            .as_str()
            .unwrap()
            .contains("resolvconf")
    );
    assert_eq!(report["netRestart"], "on-failure");
    assert_eq!(report["fwRestart"], "on-failure");
    Ok(())
}

/// Physical graphics startup preserves hardware guards, input authorization and desktop dependency ordering.
#[test]
#[ignore = "explicit package builds: report reads realized input receiver and service scripts"]
fn package_physical_graphics_and_input_dependencies_preserve_boot_guards() -> Result<()> {
    let report = crate::packaged::inspect_configuration(
        "gui_gpu_assignment/gpu_selection",
        "airlock-machine",
    )?;
    assert_eq!(report["normal"]["enabled"], json!(false));
    assert_eq!(report["normalGuard"]["enable"], json!(false));
    assert_eq!(report["normal"]["pci"], json!([]));
    assert!(contains(&report["normal"]["early"], &json!("amdgpu")));
    assert!(!contains(
        &report["alternate"]["params"],
        &json!("xen-pciback.hide=(0000:04:00.0)")
    ));
    let service = &report["service"];
    assert!(contains(
        &service["requires"],
        &json!("airlock-setup-config.service")
    ));
    assert!(!contains(&service["requires"], &json!("qubesd.service")));
    assert!(contains(&service["wants"], &json!("qubesd.service")));
    assert!(contains(&service["after"], &json!("qubesd.service")));
    assert!(contains(
        &service["after"],
        &json!("airlock-setup-config.service")
    ));
    assert_eq!(service["serviceConfig"]["Restart"], json!("no"));
    let pre = &service["serviceConfig"]["ExecStartPre"];
    assert!((pre.as_array().unwrap().iter()).any(|command| contains(
        command,
        &json!("airlock-dom0-service boot-supervisor stage gui")
    )));
    assert!(
        (pre.as_array().unwrap().iter())
            .any(|command| contains(command, &json!("is-active --quiet qubesd.service")))
    );
    assert!(
        (pre.as_array().unwrap().iter()).any(|command| contains(command, &json!("--phase start")))
    );
    assert_eq!(report["noBypass"], json!(true));
    assert_eq!(report["framebuffer"]["enabled"], json!(true));
    assert_eq!(report["framebuffer"]["statusDevice"], json!("/dev/tty1"));
    assert_eq!(report["framebuffer"]["getty"], json!(false));
    assert_eq!(report["framebuffer"]["displayManager"], json!(false));
    assert!(
        (report["framebuffer"]["prepare"].as_array().unwrap().iter())
            .any(|command| text(command).ends_with("/bin/chvt 1"))
    );
    assert!(!contains(
        &report["lab"]["params"],
        &json!("initcall_blacklist=sysfb_init")
    ));
    assert!(!contains(
        &report["lab"]["params"],
        &json!("video=efifb:off")
    ));
    assert!(contains(&report["lab"]["params"], &json!("fbcon=nodefer")));
    assert!(contains(&report["lab"]["xenParams"], &json!("vga=current")));
    assert!(
        !((report["lab"]["xenParams"].as_array().unwrap().iter())
            .any(|p| text(p).starts_with("vga=") && contains(p, &json!(",keep"))))
    );
    assert!(contains(
        &report["dark"]["params"],
        &json!("initcall_blacklist=sysfb_init")
    ));
    assert!(contains(
        &report["dark"]["params"],
        &json!("video=efifb:off")
    ));
    assert!(contains(
        &json!(join(pre, "\n")),
        &json!("airlock-dom0-service gpu framebuffer --gpu 0000:04:00.0")
    ));
    assert!(
        (pre.as_array().unwrap().iter())
            .any(|command| text(command).ends_with("/bin/journalctl --sync"))
    );
    assert!(contains(
        &service["serviceConfig"]["ExecStart"],
        &json!("airlock-start-qube-ready sys-gui")
    ));
    assert!(text(&service["serviceConfig"]["ExecStartPost"]).ends_with("/bin/journalctl --sync"));
    assert_eq!(report["inputTarget"], json!([]));
    assert!(truth(&report["inputServices"]));
    assert_eq!(
        report["inputEvents"]["wantedBy"],
        json!(["multi-user.target"])
    );
    assert_eq!(
        report["inputEvents"]["requires"],
        json!(["airlock-setup-config.service"])
    );
    assert_eq!(report["inputEvents"]["wants"], json!(["qubesd.service"]));
    assert_eq!(
        report["inputEvents"]["after"],
        json!(["airlock-setup-config.service", "qubesd.service"])
    );
    assert!(contains(
        &report["inputEvents"]["serviceConfig"]["ExecStart"],
        &json!("airlock-dom0-service input events --target sys-gui")
    ));
    assert_eq!(
        report["inputEvents"]["serviceConfig"]["Restart"],
        json!("on-failure")
    );
    assert_eq!(report["inputConnect"]["Type"], json!("oneshot"));
    // Receiver negotiation, three Xen identity samples and registration polling share this unit budget.
    assert_eq!(report["inputConnect"]["TimeoutStartSec"], json!(240));
    assert!(contains(
        &report["inputConnect"]["requires"],
        &json!("airlock-input-boot-guard.service")
    ));
    assert!(contains(
        &report["service"]["requires"],
        &json!("airlock-input-boot-guard.service")
    ));
    assert!(contains(
        &report["service"]["after"],
        &json!("airlock-input-boot-guard.service")
    ));
    let guard = &report["inputGuard"];
    assert!(contains(
        &guard["before"],
        &json!("airlock-start-gui-gpu.service")
    ));
    assert!(contains(
        &guard["after"],
        &json!("airlock-setup-config.service")
    ));
    assert_eq!(guard["serviceConfig"]["Restart"], json!("no"));
    assert_eq!(guard["serviceConfig"]["TimeoutStartSec"], json!(75));
    assert!(contains(
        &guard["serviceConfig"]["ExecStopPost"],
        &json!("airlock-dom0-service input finalize")
    ));
    assert_eq!(
        guard["unitConfig"]["OnFailure"],
        json!(["airlock-boot-failure@%n.service"])
    );
    assert!(contains(
        &report["inputConnect"]["ExecStart"],
        &json!("airlock-connect-gui-input")
    ));
    let connect_script = &report["inputConnect"]["script"];
    assert_eq!(
        connect_script["args"],
        json!(["input", "connect", "--target", "sys-gui"])
    );
    assert_eq!(
        report["inputServices"],
        json!(["airlock-gui-input-discovery.service"])
    );
    assert!(contains(
        &report["discovery"]["ExecStart"],
        &json!("airlock-dom0-service input discover --target sys-gui")
    ));
    assert_eq!(
        report["discovery"]["StateDirectory"],
        json!("airlock/input")
    );
    assert_eq!(report["discovery"]["KillMode"], json!("control-group"));
    assert_eq!(report["discovery"]["Type"], "notify");
    assert_eq!(report["discovery"]["NotifyAccess"], "all");
    assert!(contains(
        &report["discovery"]["ExecStart"],
        &json!("/bin/systemd-notify")
    ));
    assert_eq!(report["inputConnect"]["Restart"], "on-failure");
    assert_eq!(
        report["deviceReceiver"]["args"],
        json!(["--keyboard", "--mouse", "--tablet"])
    );
    assert_eq!(report["deviceReceiver"]["callers"], json!(["dom0"]));
    assert_eq!(report["deviceReceiver"]["empty_service_argument"], true);
    assert_eq!(report["deviceReceiverConfig"], json!("force-user='root'\n"));
    assert!(contains(
        &report["inputPolicy"],
        &json!("airlock.InputDevice * @anyvm sys-gui deny")
    ));
    assert_eq!(
        report["inputReceiverReady"]["args"][0],
        "input-receiver-ready"
    );
    assert_eq!(
        report["inputReceiverReadyConfig"],
        json!("force-user='root'\n")
    );
    assert_eq!(
        report["inputInitialization"]["args"][0],
        "input-initialization"
    );
    assert_eq!(report["inputInitialization"]["callers"], json!(["dom0"]));
    assert_eq!(report["inputInitializationConfig"], "force-user='root'\n");
    assert!(contains(
        &report["inputPolicy"],
        &json!("airlock.InputReceiverReady * @anyvm sys-gui deny")
    ));
    assert!(contains(
        &report["inputPolicy"],
        &json!("airlock.InputInitialization * @anyvm sys-gui deny")
    ));
    assert!(!contains(&report["udevRules"], &json!("SYNA8018")));
    assert!(!contains(
        &report["udevRules"],
        &json!("platform-AMDI0010:01-event-touchpad")
    ));
    assert_eq!(report["normalSender"], json!(false));
    assert_eq!(report["recoverySender"], json!(false));
    let guest = &report["guest"];
    assert_eq!(guest["failed"], json!([]));
    assert_eq!(guest["defaultUnit"], json!("graphical.target"));
    assert_eq!(guest["displayWantedBy"], json!([]));
    assert_eq!(guest["session"], json!("gnome"));
    assert_eq!(guest["gdm"], json!(true));
    assert_eq!(guest["lightdm"], json!(false));
    assert_eq!(guest["receiver"], json!(true));
    assert_eq!(guest["guiAgent"], json!(false));
    assert_eq!(
        report["diagnosticGuest"]["defaultUnit"],
        json!("multi-user.target")
    );
    assert_eq!(report["diagnosticGuest"]["displayWantedBy"], json!([]));
    assert_eq!(report["diagnosticGuest"]["failed"], json!([]));
    assert_eq!(report["hybridGuest"]["displayWantedBy"], json!([]));
    assert_eq!(report["hybridGuest"]["receiver"], json!(false));
    assert_eq!(report["hybridGuest"]["gdm"], json!(false));
    assert_eq!(report["hybridGuest"]["lightdm"], json!(true));
    for service in [
        "qubes.InputKeyboard",
        "qubes.InputMouse",
        "qubes.InputTablet",
    ] {
        assert!(contains(
            &report["inputReceiverReady"]["args"],
            &json!(format!("/etc/qubes-rpc/{service}"))
        ));
    }
    let temporary = tempfile::tempdir()?;
    let mut handler = report["deviceReceiver"].clone();
    handler["program"] = json!(common::tool("printf")?);
    handler["args"] = json!(["accepted"]);
    for (source, argument, allowed) in [
        ("dom0", "", true),
        ("usr-assistant", "", false),
        ("", "", false),
        ("dom0", "unexpected", false),
    ] {
        let output = common::run(
            common::launcher(temporary.path(), &handler)?
                .env("QREXEC_REMOTE_DOMAIN", source)
                .env("QREXEC_SERVICE_ARGUMENT", argument),
            None,
        )?;
        assert_eq!(output.status.success(), allowed);
        assert_eq!(output.stdout == b"accepted", allowed);
    }
    Ok(())
}

/// A machine-owned hardware module must override every consumer of the lab device identity.
#[test]
#[ignore = "requires explicitly prepared offline Nix sources"]
fn hardware_override_reaches_reservation_and_assignment() -> Result<()> {
    let nix = context()?;
    let report = inspect(&nix, "gui_gpu_assignment/hardware_override", json!({}))?;
    assert_eq!(report["device"]["bdf"], "0000:09:03.0");
    assert_eq!(
        report["assignments"],
        json!([{"backend":"dom0","id":"00_03.1-00_00.0","mode":"required","match":"port","options":{}}])
    );
    assert_eq!(
        report["firmwareTemplate"],
        fs::read_to_string(
            nix.prepared
                .join("crates/runtime/airlock-qubes-python/assets/amd-vbios.xml")
        )?
    );
    Ok(())
}

/// Live validation observes Qubes inventory and rejects a wrong vendor while leaving its database unchanged.
#[test]
#[ignore = "requires an explicitly selected AIRLOCK_GPU_ASSIGNMENT_SSH host and prepared offline Nix sources"]
fn remote_gpu_preflight_preserves_qubes_state() -> Result<()> {
    let host = std::env::var("AIRLOCK_GPU_ASSIGNMENT_SSH")
        .context("select a read-only Qubes preflight target")?;
    let nix = context()?;
    let payload = inspect(&nix, "gui_gpu_assignment/live_preflight", json!({}))?;
    let probe = std::env::var("AIRLOCK_QUBES_PROBE")
        .context("select the prepared Qubes probe on the remote host")?;
    let remote = format!(
        "{probe} gpu-preflight",
        probe = airlock_tests::process::quote(&probe)
    );
    let report = common::json(
        Command::new("ssh").args([
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            &host,
            &remote,
        ]),
        Some(serde_json::to_vec(&payload)?),
    )?;
    assert_eq!(report["before"], report["after"]);
    assert_eq!(report["projected"]["result"]["status"], "passed");
    assert!(
        report["wrong_vendor"]["error"]
            .as_str()
            .unwrap()
            .contains("vendor mismatch")
    );
    if let Some(error) = report["actual"]["error"].as_str() {
        assert!(error.contains("running without the declared persistent assignment"));
    }
    Ok(())
}
