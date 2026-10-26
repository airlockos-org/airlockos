//! Desktop and controller configuration contracts keep VM roles and Qubes control boundaries explicit.

use super::configuration::{inspect, text};
use super::*;

/// Require dependencies by membership without coupling the contract to unrelated ordering or additions.
fn includes(value: &Value, expected: &str) {
    assert!(
        match value {
            Value::String(text) => text.contains(expected),
            Value::Array(items) => items.contains(&json!(expected)),
            _ => false,
        },
        "missing {expected} in {value}"
    );
}

/// The application VM enables desktop integrations without installing another desktop or package manager.
#[test]
#[ignore = "explicit guarded-store package builds"]
fn package_application_vm_keeps_desktop_work_out_of_the_gui_vm() -> Result<()> {
    let report = crate::packaged::inspect_configuration(
        "usr_home_gnome/personal_integrations",
        "airlock-machine",
    )?;
    for key in ["installation", "desktop"] {
        assert!(
            report[key]
                .as_object()
                .unwrap()
                .values()
                .all(|value| value == false)
        );
    }
    assert!(
        report["integrations"]
            .as_object()
            .unwrap()
            .values()
            .all(|value| value == true)
    );
    assert_eq!(report["portals"]["default"], "gtk");

    let report = crate::packaged::inspect_configuration(
        "usr_home_gnome/application_routing",
        "airlock-machine",
    )?;
    includes(
        &report["guiLogRules"],
        "d /var/log/qubes 2775 root qubes - -",
    );
    assert!(
        report["mutterFlags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|flag| {
                let flag = text(flag);
                flag.starts_with("-Dxwayland_path=")
                    && flag.contains("xwayland-qubes")
                    && flag.ends_with("/bin/Xwayland")
            })
    );
    for vm in report["appGui"].as_array().unwrap() {
        assert_eq!(
            vm["envPath"],
            "/run/current-system/sw/bin:/run/wrappers/bin"
        );
        assert_eq!(vm["restart"], "on-failure");
        assert_eq!(vm["restartSec"], "5s");
        assert_eq!(vm["startLimit"], 0);
        assert!(text(&vm["monitorLayout"]["program"]).ends_with("/bin/timeout"));
        includes(&vm["monitorLayout"]["args"], "60s");
        includes(&vm["monitorLayout"]["args"], "--kill-after=5s");
        assert!(vm["monitorLayout"]["env"]["PATH"].is_string());
        assert!(text(&vm["sessionReady"]["program"]).ends_with("/bin/airlock-vm-service"));
        assert_eq!(vm["sessionReady"]["args"], json!(["session-ready"]));
        assert_eq!(vm["sessionReadyConfig"], "force-user='user'\n");
        includes(&vm["forkAutostart"], "/bin/qrexec-fork-server");
        assert!(!text(&vm["forkAutostart"]).contains("Exec=/usr/bin/"));
        for key in ["enabled", "pam"] {
            assert_eq!(vm[key], true);
        }
        assert!(text(&vm["xorg"]).ends_with("/etc/X11/xorg-qubes.conf.template"));
        for key in ["wantedBy", "networkBoot"] {
            includes(&vm[key], "multi-user.target");
        }
        assert_eq!(vm["session"]["args"][0], "desktop");
        assert_eq!(vm["session"]["args"][1], "app-session");
        includes(&vm["networkReconcile"], "/bin/airlock-existing-uplinks");
    }
    assert_eq!(report["appGuestDhcp"], false);
    assert_eq!(report["appGuestForwarding"], false);
    includes(&report["appGuestUplink"]["requires"], "qubes-db.service");
    includes(&report["appGuestUplink"]["after"], "qubes-sysinit.service");
    assert_eq!(report["appGuestUplink"]["bindsTo"], json!([]));
    assert!(
        !report["appGuestUplink"]["after"]
            .as_array()
            .unwrap()
            .contains(&json!("sys-subsystem-net-devices-%i.device"))
    );
    for command in [
        r#"DRIVERS=="vif""#,
        "systemctl --no-block restart --job-mode=replace qubes-network-uplink@%k.service",
        "systemctl --no-block stop --job-mode=replace qubes-network-uplink@%k.service",
    ] {
        includes(&report["appGuestUdev"], command);
    }
    assert!(!text(&report["appGuestUdev"]).contains(r#"KERNEL=="eth*""#));
    assert!(text(&report["appGuestVifLink"]).ends_with("/80-qubes-vif.link"));
    assert_eq!(report["discovery"], true);
    assert_eq!(report["workspaceCoreApps"], false);
    assert_eq!(report["minimalCoreApps"], true);
    assert!(!report["workspaceEtc"].as_array().unwrap().contains(&json!(
        "xdg/autostart/airlock-gnome-desktop-shortcuts.desktop"
    )));
    includes(&report["workspaceStartApp"], "airlock-qubes-start-app");
    includes(&report["workspaceStartAppConfig"], "force-user=");
    assert!(!text(&report["workspaceGSettings"]).contains("ding@rastersoft.com"));
    Ok(())
}

/// Development workspace services run as the user and precede qrexec and source-seeding startup.
#[test]
#[ignore = "requires explicitly prepared offline Nix sources"]
fn assistant_workspace_uses_existing_management_interfaces() -> Result<()> {
    let nix = context()?;
    let report = inspect(
        &nix,
        "usr_assistant_workspace/assistant_workspace",
        json!({}),
    )?;
    assert_eq!(report["prefs"]["guivm"], "sys-gui");
    assert_eq!(report["prefs"]["virt_mode"], "pvh");
    assert_eq!(report["features"]["menu-items"], "*");
    assert_eq!(report["netvm"], "sys-firewall");
    assert_eq!(report["guiEnabled"], true);
    assert_eq!(report["readyConfig"], "force-user='user'\n");
    for (name, value) in [
        ("CODEX_HOME", "/home/user/.codex"),
        ("AIRLOCK_LOG_DIR", "/home/user/.local/state/airlock/logs"),
        ("AIRLOCK_NIX_ROOT", "/rw/airlock-builder/merged"),
        ("AIRLOCK_NIX_CONFIGURED", "1"),
        ("UV_PYTHON_DOWNLOADS", "never"),
    ] {
        assert_eq!(report["session"][name], value);
    }
    for service in ["workspace", "identity"] {
        assert_eq!(report[service]["serviceConfig"]["User"], "user");
    }
    includes(
        &report["workspace"]["after"],
        "airlock-qubes-rw-init.service",
    );
    for service in [
        "qubes-qrexec-agent.service",
        "airlock-machine-source-seed.service",
    ] {
        includes(&report["workspace"]["before"], service);
    }
    assert_eq!(report["identity"]["serviceConfig"]["Type"], "oneshot");
    includes(
        &report["identity"]["requires"],
        "airlock-usr-assistant-workspace.service",
    );
    for service in [
        "airlock-usr-assistant-workspace.service",
        "airlock-machine-source-seed.service",
    ] {
        includes(&report["identity"]["after"], service);
    }
    includes(&report["identity"]["before"], "qubes-qrexec-agent.service");
    assert_eq!(report["repoPath"], "/home/user/airlockos-machine");
    for (field, file) in [
        ("instructions", "AGENTS.md"),
        ("intro", "home-AGENTS.md"),
        ("operations", "operations.md"),
    ] {
        assert_eq!(
            report[field],
            fs::read_to_string(
                nix.prepared
                    .join("crates/airlock-config/assets/usr-assistant")
                    .join(file)
            )?
        );
    }
    includes(&report["intro"], "~/airlockos-machine");
    for action in ["plan", "apply", "status", "verify", "resume", "rollback"] {
        includes(
            &report["instructions"],
            &format!("airlock machine {action}"),
        );
    }
    Ok(())
}

/// Standalone GUI validation keeps its Qubes relay and restricts host poweroff to one fixed authenticated RPC.
#[test]
#[ignore = "explicit guarded-store package builds"]
fn package_minimal_gui_preserves_boot_supervision_and_host_control_boundaries() -> Result<()> {
    let report =
        crate::packaged::inspect_configuration("gui_minimal/minimal_desktop", "airlock-machine")?;
    let topology = &report["topology"];
    assert_eq!(
        topology["domains"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        ["sys-gui"]
    );
    assert_eq!(topology["templates"], json!({}));
    assert_eq!(topology["prefs"]["default_guivm"], "sys-gui");
    assert!(topology["prefs"]["default_netvm"].is_null());
    let gui = &topology["domains"]["sys-gui"];
    assert!(gui["netvm"].is_null());
    assert_eq!(gui["prefs"]["guivm"], "dom0");
    assert_eq!(gui["prefs"]["autostart"], true);
    assert_eq!(gui["devices"]["pci"], json!([]));
    assert_eq!(report["setupAutostart"], false);
    includes(
        &report["bootNotification"],
        "airlock-sys-gui-service boot-notification",
    );
    assert!(!text(&report["bootNotification"]).contains("X-GNOME-Autostart-Phase"));
    let supervised = &report["supervised"];
    assert_eq!(
        supervised["failure"],
        json!(["airlock-boot-background-failure.service"])
    );
    assert!(
        supervised["beforeStart"]
            .as_array()
            .unwrap()
            .iter()
            .any(|command| text(command).contains("desktop-ready"))
    );
    includes(&supervised["shutdown"], "shutdown-requested");
    assert_eq!(
        supervised["criticalFailure"],
        json!(["airlock-boot-failure@%n.service"])
    );
    includes(&supervised["retry"], "retry-services");
    assert_eq!(report["setup"]["enable"], true);
    assert_eq!(report["setup"]["scope"], "all");
    assert!(text(&report["setupCommand"]).ends_with(" --apply"));
    for key in [
        "networkStartup",
        "deferredStartup",
        "configBootstrap",
        "configPolicy",
        "devMode",
        "proxy",
    ] {
        assert_eq!(report[key], false);
    }
    assert!(report["defaultApplicationVM"].is_null());
    assert_eq!(report["discovery"], true);
    assert_eq!(report["normalDefaultApplicationVM"], "usr-home");
    assert_eq!(report["session"], "sys-gui");
    assert_eq!(report["guestSession"], "xfce");
    assert_eq!(report["xfce"], true);
    includes(
        &report["gnomeOverrides"],
        "airlock-host-poweroff@airlock.local",
    );
    includes(&report["gnomeHostPoweroffHelper"], "airlock.Dom0Poweroff");
    let source = text(&report["gnomeHostPoweroffExtensionSource"]);
    assert!(
        source.contains("GObject.registerClass(")
            && source.contains("super._init({destroyOnClose: false})")
    );
    assert!(!source.contains("constructor()"));
    assert_eq!(
        report["hostPoweroffService"]["program"],
        "/run/wrappers/bin/sudo"
    );
    assert_eq!(report["hostPoweroffService"]["callers"], json!(["sys-gui"]));
    assert_eq!(
        report["hostPoweroffService"]["empty_service_argument"],
        true
    );
    let rules: Vec<_> = report["hostPoweroffSudoRules"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|rule| {
            rule["users"]
                .as_array()
                .unwrap()
                .contains(&json!("airlock"))
                && rule["commands"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|command| text(&command["command"]).ends_with("/systemctl poweroff"))
        })
        .collect();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["commands"][0]["options"], json!(["NOPASSWD"]));
    for rule in [
        "airlock.Dom0Poweroff + sys-gui dom0 allow",
        "airlock.Dom0Poweroff * @anyvm @anyvm deny",
        "airlock.AppSessionReady + sys-gui @tag:guivm-sys-gui allow",
        "airlock.AppSessionReady * @anyvm @anyvm deny",
        "admin.vm.Stats * sys-gui dom0 allow",
    ] {
        includes(&report["hostPoweroffPolicy"], rule);
    }
    assert!(
        !report["hostEtc"]
            .as_array()
            .unwrap()
            .iter()
            .any(|name| text(name).starts_with("airlock/config-inputs/"))
    );

    let temporary = tempfile::tempdir()?;
    let mut handler = report["hostPoweroffService"].clone();
    handler["program"] = json!(common::tool("printf")?);
    handler["args"] = json!(["poweroff-requested"]);
    for (source, argument, allowed) in [
        ("sys-gui", "", true),
        ("sys-gui", "reboot", false),
        ("usr-assistant", "", false),
        ("", "", false),
    ] {
        let output = common::run(
            common::launcher(temporary.path(), &handler)?
                .env("QREXEC_REMOTE_DOMAIN", source)
                .env("QREXEC_SERVICE_ARGUMENT", argument),
            None,
        )?;
        assert_eq!(output.status.success(), allowed);
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).contains("poweroff-requested"),
            allowed
        );
    }
    Ok(())
}

/// Root admission remains a narrow controller-owned operation for the explicitly declared VM targets.
#[test]
#[ignore = "explicit guarded-store package builds"]
fn package_pool_admission_uses_narrow_root_receivers() -> Result<()> {
    let report = crate::packaged::inspect_configuration(
        "pool_admission_module/admission_receiver",
        "airlock-machine",
    )?;
    assert_eq!(report["matchingRuleCount"], 1);
    assert_eq!(report["sudoUsers"], json!(["airlock"]));
    assert_eq!(report["sudoOptions"], json!(["NOPASSWD"]));
    assert_eq!(report["handler"]["args"][0], "admission-adapter");
    assert_eq!(report["handler"]["args"][1], "handler");
    assert_eq!(report["handler"]["inherit_args"], false);
    for target in report["targets"].as_array().unwrap() {
        includes(&report["rootReceiver"]["args"], text(target));
        includes(
            &report["policy"],
            &format!(
                "airlock.Pool.AdmitIncremental +{target} usr-assistant dom0 allow",
                target = text(target)
            ),
        );
    }
    includes(
        &report["policy"],
        "airlock.Pool.AdmitIncremental * @anyvm @anyvm deny",
    );
    assert_eq!(report["incrementalHandler"]["args"][1], "handler");
    assert_eq!(report["receivers"].as_array().unwrap().len(), 2);
    assert_eq!(report["options"], json!([["NOPASSWD"], ["NOPASSWD"]]));
    includes(&report["receivers"][1]["args"], "--incremental");
    for receiver in report["receivers"].as_array().unwrap() {
        assert_eq!(receiver["args"][0], "admission-adapter");
        assert_eq!(receiver["args"][1], "receive");
        assert_eq!(receiver["argument_count"], 2);
    }
    Ok(())
}

/// Packaged search metadata supports the installed GNOME major and enables the same source UUID.
#[test]
#[ignore = "explicit guarded-store package builds"]
fn package_search_extension_metadata_matches_the_shell() -> Result<()> {
    let report =
        crate::packaged::inspect_configuration("vm_search/search_extension", "airlock-machine")?;
    includes(&report["overrides"], text(&report["metadata"]["uuid"]));
    let version = text(&report["shellVersion"]).split('.').next().unwrap();
    includes(&report["metadata"]["shell-version"], version);
    includes(&report["files"], "extension.js");
    includes(&report["files"], "model.js");
    includes(&report["source"], "InjectionManager");
    Ok(())
}

/// Common protocol headers and both Qubes endpoints receive the same negotiated window-state changes.
#[test]
#[ignore = "requires explicitly prepared offline Nix sources"]
fn qubes_gui_packages_share_protocol_and_window_state_patches() -> Result<()> {
    let nix = context()?;
    let report = inspect(&nix, "qubes_gui_window_state/window_state", json!({}))?;
    for (key, patches) in [
        (
            "common",
            &[
                "0001-protocol-add-maximize-window-flags.patch",
                "0002-protocol-add-interactive-window-move-message.patch",
            ][..],
        ),
        (
            "agent",
            &[
                "0001-gui-agent-forward-minimize-and-maximize-requests.patch",
                "0002-gui-agent-forward-interactive-window-move-requests.patch",
            ],
        ),
        (
            "daemon",
            &[
                "0001-gui-daemon-apply-maximize-window-flags.patch",
                "0002-gui-daemon-apply-interactive-window-move-requests.patch",
            ],
        ),
    ] {
        for patch in patches {
            assert!(
                report[key]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|path| text(path).ends_with(patch))
            );
        }
    }
    assert_eq!(report["preparedGuestAgent"], report["agent"]);
    for patch in report["daemon"].as_array().unwrap() {
        includes(&report["preparedGuiDaemon"], text(patch));
    }
    assert!(
        report["preparedGuiDaemon"]
            .as_array()
            .unwrap()
            .iter()
            .any(|path| {
                text(path).ends_with("0003-gui-daemon-leave-window-chrome-to-applications.patch")
            })
    );
    Ok(())
}

/// USB display startup depends on its own generation while independent recovery retains only explicitly required services.
#[test]
#[ignore = "requires explicitly prepared offline Nix sources"]
fn usb_display_and_recovery_keep_independent_boot_and_login_state() -> Result<()> {
    let nix = context()?;
    let report = nix
        .evaluate(
            "usb-display",
            "usb_dev/independent_display_startup",
            json!({"root": nix.prepared}),
        )?
        .value()?;
    assert_eq!(
        report["specialisations"],
        json!(["usb-lab", "usb-text-recovery"])
    );
    assert_eq!(report["baseSetup"], false);
    assert_eq!(report["normalSetup"], true);
    assert_eq!(report["journal"]["Storage"], "persistent");
    assert_eq!(report["journal"]["SyncIntervalSec"], "1s");
    assert_eq!(report["conciseBootMenu"], true);
    assert_eq!(report["imageMarker"], "airlock-usb-dev-v2\n");
    let recovery = &report["recovery"];
    assert_eq!(recovery["role"], "recovery\n");
    assert_eq!(recovery["xen"], true);
    for key in ["display", "setup", "networkManager", "tailscale", "ssh"] {
        assert_eq!(recovery[key], false);
    }
    includes(&recovery["poolRecovery"], "Independent pool recovery");
    assert_eq!(recovery["store"], "/var/lib/airlock/recovery-store");
    assert_eq!(
        recovery["passwordFile"],
        "/var/lib/airlock/usb/local-password.hash"
    );
    for login in report["dom0Logins"].as_array().unwrap() {
        assert_eq!(
            login,
            &json!({"mutable": false, "account": "user", "terminalAccount": "user", "uid": 1000, "home": "/home/user", "passwordFile": "/var/lib/airlock/usb/local-password.hash", "rootHash": "!"})
        );
    }
    assert_eq!(report["hasPasswordService"], false);
    assert_eq!(report["labHasPasswordService"], false);
    for key in ["displayRequires", "displayAfter"] {
        assert!(
            !report[key]
                .as_array()
                .unwrap()
                .contains(&json!("airlock-usb-gui-password.service"))
        );
    }
    assert_eq!(report["hybridLogin"], report["labLogin"]);
    assert_eq!(
        report["labLogin"],
        json!({"password": "password", "initialHash": null, "mutable": false})
    );
    assert_eq!(report["normalPassword"], "airlock");
    Ok(())
}
