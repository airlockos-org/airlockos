//! Desktop process boundaries retain workspace identity, readiness and one-shot application submission.

use crate::common::{self, peers::Peers};
use anyhow::Result;
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::{
        fs::{PermissionsExt, symlink},
        net::UnixListener,
    },
    process::Command,
    time::{Duration, Instant},
};

const IDENTITY: &str = "738a6af9-8e51-590d-afe4-790b26fbca79";

const TOKEN: &str = "728a6af9-8e51-590d-afe4-790b26fbca79";

/// GNOME receives both a resolvable icon and the installed notification source identity.
fn assert_notification_identity(call: &Value) {
    let arguments = call["args"].as_array().unwrap();
    for expected in [
        "--app-name=AirlockOS",
        "--icon=org.airlockos.Airlock",
        "--hint=string:desktop-entry:org.airlockos.Desktop",
    ] {
        assert!(arguments.contains(&json!(expected)), "{call}");
    }
}

/// A failed private-storage service prevents graphical probes, even if a display manager could run.
#[test]
fn boot_health_refuses_failed_private_storage_before_graphical_probes() -> Result<()> {
    let mut peers = Peers::new()?;
    peers.rules(
        "systemctl",
        json!([{
            "args":["is-active", "--quiet", "airlock-qubes-rw-init.service"], "exit":1
        }]),
    )?;
    let output = common::run(
        peers
            .command(common::binary(
                "AIRLOCK_VM_SERVICE_BIN",
                "airlock-vm-service",
            ))?
            .args(["boot-health", "desktop"]),
        None,
    )?;
    assert!(!output.status.success());
    let calls = peers.calls()?;
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0]["args"],
        json!(["is-active", "--quiet", "airlock-qubes-rw-init.service"])
    );
    Ok(())
}

/// The host waits for graphical health and refuses stale replies from a replaced GUI instance.
#[test]
fn boot_desktop_wait_checks_health_generation_and_xen_instance() -> Result<()> {
    use crate::coordinator::fixture::{declaration, store};

    for state in [
        "ready",
        "failed-display",
        "wrong-generation",
        "restarted",
        "dom0-xid",
    ] {
        let mut peers = Peers::new()?;
        let topology = json!({"schema":"airlock.qubes-topology.v1", "domains":{"sys-gui":declaration("sys-gui", 1)}});
        fs::write(peers.path("topology.json"), serde_json::to_vec(&topology)?)?;
        peers.rules("qvm-check", json!([{}]))?;
        peers.rules(
            "qvm-ls",
            json!([
                {"missing":"seen-xid", "write":{"seen-xid":""}, "stdout":if state == "dom0-xid" {"0\n"} else {"7\n"}},
                {"stdout":if state == "restarted" {"8\n"} else if state == "dom0-xid" {"0\n"} else {"7\n"}}
            ]),
        )?;
        peers.rules("qrexec-client", json!([
            {"args":["-d","sys-gui","user:readlink -f /run/current-system"], "stdout":store("sys-gui-system", if state == "wrong-generation" {2} else {1})},
            {"args":["-d","sys-gui","root:/run/current-system/sw/bin/airlock-vm-service boot-health desktop"], "exit":if state == "failed-display" {1} else {0}}
        ]))?;
        let output = common::run(
            peers
                .command(common::binary("AIRLOCK_DOM0_BIN", "airlock-dom0-service"))?
                .args(["wait-desktop-ready", "--timeout", "1", "--topology"])
                .arg(peers.path("topology.json")),
            None,
        )?;
        assert_eq!(
            output.status.success(),
            state == "ready",
            "{state}: {error}",
            error = String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

/// Notifications offer one action and retry only through the existing boot RPC.
#[test]
fn boot_notifications_retry_or_dismiss_once() -> Result<()> {
    for action in ["retry", "dismiss"] {
        let mut peers = Peers::new()?;
        peers.rules("boot-rpc",json!([
            {"contains":"airlock.BootStatus","exists":"status-seen","stdout":"{\"status\":\"complete\",\"desktop_ready\":true}"},
            {"contains":"airlock.BootStatus","missing":"transport-seen","exit":126,"stderr":"Request refused","write":{"transport-seen":""}},
            {"contains":"airlock.BootStatus","missing":"progress-seen","stdout":"{\"status\":\"working\",\"desktop_ready\":true,\"stage\":\"configure\",\"detail\":\"Preparing application VMs\"}","write":{"progress-seen":""}},
            {"contains":"airlock.BootStatus","stdout":"{\"status\":\"degraded\",\"desktop_ready\":true}","write":{"status-seen":""}},
            {"contains":"airlock.BootRetry"}
        ]))?;
        peers.rules(
            "notify-send",
            json!([
                {"contains":"--print-id","missing":"notification-seen","exit":1,"stderr":"notification service is starting","write":{"notification-seen":""}},
                {"contains":"--print-id","stdout":"42\n"},
                {"stdout":format!("{action}\n")}
            ]),
        )?;
        let mut command = peers.command(common::binary(
            "AIRLOCK_SYS_GUI_BIN",
            "airlock-sys-gui-service",
        ))?;
        command
            .arg("boot-notification")
            .env("AIRLOCK_QVM_RUN", peers.path("bin/boot-rpc"))
            .env("AIRLOCK_NOTIFY_SEND", peers.path("bin/notify-send"));
        peers.run(&mut command)?;
        let calls = peers.calls()?;
        for call in calls.iter().filter(|call| call["command"] == "notify-send") {
            assert_notification_identity(call);
        }
        assert!(calls.iter().any(|call| {
            call["args"]
                .as_array()
                .unwrap()
                .contains(&json!("Preparing application VMs"))
        }));
        assert!(calls.iter().any(|call| {
            call["args"]
                .as_array()
                .unwrap()
                .contains(&json!("--replace-id=42"))
        }));
        assert_eq!(
            calls
                .iter()
                .filter(|call| call["args"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("--action=retry=Retry")))
                .count(),
            1
        );
        assert_eq!(
            calls
                .iter()
                .any(|call| call["args"].as_array().unwrap().last()
                    == Some(&json!("airlock.BootRetry"))),
            action == "retry"
        );
    }
    Ok(())
}

/// Workspace reservations use Qubes UUIDs and accept only a literal UUID tuple from GDBus.
#[test]
fn workspace_reservations_preserve_identity_without_evaluating_bus_output() -> Result<()> {
    let mut peers = Peers::new()?;
    peers.rules(
        "desktop-qrexec",
        json!([{"args":["--","usr-home","admin.vm.property.Get+uuid"],"stdout":format!("0\u{0}default=False type=str {IDENTITY}")}]),
    )?;
    for reply in [
        format!("('{TOKEN}',)"),
        "not a tuple".into(),
        "('not-a-uuid',)".into(),
        "('x'); arbitrary_code()".into(),
    ] {
        peers.rules("workspace-bus", json!([{"stdout":reply}]))?;
        let mut command = peers.command(common::binary(
            "AIRLOCK_SYS_GUI_BIN",
            "airlock-sys-gui-service",
        ))?;
        command
            .args(["workspace", "prepare", "usr-home"])
            .env("AIRLOCK_QREXEC_CLIENT_VM", peers.path("bin/desktop-qrexec"))
            .env("AIRLOCK_GDBUS", peers.path("bin/workspace-bus"));
        let output = common::run(&mut command, None)?;
        assert_eq!(
            output.status.success(),
            reply.starts_with(&format!("('{TOKEN}'"))
        );
        if output.status.success() {
            assert_eq!(String::from_utf8(output.stdout)?.trim(), TOKEN);
        }
    }
    let calls = peers.calls()?;
    assert!(calls.iter().any(|call| {
        call["args"]
            .as_array()
            .unwrap()
            .ends_with(&[json!("org.airlock.Workspaces.Prepare"), json!(IDENTITY)])
    }));
    let mut command = peers.command(common::binary(
        "AIRLOCK_SYS_GUI_BIN",
        "airlock-sys-gui-service",
    ))?;
    command
        .args(["workspace", "cancel", TOKEN])
        .env("AIRLOCK_GDBUS", peers.path("bin/workspace-bus"));
    peers.run(&mut command)?;
    assert!(
        peers.calls()?.last().unwrap()["args"]
            .as_array()
            .unwrap()
            .ends_with(&[json!("org.airlock.Workspaces.Cancel"), json!(TOKEN)])
    );
    Ok(())
}

/// Session readiness uses the VM's advertised RPC and does not start any VM while selecting it.
#[test]
fn session_readiness_follows_the_advertised_interface() -> Result<()> {
    for (supported, expected) in [
        (true, "airlock.AppSessionReady"),
        (false, "qubes.WaitForSession"),
    ] {
        let mut peers = Peers::new()?;
        peers.rules(
            "desktop-qrexec",
            json!([{"args":["--","usr-home","admin.vm.feature.Get+supported-rpc.airlock.AppSessionReady"],"stdout":if supported {"0\u{0}1"} else {"2\u{0}QubesFeatureNotFoundError\u{0}\u{0}missing\u{0}"}}]),
        )?;
        let mut command = peers.command(common::binary(
            "AIRLOCK_SYS_GUI_BIN",
            "airlock-sys-gui-service",
        ))?;
        command
            .args(["readiness-service", "usr-home"])
            .env("AIRLOCK_QREXEC_CLIENT_VM", peers.path("bin/desktop-qrexec"));
        assert_eq!(
            String::from_utf8(peers.run(&mut command)?)?.trim(),
            expected
        );
        assert_eq!(peers.calls()?.len(), 1);
    }
    Ok(())
}

/// Readiness can retry, but a failed submission cancels its real workspace token without resubmission.
#[test]
fn launcher_retries_readiness_but_submits_the_application_once() -> Result<()> {
    for (failure, application_status) in [
        ("retry", 0),
        ("application", 42),
        ("timeout", 0),
        ("workspace", 0),
        ("discovery", 0),
    ] {
        let mut peers = Peers::new()?;
        peers.rules("desktop-qrexec", json!([
            {"args":["--","usr-home","admin.vm.feature.Get+supported-rpc.airlock.AppSessionReady"],"missing":"discovery-seen","write":{"discovery-seen":""},"exit":if failure == "discovery" {1} else {0},"stdout":"0\u{0}1"},
            {"args":["--","usr-home","admin.vm.feature.Get+supported-rpc.airlock.AppSessionReady"],"stdout":"0\u{0}1"},
            {"args":["--","usr-home","admin.vm.property.Get+uuid"],"stdout":format!("0\u{0}default=False type=str {IDENTITY}")}
        ]))?;
        peers.rules("workspace-bus", json!([
            {"contains":"org.airlock.Workspaces.Prepare","stdout":format!("('{TOKEN}',)"),"exit":if failure == "workspace" {1} else {0}},
            {"contains":"org.airlock.Workspaces.Cancel"}
        ]))?;
        let mut rules = Vec::new();
        if matches!(failure, "retry" | "timeout") {
            let mut fail = json!({"contains":"airlock.AppSessionReady","exit":1});
            if failure == "retry" {
                fail["missing"] = json!("readiness-seen");
                fail["write"] = json!({"readiness-seen":""});
            }
            rules.push(fail);
        }
        rules.extend([
            json!({"contains":"airlock.AppSessionReady"}),
            json!({"contains":"airlock.StartApp+editor","exit":application_status}),
        ]);
        peers.rules("qvm-run", json!(rules))?;
        for name in ["systemd-cat", "notify-send"] {
            peers.rules(name, json!([{}]))?;
        }
        let mut command = peers.command(common::binary(
            "AIRLOCK_SYS_GUI_BIN",
            "airlock-sys-gui-service",
        ))?;
        command
            .args([
                "launch",
                "--workspace",
                "--readiness-timeout",
                "3",
                "usr-home: Editor",
                "usr-home",
                "airlock.StartApp+editor",
            ])
            .env("AIRLOCK_QREXEC_CLIENT_VM", peers.path("bin/desktop-qrexec"))
            .env("AIRLOCK_GDBUS", peers.path("bin/workspace-bus"))
            .env("AIRLOCK_QVM_RUN", peers.path("bin/qvm-run"))
            .env("AIRLOCK_SYSTEMD_CAT", peers.path("bin/systemd-cat"))
            .env("AIRLOCK_NOTIFY_SEND", peers.path("bin/notify-send"));
        let output = common::run(&mut command, None)?;
        let calls = peers.calls()?;
        let count = |argument: &str| {
            calls
                .iter()
                .filter(|call| call["args"].as_array().unwrap().contains(&json!(argument)))
                .count()
        };
        if failure == "timeout" {
            assert_eq!(output.status.code(), Some(124));
            assert_eq!(
                count("airlock.StartApp+editor")
                    + count("org.airlock.Workspaces.Prepare")
                    + count("org.airlock.Workspaces.Cancel"),
                0
            );
        } else if failure == "workspace" {
            assert_eq!(output.status.code(), Some(1));
            assert_eq!(
                count("airlock.StartApp+editor") + count("org.airlock.Workspaces.Cancel"),
                0
            );
            assert_eq!(count("org.airlock.Workspaces.Prepare"), 1);
        } else {
            assert_eq!(
                output.status.code(),
                Some(application_status),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(count("airlock.StartApp+editor"), 1);
            assert_eq!(count("org.airlock.Workspaces.Prepare"), 1);
            assert_eq!(
                count("org.airlock.Workspaces.Cancel"),
                usize::from(application_status != 0)
            );
            let application = calls
                .iter()
                .find(|call| {
                    call["args"]
                        .as_array()
                        .unwrap()
                        .contains(&json!("airlock.StartApp+editor"))
                })
                .unwrap();
            assert_eq!(
                application["args"],
                json!([
                    "--auto",
                    "--gui",
                    "--service",
                    "usr-home",
                    "airlock.StartApp+editor"
                ])
            );
        }
        assert_eq!(
            calls.iter().any(|call| call["command"] == "notify-send"),
            matches!(failure, "timeout" | "workspace" | "application")
        );
        if let Some(notice) = calls.iter().find(|call| call["command"] == "notify-send") {
            assert_notification_identity(notice);
            let arguments = notice["args"].as_array().unwrap();
            let separator = arguments
                .iter()
                .position(|argument| argument == "--")
                .unwrap();
            let title = arguments[separator + 1].as_str().unwrap();
            assert_eq!(title, "Launch not confirmed: Editor in usr-home");
            if failure == "application" {
                assert!(
                    arguments[separator + 2]
                        .as_str()
                        .unwrap()
                        .contains("exit status 42")
                );
            }
        }
    }
    Ok(())
}

/// Upstream StartApp can remain connected while an already opened application runs beyond ninety seconds.
#[test]
#[ignore = "waits 91 seconds to cover a healthy upstream application-lifetime channel"]
fn application_lifetime_does_not_trigger_a_false_launch_failure() -> Result<()> {
    let mut peers = Peers::new()?;
    peers.rules("desktop-qrexec", json!([{"stdout":"0\u{0}1"}]))?;
    peers.rules(
        "qvm-run",
        json!([
            {"contains":"airlock.AppSessionReady"},
            {"contains":"qubes.StartApp+org.gnome.Console", "delay_ms":91000}
        ]),
    )?;
    for name in ["systemd-cat", "notify-send"] {
        peers.rules(name, json!([{}]))?;
    }
    let mut command = peers.command(common::binary(
        "AIRLOCK_SYS_GUI_BIN",
        "airlock-sys-gui-service",
    ))?;
    command
        .args([
            "launch",
            "usr-assistant: Console",
            "usr-assistant",
            "qubes.StartApp+org.gnome.Console",
        ])
        .env("AIRLOCK_QREXEC_CLIENT_VM", peers.path("bin/desktop-qrexec"))
        .env("AIRLOCK_QVM_RUN", peers.path("bin/qvm-run"))
        .env("AIRLOCK_SYSTEMD_CAT", peers.path("bin/systemd-cat"))
        .env("AIRLOCK_NOTIFY_SEND", peers.path("bin/notify-send"));
    let started = std::time::Instant::now();
    let mut child =
        airlock_tests::system::Job::spawn(&mut command, &peers.path("application-lifetime"))?;
    assert!(child.wait(Duration::from_secs(120))?.success());
    assert!(started.elapsed() >= Duration::from_secs(91));

    let calls = peers.calls()?;
    assert_eq!(
        calls
            .iter()
            .filter(|call| call["command"] == "qvm-run"
                && call["args"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("qubes.StartApp+org.gnome.Console")))
            .count(),
        1
    );
    assert!(!calls.iter().any(|call| call["command"] == "notify-send"));
    Ok(())
}

/// Menu-only startup and non-GNOME launches never reserve a workspace.
#[test]
fn launcher_reserves_only_for_a_requested_workspace_application() -> Result<()> {
    for (workspace, service) in [
        (true, None),
        (
            false,
            Some("airlock.OpenUrl+https://example.test/a?x=$literal"),
        ),
    ] {
        let mut peers = Peers::new()?;
        peers.rules(
            "desktop-qrexec",
            json!([{"stdout":"2\u{0}QubesFeatureNotFoundError\u{0}\u{0}missing\u{0}"}]),
        )?;
        peers.rules(
            "qvm-run",
            json!([{"contains":"qubes.WaitForSession"},{"contains":service}]),
        )?;
        let mut command = peers.command(common::binary(
            "AIRLOCK_SYS_GUI_BIN",
            "airlock-sys-gui-service",
        ))?;
        command
            .args(["launch", "Web link", "usr-home"])
            .env("AIRLOCK_QREXEC_CLIENT_VM", peers.path("bin/desktop-qrexec"))
            .env("AIRLOCK_QVM_RUN", peers.path("bin/qvm-run"));
        if workspace {
            command.arg("--workspace");
        }
        if let Some(service) = service {
            command.arg(service);
        }
        peers.run(&mut command)?;
        let calls = peers.calls()?;
        assert_eq!(calls.len(), if service.is_some() { 3 } else { 2 });
        if let Some(service) = service {
            assert_eq!(
                calls.last().unwrap()["args"],
                json!(["--auto", "--gui", "--service", "usr-home", service])
            );
        }
    }
    Ok(())
}

/// Run the native guest endpoint with a stale inherited display and only fixture-owned helpers/state.
fn guest_session(peers: &Peers) -> Result<Command> {
    let mut command = peers.command(common::binary("AIRLOCK_VM_BIN", "airlock-vm-service"))?;
    command
        .args(["session-ready", "--timeout", "1"])
        .env("QREXEC_REMOTE_DOMAIN", "sys-gui")
        .env_remove("QREXEC_SERVICE_ARGUMENT")
        .env("XDG_RUNTIME_DIR", peers.path("runtime"))
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .env("DISPLAY", ":stale")
        .env("XAUTHORITY", "/stale/authority")
        .env("AIRLOCK_SYSTEMCTL", peers.path("bin/session-manager"))
        .env("AIRLOCK_XDPYINFO", peers.path("bin/session-display"));
    Ok(command)
}

/// Caller and service-argument restrictions reject a request before observing the user's session.
#[test]
fn guest_session_readiness_rejects_untrusted_callers_and_arguments() -> Result<()> {
    for (caller, argument) in [
        ("dom0", ""),
        ("usr-home", ""),
        ("", ""),
        ("sys-gui", "unexpected"),
    ] {
        let peers = Peers::new()?;
        let output = common::run(
            guest_session(&peers)?
                .env("QREXEC_REMOTE_DOMAIN", caller)
                .env("QREXEC_SERVICE_ARGUMENT", argument),
            None,
        )?;
        assert_eq!(output.status.code(), Some(1));
        assert!(peers.calls()?.is_empty());
    }
    Ok(())
}

/// Readiness requires every local dependency and obtains current display/authority from the user manager.
#[test]
fn guest_session_readiness_requires_the_current_graphical_session() -> Result<()> {
    for state in [
        "ready",
        "manager-retry",
        "missing-marker",
        "fake-bus",
        "empty-display",
        "probe-failure",
    ] {
        let mut peers = Peers::new()?;
        fs::create_dir(peers.path("runtime"))?;
        let _bus = if state == "fake-bus" {
            fs::write(peers.path("runtime/bus"), "not a socket")?;
            None
        } else {
            Some(UnixListener::bind(peers.path("runtime/bus"))?)
        };
        if state != "missing-marker" {
            fs::write(peers.path("runtime/airlock-app-session-ready"), "")?;
        }
        let environment = if state == "empty-display" {
            "DISPLAY=\n"
        } else {
            "DISPLAY=:99\nXAUTHORITY=/current/authority\n"
        };
        let mut address = format!("unix:path={bus}", bus = peers.path("runtime/bus").display());
        if state == "ready" {
            address.push_str(",guid=0123456789abcdef0123456789abcdef");
        }

        peers.rules("session-manager", json!([
            {"missing":"manager-seen", "write":{"manager-seen":""}, "exit":if state == "manager-retry" {1} else {0}, "stdout":environment},
            {"args":["--user","show-environment"],"stdout":environment}
        ]))?;
        peers.rules("session-display", json!([
            {"args":["-display",":99"],"env":{"DISPLAY":":99","XAUTHORITY":"/current/authority","DBUS_SESSION_BUS_ADDRESS":address},"exit":if state == "probe-failure" {1} else {0}}
        ]))?;
        let mut command = guest_session(&peers)?;
        if state == "ready" {
            command.env("DBUS_SESSION_BUS_ADDRESS", address);
        }
        let output = common::run(&mut command, None)?;
        let success = matches!(state, "ready" | "manager-retry");
        assert_eq!(
            output.status.code(),
            Some(if success { 0 } else { 124 }),
            "state={state}: {error}",
            error = String::from_utf8_lossy(&output.stderr)
        );
        let calls = peers.calls()?;
        let probes = calls
            .iter()
            .filter(|call| call["command"] == "session-display")
            .count();
        assert_eq!(probes != 0, success || state == "probe-failure");
        if state == "manager-retry" {
            assert!(
                calls
                    .iter()
                    .filter(|call| call["command"] == "session-manager")
                    .count()
                    >= 2
            );
        }
    }
    Ok(())
}

/// A stuck manager or X probe is cancelled within the endpoint budget and cannot report readiness.
#[test]
fn guest_session_readiness_bounds_stuck_probes() -> Result<()> {
    for stuck in ["session-manager", "session-display"] {
        let mut peers = Peers::new()?;
        fs::create_dir(peers.path("runtime"))?;
        let _bus = UnixListener::bind(peers.path("runtime/bus"))?;
        fs::write(peers.path("runtime/airlock-app-session-ready"), "")?;
        for tool in ["session-manager", "session-display"] {
            peers.rules(tool, json!([{"stdout":if tool == "session-manager" {"DISPLAY=:99\n"} else {""}, "delay_ms":if tool == stuck {10_000} else {0}}]))?;
        }
        let start = Instant::now();
        let output = common::run(&mut guest_session(&peers)?, None)?;
        assert_eq!(output.status.code(), Some(124));
        assert!(start.elapsed() < Duration::from_secs(4));
        let calls = peers.calls()?;
        assert_eq!(calls.len(), if stuck == "session-manager" { 1 } else { 2 });
    }
    Ok(())
}

/// Style publication writes one private runtime selection and refuses malformed or unreviewed changes.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_style_defaults_and_rejections() -> Result<()> {
    let peers = Peers::new()?;
    fs::create_dir(peers.path("runtime"))?;
    fs::create_dir(peers.path("persistent"))?;
    let binary = common::binary("AIRLOCK_SYS_GUI_BIN", "airlock-sys-gui-service");
    symlink(
        binary.parent().unwrap(),
        peers.path("runtime/current-system"),
    )?;
    let run = |request: Value, boot: bool| -> Result<airlock_vm_service::support::Output> {
        let mut command = Command::new("bwrap");
        command.args([
            "--die-with-parent",
            "--unshare-user",
            "--uid",
            "0",
            "--gid",
            "0",
            "--tmpfs",
            "/",
        ]);
        for path in ["/nix", "/home", "/etc", "/usr", "/bin", "/lib", "/lib64"] {
            if std::path::Path::new(path).exists() {
                command.args(["--ro-bind", path, path]);
            }
        }
        command
            .arg("--bind")
            .arg(peers.path("runtime"))
            .arg("/run")
            .arg("--bind")
            .arg(peers.path("persistent"))
            .arg("/rw")
            .args(["--tmpfs", "/tmp", "--proc", "/proc", "--dev", "/dev"])
            .arg(&binary)
            .arg("gui-style");
        if boot {
            command.arg("--boot");
        }
        common::run(&mut command, Some(serde_json::to_vec(&request)?))
    };
    let request = json!({"schema":"airlock.gui-style.v1","color_width":3,"revision":null});
    for change in [
        json!({"color_width":true}),
        json!({"color_width":0}),
        json!({"color_width":17}),
        json!({"revision":"branch-name"}),
        json!({"unknown":1}),
        json!({"schema":"unknown"}),
    ] {
        let mut damaged = request.clone();
        damaged
            .as_object_mut()
            .unwrap()
            .extend(change.as_object().unwrap().clone());
        assert!(!run(damaged, true)?.status.success());
        assert!(!peers.path("persistent/airlock/gui-border-width").exists());
    }
    assert!(!run(request.clone(), false)?.status.success());
    let record: Value = serde_json::from_slice(&run(request, true)?.checked()?)?;
    assert_eq!(record["status"], "boot-default");
    assert_eq!(record["daemon_count"], 0);
    let border = peers.path("persistent/airlock/gui-border-width");
    assert_eq!(fs::read(&border)?, b"3\n");
    assert_eq!(fs::metadata(border)?.permissions().mode() & 0o777, 0o644);
    assert_eq!(
        peers.read("persistent/airlock/gui-style-selection.json")?,
        record
    );
    Ok(())
}
