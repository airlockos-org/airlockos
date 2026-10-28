//! Hotplug events own independent qrexec process trees until cancellation and reaping finish.

use crate::common::{self, peers::Peers};
use anyhow::Result;
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    io::Write,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

/// Interactive driver with acknowledgements on a regular file, so waits remain bounded.
struct Forwarder {
    // Temporary peer links, process receipts and private output streams.
    temporary: tempfile::TempDir,
    // Driver owning all transport children.
    child: Child,
    // Driver output records exactly one acknowledgement for each accepted action.
    output: PathBuf,
    // Number of actions whose acknowledgements have been observed.
    actions: usize,
    // Literal sender path used to test qrexec's shell quoting boundary.
    sender: PathBuf,
}

impl Forwarder {
    /// Spawn the actual sender owner with an inert qrexec peer.
    fn new() -> Result<Self> {
        let temporary = tempfile::tempdir()?;
        let directory = temporary.path();
        let qrexec = common::peer_link(directory, "input-qrexec")?;
        let output = directory.join("stdout");
        let sender = directory.join("sender ' with spaces");
        let driver = common::binary("AIRLOCK_INPUT_TEST_BIN", "examples/test_input");
        let child = Command::new(driver)
            .arg("forward")
            .arg(qrexec)
            .arg(&sender)
            .env("AIRLOCK_TEST_CALLS", directory.join("calls.jsonl"))
            .env("AIRLOCK_TEST_FAILURE", directory.join("failure"))
            .stdin(Stdio::piped())
            .stdout(File::create(&output)?)
            .stderr(File::create(directory.join("stderr"))?)
            .process_group(0)
            .spawn()?;
        Ok(Self {
            temporary,
            child,
            output,
            actions: 0,
            sender,
        })
    }

    /// Wait for the driver to finish an action without blocking on a pipe read.
    fn send(&mut self, action: &str, number: u32) -> Result<()> {
        writeln!(
            self.child.stdin.as_mut().unwrap(),
            "{action} /dev/input/event{number}"
        )?;
        self.child.stdin.as_mut().unwrap().flush()?;
        self.actions += 1;
        common::until(|| Ok(fs::read_to_string(&self.output)?.lines().count() == self.actions))
    }

    /// Wait for complete atomically appended launch records.
    fn calls(&self, count: usize) -> Result<Vec<Value>> {
        let path = self.temporary.path().join("calls.jsonl");
        let mut rows = Vec::new();
        common::until(|| {
            rows = match fs::read_to_string(&path) {
                Ok(text) => text
                    .lines()
                    .map(serde_json::from_str)
                    .collect::<std::result::Result<_, _>>()?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                Err(error) => return Err(error.into()),
            };
            Ok(rows.len() >= count)
        })?;
        Ok(rows)
    }

    /// Close the interactive protocol and require clean driver shutdown.
    fn finish(&mut self) -> Result<()> {
        drop(self.child.stdin.take());
        common::until(|| Ok(self.child.try_wait()?.is_some()))?;
        assert!(self.child.wait()?.success());
        Ok(())
    }
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = rustix::process::kill_process_group(
                rustix::process::Pid::from_child(&self.child),
                rustix::process::Signal::KILL,
            );
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Determine whether an observed process identity still belongs to the kernel.
fn alive(row: &Value) -> bool {
    Path::new(&format!("/proc/{pid}", pid = row["pid"])).exists()
}

/// Duplicates do not overlap senders and pointer replug leaves the keyboard working.
#[test]
fn duplicate_remove_and_replug_preserve_keyboard() -> Result<()> {
    let mut forwarder = Forwarder::new()?;
    forwarder.send("add", 1)?;
    forwarder.send("add", 2)?;
    forwarder.send("add", 2)?;
    let mut calls = forwarder.calls(2)?;
    calls.sort_by(|a, b| a["node"].as_str().cmp(&b["node"].as_str()));
    assert_eq!(calls.len(), 2);
    let sender = forwarder.sender.to_str().unwrap().replace('\'', "'\\''");
    assert_eq!(
        calls[0]["args"][3],
        format!("'{sender}' '/dev/input/event1'")
    );
    for row in &calls {
        assert_eq!(
            row["args"].as_array().unwrap().last().unwrap(),
            "DEFAULT:QUBESRPC airlock.InputDevice dom0"
        );
    }

    forwarder.send("remove", 2)?;
    assert!(alive(&calls[0]));
    forwarder.send("add", 2)?;
    common::until(|| {
        forwarder.send("reap", 1)?;
        Ok(!alive(&calls[1]))
    })?;
    assert_eq!(forwarder.calls(3)?.len(), 3);
    assert!(alive(&calls[0]));
    forwarder.finish()?;
    Ok(())
}

/// A failed sender is not retried by change events and does not stop another device.
#[test]
fn failed_pointer_does_not_retry_or_stop_keyboard() -> Result<()> {
    let mut forwarder = Forwarder::new()?;
    fs::write(forwarder.temporary.path().join("failure"), b"")?;
    forwarder.send("add", 1)?;
    forwarder.send("add", 2)?;
    let calls = forwarder.calls(2)?;
    let failed = calls
        .iter()
        .find(|row| row["node"] == "/dev/input/event2")
        .unwrap();
    common::until(|| {
        let pid = &failed["pid"];
        Ok(fs::read_to_string(format!("/proc/{pid}/stat"))?
            .split_whitespace()
            .nth(2)
            == Some("Z"))
    })?;
    forwarder.send("reap", 1)?;
    forwarder.send("add", 2)?;
    assert_eq!(forwarder.calls(2)?.len(), 2);
    assert!(alive(
        calls
            .iter()
            .find(|row| row["node"] == "/dev/input/event1")
            .unwrap()
    ));
    assert!(!alive(failed));
    forwarder.finish()?;
    Ok(())
}

/// Supply an explicit physical observation while process peers stand in for the GUI VM.
fn input_inventory(peers: &Peers) -> Result<PathBuf> {
    let path = peers.path("physical.json");
    fs::write(
        &path,
        br#"[{"name":"Keyboard","keyboard":true,"pointer":false}]"#,
    )?;
    Ok(path)
}

/// A fresh guest-side observation of the kernel device registered by the upstream receiver.
fn receiver_reply() -> Value {
    json!({"schema":"airlock.input-receiver.v1","devices":[{"name":"dom0: Keyboard","keyboard":true,"pointer":false}]})
}

/// Forwarding starts only after readiness from the same still-running Xen instance.
#[test]
fn input_connection_requires_the_same_ready_instance() -> Result<()> {
    for state in [
        "ready",
        "no-keyboard",
        "pointer-only",
        "halted",
        "invalid-xid",
        "dom0-xid",
        "readiness-failed",
        "stopped",
        "restarted",
        "late-restarted",
        "discovery-failed",
    ] {
        let mut peers = Peers::new()?;
        peers.rules("qvm-check", json!([
            {"args":["--running","sys-gui"],"exists":"ready","exit":if state == "stopped" {1} else {0}},
            {"args":["--running","sys-gui"],"exit":if state == "halted" {1} else {0}}
        ]))?;
        peers.rules("qvm-ls", json!([
            {"args":["--raw-data","--fields","XID","sys-gui"],"missing":"xid-seen","write":{"xid-seen":""},"stdout":if state == "invalid-xid" {" 7\n"} else if state == "dom0-xid" {"0\n"} else {"7\n"}},
            {"args":["--raw-data","--fields","XID","sys-gui"],"missing":"second-xid","write":{"second-xid":""},"stdout":if state == "restarted" {"8\n"} else {"7\n"}},
            {"args":["--raw-data","--fields","XID","sys-gui"],"stdout":if state == "late-restarted" {"8\n"} else {"7\n"}}
        ]))?;
        peers.rules("qrexec-client", json!([
            {"args":["-d","sys-gui","-T","-w","60","DEFAULT:QUBESRPC airlock.InputReceiverReady dom0"],"write":{"ready":""},"exit":if state == "readiness-failed" {1} else {0}},
            {"args":["-d","sys-gui","-T","-w","5","DEFAULT:QUBESRPC airlock.InputReceiverReady dom0"],"stdout":serde_json::to_string(&if state == "no-keyboard" {json!({"schema":"airlock.input-receiver.v1","devices":[]})} else if state == "pointer-only" {json!({"schema":"airlock.input-receiver.v1","devices":[{"name":"dom0: Mouse","keyboard":false,"pointer":true}]})} else {receiver_reply()})?},
            {"args":["-d","7","-T","-w","5","DEFAULT:QUBESRPC airlock.InputInitialization+ready dom0"]},
            {"args":["-d","7","-T","-w","5","DEFAULT:QUBESRPC airlock.InputInitialization+retrying dom0"]}
        ]))?;
        peers.rules("systemctl", json!([
            {"args":["restart","airlock-gui-input.target"]},
            {"args":["is-active","--quiet","airlock-gui-input-discovery.service"],"exit":if state == "discovery-failed" {1} else {0}}
        ]))?;
        let physical = input_inventory(&peers)?;
        if state == "no-keyboard" {
            fs::write(&physical, "[]")?;
        } else if state == "pointer-only" {
            fs::write(
                &physical,
                r#"[{"name":"Mouse","keyboard":false,"pointer":true}]"#,
            )?;
        }
        let initialized = matches!(state, "ready" | "no-keyboard" | "pointer-only");
        let mut command =
            peers.command(common::binary("AIRLOCK_DOM0_BIN", "airlock-dom0-service"))?;
        command
            .args(["input", "connect", "--target", "sys-gui"])
            .env("AIRLOCK_INPUT_PHYSICAL", physical)
            .env("AIRLOCK_INPUT_QVM_CHECK", peers.path("bin/qvm-check"))
            .env("AIRLOCK_INPUT_QVM_LS", peers.path("bin/qvm-ls"))
            .env("AIRLOCK_INPUT_QREXEC", peers.path("bin/qrexec-client"))
            .env("AIRLOCK_INPUT_SYSTEMCTL", peers.path("bin/systemctl"));
        let output = common::run(&mut command, None)?;
        assert_eq!(
            output.status.success(),
            initialized,
            "state={state}: {error}",
            error = String::from_utf8_lossy(&output.stderr)
        );
        let calls = peers.calls()?;
        let forwarding: Vec<_> = calls
            .iter()
            .filter(|call| call["command"] == "systemctl")
            .collect();
        assert_eq!(
            forwarding.len(),
            match state {
                "ready" | "no-keyboard" | "pointer-only" | "late-restarted" => 3,
                "discovery-failed" => 2,
                _ => 0,
            }
        );
        assert_eq!(
            calls.iter().any(|call| call["args"]
                == json!([
                    "-d",
                    "7",
                    "-T",
                    "-w",
                    "5",
                    "DEFAULT:QUBESRPC airlock.InputInitialization+ready dom0"
                ])),
            initialized
        );
        if initialized {
            assert_eq!(
                calls
                    .iter()
                    .filter(|call| call["command"] == "qvm-ls")
                    .count(),
                3
            );
            assert!(calls.iter().any(|call| call["args"]
                == json!([
                    "-d",
                    "sys-gui",
                    "-T",
                    "-w",
                    "5",
                    "DEFAULT:QUBESRPC airlock.InputReceiverReady dom0"
                ])));
        }
    }
    Ok(())
}

/// The boot gate retries a cancelled lifecycle job but rejects an unavailable or replaced GUI instance.
#[test]
fn boot_input_readiness_survives_connection_job_cancellation() -> Result<()> {
    for state in ["ready", "unavailable", "restarted"] {
        let mut peers = Peers::new()?;
        peers.rules("qvm-check", json!([{}]))?;
        peers.rules(
            "qrexec-client",
            json!([{"stdout":serde_json::to_string(&receiver_reply())?}]),
        )?;
        peers.rules(
            "qvm-ls",
            json!([
                {"missing":"seen-xid", "write":{"seen-xid":""}, "stdout":"7\n"},
                {"stdout":if state == "restarted" {"8\n"} else {"7\n"}}
            ]),
        )?;
        peers.rules("systemctl", json!([
            {"args":["start","airlock-gui-input-connect.service"], "missing":"cancelled", "write":{"cancelled":""}, "exit":1},
            {"args":["start","airlock-gui-input-connect.service"], "exit":if state == "unavailable" {1} else {0}},
            {"args":["is-active","--quiet","airlock-gui-input-discovery.service"]}
        ]))?;
        let mut command =
            peers.command(common::binary("AIRLOCK_DOM0_BIN", "airlock-dom0-service"))?;
        command
            .args(["input", "boot-ready", "--target", "sys-gui"])
            .env("AIRLOCK_INPUT_PHYSICAL", input_inventory(&peers)?)
            .env("AIRLOCK_INPUT_QREXEC", peers.path("bin/qrexec-client"))
            .env("AIRLOCK_INPUT_QVM_CHECK", peers.path("bin/qvm-check"))
            .env("AIRLOCK_INPUT_QVM_LS", peers.path("bin/qvm-ls"))
            .env("AIRLOCK_INPUT_SYSTEMCTL", peers.path("bin/systemctl"));
        if state != "ready" {
            command.args(["--timeout", "1"]);
        }
        let output = common::run(&mut command, None)?;
        assert_eq!(
            output.status.success(),
            state == "ready",
            "{state}: {error}",
            error = String::from_utf8_lossy(&output.stderr)
        );
        if state != "restarted" {
            assert!(
                peers
                    .calls()?
                    .iter()
                    .filter(|call| call["args"]
                        == json!(["start", "airlock-gui-input-connect.service"]))
                    .count()
                    >= 2
            );
        }
    }
    Ok(())
}

/// Only an argument-free dom0 request can acknowledge a writable character device and executable handlers.
#[test]
fn input_receiver_readiness_enforces_caller_device_and_handler_guards() -> Result<()> {
    for state in [
        "ready",
        "relative-pointer",
        "multitouch-pointer",
        "wrong-caller",
        "argument",
        "regular-device",
        "missing-device",
        "missing-handler",
        "non-executable-handler",
        "missing-event",
        "regular-event",
    ] {
        let peers = Peers::new()?;
        let sys_input = peers.path("sys-input");
        fs::create_dir(peers.path("dev-input"))?;
        match state {
            "missing-event" => {}
            "regular-event" => fs::write(peers.path("dev-input/event1"), "not a device")?,
            _ => std::os::unix::fs::symlink("/dev/null", peers.path("dev-input/event1"))?,
        }
        let device_path = sys_input.join("event1/device");
        fs::create_dir_all(device_path.join("capabilities"))?;
        fs::write(device_path.join("name"), "dom0: Keyboard\n")?;
        fs::write(device_path.join("capabilities/key"), "100050000000\n")?;
        fs::write(
            device_path.join("capabilities/rel"),
            if state == "relative-pointer" {
                "3\n"
            } else {
                "0\n"
            },
        )?;
        fs::write(
            device_path.join("capabilities/abs"),
            if state == "multitouch-pointer" {
                "60000000000000\n"
            } else {
                "0\n"
            },
        )?;
        let first = peers.path("first-handler");
        fs::write(&first, "not executed")?;
        fs::set_permissions(&first, fs::Permissions::from_mode(0o755))?;
        let handler = peers.path("handler");
        if state != "missing-handler" {
            fs::write(&handler, "not executed")?;
            fs::set_permissions(
                &handler,
                fs::Permissions::from_mode(if state == "non-executable-handler" {
                    0o644
                } else {
                    0o755
                }),
            )?;
        }
        let device = match state {
            "regular-device" => {
                fs::write(peers.path("regular-device"), "not a device")?;
                peers.path("regular-device")
            }
            "missing-device" => peers.path("missing-device"),
            _ => PathBuf::from("/dev/null"),
        };
        let mut command = peers.command(common::binary("AIRLOCK_VM_BIN", "airlock-vm-service"))?;
        command
            .arg("input-receiver-ready")
            .arg("--sys-input")
            .arg(&sys_input)
            .arg("--dev-input")
            .arg(peers.path("dev-input"))
            .arg("--uinput")
            .arg(device)
            .arg("--handler")
            .arg(first)
            .arg("--handler")
            .arg(handler)
            .env(
                "QREXEC_REMOTE_DOMAIN",
                if state == "wrong-caller" {
                    "sys-gui"
                } else {
                    "dom0"
                },
            )
            .env(
                "QREXEC_SERVICE_ARGUMENT",
                if state == "argument" {
                    "unexpected"
                } else {
                    ""
                },
            );
        let output = common::run(&mut command, None)?;
        assert_eq!(
            output.status.success(),
            matches!(
                state,
                "ready"
                    | "relative-pointer"
                    | "multitouch-pointer"
                    | "missing-event"
                    | "regular-event"
            ),
            "state={state}: {error}",
            error = String::from_utf8_lossy(&output.stderr)
        );
        assert!(peers.calls()?.is_empty());
        if matches!(state, "missing-event" | "regular-event") {
            let reply: Value = serde_json::from_slice(&output.stdout)?;
            assert_eq!(reply["devices"], json!([]));
        }
        if matches!(state, "ready" | "relative-pointer" | "multitouch-pointer") {
            let reply: Value = serde_json::from_slice(&output.stdout)?;
            assert_eq!(reply["devices"][0]["name"], "dom0: Keyboard");
            assert_eq!(reply["devices"][0]["keyboard"], true);
            assert_eq!(reply["devices"][0]["pointer"], state != "ready");
        }
    }
    Ok(())
}

/// Startup does not inspect hardware; only dom0's closed handoff may activate the fixed login target.
#[test]
fn login_starts_only_on_dom0_initialization_and_retries_remain_recoverable() -> Result<()> {
    for state in [
        "ready",
        "retrying",
        "retry-active",
        "wrong-caller",
        "missing-caller",
        "argument",
        "release-failed",
    ] {
        let mut peers = Peers::new()?;
        peers.rules("systemctl", json!([
            {"args":["--no-block","start","airlock-input-initialized.target"],"exit":if state == "release-failed" {1} else {0}},
            {"args":["is-active","--quiet","airlock-input-initialized.target"],"exit":if state == "retry-active" {0} else {3}}
        ]))?;
        let mut startup = peers.command(common::binary("AIRLOCK_VM_BIN", "airlock-vm-service"))?;
        common::run(
            startup
                .arg("input-startup")
                .arg("--status-device")
                .arg(peers.path("status")),
            None,
        )?
        .checked()?;
        assert!(peers.calls()?.is_empty());
        let initial = fs::read_to_string(peers.path("status"))?;
        assert!(initial.contains("Initializing input forwarding"));

        let mut command = peers.command(common::binary("AIRLOCK_VM_BIN", "airlock-vm-service"))?;
        command
            .arg("input-initialization")
            .arg("--status-device")
            .arg(peers.path("status"))
            .arg("--systemctl")
            .arg(peers.path("bin/systemctl"))
            .env(
                "QREXEC_REMOTE_DOMAIN",
                if state == "wrong-caller" {
                    "usr-home"
                } else {
                    "dom0"
                },
            )
            .env(
                "QREXEC_SERVICE_ARGUMENT",
                match state {
                    "retrying" | "retry-active" => "retrying",
                    "argument" => "start-other-service",
                    _ => "ready",
                },
            );
        if state == "missing-caller" {
            command.env_remove("QREXEC_REMOTE_DOMAIN");
        }
        let output = common::run(&mut command, None)?;
        assert_eq!(
            output.status.success(),
            matches!(state, "ready" | "retrying" | "retry-active"),
            "{state}: {error}",
            error = String::from_utf8_lossy(&output.stderr)
        );
        let calls = peers.calls()?;
        if matches!(state, "wrong-caller" | "missing-caller" | "argument") {
            assert!(calls.is_empty());
        } else {
            assert_eq!(calls.len(), 1);
        }
        assert_eq!(
            fs::read_to_string(peers.path("status"))?.contains("Retrying automatically"),
            state == "retrying"
        );
        if state == "ready" {
            // A second completion after reconnect must not restart an already active GDM.
            common::run(&mut command, None)?.checked()?;
            assert!(peers.calls()?.iter().all(|call| call["args"]
                == json!(["--no-block", "start", "airlock-input-initialized.target"])));
        }
    }
    Ok(())
}

/// Read-only resampling rejects missing, partial or malformed receiver observations without starting services.
#[test]
fn input_check_requires_registered_physical_interfaces() -> Result<()> {
    for failure in [
        "",
        "empty",
        "wrong-name",
        "missing-pointer",
        "schema",
        "daemon",
        "rpc",
    ] {
        let mut peers = Peers::new()?;
        let physical = input_inventory(&peers)?;
        fs::write(&physical, br#"[{"name":"Keyboard","keyboard":true,"pointer":false},{"name":"Mouse","keyboard":false,"pointer":true}]"#)?;
        let mut reply = receiver_reply();
        if failure != "missing-pointer" {
            reply["devices"]
                .as_array_mut()
                .unwrap()
                .push(json!({"name":"dom0: Mouse","keyboard":false,"pointer":true}));
        }
        match failure {
            "empty" => reply["devices"] = json!([]),
            "wrong-name" => reply["devices"][0]["name"] = json!("sys-usb: Keyboard"),
            "schema" => reply["schema"] = json!("unknown"),
            _ => {}
        }
        peers.rules("systemctl",json!([{"args":["is-active","--quiet","airlock-gui-input-discovery.service"],"exit":if failure == "daemon" {1} else {0}}]))?;
        peers.rules("qrexec-client",json!([{"stdout":serde_json::to_string(&reply)?,"exit":if failure == "rpc" {1} else {0}}]))?;
        let mut command =
            peers.command(common::binary("AIRLOCK_DOM0_BIN", "airlock-dom0-service"))?;
        command
            .args(["input", "check", "--target", "sys-gui"])
            .env("AIRLOCK_INPUT_PHYSICAL", physical)
            .env("AIRLOCK_INPUT_SYSTEMCTL", peers.path("bin/systemctl"))
            .env("AIRLOCK_INPUT_QREXEC", peers.path("bin/qrexec-client"));
        let output = common::run(&mut command, None)?;
        assert_eq!(
            output.status.success(),
            failure.is_empty(),
            "{failure}: {error}",
            error = String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            peers
                .calls()?
                .iter()
                .all(|call| call["command"] == "qrexec-client"
                    || call["args"]
                        == json!([
                            "is-active",
                            "--quiet",
                            "airlock-gui-input-discovery.service"
                        ]))
        );
    }
    Ok(())
}
