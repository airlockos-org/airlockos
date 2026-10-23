//! Capture transfer protects personal files, validates streams and binds every retry to its destination.

use crate::common;
use airlock_vm_service::support::Output;
use anyhow::Result;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::{fs::symlink, net::UnixListener},
    path::{Path, PathBuf},
    process::Command,
};

/// One sender and receiver with separate homes, durable state and a harmless graphical-session peer.
struct Capture {
    // Owns short socket paths and both homes for the complete scenario.
    temporary: tempfile::TempDir,
    // Holds the advertised session socket open without providing a real desktop bus.
    _bus: UnixListener,
}

impl Capture {
    /// Prepare only inert process peers; the production sender and receiver implement the transfer.
    fn new() -> Result<Self> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path();
        for name in ["home", "remote", "bin", "runtime"] {
            fs::create_dir(root.join(name))?;
        }
        for name in [
            "xdg-user-dir",
            "capture-open-peer",
            "capture-qrexec",
            "capture-systemctl",
            "capture-xdpyinfo",
        ] {
            common::peer_link(&root.join("bin"), name)?;
        }
        fs::write(root.join("runtime/airlock-app-session-ready"), b"")?;
        let bus = UnixListener::bind(root.join("runtime/bus"))?;
        Ok(Self {
            temporary,
            _bus: bus,
        })
    }

    /// Resolve fixture-owned state without allowing an absolute name to select the host filesystem.
    fn path(&self, name: &str) -> PathBuf {
        assert!(!Path::new(name).is_absolute());
        self.temporary.path().join(name)
    }

    /// Locate personal captures separately from sender receipts and receiving VM state.
    fn directory(&self, kind: &str, remote: bool) -> PathBuf {
        let home = if remote { "remote" } else { "home" };
        let directory = if kind == "image" {
            "Screenshots"
        } else {
            "Screencasts"
        };
        self.path(&format!("{home}/Media/{directory}"))
    }

    /// Build a child-local sender or receiver environment without changing the test process.
    fn command(&self, sender: bool, arguments: &[&str]) -> Command {
        let mut command = Command::new(if sender {
            common::binary("AIRLOCK_SYS_GUI_BIN", "airlock-sys-gui-service")
        } else {
            common::binary("AIRLOCK_VM_BIN", "airlock-vm-service")
        });
        if sender {
            command.arg("screen-capture");
        }
        command
            .args(arguments)
            .env("HOME", self.path("home"))
            .env("XDG_STATE_HOME", self.path("home/state"))
            .env("XDG_RUNTIME_DIR", self.path("runtime"))
            .env("AIRLOCK_XDG_USER_DIR", self.path("bin/xdg-user-dir"))
            .env("AIRLOCK_QREXEC_CLIENT_VM", self.path("bin/capture-qrexec"))
            .env("AIRLOCK_SYSTEMCTL", self.path("bin/capture-systemctl"))
            .env("AIRLOCK_XDPYINFO", self.path("bin/capture-xdpyinfo"))
            .env("AIRLOCK_TEST_CAPTURE_CALLS", self.path("calls.jsonl"))
            .env("AIRLOCK_TEST_CAPTURE_REMOTE", self.path("remote"))
            .env("AIRLOCK_TEST_CAPTURE_FAILURE", self.path("failure"))
            .env(
                "AIRLOCK_TEST_CAPTURE_VM",
                common::binary("AIRLOCK_VM_BIN", "airlock-vm-service"),
            )
            .env("QREXEC_REMOTE_DOMAIN", "sys-gui");
        for variable in ["AIRLOCK_NOTIFY_SEND", "AIRLOCK_GDBUS", "AIRLOCK_GIO"] {
            command.env(variable, self.path("bin/capture-open-peer"));
        }
        command
    }

    /// Deliver a complete image through the native receiver and decode its durable receipt.
    fn receive(&self, wire: &[u8]) -> Result<Value> {
        common::json(
            &mut self.command(false, &["capture-receive", "image"]),
            Some(wire.to_vec()),
        )
    }

    /// Run a native command and keep rejected operations available to assertions.
    fn run(
        &self,
        sender: bool,
        arguments: &[&str],
        wire: Option<Vec<u8>>,
        success: bool,
    ) -> Result<Output> {
        let output = common::run(&mut self.command(sender, arguments), wire)?;
        assert_eq!(
            output.status.success(),
            success,
            "{error}",
            error = String::from_utf8_lossy(&output.stderr)
        );
        Ok(output)
    }

    /// Count actual pending receipt files without depending on directory iteration order.
    fn pending(&self, target: &str) -> Result<Vec<PathBuf>> {
        files(&self.path(&format!(
            "home/state/airlock/captures/outgoing/{target}/pending"
        )))
    }

    /// Decode opener or notification invocations recorded by the inert process peer.
    fn calls(&self) -> Result<Vec<Value>> {
        let path = self.path("calls.jsonl");
        if !path.exists() {
            return Ok(Vec::new());
        }
        fs::read_to_string(path)?
            .lines()
            .map(|line| Ok(serde_json::from_str(line)?))
            .collect()
    }
}

/// List only existing scenario artifacts; an absent directory represents no published work.
fn files(directory: &Path) -> Result<Vec<PathBuf>> {
    if !directory.exists() {
        return Ok(Vec::new());
    }
    Ok(fs::read_dir(directory)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<_>>()?)
}

/// Frame literal capture bytes with the production wire schema and their content digest.
fn payload(name: &str) -> Result<(Value, Vec<u8>)> {
    let data = b"capture contents";
    let header = json!({
        "schema": "airlock.capture.v1", "id": "a".repeat(64), "name": name,
        "size": data.len(), "sha256": format!("{digest:x}", digest = Sha256::digest(data))
    });
    let mut wire = serde_json::to_vec(&header)?;
    wire.push(b'\n');
    wire.extend(data);
    Ok((header, wire))
}

/// Repeated imports reuse receipts, while colliding or later edited personal files remain untouched.
#[test]
fn capture_import_is_idempotent_and_preserves_personal_files() -> Result<()> {
    let capture = Capture::new()?;
    let (_, wire) = payload("Screenshot From today.png")?;
    let first = capture.receive(&wire)?;
    let destination = Path::new(first["path"].as_str().unwrap());
    assert_eq!(fs::read(destination)?, b"capture contents");
    assert_eq!(capture.receive(&wire)?, first);
    assert_eq!(files(&capture.directory("image", false))?, [destination]);

    fs::write(destination, b"later personal edit")?;
    let second = capture.receive(&wire)?;
    assert_ne!(second["path"], first["path"]);
    assert_eq!(fs::read(destination)?, b"later personal edit");
    assert_eq!(
        fs::read(second["path"].as_str().unwrap())?,
        b"capture contents"
    );

    for stem in ["x".repeat(236), "é".repeat(118)] {
        let capture = Capture::new()?;
        let name = format!("{stem}.png");
        let original = capture.directory("image", false).join(&name);
        fs::create_dir_all(original.parent().unwrap())?;
        fs::write(&original, b"personal file")?;
        let (_, wire) = payload(&name)?;
        let receipt = capture.receive(&wire)?;
        let destination = Path::new(receipt["path"].as_str().unwrap());
        assert!(destination.file_name().unwrap().len() <= 255);
        assert_eq!(fs::read(destination)?, b"capture contents");
        assert_eq!(fs::read(original)?, b"personal file");
        assert_eq!(capture.receive(&wire)?, receipt);
    }
    Ok(())
}

/// A reserved and already published file survives an interrupted acknowledgement without duplication.
#[test]
fn capture_import_resumes_a_reserved_receipt() -> Result<()> {
    let capture = Capture::new()?;
    let (header, wire) = payload("Screenshot From today.png")?;
    let destination = capture
        .directory("image", false)
        .join(header["name"].as_str().unwrap());
    fs::create_dir_all(destination.parent().unwrap())?;
    fs::write(&destination, b"capture contents")?;
    let receipt = json!({"id": header["id"], "path": destination, "sha256": header["sha256"], "kind": "image"});
    let record = capture.path(&format!(
        "home/state/airlock/captures/imported/{id}.json",
        id = header["id"].as_str().unwrap()
    ));
    fs::create_dir_all(record.parent().unwrap())?;
    fs::write(record, serde_json::to_vec(&receipt)?)?;
    assert_eq!(capture.receive(&wire)?, receipt);
    assert_eq!(files(&capture.directory("image", false))?, [destination]);
    Ok(())
}

/// Truncation, surplus bytes and wrong content never publish a partial file or import receipt.
#[test]
fn capture_stream_validation_precedes_publication() -> Result<()> {
    for data in [
        b"capture".as_slice(),
        b"capture contents!",
        b"Capture contents",
    ] {
        let capture = Capture::new()?;
        let (header, _) = payload("Capture.png")?;
        let mut wire = serde_json::to_vec(&header)?;
        wire.push(b'\n');
        wire.extend(data);
        capture.run(false, &["capture-receive", "image"], Some(wire), false)?;
        assert!(files(&capture.directory("image", false))?.is_empty());
        assert!(
            !capture
                .path("home/state/airlock/captures/imported")
                .exists()
        );
    }
    for (field, value) in [
        ("name", json!("../escape.png")),
        ("name", json!("x\n.png")),
        ("name", json!("link.svg")),
        ("id", json!("../../escape")),
        ("sha256", json!("bad")),
        ("size", json!(true)),
        ("size", json!(-1)),
        ("schema", json!("unknown")),
    ] {
        let capture = Capture::new()?;
        let (mut header, _) = payload("Capture.png")?;
        header[field] = value;
        let mut wire = serde_json::to_vec(&header)?;
        wire.push(b'\n');
        capture.run(false, &["capture-receive", "image"], Some(wire), false)?;
        assert!(!capture.directory("image", false).exists());
    }
    let capture = Capture::new()?;
    let result = common::run(
        capture
            .command(false, &["capture-receive", "image"])
            .env("QREXEC_REMOTE_DOMAIN", "other-vm"),
        Some(Vec::new()),
    )?;
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("capture caller is not authorized"));
    assert!(!capture.directory("image", false).exists());
    Ok(())
}

/// Failed delivery remains queued; retries preserve local sources and cannot redirect another target's work.
#[test]
fn capture_sender_retries_only_its_bound_destination() -> Result<()> {
    let capture = Capture::new()?;
    let source = capture.directory("image", false).join("Capture.png");
    fs::create_dir_all(source.parent().unwrap())?;
    fs::write(&source, b"finished capture")?;
    fs::write(capture.path("failure"), b"")?;
    capture.run(
        true,
        &["enqueue", "image", source.to_str().unwrap()],
        None,
        true,
    )?;
    let pending = capture.pending("usr-home")?;
    assert_eq!(pending.len(), 1);
    assert!(source.exists());
    fs::remove_file(capture.path("failure"))?;
    let other = capture.path("home/state/airlock/captures/outgoing/usr-work");
    fs::create_dir_all(&other)?;
    fs::write(other.join("backfill.json"), br#"{"complete":true}"#)?;
    capture.run(true, &["retry", "--target", "usr-work"], None, true)?;
    assert!(pending[0].exists());
    assert!(!capture.directory("image", true).exists());

    capture.run(true, &["retry"], None, true)?;
    assert!(capture.pending("usr-home")?.is_empty());
    let received = files(&capture.directory("image", true))?;
    assert_eq!(received.len(), 1);
    assert_eq!(fs::read(&received[0])?, fs::read(&source)?);
    capture.run(
        true,
        &["enqueue", "image", source.to_str().unwrap()],
        None,
        true,
    )?;
    assert_eq!(files(&capture.directory("image", true))?, received);
    Ok(())
}

/// Sender authorization refuses unrelated files and links; unfinished recording notifications do not queue work.
#[test]
fn capture_sender_does_not_queue_unrelated_or_unfinished_files() -> Result<()> {
    let capture = Capture::new()?;
    let outside = capture.path("outside.png");
    fs::write(&outside, b"capture")?;
    capture.run(
        true,
        &["enqueue", "image", outside.to_str().unwrap()],
        None,
        false,
    )?;
    fs::create_dir_all(capture.directory("image", false))?;
    let link = capture.directory("image", false).join("linked.png");
    symlink(outside, &link)?;
    capture.run(
        true,
        &["enqueue", "image", link.to_str().unwrap()],
        None,
        false,
    )?;
    assert!(capture.pending("usr-home")?.is_empty());

    let recording = capture.directory("video", false).join("Recording.webm");
    fs::create_dir_all(recording.parent().unwrap())?;
    fs::write(&recording, b"incomplete recording")?;
    capture.run(
        true,
        &["show", "video", recording.to_str().unwrap()],
        None,
        true,
    )?;
    assert!(capture.pending("usr-home")?.is_empty());
    assert!(
        !capture
            .path("home/state/airlock/captures/outgoing/usr-home/sent")
            .exists()
    );
    Ok(())
}

/// Opening uses a recorded receipt, its matching media kind and the receiver's current graphical session.
#[test]
fn capture_open_requires_the_matching_receipt_and_session() -> Result<()> {
    let capture = Capture::new()?;
    let (_, wire) = payload("Capture.png")?;
    let config = capture.path("receiver.json");
    fs::write(&config, br#"{"sources":["capture-display"]}"#)?;
    let receipt = common::json(
        capture
            .command(
                false,
                &[
                    "capture-receive",
                    "image",
                    "--config",
                    config.to_str().unwrap(),
                ],
            )
            .env("QREXEC_REMOTE_DOMAIN", "capture-display")
            .env("DISPLAY", ":stale"),
        Some(wire),
    )?;
    let mut request = serde_json::to_vec(&json!({"id": receipt["id"], "action": "show"}))?;
    request.push(b'\n');
    common::run(
        capture
            .command(
                false,
                &[
                    "capture-open",
                    "image",
                    "--config",
                    config.to_str().unwrap(),
                ],
            )
            .env("QREXEC_REMOTE_DOMAIN", "capture-display")
            .env("DISPLAY", ":stale"),
        Some(request.clone()),
    )?
    .checked()?;
    let calls = capture.calls()?;
    let last = calls.last().unwrap().as_array().unwrap();
    assert!(last.contains(&json!("org.freedesktop.FileManager1.ShowItems")));
    let path = receipt["path"].as_str().unwrap();
    assert!(
        last[last.len() - 2]
            .as_str()
            .unwrap()
            .contains(&format!("file://{path}"))
    );
    let mismatch = common::run(
        capture
            .command(
                false,
                &[
                    "capture-open",
                    "video",
                    "--config",
                    config.to_str().unwrap(),
                ],
            )
            .env("QREXEC_REMOTE_DOMAIN", "capture-display"),
        Some(request),
    )?;
    assert!(!mismatch.status.success());
    assert!(
        String::from_utf8_lossy(&mismatch.stderr)
            .contains("capture receipt identity or kind mismatch")
    );

    let capture = Capture::new()?;
    let source = capture.directory("image", false).join("Capture.png");
    fs::create_dir_all(source.parent().unwrap())?;
    fs::write(&source, b"finished capture")?;
    capture.run(
        true,
        &["enqueue", "image", source.to_str().unwrap()],
        None,
        true,
    )?;
    capture.run(
        true,
        &[
            "open",
            "image",
            source.to_str().unwrap(),
            "--target",
            "usr-work",
        ],
        None,
        true,
    )?;
    let calls = capture.calls()?;
    assert_eq!(calls.len(), 1);
    let arguments = calls[0].as_array().unwrap();
    let separator = arguments
        .iter()
        .position(|argument| argument == "--")
        .unwrap();
    assert_eq!(arguments[separator + 1], "Screen capture");
    assert!(arguments.contains(&json!("--icon=org.airlockos.Airlock")));
    assert!(arguments.contains(&json!("--hint=string:desktop-entry:org.airlockos.Desktop")));
    Ok(())
}

/// Explicit contracts fail closed before creating state; an installed destination cannot be silently overridden.
#[test]
fn capture_contracts_reject_invalid_inputs_before_side_effects() -> Result<()> {
    for record in [
        json!({"target": "dom0"}),
        json!({"target": "../escape"}),
        json!({"target": ""}),
        json!({"target": "usr-home", "typo": true}),
        json!({}),
        json!({"target": null}),
    ] {
        let capture = Capture::new()?;
        let config = capture.path("sender.json");
        fs::write(&config, serde_json::to_vec(&record)?)?;
        let output = capture.run(
            true,
            &["retry", "--config", config.to_str().unwrap()],
            None,
            false,
        )?;
        assert!(String::from_utf8_lossy(&output.stderr).contains("invalid capture configuration"));
        assert!(!capture.path("home/state/airlock/captures").exists());
        assert!(capture.calls()?.is_empty());
    }
    for (operation, record) in [
        ("capture-receive", json!({"sources": ["dom0"]})),
        ("capture-receive", json!({"sources": ["../escape"]})),
        ("capture-open", json!({"sources": []})),
        (
            "capture-open",
            json!({"sources": ["sys-gui"], "typo": true}),
        ),
        ("capture-receive", json!({})),
        ("capture-open", json!({"sources": null})),
    ] {
        let capture = Capture::new()?;
        let config = capture.path("receiver.json");
        fs::write(&config, serde_json::to_vec(&record)?)?;
        capture.run(
            false,
            &[operation, "image", "--config", config.to_str().unwrap()],
            Some(Vec::new()),
            false,
        )?;
        assert!(!capture.path("home/state/airlock/captures").exists());
        assert!(capture.calls()?.is_empty());
    }
    let capture = Capture::new()?;
    let config = capture.path("missing");
    capture.run(
        true,
        &["check-config", "--config", config.to_str().unwrap()],
        None,
        false,
    )?;
    for operation in ["capture-receive", "capture-open"] {
        capture.run(
            false,
            &[operation, "image", "--config", config.to_str().unwrap()],
            Some(Vec::new()),
            false,
        )?;
    }
    fs::write(&config, b"not JSON")?;
    capture.run(
        true,
        &[
            "retry",
            "--config",
            config.to_str().unwrap(),
            "--target",
            "usr-home",
        ],
        None,
        false,
    )?;
    assert!(!capture.path("home/state/airlock/captures").exists());
    Ok(())
}

/// Destination configuration selects a separate durable queue and rejects a conflicting command-line target.
#[test]
fn capture_configured_destination_owns_its_queue() -> Result<()> {
    let capture = Capture::new()?;
    let config = capture.path("sender.json");
    fs::write(&config, br#"{"target":"usr-personal"}"#)?;
    assert_eq!(
        common::json(
            &mut capture.command(
                true,
                &["--config", config.to_str().unwrap(), "check-config"]
            ),
            None
        )?,
        json!({"target": "usr-personal"})
    );
    assert!(!capture.path("home/state/airlock/captures").exists());
    let source = capture.directory("image", false).join("Capture.png");
    fs::create_dir_all(source.parent().unwrap())?;
    fs::write(&source, b"finished capture")?;
    fs::write(capture.path("failure"), b"")?;
    capture.run(
        true,
        &[
            "enqueue",
            "image",
            source.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
        ],
        None,
        true,
    )?;
    assert_eq!(capture.pending("usr-personal")?.len(), 1);
    assert!(capture.pending("usr-home")?.is_empty());
    capture.run(
        true,
        &[
            "enqueue",
            "image",
            source.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
            "--target",
            "usr-home",
        ],
        None,
        false,
    )?;
    assert!(capture.pending("usr-home")?.is_empty());
    capture.run(
        true,
        &[
            "enqueue",
            "image",
            source.to_str().unwrap(),
            "--target",
            "usr-home",
        ],
        None,
        true,
    )?;
    assert_eq!(capture.pending("usr-home")?.len(), 1);
    assert_eq!(capture.pending("usr-personal")?.len(), 1);
    Ok(())
}
