//! Exercise the installed exporter entry point with real pipes, admission and namespace isolation.
//! All state belongs to a disposable directory; no live desktop or Qubes session is contacted.

#![cfg(feature = "runtime")]

use airlock_desktop_preferences::{FrameDecoder, Setting, Snapshot, encode_frame};
use anyhow::{Result, bail};
use std::fs;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// Kill/reap the sandbox even when a boundary assertion fails.
struct Exporter {
    /// Trusted launcher, replaced by bubblewrap and responsible for its child lifetime.
    child: Child,
}

impl Exporter {
    /// Observe shutdown within the transport's bounded input/disconnect deadline.
    fn wait(&mut self) -> Result<ExitStatus> {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                bail!("exporter did not exit");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Exporter {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Invoke the production CLI with only fixture-owned runtime state and trusted Qubes metadata.
fn command(runtime: &Path, bwrap: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_airlock-sys-gui-service"));
    command
        .args(["preferences", "export"])
        .env("XDG_RUNTIME_DIR", runtime)
        .env("QREXEC_REMOTE_DOMAIN", "usr-preferences-fixture")
        .env_remove("QREXEC_SERVICE_ARGUMENT")
        .env("AIRLOCK_PREFERENCES_BWRAP", bwrap);
    command
}

/// Connect qrexec-like duplex descriptors to the actual sandbox launcher.
fn start(runtime: &Path, bwrap: &Path) -> Result<(Exporter, UnixStream)> {
    let (peer, stream) = UnixStream::pair()?;
    peer.set_read_timeout(Some(Duration::from_secs(3)))?;
    let child = command(runtime, bwrap)
        .stdin(Stdio::from(OwnedFd::from(stream.try_clone()?)))
        .stdout(Stdio::from(OwnedFd::from(stream)))
        .spawn()?;
    Ok((Exporter { child }, peer))
}

/// Publish through the same atomic file boundary, without exposing writer access to the process.
fn publish(directory: &Path, snapshot: &Snapshot) -> Result<()> {
    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
    temporary.write_all(&encode_frame(snapshot)?)?;
    temporary.persist(directory.join("snapshot"))?;
    Ok(())
}

/// Read one complete contract frame from the real exporter process.
fn receive(peer: &mut UnixStream) -> Result<Snapshot> {
    let mut header = [0; 8];
    peer.read_exact(&mut header)?;
    let length = u16::from_be_bytes([header[6], header[7]]) as usize;
    let mut frame = header.to_vec();
    frame.resize(8 + length, 0);
    peer.read_exact(&mut frame[8..])?;
    Ok(FrameDecoder::default()
        .decode(&mut frame.as_slice())?
        .unwrap())
}

/// The real launcher holds admission through exec, rejects writes/arguments and releases on exit.
#[test]
#[ignore = "requires explicitly prepared AIRLOCK_PREFERENCES_BWRAP and user namespaces"]
fn namespace_export_lifecycle_preserves_admission_and_read_only_state() -> Result<()> {
    let runtime = tempfile::tempdir()?;
    fs::set_permissions(runtime.path(), fs::Permissions::from_mode(0o700))?;
    let root = runtime.path().join("airlock-desktop-preferences");
    fs::DirBuilder::new().mode(0o700).create(&root)?;
    let feed = root.join("feed");
    fs::DirBuilder::new().mode(0o700).create(&feed)?;
    let bwrap = fs::canonicalize(
        std::env::var_os("AIRLOCK_PREFERENCES_BWRAP")
            .expect("prepare AIRLOCK_PREFERENCES_BWRAP explicitly"),
    )?;
    let initial = Snapshot::default();
    publish(&feed, &initial)?;
    let (mut exporter, mut peer) = start(runtime.path(), &bwrap)?;
    assert_eq!(receive(&mut peer)?, initial);
    let duplicate = command(runtime.path(), &bwrap).output()?;
    assert!(!duplicate.status.success());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("already active"));
    let changed = Snapshot {
        high_contrast: Setting::Supported(true),
        ..initial
    };
    publish(&feed, &changed)?;
    assert_eq!(receive(&mut peer)?, changed);
    peer.write_all(b"write-setting")?;
    assert!(!exporter.wait()?.success());
    let input = fs::read(feed.join("snapshot"))?;
    assert_eq!(
        FrameDecoder::default().decode(&mut input.as_slice())?,
        Some(changed.clone())
    );

    let (mut replacement, mut peer) = start(runtime.path(), &bwrap)?;
    assert_eq!(receive(&mut peer)?, changed);
    drop(peer);
    assert!(!replacement.wait()?.success());
    assert!(
        !command(runtime.path(), &bwrap)
            .env("QREXEC_SERVICE_ARGUMENT", "font-name")
            .output()?
            .status
            .success()
    );
    assert!(
        !command(runtime.path(), &bwrap)
            .arg("set")
            .output()?
            .status
            .success()
    );
    Ok(())
}
