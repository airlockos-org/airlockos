//! Inert qrexec peer for the disposable desktop integration scenario.
//! It serves fixture-owned bytes and records routing; it never contacts Qubes or a real VM.

use anyhow::{Context, Result, ensure};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

/// Stream the selected fixture on file changes, with EOF-only stdin proving no write-back protocol.
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        args.len() == 3 && args[0] == "--" && args[2] == "airlock.DesktopPreferences",
        "unexpected RPC arguments"
    );
    let source: airlock_nix_core::identity::GuestName = args[1].parse()?;
    // Only the test launcher selects this mode. The production guest still invokes
    // the fixed qrexec service; replace transport establishment with a local exec
    // so the real exporter, including its sandbox, handles all subsequent bytes.
    if let Some(runtime) = std::env::var_os("AIRLOCK_TEST_EXPORTER_RUNTIME") {
        ensure!(source.as_str() == "sys-gui", "unexpected publisher");
        return Err(Command::new(
            std::env::var_os("AIRLOCK_TEST_PREFERENCES_PUBLISHER")
                .context("prepared publisher executable")?,
        )
        .args(["preferences", "export"])
        .env("XDG_RUNTIME_DIR", runtime)
        .env("QREXEC_REMOTE_DOMAIN", "usr-session-fixture")
        .env_remove("QREXEC_SERVICE_ARGUMENT")
        .exec()
        .into());
    }
    let root = PathBuf::from(
        std::env::var_os("AIRLOCK_TEST_PREFERENCES_FEED").context("fixture directory")?,
    );
    let mut calls = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join("calls"))?;
    writeln!(calls, "{source}", source = source.as_str())?;
    ensure!(
        std::io::stdin().read(&mut [0])? == 0,
        "unexpected guest input"
    );
    let watch = rustix::fs::inotify::init(rustix::fs::inotify::CreateFlags::CLOEXEC)?;
    rustix::fs::inotify::add_watch(
        &watch,
        &root,
        rustix::fs::inotify::WatchFlags::CLOSE_WRITE | rustix::fs::inotify::WatchFlags::MOVED_TO,
    )?;
    let filename = format!("{source}.frame", source = source.as_str());
    let mut previous = Vec::new();
    let mut buffer = [std::mem::MaybeUninit::uninit(); 4096];
    let mut events = rustix::fs::inotify::Reader::new(&watch, &mut buffer);
    loop {
        if root.join("offline").exists() {
            return Ok(());
        }
        if let Ok(bytes) = fs::read(root.join(&filename)) {
            ensure!(bytes.len() <= 8192, "fixture exceeds two-frame bound");
            if bytes != previous {
                std::io::stdout().write_all(&bytes)?;
                std::io::stdout().flush()?;
                previous = bytes;
            }
        }
        loop {
            let event = events.next()?;
            if event.file_name().is_some_and(|name| {
                name.to_bytes() == filename.as_bytes() || name.to_bytes() == b"offline"
            }) {
                break;
            }
        }
    }
}
