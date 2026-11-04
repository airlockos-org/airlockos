//! Enter enforced isolation before reading any guest bytes or exporting a snapshot.

use super::{admission, feed};
use airlock_nix_core::identity::GuestName;
use anyhow::{Context, Result, ensure};
use rustix::process::{Resource, Rlimit, setrlimit};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

/// Build a filesystem with only immutable runtime code and the read-only feed.
///
/// A distinct network namespace also removes abstract Unix sockets, which merely
/// hiding /run would leave reachable. PID isolation prevents signaling/ptracing
/// the session. UID/GID 65534 map only to the launching user's IDs outside the
/// namespace; all capabilities and further user-namespace creation are removed.
/// No environment, display descriptor, session-bus descriptor or writable host
/// directory is inherited. Bubblewrap closes other descriptors except its sync FD.
pub(super) fn command(bwrap: &Path, executable: &Path, directory: &Path) -> Command {
    let mut command = Command::new(bwrap);
    command
        .env_clear()
        .args([
            "--unshare-all",
            "--unshare-user",
            "--disable-userns",
            "--die-with-parent",
            "--new-session",
            "--cap-drop",
            "ALL",
            "--uid",
            "65534",
            "--gid",
            "65534",
            "--clearenv",
            "--ro-bind",
            "/nix/store",
            "/nix/store",
        ])
        .arg("--ro-bind")
        .arg(executable)
        .arg("/exporter")
        .arg("--ro-bind")
        .arg(directory)
        .arg("/feed")
        .args([
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--chdir",
            "/",
            "--remount-ro",
            "/",
        ]);
    command
}

/// Admit the authenticated source and replace this trusted launcher with bubblewrap.
pub(super) fn enter(root: &Path) -> Result<()> {
    let caller: GuestName = std::env::var("QREXEC_REMOTE_DOMAIN")
        .context("missing Qubes caller identity")?
        .parse()?;
    ensure!(
        std::env::var_os("QREXEC_SERVICE_ARGUMENT").is_none_or(|value| value.is_empty()),
        "preferences RPC takes no argument"
    );
    let slot = admission::acquire(root, &caller)?;
    let directory = root.join("feed");
    // Export may start before GNOME. Binding an empty stable directory lets the
    // sandbox observe the initial atomic publication without reaching the session.
    feed::private_directory(&directory)?;
    let bwrap = std::env::var_os("AIRLOCK_PREFERENCES_BWRAP")
        .context("installed preferences sandbox executable is not configured")?;
    let bwrap = Path::new(&bwrap);
    ensure!(
        bwrap.starts_with("/nix/store"),
        "sandbox executable must be an installed store path"
    );
    let mut command = command(bwrap, &std::env::current_exe()?, &directory);
    command.args([
        "--sync-fd",
        &slot.as_raw_fd().to_string(),
        "--",
        "/exporter",
        "preferences",
        "stream",
    ]);

    // Bubblewrap keeps the locked slot for the whole sandbox lifetime and closes
    // it on disconnect/crash. The guest-facing child cannot replace the slot file.
    rustix::io::fcntl_setfd(&slot, rustix::io::FdFlags::empty())?;
    for (resource, limit) in [
        (Resource::As, 512 * 1024 * 1024),
        (Resource::Nofile, 64),
        (Resource::Core, 0),
        (Resource::Cpu, 30),
    ] {
        setrlimit(
            resource,
            Rlimit {
                current: Some(limit),
                maximum: Some(limit),
            },
        )?;
    }
    Err(command.exec().into())
}
