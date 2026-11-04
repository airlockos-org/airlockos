//! One-way GNOME preferences feed, with no guest connection to the session publisher.
//!
//! The session writes one bounded frame atomically and refreshes its liveness every
//! second. Exporters mount only that feed read-only in a separate user, mount, PID
//! and network namespace. They cannot reach dconf, either D-Bus, the display, or
//! host processes. Qubes policy authenticates/routes callers; admission here limits
//! resources only. Session and RPC installation is composed by machine authoring.

mod admission;

mod export;

mod feed;

mod sandbox;

mod source;

#[cfg(test)]
mod tests;

use anyhow::Result;
use clap::Subcommand;
use std::path::PathBuf;
use std::time::Duration;

/// Polling coalesces settings bursts without building a replay queue.
const TICK: Duration = Duration::from_millis(100);

/// Refresh even unchanged preferences so crashed/logged-out sessions expire.
const HEARTBEAT: Duration = Duration::from_secs(1);

/// Readers reject a feed whose publisher has stopped refreshing it.
const MAX_AGE: Duration = Duration::from_secs(5);

/// Fixed operations, invoked by the session unit and the policy-authorized RPC.
#[derive(Subcommand)]
pub(super) enum Action {
    /// Observe allowlisted GSettings in the current graphical session.
    Publish,
    /// Admit a Qubes-authenticated caller, then enter the read-only sandbox.
    Export,
    /// Run the byte pump inside the namespace created by export.
    #[command(hide = true)]
    Stream,
}

/// Use the login user's private runtime directory, never a caller-supplied path.
fn root() -> Result<PathBuf> {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(format!(
                "/run/user/{uid}",
                uid = rustix::process::geteuid().as_raw()
            ))
        });
    feed::check_directory(&runtime)?;
    let root = runtime.join("airlock-desktop-preferences");
    feed::private_directory(&root)?;
    Ok(root)
}

/// Dispatch locally selected operations without accepting guest request arguments.
pub(super) fn execute(action: Action) -> Result<()> {
    match action {
        Action::Publish => source::run(&root()?),
        Action::Export => sandbox::enter(&root()?),
        Action::Stream => export::run(std::path::Path::new("/feed")),
    }
}
