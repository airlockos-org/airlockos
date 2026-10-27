//! Select the configured private or admitted worker Nix store without shell-owned policy.

use airlock_nix_core::runtime::process;
use anyhow::{Result, ensure};
use clap::Args;
use serde_json::Value;
use std::{
    ffi::OsString,
    fs,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

/// Installed store adapter parameters, separate from caller-provided Nix arguments.
#[derive(Args)]
pub(crate) struct Request {
    /// Immutable Nix executable selected by the machine's package set.
    #[arg(long)]
    executable: PathBuf,
    /// Role's configured private root, before any explicit user override.
    #[arg(long)]
    root: PathBuf,
    /// Require the admitted pool-backed worker mount and readiness record.
    #[arg(long)]
    pinned: bool,
    /// Legacy nix-store entry point always requires its pinned store.
    #[arg(long)]
    store_command: bool,
    /// Nix's unchanged command-line arguments, including explicit store selection.
    #[arg(last = true, allow_hyphen_values = true)]
    arguments: Vec<OsString>,
}

/// Require the existing mount identity evidence before reading the admitted store URI.
fn pinned(root: &Path) -> Result<String> {
    pinned_at(
        root,
        Path::new("/run/airlock-builder"),
        Duration::from_secs(60),
    )
}

/// Observe the same mounted layers and readiness URI used by implicit worker Nix commands.
pub(crate) fn pinned_at(root: &Path, runtime: &Path, timeout: Duration) -> Result<String> {
    let deadline = Instant::now() + timeout;
    for directory in [root.join("nix/store"), runtime.join("lower/nix/store")] {
        let output = process::run(
            Command::new("mountpoint").arg("-q").arg(&directory),
            None,
            Some(deadline.saturating_duration_since(Instant::now())),
        )?;
        ensure!(
            output.status.success(),
            "pool-backed build store is not ready; inspect its build-store service"
        );
    }
    let ready: Value =
        airlock_nix_core::state::read_json(&runtime.join("ready.json"), 1024 * 1024)?;
    Ok(ready["uri"]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("worker readiness record has no store URI"))?
        .into())
}

/// Preserve explicit store overrides while refusing implicit fallback from a pinned worker store.
pub(crate) fn execute(request: Request) -> Result<()> {
    let mut command = Command::new(request.executable);
    let explicit = !request.store_command
        && request.arguments.iter().any(|argument| {
            argument == "--store"
                || argument
                    .to_str()
                    .is_some_and(|argument| argument.starts_with("--store="))
        });
    if !explicit {
        let selected = std::env::var_os("AIRLOCK_CONFIG_NIX_STORE_ROOT")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| request.root.clone());
        ensure!(
            selected.is_absolute(),
            "private Nix store root must be absolute"
        );
        if request.pinned {
            if !request.store_command {
                ensure!(
                    selected == request.root,
                    "worker uses its pinned pool-backed store; use an explicit --store for a different store"
                );
            }
            let uri = pinned(&request.root)?;
            command.args([if request.store_command {
                "--option"
            } else {
                "--extra-experimental-features"
            }]);
            if request.store_command {
                command.arg("experimental-features");
            }
            command.args([
                "nix-command flakes local-overlay-store read-only-local-store",
                "--option",
                "build-hook",
                "",
                "--store",
                &uri,
            ]);
        } else {
            fs::create_dir_all(&selected)?;
            command.arg("--store").arg(selected);
        }
    }
    Err(command.args(request.arguments).exec().into())
}
