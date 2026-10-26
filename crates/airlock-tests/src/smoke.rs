//! Explicit live smoke scenarios; ordinary Cargo tests use isolated command peers.

#[path = "smoke/common.rs"]
mod common;

#[path = "smoke/basic.rs"]
mod basic;

#[path = "smoke/config.rs"]
mod config;

#[path = "smoke/closure.rs"]
mod closure;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Script/package root used only to select a writable default evidence directory.
    #[arg(long, global = true)]
    root: Option<PathBuf>,
    /// Explicitly requested live scenario or read-only parser operation.
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Check an exact upstream Qubes volume-list entry without mutating the VM.
    CheckVolume {
        /// Existing VM to observe.
        guest: String,
        /// Exact expected volume name.
        volume: String,
    },
    /// Exercise explicit shared-store generation, isolation, retention and rollback scenarios.
    Closure,
    /// Exercise configuration-role preflight, staged source and explicit apply modes.
    Config,
    /// Create/start a disposable VM and check the upstream qrexec path.
    Qubes,
    /// Launch a bounded GUI test window through upstream Qubes tools.
    Gui,
    /// Validate porcelain-v2 main-branch status without interpreting shell text.
    CleanMain {
        /// Captured Git status from the local or remote repository.
        status: PathBuf,
    },
}

/// Live operations remain explicit commands, with failures preserved in structured receipts.
fn execute(args: Args) -> Result<()> {
    match args.action {
        Action::CheckVolume { guest, volume } => common::check_volume(&guest, &volume),
        Action::Closure => closure::execute(),
        Action::Config => config::execute(),
        Action::Qubes => basic::qubes(args.root.as_deref()),
        Action::Gui => basic::gui(args.root.as_deref()),
        Action::CleanMain { status } => {
            anyhow::ensure!(
                common::clean_main(&std::fs::read_to_string(status)?),
                "repository is not committed, clean main"
            );
            Ok(())
        }
    }
}

fn main() -> std::process::ExitCode {
    match execute(Args::parse()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("airlock-smoke: {error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}
