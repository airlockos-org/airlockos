//! Display recovery runs inside sys-gui, which owns its GPU and desktop session.
//! It grants no PCI assignment authority and never runs automatically.

mod recovery;

use anyhow::Result;
use clap::{Args, Subcommand};

#[derive(Args)]
pub(crate) struct Request {
    // One explicit local diagnostic or recovery operation.
    #[command(subcommand)]
    action: Action,
    // Human confirmation of a stalled display, required for either mutation.
    #[arg(long, global = true)]
    confirm_display_stall: bool,
}

#[derive(Subcommand, Clone, Copy)]
enum Action {
    /// Capture bounded display diagnostics without reading the reset interface.
    Capture,
    /// Attempt one GPU reset this boot after a recorded recent flip timeout.
    Recover,
    /// Restart the desktop once, only after the recorded reset returned successfully.
    RestartDesktop,
    #[command(hide = true)]
    Reset,
}

pub(crate) fn execute(request: Request) -> Result<()> {
    if matches!(request.action, Action::Reset) {
        recovery::reset()
    } else {
        recovery::execute(request.action, request.confirm_display_stall)
    }
}
