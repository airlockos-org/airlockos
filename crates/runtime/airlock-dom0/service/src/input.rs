//! Physical input crosses from dom0 to the GUI VM through the upstream Qubes proxy.
//! Device records describe what was observed; they are not an enrollment approval policy.

mod discovery;

pub(crate) mod connect;

mod events;

mod forwarder;

mod guard;

mod model;

use airlock_nix_core::{
    identity::GuestName,
    state::{OperationKind, OperationLock, OperationOwner, StateStore},
};
use anyhow::Result;
use clap::{Args, Subcommand};
use std::{
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
};

#[derive(Args)]
pub(crate) struct Request {
    // Local input operation selected by a dedicated dom0 systemd unit.
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Wait for lifecycle-managed forwarding without making its transient job a boot prerequisite.
    BootReady {
        // Already-running GUI VM whose connection must complete on the same instance.
        #[arg(long)]
        target: GuestName,
        // Total retry budget, including cancelled connection jobs.
        #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(1..=300))]
        timeout: u64,
    },
    /// Observe an already-running input connection without changing VM or service state.
    Check {
        // Guest whose physical input connection is inspected.
        #[arg(long)]
        target: GuestName,
    },
    /// Enable forwarding only after the same running GUI instance answers readiness.
    Connect {
        // Already-running GUI VM; readiness must never autostart it.
        #[arg(long)]
        target: GuestName,
    },
    /// Watch physical evdev devices and forward each independently to the GUI VM.
    Discover {
        // Already-running GUI VM; this command never starts it.
        #[arg(long)]
        target: GuestName,
        // Existing dom0 Qubes transport, invoked with a fixed input RPC.
        #[arg(long)]
        qrexec: PathBuf,
        // Upstream input-proxy sender executable, invoked with a validated event node.
        #[arg(long)]
        sender: PathBuf,
        // Advisory record of observed physical devices; failure does not disable input.
        #[arg(long)]
        inventory: PathBuf,
    },
    /// Connect and release forwarding in response to native Qubes lifecycle events.
    Events {
        // GUI VM whose lifecycle controls the fixed input systemd units.
        #[arg(long)]
        target: GuestName,
    },
    /// Diagnose explicit kernel keyboard initialization errors and allow one recovery.
    BootGuard,
    /// Persist systemd's unsuccessful keyboard-guard result after process termination.
    Finalize,
    #[command(hide = true)]
    Rebind,
}

fn stopping() -> Result<Arc<AtomicBool>> {
    let stop = Arc::new(AtomicBool::new(false));
    for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        signal_hook::flag::register(signal, stop.clone())?;
    }
    Ok(stop)
}

fn tool(key: &str, default: &str) -> std::ffi::OsString {
    std::env::var_os(key).unwrap_or_else(|| default.into())
}

// Runtime ownership is separate from the advisory inventory: a full persistent
// disk must not deprive the user of a working keyboard or its lifecycle observer.
fn runtime_lock(name: &str, target: &GuestName) -> Result<OperationLock> {
    let root = std::path::Path::new("/run/airlock/input");
    crate::state::directory(root)?;
    let locks = StateStore::initialize(root)?;
    Ok(locks.try_operation(
        &name.parse()?,
        OperationOwner::new(
            format!("airlock-dom0-service input {name}"),
            format!("manage physical input for {target}"),
            OperationKind::Maintenance,
        )?,
    )?)
}

pub(crate) fn execute(request: Request) -> Result<()> {
    match request.action {
        Action::BootReady { target, timeout } => connect::boot_ready(&target, timeout),
        Action::Connect { target } => connect::connect(&target),
        Action::Check { target } => connect::check(&crate::process::Runner::default(), &target),
        Action::Discover {
            target,
            qrexec,
            sender,
            inventory,
        } => discovery::run(target, qrexec, sender, inventory, stopping()?),
        Action::Events { target } => events::run(target, stopping()?),
        Action::BootGuard => guard::check(),
        Action::Finalize => guard::finalize(),
        Action::Rebind => guard::rebind(),
    }
}
