//! Ask the GNOME extension to reserve a VM workspace through its existing session bus API.

use crate::qubes;
use airlock_nix_core::identity::GuestName;
use airlock_vm_service::support;
use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use std::{process::Command, time::Duration};
use uuid::Uuid;

#[derive(Subcommand)]
pub(crate) enum Action {
    /// Reserve a workspace for the Qubes identity currently owning this VM name.
    Prepare {
        // Name resolved through the Qubes API immediately before desktop preparation.
        name: GuestName,
    },
    /// Cancel a reservation after the application launch failed.
    Cancel {
        // Opaque UUID returned by the workspace service's Prepare method.
        token: Uuid,
    },
}

pub(crate) fn execute(action: Action) -> Result<()> {
    match action {
        Action::Prepare { name } => println!("{}", prepare(&name)?),
        Action::Cancel { token } => cancel(token)?,
    }

    Ok(())
}

/// Invoke the fixed workspace bus interface with a trusted VM identity or parsed token.
fn call(method: &str, id: Uuid) -> Result<String> {
    support::text(
        Command::new(support::tool("AIRLOCK_GDBUS", "gdbus")).args([
            "call",
            "--session",
            "--timeout",
            "5",
            "--dest",
            "org.airlock.Workspaces",
            "--object-path",
            "/org/airlock/Workspaces",
            "--method",
            &format!("org.airlock.Workspaces.{method}"),
            &id.to_string(),
        ]),
        Duration::from_secs(10),
    )
}

/// Reserve for the current Qubes UUID and accept only a literal UUID tuple from GDBus.
pub(crate) fn prepare(name: &GuestName) -> Result<Uuid> {
    let reply = call("Prepare", qubes::identity(name)?)?;
    let value = reply
        .strip_prefix("('")
        .and_then(|v| v.strip_suffix("',)"))
        .or_else(|| {
            reply
                .strip_prefix("(\"")
                .and_then(|v| v.strip_suffix("\",)"))
        })
        .context("invalid workspace reservation reply")?;
    ensure!(
        !value.contains(['\'', '"', '\\']),
        "invalid workspace token encoding"
    );
    Ok(Uuid::parse_str(value)?)
}

/// Release only the reservation identified by the service-issued token.
pub(crate) fn cancel(token: Uuid) -> Result<()> {
    call("Cancel", token)?;
    Ok(())
}
