//! Read dom0's existing boot-status RPC without starting guests or changing control policy.

use airlock_nix_core::identity::GuestName;
use airlock_vm_service::support;
use anyhow::Result;
use serde::Deserialize;
use std::{process::Command, time::Duration};

/// User-visible progress from the boot supervisor; it conveys no deployment authority.
#[derive(Deserialize)]
pub(crate) struct Status {
    /// Host boot identity, used to avoid carrying a previous boot's UI state forward.
    #[serde(default)]
    pub(crate) boot_id: String,
    /// Current supervisor outcome, including working, complete and degraded.
    pub(crate) status: String,
    /// Whether the graphical desktop has passed its readiness checks.
    #[serde(default)]
    pub(crate) desktop_ready: bool,
    /// Current unit or guest being prepared or started.
    #[serde(default)]
    pub(crate) stage: String,
    /// Human-readable explanation of the most recent checkpoint.
    #[serde(default)]
    pub(crate) detail: String,
    /// Declared autostart guests with their last observed readiness checkpoint.
    #[serde(default)]
    pub(crate) guests: Vec<Guest>,
}

/// One guest described by dom0's existing read-only boot-status service.
#[derive(Deserialize)]
pub(crate) struct Guest {
    /// Validated Qubes identity; display text cannot supply a different target.
    pub(crate) name: GuestName,
    /// Last observed checkpoint: waiting, starting, ready or failed.
    pub(crate) phase: String,
    /// Whether this guest publishes application launchers in this GUI VM.
    applications: bool,
}

/// Combine host observations with successful local menu publication for the panel.
pub(crate) fn panel_status() -> Result<()> {
    let status = read(Duration::from_secs(10))?;
    let mut guests = Vec::new();
    let mut available = true;
    let mut attention = matches!(
        status.status.as_str(),
        "failed" | "degraded" | "interrupted" | "recovery-required"
    );
    for guest in &status.guests {
        anyhow::ensure!(
            matches!(
                guest.phase.as_str(),
                "waiting" | "starting" | "ready" | "failed"
            ),
            "invalid startup guest phase"
        );

        let mut phase = guest.phase.clone();
        let mut detail = match phase.as_str() {
            "waiting" => "Waiting to start",
            "starting" => "Starting services",
            "ready" => "Ready",
            _ => "Could not start",
        }
        .to_owned();
        if guest.applications && phase == "ready" {
            let publication = crate::menus::publication(&guest.name)?;
            if !publication.available {
                if let Some(error) = publication.error {
                    phase = "failed".into();
                    detail = error;
                } else {
                    phase = "loading".into();
                    detail = "Loading applications".into();
                }
            }
        }
        available &= phase == "ready";
        attention |= phase == "failed";
        guests.push(serde_json::json!({"name":guest.name,"phase":phase,"detail":detail}));
    }

    let complete = status.status == "complete" && available;
    let detail = if complete {
        "Ready".to_owned()
    } else if attention {
        "Some applications or services need attention".to_owned()
    } else if status.status == "complete" && !available {
        "Loading applications".to_owned()
    } else if let Some(name) = status.stage.strip_prefix("qube:") {
        format!("Starting {name}")
    } else {
        "Preparing applications and services".to_owned()
    };
    let snapshot = serde_json::json!({
        "schema":"airlock.startup-panel.v1", "boot_id":status.boot_id,
        "complete":complete, "attention":attention, "detail":detail, "guests":guests
    });
    println!("{snapshot}");
    Ok(())
}

impl Status {
    /// Describe the current checkpoint while bounding notification and terminal text.
    pub(crate) fn progress(&self) -> String {
        let text = if self.detail.is_empty() {
            &self.stage
        } else {
            &self.detail
        };
        text.chars().filter(|c| !c.is_control()).take(512).collect()
    }
}

/// Read a bounded status reply; a transport failure remains distinct from a boot outcome.
pub(crate) fn read(timeout: Duration) -> Result<Status> {
    let bytes = support::run(
        Command::new(support::tool("AIRLOCK_QVM_RUN", "qvm-run")).args([
            "--pass-io",
            "--no-gui",
            "--service",
            "dom0",
            "airlock.BootStatus",
        ]),
        None,
        timeout,
    )?
    .checked()?;
    Ok(serde_json::from_slice(&bytes)?)
}
