//! Boot attempts distinguish hardware startup failure from an already usable desktop.
//! Persisted statuses are observations; only an explicit recovery acknowledgement clears the next-boot gate.

use airlock_nix_core::identity::GuestName;
use airlock_nix_core::state::ResourceKey;
use anyhow::{Result, ensure};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt, str::FromStr};

/// A boot identity that can safely select one attempt directory and journal boot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub(super) struct AttemptId(
    // Single validated path component identifying a kernel boot attempt.
    String,
);

impl FromStr for AttemptId {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        value.parse::<ResourceKey>()?;
        Ok(Self(value.to_owned()))
    }
}

impl TryFrom<String> for AttemptId {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        value.parse()
    }
}

impl From<AttemptId> for String {
    fn from(value: AttemptId) -> Self {
        value.0
    }
}

impl fmt::Display for AttemptId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Readiness outcome distinguishing critical startup from optional background work.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Status {
    #[default]
    Working,
    Failed,
    Interrupted,
    RecoveryRequired,
    Complete,
    Degraded,
}

/// Observed startup checkpoint for one guest, independent of desktop menu publication.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum GuestState {
    /// Startup has not yet reached this guest.
    #[default]
    Waiting,
    /// Qubes is starting the guest or its required services.
    Starting,
    /// The running generation and required services passed readiness checks.
    Ready,
    /// The latest attempt to start or verify this guest failed.
    Failed,
}

/// Durable observations used to diagnose the attempt and gate unsafe automatic retries.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Attempt {
    /// Record format identifying the persistent boot-attempt state.
    pub schema: String,
    /// Kernel boot identity to which every observation in this record belongs.
    pub boot_id: AttemptId,
    /// UTC wall-clock time of the most recent state change.
    pub updated_at: String,
    /// UTC time when supervision first recorded this attempt.
    pub started_at: String,
    /// Human-readable startup checkpoint, including systemd unit or VM names.
    pub stage: String,
    /// Whether this attempt is progressing, usable, failed or awaiting recovery.
    pub status: Status,
    /// Explanation suitable for the diagnostic console and persisted evidence.
    pub detail: String,
    /// A usable desktop makes later background-service failures noncritical.
    #[serde(default)]
    pub desktop_ready: bool,
    /// Per-guest checkpoints retained while subsequent guests start.
    #[serde(default)]
    pub guests: BTreeMap<GuestName, GuestState>,
    /// A deliberate shutdown distinguishes cancelled startup from power loss.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shutdown_requested_at: Option<String>,
    /// Boot that captured diagnostics for this interrupted attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovered_by: Option<AttemptId>,
    /// Interrupted attempt that caused this boot to enter safe recovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_boot_id: Option<AttemptId>,
}

impl Attempt {
    pub(super) fn validate(&self, identifier: Option<&AttemptId>) -> Result<()> {
        ensure!(
            self.schema == "airlock.boot-attempt.v1",
            "invalid boot state schema"
        );
        ensure!(
            identifier.is_none_or(|id| *id == self.boot_id),
            "boot state identity mismatch"
        );
        ensure!(
            !self.stage.is_empty() && self.stage.len() <= 4096,
            "invalid boot stage"
        );
        Ok(())
    }
}

/// Reject labels that could escape the attempt's snapshot directory.
pub(super) fn snapshot_label(value: &str) -> Result<String> {
    ensure!(
        !value.is_empty()
            && value.len() <= 255
            && value != "."
            && value != ".."
            && !value.contains('/')
            && !value.chars().any(char::is_control),
        "snapshot label must be a single nonempty path component"
    );
    Ok(value.to_owned())
}

/// Runtime publication confirming that this boot's prepare operation finished.
#[derive(Serialize, Deserialize)]
pub(super) struct Current {
    /// Boot whose marker and recovery gate have been initialized.
    pub boot_id: AttemptId,
    /// Prior interrupted boot for which this attempt entered recovery.
    pub recovered: Option<AttemptId>,
}
