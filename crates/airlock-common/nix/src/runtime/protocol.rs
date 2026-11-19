//! Source-submission envelope and validation shared by sender and receiver.

use super::{Result, process, require};
use crate::{
    identity::{GuestName, ReviewId, SourceIdentity},
    review::{CandidateIdentity, DeploymentTarget},
    wire::string_enum,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

/// Maximum compressed source bundle size accepted by both transport endpoints.
pub const ARCHIVE_LIMIT: u64 = 512 * 1024 * 1024;

/// The committed parameter document understood by the machine compiler and sys-ctrl.
pub const FIREWALL_SETTINGS_FILE: &str = "firewall-parameters.json";

/// A deployment carries this feature only if its machine compiler consumes the data file.
pub const FIREWALL_SETTINGS_SOURCE: &str = "airlock-hermit-firewall-settings-source";

string_enum! {
    /// Schema of the settings-only request on the existing machine deployment service.
    pub enum FirewallSettingsSchema ("firewall settings request schema") {
        /// Change one protected startup document while retaining the selected release's artifacts.
        V1 => "airlock.firewall-settings-update.v1",
    }
}

/// A settings-only candidate derived from two committed trees by sys-ctrl.
/// Dom0 still checks source approval, the selected baseline and the generated plan.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallSettingsUpdate {
    /// Protocol version understood by both deployment endpoints.
    pub schema: FirewallSettingsSchema,
    /// Source currently selected by the machine.
    pub baseline: SourceIdentity,
    /// Candidate committed source, with the same dependency lock.
    pub candidate: SourceIdentity,
    /// Setting observed in the baseline source tree.
    pub before: airlock_firewall_parameters::Limits,
    /// Setting read from the approved candidate tree.
    pub after: airlock_firewall_parameters::Limits,
    /// Exact source approval issued by dom0 for this candidate.
    pub review_authorization: ReviewId,
}

string_enum! {
    /// Versioned source-submission format shared by sender and receiver.
    pub enum RequestSchema ("submission schema") {
        /// Committed-source submission through the normal review workflow.
        V1 => "airlock.sys-ctrl-guest-request.v1",
    }
}

string_enum! {
    /// Work requested from sys-ctrl; authorization is checked separately in dom0.
    pub enum Action ("submission action") {
        /// Prepare a guest-only plan without activation.
        GuestPlan => "plan",
        /// Prepare and submit a guest-only activation.
        GuestApply => "apply",
        /// Build machine release artifacts without activating them.
        MachineBuild => "machine-build",
        /// Prepare a whole-machine plan without activation.
        MachinePlan => "machine-plan",
        /// Prepare and submit a whole-machine activation.
        MachineApply => "machine-apply",
    }
}

impl Action {
    /// Return whether the action targets the whole machine rather than a guest.
    pub fn is_machine(self) -> bool {
        matches!(
            self,
            Self::MachineBuild | Self::MachinePlan | Self::MachineApply
        )
    }

    /// Return whether the requested action computes effects without activation.
    pub fn is_plan(self) -> bool {
        matches!(self, Self::GuestPlan | Self::MachinePlan)
    }

    /// Return whether the requested action prepares and submits activation.
    pub fn is_apply(self) -> bool {
        matches!(self, Self::GuestApply | Self::MachineApply)
    }
}

/// Bounded source-upload envelope validated before accepting its archive.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    /// Wire format identifier used to reject unsupported record versions.
    pub schema: RequestSchema,
    /// Requested controller operation, independent of human approval.
    pub action: Action,
    /// Guest name for guest operations; absent for whole-machine work.
    pub target: Option<GuestName>,
    /// Git commit identifying the candidate source tree.
    pub revision: crate::identity::GitRevision,
    /// SHA-256 of flake.lock, binding the source to its dependency versions.
    pub lock_hash: crate::identity::LockHash,
    /// Declared compressed source archive size, bounded before receiving it.
    pub archive_bytes: u64,
}

impl Header {
    /// Return the source revision and dependency-lock identity carried by this envelope.
    pub fn source(&self) -> SourceIdentity {
        SourceIdentity {
            revision: self.revision.clone(),
            lock_hash: self.lock_hash.clone(),
        }
    }

    /// Validate action, target and archive size before identifying the candidate.
    pub fn candidate(&self) -> Result<CandidateIdentity> {
        require(
            self.action.is_machine() == self.target.is_none(),
            "deployment target differs from action",
        )?;
        if let Some(target) = &self.target {
            require(
                [
                    "usr-assistant",
                    "sys-ctrl",
                    "sys-gui",
                    "sys-net",
                    "sys-firewall",
                    "usr-home",
                ]
                .contains(&target.as_str()),
                "unsupported guest deployment target",
            )?;
        }
        require(
            self.archive_bytes > 0 && self.archive_bytes <= ARCHIVE_LIMIT,
            "invalid source archive size",
        )?;

        Ok(CandidateIdentity {
            source: self.source(),
            target: self
                .target
                .clone()
                .map(DeploymentTarget::Guest)
                .unwrap_or(DeploymentTarget::Machine),
        })
    }
}

/// Require a clean checkout and read its committed revision and dependency-lock digest.
pub fn identity(repo: &Path) -> Result<SourceIdentity> {
    let repo = repo
        .to_str()
        .ok_or_else(|| super::Error::Message("non-UTF-8 repository path".into()))?;
    require(
        process::text("git", &["-C", repo, "status", "--porcelain"])?.is_empty(),
        "commit or stash checkout changes before submission",
    )?;

    let revision = process::text("git", &["-C", repo, "rev-parse", "HEAD"])?.parse()?;
    let lock_hash = format!(
        "{:x}",
        Sha256::digest(fs::read(Path::new(repo).join("flake.lock"))?)
    )
    .parse()?;

    Ok(SourceIdentity {
        revision,
        lock_hash,
    })
}
