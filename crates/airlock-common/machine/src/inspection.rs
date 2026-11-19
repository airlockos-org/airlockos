//! Plan evaluated releases using explicit observations, without reading runtime state.

use crate::{
    model::{Manifest, Plan, StorePath, Topology},
    planning,
};
use airlock_nix_core::identity::GuestName;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Evaluated configuration and artifact paths; decoding does not prove a build or admission.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EvaluatedMachine {
    /// Release identity and evaluated artifact selections.
    pub manifest: Manifest,
    /// Final Qubes configuration after NixOS merging and normalization.
    pub topology: Topology,
}

impl EvaluatedMachine {
    /// Borrow the evaluated records for common validation and inspection.
    pub fn view(&self) -> MachineView<'_> {
        MachineView {
            manifest: &self.manifest,
            topology: &self.topology,
        }
    }
}

/// Borrowed records shared by file inspection and the existing runtime release loader.
#[derive(Clone, Copy)]
pub struct MachineView<'a> {
    /// Release metadata whose identities and targets must match the topology.
    pub manifest: &'a Manifest,
    /// Evaluated topology carrying the actual settings used for planning.
    pub topology: &'a Topology,
}

impl MachineView<'_> {
    /// Check the existing topology and manifest invariants without I/O or authority changes.
    pub fn validate(self) -> Result<()> {
        self.topology.validate()?;
        self.manifest.validate(self.topology)
    }
}

/// Authority explicitly limited to a local explanation of supplied configurations.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum InspectionAuthority {
    /// No build completion, runtime admission or activation permission is implied.
    #[serde(rename = "local-inspection-only")]
    LocalInspectionOnly,
}

/// Pure planning result with the same wire shape as the dom0 inspection command.
#[derive(Debug, Deserialize, Serialize)]
pub struct Inspection {
    /// Explicitly distinguishes inspection from a protected deployment decision.
    pub authority: InspectionAuthority,
    /// Computed effects for the supplied topology, host and running-VM observations.
    pub plan: Plan,
}

/// Compare evaluated releases using the same checks as dom0's explicit-baseline command.
/// The host and running set are caller-supplied observations; no live state is read.
pub fn inspect(
    before: MachineView<'_>,
    after: MachineView<'_>,
    running: &BTreeSet<GuestName>,
    host: &StorePath,
) -> Result<Inspection> {
    before.validate()?;
    after.validate()?;
    ensure!(
        before.manifest.profile == after.manifest.profile,
        "release profiles differ"
    );
    ensure!(
        running
            .iter()
            .all(|name| before.topology.domains.contains_key(name)
                || after.topology.domains.contains_key(name)),
        "unknown running guest"
    );

    let mut plan = planning::plan(
        before.topology,
        after.topology,
        running,
        &after.manifest.retire_domains,
        false,
    )?;
    plan.host_reboot_required = Some(*host != after.manifest.host);
    plan.revision = Some(after.manifest.revision.clone());
    Ok(Inspection {
        authority: InspectionAuthority::LocalInspectionOnly,
        plan,
    })
}
