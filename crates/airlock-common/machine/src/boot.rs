//! Validate boot configuration once while retaining the original declaration.
//! Raw JSON preserves omitted settings; the typed projection supplies identities
//! and dependency semantics. Neither representation grants deployment approval.

use crate::{model::Topology, planning};
use airlock_nix_core::identity::GuestName;
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::collections::BTreeSet;

pub mod artifacts;

/// Default budget for Qubes to start one guest, before readiness polling begins.
pub const GUEST_START_SECONDS: u64 = 240;

/// Default budget for one running guest's generation and service-health probes.
pub const GUEST_READY_SECONDS: u64 = 180;

/// Outer helper budget, including both supervisor calls, bounded probe overrun and cleanup.
pub const GUEST_HELPER_SECONDS: u64 = GUEST_START_SECONDS + GUEST_READY_SECONDS + 240;

/// Additional time for systemd pre/post commands surrounding the native helper.
pub const BOOT_UNIT_OVERHEAD_SECONDS: u64 = 120;

/// Select the GUI, explicitly foreground guests and their local dependency closure.
/// These VMs must be configured and usable before desktop readiness completes startup.
pub fn foreground_guests(topology: &Topology) -> Result<Vec<GuestName>> {
    let gui: GuestName = "sys-gui".parse()?;
    ensure!(
        topology.domains.contains_key(&gui),
        "physical GUI startup requires a declared sys-gui"
    );
    let mut names = BTreeSet::from([gui]);
    for (name, domain) in &topology.domains {
        match domain.features.get("airlock-boot-foreground") {
            None => {}
            Some(Value::String(value)) if value == "0" => {}
            Some(Value::String(value)) if value == "1" => {
                names.insert(name.clone());
            }
            Some(_) => anyhow::bail!("{name}: invalid foreground boot preference"),
        }
    }
    let dependencies = planning::dependencies(topology, false)?;
    loop {
        let before = names.len();
        let parents = names
            .iter()
            .flat_map(|name| dependencies.get(name).into_iter().flatten())
            .filter(|name| topology.domains.contains_key(*name))
            .cloned()
            .collect::<Vec<_>>();
        names.extend(parents);
        if before == names.len() {
            break;
        }
    }
    Ok(planning::ordered(topology)?
        .into_iter()
        .filter(|name| names.contains(name))
        .collect())
}

/// One immutable boot input accepted by the runtime topology and graph decoders.
/// Keep this value across planning so later code cannot replace the declaration
/// while retaining an earlier successful validation.
#[derive(Clone)]
pub struct BootInputs {
    // Original settings, including omitted, null and explicit overrides.
    raw: Value,
    // Runtime identities decoded from these exact settings.
    topology: Topology,
}

impl BootInputs {
    /// Decode identities and reject invalid dependency graphs before setup effects.
    pub fn new(raw: Value) -> Result<Self> {
        let topology: Topology =
            serde_json::from_value(raw.clone()).context("decode boot topology")?;
        topology.validate().context("validate boot topology")?;
        planning::ordered(&topology).context("validate boot dependency graph")?;
        Ok(Self { raw, topology })
    }

    /// Borrow the unchanged declaration for adapters which must preserve defaults.
    pub fn raw(&self) -> &Value {
        &self.raw
    }

    /// Borrow the typed projection used by dependency and boot planning.
    pub fn topology(&self) -> &Topology {
        &self.topology
    }
}
