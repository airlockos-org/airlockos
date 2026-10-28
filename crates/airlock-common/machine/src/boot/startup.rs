//! Build one checked foreground plan from the complete selected topology.
//! Display attachment can reconnect; explicit service authorities remain hard prerequisites.

use super::{BootInputs, foreground_guests};
use crate::planning;
use airlock_deployment_core::boot::startup::{Phase, Plan};
use airlock_nix_core::identity::GuestName;
use anyhow::{Context, Result, ensure};
use std::collections::BTreeMap;

/// One canonical foreground set with checked phases and all resolved hard provider edges.
/// The original boot inputs remain borrowed so neither phase can substitute another topology.
///
/// ```compile_fail
/// use airlock_deployment_core::boot::startup::Plan;
/// use airlock_machine_core::boot::{BootInputs, startup::ForegroundPlan};
/// /// A checked schedule cannot be rebound to a smaller guest table.
/// fn bypass(inputs: &BootInputs, schedule: Plan) -> ForegroundPlan<'_> {
///     ForegroundPlan { inputs, guests: vec![], schedule }
/// }
/// ```
pub struct ForegroundPlan<'a> {
    // Complete immutable topology used to resolve foreground membership and dependencies.
    inputs: &'a BootInputs,
    // Dependency-first identities; each guest has one stable index in the verified plan.
    guests: Vec<GuestName>,
    // Verified partition and hard-edge ordering for the entire canonical guest set.
    schedule: Plan,
}

impl BootInputs {
    /// Derive both execution phases together, rejecting unresolved hard foreground providers.
    pub fn foreground_plan(&self) -> Result<ForegroundPlan<'_>> {
        let guests = foreground_guests(self.topology())?;
        let indices = guests
            .iter()
            .enumerate()
            .map(|(i, name)| (name.clone(), i))
            .collect::<BTreeMap<_, _>>();
        let gui = *indices.get(&"sys-gui".parse()?).context("missing GUI")?;
        let dependencies = planning::dependencies(self.topology(), true)?;
        let mut parents = Vec::new();
        let mut stages = Vec::new();
        for (i, name) in guests.iter().enumerate() {
            let providers = dependencies[name]
                .iter()
                .map(|provider| {
                    indices.get(provider).copied().with_context(|| {
                        format!("{name}: hard startup provider {provider} is outside the foreground plan")
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            ensure!(
                providers.iter().all(|p| *p < i),
                "invalid foreground dependency order"
            );
            let phase = if i == gui {
                Phase::Gui
            } else if providers.iter().any(|p| stages[*p] != Phase::BeforeGui) {
                Phase::AfterGui
            } else {
                Phase::BeforeGui
            };
            parents.push(providers);
            stages.push(phase);
        }
        let schedule = Plan::check(&parents, gui, stages)
            .context("foreground schedule violates its hard dependency graph")?;
        Ok(ForegroundPlan {
            inputs: self,
            guests,
            schedule,
        })
    }
}

impl<'a> ForegroundPlan<'a> {
    /// Borrow the complete selected topology retained by this plan.
    pub fn inputs(&self) -> &'a BootInputs {
        self.inputs
    }

    /// Borrow the canonical complete foreground set, including the guarded GUI itself.
    pub fn guests(&self) -> &[GuestName] {
        &self.guests
    }

    /// Inspect one checked phase in dependency order; inspecting a plan grants no runtime readiness.
    pub fn phase(&self, phase: Phase) -> Vec<GuestName> {
        self.guests
            .iter()
            .enumerate()
            .filter(|(i, _)| self.schedule.phase(*i) == Some(phase))
            .map(|(_, name)| name.clone())
            .collect()
    }

    /// Permit an optional overlapping guest only when all its hard providers precede home in this phase.
    pub fn can_overlap(&self, phase: Phase, guest: &GuestName, home: &GuestName) -> Result<bool> {
        let names = self.phase(phase);
        let Some(position) = names.iter().position(|name| name == home) else {
            return Ok(false);
        };
        let dependencies = planning::dependencies(self.inputs.topology(), true)?;
        let early = self.phase(Phase::BeforeGui);
        Ok(dependencies.get(guest).is_some_and(|providers| {
            providers.iter().all(|provider| {
                names[..position].contains(provider)
                    || (phase == Phase::AfterGui && early.contains(provider))
                    || (phase == Phase::AfterGui && provider.as_str() == "sys-gui")
            })
        }))
    }
}
