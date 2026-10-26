//! Explicit private-volume replacement and network-device ownership handoff.
//! Copies are journalled before configuration can create a destination VM.

use super::*;
use crate::qubes::{self, PrivateIdentity};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CopyStatus {
    Planned,
    Copying,
    Complete,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct PrivateCopy {
    // Independent source disk and registered VM captured during preflight.
    source: PrivateIdentity,
    // New VM name whose disk may be overwritten only by this recorded operation.
    target_name: GuestName,
    // Complete intended target configuration, detecting name reuse or changed requests.
    target_config: Domain,
    // Destination's registered VM and disk, fixed before the first clone call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target: Option<PrivateIdentity>,
    // Durable copy state; complete prevents later retries overwriting user data.
    status: CopyStatus,
}

/// Decode protected preflight identities without replacing their checked pair ordering.
pub(super) fn copy_definitions(
    plan: &Plan,
) -> Result<Vec<airlock_deployment_core::copy::Definition>> {
    let copies: Vec<PrivateCopy> = plan
        .extra
        .get("private_copies")
        .map(|v| serde_json::from_value(v.clone()))
        .transpose()?
        .unwrap_or_default();
    copies.iter().map(copy_definition).collect()
}

/// Decode one protected copy intent without omitting progress or either resource identity.
fn copy_definition(copy: &PrivateCopy) -> Result<airlock_deployment_core::copy::Definition> {
    Ok(airlock_deployment_core::copy::Definition {
        source: copy_volume(&copy.source),
        target: copy.target_name.as_str().into(),
        configuration: state::digest(&serde_json::to_value(&copy.target_config)?)?,
        status: match copy.status {
            CopyStatus::Planned => airlock_deployment_core::copy::Status::Planned,
            CopyStatus::Copying => airlock_deployment_core::copy::Status::Copying,
            CopyStatus::Complete => airlock_deployment_core::copy::Status::Complete,
        },
        pinned: copy.target.as_ref().map(copy_volume),
    })
}

/// Preserve the four independent identity components at the verified boundary.
fn copy_volume(identity: &PrivateIdentity) -> airlock_deployment_core::copy::Volume {
    airlock_deployment_core::copy::Volume {
        name: identity.domain.as_str().into(),
        uuid: identity.uuid.to_string(),
        pool: identity.pool.clone(),
        vid: identity.vid.clone(),
    }
}

impl Coordinator {
    fn private_identity(&self, name: &GuestName) -> Result<(PrivateIdentity, u64)> {
        let (volume, size) = qubes::volume(name, "private")?;
        ensure!(
            volume.rw && volume.save_on_stop && !volume.snap_on_start && volume.source.is_none(),
            "{name}: copy requires independent persistent private storage"
        );
        Ok((
            PrivateIdentity {
                domain: name.clone(),
                uuid: self
                    .runner
                    .text("qvm-prefs", &[name.as_str(), "uuid"])?
                    .parse()?,
                pool: volume.pool,
                vid: volume.vid,
            },
            size,
        ))
    }

    fn copy_path(&self, name: &GuestName) -> PathBuf {
        self.state
            .join("private-copies")
            .join(format!("{name}.json"))
    }

    pub(super) fn private_copy_plan(
        &self,
        old: &Release,
        new: &Release,
        previous: Option<&Record>,
    ) -> Result<Vec<PrivateCopy>> {
        if new.manifest.private_volume_copies.is_empty() {
            return Ok(Vec::new());
        }
        let registered = self.registered()?;
        let running = self.running()?;
        let mut result = Vec::new();
        for (target, source) in &new.manifest.private_volume_copies {
            ensure!(
                !old.topology.domains.contains_key(target),
                "private copy must replace an old VM with a new VM"
            );
            for (topology, name) in [(&old.topology, source), (&new.topology, target)] {
                let domain = topology
                    .domains
                    .get(name)
                    .context("private copy source or target absent from topology")?;
                ensure!(
                    domain.class_name == "StandaloneVM"
                        && domain
                            .backend
                            .state()
                            .get("persistent")
                            .is_some_and(|v| !v.is_null() && v != &json!(false)),
                    "{name}: unsupported private copy backend"
                );
            }
            let source_identity = self.private_identity(source)?.0;
            let receipt: Option<PrivateCopy> = state::optional(&self.copy_path(target))?;
            if let Some(r) = &receipt {
                ensure!(
                    r.source == source_identity
                        && r.target_name == *target
                        && r.target_config == new.topology.domains[target],
                    "private copy receipt differs from requested replacement"
                );
            }
            if registered.contains(target) {
                let saved = receipt
                    .as_ref()
                    .context("refuse to overwrite an existing VM without a copy receipt")?;
                let identity = self.private_identity(target)?.0;
                ensure!(
                    saved.target.as_ref().is_none_or(|t| t == &identity),
                    "private copy target identity changed"
                );
                ensure!(
                    !running.contains(target) || saved.status == CopyStatus::Complete,
                    "incomplete copy target is running"
                );
            }
            let current = receipt.unwrap_or(PrivateCopy {
                source: source_identity,
                target_name: target.clone(),
                target_config: new.topology.domains[target].clone(),
                target: None,
                status: CopyStatus::Planned,
            });
            if let Some(prior) = previous {
                let originals = copy_definitions(&prior.plan)?;
                let original = originals.iter().find(|copy| copy.target == target.as_str());
                ensure!(
                    airlock_deployment_core::copy::recovery(original, &copy_definition(&current)?),
                    "private copy recovery differs from or is missing its original authorised resources"
                );
            }
            result.push(current);
        }
        Ok(result)
    }

    pub(super) fn prepare_copies(&self, copies: &[PrivateCopy]) -> Result<()> {
        for copy in copies {
            let path = self.copy_path(&copy.target_name);
            if !path.try_exists()? {
                state::save(&path, copy)?;
            }
        }
        Ok(())
    }

    pub(super) fn copy_private(
        &self,
        copies: &[PrivateCopy],
        authority: &super::approval::DurableAuthorization,
        record: &Record,
    ) -> Result<()> {
        use airlock_deployment_core::copy::{Observation, Receipt, Status};
        for (index, copy) in copies.iter().enumerate() {
            let path = self.copy_path(&copy.target_name);
            let mut saved: PrivateCopy = state::read(&path)?;
            let (source, source_size) = self.private_identity(&saved.source.domain)?;
            let (target, target_size) = self.private_identity(&saved.target_name)?;
            let receipt = Receipt {
                source: copy_volume(&saved.source),
                target: saved.target_name.as_str().into(),
                configuration: state::digest(&serde_json::to_value(&saved.target_config)?)?,
                pinned: saved.target.as_ref().map(copy_volume),
                status: match saved.status {
                    CopyStatus::Planned => Status::Planned,
                    CopyStatus::Copying => Status::Copying,
                    CopyStatus::Complete => Status::Complete,
                },
            };
            let observed = Observation {
                source: copy_volume(&source),
                target: copy_volume(&target),
                source_power: self.operation_power(&source.domain)?,
                target_power: self.operation_power(&target.domain)?,
                source_size,
                target_size,
            };
            let Some(intent) = authority.copy(record, index, &receipt, &observed)? else {
                continue;
            };
            let pinned = intent.target();
            saved.target = Some(PrivateIdentity {
                domain: pinned.name.parse()?,
                uuid: pinned.uuid.parse()?,
                pool: pinned.pool.clone(),
                vid: pinned.vid.clone(),
            });
            saved.status = CopyStatus::Copying;
            state::save(&path, &saved)?;
            qubes::clone_private(intent.published())?;
            saved.status = CopyStatus::Complete;
            state::save(&path, &saved)?;
        }
        Ok(())
    }

    /// Missing or duplicate named observations cannot be treated as a stopped copy endpoint.
    pub(super) fn operation_power(
        &self,
        name: &GuestName,
    ) -> Result<airlock_deployment_core::inventory::PowerState> {
        let inventory = self
            .runner
            .text("qvm-ls", &["--raw-data", "--fields", "NAME,STATE"])?;
        let mut states = inventory
            .lines()
            .filter_map(|line| line.split_once('|'))
            .filter(|(vm, _)| *vm == name.as_str());
        let (_, power) = states
            .next()
            .context("private copy VM missing from runtime inventory")?;
        ensure!(
            states.next().is_none(),
            "duplicate private copy VM in runtime inventory"
        );
        Ok(airlock_deployment_core::inventory::PowerState::classify(
            power,
        ))
    }

    /// Observe the entire expected device set before issuing any unassignment.
    pub(super) fn check_pci_handoff(
        &self,
        handoff: &Value,
        recovery: bool,
    ) -> Result<airlock_deployment_core::pci::CheckedObservation> {
        let previous: GuestName = serde_json::from_value(handoff["from"].clone())?;
        let target: GuestName = serde_json::from_value(handoff["to"].clone())?;
        crate::qubes::pci::observe()?
            .check(previous.as_str().into(), target.as_str().into(), recovery)
            .context("network PCI handoff has unsupported endpoints, no controllers, or conflicting/foreign ownership")
    }

    /// Dispatch exact assignments from the original checked endpoints; never accept raw targets.
    pub(super) fn pci_handoff(
        &self,
        authority: &super::approval::DurableAuthorization,
        record: &Record,
        recovery: bool,
    ) -> Result<()> {
        let handoff = record
            .plan
            .pci_handoff
            .as_ref()
            .context("missing PCI handoff")?;
        let observed = self.check_pci_handoff(handoff, recovery)?;
        let execution = authority.pci(record, &observed)?;
        for index in 0..execution.len() {
            if let Some(request) = execution.request(index) {
                crate::qubes::pci::unassign(request)?;
            }
        }
        Ok(())
    }
}
