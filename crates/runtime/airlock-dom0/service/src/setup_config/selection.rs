//! A boot selection crosses the setup process boundary as a closed, topology-bound record.
//! Decoding never creates approval: retained entries must match freshly loaded committed
//! generations; explicit manual entries retain the existing boot/manual admission policy.

use crate::model::{GenerationId, StoreArtifact, StoreFile, StoreMode, StorePath};
use airlock_deployment_core::boot::{Argument, Handoff, SelectedGeneration, Selection};
use airlock_machine_core::boot::BootInputs;
use airlock_nix_core::identity::{GuestName, LockHash};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path};

/// Closed wire version; an unknown protocol cannot become a manual setup request.
#[derive(Serialize, Deserialize)]
enum Schema {
    /// Complete VM classification bound to one effective topology.
    #[serde(rename = "airlock.selected-setup.v1")]
    V1,
}

/// Typed transport for one selected generation; only the verifier constructs its executable counterpart.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSelection {
    // Positive generation in the map key's VM namespace.
    generation: GenerationId,
    // Exact immutable guest system.
    system: StorePath,
    // Root seed paired with that system.
    root: StoreFile,
    // Prepared descriptor or closure source belonging to this VM.
    source: StoreArtifact,
    // Kernel name recorded by generation admission.
    kernel: String,
    // Guest software-sharing protocol.
    mode: StoreMode,
    // Metadata frontend seen by the guest.
    device: String,
    // External-data frontend seen by the guest.
    blob_device: String,
    // Guest mount location for this software view.
    mountpoint: String,
    // Storage view implementation.
    backend: String,
}

impl WireSelection {
    fn encode(selection: &Selection) -> Result<Self> {
        Ok(Self {
            generation: selection.generation.to_string().parse()?,
            system: selection.system.parse()?,
            root: selection.root.parse()?,
            source: selection.source.parse()?,
            kernel: selection.kernel.clone(),
            mode: serde_json::from_value(Value::String(selection.mode.clone()))?,
            device: selection.device.clone(),
            blob_device: selection.blob_device.clone(),
            mountpoint: selection.mountpoint.clone(),
            backend: selection.backend.clone(),
        })
    }

    fn decode(self, domain: &GuestName) -> Result<Selection> {
        Ok(Selection {
            domain: domain.to_string(),
            generation: self.generation.to_string().parse()?,
            system: self.system.to_string(),
            root: self.root.to_string(),
            source: self.source.to_string(),
            kernel: self.kernel,
            mode: serde_json::to_value(self.mode)?
                .as_str()
                .context("invalid store mode")?
                .into(),
            device: self.device,
            blob_device: self.blob_device,
            mountpoint: self.mountpoint,
            backend: self.backend,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSetup {
    // Exact version of the selected-setup protocol.
    schema: Schema,
    // Includes all settings, not merely the generation fields compared by Verus.
    topology: LockHash,
    // Every declared VM is classified. Null explicitly retains manual admission semantics.
    domains: BTreeMap<GuestName, Option<WireSelection>>,
}

/// Checked selections for exactly one topology, with explicit manual exceptions.
pub(crate) struct BootSetup {
    // No missing entry can silently acquire manual admission semantics.
    domains: BTreeMap<GuestName, Option<SelectedGeneration>>,
}

impl BootSetup {
    /// Publish a protected handoff for the exact setup scope, preserving partial legacy staging explicitly.
    pub(crate) fn save(handoff: &Handoff, topology: &Value, path: &Path) -> Result<LockHash> {
        let inputs = BootInputs::new(topology.clone())?;
        let mut domains = inputs
            .topology()
            .domains
            .keys()
            .map(|name| (name.clone(), None))
            .collect::<BTreeMap<_, _>>();
        for selection in handoff.selections() {
            let name: GuestName = selection.domain.parse()?;
            if let Some(entry) = domains.get_mut(&name) {
                *entry = Some(WireSelection::encode(selection)?);
            }
        }
        let record = serde_json::to_value(WireSetup {
            schema: Schema::V1,
            topology: crate::state::digest(topology)?.parse()?,
            domains,
        })?;
        let digest = record_digest(&record)?;
        crate::state::save(path, &record)?;
        Ok(digest)
    }

    /// Authenticate all retained entries before setup can perform global or per-VM changes.
    pub(crate) fn read(path: &Path, digest: &LockHash, topology: &Value) -> Result<Self> {
        let raw: Value = crate::state::read(path)?;
        ensure!(
            record_digest(&raw)? == *digest,
            "checked setup selection record changed"
        );
        let record: WireSetup = serde_json::from_value(raw)?;
        ensure!(
            record.topology.as_str() == crate::state::digest(topology)?,
            "setup topology differs from checked selection"
        );
        let inputs = BootInputs::new(topology.clone())?;
        ensure!(
            record.domains.keys().eq(inputs.topology().domains.keys()),
            "setup selection is missing or has extra VMs"
        );
        let mut domains = BTreeMap::new();
        for (name, wire) in record.domains {
            let selected = wire
                .map(|wire| -> Result<_> {
                    let wanted = crate::store::handoff::expected(
                        &name,
                        &inputs.topology().domains[&name].backend,
                        wire.generation,
                    )?;
                    let selection = wire.decode(&name)?;
                    // First check the transported identity against this exact topology.
                    let selected = SelectedGeneration::check(selection, &wanted)
                        .context("transported setup selection differs from topology")?;
                    // Then authenticate it against current committed records under the pool lock.
                    crate::store::handoff::authenticate(selected)
                })
                .transpose()?;
            domains.insert(name, selected);
        }
        Ok(Self { domains })
    }

    /// A missing classification is an error, never permission to admit new software.
    pub(crate) fn get(&self, name: &str) -> Result<Option<&SelectedGeneration>> {
        let name: GuestName = name.parse()?;
        self.domains
            .get(&name)
            .context("VM absent from checked setup scope")
            .map(Option::as_ref)
    }
}

/// The only numeric rendering step; flags and identities remain exactly as selected by verified Rust.
pub(crate) fn arguments(arguments: Vec<Argument>) -> Vec<String> {
    arguments
        .into_iter()
        .map(|arg| match arg {
            Argument::Text(value) => value,
            Argument::Generation(value) => value.to_string(),
        })
        .collect()
}

/// Bind the new handoff protocol's complete JSON value, including its explicit policy classifications.
/// Unlike legacy review fingerprints, this wire protocol uses compact Serde JSON encoding.
fn record_digest(value: &Value) -> Result<LockHash> {
    Ok(format!(
        "{digest:x}",
        digest = Sha256::digest(serde_json::to_vec(value)?)
    )
    .parse()?)
}
