//! Capture complete guest identities in authoritative intent before privileged activation.
//! Recovery reauthenticates those identities; fresh plan/attempt bindings never select replacements.
//! The numeric map is a compatibility projection; native setup never reconstructs authority from it.

use super::*;
use crate::store::{GenerationMatchOutcome, GenerationMatchSchema};
use airlock_deployment_core::{
    boot::SelectedGeneration,
    storage::{
        StoragePlan,
        staging::{
            Requirement, Resolution, StagedGenerations,
            persistence::{PinnedGenerations, RecordedResolution, Snapshot},
        },
    },
};
use airlock_nix_core::identity::StoreNamespace;
use serde::Deserialize;

/// Immutable prepared descriptors suggest a generation; committed storage independently authenticates it.
#[derive(Deserialize)]
struct PreparedHint {
    /// Known prepared descriptor protocol, not an admission/installation result.
    schema: PreparedSchema,
    /// Guest runtime namespace in which the positive generation must exist.
    domain: StoreNamespace,
    /// Candidate generation; no authority is gained by decoding it.
    generation: GenerationId,
}

/// Closed prepared protocol used only to discover the already committed generation.
#[derive(Deserialize)]
enum PreparedSchema {
    /// Descriptor generated during image preparation.
    #[serde(rename = "airlock.closure-store.prepared.v1")]
    V1,
}

impl Coordinator {
    /// Resolve and authenticate complete selections before publishing the authoritative intent.
    pub(super) fn pin_images(
        &self,
        release: &Release,
        record: &mut Record,
        previous: Option<&Record>,
        plan: &StoragePlan,
    ) -> Result<PinnedGenerations> {
        let mut snapshots = previous
            .map(retained_snapshots)
            .transpose()?
            .unwrap_or_default();
        let target = target(&record.release, release.fingerprint())?;
        let saved = snapshots
            .iter()
            .find(|s| s.release == record.release)
            .map(snapshot)
            .transpose()?;
        let context = super::approval::effect_context(record)?;
        let mut entries = Vec::new();
        for (index, definition) in plan.definitions().iter().enumerate() {
            let entry = match plan
                .requirement(index)
                .context("missing staging coordinate")?
            {
                Requirement::NonNative => Resolution::NonNative,
                Requirement::Existing => Resolution::Existing,
                Requirement::Resolve(pin) => {
                    let name: GuestName = definition.name.parse()?;
                    let native = definition
                        .native
                        .as_ref()
                        .context("missing original native backend")?;
                    let backend = &release
                        .topology
                        .domains
                        .get(&name)
                        .context("staged VM is undeclared")?
                        .backend;
                    let original = saved
                        .as_ref()
                        .map(|s| {
                            s.entries
                                .get(index)
                                .context("missing retained guest selection")
                        })
                        .transpose()?;
                    let generation = if let Some(original) = original {
                        match original {
                            RecordedResolution::Retained(s) => s.generation.to_string().parse()?,
                            _ => bail!("retained staging classification differs"),
                        }
                    } else if previous
                        .is_some_and(|p| p.metadata.details.guest_generations.is_none())
                        && pin.is_none()
                    {
                        // An old journal cannot establish which unpinned generation may already have run.
                        bail!("legacy recovery has no durable guest generation selection")
                    } else if let Some(pin) = pin {
                        pin.to_string().parse()?
                    } else {
                        let prepared = Path::new(&native.artifact).join("prepared.json");
                        if prepared.try_exists()? {
                            // Prepared descriptors are immutable configuration and may use store symlinks.
                            let hint: PreparedHint = state::configuration(&prepared)?;
                            let PreparedSchema::V1 = hint.schema;
                            ensure!(
                                hint.domain.as_str()
                                    == crate::store::runtime_namespace(name.as_str()),
                                "prepared staging namespace differs"
                            );
                            hint.generation
                        } else {
                            let reply = self.store().find(&name, backend, "usr-assistant")?;
                            let GenerationMatchSchema::V1 = reply.schema;
                            ensure!(
                                reply.domain.as_str()
                                    == crate::store::runtime_namespace(name.as_str()),
                                "retained lookup namespace differs"
                            );
                            match reply.outcome {
                                GenerationMatchOutcome::Found { generation, .. } => generation,
                                GenerationMatchOutcome::Missing => bail!(
                                    "retained image generation unavailable; refusing implicit admission"
                                ),
                            }
                        }
                    };
                    let wanted = match original {
                        Some(RecordedResolution::Retained(s)) => clone_selection(s),
                        _ => crate::store::handoff::expected(&name, backend, generation)?,
                    };
                    let info = self.generation(&name, generation)?;
                    let observed = crate::store::handoff::described(&info)?;
                    Resolution::Retained(Box::new(
                        SelectedGeneration::check(wanted, &observed).context(
                            "staged generation differs from complete desired boot identity",
                        )?,
                    ))
                }
            };
            entries.push(entry);
        }
        let pinned = plan
            .pin(&context, target, saved.as_ref(), entries)
            .context("guest generation selections differ from original operation or target")?;
        if saved.is_none() {
            snapshots.push(encode_snapshot(plan, &pinned)?);
        }
        record.metadata.details.guest_generations = Some(snapshots);
        Ok(pinned)
    }

    /// Activate the prepublication pin; the numeric map is only a legacy compatibility projection.
    pub(super) fn stage_images(
        &self,
        record: &Record,
        directory: &Path,
        durable: &super::approval::DurableAuthorization,
        pinned: PinnedGenerations,
    ) -> Result<StagedGenerations> {
        let staged = durable.activate_pinned(record, pinned)?;
        let mapping = staged
            .entries()
            .iter()
            .filter_map(|entry| match entry {
                Resolution::Retained(selected) => Some((
                    selected.selection().domain.clone(),
                    selected.selection().generation,
                )),
                _ => None,
            })
            .map(|(name, generation)| -> Result<_> {
                Ok((
                    name.parse::<GuestName>()?,
                    generation.to_string().parse::<GenerationId>()?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;

        // Legacy admitted helpers consume this projection. Its publication failure stops activation.
        // Current native execution retains `staged` itself and never re-reads the map.
        state::save(&directory.join("staged.json"), &mapping)?;
        Ok(staged)
    }
}

/// Fingerprint and path together identify the target independently of a rebuilt plan.
pub(super) fn target(release: &ReleasePath, fingerprint: &ReleaseFingerprint) -> Result<String> {
    Ok(serde_json::to_string(&(release, fingerprint))?)
}

/// Retain both endpoint snapshots across rollback/resume, never an unrelated target or authority.
pub(super) fn retained_snapshots(previous: &Record) -> Result<Vec<GuestGenerationSnapshot>> {
    let Some(snapshots) = &previous.metadata.details.guest_generations else {
        return Ok(Vec::new());
    };
    let native = previous.metadata.origin.require_native()?;
    let operation = previous
        .metadata
        .details
        .operation
        .as_ref()
        .context("missing snapshot operation")?;
    ensure!(
        !snapshots.is_empty() && snapshots.len() <= 2,
        "invalid guest generation snapshot count"
    );
    let mut seen = BTreeSet::new();
    for s in snapshots {
        ensure!(
            &s.operation == operation,
            "guest generation snapshot authority differs"
        );
        ensure!(
            (s.release == previous.release && s.fingerprint == native.release_fingerprint)
                || (s.release == previous.previous && s.fingerprint == native.previous_fingerprint),
            "guest generation snapshot target differs"
        );
        ensure!(
            seen.insert(s.release.to_string()),
            "duplicate guest generation snapshot target"
        );
    }
    ensure!(
        seen.contains(previous.release.as_str()),
        "current target has no durable guest generation snapshot"
    );
    Ok(snapshots.clone())
}

/// Read the target snapshot from the actual journal consumed by the durable publication gate.
pub(super) fn current_snapshot(record: &Record) -> Result<Snapshot> {
    let snapshots = retained_snapshots(record)?;
    snapshot(
        snapshots
            .iter()
            .find(|s| s.release == record.release)
            .context("published intent has no target guest selections")?,
    )
}

/// Decode typed journal evidence into inert Verus inputs, preserving every field.
pub(super) fn snapshot(saved: &GuestGenerationSnapshot) -> Result<Snapshot> {
    Ok(Snapshot {
        operation: saved.operation.id.as_str().to_owned(),
        authority: serde_json::to_string(&saved.operation.authority)?,
        target: target(&saved.release, &saved.fingerprint)?,
        entries: saved
            .entries
            .iter()
            .map(|entry| match entry {
                GuestGenerationEntry::NonNative { domain } => {
                    RecordedResolution::NonNative(domain.to_string())
                }
                GuestGenerationEntry::Existing { domain } => {
                    RecordedResolution::Existing(domain.to_string())
                }
                GuestGenerationEntry::Retained { domain, identity } => {
                    RecordedResolution::Retained(Box::new(crate::store::handoff::fields(
                        domain, identity,
                    )))
                }
            })
            .collect(),
    })
}

/// Journal encoding is derived from the opaque pin rather than resolver hints or ambient maps.
fn encode_snapshot(
    plan: &StoragePlan,
    pinned: &PinnedGenerations,
) -> Result<GuestGenerationSnapshot> {
    let (release, fingerprint) = serde_json::from_str(pinned.target())?;
    let entries = pinned
        .entries()
        .iter()
        .zip(plan.definitions())
        .map(|(resolution, d)| -> Result<_> {
            let domain = d.name.parse()?;
            Ok(match resolution {
                Resolution::NonNative => GuestGenerationEntry::NonNative { domain },
                Resolution::Existing => GuestGenerationEntry::Existing { domain },
                Resolution::Retained(selected) => {
                    let s = selected.selection();
                    GuestGenerationEntry::Retained {
                        domain,
                        identity: Box::new(StorageIdentity {
                            generation: s.generation.to_string().parse()?,
                            system: s.system.clone(),
                            root_source: s.root.clone(),
                            source: s.source.clone(),
                            kernel_name: s.kernel.clone(),
                            mode: serde_json::from_value(json!(s.mode))?,
                            device: s.device.clone(),
                            blob_device: s.blob_device.clone(),
                            mountpoint: s.mountpoint.clone(),
                            view_backend: s.backend.clone(),
                        }),
                    }
                }
            })
        })
        .collect::<Result<_>>()?;
    Ok(GuestGenerationSnapshot {
        operation: DeploymentOperation {
            id: pinned.operation().to_owned().try_into()?,
            authority: serde_json::from_str(pinned.authority())?,
        },
        release,
        fingerprint,
        entries,
    })
}

/// Copy inert expected evidence for fresh comparison against independently loaded committed storage.
fn clone_selection(
    s: &airlock_deployment_core::boot::Selection,
) -> airlock_deployment_core::boot::Selection {
    airlock_deployment_core::boot::Selection {
        domain: s.domain.clone(),
        generation: s.generation,
        system: s.system.clone(),
        root: s.root.clone(),
        source: s.source.clone(),
        kernel: s.kernel.clone(),
        mode: s.mode.clone(),
        device: s.device.clone(),
        blob_device: s.blob_device.clone(),
        mountpoint: s.mountpoint.clone(),
        backend: s.backend.clone(),
    }
}

#[cfg(test)]
mod tests;
