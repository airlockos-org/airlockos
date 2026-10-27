//! Compare intended boot artifacts with committed generations before any setup mutation.
//! Record loading, filesystem observations and JSON projection remain adapter duties;
//! the equality and complete-set decision executes the deployment core's Verus code.

use super::{fs::*, generations, prepared, runtime_namespace};
use crate::model::{
    Backend, CheckStatus, GenerationId, GenerationInfo, GenerationReceipt, InstalledStorageReceipt,
    StorageIdentity, Topology,
};
use airlock_deployment_core::boot::{Handoff, SelectedGeneration, Selection};
use airlock_machine_core::boot::BootInputs;
use airlock_nix_core::identity::GuestName;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, path::Path};

/// Retain every identity and layout field that setup uses to select a guest generation.
pub(crate) fn expected(
    name: &GuestName,
    backend: &Backend,
    generation: GenerationId,
) -> Result<Selection> {
    Ok(Selection {
        domain: name.to_string(),
        generation: generation.to_string().parse()?,
        system: backend.system.source.to_string(),
        root: backend.nixos()?.root.source.to_string(),
        source: backend.nixos()?.store.source.to_string(),
        kernel: backend.nixos()?.kernel.name.clone(),
        mode: serde_json::to_value(backend.nixos()?.store.mode)?
            .as_str()
            .context("invalid store mode")?
            .into(),
        device: backend.nixos()?.store.device.clone(),
        blob_device: backend.nixos()?.store.blob_device.clone(),
        mountpoint: backend.nixos()?.store.mountpoint.clone(),
        backend: backend.nixos()?.store.view_backend.clone(),
    })
}

/// Project only a loaded generation; installation receipts cannot be supplied here.
pub(crate) fn observed(value: &GenerationReceipt) -> Result<Selection> {
    let domain: GuestName = value
        .domain
        .as_str()
        .strip_suffix("-runtime-store")
        .context("boot generation is not a runtime storage view")?
        .parse()?;
    Ok(fields(&domain, &value.identity))
}

/// Project only an installation addressed to a guest; wire decoding checked its schema.
pub(crate) fn installed(value: &InstalledStorageReceipt) -> Selection {
    fields(&value.domain, &value.identity)
}

/// Preserve every typed identity field without wire-key selection or namespace guessing.
pub(crate) fn fields(domain: &GuestName, identity: &StorageIdentity) -> Selection {
    Selection {
        domain: domain.to_string(),
        generation: identity.generation.get(),
        system: identity.system.clone(),
        root: identity.root_source.clone(),
        source: identity.source.clone(),
        kernel: identity.kernel_name.clone(),
        mode: match identity.mode {
            crate::model::StoreMode::SharedClosure => "shared-closure".into(),
        },
        device: identity.device.clone(),
        blob_device: identity.blob_device.clone(),
        mountpoint: identity.mountpoint.clone(),
        backend: identity.view_backend.clone(),
    }
}

/// Inspection has its own typed schema and nested layout, distinct from a loaded generation.
pub(crate) fn described(value: &GenerationInfo) -> Result<Selection> {
    ensure!(
        value.status == CheckStatus::Passed,
        "boot generation inspection failed"
    );
    let domain: GuestName = value
        .domain
        .as_str()
        .strip_suffix("-runtime-store")
        .context("boot generation is not a runtime storage view")?
        .parse()?;
    Ok(fields(
        &domain,
        &StorageIdentity {
            generation: value.generation,
            system: value.system.to_string(),
            root_source: value.root_source.to_string(),
            source: value.closure_source.to_string(),
            kernel_name: value.kernel_name.clone(),
            mode: value.store._mode,
            device: value.store.device.clone(),
            blob_device: value.store.blob_device.clone(),
            mountpoint: value.store.mountpoint.clone(),
            view_backend: value.store.view_backend.clone(),
        },
    ))
}

/// Compare every explicitly staged VM before privileged boot setup.
/// Releases may stage a subset; the image adapter separately requires complete coverage.
pub(crate) fn selected(
    topology: &Topology,
    mapping: &BTreeMap<GuestName, GenerationId>,
    mut describe: impl FnMut(&GuestName, GenerationId) -> Result<GenerationInfo>,
) -> Result<Handoff> {
    let mut wanted = Vec::new();
    let mut actual = Vec::new();
    for (name, generation) in mapping {
        let domain = topology
            .domains
            .get(name)
            .with_context(|| format!("staged boot VM is undeclared: {name}"))?;
        let generation = *generation;
        wanted.push(expected(name, &domain.backend, generation)?);
        let described = describe(name, generation)
            .with_context(|| format!("inspect boot generation for {name}"))?;
        actual.push(self::described(&described)?);
    }
    Handoff::check(wanted, &actual)
        .context("boot artifacts differ from selected committed generations")
}

/// Validate each prepared descriptor and its committed generation as one image handoff.
/// Payload hashes are checked by the existing image-output gate. This additionally
/// checks the metadata hashes and exact generation/descriptor/topology bindings.
pub(super) fn image(topology: Value, physical: &Path, logical: &Path) -> Result<Value> {
    let inputs = BootInputs::new(topology)?;
    let mut wanted = Vec::new();
    let mut actual = Vec::new();
    let mut mapping = BTreeMap::new();
    for (name, domain) in &inputs.topology().domains {
        let backend = &domain.backend;
        if let Some(artifact) = backend.hermit() {
            crate::hermit::verify_image(
                artifact,
                domain
                    .prefs
                    .get("memory")
                    .and_then(Value::as_u64)
                    .context("missing Hermit memory")?,
            )?;
            continue;
        }
        let descriptor: Value =
            read(&Path::new(backend.nixos()?.store.source.as_str()).join("prepared.json"))
                .with_context(|| format!("read prepared descriptor for {name}"))?;
        ensure!(
            descriptor["schema"] == "airlock.closure-store.prepared.v1"
                && descriptor["domain"] == runtime_namespace(name.as_str())
                && descriptor["pool_root"].as_str() == logical.to_str(),
            "prepared descriptor binding mismatch: {name}"
        );
        let generation: GenerationId = number(&descriptor, "generation")?.to_string().parse()?;
        let loaded = generations::load(
            physical,
            logical,
            &runtime_namespace(name.as_str()),
            generation.to_string().parse()?,
        )?;
        ensure!(
            descriptor["system"] == loaded.identity.system
                && descriptor["root_source"] == loaded.identity.root_source
                && descriptor["kernel_name"] == loaded.identity.kernel_name
                && descriptor["closure_hash"] == loaded.closure_hash,
            "prepared identity differs from committed generation: {name}"
        );
        let manifest = super::records::manifest_path(
            physical,
            &runtime_namespace(name.as_str()),
            generation.to_string().parse()?,
        )?;
        let key = manifest
            .strip_prefix(physical)?
            .to_str()
            .context("invalid manifest path")?;
        ensure!(
            descriptor["files"].get(key).is_some(),
            "prepared manifest checksum missing: {name}"
        );
        prepared::verify_files(physical, &descriptor["files"], true)?;

        let kernel = inputs
            .topology()
            .kernels
            .get(&backend.nixos()?.kernel.name)
            .with_context(|| format!("missing boot kernel definition: {name}"))?;
        let kernel = Path::new(
            kernel["source"]
                .as_str()
                .context("missing kernel bundle source")?,
        );
        ensure!(
            fs::metadata(kernel.join("vmlinuz"))?.is_file(),
            "missing boot kernel: {name}"
        );
        wanted.push(expected(name, backend, generation)?);
        actual.push(observed(&loaded)?);
        mapping.insert(name.clone(), generation);
    }
    let handoff = Handoff::check(wanted, &actual)
        .context("prepared image topology differs from committed generations")?;
    ensure!(
        handoff.selections().len() == mapping.len(),
        "incomplete checked image handoff"
    );
    Ok(json!({"schema":"airlock.boot-handoff.v1", "status":"passed", "generations":mapping}))
}

/// Revalidate a transported selection against committed records, never admitting new content.
pub(crate) fn authenticate(selected: SelectedGeneration) -> Result<SelectedGeneration> {
    let wanted = selected.selection();
    let root = std::env::var_os("AIRLOCK_CLOSURE_STORE_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "/var/lib/airlock/closure-store".into());
    let _lock = PoolLock::acquire(&root.join("admission.lock"))?;
    let receipt = generations::load(
        &root,
        &root,
        &runtime_namespace(&wanted.domain),
        wanted.generation,
    )?;
    let actual = observed(&receipt)?;
    ensure!(
        selected.setup(&actual).is_some(),
        "committed generation differs from checked setup selection"
    );
    Ok(selected)
}
