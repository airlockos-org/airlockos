//! Builder bases own reusable package bytes while private overlays can reference them.
//! Only temporary admission pins are released here. Existing generation tracing, explicit
//! retention, running references and stopped-VM predecessor handoff still govern collection.

use super::{builder, fs::*, generations, records};
use airlock_deployment_core::retention::{
    Candidate, Generation, Pin, ProtectedGenerations, Protection,
};
use airlock_nix_core::build_cache::DOMAIN;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, path::Path};

/// Release original scratch-admission pins only after the coordinator ends their ownership.
/// The caller holds the machine lock; pool exclusion covers observation and pin changes.
pub(crate) fn release(protections: Vec<Protection>) -> Result<Value> {
    let root = Path::new(super::host::POOL);
    ensure_pool(root)?;
    let _lock = PoolLock::acquire(&root.join("admission.lock"))?;
    let protected = ProtectedGenerations::new(protections).context("invalid build protections")?;
    let domain = super::runtime_namespace(DOMAIN);
    let mut released = Vec::new();
    let mut kept = 0;
    for directory in children(&root.join("domains").join(&domain).join("generations"))? {
        let path = directory.join("manifest.json");
        pool_path(root, &path)?;
        if !path.try_exists()? {
            continue;
        }
        let manifest: Value = read(&path)?;
        if !records::committed(root, &manifest)? {
            continue;
        }
        let generation = number(&manifest, "generation")?;
        ensure!(
            manifest["domain"] == domain
                && path == records::manifest_path(root, &domain, generation)?,
            "build admission generation differs"
        );
        let pin = Pin::classify(
            manifest["retention"]["retain"]
                .as_bool()
                .context("missing build retention")?,
            manifest["retention"].get("updated_at").is_some(),
        );
        if let Some(request) = protected.release(
            Candidate {
                generation: Generation {
                    domain: domain.clone(),
                    number: generation,
                },
                system: text(&manifest, "system")?,
            },
            pin,
        ) {
            generations::retention(root, request.domain(), request.generation(), false)?;
            released.push(generation);
        } else {
            kept += 1;
        }
    }
    Ok(json!({"released_admission_generations":released,"kept_admission_generations":kept}))
}

/// Report logical NAR footprint separately from the pool's physical segment accounting.
/// These observations never authorize collection or change an attached builder base.
pub(super) fn summary(root: &Path) -> Result<Value> {
    let mut roles = json!({});
    let mut unique = BTreeMap::new();
    let mut logical_objects = 0u64;
    for role in ["sys-ctrl", "usr-assistant"] {
        let path = root.join("builders").join(format!("{role}.json"));
        if !path.try_exists()? {
            continue;
        }
        pool_path(root, &path)?;
        let descriptor: Value = read(&path)?;
        let domain = format!("{role}-build-store");
        let generation = number(&descriptor, "generation")?;
        let manifest = records::generation(root, &domain, generation)?;
        ensure!(
            manifest["builder"] == descriptor,
            "builder status descriptor differs"
        );
        let directory = records::manifest_path(root, &domain, generation)?;
        let registration = directory
            .parent()
            .context("missing builder directory")?
            .join("registration");
        pool_path(root, &registration)?;
        ensure!(
            descriptor["registration_sha256"] == hash(&registration)?,
            "builder registration changed"
        );
        let entries = builder::registration(&fs::read_to_string(&registration)?)?;
        let nar_bytes = entries.values().try_fold(0u64, |sum, entry| {
            sum.checked_add(entry.nar_size())
                .context("builder NAR accounting overflow")
        })?;
        logical_objects = logical_objects
            .checked_add(entries.len() as u64)
            .context("builder object accounting overflow")?;
        for (path, entry) in &entries {
            if let Some(previous) = unique.insert(path.clone(), entry.nar_size()) {
                ensure!(
                    previous == entry.nar_size(),
                    "conflicting shared builder metadata"
                );
            }
        }
        let mut seed = manifest["build_seed"].clone();
        if let Some(inputs) = seed.get_mut("inputs").and_then(Value::as_object_mut) {
            let roots = inputs.remove("roots");
            inputs.insert(
                "root_count".into(),
                json!(roots.and_then(|roots| roots.as_array().map(Vec::len))),
            );
        }
        roles[role] = json!({"generation":generation,"object_count":entries.len(),"nar_bytes":nar_bytes,
            "registration_sha256":descriptor["registration_sha256"],"image_seed":seed,
            "retention":"current base and persistent private-overlay dependencies; predecessor views until stopped handoff"});
    }
    let bytes = unique.values().try_fold(0u64, |sum, size| {
        sum.checked_add(*size)
            .context("shared builder NAR accounting overflow")
    })?;
    Ok(
        json!({"roles":roles,"unique_objects":unique.len(),"unique_nar_bytes":bytes,
        "shared_object_references":logical_objects.saturating_sub(unique.len() as u64),
        "physical_accounting":"shared pool segment and allocated-byte totals; NAR bytes are logical"}),
    )
}

/// Reuse only a committed publication whose exact admission and current builder
/// descriptors still exist. Machine exclusion precedes this pool lock. Missing
/// or superseded evidence is a cache miss; corrupt retained evidence is an error.
/// Filesystem reads and checksum validation remain trusted storage adapters;
/// fresh source authorization is required by the coordinator before this call.
pub(crate) fn completed(
    request: &airlock_nix_core::build_cache::Request,
    receipt: &Value,
) -> Result<bool> {
    completed_at(Path::new(super::host::POOL), request, receipt)
}

/// The same storage check with an explicit physical pool for offline validation.
pub(super) fn completed_at(
    root: &Path,
    request: &airlock_nix_core::build_cache::Request,
    receipt: &Value,
) -> Result<bool> {
    let _lock = PoolLock::acquire(&root.join("admission.lock"))?;
    let admitted: super::AdmissionReceipt = serde_json::from_value(receipt.clone())?;
    admitted.check_transfer(
        &DOMAIN.parse()?,
        &airlock_nix_core::identity::SourceIdentity {
            revision: request.revision.clone(),
            lock_hash: request.lock_hash.clone(),
        },
    )?;
    ensure!(
        admitted.system == request.derivation,
        "publication result differs from its recipe"
    );
    let namespace = super::runtime_namespace(DOMAIN);
    let path = records::manifest_path(root, &namespace, admitted.generation.get())?;
    ensure!(
        path == admitted.manifest,
        "publication manifest identity differs"
    );
    if !path.try_exists()? {
        return Ok(false);
    }
    let manifest = records::generation(root, &namespace, admitted.generation.get())?;
    ensure!(
        manifest["system"] == json!(request.derivation)
            && receipt["build_publication"]["schema"] == airlock_nix_core::build_cache::SCHEMA
            && receipt["build_publication"]["request_hash"] == json!(request.fingerprint()?)
            && receipt["build_publication"]["result"] == json!(request.result)
            && receipt["build_publication"]["publication"] == "complete"
            && receipt["build_publication"]["admission"] == "complete",
        "committed publication binding differs"
    );
    request.check_registration(&fs::read_to_string(
        path.parent()
            .context("missing publication directory")?
            .join("registration"),
    )?)?;
    super::views::attachment_map(root, &manifest["store"])?;
    for role in ["sys-ctrl", "usr-assistant"] {
        let descriptor = root.join("builders").join(format!("{role}.json"));
        if !descriptor.try_exists()? {
            return Ok(false);
        }
        let current: Value = read(&descriptor)?;
        if current != receipt["build_publication"]["views"][role] {
            return Ok(false);
        }
        // Older descriptors have no immutable image digest; retain their normal
        // publication path rather than claiming a freshly checked cache hit.
        let Some(digest) = current["metadata_image_sha256"].as_str() else {
            return Ok(false);
        };
        let image = std::path::PathBuf::from(text(&current, "metadata_image")?);
        pool_path(root, &image)?;
        ensure!(hash(&image)? == digest, "builder metadata checksum differs");
        let domain = format!("{role}-build-store");
        let generation = number(&current, "generation")?;
        let builder = records::generation(root, &domain, generation)?;
        let registration = records::manifest_path(root, &domain, generation)?
            .parent()
            .context("missing builder directory")?
            .join("registration");
        ensure!(
            json!(hash(&registration)?) == current["registration_sha256"],
            "builder registration checksum differs"
        );
        super::views::attachment_map(root, &builder["store"])?;
        super::builder::volume_configs(root, root, "airlock", role)?;
    }
    Ok(true)
}
