//! Admission commits a verified software view before making it selectable.
//! Retention and retirement are separate from selection so rollback and running guests stay safe.

use super::{
    GenerationMatch, GenerationMatchOutcome, GenerationMatchSchema, fs::*, records, root, segments,
    views,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{fs, path::Path, time::Instant};

/// Inputs fixed by the caller before a new immutable generation is admitted.
pub(super) struct Admission<'a> {
    /// Pool being mutated while the caller holds its admission lock.
    pub(super) pool: &'a Path,
    /// VM or builder whose generation namespace receives the view.
    pub(super) domain: &'a str,
    /// Logical NixOS system included in the frozen closure.
    pub(super) system: &'a str,
    /// Closure metadata or a newline-delimited list of complete Nix store roots.
    pub(super) source: &'a Path,
    /// Logical source identity retained in the generation manifest.
    pub(super) source_identity: &'a str,
    /// Optional immutable guest boot disk source.
    pub(super) root_source: &'a str,
    /// Qubes kernel selection associated with the boot disk.
    pub(super) kernel: &'a str,
    /// Physical directory supplying package bytes during local admission.
    pub(super) physical: &'a Path,
    /// Maximum ordinary segment size before rollover.
    pub(super) segment_target: u64,
    /// Verification policy selected before publication.
    pub(super) verification: &'a str,
    /// Authenticated entity whose approval authorizes this admission.
    pub(super) approved_by: &'a str,
    /// Review or source record explaining the approval.
    pub(super) approval_source: &'a str,
    /// Whether to replace this domain's current selection after commit.
    pub(super) activate: bool,
    /// Whether maintenance must retain the generation independently of selection.
    pub(super) retain: bool,
    /// Authenticated predecessor index for an additive builder transition.
    pub(super) previous_index: Option<&'a Value>,
    /// Guest-visible metadata block device.
    pub(super) device: &'a str,
    /// Guest-visible external package-data block device.
    pub(super) blob_device: &'a str,
    /// Guest filesystem location served by the immutable view.
    pub(super) mountpoint: &'a str,
}

/// Pool namespaces include dom0 and administrative names, not just guest runtime stores.
/// Component validation prevents path traversal; guest attachment requires its stricter type.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(transparent)]
pub(super) struct PoolNamespace {
    /// Validated single path component addressed by the admission operation.
    name: String,
}

impl PoolNamespace {
    /// Preserve the requested namespace after the same path check used by pool operations.
    fn new(name: &str) -> Result<Self> {
        component(name)?;
        Ok(Self { name: name.into() })
    }
}

/// Admission has the same receipt fields for host and guest storage namespaces.
pub(super) type AdmittedGeneration = crate::model::GenerationReceipt<PoolNamespace>;

/// Guest installation cannot consume host or arbitrary administrative admission namespaces.
pub(super) fn guest_receipt(
    receipt: AdmittedGeneration,
) -> Result<crate::model::GenerationReceipt> {
    Ok(crate::model::GenerationReceipt {
        domain: receipt.domain.name.parse()?,
        schema: receipt.schema,
        identity: receipt.identity,
        manifest: receipt.manifest,
        metadata_image: receipt.metadata_image,
        blob_map: receipt.blob_map,
        blob_logical_size: receipt.blob_logical_size,
        closure_hash: receipt.closure_hash,
        approval_source: receipt.approval_source,
        view_image: receipt.view_image,
        image: receipt.image,
        blob_volume: receipt.blob_volume,
        view_created: receipt.view_created,
        diagnostics: receipt.diagnostics,
    })
}

fn verification(paths: &[String], mode: &str, recursive: bool) -> Result<Value> {
    if paths.is_empty() {
        return Ok(json!({"mode":mode,"status":"passed","reason":"no new objects"}));
    }
    match mode {
        "none" => {
            return Ok(json!({"mode":mode,"status":"skipped","reason":"verification disabled"}));
        }
        "tree" => {
            return Ok(
                json!({"mode":mode,"status":"passed","reason":"deterministic tree hashes computed during admission"}),
            );
        }
        "nix-store" | "nix-store-trust" => {}
        _ => anyhow::bail!("unsupported verification mode"),
    }
    failpoint("verification-before-command")?;
    let mut args = vec![
        "--extra-experimental-features",
        "nix-command",
        "store",
        "verify",
    ];
    if recursive {
        args.push("--recursive");
    }
    if mode == "nix-store" {
        args.push("--no-trust");
    }
    args.extend(paths.iter().map(String::as_str));
    let stdout = command("nix", &args, None)?;
    failpoint("verification-after-command")?;
    Ok(json!({
        "mode": mode,
        "status": "passed",
        "command": std::iter::once("nix").chain(args).collect::<Vec<_>>(),
        "stdout": stdout,
        "stderr": "",
    }))
}

pub(super) fn admit(args: &Admission<'_>) -> Result<AdmittedGeneration> {
    let started = Instant::now();
    let root = args.pool;
    let namespace = PoolNamespace::new(args.domain)?;
    entry(args.system)?;

    let artifact = if args.root_source.is_empty() {
        None
    } else {
        Some(root::admit(
            root,
            Path::new(args.root_source),
            args.physical,
        )?)
    };

    let generation = records::next(root, args.domain)?;
    let previous = records::current(root, args.domain)?;
    let transaction = transaction(&format!("{}:{generation}:{}", args.domain, args.system))?;
    let tx_path = root
        .join("transactions")
        .join(format!("{transaction}.json"));
    let manifest_path = records::manifest_path(root, args.domain, generation)?;
    let generation_dir = manifest_path
        .parent()
        .context("missing generation parent")?;
    mkdir_all(
        generation_dir
            .parent()
            .context("missing generations directory")?,
    )?;
    mkdir(generation_dir)?;
    write(
        &tx_path,
        &json!({"schema":"airlock.closure-store.transaction.v1","id":transaction,"domain":args.domain,"generation":generation,"status":"preparing","created_at":now()}),
        0o644,
    )?;
    failpoint("admit-after-tx-create")?;

    let paths = store_paths(args.source, args.system)?;
    let mut cached = std::collections::BTreeMap::new();
    if args.verification == "incremental" {
        for path in &paths {
            if let Some(value) = segments::reusable(root, path)? {
                cached.insert(path.clone(), value);
            }
        }
    }

    let mut verified = super::progress::phase(
        &format!("{domain}: verifying objects", domain = args.domain),
        || {
            Ok(if args.verification == "incremental" {
                let additions: Vec<_> = paths
                    .iter()
                    .filter(|path| !cached.contains_key(*path))
                    .cloned()
                    .collect();
                let mut result = verification(&additions, "nix-store", false)?;
                result["mode"] = json!("incremental");
                result["verified_objects"] = json!(additions.len());
                result["reused_objects"] = json!(cached.len());
                result
            } else {
                verification(&[args.system.to_owned()], args.verification, true)?
            })
        },
    )?;
    let verification_seconds = started.elapsed().as_secs_f64();

    let started = Instant::now();
    let (admitted, reused) = super::progress::phase(
        &format!("{domain}: admitting objects", domain = args.domain),
        || {
            let mut admitted = Vec::new();
            let mut reused = Vec::new();

            for (index, path) in paths.iter().enumerate() {
                super::progress::detail(&format!(
                    "{index}/{total} objects, {added} added, {reused} reused | {path}",
                    total = paths.len(),
                    added = admitted.len(),
                    reused = reused.len()
                ));
                let value = match cached.get(path) {
                    Some(value) => value.clone(),
                    None => segments::admit(
                        root,
                        path,
                        args.physical,
                        &transaction,
                        args.segment_target,
                    )?,
                };
                if value["admitted"] == true {
                    admitted.push(value);
                } else {
                    reused.push(value);
                }
            }

            super::progress::detail(&format!(
                "{total}/{total} objects, {added} added, {reused} reused",
                total = paths.len(),
                added = admitted.len(),
                reused = reused.len()
            ));
            Ok((admitted, reused))
        },
    )?;
    let admission_seconds = started.elapsed().as_secs_f64();

    let closure = closure_hash(&paths, args.system, args.root_source, args.kernel);

    let started = Instant::now();
    let mut store = super::progress::phase(
        &format!("{domain}: preparing storage index", domain = args.domain),
        || {
            views::materialize(views::ViewRequest {
                root,
                generation_dir,
                paths: &paths,
                closure: &closure,
                transaction: &transaction,
                target: args.segment_target,
                trusted: &cached.keys().cloned().collect(),
                previous: args.previous_index,
            })
        },
    )?;
    let mut timings = store["preparation"].clone();
    let view_created = store["image_created"].clone();
    store
        .as_object_mut()
        .context("invalid view record")?
        .remove("preparation");
    store
        .as_object_mut()
        .context("invalid view record")?
        .remove("image_created");
    timings["object_verification_seconds"] = json!(verification_seconds);
    timings["object_admission_seconds"] = json!(admission_seconds);
    timings["view_preparation_seconds"] = json!(started.elapsed().as_secs_f64());
    store["mode"] = json!("shared-closure");
    store["closure_hash"] = json!(closure);
    store["source"] = json!(args.source_identity);
    store["mountpoint"] = json!(args.mountpoint);
    store["device"] = json!(args.device);
    store["blob_device"] = json!(args.blob_device);
    store["read_only"] = json!(true);
    store["paths"] = json!(paths);
    store["object_count"] = json!(paths.len());
    store["segment_target_bytes"] = json!(args.segment_target);

    let mut manifest = json!({
        "schema": GENERATION_SCHEMA,
        "status": "prepared",
        "domain": args.domain,
        "generation": generation,
        "previous_generation": previous,
        "created_at": now(),
        "transaction": transaction,
        "approval": {"approved_by":args.approved_by,"source":args.approval_source},
        "system": args.system,
        "root": {"source":args.root_source,"artifact":artifact},
        "kernel": {"name":args.kernel},
        "store": store,
        "verification": verified,
        "retention": {"retain":args.retain},
    });
    failpoint("generation-before-manifest")?;
    write(&manifest_path, &manifest, 0o644)?;
    failpoint("generation-after-manifest")?;
    write(
        &tx_path,
        &json!({
            "schema": "airlock.closure-store.transaction.v1",
            "id": transaction,
            "domain": args.domain,
            "generation": generation,
            "status": "committed",
            "activated": args.activate,
            "committed_at": now(),
            "manifest": manifest_path,
        }),
        0o644,
    )?;
    failpoint("generation-after-tx-commit")?;

    manifest["status"] = json!("committed");
    write(&manifest_path, &manifest, 0o644)?;
    failpoint("generation-after-manifest-commit")?;
    if args.activate {
        records::select(root, args.domain, generation)?;
    }

    // Keep extension diagnostics at the wire edge; authoritative fields are constructed directly.
    let mut diagnostics = store.as_object().context("invalid store record")?.clone();
    for key in [
        "schema",
        "domain",
        "manifest",
        "approval_source",
        "view_image",
        "view_created",
        "generation",
        "system",
        "root_source",
        "source",
        "kernel_name",
        "mode",
        "device",
        "blob_device",
        "mountpoint",
        "view_backend",
        "metadata_image",
        "blob_map",
        "blob_logical_size",
        "closure_hash",
        "image",
        "blob_volume",
    ] {
        diagnostics.remove(key);
    }
    for (key, value) in json!({
        "status": "passed", "timings": timings, "pool_root": root,
        "previous_generation": previous,
        "current_generation": records::current(root, args.domain)?,
        "activated": args.activate, "retained": args.retain,
        "root_artifact": artifact, "verification": verified.take(), "store": store,
        "objects_total": paths.len(), "objects_admitted": admitted.len(),
        "objects_reused": reused.len(), "admitted": admitted, "reused": reused,
        "canonical_view_image": store["canonical_image"],
        "view_size": fs::metadata(Path::new(&text(&store, "canonical_image")?))?.len(),
    })
    .as_object()
    .context("invalid admission diagnostics")?
    {
        diagnostics.insert(key.clone(), value.clone());
    }

    Ok(crate::model::GenerationReceipt {
        schema: Some(airlock_nix_core::admission::GenerationReceiptSchema::Admission),
        domain: namespace,
        identity: crate::model::StorageIdentity {
            generation: generation.try_into()?,
            system: args.system.into(),
            root_source: args.root_source.into(),
            source: args.source_identity.into(),
            kernel_name: args.kernel.into(),
            mode: crate::model::StoreMode::SharedClosure,
            device: args.device.into(),
            blob_device: args.blob_device.into(),
            mountpoint: args.mountpoint.into(),
            view_backend: text(&store, "view_backend")?,
        },
        manifest: manifest_path,
        metadata_image: text(&store, "metadata_image")?.into(),
        blob_map: text(&store, "blob_map")?.into(),
        blob_logical_size: number(&store, "blob_logical_size")?,
        closure_hash: closure,
        approval_source: None,
        view_image: Some(text(&store, "image")?),
        image: store["image"].as_str().map(str::to_owned),
        blob_volume: store["blob_volume"].as_str().map(str::to_owned),
        view_created: view_created
            .as_bool()
            .context("invalid view-created result")?,
        diagnostics: diagnostics.into_iter().collect(),
    })
}

pub(super) fn describe(root: &Path, domain: &str, generation: u64) -> Result<Value> {
    let manifest = records::generation(root, domain, generation)?;
    records::root_image(root, &manifest)?;
    let selected = records::current(root, domain)?;

    let mut store = json!({});
    for key in [
        "mode",
        "mountpoint",
        "device",
        "blob_device",
        "view_backend",
        "closure_hash",
    ] {
        store[key] = manifest["store"][key].clone();
    }
    Ok(json!({
        "schema": "airlock.closure-store.generation-info.v1",
        "status": "passed",
        "domain": domain,
        "generation": generation,
        "current_generation": selected,
        "selected": selected == Some(generation),
        "manifest": records::manifest_path(root,domain,generation)?,
        "system": manifest["system"],
        "root_source": manifest["root"]["source"],
        "root_artifact": manifest["root"]["artifact"],
        "kernel_name": manifest["kernel"]["name"],
        "closure_source": manifest["store"]["source"],
        "store": store,
        "approval": manifest["approval"],
        "provenance": manifest.get("provenance").cloned().unwrap_or(json!({})),
        "verification": manifest["verification"],
        "retention": manifest["retention"],
    }))
}

pub(super) fn switch(root: &Path, domain: &str, generation: u64, rollback: bool) -> Result<Value> {
    let manifest = records::generation(root, domain, generation)?;
    records::root_image(root, &manifest)?;
    let previous = records::current(root, domain)?;

    records::select(root, domain, generation)?;

    let mut result = manifest["store"].clone();
    for (key, value) in json!({
        "schema": if rollback { "airlock.closure-store.rollback.v1" } else { "airlock.closure-store.switch.v1" },
        "status": "passed",
        "pool_root": root,
        "domain": domain,
        "previous_generation": previous,
        "current_generation": generation,
        "manifest": records::manifest_path(root,domain,generation)?,
        "system": manifest["system"],
        "root_source": manifest["root"]["source"],
        "kernel_name": manifest["kernel"]["name"],
        "store": manifest["store"],
        "view_image": manifest["store"]["image"],
        "canonical_view_image": manifest["store"]["canonical_image"],
    }).as_object().context("invalid switch result")? {
        result[key] = value.clone();
    }
    Ok(result)
}

/// Recheck manual retention under the pool lock; an uncertain retry never overwrites it.
pub(super) fn release_automatic(
    root: &Path,
    domain: &str,
    generation: u64,
    references: Vec<airlock_deployment_core::retention::Protection>,
) -> Result<Value> {
    use airlock_deployment_core::retention::{Candidate, Generation, Pin, ProtectedGenerations};
    let manifest = records::generation(root, domain, generation)?;
    let retain = manifest["retention"]["retain"]
        .as_bool()
        .context("invalid retention pin")?;
    let pin = Pin::classify(retain, manifest["retention"].get("updated_at").is_some());
    let protection = ProtectedGenerations::new(references).context("invalid protection set")?;
    let request = protection.release(
        Candidate {
            generation: Generation {
                domain: domain.to_owned(),
                number: generation,
            },
            system: text(&manifest, "system")?,
        },
        pin,
    );
    match request {
        Some(request) => retention(root, request.domain(), request.generation(), false),
        None => Ok(json!({"status":"unchanged", "domain":domain, "generation":generation})),
    }
}

pub(super) fn retention(root: &Path, domain: &str, generation: u64, retain: bool) -> Result<Value> {
    let path = records::manifest_path(root, domain, generation)?;
    let mut manifest = records::generation(root, domain, generation)?;
    let previous = manifest["retention"]["retain"] == true;
    manifest["retention"]["retain"] = json!(retain);
    manifest["retention"]["updated_at"] = json!(now());
    write(&path, &manifest, 0o644)?;
    Ok(json!({
        "schema": "airlock.closure-store.retention.v1",
        "status": "passed",
        "pool_root": root,
        "domain": domain,
        "generation": generation,
        "previous_retain": previous,
        "retain": retain,
        "manifest": path,
    }))
}

pub(super) fn retire(root: &Path, domain: &str, generation: u64) -> Result<Value> {
    let path = records::manifest_path(root, domain, generation)?;
    let receipt = root
        .join("domains")
        .join(component(domain)?)
        .join("retired-generations")
        .join(format!("{generation}.json"));
    let prior: Option<Value> = if receipt.try_exists()? {
        Some(read(&receipt)?)
    } else {
        None
    };
    let current = records::current(root, domain)?;
    ensure!(
        !records::running_refs(root)?
            .iter()
            .any(|(_, value)| value["domain"] == domain && value["generation"] == generation),
        "generation still has running references"
    );
    if !path.try_exists()? {
        let mut prior = prior.context("generation missing without retirement receipt")?;
        ensure!(current.is_none(), "another generation is selected");
        prior["status"] = json!("retired");
        write(&receipt, &prior, 0o644)?;
        return Ok(prior);
    }
    let mut manifest = records::generation(root, domain, generation)?;
    ensure!(
        current == Some(generation)
            || (current.is_none()
                && (manifest["retention"]["retain"] != true
                    || prior.as_ref().is_some_and(|v| v["status"] == "retiring"))),
        "generation is not current"
    );
    let mut result = json!({"schema":"airlock.closure-store.generation-retirement.v1","status":"retiring","pool_root":root,"domain":domain,"generation":generation,"manifest":path});
    write(&receipt, &result, 0o644)?;
    manifest["retention"]["retain"] = json!(false);
    manifest["retention"]["updated_at"] = json!(now());
    manifest["retention"]["retired_at"] = json!(now());
    write(&path, &manifest, 0o644)?;
    if current == Some(generation) {
        let link = root.join("domains").join(domain).join("current");
        remove(&link)?;
        sync_dir(link.parent().context("missing selection parent")?)?;
    }
    result["status"] = json!("retired");
    write(&receipt, &result, 0o644)?;
    Ok(result)
}

pub(super) fn find(
    root: &Path,
    domain: &str,
    system: &str,
    source: &str,
    root_source: &str,
    kernel: &str,
    approved_by: &str,
) -> Result<GenerationMatch> {
    let mut matches = Vec::new();
    for path in records::manifests(root)? {
        let manifest: Value = read(&path)?;
        if records::committed(root, &manifest)?
            && manifest["domain"] == domain
            && manifest["system"] == system
            && manifest["root"]["source"] == root_source
            && manifest["kernel"]["name"] == kernel
            && manifest["store"]["source"] == source
            && manifest["approval"]["approved_by"] == approved_by
        {
            matches.push((number(&manifest, "generation")?, path, manifest));
        }
    }
    matches.sort_by_key(|(generation, _, _)| *generation);
    let namespace = domain.parse()?;
    let Some((generation, path, manifest)) = matches.pop() else {
        return Ok(GenerationMatch {
            schema: GenerationMatchSchema::V1,
            domain: namespace,
            outcome: GenerationMatchOutcome::Missing,
        });
    };
    records::root_image(root, &manifest)?;
    views::verify(root, &manifest["store"])?;
    Ok(GenerationMatch {
        schema: GenerationMatchSchema::V1,
        domain: namespace,
        outcome: GenerationMatchOutcome::Found {
            generation: generation.to_string().parse()?,
            manifest: path,
            closure_hash: text(&manifest["store"], "closure_hash")?.parse()?,
        },
    })
}

pub(super) fn resolve_root(
    root: &Path,
    domain: &str,
    source: &str,
    generation: Option<u64>,
) -> Result<super::ResolvedRoot> {
    let mut matches = std::collections::BTreeMap::new();
    for path in records::manifests(root)? {
        let manifest: Value = read(&path)?;
        if manifest["domain"] != domain
            || manifest["root"]["source"] != source
            || generation.is_some_and(|g| manifest["generation"] != g)
            || !records::committed(root, &manifest)?
        {
            continue;
        }
        let image = records::root_image(root, &manifest)?.context("generation has no root")?;
        matches.insert(image, manifest["root"]["artifact"].clone());
    }
    ensure!(
        matches.len() == 1,
        "root source has no unique verified artifact for domain"
    );
    let (image, descriptor) = matches
        .into_iter()
        .next()
        .context("missing root identity")?;
    let artifact: airlock_nix_core::artifact::RootDescriptor = serde_json::from_value(descriptor)?;
    artifact.validate()?;
    Ok(super::ResolvedRoot {
        image,
        artifact,
        domain: domain.parse()?,
        root_source: source.into(),
    })
}

pub(super) fn load(
    root: &Path,
    logical: &Path,
    domain: &str,
    generation: u64,
) -> Result<crate::model::GenerationReceipt> {
    let manifest = records::generation(root, domain, generation)?;
    let root_image = records::root_image(root, &manifest)?;
    let store = &manifest["store"];
    let metadata = text(store, "metadata_image")?;
    let physical = root.join(Path::new(&metadata).strip_prefix(logical)?);
    let mut value = store.clone();
    for (key, field) in json!({
        "domain": domain,
        "generation": generation,
        "previous_generation": manifest["previous_generation"],
        "closure_hash": store["closure_hash"],
        "manifest": records::manifest_path(logical,domain,generation)?,
        "system": manifest["system"],
        "root_source": manifest["root"]["source"],
        "root_artifact": manifest["root"]["artifact"],
        "root_image": root_image,
        "kernel_name": manifest["kernel"]["name"],
        "source": store["source"],
        "approval_source": manifest["approval"]["source"],
        "view_created": false,
        "view_image": store["metadata_image"],
        "canonical_view_image": store["canonical_metadata_image"],
        "metadata_image": store["metadata_image"],
        "canonical_metadata_image": store["canonical_metadata_image"],
        "view_size": fs::metadata(&physical)?.len(),
        "objects_total": store["object_count"],
        "objects_admitted": 0,
        "objects_reused": store["object_count"],
    })
    .as_object()
    .context("invalid generation receipt")?
    {
        value[key] = field.clone();
    }
    Ok(serde_json::from_value(value)?)
}
