//! Publish only after the original checked build completes. Store identities come from
//! Nix, and dom0 reauthenticates source approval before admitting and publishing them.

use super::*;
use airlock_nix_core::build_cache::{Request, SCHEMA, Tools};

/// Send reusable inputs of this actual result; failure preserves the completed build for retry.
pub(super) fn publish(
    store: &StateStore,
    grant: &Grant,
    lock: &OperationLock,
    result: &StorePath,
) -> Result<Value> {
    grant.check(lock)?;
    let start = Instant::now();
    let tools = Tools {
        nix: "airlock-config-nix",
        nix_store: "airlock-config-nix-store",
    };
    let derivation = tools.deriver(result).map_err(|error| {
        Error::Message(format!(
            "build completed; publication inventory failed: {error:#}"
        ))
    })?;
    let inventory = tools.inventory(&derivation, result).map_err(|error| {
        Error::Message(format!(
            "build completed; publication inventory failed: {error:#}"
        ))
    })?;
    let registration = tools.registration(&inventory.paths).map_err(|error| {
        Error::Message(format!(
            "build completed; Nix registration failed: {error:#}"
        ))
    })?;
    let registration_sha256 = airlock_nix_core::build_cache::registration_hash(&registration)
        .map_err(|error| Error::Message(format!("build registration identity: {error:#}")))?;
    let request = Request {
        schema: SCHEMA.into(),
        review_authorization: grant.id.clone(),
        revision: grant.header.revision.clone(),
        lock_hash: grant.header.lock_hash.clone(),
        target: grant.header.target.clone(),
        result: result.clone(),
        derivation,
        paths: inventory.paths,
        metadata: inventory.metadata,
        registration_sha256,
    };
    request.validate().map_err(|error| {
        Error::Message(format!("build completed; publication refused: {error:#}"))
    })?;
    let fingerprint = request
        .fingerprint()
        .map_err(|error| Error::Message(format!("build publication identity: {error:#}")))?;
    grant.check(lock)?;
    let prepared = progress::phase("preparing_build_publication", || {
        super::send_objects(
            "airlock.Ctrl.BuildPrepare",
            &serde_json::to_value(&request)?,
            &request.metadata,
        )
    })?;
    require(
        prepared["schema"] == SCHEMA
            && prepared["request_hash"] == json!(fingerprint)
            && prepared["admission"] == "prepared"
            && prepared["activated"] == false,
        "build completed; invalid protected build preparation",
    )?;
    grant.check(lock)?;
    let source = airlock_nix_core::artifact::Source {
        domain: airlock_nix_core::build_cache::DOMAIN.into(),
        system: request.derivation.to_string(),
        closure_source: request.derivation.to_string(),
        root_source: String::new(),
        kernel_name: String::new(),
        source_revision: request.revision.to_string(),
        lock_hash: request.lock_hash.to_string(),
        physical_store_root: PathBuf::from("/rw/airlock-builder/merged/nix/store"),
        nix: "airlock-config-nix".into(),
        nix_store: None,
        path_info: None,
    };
    let saved_name = name(grant, "build-publication");
    records::save(
        store,
        &saved_name,
        &json!({"schema":SCHEMA,"request_hash":fingerprint,
        "build":"complete","admission":"prepared","publication":"pending"}),
    )?;
    let transferred = progress::phase("publishing_build_inputs", || {
        source
            .send_build("qrexec-client-vm", &request, &registration)
            .map_err(|error| {
                Error::Message(format!(
                    "build completed; pool publication may be partial: {error:#}"
                ))
            })
    });
    let admission = match transferred {
        Ok(receipt) => receipt,
        Err(error) => {
            records::save(
                store,
                &saved_name,
                &json!({"schema":SCHEMA,"request_hash":fingerprint,
                "build":"complete","admission":"uncertain","publication":"uncertain","error":error.to_string()}),
            )?;
            return Err(error);
        }
    };
    let mut receipt = admission
        .diagnostics
        .get("build_publication")
        .cloned()
        .ok_or_else(|| Error::Message("build completed; publication receipt missing".into()))?;
    require(
        receipt["schema"] == SCHEMA
            && receipt["request_hash"] == json!(fingerprint)
            && receipt["result"] == json!(result)
            && receipt["activated"] == false
            && receipt["build"] == "complete"
            && receipt["admission"] == "complete"
            && receipt["publication"] == "complete"
            && receipt["adoption"] == "next-stopped-start"
            && ["sys-ctrl", "usr-assistant"]
                .iter()
                .all(|role| receipt["views"][*role].is_object()),
        "build completed; invalid build publication receipt",
    )?;
    grant.check(lock)?;
    receipt["objects_total"] = admission
        .diagnostics
        .get("objects_total")
        .cloned()
        .unwrap_or(Value::Null);
    receipt["objects_transferred"] = admission
        .diagnostics
        .get("objects_transferred")
        .cloned()
        .unwrap_or(Value::Null);
    receipt["payload_bytes_transferred"] = admission
        .diagnostics
        .get("payload_bytes_transferred")
        .cloned()
        .unwrap_or(Value::Null);
    receipt["metadata_transfer"] = prepared;
    receipt["elapsed_seconds"] = json!(start.elapsed().as_secs_f64());
    records::save(store, &name(grant, "build-publication"), &receipt)?;
    Ok(receipt)
}
