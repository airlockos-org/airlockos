//! The Rust worker owns a separate versioned namespace. Legacy records stay
//! intact and are checked for active work before admitting a new submission.
use super::{Result, now};
use airlock_nix_core::{
    identity::JobId,
    job::JobSnapshot,
    state::{OperationKind, OperationOwner, RecordPermissions, ResourceKey, StateStore},
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
};

pub(super) const LIMIT: u64 = 32 * 1024 * 1024;

pub(super) use super::home;

pub(super) fn root() -> Result<PathBuf> {
    Ok(home()?.join(".local/share/airlock/controller/rust-v1"))
}

pub(super) fn initialize() -> Result<StateStore> {
    let root = root()?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&root)?;
    Ok(StateStore::initialize(&root)?)
}

pub(super) fn owner(name: &str, reason: &str, kind: OperationKind) -> Result<OperationOwner> {
    Ok(OperationOwner::new(
        name.to_owned(),
        reason.to_owned(),
        kind,
    )?)
}

pub(super) fn key(name: &str) -> Result<ResourceKey> {
    Ok(name.parse()?)
}

pub(super) fn save<T: Serialize + DeserializeOwned>(
    store: &StateStore,
    name: &str,
    value: &T,
) -> Result<()> {
    let record = store.record::<T>(key(name)?, LIMIT)?;
    let mut writer = record.try_write(owner(
        "Controller worker",
        "Publish this worker's durable record",
        OperationKind::Review,
    )?)?;

    let before = writer.read()?;
    writer.commit(&before, value, RecordPermissions::Private)?;
    Ok(())
}

pub(super) fn read_owned<T: DeserializeOwned>(name: &str) -> Result<T> {
    Ok(airlock_nix_core::state::read_json(
        &root()?.join("records").join(format!("{name}.json")),
        LIMIT,
    )?)
}

pub(super) fn job_key(id: &JobId) -> String {
    format!("job-{id}")
}

pub(super) fn job(id: &JobId) -> Result<JobSnapshot> {
    let job: JobSnapshot = read_owned(&job_key(id))?;
    super::require(
        job.request_id() == id,
        "job record identity differs from requested ID",
    )?;
    Ok(job)
}

pub(super) fn save_job(store: &StateStore, job: &mut JobSnapshot) -> Result<()> {
    job.set_detail("updated_at", json!(now()));
    save(store, &job_key(job.request_id()), job)
}

pub(super) fn names(prefix: &str) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(root()?.join("records"))? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| super::Error::Message("invalid record filename".into()))?;
        if name.starts_with(prefix) && name.ends_with(".json") {
            names.push(name.trim_end_matches(".json").to_owned());
        }
    }

    names.sort();
    Ok(names)
}

pub(super) fn legacy() -> Result<Vec<(JobId, Value)>> {
    let path = home()?.join(".local/share/airlock/controller/jobs");
    let mut result = Vec::new();
    if !path.exists() {
        return Ok(result);
    }

    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let id: JobId = entry.file_name().to_str().unwrap_or("").parse()?;
        let value = read_legacy(&id, &entry.path().join("status.json"))?;
        result.push((id, value));
    }

    Ok(result)
}

pub(super) fn legacy_job(id: &JobId) -> Result<Value> {
    let mut value = read_legacy(
        id,
        &home()?
            .join(".local/share/airlock/controller/jobs")
            .join(id.as_str())
            .join("status.json"),
    )?;
    super::require(value.is_object(), "invalid legacy job")?;

    value["record_format"] = json!("legacy-python");
    Ok(value)
}

fn read_legacy(id: &JobId, path: &Path) -> Result<Value> {
    let value: Value = airlock_nix_core::state::read_json(path, LIMIT)?;
    super::require(
        value.is_object(),
        "invalid legacy controller job; explicit recovery required",
    )?;

    let status = value.get("status").and_then(Value::as_str).ok_or_else(|| {
        super::Error::Message("legacy job status missing; explicit recovery required".into())
    })?;
    let _: airlock_nix_core::job::JobStatus = status.to_owned().try_into()?;
    super::require(
        value.get("request_id").is_none_or(|v| v == id.as_str()),
        "legacy job identity differs from filename",
    )?;
    Ok(value)
}

pub(super) fn record_path(name: &str) -> Result<PathBuf> {
    let _ = key(name)?;
    Ok(root()?.join("records").join(format!("{name}.json")))
}

pub(super) fn read_file(path: &Path) -> Result<Value> {
    Ok(airlock_nix_core::state::read_json(path, LIMIT)?)
}
