//! Airlock's immutable-volume rules behind Qubes' pool and volume callbacks.
//! Device attachment and running references share the storage engine's admission lock.

use super::{
    fs::{PoolLock, component, ensure_pool},
    qubes_inspect::{Definition, absolute, verify},
    records, views,
};
use crate::storage_plugin::{
    GenerationIdentity, LifecycleRequest, Metadata, NormalizationInput, Normalized,
};
use airlock_deployment_core::volume_lifecycle::{
    Action, Effect, ImmutableOptions, LifecyclePlan, admission_lock,
};
use airlock_nix_core::identity::GuestName;
use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
};

/// Normalize primitive Qubes configuration before constructing an upstream volume.
pub(super) fn normalize(
    domain: Option<&GuestName>,
    config: Value,
    has_source: bool,
) -> Result<Value> {
    let mut config = config
        .as_object()
        .context("invalid Qubes volume configuration")?
        .clone();
    let flag = |key: &str| -> Result<bool> {
        match config.get(key) {
            None => Ok(false),
            Some(Value::Bool(value)) => Ok(*value),
            _ => bail!("immutable volume flag must be boolean: {key}"),
        }
    };
    let writable = flag("rw")?;
    let snapshot = flag("snap_on_start")?;
    config.entry("view_kind").or_insert(json!("metadata-image"));
    if let Some(Value::String(size)) = config.get("blob_logical_size") {
        let size: std::num::NonZeroU64 = size.parse()?;
        config.insert("blob_logical_size".into(), json!(size.get()));
    }
    let metadata: Metadata = serde_json::from_value(Value::Object(config.clone()))?;
    let result = normalize_typed(NormalizationInput {
        domain: domain.cloned(),
        name: config
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("store")
            .into(),
        vid_supplied: config.contains_key("vid"),
        writable,
        snapshot,
        has_source,
        metadata,
    })?;
    config.insert("rw".into(), json!(result.options.writable()));
    config.insert("snap_on_start".into(), json!(result.options.snapshot()));
    config.insert("save_on_stop".into(), json!(result.options.persistent()));
    if let Some(vid) = result.generated_vid {
        config.insert("vid".into(), json!(vid));
    }
    let fields = serde_json::to_value(result.metadata)?;
    for key in fields.as_object().expect("metadata fields").keys() {
        config.remove(key);
    }
    let persisted = fields
        .as_object()
        .expect("metadata fields")
        .iter()
        .filter(|(_, value)| !value.is_null())
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<serde_json::Map<_, _>>();
    Ok(json!({"config":config,"fields":fields,"persisted":persisted}))
}

/// Normalize only Airlock-owned fields; upstream kwargs never enter this typed engine interface.
pub(crate) fn normalize_typed(mut input: NormalizationInput) -> Result<Normalized> {
    let options = ImmutableOptions::check(
        input.metadata.definition.view_kind,
        input.writable,
        input.snapshot,
        input.has_source,
    )
    .context("airlock-closure volumes are read-only, without snapshots or source volumes")?;
    if let Some(domain) = &input.metadata.domain_name {
        component(domain)?;
    }
    let generated_vid = if !input.vid_supplied {
        let domain = input
            .domain
            .context("volume identifier requires its Qubes VM")?;
        let generation = input
            .metadata
            .generation
            .context("airlock-closure volume requires generation")?;
        component(&input.name)?;
        let fallback = if matches!(input.name.as_str(), "builder-store" | "builder-data") {
            format!("{domain}-build-store")
        } else {
            super::runtime_namespace(domain.as_str())
        };
        let namespace = input.metadata.domain_name.get_or_insert(fallback);
        Some(format!(
            "domains/{namespace}/generations/{generation}/{name}",
            name = input.name
        ))
    } else {
        None
    };
    for path in [
        &mut input.metadata.definition.view_path,
        &mut input.metadata.definition.blob_map_path,
        &mut input.metadata.definition.manifest_path,
    ] {
        *path = match path.as_ref().filter(|path| !path.as_os_str().is_empty()) {
            Some(value) => {
                let value = std::path::absolute(value)?;
                absolute(&value)?;
                Some(value)
            }
            None => None,
        };
    }
    let path = input
        .metadata
        .definition
        .view_path
        .take()
        .map(|path| {
            path.into_os_string()
                .into_string()
                .map_err(|_| anyhow::anyhow!("non-UTF-8 volume path"))
        })
        .transpose()?;
    input.metadata.definition.view_path = options.persisted_path(path).map(PathBuf::from);
    Ok(Normalized {
        generated_vid,
        metadata: input.metadata,
        options,
    })
}

/// Serialized compatibility lifecycle input; decoded once before invoking the typed engine.
#[derive(Deserialize)]
pub(super) struct Request {
    // Closed action spelling parsed by verified Rust below.
    action: String,
    // Existing pool admission-lock namespace.
    root: PathBuf,
    // Namespace and generation are used together; incomplete legacy metadata has no retained identity.
    domain: Option<String>,
    // Decimal wire generation, converted to a positive numeric identity.
    generation: Option<String>,
    // Independent running-reference key.
    name: String,
    // Existing serialized immutable-view metadata.
    #[serde(flatten)]
    definition: Definition,
}

/// Validate a filtered mapper returned by the engine before exposing it to Qubes.
fn attached_device(value: Value) -> Result<PathBuf> {
    filtered_device(value, |path| fs::canonicalize(path))
}

/// Check the mapper namespace and resolved backing aliases with one filesystem resolver.
fn filtered_device(
    value: Value,
    resolve: impl Fn(&Path) -> std::io::Result<PathBuf>,
) -> Result<PathBuf> {
    let device = PathBuf::from(
        value["device"]
            .as_str()
            .context("blob-map attach returned no device")?,
    );
    ensure!(
        device.starts_with("/dev/mapper")
            && device.parent() == Some(std::path::Path::new("/dev/mapper")),
        "blob-map attach returned an unfiltered device"
    );
    let resolved = resolve(&device)?;
    for backing in value["backing_paths"]
        .as_array()
        .context("missing blob backing paths")?
    {
        let backing = backing.as_str().context("invalid blob backing path")?;
        ensure!(
            resolved != resolve(Path::new(backing))?,
            "refusing to expose global Airlock backing storage to a VM"
        );
    }
    Ok(device)
}

/// Preserve the serialized CLI while native callbacks use the typed entry point directly.
pub(super) fn execute(request: Request) -> Result<Value> {
    let action = Action::parse(&request.action).context("unsupported volume lifecycle action")?;
    if matches!(action, Action::Immutable) {
        bail!("airlock-closure volumes are immutable");
    }
    let identity = request
        .domain
        .zip(request.generation)
        .map(|(domain, generation)| -> Result<_> {
            Ok(GenerationIdentity {
                domain,
                generation: generation.parse()?,
            })
        })
        .transpose()?;
    Ok(json!({"path":execute_typed(LifecycleRequest {
        action, root: request.root, identity, name: request.name, definition: request.definition,
    })?, "valid":true}))
}

/// Execute only the verified callback effects while holding their required admission lock.
pub(crate) fn execute_typed(mut request: LifecycleRequest) -> Result<Option<PathBuf>> {
    if matches!(request.action, Action::Immutable) {
        bail!("airlock-closure volumes are immutable");
    }
    absolute(&request.root)?;
    component(&request.name)?;
    if let Some(identity) = &request.identity {
        component(&identity.domain)?;
    }
    let guard = if admission_lock(
        request.action,
        request.definition.view_kind,
        request.identity.is_some(),
    ) {
        ensure_pool(&request.root)?;
        Some(PoolLock::acquire(&request.root.join("admission.lock"))?)
    } else {
        None
    };
    // Mapper availability can change while waiting for admission. Observe it only
    // after acquiring the lock, and only for callbacks that reuse existing devices.
    let path_exists = matches!(
        request.definition.view_kind,
        crate::storage_plugin::ViewKind::ErofsBlobMap
    ) && matches!(request.action, Action::Verify | Action::BlockDevice)
        && request
            .definition
            .view_path
            .as_ref()
            .is_some_and(|path| path.exists());
    let plan = LifecyclePlan::select(
        request.action,
        request.definition.view_kind,
        request.identity.is_some(),
        path_exists,
    )
    .context("missing domain/generation for blob-map view")?;
    ensure!(
        !plan.requires_lock() || guard.is_some(),
        "lifecycle admission lock is missing"
    );

    for effect in plan.effects() {
        match effect {
            Effect::Verify => verify(&request.definition)?,
            Effect::Attach => {
                let identity = request
                    .identity
                    .as_ref()
                    .context("missing retained mapper identity")?;
                request.definition.view_path = Some(attached_device(views::attach(
                    &request.root,
                    &identity.domain,
                    identity.generation.get(),
                    true,
                )?)?);
            }
            Effect::Detach => {
                let identity = request
                    .identity
                    .as_ref()
                    .context("missing retained mapper identity")?;
                views::attach(
                    &request.root,
                    &identity.domain,
                    identity.generation.get(),
                    false,
                )?;
                request.definition.view_path = None;
            }
            Effect::Pin | Effect::Unpin => {
                let identity = request
                    .identity
                    .as_ref()
                    .context("missing retained running identity")?;
                records::running(
                    &request.root,
                    &identity.domain,
                    identity.generation.get(),
                    &request.name,
                    matches!(effect, Effect::Pin),
                )?;
            }
        }
    }
    Ok(request.definition.view_path)
}

#[cfg(test)]
mod tests;
