//! Decode the native boot identity and resolve its explicit or staged generation.

use super::{Session, field, source};
use airlock_deployment_core::storage as verified;
use anyhow::{Result, ensure};
use serde_json::Value;

/// Read-only configuration shared by the ordered reconciliation phases; it grants no authority.
pub(super) struct NativeConfig<'a> {
    /// VM whose existing Qubes backend is being reconciled.
    pub(super) domain: &'a str,
    /// Whole-system source selected for the next boot.
    pub(super) system: &'a str,
    /// Root image source, kept distinct from its resolved local image.
    pub(super) root: &'a str,
    /// Immutable shared-closure source.
    pub(super) store: &'a str,
    /// Qubes kernel identity selected for this VM.
    pub(super) kernel: &'a str,
    /// Optional source bundle used to install or adopt the kernel.
    pub(super) kernel_source: &'a str,
    /// Validated shared-closure storage protocol.
    pub(super) mode: &'a str,
    /// Validated immutable metadata and external-data layout.
    pub(super) view: &'a str,
    /// Guest mountpoint for the shared software store.
    pub(super) mount: &'a str,
    /// Guest block device carrying the metadata image.
    pub(super) device: &'a str,
    /// Guest block device carrying the filtered object data.
    pub(super) blob_device: &'a str,
}

/// Decode supported backend fields without inspecting or mutating VM state.
pub(super) fn decode<'a>(
    domain: &'a str,
    definition: &'a Value,
    checked: Option<&'a airlock_deployment_core::boot::SetupRequest<'_>>,
    default_kernel: &'a str,
) -> Result<NativeConfig<'a>> {
    let backend = &definition["backend"];
    let chosen = checked.map(|request| request.selection());
    let system = match chosen {
        Some(s) => s.system.as_str(),
        None => source(backend, "system")?,
    };
    let root = match chosen {
        Some(s) => s.root.as_str(),
        None => source(backend, "root")?,
    };
    let store = match chosen {
        Some(s) => s.source.as_str(),
        None => source(backend, "store")?,
    };
    let store_config = &backend["store"];
    let mode = field(store_config, "mode", "shared-closure")?;
    let view = field(store_config, "view_backend", "erofs-objectmap")?;
    let mount = field(store_config, "mountpoint", "/nix/store")?;
    let device = field(store_config, "device", "/dev/xvde")?;
    let blob_device = field(store_config, "blob_device", "/dev/xvdf")?;
    ensure!(
        mode == "shared-closure",
        "unsupported Nix-native domain store mode for {domain}: {mode}"
    );
    ensure!(
        view == "erofs-objectmap"
            && mount == "/nix/store"
            && device == "/dev/xvde"
            && blob_device == "/dev/xvdf",
        "unsupported Nix-native store layout for {domain}"
    );
    let declared_kernel = field(&backend["kernel"], "name", "")?;
    let kernel_name = if declared_kernel.is_empty() || declared_kernel == "null" {
        default_kernel
    } else {
        declared_kernel
    };
    let kernel_source = field(&backend["kernel"], "source", "")?;

    let kernel_name = chosen.map_or(kernel_name, |s| s.kernel.as_str());

    Ok(NativeConfig {
        domain,
        system,
        root,
        store,
        kernel: kernel_name,
        kernel_source,
        mode,
        view,
        mount,
        device,
        blob_device,
    })
}

/// Match ambient staging to a checked selection without replacing either identity.
pub(super) fn generation(
    session: &Session,
    domain: &str,
    staged_authority: Option<&verified::staging::StagedBackend<'_>>,
    selected: Option<&airlock_deployment_core::boot::SelectedGeneration>,
) -> Result<Option<String>> {
    let generation = if let Some(staged) = staged_authority {
        staged
            .selected()
            .map(|selected| selected.selection().generation.to_string())
    } else {
        let staged: Value = match &session.staged {
            Some(path) if path.is_file() => crate::state::read(path)?,
            _ => Value::Null,
        };
        staged
            .get(domain)
            .filter(|value| !value.is_null())
            .map(|value| match value {
                Value::String(value) => value.clone(),
                _ => value.to_string(),
            })
    };
    let generation = match selected.map(|selected| selected.selection()) {
        Some(s) => {
            if let Some(ambient) = &generation {
                ensure!(
                    ambient.parse::<u64>()? == s.generation,
                    "ambient generation conflicts with checked setup"
                );
            }
            Some(s.generation.to_string())
        }
        None => generation,
    };

    Ok(generation)
}
