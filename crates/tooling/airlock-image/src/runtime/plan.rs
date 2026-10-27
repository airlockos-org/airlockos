//! An admitted software view is a verified, immutable set of packages. Connect
//! each VM to its view before upstream Qubes creates the initial disks.

use super::{
    POOL,
    model::{Domain, custom_color, feature, kernelopts},
};
use crate::support::{input_json, output};
use airlock_machine_core::model::VmReference;
use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{Value, json};
use sha1::{Digest, Sha1};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Serialize)]
pub(super) struct VmPlan {
    // Backend-specific Qubes class sharing the same identity and lifecycle graph.
    pub(super) class: String,
    // Validated Qubes VM name, used for paths and cross-VM references.
    pub(super) name: String,
    // Deterministic namespace UUID so identical images preserve VM identity.
    pub(super) uuid: String,
    // Label name whose custom color has already been validated.
    pub(super) label: String,
    // Custom label color, if this VM declares a managed label.
    pub(super) color: Option<String>,
    // VM properties excluding separately managed providers and kernel options.
    pub(super) prefs: BTreeMap<String, Value>,
    // Selected bundle installed under the offline kernel pool.
    pub(super) kernel: String,
    // Validated immutable-store boot parameters.
    pub(super) kernelopts: String,
    // Fully constructed feature map passed directly to upstream Qubes.
    pub(super) features: BTreeMap<String, String>,
    // Physical seed used only by the build's sparse root copy.
    pub(super) root_image: Option<PathBuf>,
    // Sparse private-volume capacity; None delegates the default to Qubes.
    pub(super) private_size: Option<u64>,
    // Native storage configurations registered through the upstream driver.
    pub(super) volumes: Vec<Value>,
    // Runtime provider declaration; omission inherits Qubes defaults after temporary isolation.
    pub(super) netvm: VmReference,
    // Explicit GUI override after providers exist; None retains the upstream default.
    pub(super) guivm: Option<Value>,
    // Prepared source used when verifying the reloaded Qubes snapshot.
    pub(super) source: String,
}

fn vm_uuid(name: &str) -> String {
    let mut hash = Sha1::new();
    hash.update([
        0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30,
        0xc8,
    ]);
    hash.update(format!("airlock-image:{name}"));
    let mut data = hash.finalize();
    data[6] = (data[6] & 0x0f) | 0x50;
    data[8] = (data[8] & 0x3f) | 0x80;
    let hex: String = data[..16].iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

pub(super) fn storage(arguments: &[&str], request: &Value) -> Result<Value> {
    input_json(
        Command::new("airlock-dom0-service")
            .arg("storage")
            .args(arguments),
        request,
    )
}

pub(super) fn plan(name: &str, domain: &Domain, pool: &Path) -> Result<VmPlan> {
    let system = &domain.backend.system.source;
    if let Some(artifact) = domain.backend.hermit() {
        artifact.validate(false)?;
        let mut features: BTreeMap<_, _> = domain
            .features
            .iter()
            .map(|(key, value)| Ok((key.clone(), feature(value)?)))
            .collect::<Result<_>>()?;
        features.insert(
            "airlock-hermit-artifact".into(),
            serde_json::to_string(artifact)?,
        );
        features.insert("airlock-system-source".into(), system.to_string());
        features.insert("airlock-hermit-generation".into(), "image-boot".into());
        return Ok(VmPlan {
            class: domain.class.clone(),
            name: name.into(),
            uuid: vm_uuid(name),
            label: domain.label.clone(),
            color: custom_color(domain)?,
            prefs: domain
                .prefs
                .iter()
                .filter(|(key, _)| {
                    !matches!(key.as_str(), "netvm" | "guivm" | "kernelopts" | "kernel")
                })
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
            kernel: String::new(),
            kernelopts: String::new(),
            features,
            root_image: None,
            private_size: None,
            volumes: Vec::new(),
            netvm: domain.netvm.clone(),
            guivm: domain.prefs.get("guivm").cloned(),
            source: system.to_string(),
        });
    }
    let backend = domain.backend.nixos()?;
    let mut admission = storage(
        &["image", "inspect-prepared", "--request", "-"],
        &json!({
            "descriptor": Path::new(backend.store.source.as_str()).join("prepared.json"),
            "physical_pool": pool,
            "pool_root": POOL,
            "domain": name,
            "system": system,
            "root_source": backend.root.source,
            "kernel_name": backend.kernel.name,
        }),
    )?;
    let size = admission["view_size"]
        .as_u64()
        .context("missing prepared view size")?;
    let root_image = PathBuf::from(
        admission
            .as_object_mut()
            .context("invalid admission")?
            .remove("root_image")
            .context("missing root image")?
            .as_str()
            .context("invalid root image")?,
    );
    let mut volumes: Vec<Value> = serde_json::from_value(storage(
        &[
            "domain",
            "image-volumes",
            name,
            "--admission",
            "-",
            "--pool-root",
            POOL,
            "--metadata-size",
            &size.to_string(),
        ],
        &admission,
    )?)?;
    if matches!(name, "usr-assistant" | "sys-ctrl") {
        let builders: Value = serde_json::from_str(&output(
            Command::new("airlock-dom0-service")
                .args(["storage", "builder", "volumes", "--pool-root"])
                .arg(pool)
                .args([
                    "--logical-root",
                    POOL,
                    "--pool-name",
                    "airlock-closure",
                    "--domain",
                    name,
                ]),
        )?)?;
        volumes.push(builders["builder-store"].clone());
        volumes.push(builders["builder-data"].clone());
    }

    let mut features = BTreeMap::new();
    for (key, value) in &domain.features {
        features.insert(key.clone(), feature(value)?);
    }
    for (key, value) in &domain.services {
        features.insert(format!("service.{key}"), feature(value)?);
    }

    let mut add = |key: &str, value: String| {
        features.insert(key.into(), value);
    };
    for (key, value) in [
        ("airlock-backend", "nix-closure"),
        ("airlock-root-source", backend.root.source.as_str()),
        ("airlock-system-source", system.as_str()),
        ("airlock-store-source", backend.store.source.as_str()),
        ("airlock-store-mode", "shared-closure"),
        ("airlock-store-view-backend", "erofs-objectmap"),
        ("airlock-store-filesystem", "erofs"),
        ("airlock-store-blob-volume", "store-data"),
        ("airlock-store-mountpoint", "/nix/store"),
        ("airlock-store-device", "/dev/xvde"),
        ("airlock-store-blob-device", "/dev/xvdf"),
        ("airlock-store-read-only", "True"),
    ] {
        add(key, value.into());
    }
    add(
        "airlock-root-artifact",
        admission["root_artifact"]["sha256"]
            .as_str()
            .context("root artifact digest")?
            .into(),
    );
    for (key, source) in [
        ("airlock-store-closure-hash", "closure_hash"),
        ("airlock-store-view-image", "view_image"),
        ("airlock-store-blob-map", "blob_map"),
    ] {
        add(
            key,
            admission[source]
                .as_str()
                .context("admission feature missing")?
                .into(),
        );
    }

    let generation = admission["generation"]
        .as_u64()
        .context("invalid prepared generation")?
        .to_string();
    add("airlock-store-generation", generation);

    let prefs = domain
        .prefs
        .iter()
        .filter(|(key, _)| !matches!(key.as_str(), "netvm" | "guivm" | "kernelopts" | "kernel"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    Ok(VmPlan {
        class: domain.class.clone(),
        name: name.into(),
        uuid: vm_uuid(name),
        label: domain.label.clone(),
        color: custom_color(domain)?,
        prefs,
        kernel: backend.kernel.name.clone(),
        kernelopts: kernelopts(domain)?,
        features,
        root_image: Some(root_image),
        private_size: backend
            .state
            .get("persistent_size")
            .and_then(Value::as_u64)
            .filter(|v| *v > 0),
        volumes,
        netvm: domain.netvm.clone(),
        guivm: domain.prefs.get("guivm").cloned(),
        source: backend.store.source.to_string(),
    })
}
