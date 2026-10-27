//! A Qubes snapshot preserves volume order as well as persisted configuration.
//! Order determines Xen frontend names, while independent writable identities
//! prevent one VM's private state from becoming another VM's backing storage.

use super::super::domain_cli::Target;
use airlock_deployment_core::{attachment, inventory::PowerState};
use airlock_nix_core::identity::GuestName;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, path::PathBuf};

/// Stable backing identity, independent of a VM's current device frontend.
#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub(super) struct VolumeIdentity {
    // Qubes pool namespace containing this backing object.
    pub(super) pool: String,
    // Driver-defined backing-object identity, unique within its pool.
    pub(super) vid: String,
}

/// Both persisted definition and live driver properties of one ordered boot volume.
#[derive(Debug, Deserialize, Serialize)]
pub(super) struct Volume {
    /// Boot-volume key; order in the containing vector is significant.
    pub(super) name: String,
    // Stable backing identity used for writable-volume isolation.
    #[serde(flatten)]
    pub(super) identity: VolumeIdentity,
    // Whether the guest may mutate this backing object.
    pub(super) rw: bool,
    // Whether Qubes derives a fresh snapshot at VM start.
    pub(super) snap_on_start: bool,
    // Whether Qubes preserves changes and backing identity after stop.
    pub(super) save_on_stop: bool,
    // Optional backing volume from which this volume derives its contents.
    pub(super) source: Option<VolumeIdentity>,
    // Immutable Airlock generation, absent on conventional Qubes volumes.
    generation: Option<String>,
    // Closure digest binding an Airlock volume to its committed manifest.
    closure_hash: Option<String>,
    // Metadata image or currently attached runtime device.
    path: Option<PathBuf>,
    // Filtered external-data map, absent for metadata images.
    blob_map_path: Option<PathBuf>,
    // Guest-visible logical size reported by the storage driver.
    size: u64,
    /// Exact persisted definition, retained for compare-and-swap and policy checks.
    pub(super) config: Value,
}

#[derive(Debug, Deserialize, Serialize)]
struct Reference {
    // Other VM owning or deriving from the observed backing volume.
    domain: String,
    // Stable backing identity of that VM's volume.
    #[serde(flatten)]
    identity: VolumeIdentity,
    // Optional parent backing identity that also counts as sharing.
    source: Option<VolumeIdentity>,
}

/// One observed Qubes state used for policy validation and compare-and-swap updates.
#[derive(Debug, Deserialize, Serialize)]
pub(super) struct Snapshot {
    /// VM whose exact state was inspected through Qubes.
    pub(super) domain: GuestName,
    // Upstream VM class; immutable system views require StandaloneVM.
    pub(super) klass: String,
    /// Runtime state observed through libvirt rather than inferred from XML.
    pub(super) running: bool,
    // Missing legacy power evidence is readable but cannot authorize installation.
    #[serde(default)]
    power_state: Option<String>,
    /// Persisted feature bindings used by setup to identify the attached generation.
    pub(super) features: BTreeMap<String, String>,
    /// Current boot-volume order, including standard and additional volumes.
    pub(super) volumes: Vec<Volume>,
    /// Persisted pool definitions, including their driver and installed root.
    pub(super) pools: BTreeMap<String, Value>,
    // Backing identities of other VMs needed to detect shared writable storage.
    references: Vec<Reference>,
}

impl Snapshot {
    pub(super) fn validate(&self, domain: &GuestName) -> Result<()> {
        ensure!(self.domain == *domain, "Qubes snapshot domain mismatch");
        ensure!(
            self.klass == "StandaloneVM",
            "domain is not a StandaloneVM: {domain}"
        );
        let mut names = std::collections::BTreeSet::new();
        ensure!(
            self.volumes.iter().all(|v| names.insert(&v.name)),
            "duplicate Qubes volume"
        );
        Ok(())
    }

    pub(super) fn feature(&self, name: &str) -> &str {
        self.features.get(name).map(String::as_str).unwrap_or("")
    }

    pub(super) fn volume(&self, name: &str) -> Option<&Volume> {
        self.volumes.iter().find(|v| v.name == name)
    }

    pub(super) fn power(&self) -> PowerState {
        PowerState::classify(self.power_state.as_deref().unwrap_or(""))
    }

    /// Retain all aliases, including sibling volumes and other VMs' source volumes.
    pub(super) fn writable(
        &self,
    ) -> Result<(
        attachment::WritableVolume,
        attachment::WritableVolume,
        Vec<attachment::Backing>,
    )> {
        let root = super::attachment::writable(
            self.volume("root")
                .context("missing writable root volume")?,
        )?;
        let private = super::attachment::writable(
            self.volume("private")
                .context("missing writable private volume")?,
        )?;
        let mut references = Vec::new();
        let mut retain = |identity: &VolumeIdentity| {
            references.push(attachment::Backing {
                pool: identity.pool.clone(),
                vid: identity.vid.clone(),
            });
        };
        for volume in &self.volumes {
            if volume.name != "root" && volume.name != "private" {
                retain(&volume.identity);
                if let Some(source) = &volume.source {
                    retain(source);
                }
            }
        }
        for reference in &self.references {
            retain(&reference.identity);
            if let Some(source) = &reference.source {
                retain(source);
            }
        }
        Ok((root, private, references))
    }

    pub(super) fn verify_isolation(&self) -> Result<()> {
        self.validate(&self.domain)?;
        let (root, private, references) = self.writable()?;
        ensure!(
            attachment::isolation(&root, &private, &references),
            "writable root/private storage must be independent, persistent and unshared"
        );
        Ok(())
    }

    pub(super) fn verify_pool(&self, target: &Target) -> Result<()> {
        if let Some(pool) = self.pools.get(&target.pool_name) {
            ensure!(
                pool["driver"] == "airlock-closure"
                    && pool["root_dir"].as_str() == target.pool_root.to_str(),
                "existing Qubes pool differs from the requested driver or root"
            );
        }
        Ok(())
    }

    pub(super) fn matches(&self, desired: &[Value]) -> bool {
        desired.iter().all(|config| {
            let Some(name) = config["name"].as_str() else {
                return false;
            };
            let Some(volume) = self.volume(name) else {
                return false;
            };
            let metadata = config["view_kind"] == "metadata-image";
            (metadata || config["view_kind"] == "erofs-blob-map")
                && config_matches(&volume.config, config)
                && !volume.rw
                && !volume.snap_on_start
                && volume.save_on_stop
                && volume.source.is_none()
                && config["pool"] == volume.identity.pool
                && config["vid"] == volume.identity.vid
                && config["generation"].as_str() == volume.generation.as_deref()
                && config["closure_hash"].as_str() == volume.closure_hash.as_deref()
                && config["size"].as_u64() == Some(volume.size)
                && if metadata {
                    config["view_path"].as_str().map(PathBuf::from) == volume.path
                } else {
                    config["blob_map_path"].as_str().map(PathBuf::from) == volume.blob_map_path
                }
        })
    }

    pub(super) fn frontends(&self, desired: &[Value], expected: &[(&str, &str)]) -> Result<()> {
        let mut names = self
            .volumes
            .iter()
            .map(|v| v.name.as_str())
            .collect::<Vec<_>>();
        for config in desired {
            let name = config["name"].as_str().context("volume has no name")?;
            if !names.contains(&name) {
                names.push(name);
            }
        }

        let mut extra = b'e';
        for name in names {
            let device = match name {
                "root" => "xvda".to_owned(),
                "private" => "xvdb".to_owned(),
                "volatile" => "xvdc".to_owned(),
                "kernel" => "xvdd".to_owned(),
                _ => {
                    ensure!(extra <= b'y', "too many non-standard Qubes boot volumes");
                    let device = format!("xvd{}", extra as char);
                    extra += 1;
                    device
                }
            };
            if let Some((_, expected)) = expected.iter().find(|(key, _)| *key == name) {
                ensure!(
                    device == expected.trim_start_matches("/dev/"),
                    "Qubes boot frontend assignment mismatch for {}:{name}: expected {expected}, got {device}",
                    self.domain
                );
            }
        }
        ensure!(
            expected.iter().all(|(name, _)| self.volume(name).is_some()
                || desired.iter().any(|c| c["name"] == *name)),
            "missing Qubes boot volume"
        );
        Ok(())
    }
}

pub(super) fn config_matches(actual: &Value, desired: &Value) -> bool {
    desired.as_object().is_some_and(|fields| {
        fields.iter().all(|(key, expected)| {
            if key == "size" {
                return true;
            }
            let value = &actual[key];
            value == expected
                || match expected {
                    Value::Bool(false) => value.is_null() || value == "False" || value == "false",
                    Value::Bool(true) => value == "True" || value == "true",
                    Value::Number(number) => value.as_str() == Some(number.to_string().as_str()),
                    Value::Null => value.is_null(),
                    _ => false,
                }
        })
    })
}
