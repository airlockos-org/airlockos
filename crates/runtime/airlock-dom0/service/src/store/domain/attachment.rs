//! Translate storage wire records once and require a checked request at installation.
//! Decimal identifiers, JSON encoding and filesystem authentication are adapter duties;
//! the deployment core owns pair selection and writable-state preservation decisions.

use super::{Snapshot, Target, generations, snapshot::Volume};
use airlock_deployment_core::attachment::{
    self, AttachmentPlan, CheckedInstallation, Definition, Generation, Pool, Slot, StorePair,
    WritablePair,
};
use airlock_nix_core::identity::{GuestName, StoreNamespace};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{fs, num::NonZeroU64, path::Path};

/// Immutable generation loaded through the existing committed-record validator.
pub(super) struct CommittedGeneration {
    // Authenticated receipt used only to derive the checked software-volume pair.
    receipt: crate::model::GenerationReceipt,
}

impl CommittedGeneration {
    /// The caller holds the pool admission lock across loading and installation.
    pub(super) fn load(target: &Target, generation: u64) -> Result<Self> {
        Ok(Self {
            receipt: generations::load(
                &target.pool_root,
                &target.pool_root,
                &super::super::runtime_namespace(target.domain.as_str()),
                generation,
            )?,
        })
    }

    pub(super) fn definitions(&self, target: &Target) -> Result<Vec<Value>> {
        project(target, &self.receipt, None)
    }
}

/// Validate the typed volume-pair projection for image construction or authenticated attachment.
pub(super) fn project(
    target: &Target,
    receipt: &crate::model::GenerationReceipt,
    metadata_size: Option<u64>,
) -> Result<Vec<Value>> {
    ensure!(
        receipt.identity.view_backend == "erofs-objectmap",
        "unsupported store view backend"
    );
    ensure!(
        receipt.identity.device == target.device
            && receipt.identity.blob_device == target.blob_device
            && receipt.identity.mountpoint == target.mountpoint,
        "store generation frontend binding mismatch"
    );
    let metadata = receipt
        .metadata_image
        .to_str()
        .context("non-UTF-8 metadata image")?
        .to_owned();
    let metadata_size = match metadata_size {
        Some(size) => size,
        None => fs::metadata(&metadata)?.len(),
    };
    let pair = StorePair::new(
        target.domain.as_str(),
        target.pool_name.clone(),
        Generation {
            domain: receipt.domain.to_string(),
            number: receipt.identity.generation.get(),
            closure_hash: receipt.closure_hash.clone(),
            manifest: receipt
                .manifest
                .to_str()
                .context("non-UTF-8 manifest")?
                .into(),
            metadata,
            metadata_size,
            data: receipt
                .blob_map
                .to_str()
                .context("non-UTF-8 blob map")?
                .into(),
            data_size: receipt.blob_logical_size,
        },
    )
    .context("invalid or mismatched storage generation projection")?;
    Ok(pair.definitions().iter().map(encode).collect())
}

/// Canonical driver identity; numeric rendering is kept at this wire boundary.
fn vid(definition: &Definition) -> String {
    format!(
        "domains/{domain}/generations/{generation}/{name}",
        domain = definition.domain,
        generation = definition.generation,
        name = definition.slot.name(),
    )
}

/// Encode only fields selected by the checked definition, with fixed upstream driver semantics.
fn encode(definition: &Definition) -> Value {
    let mut wire = json!({
        "name": definition.slot.name(), "pool": definition.pool, "vid": vid(definition),
        "rw": definition.writable, "save_on_stop": definition.persistent,
        "snap_on_start": definition.snap_on_start, "source": null, "revisions_to_keep": 0,
        "domain_name": definition.domain, "generation": definition.generation.to_string(),
        "closure_hash": definition.closure_hash, "manifest_path": definition.manifest,
        "size": definition.size,
    });
    match definition.slot {
        Slot::Store | Slot::BuilderStore => {
            wire["view_kind"] = json!("metadata-image");
            wire["view_path"] = json!(definition.path);
        }
        Slot::StoreData | Slot::BuilderData => {
            wire["view_kind"] = json!("erofs-blob-map");
            wire["blob_map_path"] = json!(definition.path);
            wire["blob_logical_size"] = json!(definition.size);
        }
    }
    wire
}

/// The accepted wire vocabulary is closed: extra storage effects cannot be silently discarded.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireDefinition {
    // Immutable slot decoded through the core's exhaustive selector.
    name: String,
    // Requested Qubes storage pool.
    pool: String,
    // Canonical driver identity compared with the typed coordinates below.
    vid: String,
    // Requested write access, rejected by the core when true.
    rw: bool,
    // Retention of this immutable view after shutdown.
    save_on_stop: bool,
    // Qubes snapshot derivation, forbidden for immutable views.
    snap_on_start: bool,
    // Parent-volume derivation is forbidden at this boundary.
    source: Option<Value>,
    // Qubes-managed revisions are unsupported for these immutable views.
    revisions_to_keep: u64,
    // Storage namespace, distinct from the consuming VM for both runtime and build views.
    domain_name: StoreNamespace,
    // Canonical positive decimal generation as persisted by Qubes.
    generation: String,
    // Closure identity common to the complete pair.
    closure_hash: String,
    // Manifest common to the complete pair.
    manifest_path: String,
    // Requested logical volume size.
    size: u64,
    // Metadata-image and external-data views have distinct field requirements.
    view_kind: String,
    // Metadata image, present only on metadata slots.
    view_path: Option<String>,
    // Filtered external map, present only on data slots.
    blob_map_path: Option<String>,
    // Data address space must agree with the Qubes volume size.
    blob_logical_size: Option<u64>,
}

impl WireDefinition {
    pub(super) fn decode(value: &Value) -> Result<Definition> {
        let wire: Self = serde_json::from_value(value.clone())?;
        let generation: NonZeroU64 = wire.generation.parse()?;
        ensure!(
            generation.to_string() == wire.generation,
            "noncanonical storage generation"
        );
        ensure!(
            wire.source.is_none() && wire.revisions_to_keep == 0,
            "unsupported storage derivation or revisions"
        );
        let slot = Slot::parse(&wire.name)
            .context("attachment cannot replace writable or unknown volume slots")?;
        let path = match slot {
            Slot::Store | Slot::BuilderStore => {
                ensure!(
                    wire.view_kind == "metadata-image"
                        && wire.blob_map_path.is_none()
                        && wire.blob_logical_size.is_none(),
                    "invalid metadata volume definition"
                );
                wire.view_path.context("missing metadata image")?
            }
            Slot::StoreData | Slot::BuilderData => {
                ensure!(
                    wire.view_kind == "erofs-blob-map"
                        && wire.view_path.is_none()
                        && wire.blob_logical_size == Some(wire.size),
                    "invalid data volume definition"
                );
                wire.blob_map_path.context("missing external-data map")?
            }
        };
        super::super::qubes_inspect::absolute(Path::new(&path))?;
        super::super::qubes_inspect::absolute(Path::new(&wire.manifest_path))?;
        let definition = Definition {
            slot,
            pool: wire.pool,
            domain: wire.domain_name.to_string(),
            generation: generation.get(),
            closure_hash: wire.closure_hash,
            manifest: wire.manifest_path,
            path,
            size: wire.size,
            writable: wire.rw,
            persistent: wire.save_on_stop,
            snap_on_start: wire.snap_on_start,
        };
        ensure!(
            wire.vid == vid(&definition),
            "storage backing identity differs from its generation"
        );
        Ok(definition)
    }
}

/// Decode a closed pool declaration at the worker boundary.
pub(super) fn pool(value: &Value) -> Result<Pool> {
    let name = value["name"].as_str().context("missing attachment pool")?;
    let root = value["root_dir"]
        .as_str()
        .context("missing attachment pool root")?;
    super::super::qubes_inspect::absolute(Path::new(root))?;
    ensure!(
        value["driver"] == "airlock-closure" && value["revisions_to_keep"] == 0,
        "unsupported attachment pool"
    );
    ensure!(
        value.as_object().is_some_and(|fields| fields.len() == 4),
        "unsupported attachment pool fields"
    );
    Pool::new(name.into(), root.into()).context("missing attachment pool identity")
}

/// Checked request retained across the isolated worker's serialized transport.
pub(super) struct Installation<'a> {
    // Semantic request consumed directly by typed dispatch inside the worker.
    checked: CheckedInstallation,
    // Exact observed state retained for Qubes' locked compare-and-swap.
    before: &'a Snapshot,
}

impl<'a> Installation<'a> {
    pub(super) fn new(
        domain: &GuestName,
        before: &'a Snapshot,
        pool: &Value,
        configs: &[Value],
    ) -> Result<Self> {
        let definitions = configs
            .iter()
            .map(WireDefinition::decode)
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            checked: checked(domain, before, self::pool(pool)?, definitions)?,
            before,
        })
    }

    pub(super) fn wire(&self) -> Value {
        let pool = self.checked.pool();
        json!({"operation": "install", "domain": self.checked.plan().target(), "expected": self.before,
            "pool": {"name":pool.name(), "root_dir":pool.root(), "driver":"airlock-closure", "revisions_to_keep":0},
            "volumes": self.checked.plan().definitions().iter().map(encode).collect::<Vec<_>>()})
    }

    pub(super) fn check_after(&self, after: &Snapshot) -> Result<()> {
        check_after(&self.checked, after)
    }
}

/// Validate typed declarations against the fresh locked observation, producing no JSON authority.
pub(super) fn checked(
    domain: &GuestName,
    before: &Snapshot,
    pool: Pool,
    definitions: Vec<Definition>,
) -> Result<CheckedInstallation> {
    before.validate(domain)?;
    super::super::qubes_inspect::absolute(Path::new(pool.root()))?;
    if let Some(existing) = before.pools.get(pool.name()) {
        ensure!(
            existing["driver"] == "airlock-closure" && existing["root_dir"] == pool.root(),
            "existing Qubes pool differs from the requested driver or root"
        );
    }
    let (root, private, references) = before.writable()?;
    for definition in &definitions {
        let id = vid(definition);
        for writable in [&root, &private] {
            ensure!(
                definition.pool != writable.backing.pool || id != writable.backing.vid,
                "immutable volume aliases writable backing"
            );
        }
    }
    let plan = AttachmentPlan::new(
        domain.to_string(),
        &before.klass,
        before.power(),
        before.running,
        WritablePair { root, private },
        &references,
        definitions,
    )
    .context(
        "attachment requires an isolated, halted standalone VM and one immutable generation pair",
    )?;
    let configs = plan.definitions().iter().map(encode).collect::<Vec<_>>();
    before.frontends(&configs, &frontends(plan.definitions()))?;
    CheckedInstallation::new(plan, pool).context("attachment volume names another pool")
}

/// Check post-installation evidence using the same opaque plan selected before dispatch.
pub(super) fn check_after(checked: &CheckedInstallation, after: &Snapshot) -> Result<()> {
    let plan = checked.plan();
    after.validate(&plan.target().parse()?)?;
    let (root, private, references) = after.writable()?;
    ensure!(
        !after.running && after.power().is_halted(),
        "VM is not halted after storage installation"
    );
    ensure!(
        plan.preserves(&root, &private) && attachment::isolation(&root, &private, &references),
        "storage installation changed or shared writable root/private state"
    );
    let configs = plan.definitions().iter().map(encode).collect::<Vec<_>>();
    ensure!(
        after.matches(&configs),
        "installed Qubes volumes differ from requested configuration"
    );
    after.frontends(&[], &frontends(plan.definitions()))
}

/// Fixed Xen slots for immutable views; writable disks keep their upstream assignments.
fn frontends(definitions: &[Definition]) -> Vec<(&str, &str)> {
    definitions
        .iter()
        .map(|definition| {
            let frontend = match definition.slot {
                Slot::Store => "xvde",
                Slot::StoreData => "xvdf",
                Slot::BuilderStore => "xvdg",
                Slot::BuilderData => "xvdh",
            };
            (definition.slot.name(), frontend)
        })
        .collect()
}

/// Observe one complete writable-volume definition without discarding driver-specific fields.
pub(super) fn writable(volume: &Volume) -> Result<attachment::WritableVolume> {
    Ok(attachment::WritableVolume {
        backing: attachment::Backing {
            pool: volume.identity.pool.clone(),
            vid: volume.identity.vid.clone(),
        },
        writable: volume.rw,
        persistent: volume.save_on_stop,
        snap_on_start: volume.snap_on_start,
        source: volume.source.as_ref().map(|source| attachment::Backing {
            pool: source.pool.clone(),
            vid: source.vid.clone(),
        }),
        record: serde_json::to_string(volume)?,
    })
}
