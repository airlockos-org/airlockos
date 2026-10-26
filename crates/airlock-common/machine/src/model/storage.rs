//! Storage handoffs have distinct identities: generations name namespaces, installations name guests.
//! These records validate wire shape, not filesystem authenticity or permission to attach volumes.

use super::{GenerationId, StoreMode};
use airlock_nix_core::identity::{GuestName, StoreNamespace};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, path::PathBuf};

/// Boot and frontend identities shared by an admitted generation and its installation result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageIdentity {
    /// Positive generation in the separately named storage namespace.
    pub generation: GenerationId,
    /// Guest system identity; native manual setup may use a local artifact path.
    pub system: String,
    /// Original root-image source, independent of the resolved retained image.
    pub root_source: String,
    /// Closure or prepared-descriptor identity, independent of its physical storage path.
    pub source: String,
    /// Kernel bundle selected for this guest.
    pub kernel_name: String,
    /// Supported immutable sharing protocol.
    pub mode: StoreMode,
    /// Guest metadata block-device frontend.
    pub device: String,
    /// Guest data block-device frontend.
    pub blob_device: String,
    /// Guest software-store mountpoint.
    pub mountpoint: String,
    /// Implementation of the immutable software view.
    pub view_backend: String,
}

/// Admission protocol marker shared with build and controller components.
pub use airlock_nix_core::admission::GenerationReceiptSchema;

/// A generation projection addressed to storage, never a consuming guest.
/// The default namespace names a guest runtime or builder. Pool admission also uses
/// a local namespace type for host and administrative generations; callers must
/// validate that namespace before supplying a guest receipt to attachment.
///
/// ```compile_fail
/// use airlock_machine_core::model::GenerationReceipt;
/// fn attach(receipt: GenerationReceipt) {}
/// fn administrative_receipt(receipt: GenerationReceipt<String>) { attach(receipt); }
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenerationReceipt<Namespace = StoreNamespace> {
    /// Admission marker when present; installed or inspection schemas cannot masquerade as a load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<GenerationReceiptSchema>,
    /// Runtime or builder namespace; attachment applies its stricter runtime-pair checks.
    pub domain: Namespace,
    /// Complete boot and frontend identity retained from the committed manifest.
    #[serde(flatten)]
    pub identity: StorageIdentity,
    /// Manifest whose filesystem authentication remains the storage loader's duty.
    pub manifest: PathBuf,
    /// Immutable metadata image belonging to this generation.
    pub metadata_image: PathBuf,
    /// External-data address map belonging to the same generation.
    pub blob_map: PathBuf,
    /// Complete logical address space exposed by the data volume.
    pub blob_logical_size: u64,
    /// Content identity of the admitted software closure.
    pub closure_hash: String,
    /// Approved source identity; older admission responses omit this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_source: Option<String>,
    /// Preferred metadata image for installed guest features.
    #[serde(default)]
    pub view_image: Option<String>,
    /// Compatibility metadata image for older native responses.
    #[serde(default)]
    pub image: Option<String>,
    /// Immutable data-volume slot, when supplied by the view implementation.
    #[serde(default)]
    pub blob_volume: Option<String>,
    /// Whether this invocation materialized a view.
    #[serde(default)]
    pub view_created: bool,
    /// Diagnostics preserved only when serializing a response; decisions use typed fields.
    #[serde(flatten)]
    pub diagnostics: BTreeMap<String, Value>,
}

/// Closed installation-result schema, distinct from admission and generation inspection.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum InstallationSchema {
    /// Result of ensuring or switching a guest's software storage.
    #[serde(rename = "airlock.nix-domain-storage.v1")]
    V1,
}

/// Storage installation result addressed to a guest, not a storage namespace.
///
/// ```compile_fail
/// use airlock_machine_core::model::{GenerationReceipt, InstalledStorageReceipt};
/// fn attach(generation: GenerationReceipt) {}
/// fn wrong_handoff(receipt: InstalledStorageReceipt) { attach(receipt); }
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstalledStorageReceipt {
    /// Exact result protocol; other storage response formats are rejected during decoding.
    pub schema: InstallationSchema,
    /// Consuming guest whose configuration was reconciled.
    pub domain: GuestName,
    /// Actual installed generation and boot identity.
    #[serde(flatten)]
    pub identity: StorageIdentity,
    /// Whether qubesd still needs restoration; omission must not mean false.
    pub qubesd_restart_required: bool,
    /// Whether this call already restored qubesd; omission must not mean false.
    pub qubesd_restarted: bool,
    /// Created immutable volume slots; absence supports the older single-volume counter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volumes_created: Option<Vec<String>>,
    /// Legacy single-volume creation counter.
    #[serde(default)]
    pub volume_created: bool,
    /// Whether a new immutable view was materialized.
    #[serde(default)]
    pub view_created: bool,
    /// Closure identity supplied for derived guest features.
    #[serde(default)]
    pub closure_hash: Option<String>,
    /// Preferred metadata-image identity supplied for derived guest features.
    #[serde(default)]
    pub view_image: Option<String>,
    /// Compatibility metadata-image field used by older native responses.
    #[serde(default)]
    pub image: Option<String>,
    /// External-data map supplied for derived guest features.
    #[serde(default)]
    pub blob_map: Option<String>,
    /// Qubes data-volume slot supplied for derived guest features.
    #[serde(default)]
    pub blob_volume: Option<String>,
    /// Diagnostics retained at serialization boundaries, never interpreted as decision fields.
    #[serde(flatten)]
    pub diagnostics: BTreeMap<String, Value>,
}
