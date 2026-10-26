//! Records exchanged with existing approval and closure-storage helpers.
//! Decoding checks shape and identity; protected state and Qubes policy supply trust.

pub use airlock_nix_core::admission::{
    AdmissionSender, AdmissionTransport, CheckStatus, GuestTransport,
};

use super::{GenerationId, ReleasePath, StoreArtifact, StoreFile, StorePath};
use airlock_nix_core::{
    identity::{
        BaselineFingerprint, GitRevision, GuestName, LockHash, ReviewFingerprint, ReviewId,
        StoreNamespace,
    },
    review::Scope,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Guest backend protocol supported by this coordinator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackendKind {
    #[serde(rename = "nix-closure")]
    /// Boot an immutable NixOS closure with Airlock storage artifacts.
    NixClosure,
    /// Boot an immutable native Hermit PVH executable.
    #[serde(rename = "hermit")]
    Hermit,
}

/// Sharing protocol used to expose an immutable Nix closure to a guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StoreMode {
    #[serde(rename = "shared-closure")]
    /// Expose immutable software through the shared-closure storage protocol.
    SharedClosure,
}

/// Protected link from one admitted release to its human source approval.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseBinding {
    /// Correlation identity used to associate requests, decisions and status replies.
    pub request_id: ReviewId,
    /// Release path to associate with the protected source approval.
    pub release: ReleasePath,
    /// Git commit identifying the candidate source tree.
    pub revision: GitRevision,
    /// SHA-256 of flake.lock, binding the source to its dependency versions.
    pub lock_hash: LockHash,
}

/// Whole-machine or guest-only target bound to a human source review.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "family", rename_all = "snake_case")]
pub enum ReviewTarget {
    /// Apply the enclosing operation to the whole machine, including dom0.
    Machine {
        /// Explicit null target required by the whole-machine wire protocol.
        target: (),
    },
    /// Apply the enclosing operation to one non-dom0 VM.
    Guest {
        /// Guest VM targeted by this operation; dom0 is excluded.
        target: GuestName,
    },
}

/// Exact source and target whose effects a protected approval may authorize.
#[derive(Debug, Serialize, Deserialize)]
#[serde(try_from = "ReviewBindingWire")]
pub struct ReviewBinding {
    /// Git commit identifying the candidate source tree.
    pub revision: GitRevision,
    /// SHA-256 of flake.lock, binding the source to its dependency versions.
    pub lock_hash: LockHash,
    /// Guest target, or absent/null for whole-machine work.
    #[serde(flatten)]
    pub target: ReviewTarget,
    /// Additional protocol metadata retained without treating it as authority.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReviewFamily {
    /// Apply the enclosing operation to the whole machine, including dom0.
    Machine,
    /// Apply the enclosing operation to one non-dom0 VM.
    Guest,
}

#[derive(Deserialize)]
struct ReviewBindingWire {
    /// Git commit identifying the candidate source tree.
    revision: GitRevision,
    /// SHA-256 of flake.lock, binding the source to its dependency versions.
    lock_hash: LockHash,
    /// Selects whole-machine work or an operation on one guest.
    family: ReviewFamily,
    /// Guest target, or absent/null for whole-machine work.
    target: Value,
    /// Additional protocol metadata retained without treating it as authority.
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

impl TryFrom<ReviewBindingWire> for ReviewBinding {
    type Error = anyhow::Error;

    fn try_from(w: ReviewBindingWire) -> anyhow::Result<Self> {
        let target = match w.family {
            ReviewFamily::Machine => {
                anyhow::ensure!(w.target.is_null(), "invalid machine approval target");
                ReviewTarget::Machine { target: () }
            }
            ReviewFamily::Guest => ReviewTarget::Guest {
                target: serde_json::from_value(w.target)?,
            },
        };

        Ok(Self {
            revision: w.revision,
            lock_hash: w.lock_hash,
            target,
            extra: w.extra,
        })
    }
}

/// Protected review state consulted before starting or continuing activation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    /// Wait for the human decision bound to this source and scope.
    AwaitingApproval,
    /// The recorded review accepted the proposed source and effect limits.
    Approved,
    /// The approved request has entered the deployment workflow.
    DeploymentStarted,
    /// The reviewer declined this request.
    Rejected,
    /// The request was withdrawn before completion.
    Cancelled,
    /// The computed effects exceed the approved limits.
    ScopeExceeded,
}

impl ApprovalStatus {
    /// Return whether protected review state is approved or already handed to deployment.
    pub fn permits_activation(self) -> bool {
        matches!(self, Self::Approved | Self::DeploymentStarted)
    }
}

/// Dom0-protected source approval, its scope and any associated deployment start.
#[derive(Debug, Serialize, Deserialize)]
pub struct ApprovalRecord {
    /// Correlation identity used to associate requests, decisions and status replies.
    pub request_id: ReviewId,
    /// Reviewed source and operation target bound to this approval.
    pub binding: ReviewBinding,
    /// Digest of the material shown to the user; absent until a human decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_fingerprint: Option<ReviewFingerprint>,
    /// Fingerprint of the deployed selection, used to detect a stale review.
    pub baseline_state: BaselineFingerprint,
    /// Maximum VM impact and reboot permission recorded for this review.
    pub scope: Scope,
    /// Protected human-review/deployment state read from dom0.
    pub status: ApprovalStatus,
    /// Candidate release location containing its manifest and topology.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release: Option<ReleasePath>,
    /// Unix timestamp at which deployment began, when recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<f64>,
    /// Durable operation that consumed this decision; missing in legacy records.
    #[serde(
        default,
        deserialize_with = "operation_identity",
        skip_serializing_if = "Option::is_none"
    )]
    pub deployment_operation: Option<super::TransactionId>,
    /// Additional protocol metadata retained without treating it as authority.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Missing denotes a legacy record; explicit null cannot erase a consumed operation binding.
fn operation_identity<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<super::TransactionId>, D::Error> {
    super::TransactionId::deserialize(deserializer).map(Some)
}

/// Guest-only admission context restricting a release to one VM.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuestAdmission {
    /// Guest VM to which this stored generation or observation belongs.
    pub domain: GuestName,
    /// Additional protocol metadata retained without treating it as authority.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Version marker accepted for closure-store generation inspection replies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GenerationSchema {
    #[serde(rename = "airlock.closure-store.generation-info.v1")]
    /// Version one of this enclosing wire record.
    V1,
}

/// Guest-facing closure storage view reported by generation inspection.
#[derive(Debug, Serialize, Deserialize)]
pub struct GenerationStore {
    /// Required shared-closure protocol marker, validated during decoding.
    #[serde(rename = "mode")]
    pub _mode: StoreMode,
    /// Content identity shared by the inspected generation's immutable volumes.
    pub closure_hash: String,
    /// Guest mount location exposing the shared Nix closure.
    pub mountpoint: String,
    /// Block-device identifier providing the guest closure view.
    pub device: String,
    /// Block-device identifier providing shared closure data blobs.
    pub blob_device: String,
    /// Storage implementation used to expose the closure to the guest.
    pub view_backend: String,
}

/// Storage-integrity outcome attached to an inspected guest generation.
#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationReport {
    /// Whether the storage helper reports verification succeeded.
    pub status: CheckStatus,
    /// Additional verification diagnostics retained only for wire publication.
    #[serde(flatten)]
    pub diagnostics: BTreeMap<String, Value>,
}

/// Storage retention protection attached to an inspected guest generation.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RetentionReport {
    /// Whether this guest generation must be kept during retention planning.
    #[serde(default)]
    pub retain: bool,
    /// Retention diagnostics preserved without treating unknown keys as protection.
    #[serde(flatten)]
    pub diagnostics: BTreeMap<String, Value>,
}

/// Existing storage generation and its artifacts, selection and verification metadata.
#[derive(Debug, Serialize, Deserialize)]
pub struct GenerationInfo {
    /// Required generation-info version, validated during decoding.
    #[serde(rename = "schema")]
    pub _schema: GenerationSchema,
    /// Whether the storage helper successfully inspected this generation.
    pub status: CheckStatus,
    /// Runtime storage namespace, named after the consuming VM with a `-runtime-store` suffix.
    pub domain: StoreNamespace,
    /// Nonzero storage generation number identifying the admitted guest system.
    pub generation: GenerationId,
    /// Committed manifest whose path is compared when binding admission receipts.
    pub manifest: std::path::PathBuf,
    /// NixOS system closure selected for the guest to boot.
    pub system: StorePath,
    /// Immutable guest root image inside the Nix store.
    pub root_source: StoreFile,
    /// Qubes kernel directory name used when starting the guest.
    pub kernel_name: String,
    /// Closure descriptor artifact against which the declared backend is checked.
    pub closure_source: StoreArtifact,
    /// Guest-facing storage view reported for the admitted generation.
    pub store: GenerationStore,
    /// Storage-integrity result returned by the generation helper.
    pub verification: VerificationReport,
    /// Whether this generation is currently selected; omission cannot mean inactive.
    pub selected: bool,
    /// Optional storage artifact metadata supplied for the guest root.
    #[serde(default)]
    pub root_artifact: Option<Value>,
    /// Optional protection from automatic generation removal.
    #[serde(default)]
    pub retention: Option<RetentionReport>,
    /// Admission metadata, decoded strictly only when staging a new activation.
    /// Older selected generations need not carry modern admission records.
    #[serde(default)]
    pub approval: Value,
    /// Build-source information retained for admission and identity checks.
    #[serde(default)]
    pub provenance: Value,
    /// Additional inspection diagnostics retained without extending the typed decision fields.
    #[serde(flatten)]
    pub diagnostics: BTreeMap<String, Value>,
}

/// Admission transport, sender and source identity required for newly staged output.
#[derive(Debug, Deserialize)]
pub struct GenerationApproval {
    /// Required qrexec admission transport marker.
    #[serde(rename = "transport")]
    pub _transport: AdmissionTransport,
    /// Recognized submitting VM recorded by storage admission.
    #[serde(rename = "approved_by")]
    pub _approved_by: AdmissionSender,
    /// Closure descriptor artifact admitted by the existing Qubes transport.
    pub source: StoreArtifact,
}

/// Build source identities required when validating newly staged guest output.
#[derive(Debug, Deserialize)]
pub struct GenerationProvenance {
    /// Git commit from which this guest system was built.
    pub source_revision: GitRevision,
    /// SHA-256 of flake.lock, binding the source to its dependency versions.
    pub lock_hash: LockHash,
}

/// Version marker accepted when reading release-pruning history.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
pub enum PruneSchema {
    #[serde(rename = "airlock.machine-release-prune.v1")]
    /// Version one of this enclosing wire record.
    V1,
}

/// Outcome recorded for a previous advisory release-pruning operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PruneStatus {
    /// Release pruning started and may require recovery after interruption.
    Pruning,
    /// The release artifacts have been removed according to retention policy.
    Pruned,
}

/// Release and recorded prune outcome used when proposing retention actions.
#[derive(Debug, Deserialize)]
pub struct PruneRecord {
    /// Prune-record format marker checked when loading retention history.
    #[serde(rename = "schema")]
    pub _schema: PruneSchema,
    /// Recorded prune outcome used to avoid proposing already-pruned releases.
    pub status: PruneStatus,
    /// Release directory to which this retained history entry refers.
    pub release: ReleasePath,
}

/// Version marker accepted for retired-VM storage entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrashSchema {
    #[serde(rename = "airlock.machine-trash.v1")]
    /// Version one of this enclosing wire record.
    V1,
}

/// Retired-storage lifecycle state used to determine purge eligibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrashStatus {
    /// Record intended retirement before changing the VM.
    Planned,
    /// Remove retired VMs from active configuration while preserving recovery data.
    Retiring,
    /// The VM is retired and its recovery data remains retained.
    Trashed,
    /// Permanent removal of retained recovery data is in progress.
    Purging,
    /// Retained recovery data has been permanently removed.
    Purged,
    /// The retired VM has returned to active configuration.
    Restored,
}

impl TrashStatus {
    /// Return whether retirement is in progress, retained as trash or currently being purged.
    pub fn is_active(self) -> bool {
        matches!(self, Self::Retiring | Self::Trashed | Self::Purging)
    }
}

/// Retired VM identity and recoverable storage, retained through restoration or explicit purge.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrashRecord {
    /// Trash-record format marker checked before planning purges.
    #[serde(rename = "schema")]
    pub _schema: TrashSchema,
    /// Transaction-and-VM identity required for an explicit purge confirmation.
    pub id: String,
    /// Guest VM to which this stored generation or observation belongs.
    pub domain: GuestName,
    /// Lifecycle state controlling whether the retired data can be purged.
    pub status: TrashStatus,
    /// Registered Qubes UUID, preventing deletion of a replacement VM with the same name.
    pub uuid: super::BootId,
    /// Configuration and storage identity captured when this VM left the active topology.
    pub domain_config: super::Domain,
    /// Release that still retains the VM as a rollback choice.
    pub source_release: ReleasePath,
    /// Deployment transaction that initiated retirement.
    pub source_transaction: super::TransactionId,
    /// Selected guest pool generation retained with the retired VM.
    pub pool_generation: super::GenerationId,
    /// Earliest Unix time at which explicit purge may proceed without an override.
    pub purge_after: f64,
    /// Number of days to retain recoverable data after retirement.
    pub retention_days: u32,
    /// Persistent volume identities and the retained pool manifest.
    pub storage: TrashStorage,
    /// Additional audit timestamps and restore or purge details.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Storage that must match before a retired VM can be permanently deleted.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrashStorage {
    /// Registered-stopped, active or purged state of the VM's data.
    pub disposition: String,
    /// Persistent-state declaration captured from the topology.
    pub private: Value,
    /// Pool generation's immutable manifest path.
    pub pool_manifest: String,
    /// Per-volume ownership snapshot used to detect aliases and foreign snapshots.
    pub volumes: BTreeMap<String, super::Volume>,
}

/// Release with its first successful verification time, used to retain recovery points.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifiedGeneration {
    /// Release directory to which this retained history entry refers.
    pub release: ReleasePath,
    /// First successful verification time, in seconds since the Unix epoch.
    pub first_verified_at: f64,
    /// Additional protocol metadata retained without treating it as authority.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Whether host policy permits automatic retention proposals.
#[derive(Debug, Deserialize)]
pub struct RetentionPolicy {
    /// Whether automatic retention planning is enabled by host policy.
    pub enabled: bool,
}

/// Named mutation category exposed in whole-machine lock diagnostics.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineOperation {
    /// Activate a selected machine release.
    Apply,
    /// Resume or roll back an interrupted transaction.
    Recover,
    /// Observe and verify the selected machine generation.
    Verify,
    /// Manage source-bound review records.
    Review,
    /// Validate and admit a candidate through the protected runtime workflow.
    Admission,
    /// Prepare or inspect a proposed machine release.
    Candidate,
    /// Configure or observe machine startup.
    Boot,
    /// Remove unretained release artifacts.
    Prune,
    /// Permanently remove retired VM recovery data.
    Purge,
    /// Perform the existing generation-maintenance operation.
    Maintenance,
    /// Change the explicit retention selection for a release.
    Retain,
}
