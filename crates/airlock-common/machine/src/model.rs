//! A release pairs built NixOS systems with the intended Qubes VM configuration.
//! These records let dom0 compare releases, record activation and verify what runs.

use airlock_nix_core::identity::{GitRevision, GuestName, LockHash, VmName};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    path::{Component, Path},
};

mod identity;

mod journal;

mod protocol;

mod storage;

pub use identity::*;
pub use journal::*;
pub use protocol::*;
pub use storage::*;

pub use airlock_nix_core::store_path::{StoreArtifact, StoreFile, StorePath};

/// Wire format accepted by runtime topology admission and native machine authoring.
pub const TOPOLOGY_SCHEMA: &str = "airlock.qubes-topology.v1";

/// Decimal journal identifier used to select a recorded activation or recovery attempt.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TransactionId(
    /// Nonempty decimal journal identifier of at most 40 characters, excluding zero.
    String,
);

impl TryFrom<String> for TransactionId {
    type Error = anyhow::Error;

    fn try_from(s: String) -> Result<Self> {
        ensure!(
            !s.is_empty() && s.len() <= 40 && s.bytes().all(|b| b.is_ascii_digit()) && s != "0",
            "invalid transaction ID"
        );

        Ok(Self(s))
    }
}

impl From<TransactionId> for String {
    fn from(v: TransactionId) -> Self {
        v.0
    }
}

impl TransactionId {
    /// Borrow the validated decimal transaction identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Artifact source with extension metadata retained for topology comparison.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source<T> {
    /// Immutable store location supplying the enclosing artifact.
    pub source: T,
    /// Additional protocol metadata retained without treating it as authority.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Qubes kernel selection paired with a guest boot configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Kernel {
    /// Qubes kernel directory name used for this guest.
    pub name: String,
    /// Additional protocol metadata retained without treating it as authority.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Immutable software view exposed through the existing Qubes storage backend.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Store {
    /// Closure descriptor output or prepared per-guest directory in the Nix store.
    pub source: StoreArtifact,
    /// Sharing protocol expected by the guest storage view.
    pub mode: StoreMode,
    /// Guest mount location exposing the shared Nix closure.
    pub mountpoint: String,
    /// Block-device identifier providing the guest closure view.
    pub device: String,
    /// Block-device identifier providing shared closure data blobs.
    pub blob_device: String,
    /// Storage implementation used to expose the closure to the guest.
    pub view_backend: String,
    /// Additional protocol metadata retained without treating it as authority.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Immutable guest system with a backend-specific boot contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Backend {
    /// Immutable system object, common to generation identity and source retention.
    pub system: Source<StorePath>,
    /// Guest ABI; Hermit cannot deserialize Linux boot or storage fields.
    #[serde(flatten)]
    pub guest: GuestBackend,
}

/// Closed guest boot contracts, independent of the VM's role.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum GuestBackend {
    /// Existing NixOS shared-closure boot implementation.
    #[serde(rename = "nix-closure")]
    Nixos(NixosBackend),
    /// Native Hermit executable with no Linux storage layout.
    #[serde(rename = "hermit")]
    Hermit(HermitBackend),
}

/// Hermit-specific boot metadata authenticated before selecting an executable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HermitBackend {
    /// Exact executable, build provenance and compiled authority mode.
    pub artifact: airlock_nix_core::hermit_artifact::Descriptor,
    /// Optional encrypted scratch disk; never a Linux root or persistent volume.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scratch: Option<airlock_nix_core::hermit_artifact::ScratchDisk>,
}

/// Existing Linux root, kernel and shared-store implementation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NixosBackend {
    /// Root filesystem image from which the guest starts.
    pub root: Source<StoreFile>,
    /// Kernel configuration paired with the guest root.
    pub kernel: Kernel,
    /// Shared Nix closure and its guest-facing storage settings.
    pub store: Store,
    /// Persistent state compared during migration planning.
    #[serde(default)]
    pub state: Value,
    /// Extension metadata preserved for existing Linux topology comparisons.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Backend {
    /// Borrow the scratch contract only for guests explicitly admitting that device.
    pub fn hermit_scratch(&self) -> Option<&airlock_nix_core::hermit_artifact::ScratchDisk> {
        match &self.guest {
            GuestBackend::Hermit(backend) => backend.scratch.as_ref(),
            GuestBackend::Nixos(_) => None,
        }
    }
    /// Return the backend protocol without inspecting the VM's name or role.
    pub fn kind(&self) -> BackendKind {
        match self.guest {
            GuestBackend::Nixos(_) => BackendKind::NixClosure,
            GuestBackend::Hermit(_) => BackendKind::Hermit,
        }
    }

    /// Borrow Linux boot settings or reject an accidental Linux-only operation.
    pub fn nixos(&self) -> Result<&NixosBackend> {
        match &self.guest {
            GuestBackend::Nixos(backend) => Ok(backend),
            GuestBackend::Hermit(_) => bail!("Hermit does not support Linux guest storage"),
        }
    }

    /// Borrow the executable descriptor when this guest uses Hermit.
    pub fn hermit(&self) -> Option<&airlock_nix_core::hermit_artifact::Descriptor> {
        match &self.guest {
            GuestBackend::Hermit(backend) => Some(&backend.artifact),
            GuestBackend::Nixos(_) => None,
        }
    }

    /// Describe persistent state; Hermit services have none.
    pub fn state(&self) -> &Value {
        match &self.guest {
            GuestBackend::Nixos(backend) => &backend.state,
            GuestBackend::Hermit(_) => &Value::Null,
        }
    }
}

/// Missing settings inherit existing/default configuration; explicit null resets
/// it. Collapsing those cases hides changes from planning and scope checks.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum VmReference {
    #[default]
    /// Use the enclosing Qubes default or existing setting because this field was omitted.
    Inherit,
    /// Explicitly clear the provider with a JSON null.
    Disabled,
    /// Preserve an explicit empty string, which differs from omission and null.
    Empty,
    /// Select a validated VM identity, including dom0 where the protocol permits it.
    Named(
        /// Explicit VM reference, distinct from inherited, disabled or empty settings.
        VmName,
    ),
}

impl VmReference {
    /// Return whether this setting was omitted and should inherit existing/default state.
    pub fn is_inherited(&self) -> bool {
        matches!(self, Self::Inherit)
    }

    /// Return a named or explicitly empty reference; inherited and disabled settings return `None`.
    pub fn as_deref(&self) -> Option<&str> {
        match self {
            Self::Named(name) => Some(name.as_str()),
            Self::Empty => Some(""),
            _ => None,
        }
    }
}

impl<'de> Deserialize<'de> for VmReference {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        match Option::<String>::deserialize(d)? {
            None => Ok(Self::Disabled),
            Some(s) if s.is_empty() => Ok(Self::Empty),
            Some(s) => s.parse().map(Self::Named).map_err(serde::de::Error::custom),
        }
    }
}

impl Serialize for VmReference {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Named(name) => name.serialize(s),
            Self::Empty => s.serialize_str(""),
            _ => s.serialize_none(),
        }
    }
}

/// Intended Qubes guest configuration, compared before planning disruptive changes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Domain {
    /// Guest boot artifacts and the storage arrangement that supplies them.
    pub backend: Backend,
    /// Qubes VM property overrides applied during configuration.
    #[serde(default)]
    pub prefs: BTreeMap<String, Value>,
    /// Qubes feature values advertised by the guest.
    #[serde(default)]
    pub features: BTreeMap<String, Value>,
    /// Qubes service enablement settings for the guest.
    #[serde(default)]
    pub services: BTreeMap<String, Value>,
    /// Network-provider reference; absence inherits while explicit null disables it.
    #[serde(default, skip_serializing_if = "VmReference::is_inherited")]
    pub netvm: VmReference,
    /// Template reference; absence inherits while explicit null clears it.
    #[serde(default, skip_serializing_if = "VmReference::is_inherited")]
    pub template: VmReference,
    /// Qubes VM class used when creating or checking the domain.
    #[serde(rename = "class")]
    pub class_name: String,
    /// Device assignments included when comparing guest configuration.
    #[serde(default)]
    pub devices: Value,
    /// Additional protocol metadata retained without treating it as authority.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Intended machine-wide Qubes configuration, including guests and RPC policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Topology {
    /// Wire format identifier used to reject unsupported record versions.
    pub schema: String,
    /// Declared guest names and their intended configuration.
    pub domains: BTreeMap<GuestName, Domain>,
    /// Host-wide Qubes preferences declared by this topology.
    #[serde(default)]
    pub prefs: BTreeMap<String, Value>,
    /// Kernel definitions available to configured guests.
    #[serde(default)]
    pub kernels: BTreeMap<String, Value>,
    /// Template definitions available to configured guests.
    #[serde(default)]
    pub templates: BTreeMap<String, Value>,
    /// Inter-VM RPC policy declared by this topology.
    #[serde(default)]
    pub qrexec_policy: Value,
    /// Additional protocol metadata retained without treating it as authority.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Topology {
    /// Reject unsupported topology versions, excessive guest counts and invalid kernel names.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == TOPOLOGY_SCHEMA,
            "unsupported topology schema"
        );
        ensure!(self.domains.len() <= 4096, "topology has too many domains");

        for (name, d) in &self.domains {
            if let Some(artifact) = d.backend.hermit() {
                artifact.validate(false)?;
                if let Some(scratch) = d.backend.hermit_scratch() {
                    scratch.validate()?;
                }
                ensure!(
                    artifact.executable.as_str()
                        == format!("{system}/kernel.elf", system = d.backend.system.source),
                    "{name}: executable is outside its system object"
                );
                ensure!(
                    d.class_name == "HermitVM"
                        && d.template == VmReference::Disabled
                        && d.netvm == VmReference::Disabled,
                    "{name}: Hermit requires an isolated, template-free domain"
                );
                ensure!(
                    d.prefs.get("virt_mode") == Some(&Value::from("pvh"))
                        && d.prefs.get("kernel") == Some(&Value::from(""))
                        && d.prefs.get("vcpus") == Some(&Value::from(1))
                        && d.prefs.get("guivm") == Some(&Value::Null)
                        && d.prefs.get("audiovm") == Some(&Value::Null),
                    "{name}: incompatible Hermit properties"
                );
                let memory = d.prefs.get("memory").and_then(Value::as_u64).unwrap_or(0);
                ensure!(
                    (16..=256).contains(&memory)
                        && d.prefs.get("maxmem").and_then(Value::as_u64) == Some(memory),
                    "{name}: invalid Hermit memory"
                );
                if artifact.authority == airlock_nix_core::hermit_artifact::AuthorityMode::Normal {
                    ensure!(
                        memory >= 128,
                        "{name}: normal clipboard requires at least 128 MiB"
                    );
                    let gui = d
                        .features
                        .get("airlock-clipboard-authority")
                        .and_then(Value::as_str)
                        .context("normal clipboard has no GUI authority")?;
                    let authority = self
                        .domains
                        .get(&gui.parse::<GuestName>()?)
                        .context("clipboard authority is outside this topology")?;
                    ensure!(
                        gui != name.as_str()
                            && authority.backend.hermit().is_none()
                            && authority.services.get("guivm") == Some(&Value::Bool(true)),
                        "{name}: clipboard authority must be a Linux GUI VM"
                    );
                } else {
                    ensure!(
                        !d.features.contains_key("airlock-clipboard-authority"),
                        "{name}: disconnected Hermit has a clipboard authority"
                    );
                }
                ensure!(
                    d.features.get("qrexec") == Some(&Value::from(""))
                        && d.features.get("gui") == Some(&Value::from(""))
                        && d.services.is_empty(),
                    "{name}: Hermit has no Linux guest services"
                );
                ensure!(
                    d.devices.is_null()
                        || d.devices.as_object().is_some_and(|devices| devices
                            .values()
                            .all(|value| value.as_array().is_some_and(Vec::is_empty))),
                    "{name}: Hermit has no device assignments"
                );
            } else {
                let kernel = &d.backend.nixos()?.kernel.name;
                ensure!(
                    !kernel.is_empty()
                        && kernel.len() <= 128
                        && kernel
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b)),
                    "{name}: invalid kernel name"
                );
            }
        }
        Ok(())
    }
}

/// Release wire format shared by authoring, inspection and admission.
pub const MANIFEST_SCHEMA: &str = "airlock.machine-release.v1";

/// Built release artifacts and source identities used to stage a machine or guest update.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    /// Wire format identifier used to reject unsupported record versions.
    pub schema: String,
    /// Machine configuration name selected when building the release.
    pub profile: MachineProfile,
    /// NixOS system closure selected for dom0.
    pub host: StorePath,
    /// Store-resident setup program applying the topology through Qubes.
    pub setup: StoreFile,
    /// Git commit identifying the candidate source tree.
    pub revision: GitRevision,
    /// SHA-256 of flake.lock, binding the source to its dependency versions.
    pub lock_hash: LockHash,
    /// Optional coordinator executable recorded with the built release.
    #[serde(default)]
    pub coordinator: Option<StoreFile>,
    /// Guest storage generations already admitted for activation.
    #[serde(default)]
    pub staged_generations: BTreeMap<GuestName, GenerationId>,
    /// Guests intentionally removed by this release.
    #[serde(default)]
    pub retire_domains: Vec<GuestName>,
    /// Destination-to-source mapping for recoverable private-volume migration.
    #[serde(default)]
    pub private_volume_copies: BTreeMap<GuestName, GuestName>,
    /// Per-guest storage artifact metadata carried by the release.
    #[serde(default)]
    pub guest_root_artifacts: BTreeMap<GuestName, Value>,
    /// Per-guest source identities for mixed-source guest updates.
    #[serde(default)]
    pub guest_provenance: BTreeMap<GuestName, Provenance>,
    /// Storage admission protocol used for guest system artifacts.
    #[serde(default)]
    pub guest_transport: Option<GuestTransport>,
    /// Whole-machine source release from which a guest update was derived.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_release: Option<StorePath>,
    /// Admission context constraining a guest-only release to one target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_admission: Option<GuestAdmission>,
    /// Additional protocol metadata retained without treating it as authority.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Source commit and dependency selection for a guest built independently of the host.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Provenance {
    /// Git commit identifying the candidate source tree.
    pub revision: GitRevision,
    /// SHA-256 of flake.lock, binding the source to its dependency versions.
    #[serde(rename = "lockHash")]
    pub lock_hash: LockHash,
}

impl Manifest {
    /// Reject unsupported release versions and inconsistent staging, retirement or copy targets.
    pub fn validate(&self, topology: &Topology) -> Result<()> {
        ensure!(self.schema == MANIFEST_SCHEMA, "unsupported release schema");
        ensure!(
            self.retire_domains
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == self.retire_domains.len(),
            "duplicate retired VM"
        );
        if let Some(value) = self.extra.get("trashRetentionDays") {
            ensure!(
                value
                    .as_u64()
                    .is_some_and(|days| (1..=3650).contains(&days)),
                "trash retention must be 1–3650 days"
            );
        }

        for name in self.staged_generations.keys() {
            ensure!(
                topology.domains.contains_key(name),
                "invalid staged generation for {name}"
            );
        }

        for name in &self.retire_domains {
            ensure!(
                !topology.domains.contains_key(name),
                "retired guest is still declared: {name}"
            );
        }

        for (target, source) in &self.private_volume_copies {
            ensure!(
                target != source
                    && topology.domains.contains_key(target)
                    && self.retire_domains.contains(source),
                "invalid private-volume copy"
            );
        }
        Ok(())
    }
}

/// Durable intended selection and transaction identity, published before VM configuration.
/// This record does not attest that the selected generation is applied or running.
/// Recovery takes both release endpoints from the fingerprint-bound journal instead.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Selection {
    /// Release directory selected by this machine transaction.
    pub release: ReleasePath,
    /// Prior release retained as the rollback baseline.
    pub previous: ReleasePath,
    /// Journal transaction that selected this release.
    pub transaction: TransactionId,
    /// Machine configuration name selected when building the release.
    pub profile: MachineProfile,
    /// Additional protocol metadata retained without treating it as authority.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Recovery authority comes from a checked journal, never a JSON flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyMode {
    /// Begin a newly authorized activation transaction.
    New,
    /// Continue the recorded transaction after an interruption.
    Resume,
    /// Restore the previous recorded machine selection.
    Rollback,
}

impl ApplyMode {
    /// Return whether the operation continues or rolls back an existing journal.
    pub fn is_recovery(self) -> bool {
        self != Self::New
    }
}

/// Last attempted activation stage; an interrupted phase does not attest completion of its effects.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    /// Check prerequisites before changing running systems.
    Preflight,
    /// Prepare the new immutable VM generations.
    Staging,
    /// Prepare the host boot artifacts without selecting them yet.
    HostBootPreparation,
    /// Stop running VMs in dependency-safe order.
    Stopping,
    /// Remove retired VMs from active configuration while preserving recovery data.
    Retiring,
    /// Apply the declared Qubes configuration.
    Configuring,
    /// Select the prepared host generation for the next boot.
    HostBootSelection,
    /// Transfer explicitly authorized persistent VM data.
    CopyingPrivate,
    /// Start the desired VMs after their dependencies.
    Starting,
    /// Check observed systems against the selected configuration.
    Verifying,
    /// Reconnect windows for unchanged applications after GUI replacement.
    GuiReconnecting,
    /// VM verification completed but the host still needs to boot the selection.
    RebootRequired,
    /// The operation completed its required verification.
    Complete,
    /// The operation or check failed; its enclosing record carries the details.
    Failed,
}

impl Phase {
    /// Return whether verification completed, including a release still awaiting host reboot.
    pub fn verified(self) -> bool {
        matches!(self, Self::Complete | Self::RebootRequired)
    }
}

/// Computed VM effects and reboot requirement presented before activation.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Plan {
    /// VMs whose configuration will be reconciled, including unchanged declarations.
    #[serde(default)]
    pub configure: Vec<GuestName>,
    /// VMs whose declared configuration differs from the baseline.
    pub changed: Vec<GuestName>,
    /// VMs whose new system generations must be prepared before activation.
    pub stage: Vec<GuestName>,
    /// VMs to stop before applying the configuration.
    pub stop: Vec<GuestName>,
    /// VMs to start after applying the configuration.
    pub start: Vec<GuestName>,
    /// Additional VM impact explicitly reported by the plan producer.
    pub affected: Vec<GuestName>,
    /// VMs to remove from active configuration while retaining recoverable data.
    pub retire: Vec<GuestName>,
    /// Previously retired VMs to restore to active configuration.
    pub restore: Vec<GuestName>,
    /// Existing guests kept running although no longer declared.
    pub retained_undeclared: Vec<GuestName>,
    /// GUI-provider names mapped to unchanged guests whose windows may reconnect.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub gui_reconnect: BTreeMap<GuestName, Vec<GuestName>>,
    /// Optional device ownership handoff details retained for activation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pci_handoff: Option<Value>,
    /// Whether the selected host differs enough to need a reboot.
    #[serde(default)]
    pub host_reboot_required: bool,
    /// Git commit identifying the candidate source tree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<GitRevision>,
    /// Additional protocol metadata retained without treating it as authority.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Selected and observed running system identities for one guest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Observation {
    /// System closure selected for the next guest start.
    pub selected: StorePath,
    /// Currently booted guest closure, or absent if it could not be observed.
    pub running: Option<StorePath>,
}

/// Durable transaction journal binding a release, planned effects and verification evidence.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    /// Journal identity of the whole-machine deployment transaction.
    pub id: TransactionId,
    /// Host boot identity, preventing metadata from a prior boot being trusted.
    pub boot_id: BootId,
    /// Release directory selected by this machine transaction.
    pub release: ReleasePath,
    /// Prior release retained as the rollback baseline.
    pub previous: ReleasePath,
    /// Git commit identifying the candidate source tree.
    pub revision: GitRevision,
    /// Deployment effects recorded before starting the transaction.
    pub plan: Plan,
    /// Latest reported phase of the operation; diagnostic rather than authorization.
    pub phase: Phase,
    /// Per-guest selected and running system observations.
    #[serde(default)]
    pub observed: BTreeMap<GuestName, Observation>,
    /// Observed currently booted dom0 system closure.
    #[serde(default)]
    pub host_running: Option<StorePath>,
    /// Observed dom0 system selected for the next boot.
    #[serde(default)]
    pub host_selected: Option<StorePath>,
    /// Positive Unix timestamp of verification on this transaction.
    #[serde(default)]
    #[serde(deserialize_with = "positive_time")]
    pub verified_at: Option<f64>,
    /// Positive Unix timestamp confirming the selected whole-machine generation.
    #[serde(default)]
    #[serde(deserialize_with = "positive_time")]
    pub generation_verified_at: Option<f64>,
    /// Coordinator version, release fingerprints and recovery diagnostics.
    #[serde(flatten)]
    pub metadata: JournalMetadata,
}

fn positive_time<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<f64>, D::Error> {
    let value = Option::<f64>::deserialize(d)?;
    if value.is_some_and(|t| !t.is_finite() || t <= 0.0) {
        return Err(serde::de::Error::custom("invalid verification timestamp"));
    }
    Ok(value)
}

/// Reject relative paths, control characters and traversal components without touching the filesystem.
pub fn absolute(s: &str) -> Result<&Path> {
    let p = Path::new(s);
    ensure!(
        p.is_absolute() && !s.chars().any(char::is_control),
        "invalid absolute path"
    );

    for c in p.components() {
        if !matches!(c, Component::RootDir | Component::Normal(_)) {
            bail!("invalid path component");
        }
    }
    Ok(p)
}

/// Persistent storage identity, excluding mutable usage and filesystem contents.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Volume {
    /// Qubes pool that owns this volume identifier.
    pub pool: String,
    /// Identifier unique within the owning storage pool.
    pub vid: String,
    /// Foreign source volume, if this is a snapshot rather than independent data.
    pub source: Option<String>,
    /// Whether the volume accepts guest writes.
    pub rw: bool,
    /// Whether guest writes survive shutdown.
    pub save_on_stop: bool,
    /// Whether startup takes a snapshot instead of using independent data.
    pub snap_on_start: bool,
}
