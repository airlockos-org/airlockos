//! Native Qubes callbacks pass Rust values directly to the storage engine.
//! Python owns upstream configuration objects; this interface owns Airlock view
//! metadata and immutable lifecycle decisions. CLI serialization stays separate.

pub use airlock_deployment_core::volume_lifecycle::{Action, ImmutableOptions, ViewKind};
use airlock_nix_core::identity::GuestName;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{
    num::NonZeroU64,
    path::{Path, PathBuf},
};

/// Immutable view metadata observed from an upstream volume.
#[derive(Clone, Deserialize, Serialize)]
pub struct Definition {
    /// Supported metadata image or filtered external-data view.
    #[serde(deserialize_with = "view_kind", serialize_with = "view_kind_text")]
    pub view_kind: ViewKind,
    /// Metadata image or currently attached transient mapper.
    pub view_path: Option<PathBuf>,
    /// Immutable external-data extent map.
    pub blob_map_path: Option<PathBuf>,
    /// Positive external-data address space.
    pub blob_logical_size: Option<NonZeroU64>,
    /// Retained generation manifest when present.
    pub manifest_path: Option<PathBuf>,
}

/// Airlock-owned fields separated from upstream's ordinary volume kwargs.
#[derive(Deserialize, Serialize)]
pub struct Metadata {
    /// Store namespace; existing legacy metadata may omit it.
    pub domain_name: Option<String>,
    /// Positive generation, encoded as decimal text in upstream persisted configuration.
    #[serde(
        default,
        deserialize_with = "optional_number",
        serialize_with = "generation_text"
    )]
    pub generation: Option<NonZeroU64>,
    /// Immutable closure digest supplied by generation admission.
    pub closure_hash: Option<String>,
    /// Persisted view configuration; transient mapper paths are removed during normalization.
    #[serde(flatten)]
    pub definition: Definition,
}

/// Constructor inputs; arbitrary upstream kwargs stay in Python and never enter this request.
pub struct NormalizationInput {
    /// Consuming guest used only when synthesizing a missing driver identity.
    pub domain: Option<GuestName>,
    /// Upstream volume key, defaulting to store only for identity synthesis.
    pub name: String,
    /// Preserve an explicitly supplied upstream vid, including explicit None.
    pub vid_supplied: bool,
    /// Requested write access, rejected when true.
    pub writable: bool,
    /// Requested snapshot derivation, rejected when true.
    pub snapshot: bool,
    /// A source Python object was supplied, which immutable Airlock views forbid.
    pub has_source: bool,
    /// Airlock metadata whose paths and identities must be normalized.
    pub metadata: Metadata,
}

/// Normalized fields and opaque immutable options passed back to the upstream constructor.
///
/// ```compile_fail
/// use airlock_dom0_service::storage_plugin::Normalized;
/// fn substitute(result: &mut Normalized) { result.metadata.definition.view_path = None; }
/// ```
pub struct Normalized {
    /// Synthesized driver identity; absent means retain the caller's original vid.
    pub(crate) generated_vid: Option<String>,
    /// Normalized Airlock fields, with no persisted transient mapper path.
    pub(crate) metadata: Metadata,
    /// Verified options; no caller-provided writable or snapshot flag can survive.
    pub(crate) options: ImmutableOptions,
}

impl Normalized {
    /// Borrow normalized Airlock metadata without allowing a transient path to be substituted.
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    /// Borrow the immutable options accepted by the verified constructor gate.
    pub fn options(&self) -> &ImmutableOptions {
        &self.options
    }

    /// Borrow a synthesized driver identity, or retain the upstream caller's original vid.
    pub fn generated_vid(&self) -> Option<&str> {
        self.generated_vid.as_deref()
    }
}

/// Retained generation coordinates used together for mapper and running-reference effects.
pub struct GenerationIdentity {
    /// Store namespace authenticated further by existing admission and view checks.
    pub domain: String,
    /// Positive generation within that namespace.
    pub generation: NonZeroU64,
}

/// One typed callback; absence of a retained identity supports legacy metadata volumes only.
pub struct LifecycleRequest {
    /// Closed lifecycle operation, decoded by the verified parser.
    pub action: Action,
    /// Pool root whose admission lock protects the selected effects.
    pub root: PathBuf,
    /// Retained namespace and generation, when both are available.
    pub identity: Option<GenerationIdentity>,
    /// Independent running-reference key for this volume.
    pub name: String,
    /// Current view metadata and transient device path.
    pub definition: Definition,
}

/// Observed byte accounting; usage is absent when only constant-time capacity was requested.
#[derive(Serialize)]
pub struct Stats {
    /// Guest-visible volume bytes or filesystem pool capacity.
    pub size: u64,
    /// Allocated bytes, omitted when no usage traversal was requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<u64>,
}

/// Normalize immutable constructor inputs without transporting upstream kwargs through JSON.
pub fn normalize(input: NormalizationInput) -> Result<Normalized> {
    crate::store::qubes_volume::normalize_typed(input)
}

/// Perform one complete callback and return its current device path directly.
pub fn lifecycle(request: LifecycleRequest) -> Result<Option<PathBuf>> {
    crate::store::qubes_volume::execute_typed(request)
}

/// Normalize the pool root and optionally initialize its existing filesystem namespace.
pub fn pool_root(root: &Path, create: bool) -> Result<PathBuf> {
    crate::store::qubes_inspect::pool_root(root, create)
}

/// Validate immutable source files and retained view metadata.
pub fn verify(definition: &Definition) -> Result<()> {
    crate::store::qubes_inspect::verify(definition)
}

/// Observe bounded pool accounting without following links.
pub fn pool_stats(root: &Path, include_usage: bool) -> Result<Stats> {
    crate::store::qubes_inspect::pool_stats(root, include_usage)
}

/// Observe volume accounting without coordinating lifecycle changes in Python.
pub fn volume_stats(definition: &Definition, fallback_size: u64) -> Result<Stats> {
    crate::store::qubes_inspect::volume_stats(definition, fallback_size)
}

/// Decode legacy decimal strings and integer fields into one positive numeric type.
fn optional_number<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> Result<Option<NonZeroU64>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Number {
        /// Native JSON integer spelling.
        Integer(NonZeroU64),
        /// Upstream persisted decimal spelling.
        Text(String),
    }
    Option::<Number>::deserialize(decoder)?
        .map(|number| match number {
            Number::Integer(number) => Ok(number),
            Number::Text(number) => number.parse().map_err(serde::de::Error::custom),
        })
        .transpose()
}

/// Preserve Qubes' decimal-string generation representation at the CLI boundary.
fn generation_text<S: serde::Serializer>(
    value: &Option<NonZeroU64>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    value.map(|number| number.to_string()).serialize(serializer)
}

/// Decode the same view vocabulary used by executable verified decisions.
fn view_kind<'de, D: serde::Deserializer<'de>>(decoder: D) -> Result<ViewKind, D::Error> {
    let name = String::deserialize(decoder)?;
    ViewKind::parse(&name).ok_or_else(|| serde::de::Error::custom("unsupported storage view kind"))
}

/// Encode the stable upstream view spelling.
fn view_kind_text<S: serde::Serializer>(kind: &ViewKind, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(kind.name())
}
