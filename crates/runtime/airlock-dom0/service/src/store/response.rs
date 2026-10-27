//! Distinct typed storage responses shared by producers and setup/candidate receivers.

use airlock_nix_core::{artifact::RootDescriptor, identity::StoreNamespace};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A resolved retained root belongs to a storage namespace and its original source.
/// Filesystem authentication stays with the loader, and setup checks the requested binding.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResolvedRoot {
    /// Namespace searched by the storage service.
    pub domain: StoreNamespace,
    /// Original boot-root identity used in the lookup.
    pub root_source: String,
    /// Retained physical root image to import.
    pub image: PathBuf,
    /// Sparse artifact descriptor authenticated by the storage service.
    pub artifact: RootDescriptor,
}

pub(crate) use airlock_nix_core::admission::AdmissionReceipt;

/// The retained-generation lookup has its own wire protocol and outcomes.
#[derive(Serialize, Deserialize)]
pub(crate) struct GenerationMatch {
    /// Known lookup protocol, distinct from committed generation or install receipts.
    pub schema: GenerationMatchSchema,
    /// Runtime namespace whose retained records were searched.
    pub domain: airlock_nix_core::identity::StoreNamespace,
    /// Missing cannot silently select a fallback admission path.
    #[serde(flatten)]
    pub outcome: GenerationMatchOutcome,
}

/// Closed lookup response protocol.
#[derive(Serialize, Deserialize)]
pub(crate) enum GenerationMatchSchema {
    /// Lookup performed by the existing pool API.
    #[serde(rename = "airlock.closure-store.generation-match.v1")]
    V1,
}

/// Lookup is evidence for inspection, never permission to execute an effect.
#[derive(Serialize, Deserialize)]
#[serde(tag = "status")]
pub(crate) enum GenerationMatchOutcome {
    /// Committed records contain an eligible candidate generation.
    #[serde(rename = "found")]
    Found {
        /// Positive generation whose full identity still needs independent inspection.
        generation: crate::model::GenerationId,
        /// Independently addressed committed manifest returned by the pool.
        manifest: PathBuf,
        /// Immutable closure hash retained in that manifest.
        closure_hash: airlock_nix_core::identity::LockHash,
    },
    /// No retained generation matches; deployments refuse new implicit admission.
    #[serde(rename = "missing")]
    Missing,
}
