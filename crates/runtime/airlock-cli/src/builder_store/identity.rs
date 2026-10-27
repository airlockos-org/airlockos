//! A builder base binds its packages and Nix registrations to one immutable generation.
//! Only an explicitly listed predecessor may carry private build output into a successor.

use airlock_nix_core::identity::GuestName;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, num::NonZeroU64};

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
struct Sha256(
    // Lowercase digest text validated before it becomes a base binding.
    String,
);

impl TryFrom<String> for Sha256 {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        ensure!(
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "invalid builder SHA-256 digest"
        );
        Ok(Self(value))
    }
}

impl From<Sha256> for String {
    fn from(value: Sha256) -> Self {
        value.0
    }
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    // Positive generation whose registrations and packages form this base.
    generation: NonZeroU64,
    // Digest of the complete immutable software closure.
    closure_hash: Sha256,
    // Digest of the exact Nix database registration bytes.
    registration_sha256: Sha256,
}

/// Authenticated on-disk builder metadata, independent of its mount locations.
#[derive(PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Identity {
    // Versioned format also identifying the builder role.
    schema: String,
    // Builder namespace; kept distinct from the VM consuming it.
    domain: GuestName,
    // Positive generation checked before any private upper layer is reused.
    generation: NonZeroU64,
    // Digest of the complete immutable software closure.
    closure_hash: Sha256,
    // Digest of the exact Nix database registration bytes.
    registration_sha256: Sha256,
    // Optional pinned flake input index, absent from bases without offline inputs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    flake_inputs_sha256: Option<Sha256>,
    // Authorized earlier bases whose private outputs this base can preserve.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    predecessors: Vec<Binding>,
}

impl Identity {
    /// Reject incompatible role schemas and ambiguous predecessor histories.
    pub(super) fn validate(&self) -> Result<()> {
        let role = self.domain.as_str().strip_suffix("-build-store");
        ensure!(
            role.is_some_and(
                |role| !role.is_empty() && self.schema == format!("airlock.{role}-build-store.v1")
            ),
            "invalid pinned builder identity"
        );
        let mut generations = BTreeSet::new();
        ensure!(
            self.predecessors
                .iter()
                .all(|previous| previous.generation < self.generation
                    && generations.insert(previous.generation)),
            "invalid builder predecessor history"
        );
        Ok(())
    }

    /// Return the builder namespace authenticated by this base.
    pub(super) fn domain(&self) -> &str {
        self.domain.as_str()
    }

    /// Return the digest required before importing the base Nix database.
    pub(super) fn registration_hash(&self) -> &str {
        &self.registration_sha256.0
    }

    /// Return the optional digest required for offline flake input metadata.
    pub(super) fn inputs_hash(&self) -> Option<&str> {
        self.flake_inputs_sha256
            .as_ref()
            .map(|digest| digest.0.as_str())
    }

    /// Permit private output reuse only for an explicitly authorized older base.
    pub(super) fn accepts(&self, previous: &Self) -> bool {
        self.domain == previous.domain
            && self.predecessors.contains(&Binding {
                generation: previous.generation,
                closure_hash: previous.closure_hash.clone(),
                registration_sha256: previous.registration_sha256.clone(),
            })
    }
}
