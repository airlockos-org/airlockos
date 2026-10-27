//! Decode boot snapshots at the filesystem edge; no untyped field grants restoration.

use crate::model::{
    GenerationId, Phase, ReleaseFingerprint, ReleasePath, Selection, StorePath, TransactionId,
};
use airlock_deployment_core::host::{Observation, boot};
use airlock_nix_core::identity::{GuestName, LockHash};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Canonical guest namespace; names exclude dom0 and generations exclude zero.
pub(super) type Generations = BTreeMap<GuestName, GenerationId>;

/// Versioned storage protocol, with legacy compatibility distinct from current guarantees.
#[derive(Serialize, Deserialize)]
#[serde(tag = "schema", deny_unknown_fields)]
pub(super) enum BootBinding {
    /// Legacy bindings authenticate a system but did not capture the full host/release identity.
    #[serde(rename = "airlock.host-machine.v1")]
    Legacy {
        /// Immutable host system recorded by the legacy producer.
        system: StorePath,
        /// Nullable but mandatory original machine selection.
        #[serde(deserialize_with = "selection")]
        selection: Option<Selection>,
        /// Exact guest snapshot, including an explicitly empty object.
        staged: Generations,
    },
    /// Current bindings retain full host receipt and release content identity.
    #[serde(rename = "airlock.host-machine.v2")]
    Current {
        /// Immutable system selected by the boot entry.
        system: StorePath,
        /// Positive host storage generation whose directory owns this binding.
        generation: GenerationId,
        /// Digest of the complete authenticated host receipt.
        host_record: LockHash,
        /// Nullable but mandatory selected transaction; null means an image snapshot.
        #[serde(deserialize_with = "selection")]
        selection: Option<Selection>,
        /// Manifest/topology digest, present exactly when a release is selected.
        #[serde(deserialize_with = "fingerprint")]
        release_fingerprint: Option<ReleaseFingerprint>,
        /// Complete guest-generation snapshot, never inferred from a nonempty subset.
        staged: Generations,
    },
}

/// Require the nullable field to exist; omission cannot silently select image restoration.
fn selection<'de, D: serde::Deserializer<'de>>(decoder: D) -> Result<Option<Selection>, D::Error> {
    Option::deserialize(decoder)
}

/// Require an explicit nullable release fingerprint in the current wire protocol.
fn fingerprint<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> Result<Option<ReleaseFingerprint>, D::Error> {
    Option::deserialize(decoder)
}

/// Exact journal coordinates needed for boot, retaining the entire original document.
#[derive(Serialize, Deserialize)]
pub(super) struct Status {
    /// Transaction identity checked against selection and the journal filename.
    pub id: TransactionId,
    /// Selected release, not an observation of live machine state.
    pub release: ReleasePath,
    /// Original rollback baseline.
    pub previous: ReleasePath,
    /// Only completed verification permits boot restoration.
    pub phase: Phase,
    /// Preserve all other journal data when publishing latest.json.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl BootBinding {
    /// Borrow the original selection for loading independent release and journal evidence.
    pub(super) fn selection(&self) -> Option<&Selection> {
        match self {
            Self::Legacy { selection, .. } | Self::Current { selection, .. } => selection.as_ref(),
        }
    }

    /// Retain host identity and canonical documents in the executable verified representation.
    pub(super) fn verified(&self) -> Result<boot::Binding> {
        let (host, selection, staged, fingerprint) = match self {
            Self::Legacy {
                system,
                selection,
                staged,
            } => (
                boot::Host::Legacy {
                    system: system.to_string(),
                },
                selection,
                staged,
                None,
            ),
            Self::Current {
                system,
                generation,
                host_record,
                selection,
                release_fingerprint,
                staged,
            } => {
                ensure!(
                    selection.is_some() == release_fingerprint.is_some(),
                    "incomplete boot release binding"
                );
                (
                    boot::Host::Checked(Observation {
                        system: system.to_string(),
                        generation: generation.to_string(),
                        record: host_record.to_string(),
                    }),
                    selection,
                    staged,
                    release_fingerprint.as_ref(),
                )
            }
        };
        let selection = selection
            .as_ref()
            .map(|s| -> Result<_> {
                Ok(boot::Selection {
                    release: s.release.to_string(),
                    previous: s.previous.to_string(),
                    attempt: s.transaction.as_str().into(),
                    profile: s.profile.to_string(),
                    document: serde_json::to_string(s)?,
                    fingerprint: fingerprint.map(ToString::to_string),
                })
            })
            .transpose()?;

        Ok(boot::Binding {
            host,
            selection,
            guests: guests(staged)?,
        })
    }
}

/// One projection creates both the canonical guest document and its mathematical entries.
pub(super) fn guests(map: &Generations) -> Result<boot::Guests> {
    Ok(boot::Guests {
        entries: map
            .iter()
            .map(|(name, generation)| boot::Guest {
                domain: name.to_string(),
                generation: generation.get(),
            })
            .collect(),
        document: serde_json::to_string(map)?,
    })
}

impl Status {
    /// Reduce only known phases; all other progress remains incomplete for boot recovery.
    pub(super) fn verified(&self) -> Result<boot::Status> {
        Ok(boot::Status {
            attempt: self.id.as_str().into(),
            release: self.release.to_string(),
            previous: self.previous.to_string(),
            phase: match self.phase {
                Phase::HostBootSelection => boot::Phase::Selecting,
                Phase::Complete => boot::Phase::Complete,
                Phase::RebootRequired => boot::Phase::RebootRequired,
                _ => boot::Phase::Incomplete,
            },
            document: serde_json::to_string(self)?,
        })
    }
}
