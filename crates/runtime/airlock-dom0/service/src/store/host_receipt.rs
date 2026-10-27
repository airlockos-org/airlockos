//! Host boot records cross coordinator/storage boundaries as one typed identity.
//! Parsing validates shape; the storage loader authenticates files, retention and checksums.

use crate::model::{GenerationId, StorePath};
use airlock_deployment_core::host::Observation;
use airlock_nix_core::identity::LockHash;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, path::PathBuf};

/// Closed host-record protocol; guest admission receipts are not host generations.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum Schema {
    /// Retained host boot identity and its complete immutable storage metadata.
    #[serde(rename = "airlock.host-store.v1")]
    V1,
}

/// Complete publication/validation result, distinct from a deployment approval.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct HostReceipt {
    /// Known host boot-record schema.
    pub schema: Schema,
    /// Exact immutable Nix host system.
    pub system: StorePath,
    /// Positive generation in the host storage namespace.
    pub generation: GenerationId,
    /// Committed generation manifest authenticated by the storage loader.
    pub manifest: PathBuf,
    /// Complete closure identity retained by the generation.
    pub closure_hash: LockHash,
    /// Registration database input for this host generation.
    pub registration: PathBuf,
    /// Authenticated registration bytes.
    pub registration_sha256: LockHash,
    /// Immutable metadata image belonging to the host generation.
    pub metadata_image: PathBuf,
    /// Authenticated metadata-image bytes.
    pub metadata_image_sha256: LockHash,
    /// External-data map paired with the metadata image.
    pub blob_map: PathBuf,
    /// Authenticated external-data map bytes.
    pub blob_map_sha256: LockHash,
    /// Omission preserves old active records; malformed/null values never mean active.
    #[serde(
        default,
        deserialize_with = "retirement",
        skip_serializing_if = "Option::is_none"
    )]
    pub retired: Option<bool>,
    /// Publication timing is diagnostic and excluded from the durable identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timings: Option<Value>,
    /// Preserve extensions in the identity rather than silently dropping unclassified metadata.
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

/// An explicitly supplied retirement marker must be boolean.
fn retirement<'de, D: serde::Deserializer<'de>>(decoder: D) -> Result<Option<bool>, D::Error> {
    bool::deserialize(decoder).map(Some)
}

impl HostReceipt {
    /// Reduce nominal Rust identities only after checking active status and path shape.
    pub(crate) fn observation(&self) -> Result<Observation> {
        ensure!(self.retired != Some(true), "host generation is retired");
        for path in [
            &self.manifest,
            &self.registration,
            &self.metadata_image,
            &self.blob_map,
        ] {
            ensure!(
                path.is_absolute()
                    && !path
                        .components()
                        .any(|part| part == std::path::Component::ParentDir),
                "invalid host generation metadata path"
            );
        }

        Ok(Observation {
            system: self.system.as_str().into(),
            generation: self.generation.to_string(),
            record: self.binding()?.to_string(),
        })
    }

    /// Bind all recorded identities and checksums; timing observations do not change a generation.
    pub(crate) fn binding(&self) -> Result<LockHash> {
        let mut record = serde_json::to_value(self)?;
        record
            .as_object_mut()
            .expect("host receipt object")
            .remove("timings");

        Ok(crate::state::digest(&record)?.parse()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A complete retained record uses the same mandatory identity fields as publication.
    fn record() -> Value {
        json!({"schema":"airlock.host-store.v1", "system":"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-host",
            "generation":1, "manifest":"/pool/manifest.json", "closure_hash":"a".repeat(64),
            "registration":"/pool/registration", "registration_sha256":"b".repeat(64),
            "metadata_image":"/pool/metadata.erofs", "metadata_image_sha256":"c".repeat(64),
            "blob_map":"/pool/map.json", "blob_map_sha256":"d".repeat(64)})
    }

    /// Missing, malformed, retired and structurally invalid results cannot become observations.
    #[test]
    fn host_receipt_shape_and_active_identity_are_mandatory() -> Result<()> {
        let valid = record();
        serde_json::from_value::<HostReceipt>(valid.clone())?.observation()?;
        for (field, value) in [
            ("schema", json!("guest-receipt")),
            ("generation", json!(0)),
            ("generation", json!("1")),
            ("retired", Value::Null),
            ("metadata_image_sha256", json!("bad")),
        ] {
            let mut invalid = valid.clone();
            invalid[field] = value;
            assert!(
                serde_json::from_value::<HostReceipt>(invalid).is_err(),
                "accepted {field}"
            );
        }
        for field in ["system", "generation", "manifest", "blob_map_sha256"] {
            let mut invalid = valid.clone();
            invalid.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<HostReceipt>(invalid).is_err());
        }
        for (field, value) in [
            ("retired", json!(true)),
            ("manifest", json!("relative")),
            ("blob_map", json!("/pool/../outside")),
        ] {
            let mut invalid = valid.clone();
            invalid[field] = value;
            assert!(
                serde_json::from_value::<HostReceipt>(invalid)?
                    .observation()
                    .is_err()
            );
        }
        Ok(())
    }

    /// Diagnostic timing can vary; storage identities, checksums and preserved extensions cannot.
    #[test]
    fn host_record_binding_covers_all_non_timing_metadata() -> Result<()> {
        let valid = record();
        let identity = serde_json::from_value::<HostReceipt>(valid.clone())?.binding()?;
        let mut timed = valid.clone();
        timed["timings"] = json!({"elapsed":20});
        assert_eq!(
            serde_json::from_value::<HostReceipt>(timed)?.binding()?,
            identity
        );
        for (field, value) in [
            ("generation", json!(2)),
            ("manifest", json!("/pool/other.json")),
            ("metadata_image_sha256", json!("e".repeat(64))),
            ("extra_storage_identity", json!("new")),
        ] {
            let mut changed = valid.clone();
            changed[field] = value;
            assert_ne!(
                serde_json::from_value::<HostReceipt>(changed)?.binding()?,
                identity
            );
        }
        Ok(())
    }
}
