//! Candidate admission keeps typed transport claims distinct from freshly inspected storage records.
//! Shared wire types project into the production Verus authentication and candidate-binding gates.

use crate::model::{
    AdmissionSender, CheckStatus, GenerationApproval, GenerationInfo, GenerationProvenance,
};
use crate::store::AdmissionReceipt;
use airlock_deployment_core::admission as verified;
use airlock_nix_core::{
    admission::{self, ExpectedAdmission},
    root_artifact::RootDescriptor,
};
use anyhow::{Context, Result};

/// A receipt matched against its retained, verified generation and recorded admission provenance.
pub(super) struct CheckedAdmission {
    // Original typed transport claims, available only through immutable access.
    receipt: AdmissionReceipt,
    // Fresh inspection; never converted back to generic JSON for decisions.
    info: GenerationInfo,
    // Opaque verified evidence; construction requires all independent storage and approval facts.
    evidence: admission::Authenticated,
}

impl CheckedAdmission {
    /// Authenticate receipt claims against independently inspected, verified and retained storage.
    pub(super) fn check(receipt: AdmissionReceipt, info: GenerationInfo) -> Result<Self> {
        let root: RootDescriptor = serde_json::from_value(
            info.root_artifact
                .clone()
                .context("missing generation root artifact")?,
        )?;
        let provenance: GenerationProvenance = serde_json::from_value(info.provenance.clone())
            .context("invalid generation provenance")?;
        let approval: GenerationApproval =
            serde_json::from_value(info.approval.clone()).context("invalid generation approval")?;
        let inspection = admission::Inspection {
            namespace: info.domain.as_str().to_owned(),
            generation: info.generation.get(),
            manifest: info
                .manifest
                .to_str()
                .context("non-UTF-8 generation manifest")?
                .to_owned(),
            artifacts: verified::Artifacts {
                system: info.system.as_str().to_owned(),
                root_source: info.root_source.as_str().to_owned(),
                kernel: info.kernel_name.clone(),
                root: admission::root_identity(&root)?,
            },
            closure_source: info.closure_source.as_str().to_owned(),
            closure_hash: info.store.closure_hash.clone(),
            source: verified::Source {
                revision: provenance.source_revision.as_str().to_owned(),
                lock_hash: provenance.lock_hash.as_str().to_owned(),
            },
            passed: info.status == CheckStatus::Passed,
            verified: info.verification.status == CheckStatus::Passed,
            retained: info.retention.as_ref().is_some_and(|r| r.retain),
            sender: match approval._approved_by {
                AdmissionSender::Controller => admission::Sender::Controller,
                AdmissionSender::Assistant => admission::Sender::Assistant,
            },
            approval_source: approval.source.as_str().to_owned(),
        };
        let evidence = admission::Authenticated::check(receipt.evidence()?, inspection).context(
            "admission receipt identity mismatch or independently inspected authority mismatch",
        )?;
        Ok(Self {
            receipt,
            info,
            evidence,
        })
    }

    /// Consume independently checked storage evidence through this exact candidate's verified binding gate.
    pub(super) fn bind(
        self,
        expected: &ExpectedAdmission,
        candidate: &str,
    ) -> Result<(AdmissionReceipt, admission::Bound)> {
        let bound = self
            .evidence
            .bind(expected.evidence(candidate)?)
            .context("admission artifacts, sender or provenance differ from candidate")?;
        Ok((self.receipt, bound))
    }

    /// Original claims after comparison with the independently inspected generation.
    pub(super) fn receipt(&self) -> &AdmissionReceipt {
        &self.receipt
    }

    /// Complete inspection without erasing its typed identity and selection fields.
    pub(super) fn info(&self) -> &GenerationInfo {
        &self.info
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    /// Independent committed inspection and admission message for one retained, inactive generation.
    fn records() -> (Value, Value) {
        let system = format!("/nix/store/{hash}-system", hash = "a".repeat(32));
        let root = format!("/nix/store/{hash}-root/root.img", hash = "b".repeat(32));
        let source = format!("/nix/store/{hash}-closure", hash = "c".repeat(32));
        let artifact = json!({"schema":"airlock.root-artifact.v1", "sha256":"d".repeat(64),
            "logical_bytes":65536, "payload_bytes":64, "format":"ext4", "boot_abi":"airlock.nix-closure-root.v1"});
        let info = json!({"schema":"airlock.closure-store.generation-info.v1", "status":"passed",
            "domain":"app-runtime-store", "generation":2, "selected":false, "manifest":"/pool/app/2/manifest.json",
            "system":system, "root_source":root, "root_artifact":artifact, "kernel_name":"kernel", "closure_source":source,
            "store":{"mode":"shared-closure", "closure_hash":"e".repeat(64), "mountpoint":"/nix/store", "device":"/dev/xvde", "blob_device":"/dev/xvdf", "view_backend":"erofs-objectmap"},
            "verification":{"status":"passed"}, "retention":{"retain":true},
            "approval":{"transport":"qrexec", "approved_by":"sys-ctrl", "source":source},
            "provenance":{"source_revision":"f".repeat(40), "lock_hash":"a".repeat(64)}});
        let receipt = json!({"schema":"airlock.closure-store.admission.v1", "status":"passed", "transport":"qrexec",
            "domain":"app", "generation":2, "current_generation":1, "activated":false, "retained":true,
            "manifest":"/pool/app/2/manifest.json", "system":system, "root_source":root, "root_artifact":artifact,
            "kernel_name":"kernel", "closure_hash":"e".repeat(64), "source_revision":"f".repeat(40), "lock_hash":"a".repeat(64)});
        (receipt, info)
    }

    /// Nominal receipt shape and independently loaded authority must both validate.
    fn checked(receipt: Value, info: Value) -> Result<CheckedAdmission> {
        CheckedAdmission::check(
            serde_json::from_value(receipt)?,
            serde_json::from_value(info)?,
        )
    }

    /// Independently declared candidate artifacts, kept separate from the admitted generation's provenance.
    fn requirement(receipt: &Value, info: &Value) -> ExpectedAdmission {
        serde_json::from_value(json!({
            "domain":receipt["domain"], "system":receipt["system"], "root_source":receipt["root_source"],
            "closure_source":info["closure_source"], "kernel_name":receipt["kernel_name"],
            "source_revision":receipt["source_revision"], "lock_hash":receipt["lock_hash"], "root_artifact":receipt["root_artifact"],
        })).unwrap()
    }

    #[test]
    fn candidate_binding_checks_actual_artifacts_before_accepting_historical_provenance()
    -> Result<()> {
        let (receipt, info) = records();
        let fingerprint = "c".repeat(64);
        let mut expected = requirement(&receipt, &info);
        expected.source_revision = "b".repeat(40).parse()?;
        assert!(
            checked(receipt.clone(), info.clone())?
                .bind(&expected, &fingerprint)
                .is_err()
        );

        let mut reused = receipt.clone();
        reused["generation_reused"] = json!(true);
        let (original, bound) =
            checked(reused.clone(), info.clone())?.bind(&expected, &fingerprint)?;
        assert_eq!(bound.generation(), original.generation.get());
        assert_eq!(bound.source().revision, "f".repeat(40));
        assert_eq!(bound.guest(), "app");

        expected.root_artifact.sha256 = "b".repeat(64);
        assert!(
            checked(reused.clone(), info.clone())?
                .bind(&expected, &fingerprint)
                .is_err()
        );
        let expected = requirement(&receipt, &info);
        let mut other_sender = info.clone();
        other_sender["approval"]["approved_by"] = json!("usr-assistant");
        assert!(
            checked(reused, other_sender)?
                .bind(&expected, &fingerprint)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn candidate_identity_is_checked_without_erasing_inspection_types() -> Result<()> {
        let (receipt, info) = records();
        let admission = checked(receipt.clone(), info.clone())?;
        assert!(admission.evidence.controller());
        // Candidate files compare retained receipts on retry; typing must preserve the wire record.
        assert_eq!(serde_json::to_value(admission.receipt())?, receipt);
        for reused in [false, true] {
            let mut original = receipt.clone();
            original["generation_reused"] = json!(reused);
            let typed: AdmissionReceipt = serde_json::from_value(original.clone())?;
            assert_eq!(serde_json::to_value(typed)?, original);
        }
        assert_eq!(admission.info().generation.get(), 2);
        assert!(!admission.info().selected);

        for (field, value) in [
            ("domain", json!("other")),
            ("generation", json!(3)),
            ("manifest", json!("/other/manifest.json")),
            ("root_source", json!("/tmp/manual-root.img")),
            ("kernel_name", json!("other")),
            ("closure_hash", json!("b".repeat(64))),
            ("source_revision", json!("a".repeat(40))),
            ("lock_hash", json!("b".repeat(64))),
            ("activated", json!(true)),
            ("retained", json!(false)),
            ("root_artifact", Value::Null),
        ] {
            let mut invalid = receipt.clone();
            invalid[field] = value;
            assert!(checked(invalid, info.clone()).is_err(), "accepted {field}");
        }
        let mut invalid = info.clone();
        invalid["verification"]["status"] = json!("failed");
        assert!(checked(receipt.clone(), invalid).is_err());
        let mut invalid = info.clone();
        invalid["retention"]["retain"] = json!(false);
        assert!(checked(receipt.clone(), invalid).is_err());
        let mut wrong_root = receipt.clone();
        wrong_root["root_artifact"]["sha256"] = json!("c".repeat(64));
        assert!(checked(wrong_root, info.clone()).is_err());

        let mut other_sender = info.clone();
        other_sender["approval"]["approved_by"] = json!("usr-assistant");
        assert!(!checked(receipt, other_sender)?.evidence.controller());
        Ok(())
    }

    #[test]
    fn missing_selection_or_unknown_protocol_cannot_mean_inactive_admission() {
        let (receipt, info) = records();
        for field in ["activated", "retained", "current_generation"] {
            let mut missing = receipt.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(
                checked(missing, info.clone()).is_err(),
                "accepted missing {field}"
            );
        }
        let mut missing = info.clone();
        missing.as_object_mut().unwrap().remove("selected");
        assert!(checked(receipt.clone(), missing).is_err());
        for (field, value) in [
            ("schema", json!("unknown")),
            ("transport", json!("local")),
            ("retained", json!("true")),
        ] {
            let mut invalid = receipt.clone();
            invalid[field] = value;
            assert!(checked(invalid, info.clone()).is_err());
        }
        let mut empty_selection = receipt;
        empty_selection["current_generation"] = Value::Null;
        assert!(checked(empty_selection, info).is_ok());
    }
}
