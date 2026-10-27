//! Validate candidate artifacts in the existing offline validator and archive them in the vault.

use super::{
    candidate::{self, Candidate},
    io::{self, Operation},
    references,
};
use airlock_nix_core::{configuration::SubmittedConfiguration, identity::ConfigurationHash};
use anyhow::{Context, Result, ensure};
use clap::Args;
use serde_json::json;
use std::{fs, path::PathBuf};

/// Existing archive command options, retaining role-specific environment defaults.
#[derive(Args)]
pub(crate) struct Request {
    /// Offline staging VM used only when no candidate archive was supplied.
    #[arg(
        long,
        env = "AIRLOCK_CONFIG_STAGING_VM",
        default_value = "sys-config-staging"
    )]
    staging: airlock_nix_core::identity::GuestName,
    /// Offline validator VM that returns evaluated and validated artifacts.
    #[arg(
        long,
        env = "AIRLOCK_CONFIG_VALIDATOR_VM",
        default_value = "sys-config-validator"
    )]
    validator: airlock_nix_core::identity::GuestName,
    /// Offline vault receiving the validated candidate.
    #[arg(
        long,
        env = "AIRLOCK_CONFIG_VAULT_VM",
        default_value = "sys-config-vault"
    )]
    vault: airlock_nix_core::identity::GuestName,
    /// Caller-supplied staged bundle and manifest; otherwise export them from staging.
    #[arg(long)]
    candidate_tar: Option<PathBuf>,
    /// Validate without requesting archival in the vault.
    #[arg(long)]
    validate_only: bool,
}

/// Require exact original source, complete successful evidence and bound evaluated artifacts.
fn verify(
    operation: &mut Operation,
    submitted: &SubmittedConfiguration,
) -> Result<ConfigurationHash> {
    let archive = operation.file("config-candidate-validated.tar");
    let candidate = Candidate::load(operation, &archive, submitted, None)?;
    candidate.copy_evidence(operation, "config-candidate")?;
    references::validate(
        &operation.file("config-candidate-topology.json"),
        &operation.file("config-candidate-domain-references.json"),
    )?;
    Ok(candidate.archive_hash().clone())
}

/// Preserve archive results on every handled failure without confusing them with deployment authority.
pub(super) fn execute(request: Request) -> Result<()> {
    let mut operation = Operation::new("config-archive")?;
    let staging = request.staging.as_str();
    let validator = request.validator.as_str();
    let vault = request.vault.as_str();
    let export = io::setting(
        "AIRLOCK_CONFIG_CANDIDATE_EXPORT_SERVICE",
        "airlock.Config.CandidateExport",
    );
    let validate = io::setting(
        "AIRLOCK_CONFIG_CANDIDATE_VALIDATE_SERVICE",
        "airlock.Config.ValidateCandidate",
    );
    let archive = io::setting(
        "AIRLOCK_CONFIG_ARCHIVE_SERVICE",
        "airlock.Config.ArchiveCandidate",
    );
    let mut commit = String::new();
    let mut vault_commit = String::new();
    let mut submitted = None;
    let mut validated_candidate_sha256 = None;
    let result = (|| {
        operation.control_domain()?;
        if request.candidate_tar.is_none() {
            operation.offline(staging)?;
            operation.start(staging)?;
        }
        operation.offline(validator)?;
        operation.start(validator)?;
        if !request.validate_only {
            operation.offline(vault)?;
            operation.start(vault)?;
        }
        let staged = operation.file("config-candidate-staged.tar");
        let validated = operation.file("config-candidate-validated.tar");
        if let Some(candidate) = &request.candidate_tar {
            fs::copy(candidate, &staged)?;
        } else {
            operation.rpc(
                staging,
                &export,
                None,
                &staged,
                &operation.file("config-candidate-export.stderr.log"),
            )?;
        }
        let source = candidate::submitted(&staged)?;
        commit = source.commit.to_string();
        submitted = Some(source);
        operation.rpc(
            validator,
            &validate,
            Some(&staged),
            &validated,
            &operation.file("config-candidate-validate.stderr.log"),
        )?;
        validated_candidate_sha256 = Some(verify(
            &mut operation,
            submitted.as_ref().context("missing original submission")?,
        )?);
        if !request.validate_only {
            let output = operation.file("config-vault-archive.log");
            operation.rpc(
                vault,
                &archive,
                Some(&validated),
                &output,
                &operation.file("config-vault-archive.stderr.log"),
            )?;
            let archived = io::result(&output, "airlock.config-vault-archive.v1")?;
            io::save(&operation.file("config-vault-archive.json"), &archived)?;
            ensure!(
                archived["status"] == "passed" && archived["candidate_commit"] == commit,
                "vault archived a different candidate or reported failure"
            );
            vault_commit = archived["vault_commit"]
                .as_str()
                .context("missing vault commit")?
                .into();
        }
        Ok(())
    })();
    let mut receipt = json!({"schema":"airlock.config-archive.v1", "status":if result.is_ok() {"passed"} else {"failed"}, "reason":match &result { Ok(()) => "config candidate validated in sys-config-validator".into(), Err(error) => format!("{error:#}") }, "staging":staging,"validator":validator,"vault":vault,"candidate_export_service":export,"candidate_validate_service":validate,"archive_service":archive,"candidate_commit":commit,"validation_commit":commit,"vault_commit":vault_commit,
        "submitted":submitted,"validated_candidate_sha256":validated_candidate_sha256});
    for (key, file) in [
        ("staged_candidate_tar", "config-candidate-staged.tar"),
        ("validated_candidate_tar", "config-candidate-validated.tar"),
        ("topology", "config-candidate-topology.json"),
        ("system", "config-candidate-system.json"),
        (
            "domain_references",
            "config-candidate-domain-references.json",
        ),
        ("command_log", "config-archive.commands.log"),
        ("export_stderr", "config-candidate-export.stderr.log"),
        ("validate_stderr", "config-candidate-validate.stderr.log"),
        ("bundle_verify_log", "config-candidate-bundle-verify.log"),
        ("vault_archive_log", "config-vault-archive.log"),
        ("vault_archive_stderr", "config-vault-archive.stderr.log"),
    ] {
        receipt[key] = json!(operation.file(file));
    }
    for (key, file) in [
        ("validation", "config-candidate-validation.json"),
        (
            "domain_references_result",
            "config-candidate-domain-references.json",
        ),
        ("vault_archive", "config-vault-archive.json"),
    ] {
        receipt[key] = io::optional(&operation.file(file));
    }
    io::save(&operation.file("config-archive.json"), &receipt)?;
    if result.is_ok() {
        println!("{receipt}");
    }
    result
}
