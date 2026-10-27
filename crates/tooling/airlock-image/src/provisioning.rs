//! A private pipe lets an authenticated USB helper wait while an unprivileged process builds.
//! Closing the pipe without a complete same-run success record cancels provisioning. Both sides use
//! the executable Verus gate in `airlock-provisioning-core`; wire decoding, child exit status, Git
//! observations and private-pipe ownership remain trusted adapters. The output is a Nix store identity,
//! not a claim that the build itself or the contents of that store object have been formally verified.

use airlock_nix_core::{identity::GitRevision, store_path::StorePath};
use airlock_provisioning_core as verified;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

/// Helper response emitted only after device checks and credential collection finish.
pub const READY: &[u8] = b"airlock-usb-prepared-v2\n";

/// Actual build outcomes projected into the executable verification gate.
pub use airlock_provisioning_core::BuildOutcome;

/// Original source and private output coordinate, shared by the build owner and waiting USB helper.
#[derive(Clone)]
pub struct BuildRun {
    // Private result link allocated for this invocation, never the global latest link.
    result_link: PathBuf,
    // Original application source revision.
    revision: GitRevision,
    // Original machine source revision.
    machine_revision: GitRevision,
}

impl BuildRun {
    /// Bind one absolute private result link to the source revisions captured before preparation.
    pub fn new(
        result_link: PathBuf,
        revision: GitRevision,
        machine_revision: GitRevision,
    ) -> Result<Self> {
        ensure!(
            result_link.is_absolute() && result_link.to_str().is_some(),
            "build result link must be absolute UTF-8"
        );
        Ok(Self {
            result_link,
            revision,
            machine_revision,
        })
    }

    /// Preserve every original run field at the verified boundary.
    pub(crate) fn evidence(&self) -> verified::BuildRun {
        verified::BuildRun {
            result_link: self.result_link.to_string_lossy().into_owned(),
            revision: self.revision.to_string(),
            machine_revision: self.machine_revision.to_string(),
        }
    }
}

/// Closed completion protocol; the previous unbound success marker grants no write authority.
#[derive(Serialize, Deserialize)]
enum CompletionSchema {
    /// Exact run, source and immutable output binding.
    #[serde(rename = "airlock.usb-build-complete.v2")]
    V2,
}

/// Wire claims received only from this helper's original private pipe.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Completion {
    // Closed wire version, checked before constructing opaque completion evidence.
    schema: CompletionSchema,
    // Build owner's observed child outcome; a failed claim cannot create permission.
    status: airlock_nix_core::admission::CheckStatus,
    // Original private result link.
    result_link: PathBuf,
    // Application source reobserved after the build.
    revision: GitRevision,
    // Machine source reobserved after the build.
    machine_revision: GitRevision,
    // Newly published immutable output supplying the image.
    output: StorePath,
}

/// Opaque successful publication, constructed by the production Verus gate and required by the sender.
/// This trusts process/Git observations and ownership of the private pipe; it is not a remote attestation.
pub struct CompletedBuild {
    // Verified same-run source and output evidence; no serde constructor is provided.
    evidence: verified::CompletedBuild,
}

impl CompletedBuild {
    /// Require actual success, unchanged source, this private result coordinate and a published output.
    pub fn check(
        run: &BuildRun,
        outcome: BuildOutcome,
        revision: &GitRevision,
        machine_revision: &GitRevision,
        result_link: &Path,
        output: Option<StorePath>,
    ) -> Result<Self> {
        let observed = verified::BuildObservation {
            outcome,
            result_link: result_link
                .to_str()
                .context("non-UTF-8 build result")?
                .to_owned(),
            revision: revision.to_string(),
            machine_revision: machine_revision.to_string(),
            output: output.map(|p| p.to_string()),
        };
        let evidence = verified::CompletedBuild::check(run.evidence(), observed)
            .context("image build did not authorize this run, source and output")?;
        Ok(Self { evidence })
    }

    /// Serialize only the original verified completion fields; the caller must then close the pipe.
    pub fn write(&self, output: &mut impl Write) -> Result<()> {
        let run = self.evidence.run();
        let completion = Completion {
            schema: CompletionSchema::V2,
            status: airlock_nix_core::admission::CheckStatus::Passed,
            result_link: PathBuf::from(&run.result_link),
            revision: run.revision.parse()?,
            machine_revision: run.machine_revision.parse()?,
            output: self.evidence.output().parse()?,
        };
        serde_json::to_writer(&mut *output, &completion)?;
        output.write_all(b"\n")?;
        output.flush()?;
        Ok(())
    }

    /// Move the successful same-run publication into the already confirmed waiting writer.
    pub(crate) fn into_evidence(self) -> verified::CompletedBuild {
        self.evidence
    }
}

/// Reserve stdout for the readiness frame while sending ordinary helper output to the terminal.
/// Child tools cannot inherit this pipe, and device or Git log text cannot impersonate readiness.
pub(crate) fn reply_pipe() -> Result<File> {
    let reply = File::from(rustix::io::fcntl_dupfd_cloexec(std::io::stdout(), 3)?);
    rustix::stdio::dup2_stdout(std::io::stderr())?;
    Ok(reply)
}

/// Announce completed preparation, then require a complete same-run success record followed by EOF.
/// Call this only after collecting credentials and checking the selected USB, before any writes.
/// Cancellation, truncated messages and extra input all fail without authorizing provisioning.
pub fn wait_for_build(
    run: &BuildRun,
    input: impl Read,
    mut output: impl Write,
) -> Result<CompletedBuild> {
    output.write_all(READY)?;
    output.flush()?;

    let mut message = Vec::new();
    input.take(16 * 1024 + 1).read_to_end(&mut message)?;
    ensure!(
        message.len() <= 16 * 1024,
        "USB build completion exceeds its limit"
    );
    ensure!(
        !message.is_empty(),
        "Image build was cancelled or did not authorize provisioning; USB was not written."
    );
    let completion: Completion =
        airlock_nix_core::state::parse_json(&message, Path::new("<USB build completion>"))
            .context("Image build did not authorize provisioning; USB was not written.")?;
    let outcome = match completion.status {
        airlock_nix_core::admission::CheckStatus::Passed => BuildOutcome::Success,
        airlock_nix_core::admission::CheckStatus::Failed => BuildOutcome::Failed,
    };
    CompletedBuild::check(
        run,
        outcome,
        &completion.revision,
        &completion.machine_revision,
        &completion.result_link,
        Some(completion.output),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only complete bound success permits the destructive phase; cancellation and legacy markers never do.
    #[test]
    fn cancellation_and_invalid_completion_never_authorize_provisioning() -> Result<()> {
        let run = BuildRun::new(
            "/private/run/image".into(),
            "a".repeat(40).parse()?,
            "b".repeat(40).parse()?,
        )?;
        let complete = CompletedBuild::check(
            &run,
            BuildOutcome::Success,
            &"a".repeat(40).parse()?,
            &"b".repeat(40).parse()?,
            Path::new("/private/run/image"),
            Some(format!("/nix/store/{hash}-image", hash = "c".repeat(32)).parse()?),
        )?;
        let mut valid = Vec::new();
        complete.write(&mut valid)?;
        for input in [
            Vec::new(),
            b"failed\n".to_vec(),
            b"airlock-image-build-succeeded-v1\n".to_vec(),
            valid[..valid.len() - 2].to_vec(),
            [valid.as_slice(), b"extra"].concat(),
            valid.clone(),
        ] {
            let mut output = Vec::new();
            let result = wait_for_build(&run, input.as_slice(), &mut output);
            assert_eq!(output, READY);
            assert_eq!(result.is_ok(), input == valid);
            if input.is_empty() {
                assert!(result.err().unwrap().to_string().contains("cancelled"));
            }
        }
        Ok(())
    }

    /// A closed wire format and the original run both constrain otherwise plausible success records.
    #[test]
    fn conflicting_completion_claims_cannot_create_opaque_evidence() -> Result<()> {
        let revision: GitRevision = "a".repeat(40).parse()?;
        let machine_revision: GitRevision = "b".repeat(40).parse()?;
        let run = BuildRun::new(
            "/private/run/image".into(),
            revision.clone(),
            machine_revision.clone(),
        )?;
        let valid = serde_json::json!({
            "schema": "airlock.usb-build-complete.v2",
            "status": "passed",
            "result_link": "/private/run/image",
            "revision": revision,
            "machine_revision": machine_revision,
            "output": format!("/nix/store/{hash}-image", hash = "c".repeat(32)),
        });
        for (field, value) in [
            ("schema", serde_json::json!("airlock.usb-build-complete.v1")),
            ("status", serde_json::json!("failed")),
            ("result_link", serde_json::json!("/private/stale/image")),
            ("revision", serde_json::json!("d".repeat(40))),
            ("machine_revision", serde_json::json!("e".repeat(40))),
            ("output", serde_json::Value::Null),
            ("unexpected", serde_json::json!(true)),
        ] {
            let mut claim = valid.clone();
            claim[field] = value;
            let bytes = serde_json::to_vec(&claim)?;
            assert!(
                wait_for_build(&run, bytes.as_slice(), Vec::new()).is_err(),
                "accepted {field}"
            );
        }
        let bytes = serde_json::to_vec(&valid)?;
        assert!(wait_for_build(&run, bytes.as_slice(), Vec::new()).is_ok());
        assert!(wait_for_build(&run, vec![b' '; 16 * 1024 + 1].as_slice(), Vec::new()).is_err());
        Ok(())
    }
}
