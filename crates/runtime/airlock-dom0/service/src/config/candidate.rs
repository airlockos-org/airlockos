//! Authenticate one private received snapshot before exposing its documents to source resolution.
//! Archive extraction, Git inspection and hashing are adapters to the shared production Verus gates.

use super::io::{self, Operation};
use airlock_nix_core::{
    configuration::{
        CandidateDocuments, CandidateFiles, CandidateManifest, SubmittedConfiguration,
        ValidatedConfiguration, ValidationRecord, file_hash,
    },
    identity::ConfigurationHash,
};
use anyhow::{Context, Result, ensure};
use std::{
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

/// Only these flat regular files may cross the existing validated-candidate channel.
const MEMBERS: &[&str] = &[
    "config.bundle",
    "validation.json",
    "manifest.json",
    "topology.json",
    "system.json",
    "prepared-source.tar",
];

/// Private source snapshot and checked document evidence for one candidate.
pub(super) struct Candidate {
    // Owns extracted documents and the stable archive snapshot through resolution.
    directory: tempfile::TempDir,
    // Exact validated archive identity for later explicit stage retries.
    archive_hash: ConfigurationHash,
    // Opaque shared evidence, consumed by the actual resolver.
    validated: ValidatedConfiguration,
}

/// Bound one JSON read without interpreting it before its digest can be checked.
pub(super) fn bytes(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(crate::state::LIMIT + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= crate::state::LIMIT,
        "candidate document exceeds size limit"
    );
    Ok(bytes)
}

/// Capture the original source before asking the offline validator to return evaluated artifacts.
pub(super) fn submitted(archive: &Path) -> Result<SubmittedConfiguration> {
    let directory = tempfile::tempdir()?;
    io::unpack(
        archive,
        directory.path(),
        &["config.bundle", "manifest.json"],
        &["config.bundle", "manifest.json"],
    )?;
    let manifest: CandidateManifest = crate::state::read(&directory.path().join("manifest.json"))?;
    Ok(SubmittedConfiguration {
        commit: manifest.commit,
        bundle: file_hash(&directory.path().join("config.bundle"))?,
        manifest: file_hash(&directory.path().join("manifest.json"))?,
    })
}

impl Candidate {
    /// Snapshot and authenticate all actual files against the original submission and validator receipt.
    pub(super) fn load(
        operation: &mut Operation,
        archive: &Path,
        submitted: &SubmittedConfiguration,
        expected_archive: Option<&ConfigurationHash>,
    ) -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let snapshot = directory.path().join("received.tar");
        // Bound the copy; all subsequent reads use only this private snapshot and its extracted regular files.
        let mut input = File::open(archive)?;
        ensure!(
            input.metadata()?.is_file(),
            "candidate archive is not a regular file"
        );
        let mut output = File::create(&snapshot)?;
        let copied = std::io::copy(
            &mut input.by_ref().take(8 * 1024 * 1024 * 1024 + 1),
            &mut output,
        )?;
        ensure!(
            copied <= 8 * 1024 * 1024 * 1024,
            "candidate archive exceeds size limit"
        );
        drop(output);
        let archive_hash = file_hash(&snapshot)?;
        if let Some(expected) = expected_archive {
            ensure!(
                &archive_hash == expected,
                "validated candidate archive changed after archival"
            );
        }
        io::unpack(&snapshot, directory.path(), MEMBERS, &MEMBERS[..5])?;
        let record: ValidationRecord =
            crate::state::read(&directory.path().join("validation.json"))?;
        let repo = directory.path().join("verify.git");
        let repo = repo.to_str().context("Git verification path")?;
        operation.text("git", &["init", "--bare", "-b", "main", repo])?;
        let bundle = directory.path().join("config.bundle");
        let verification = operation.text(
            "git",
            &[
                "-C",
                repo,
                "bundle",
                "verify",
                bundle.to_str().context("bundle path")?,
            ],
        )?;
        fs::write(
            operation.file("config-candidate-bundle-verify.log"),
            verification,
        )?;
        let heads = operation.text(
            "git",
            &[
                "-C",
                repo,
                "bundle",
                "list-heads",
                bundle.to_str().context("bundle path")?,
            ],
        )?;
        let commit = heads
            .split_whitespace()
            .next()
            .context("candidate bundle did not expose a commit")?
            .parse()?;
        let prepared = directory.path().join("prepared-source.tar");
        let validated = ValidatedConfiguration::check(
            submitted,
            record,
            CandidateDocuments {
                manifest: bytes(&directory.path().join("manifest.json"))?,
                topology: bytes(&directory.path().join("topology.json"))?,
                system: bytes(&directory.path().join("system.json"))?,
            },
            CandidateFiles {
                bundle_commit: commit,
                bundle: file_hash(&bundle)?,
                prepared: if prepared.exists() {
                    Some(file_hash(&prepared)?)
                } else {
                    None
                },
            },
        )?;
        Ok(Self {
            directory,
            archive_hash,
            validated,
        })
    }

    /// Exact content identity used to bind the protected archive result.
    pub(super) fn archive_hash(&self) -> &ConfigurationHash {
        &self.archive_hash
    }

    /// Read immutable accepted content and source identity for informational publication.
    pub(super) fn validated(&self) -> &ValidatedConfiguration {
        &self.validated
    }

    /// Preserve original validator bytes in evidence rather than assembling a reduced receipt.
    pub(super) fn copy_evidence(&self, operation: &Operation, prefix: &str) -> Result<()> {
        for name in ["validation", "manifest", "topology", "system"] {
            fs::copy(
                self.directory.path().join(format!("{name}.json")),
                operation.file(&format!("{prefix}-{name}.json")),
            )?;
        }
        Ok(())
    }

    /// Refresh original source evidence without replacing resolved output files during staged retries.
    pub(super) fn copy_source_evidence(&self, operation: &Operation) -> Result<()> {
        for name in ["validation", "manifest"] {
            fs::copy(
                self.directory.path().join(format!("{name}.json")),
                operation.file(&format!("config-apply-{name}.json")),
            )?;
        }
        Ok(())
    }

    /// Clone only the checked original commit, or unpack its checked generated source as data.
    pub(super) fn worktree(&self, operation: &mut Operation) -> Result<PathBuf> {
        let worktree = self.directory.path().join("worktree");
        operation.logged(
            "git",
            &[
                "clone".into(),
                self.directory.path().join("config.bundle").into_os_string(),
                worktree.as_os_str().to_owned(),
            ],
            &operation.file("config-apply-git-clone.log"),
            &[],
        )?;
        let identity = self.validated.identity();
        operation.logged(
            "git",
            &[
                "-C".into(),
                worktree.as_os_str().to_owned(),
                "checkout".into(),
                "--detach".into(),
                identity.source.commit.as_str().into(),
            ],
            &operation.file("config-apply-git-checkout.log"),
            &[],
        )?;
        if worktree.join("Cargo.toml").is_file() {
            let prepared = self.directory.path().join("prepared-source");
            airlock_nix_core::artifact::prepared::unpack(
                &self.directory.path().join("prepared-source.tar"),
                &prepared,
                &identity.source.commit,
                identity
                    .prepared
                    .as_ref()
                    .context("validated Rust candidate is missing its prepared source checksum")?
                    .as_str(),
            )?;
            return Ok(prepared);
        }
        ensure!(
            identity.prepared.is_none(),
            "generated source was supplied for a non-Rust candidate"
        );
        Ok(worktree)
    }

    /// Retain extraction lifetime while moving the checked values into the actual resolver.
    pub(super) fn into_parts(self) -> (tempfile::TempDir, ValidatedConfiguration) {
        (self.directory, self.validated)
    }
}
