//! Keep the selected Git objects and working trees independent of ongoing development.

use crate::{repository, support};
use airlock_nix_core::identity::GitRevision;
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

/// Private committed sources shared by image construction and USB personalization.
pub(super) struct Snapshot {
    /// Independent parent checkout used for every build command and source copy.
    pub(super) root: PathBuf,
    /// Parent commit selected before credentials or image construction.
    pub(super) revision: GitRevision,
    /// Machine gitlink selected by that exact parent commit.
    pub(super) machine_revision: GitRevision,
    /// Prepared offline dependencies copied independently of the active checkout's cache.
    pub(super) vendor: PathBuf,
}

impl Snapshot {
    /// Capture committed repositories and prepared dependencies independently of active development.
    pub(super) fn capture(source: &Path, destination: &Path) -> Result<Self> {
        let revision: GitRevision = support::git(source, &["rev-parse", "HEAD"])?.parse()?;
        let (machine, machine_revision) = repository::local(source)?;
        ensure!(
            repository::pinned(source, revision.as_str())? == machine_revision,
            "machine pin changed while selecting USB source; retry before building"
        );

        checkout(source, destination, &revision)?;
        let machine_revision = machine_revision.parse()?;
        checkout(
            &machine,
            &destination.join("airlock-machine"),
            &machine_revision,
        )?;
        let captured = Self {
            root: destination.to_owned(),
            revision,
            machine_revision,
            vendor: destination
                .parent()
                .context("USB snapshot needs a private parent")?
                .join("authoring-vendor"),
        };
        captured.check()?;
        repository::check_image_source(&captured.root)?;

        let vendor = std::env::var_os("AIRLOCK_CARGO_VENDOR")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| source.join(".airlock-cache/authoring-vendor"));
        let vendor = if vendor.is_absolute() {
            vendor
        } else {
            source.join(vendor)
        };
        let vendor = fs::canonicalize(&vendor).with_context(|| format!(
            "prepared authoring dependencies are missing at {path}; run make prepare-dependencies before installing a USB image",
            path = vendor.display(),
        ))?;
        ensure!(
            vendor.is_dir(),
            "authoring dependencies must be a directory"
        );

        copy_vendor(&vendor, &captured.vendor)?;

        Ok(captured)
    }

    /// Reobserve the isolated sources; active-checkout changes cannot affect this evidence.
    pub(super) fn check(&self) -> Result<(GitRevision, GitRevision)> {
        let revision = support::git(&self.root, &["rev-parse", "HEAD"])?.parse()?;
        let machine = self.root.join("airlock-machine");
        let machine_revision = support::git(&machine, &["rev-parse", "HEAD"])?.parse()?;
        ensure!(
            revision == self.revision
                && machine_revision == self.machine_revision
                && support::git(&self.root, &["status", "--porcelain"])?.is_empty()
                && support::git(&machine, &["status", "--porcelain"])?.is_empty(),
            "isolated USB source changed; USB was not written"
        );

        Ok((revision, machine_revision))
    }
}

/// Copy prepared dependency bytes without retaining links to a cache that development may replace.
fn copy_vendor(source: &Path, destination: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.is_dir() {
        fs::create_dir(destination)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            copy_vendor(&entry.path(), &destination.join(entry.file_name()))?;
        }
    } else {
        ensure!(
            metadata.is_file(),
            "unsupported authoring dependency entry: {path}",
            path = source.display()
        );
        fs::copy(source, destination)?;
    }

    Ok(())
}

/// Clone objects through Git transport so later source edits, ref updates and cleanup stay separate.
fn checkout(source: &Path, destination: &Path, revision: &GitRevision) -> Result<()> {
    support::output(
        Command::new("git")
            .args(["clone", "--quiet", "--no-local", "--no-checkout", "--"])
            .arg(source)
            .arg(destination),
    )?;
    support::output(
        Command::new("git")
            .arg("-C")
            .arg(destination)
            .args(["checkout", "--quiet", "--detach"])
            .arg(revision.as_str()),
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exercise the real offline Rust preparation boundary without evaluating or assembling an OS image.
    #[test]
    #[ignore = "requires prepared authoring dependencies and the airlock-dev executable"]
    fn captured_machine_prepares_with_private_dependencies() -> Result<()> {
        let root = repository::root(None)?;
        let temporary = tempfile::tempdir()?;
        let captured = Snapshot::capture(&root, &temporary.path().join("source"))?;

        let result = Command::new(airlock_tests::process::binary(
            "AIRLOCK_DEV_BIN",
            "airlock-dev",
        ))
        .arg("--repository-root")
        .arg(&captured.root)
        .args(["source", "prepare"])
        .env("AIRLOCK_CARGO_VENDOR", &captured.vendor)
        .env("CARGO_TARGET_DIR", temporary.path().join("target"))
        .env("AIRLOCK_PREPARED_CACHE", temporary.path().join("prepared"))
        .output()?;

        ensure!(
            result.status.success(),
            "captured Rust preparation failed: {error}",
            error = String::from_utf8_lossy(&result.stderr)
        );

        let prepared: serde_json::Value = serde_json::from_slice(&result.stdout)?;
        ensure!(
            Path::new(
                prepared["source"]
                    .as_str()
                    .context("prepared source path")?
            )
            .join("airlock-machine/flake.nix")
            .is_file(),
            "Rust preparation did not produce the machine flake"
        );
        captured.check()?;

        Ok(())
    }
}
