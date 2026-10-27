//! Keep the selected Git objects and working trees independent of ongoing development.

use crate::{repository, support};
use airlock_nix_core::identity::GitRevision;
use anyhow::{Result, ensure};
use std::{
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
}

impl Snapshot {
    /// Copy both committed repositories without sharing object storage with the active checkout.
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
        };
        captured.check()?;
        repository::check_image_source(&captured.root)?;

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
