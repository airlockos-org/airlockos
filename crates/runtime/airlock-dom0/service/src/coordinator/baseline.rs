//! Observe the initial USB image without inventing a completed deployment transaction.

use super::*;

/// Installed source and optional boot-created snapshot for a machine with no deployment selection.
pub(super) struct ImageBaseline {
    /// Active host closure, sampled before reading its immutable source metadata.
    pub(super) host: StorePath,
    /// Active boot profile, checked against the saved image manifest during verification.
    pub(super) profile: MachineProfile,
    /// Source identity embedded in the active host generation.
    pub(super) source: Provenance,
    /// Snapshot created by successful topology setup; absence means bootstrap is incomplete.
    pub(super) release: Option<Release>,
}

/// Read the running image's source identity through NixOS's generation symlinks.
pub(super) fn installed_source() -> Result<Provenance> {
    let source: Value = state::configuration(Path::new(
        "/run/current-system/etc/airlock/machine-source.json",
    ))?;
    ensure!(
        source["schema"] == "airlock.machine-source.v1",
        "deployed source baseline is unavailable for review"
    );
    Ok(serde_json::from_value(source)?)
}

impl ImageBaseline {
    /// Describe expected source and host identities without claiming runtime verification.
    pub(super) fn summary(&self) -> Value {
        let expected = self.release.as_ref().map(|release| &release.manifest);
        json!({
            "kind":"image", "initialized":expected.is_some(),
            "release":self.release.as_ref().map(|release| &release.path),
            "revision":expected.map_or(&self.source.revision, |manifest| &manifest.revision),
            "lock_hash":expected.map_or(&self.source.lock_hash, |manifest| &manifest.lock_hash),
            "host":expected.map_or(&self.host, |manifest| &manifest.host),
            "profile":expected.map_or(&self.profile, |manifest| &manifest.profile),
            "host_matches_baseline":expected.map(|manifest| manifest.host == self.host),
            "source_matches_image":expected.map(|manifest| manifest.revision == self.source.revision && manifest.lock_hash == self.source.lock_hash),
        })
    }
}

impl Coordinator {
    /// Read provenance and any saved image snapshot without initializing or pinning state.
    pub(super) fn image_baseline(&self) -> Result<ImageBaseline> {
        let host = state::host()?;
        let source = installed_source()?;
        let path = self.state.join("baseline");
        let release = if state::optional::<Manifest>(&path.join("release.json"))?.is_some() {
            state::trusted(&path)?;
            let release = Release::load(&path)?;
            release.trust()?;
            Some(release)
        } else {
            None
        };
        ensure!(
            state::host()? == host,
            "running host changed while reading image baseline"
        );
        Ok(ImageBaseline {
            host,
            profile: state::profile()?,
            source,
            release,
        })
    }

    /// Verify a boot-created image snapshot without creating deployment history or initializing state.
    pub(super) fn verify_image_baseline(&self) -> Result<Value> {
        ensure!(
            self.current()?.is_none() && self.selection()?.is_none(),
            "deployment history exists without a selection; inspect recovery state before verifying the image baseline"
        );
        let boot = state::boot_id()?;
        let image = self.image_baseline()?;
        let release = image.release.as_ref().context(
            "image baseline is not initialized; finish startup before verifying the machine",
        )?;
        ensure!(
            release.manifest.host == image.host && release.manifest.profile == image.profile,
            "image baseline differs from the running host or profile"
        );
        ensure!(
            release.manifest.revision == image.source.revision
                && release.manifest.lock_hash == image.source.lock_hash,
            "image baseline source differs from the running image"
        );
        ensure!(
            Path::new(release.manifest.setup.as_str())
                == fs::canonicalize("/run/current-system/sw/bin/airlock-setup-config")?,
            "image baseline setup differs from the running image"
        );
        let topology_path = Path::new("/var/lib/airlock/system/current-topology.json");
        let applied: Value = state::read(topology_path)?;
        ensure!(
            applied == release.raw_topology,
            "applied topology differs from the image baseline"
        );
        let mut required: BTreeSet<_> = planning::plan(
            &release.topology,
            &release.topology,
            &BTreeSet::new(),
            &[],
            false,
        )?
        .start
        .into_iter()
        .collect();
        required.extend(
            self.running()?
                .into_iter()
                .filter(|name| release.topology.domains.contains_key(name)),
        );
        let observed = self.verify_topology(release, &required)?;

        release.recheck()?;
        let current_source = installed_source()?;
        ensure!(
            state::host()? == image.host
                && state::profile()? == image.profile
                && state::boot_id()? == boot
                && current_source.revision == image.source.revision
                && current_source.lock_hash == image.source.lock_hash
                && state::read::<Value>(topology_path)? == applied,
            "image baseline changed during verification"
        );
        Ok(json!({
            "schema":"airlock.machine-verification.v1", "status":"passed", "phase":"image-baseline",
            "baseline":image.summary(), "selection":null, "revision":release.manifest.revision,
            "lock_hash":release.manifest.lock_hash, "host_selected":release.manifest.host,
            "host_running":image.host, "host_matches_baseline":true, "boot_id":boot, "observed":observed,
        }))
    }
}
