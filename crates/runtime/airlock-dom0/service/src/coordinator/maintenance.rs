//! Remove obsolete recovery choices only after checking every live reference.
//! Durable journals retain exact root and profile targets across interrupted pruning.

use super::*;
use airlock_deployment_core::retention::{
    Candidate, Generation, Pin,
    inventory::{
        EffectiveSystem, GuestPin, JournalSource, ProtectionInventory, ReleaseSource, ReleaseState,
    },
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Pruning {
    // Pruning journal format, checked before resuming any deletion.
    schema: String,
    // Canonical local release whose retention roots are being removed.
    release: ReleasePath,
    // Host view whose boot generations may become unreferenced.
    host: StorePath,
    // Original manifest retained after its transport is collected.
    manifest: Manifest,
    // Exact root names and targets authorized before deletion began.
    roots: BTreeMap<String, String>,
    // Exact numeric system-profile generations that refer to this host.
    profile_generations: Vec<u64>,
    // Current reasons preventing deletion, recalculated on every retry.
    blockers: Vec<String>,
    // Explicitly waived trash expiry blockers; other references remain protected.
    waived_blockers: Vec<String>,
    // Durable deletion state, distinct from deployment verification.
    status: PruneState,
    // First deletion attempt, for operator diagnostics.
    started_at: f64,
    // Completion time published only after all cleanup succeeded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    finished_at: Option<f64>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PruneState {
    Pruning,
    Pruned,
}

/// Typed deletion candidates; serialization is reserved for reports and durable journals.
#[derive(Serialize, Deserialize)]
struct GenerationPlan {
    // Existing external report format.
    schema: String,
    // Exact policy digests retained for diagnostics.
    keep_keys: BTreeSet<String>,
    // Policy-protected releases; execution still rechecks independent references.
    keep_generations: Vec<crate::retention::KeptRelease>,
    // Exact release targets eligible after all independent blocker checks.
    prune: BTreeSet<ReleasePath>,
    // Releases with current independent blockers.
    protected: Vec<Value>,
    // Recorded releases lacking successful verification evidence.
    unverified: Vec<ReleasePath>,
    // Exact guest coordinates from eligible release manifests.
    storage_candidates: BTreeSet<(GuestName, GenerationId)>,
}

/// Only successful collection suppresses retrying the saved plan.
#[derive(Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum MaintenanceStatus {
    #[default]
    // No completed pass is available.
    Running,
    // Every pruning and collection operation returned successfully.
    Passed,
    // An interrupted or failed pass must be reconsidered against fresh protections.
    Failed,
}

/// Typed security-relevant fields of an existing maintenance journal.
#[derive(Default, Deserialize)]
struct SavedMaintenance {
    // Required in a persisted record; default applies only when no record exists.
    status: MaintenanceStatus,
    // An interrupted single release whose deletion must recheck fresh blockers.
    pruning: Option<ReleasePath>,
    // Previous proposal, never sufficient authority to delete by itself.
    plan: Option<GenerationPlan>,
    // Previously published guest candidates retained across interruptions.
    #[serde(default)]
    storage_candidates: BTreeSet<(GuestName, GenerationId)>,
}

fn entries(path: &Path) -> Result<Vec<PathBuf>> {
    if !path.try_exists()? {
        return Ok(Vec::new());
    }
    state::trusted(path)?;
    let mut entries = fs::read_dir(path)?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort();
    Ok(entries)
}

fn path_text(path: &Path) -> Result<String> {
    Ok(path.to_str().context("non-UTF-8 state path")?.into())
}

fn resolved(path: &Path) -> Result<String> {
    path_text(&fs::canonicalize(path)?)
}

impl Coordinator {
    /// Treat only completed pruning as permission to omit a release's references.
    fn protection_state(&self, release: &str) -> Result<ReleaseState> {
        let path = self.prune_path(release)?;
        Ok(
            if path.try_exists()? && self.pruning_record(&path)?.status == PruneState::Pruned {
                ReleaseState::Pruned
            } else {
                ReleaseState::Present
            },
        )
    }

    /// Decode complete source groups; verified interpretation chooses every protection.
    fn protected_generations(&self) -> Result<ProtectionInventory> {
        let mut releases = Vec::new();
        let mut journals = Vec::new();
        for release in self.release_inventory()?.keys() {
            let state = self.protection_state(release)?;
            let (systems, pins) = if matches!(state, ReleaseState::Pruned) {
                (Vec::new(), Vec::new())
            } else {
                let r = Release::load(Path::new(release))?;
                (
                    r.topology
                        .domains
                        .iter()
                        .map(|(name, domain)| EffectiveSystem {
                            domain: name.to_string(),
                            system: domain.backend.system.source.to_string(),
                        })
                        .collect(),
                    r.manifest
                        .staged_generations
                        .iter()
                        .map(|(name, generation)| GuestPin {
                            guest: name.to_string(),
                            number: generation.get(),
                        })
                        .collect(),
                )
            };
            releases.push(ReleaseSource {
                state,
                systems,
                pins,
            });
        }

        for record in self.deployment_records()? {
            for saved in staging::retained_snapshots(&record)? {
                let state = self.protection_state(saved.release.as_str())?;
                if matches!(state, ReleaseState::Present) {
                    let release = Release::load(saved.release.as_path())?;
                    ensure!(
                        &saved.fingerprint == release.fingerprint(),
                        "protected journal release changed"
                    );
                    let mut names = BTreeSet::new();
                    for entry in &saved.entries {
                        let domain = match entry {
                            GuestGenerationEntry::Retained { domain, .. }
                            | GuestGenerationEntry::Existing { domain }
                            | GuestGenerationEntry::NonNative { domain } => domain,
                        };
                        ensure!(
                            names.insert(domain.clone())
                                && release.topology.domains.contains_key(domain),
                            "invalid protected journal coordinates"
                        );
                    }
                    ensure!(
                        names == release.topology.domains.keys().cloned().collect(),
                        "incomplete protected journal coordinates"
                    );
                }
                journals.push(JournalSource {
                    state,
                    entries: staging::snapshot(&saved)?.entries,
                });
            }
        }

        ProtectionInventory::machine(&releases, &journals)
            .context("invalid machine generation protections")
    }

    /// Include current intent even when its historical projection was not published.
    fn deployment_records(&self) -> Result<Vec<Record>> {
        let current = self.current()?;
        let mut records = Vec::new();
        for path in entries(&self.state.join("transactions"))? {
            if current
                .as_ref()
                .is_some_and(|r| path.file_name().and_then(|n| n.to_str()) == Some(r.id.as_str()))
            {
                continue;
            }
            let record: Record = state::read(&path.join("status.json"))?;
            ensure!(
                path.file_name().and_then(|n| n.to_str()) == Some(record.id.as_str()),
                "transaction identity differs from history filename"
            );
            records.push(record);
        }
        records.extend(current);
        Ok(records)
    }

    pub(super) fn prune_path(&self, path: &str) -> Result<PathBuf> {
        absolute(path)?;
        let key = format!("{:x}", Sha256::digest(path.as_bytes()));
        Ok(self
            .state
            .join("pruned-releases")
            .join(format!("{key}.json")))
    }

    fn pruning_record(&self, path: &Path) -> Result<Pruning> {
        let r: Pruning = state::read(path)?;
        ensure!(
            r.schema == "airlock.machine-release-prune.v1"
                && self.prune_path(r.release.as_str())? == path
                && r.host == r.manifest.host
                && r.profile_generations.iter().all(|n| *n > 0)
                && r.started_at.is_finite()
                && r.started_at > 0.0,
            "invalid release pruning journal"
        );
        for (name, target) in &r.roots {
            ensure!(
                !name.is_empty()
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                    && name != "."
                    && name != "..",
                "invalid retention root name"
            );
            absolute(target)?;
        }
        Ok(r)
    }

    pub(super) fn release_inventory(&self) -> Result<BTreeMap<String, Vec<String>>> {
        let mut releases: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for record in self.deployment_records()? {
            releases.entry(record.release.to_string()).or_default();
            releases.entry(record.previous.to_string()).or_default();
            if let Some(DeploymentOperation {
                authority: OperationAuthority::Reviewed { release, .. },
                ..
            }) = &record.metadata.details.operation
            {
                releases.entry(release.to_string()).or_default();
            }
        }
        for record in self.trash()? {
            releases
                .entry(record.source_release.to_string())
                .or_default();
        }
        if self.state.join("baseline/release.json").try_exists()? {
            releases
                .entry(path_text(&self.state.join("baseline"))?)
                .or_default();
        }
        for root in entries(&self.state.join("roots"))? {
            let name = root
                .file_name()
                .and_then(|s| s.to_str())
                .context("invalid root name")?;
            ensure!(
                fs::symlink_metadata(&root)?.file_type().is_symlink(),
                "machine retention root is not a symlink"
            );
            if let Some(id) = name.strip_prefix("pending-") {
                let candidate = self.state.join("candidates").join(id);
                if candidate.join("release.json").is_file() {
                    releases
                        .entry(path_text(&candidate)?)
                        .or_default()
                        .push(name.into());
                }
            } else if let Some(id) = name
                .strip_prefix("host-")
                .or_else(|| name.strip_prefix("transport-"))
            {
                let status = self.state.join("transactions").join(id).join("status.json");
                if let Some(record) = state::optional::<Record>(&status)? {
                    releases
                        .entry(record.release.to_string())
                        .or_default()
                        .push(name.into());
                }
            } else {
                let target = fs::canonicalize(&root)?;
                if target.join("release.json").is_file() {
                    releases
                        .entry(path_text(&target)?)
                        .or_default()
                        .push(name.into());
                }
            }
        }
        Ok(releases)
    }

    pub(super) fn host_profiles(&self) -> Result<BTreeMap<String, String>> {
        fn collect(path: &Path, result: &mut BTreeMap<String, String>) -> Result<()> {
            if !path.try_exists()? {
                return Ok(());
            }
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let p = entry.path();
                if entry.file_type()?.is_symlink() {
                    result.insert(path_text(&p)?, resolved(&p)?);
                } else if entry.file_type()?.is_dir() {
                    collect(&p, result)?;
                }
            }
            Ok(())
        }
        let root = Path::new("/nix/var/nix/profiles");
        let mut result = BTreeMap::new();
        for p in entries(root)? {
            let name = p
                .file_name()
                .and_then(|s| s.to_str())
                .context("invalid profile name")?;
            let generation = name
                .strip_prefix("system-")
                .and_then(|s| s.strip_suffix("-link"))
                .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()));
            if (name == "system" || generation)
                && fs::symlink_metadata(&p)?.file_type().is_symlink()
            {
                result.insert(path_text(&p)?, resolved(&p)?);
            }
        }
        collect(&root.join("system-profiles"), &mut result)?;
        Ok(result)
    }

    pub(super) fn running_hosts(&self) -> Result<BTreeSet<String>> {
        ["/run/current-system", "/run/booted-system"]
            .into_iter()
            .map(|p| resolved(Path::new(p)))
            .collect()
    }

    fn prune_preview(
        &self,
        release: &str,
        saved: Option<&Pruning>,
        overrides: &[String],
    ) -> Result<Value> {
        absolute(release)?;
        let inventory = self.release_inventory()?;
        ensure!(
            inventory.contains_key(release) || self.prune_path(release)?.try_exists()?,
            "release is not a recorded machine deployment"
        );
        let loaded = if saved.is_none() {
            Some(Release::load(Path::new(release))?)
        } else {
            None
        };
        let manifest = saved
            .map(|r| &r.manifest)
            .or(loaded.as_ref().map(|r| &r.manifest))
            .context("missing prune manifest")?;
        let mut blockers = BTreeSet::new();
        let mut waived = BTreeSet::new();
        let trash: BTreeMap<_, _> = self
            .active_trash()?
            .into_values()
            .filter(|r| r.source_release.as_str() == release)
            .map(|r| (r.id.clone(), r))
            .collect();
        ensure!(
            overrides.iter().all(|id| trash.contains_key(id)),
            "early purge override does not match active trash from release"
        );
        if saved.is_none()
            && state::optional_configuration::<RetentionPolicy>(Path::new(
                "/etc/airlock/generation-retention.json",
            ))?
            .is_some_and(|p| p.enabled)
        {
            let retained = crate::retention::plan(&self.state)?;
            let r = loaded.as_ref().context("missing release")?;
            let key = state::release_key(r)?;
            if retained.keep_generations.iter().any(|v| v.key == key) {
                blockers.insert(
                    "machine generation retention: newest two, weekly anchor or aging successor"
                        .into(),
                );
            }
        }
        if let Some(selection) = self.selection()? {
            for (label, path) in [
                ("release", selection.release),
                ("previous", selection.previous),
            ] {
                if path.as_str() == release {
                    blockers.insert(format!("selected {label}"));
                }
            }
        }
        if self.running_hosts()?.contains(manifest.host.as_str()) {
            blockers.insert("running or booted host".into());
        }
        let profiles = self.host_profiles()?;
        let mut generations = Vec::new();
        for (path, target) in &profiles {
            if target != manifest.host.as_str() {
                continue;
            }
            let path = Path::new(path);
            if path.parent() == Some(Path::new("/nix/var/nix/profiles")) {
                let name = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .context("invalid profile")?;
                if name == "system" {
                    blockers.insert("selected Nix system profile".into());
                } else {
                    generations.push(
                        name.strip_prefix("system-")
                            .and_then(|s| s.strip_suffix("-link"))
                            .context("invalid system generation")?
                            .parse::<u64>()?,
                    );
                }
            } else {
                blockers.insert(format!("recovery profile {}", path.display()));
            }
        }
        if state::optional::<BTreeSet<ReleasePath>>(&self.state.join("retained-releases.json"))?
            .unwrap_or_default()
            .iter()
            .any(|p| p.as_str() == release)
        {
            blockers.insert("explicitly retained rollback choice".into());
        }
        for record in self.deployment_records()? {
            let reviewed = record.metadata.details.operation.as_ref().is_some_and(|o| matches!(&o.authority, OperationAuthority::Reviewed { release: approved, .. } if approved.as_str() == release));
            if !record.phase.verified()
                && record.metadata.details.recovered_by.is_none()
                && (record.release.as_str() == release
                    || record.previous.as_str() == release
                    || reviewed)
            {
                blockers.insert(format!("unfinished transaction {}", record.id.as_str()));
            }
        }
        for record in trash.values() {
            if record.purge_after > state::now() {
                let reason = format!("unexpired trash {}", record.id);
                if overrides.contains(&record.id) {
                    waived.insert(reason);
                } else {
                    blockers.insert(reason);
                }
            }
            if record.status == TrashStatus::Purging {
                blockers.insert(format!("unfinished purge {}", record.id));
            }
        }
        let mut shared = false;
        for other in inventory.keys().filter(|p| p.as_str() != release) {
            if !self.prune_path(other)?.try_exists()?
                && Release::load(Path::new(other))?.manifest.host == manifest.host
            {
                shared = true;
            }
        }
        if shared {
            generations.clear();
        }
        let mut roots = BTreeMap::new();
        for name in inventory.get(release).into_iter().flatten() {
            roots.insert(
                name.clone(),
                resolved(&self.state.join("roots").join(name))?,
            );
        }
        if release == path_text(&self.state.join("baseline"))?
            && self.state.join("roots/baseline-host").is_symlink()
        {
            roots.insert(
                "baseline-host".into(),
                resolved(&self.state.join("roots/baseline-host"))?,
            );
        }
        Ok(
            json!({"schema":"airlock.machine-release-prune.v1","release":release,"host":manifest.host,"manifest":manifest,"roots":roots,"profile_generations":generations,"blockers":blockers,"waived_blockers":waived}),
        )
    }

    /// Inspect all retained release choices and their current deletion blockers.
    pub fn release_list(&self) -> Result<Value> {
        let _guard = MachineLock::acquire(
            &self.state,
            "Release inventory",
            "Inspect recorded machine releases",
            MachineOperation::Prune,
        )?;
        let mut releases = Vec::new();
        for release in self.release_inventory()?.keys() {
            let p = self.prune_path(release)?;
            if p.try_exists()? {
                releases.push(json!(self.pruning_record(&p)?));
            } else {
                releases.push(self.prune_preview(release, None, &[])?);
            }
        }
        Ok(json!({"schema":"airlock.machine-release-inventory.v1","releases":releases}))
    }

    /// Set an explicit retained rollback choice under machine exclusion.
    pub fn release_retain(&self, path: &Path, retain: bool) -> Result<Value> {
        let _guard = MachineLock::acquire(
            &self.state,
            "Release retention",
            "Update explicit retention of a machine release",
            MachineOperation::Retain,
        )?;
        self.ensure_no_pruning()?;
        let release = Release::load(path)?;
        self.ensure_available(&release)?;
        let release = ReleasePath::from_path(&release.path)?;
        ensure!(
            self.release_inventory()?.contains_key(release.as_str()),
            "release is not a recorded machine deployment"
        );
        let path = self.state.join("retained-releases.json");
        let mut kept: BTreeSet<ReleasePath> = state::optional(&path)?.unwrap_or_default();
        if retain {
            kept.insert(release.clone());
        } else {
            kept.remove(&release);
        }
        state::save(&path, &kept)?;
        Ok(json!({"release":release,"retain":retain}))
    }

    /// Report or resume deletion of a confirmed release after rechecking every blocker.
    pub fn release_prune(
        &self,
        path: &Path,
        confirmation: Option<&str>,
        overrides: &[String],
    ) -> Result<Value> {
        let _guard = MachineLock::acquire(
            &self.state,
            "Release pruning",
            "Inspect or remove an explicitly confirmed obsolete release",
            MachineOperation::Prune,
        )?;
        let release = path_text(path)?;
        let journal = self.prune_path(&release)?;
        let saved = if journal.try_exists()? {
            Some(self.pruning_record(&journal)?)
        } else {
            None
        };
        if let Some(record) = &saved
            && record.status == PruneState::Pruned
        {
            if let Some(c) = confirmation {
                ensure!(
                    c == release,
                    "release pruning confirmation must match full path"
                );
            }
            return Ok(json!(record));
        }
        let preview = self.prune_preview(&release, saved.as_ref(), overrides)?;
        if confirmation.is_none() {
            return Ok(preview);
        }
        ensure!(
            confirmation == Some(release.as_str()),
            "release pruning confirmation must match full path"
        );
        self.prune_locked(&release, overrides)
    }

    fn prune_locked(&self, release: &str, overrides: &[String]) -> Result<Value> {
        let path = self.prune_path(release)?;
        let saved = if path.try_exists()? {
            Some(self.pruning_record(&path)?)
        } else {
            None
        };
        if let Some(r) = &saved
            && r.status == PruneState::Pruned
        {
            return Ok(json!(r));
        }
        let preview = self.prune_preview(release, saved.as_ref(), overrides)?;
        ensure!(
            preview["blockers"].as_array().is_some_and(Vec::is_empty),
            "cannot prune release: {}",
            preview["blockers"]
        );
        let mut record = if let Some(saved) = saved {
            saved
        } else {
            self.ensure_no_pruning()?;
            let mut value = preview;
            value["status"] = json!("pruning");
            value["started_at"] = json!(state::now());
            let record: Pruning = serde_json::from_value(value)?;
            state::save(&path, &record)?;
            record
        };
        for (name, target) in &record.roots {
            let root = self.state.join("roots").join(name);
            match fs::symlink_metadata(&root) {
                Ok(m) => ensure!(
                    m.file_type().is_symlink() && resolved(&root)? == *target,
                    "release retention root changed during pruning"
                ),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        let mut generations = Vec::new();
        for number in &record.profile_generations {
            let link = Path::new("/nix/var/nix/profiles").join(format!("system-{number}-link"));
            if fs::symlink_metadata(&link).is_ok() {
                ensure!(
                    link.is_symlink() && resolved(&link)? == record.host.as_str(),
                    "Nix profile generation changed during pruning"
                );
                generations.push(number.to_string());
            }
        }
        if !generations.is_empty() {
            let mut args: Vec<OsString> =
                ["-p", "/nix/var/nix/profiles/system", "--delete-generations"]
                    .into_iter()
                    .map(Into::into)
                    .collect();
            args.extend(generations.into_iter().map(Into::into));
            self.runner
                .run("nix-env", &args, Duration::from_secs(600), &[])?;
        }
        if !record.profile_generations.is_empty()
            && let Some(selected) = self.selection()?
        {
            let host = Release::load(selected.release.as_path())?.manifest.host;
            self.store().install_host_boot(&host)?;
            self.store().seal_host_boot(false)?;
        }
        for name in record.roots.keys() {
            state::unlink(&self.state.join("roots").join(name))?;
        }
        let mut shared = false;
        for other in self
            .release_inventory()?
            .keys()
            .filter(|p| p.as_str() != release)
        {
            if !self.prune_path(other)?.try_exists()?
                && Release::load(Path::new(other))?.manifest.host == record.host
            {
                shared = true;
            }
        }
        if !shared {
            self.store().retire_host(&record.host)?;
        }
        record.status = PruneState::Pruned;
        record.finished_at = Some(state::now());
        state::save(&path, &record)?;
        Ok(json!(record))
    }

    /// Compute policy-eligible releases while preserving all independent pruning blockers.
    pub fn generation_plan(&self) -> Result<Value> {
        let _guard = MachineLock::acquire(
            &self.state,
            "Retention planning",
            "Inspect generation retention policy",
            MachineOperation::Maintenance,
        )?;
        Ok(serde_json::to_value(self.generation_plan_locked()?)?)
    }

    fn generation_plan_locked(&self) -> Result<GenerationPlan> {
        let policy = crate::retention::plan(&self.state)?;
        let keep: BTreeSet<_> = policy
            .keep_generations
            .iter()
            .map(|v| v.key.clone())
            .collect();
        let verified: BTreeSet<_> = policy
            .keep_generations
            .iter()
            .map(|v| v.key.clone())
            .chain(policy.prune_candidates.iter().map(|v| v.key.clone()))
            .collect();
        let mut prune = Vec::new();
        let mut protected = Vec::new();
        let mut unverified = Vec::new();
        let mut storage = BTreeSet::new();
        for release in self.release_inventory()?.keys() {
            if self.prune_path(release)?.try_exists()? {
                continue;
            }
            let r = Release::load(Path::new(release))?;
            let key = state::release_key(&r)?;
            if !verified.contains(&key) {
                unverified.push(release.parse()?);
                continue;
            }
            let preview = self.prune_preview(release, None, &[])?;
            if keep.contains(&key)
                || !preview["blockers"]
                    .as_array()
                    .context("invalid blockers")?
                    .is_empty()
            {
                protected.push(json!({"release":release,"blockers":preview["blockers"]}));
            } else {
                prune.push(release.parse()?);
                storage.extend(r.manifest.staged_generations);
            }
        }
        Ok(GenerationPlan {
            schema: "airlock.machine-generation-retention.v1".into(),
            keep_keys: keep,
            keep_generations: policy.keep_generations,
            prune: prune.into_iter().collect(),
            protected,
            unverified,
            storage_candidates: storage,
        })
    }

    /// Resume journalled background pruning and pool GC only for the verified selected generation.
    pub fn generation_maintenance(&self) -> Result<Value> {
        let mut guard = MachineLock::acquire(
            &self.state,
            "Automatic generation maintenance",
            "Remove unused generations and collect unused pool artifacts",
            MachineOperation::Maintenance,
        )?;
        ensure!(
            state::optional_configuration::<RetentionPolicy>(Path::new(
                "/etc/airlock/generation-retention.json"
            ))?
            .is_some_and(|p| p.enabled),
            "machine generation retention is disabled"
        );
        let directory = self.state.join("maintenance");
        let pending = directory.join("pending.json");
        let Some(request) = state::optional::<Value>(&pending)? else {
            return Ok(json!({"status":"idle"}));
        };
        let selected = self
            .selection()?
            .context("no selected machine generation")?;
        let status = self.record(&selected.transaction)?;
        let r = Release::load(selected.release.as_path())?;
        ensure!(
            status.phase == Phase::Complete
                && status.release == selected.release
                && state::host()? == r.manifest.host
                && request["key"] == state::release_key(&r)?,
            "cleanup must wait for selected generation verification"
        );
        self.check_recorded_release(&r, &status)?;
        guard.update(Phase::Preflight, Some(&selected.transaction))?;
        let journal = directory.join("latest.json");
        let previous: SavedMaintenance = state::optional(&journal)?.unwrap_or_default();
        let mut result = json!({"status":"running","started_at":state::now(),"request":request});
        let outcome = (|| -> Result<()> {
            // Validate authority and original snapshots before resuming even a partial pruning journal.
            self.protected_generations()?;
            if let Some(target) = &previous.pruning {
                self.prune_locked(target.as_str(), &[])?;
            }
            let mut plan = self.generation_plan_locked()?;
            let mut prune = plan.prune.clone();
            if previous.status != MaintenanceStatus::Passed {
                for target in previous.plan.as_ref().into_iter().flat_map(|p| &p.prune) {
                    if !self.prune_path(target.as_str())?.try_exists()?
                        && self.prune_preview(target.as_str(), None, &[])?["blockers"]
                            .as_array()
                            .is_some_and(Vec::is_empty)
                    {
                        prune.insert(target.clone());
                    }
                }
            }
            let mut storage = plan.storage_candidates.clone();
            storage.extend(previous.storage_candidates.clone());
            plan.prune = prune.clone();
            result["plan"] = serde_json::to_value(plan)?;
            result["storage_candidates"] = json!(storage);
            state::save(&journal, &result)?;
            for target in prune {
                result["pruning"] = json!(target);
                state::save(&journal, &result)?;
                self.prune_locked(target.as_str(), &[])?;
                result
                    .as_object_mut()
                    .context("invalid maintenance journal")?
                    .remove("pruning");
                state::save(&journal, &result)?;
            }
            let protected = self.protected_generations()?;
            for (name, generation) in storage {
                let Some(info) = self.store().generation_record(&name, generation)? else {
                    continue;
                };
                let domain = crate::store::runtime_namespace(name.as_str());
                ensure!(
                    info["domain"] == domain && info["generation"] == generation.get(),
                    "retention generation record identity differs"
                );
                let system: StorePath = serde_json::from_value(info["system"].clone())?;
                let retain = info["retention"]["retain"]
                    .as_bool()
                    .context("invalid retention pin")?;
                let pin = Pin::classify(retain, info["retention"].get("updated_at").is_some());
                if let Some(request) = protected.release(
                    Candidate {
                        generation: Generation {
                            domain,
                            number: generation.get(),
                        },
                        system: system.to_string(),
                    },
                    pin,
                ) {
                    self.store().release_retention(&request)?;
                }
            }
            self.ensure_no_pruning()?;
            result["gc"] = self.store().collect_protected(&protected)?;
            result["status"] = json!("passed");
            result["finished_at"] = json!(state::now());
            state::save(&journal, &result)?;
            state::save(&directory.join("last-cleaned-generation.json"), &request)?;
            state::unlink(&pending)?;
            Ok(())
        })();
        if let Err(error) = outcome {
            result["status"] = json!("failed");
            result["error"] = json!(format!("{error:#}"));
            if result.get("plan").is_none() {
                // An early validation failure must not lose the prior cleanup backlog.
                if let Some(plan) = &previous.plan {
                    result["plan"] = serde_json::to_value(plan)?;
                }
                result["storage_candidates"] = json!(previous.storage_candidates);
                if let Some(target) = &previous.pruning {
                    result["pruning"] = json!(target);
                }
            }
            state::save(&journal, &result)?;
            return Err(error);
        }
        Ok(result)
    }
}
