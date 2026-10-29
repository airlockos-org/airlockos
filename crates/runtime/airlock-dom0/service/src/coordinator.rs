//! Coordinate a whole-machine release through existing Qubes and NixOS helpers.
//! Selections and journal entries preserve recovery context across interruption.

use crate::{
    lock::{self, MachineLock},
    model::*,
    planning,
    process::Runner,
    state::{self, Release},
    store::Store,
};
use airlock_nix_core::{identity::GuestName, review::DeploymentPlan};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// Dom0 state directory and helper runner for machine planning, activation and verification.
pub struct Coordinator {
    /// Trusted dom0 directory holding selections, journal entries and lock metadata.
    pub state: PathBuf,
    /// Bounded helper runner owning subprocess and descendant cleanup.
    runner: Runner,
}

mod activation;

mod staging;

mod host;

mod admission;

pub(crate) mod approval;

mod boot;

mod candidates;

mod reviews;

mod retirement;

mod gui;

mod maintenance;

mod migration;

mod verification;

mod recovery;

mod baseline;

impl Coordinator {
    fn store(&self) -> Store<'_> {
        Store::new(&self.runner)
    }

    /// Select the state directory without creating state or starting helper processes.
    pub fn new(state: PathBuf) -> Self {
        Self {
            state,
            runner: Runner::default(),
        }
    }

    /// Read the current selection, rejecting invalid absolute release paths.
    pub fn selection(&self) -> Result<Option<Selection>> {
        let selection: Option<Selection> = state::optional(&self.state.join("selection.json"))?;
        Ok(selection)
    }

    /// Read authoritative current intent, rejecting damage and conflicting identities.
    fn current(&self) -> Result<Option<Record>> {
        let current: Option<Record> = state::optional(&self.state.join("latest.json"))?;
        let Some(record) = &current else {
            let transactions = self.state.join("transactions");
            ensure!(
                self.selection()?.is_none()
                    && (!transactions.try_exists()?
                        || fs::read_dir(transactions)?.next().is_none()),
                "missing authoritative deployment journal; inspect retained history"
            );
            return Ok(None);
        };
        let history = self
            .state
            .join("transactions")
            .join(record.id.as_str())
            .join("status.json");
        if let Some(copy) = state::optional::<Record>(&history)? {
            Self::same_intent(record, &copy)?;
        }
        Ok(current)
    }

    /// Progress may lag in the history copy; immutable intent must never disagree.
    fn same_intent(current: &Record, copy: &Record) -> Result<()> {
        let identity = |r: &Record| {
            json!({
                "id": r.id, "boot_id": r.boot_id, "release": r.release,
                "previous": r.previous, "revision": r.revision, "plan": r.plan,
                "origin": r.metadata.origin, "operation": r.metadata.details.operation,
                "recovery_of": r.metadata.details.recovery_of,
                "gui_preserved": r.metadata.details.gui_preserved,
                "guest_generations": r.metadata.details.guest_generations,
                "administrative": r.metadata.details.extra.get("administrative"),
            })
        };
        ensure!(
            identity(current) == identity(copy),
            "deployment journal identities disagree"
        );
        Ok(())
    }

    fn record(&self, id: &TransactionId) -> Result<Record> {
        // Current progress is authoritative in latest.json. Its history copy may
        // lag if publication was interrupted; never recover from that stale copy.
        if let Some(current) = self.current()?
            && &current.id == id
        {
            return Ok(current);
        }
        let r: Record = state::read(
            &self
                .state
                .join("transactions")
                .join(id.as_str())
                .join("status.json"),
        )?;
        ensure!(&r.id == id, "transaction identity differs from filename");
        Ok(r)
    }

    /// Report the selected release, current transaction and machine-lock diagnostics.
    pub fn status(&self) -> Result<Value> {
        let latest = self.current()?;
        let mut result = latest
            .as_ref()
            .map(serde_json::to_value)
            .transpose()?
            .unwrap_or(json!({"phase":"image-baseline"}));

        if let Some(record) = &latest {
            match airlock_nix_core::runtime::progress::status(
                &self.state.join("progress").join(record.id.as_str()),
            ) {
                Ok(Some(progress)) => result["progress"] = progress,
                Ok(None) => (),
                Err(error) => result["progress_error"] = json!(error.to_string()),
            }
        }
        let current = state::host()?;
        let selection = self.selection()?;
        result["selection"] = serde_json::to_value(&selection)?;
        result["lock"] = serde_json::to_value(lock::status(&self.state.join("lock"))?)?;
        result["host_running_now"] = json!(current);
        result["host_matches_selection"] = selection
            .as_ref()
            .map(|_| json!(result.get("host_selected") == Some(&json!(current))))
            .unwrap_or(Value::Null);
        if latest.is_none() {
            let baseline = self.image_baseline()?.summary();
            result["revision"] = baseline["revision"].clone();
            result["lock_hash"] = baseline["lock_hash"].clone();
            result["host_matches_baseline"] = baseline["host_matches_baseline"].clone();
            result["baseline"] = baseline;
        }

        Ok(result)
    }

    fn baseline(&self) -> Result<Release> {
        if self.selection()?.is_none() && !self.state.join("baseline/release.json").try_exists()? {
            self.initialize_baseline()?;
        }
        let path = self
            .selection()?
            .map(|s| s.release)
            .map(Ok)
            .unwrap_or_else(|| ReleasePath::from_path(&self.state.join("baseline")))?;
        Release::load(path.as_path())
    }

    fn initialize_baseline(&self) -> Result<()> {
        let source = baseline::installed_source()?;
        let revision = source.revision;
        let lock_hash = source.lock_hash;
        let raw: Value = state::read(Path::new("/var/lib/airlock/system/current-topology.json"))?;
        let topology: Topology = serde_json::from_value(raw.clone())?;
        topology.validate()?;
        let host = state::host()?;
        let setup = fs::canonicalize("/run/current-system/sw/bin/airlock-setup-config")?;
        let coordinator = fs::canonicalize("/run/current-system/sw/bin/airlock-dom0-service")?;
        let manifest = json!({"schema":"airlock.machine-release.v1","profile":state::profile()?,"host":host,"setup":setup,"coordinator":coordinator,"revision":revision,"lockHash":lock_hash,"retireDomains":[],"trashRetentionDays":30});
        let _: Manifest = serde_json::from_value(manifest.clone())?;
        let parent = self.state.join("baseline");
        state::directory(&parent)?;
        self.pin("baseline-host", Path::new(host.as_str()))?;
        state::save(&parent.join("topology.json"), &raw)?;
        state::save(&parent.join("release.json"), &manifest)
    }

    fn ensure_available(&self, release: &Release) -> Result<()> {
        for domain in release.topology.domains.values() {
            if let Some(artifact) = domain.backend.hermit() {
                let memory = domain
                    .prefs
                    .get("memory")
                    .and_then(Value::as_u64)
                    .context("missing Hermit memory")?;
                crate::hermit::verify(artifact, memory)?;
            }
        }
        let key = format!(
            "{:x}",
            Sha256::digest(release.path.as_os_str().as_encoded_bytes())
        );
        ensure!(
            !self
                .state
                .join("pruned-releases")
                .join(format!("{key}.json"))
                .try_exists()?,
            "release was pruned or is being pruned"
        );
        Ok(())
    }

    fn ensure_no_pruning(&self) -> Result<()> {
        let dir = self.state.join("pruned-releases");
        if !dir.try_exists()? {
            return Ok(());
        }

        for entry in fs::read_dir(dir)? {
            let p = entry?.path();
            if p.extension().is_some_and(|e| e == "json") {
                let r: PruneRecord = state::read(&p)?;
                ensure!(
                    r.status == PruneStatus::Pruned,
                    "unfinished or damaged release pruning; use existing recovery first"
                );
            }
        }
        Ok(())
    }

    fn trash(&self) -> Result<Vec<TrashRecord>> {
        let dir = self.state.join("trash");
        let mut records = Vec::new();
        if !dir.try_exists()? {
            return Ok(records);
        }

        for e in fs::read_dir(dir)? {
            let p = e?.path();
            if p.extension().is_some_and(|s| s == "json") {
                let r: TrashRecord = state::read(&p)?;
                ensure!(
                    Some(r.id.as_str()) == p.file_stem().and_then(|s| s.to_str()),
                    "invalid trash journal identity"
                );
                records.push(r);
            }
        }

        Ok(records)
    }

    fn enforce_trash(&self, topology: &Topology) -> Result<()> {
        let registered = self.registered()?;
        for t in self.trash()? {
            if t.status.is_active() {
                let name = &t.domain;
                ensure!(
                    !topology.domains.contains_key(name),
                    "selected topology declares trashed guest {name}"
                );
                if !registered.contains(name) {
                    ensure!(
                        t.status == TrashStatus::Purging,
                        "trashed VM is missing: {name}"
                    );
                    continue;
                }
                ensure!(
                    t.uuid == self.vm_uuid(name)?
                        && !t.storage.volumes.is_empty()
                        && t.storage.volumes == crate::qubes::volumes(name)?,
                    "trash registration or storage changed: {name}"
                );
                let power = self.operation_power(name)?;
                ensure!(
                    power.is_known(),
                    "trashed VM power state is unknown: {name}"
                );
                if !power.is_halted() {
                    self.runner.run(
                        "qvm-shutdown",
                        &[
                            "--wait".into(),
                            "--timeout".into(),
                            "120".into(),
                            name.as_str().into(),
                        ],
                        Duration::from_secs(150),
                        &[],
                    )?;
                    bail!("trashed VM was running and has been stopped: {name}");
                }
                self.runner
                    .text("qvm-prefs", &[name.as_str(), "autostart", "False"])?;
                let tags = self.runner.text("qvm-tags", &[name.as_str(), "list"])?;
                if !tags.lines().any(|t| t == "airlock-retired") {
                    self.runner
                        .text("qvm-tags", &[name.as_str(), "add", "airlock-retired"])?;
                }
            }
        }
        Ok(())
    }

    /// Query Qubes for the set of currently running non-dom0 guests.
    pub fn running(&self) -> Result<BTreeSet<GuestName>> {
        let output = self
            .runner
            .text("qvm-ls", &["--raw-data", "--fields", "NAME,STATE"])?;
        let mut result = BTreeSet::new();
        for line in output.lines() {
            let (name, status) = line
                .split_once('|')
                .context("invalid Qubes runtime inventory")?;
            if name != "dom0" && status == "Running" {
                result.insert(name.parse()?);
            }
        }

        Ok(result)
    }

    /// Require stable power observations before selecting deployment lifecycle effects.
    /// General status and boot operations retain their separate Running-only interpretation.
    fn deployment_running(&self) -> Result<BTreeSet<GuestName>> {
        let output = self
            .runner
            .text("qvm-ls", &["--raw-data", "--fields", "NAME,STATE"])?;
        deployment_running(&output)
    }

    /// Compare this release against the selected baseline and observed running guests.
    pub fn plan(&self, release: &Release) -> Result<Plan> {
        self.ensure_available(release)?;
        let baseline = self.baseline()?;
        ensure!(
            baseline.manifest.profile == release.manifest.profile
                && release.manifest.profile == state::profile()?,
            "deployment profile differs from booted profile"
        );

        self.make_plan(&baseline, release, &self.deployment_running()?, false)
    }

    /// Inspect a candidate under exclusion, including initial image-baseline creation when necessary.
    pub fn inspect(&self, path: &Path) -> Result<Plan> {
        let _guard = MachineLock::acquire(
            &self.state,
            "Deployment planning",
            "Inspect candidate effects against the deployed baseline",
            MachineOperation::Candidate,
        )?;
        let release = Release::load(path)?;
        release.trust()?;
        self.plan(&release)
    }

    /// Compute and validate candidate effects against the supplied baseline and running set.
    pub fn make_plan(
        &self,
        baseline: &Release,
        release: &Release,
        running: &BTreeSet<GuestName>,
        rollback: bool,
    ) -> Result<Plan> {
        ensure!(
            baseline.manifest.profile == release.manifest.profile,
            "release profiles differ"
        );

        let mut p = planning::plan(
            &baseline.topology,
            &release.topology,
            running,
            &release.manifest.retire_domains,
            rollback,
        )?;
        let trash = self.active_trash()?;
        p.restore = release
            .topology
            .domains
            .keys()
            .filter(|n| trash.contains_key(*n))
            .cloned()
            .collect();
        for (name, record) in &trash {
            if !release.topology.domains.contains_key(name) {
                ensure!(
                    !planning::references_domain(&release.topology, &record.domain)?,
                    "topology references a retired VM"
                );
            }
        }
        let copies = self.private_copy_plan(baseline, release, None)?;
        if !copies.is_empty() {
            p.extra.insert("private_copies".into(), json!(copies));
        }
        p.host_reboot_required = state::host()? != release.manifest.host;
        p.revision = Some(release.manifest.revision.clone());
        Ok(p)
    }

    fn persist(&self, record: &Record) -> Result<()> {
        self.persist_with(record, &mut |path, value| state::save(path, value))
    }

    /// Publish current intent first; history is a repairable projection.
    /// Archive the prior current record before replacing it with another attempt.
    fn persist_with(
        &self,
        record: &Record,
        save: &mut impl FnMut(&Path, &Value) -> Result<()>,
    ) -> Result<()> {
        let latest = self.state.join("latest.json");
        let history = |id: &TransactionId| {
            self.state
                .join("transactions")
                .join(id.as_str())
                .join("status.json")
        };
        let previous = self.current()?;
        if previous.as_ref().is_none_or(|saved| saved.id != record.id) {
            ensure!(
                !history(&record.id).try_exists()?,
                "transaction identity was already used"
            );
        }
        if let Some(previous) = previous {
            if previous.id != record.id {
                save(&history(&previous.id), &serde_json::to_value(previous)?)?;
            } else {
                Self::same_intent(&previous, record)?;
            }
        }
        let value = serde_json::to_value(record)?;
        save(&latest, &value)?;
        save(&history(&record.id), &value)
    }

    fn record_verified(
        &self,
        r: &Release,
        record: &mut Record,
        verified: &verification::VerifiedDeployment,
    ) -> Result<()> {
        ensure!(
            verified.phase(
                self,
                r,
                record,
                record
                    .host_running
                    .as_ref()
                    .context("missing verified host observation")?
            )? == record.phase,
            "verified deployment phase differs"
        );
        if record.phase != Phase::Complete {
            return Ok(());
        }

        record.generation_verified_at.get_or_insert(state::now());
        self.persist(record)?;

        let maintenance = (|| -> Result<()> {
            if let Some(policy) = state::optional_configuration::<RetentionPolicy>(Path::new(
                "/etc/airlock/generation-retention.json",
            ))? && policy.enabled
            {
                let key = state::release_key(r)?;
                let path = self.state.join("maintenance/verified-generations.json");
                let mut history = state::optional::<BTreeMap<String, VerifiedGeneration>>(&path)?
                    .unwrap_or_default();
                crate::retention::validate_history(&history)?;

                history.entry(key.clone()).or_insert(VerifiedGeneration {
                    release: ReleasePath::from_path(&r.path)?,
                    first_verified_at: record
                        .generation_verified_at
                        .context("missing verification time")?,
                    extra: BTreeMap::new(),
                });
                state::save(&path, &history)?;

                let cleaned: Option<Value> =
                    state::optional(&self.state.join("maintenance/last-cleaned-generation.json"))?;
                if cleaned.as_ref().and_then(|v| v.get("key")) != Some(&json!(key)) {
                    state::save(
                        &self.state.join("maintenance/pending.json"),
                        &json!({"key":key,"requested_at":state::now()}),
                    )?;
                }
            }
            Ok(())
        })();

        if let Err(error) = maintenance {
            record
                .metadata
                .details
                .extra
                .insert("maintenance_error".into(), json!(format!("{error:#}")));
        } else {
            record.metadata.details.extra.remove("maintenance_error");
        }

        self.persist(record)
    }

    /// Observe retired VM records without taking a writer lock or repairing data.
    pub fn trash_list(&self) -> Result<Value> {
        Ok(json!({"schema":"airlock.machine-trash.v1","records":self.trash()?}))
    }
}

/// Decode all inventory rows before accepting a stable deployment-planning observation.
/// Qubes is trusted to supply a complete snapshot; duplicate rows and unsupported states fail closed.
fn deployment_running(output: &str) -> Result<BTreeSet<GuestName>> {
    let mut seen = BTreeSet::new();
    let mut running = BTreeSet::new();
    for line in output.lines() {
        let (name, state) = line
            .split_once('|')
            .context("invalid Qubes runtime inventory")?;
        ensure!(
            seen.insert(name),
            "duplicate Qubes runtime identity: {name}"
        );
        let active = airlock_machine_planning::deployment::running(state)
            .with_context(|| format!("{name}: unsupported deployment power state {state:?}"))?;
        if name != "dom0" {
            let name = name.parse::<GuestName>()?;
            if active {
                running.insert(name);
            }
        }
    }
    Ok(running)
}

#[cfg(test)]
mod planning_observation_tests {
    use super::*;

    #[test]
    fn deployment_inventory_requires_stable_unique_observations() {
        let running =
            deployment_running("dom0|Running\nusr-home|Running\nsys-net|Halted\n").unwrap();
        assert_eq!(running, BTreeSet::from(["usr-home".parse().unwrap()]));
        for inventory in [
            "usr-home|Paused\n",
            "usr-home|Unknown\n",
            "usr-home|Transient\n",
            "usr-home|\n",
            "usr-home\n",
            "bad/name|Halted\n",
            "usr-home|Running\nusr-home|Halted\n",
        ] {
            assert!(deployment_running(inventory).is_err(), "{inventory:?}");
        }
    }
}
