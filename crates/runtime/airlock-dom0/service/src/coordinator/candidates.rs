//! Assemble immutable local release candidates from independently checked pool receipts.
//! A receipt identifies admitted storage; it does not authorize activation.

mod receipt;

use super::*;
use crate::store::AdmissionReceipt;
use airlock_nix_core::{
    admission::{BoundSet, ExpectedAdmission},
    root_artifact::RootDescriptor,
};
use receipt::CheckedAdmission;

impl Coordinator {
    pub(super) fn local_candidate(&self, path: &Path) -> Result<PathBuf> {
        let r = Release::load(path)?;
        r.trust()?;
        let manifest: Value = state::read(&r.path.join("release.json"))?;
        self.publish_candidate(&manifest, &r.raw_topology, BTreeMap::new())
    }

    pub(super) fn pin(&self, name: &str, path: &Path) -> Result<()> {
        ensure!(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
            "invalid root name"
        );
        let roots = self.state.join("roots");
        state::directory(&roots)?;
        self.runner.run(
            "nix-store",
            &[
                "--add-root".into(),
                roots.join(name).into_os_string(),
                "--realise".into(),
                path.as_os_str().into(),
            ],
            Duration::from_secs(600),
            &[],
        )?;
        fs::File::open(roots)?.sync_all()?;
        Ok(())
    }

    pub(super) fn generation_info(
        &self,
        name: &GuestName,
        generation: GenerationId,
    ) -> Result<GenerationInfo> {
        let info = self.store().describe(name, generation)?;
        ensure!(
            info.domain.as_str() == crate::store::runtime_namespace(name.as_str())
                && info.generation == generation
                && info.status == CheckStatus::Passed,
            "generation identity differs"
        );
        Ok(info)
    }

    fn receipt_identity(&self, receipt: AdmissionReceipt) -> Result<CheckedAdmission> {
        let info = self.generation_info(&receipt.domain, receipt.generation)?;
        CheckedAdmission::check(receipt, info)
    }

    fn publish_candidate(
        &self,
        manifest: &Value,
        topology: &Value,
        mut files: BTreeMap<&str, Value>,
    ) -> Result<PathBuf> {
        let id = state::digest(&json!({"release":manifest,"topology":topology}))?;
        let parent = self.state.join("candidates");
        state::directory(&parent)?;
        let path = parent.join(&id);
        files.insert("release.json", manifest.clone());
        files.insert("topology.json", topology.clone());
        files.insert("staged.json", manifest["stagedGenerations"].clone());
        if path.try_exists()? {
            state::trusted(&path)?;
            for (name, expected) in &files {
                ensure!(
                    state::read::<Value>(&path.join(name))? == *expected,
                    "existing candidate differs"
                );
            }
        } else {
            let temp = tempfile::Builder::new()
                .prefix(".candidate-")
                .tempdir_in(&parent)?;
            for (name, value) in files {
                state::save(&temp.path().join(name), &value)?;
            }
            let candidate = Release::load(temp.path())?;
            candidate.trust()?;
            fs::rename(temp.path(), &path)?;
            fs::File::open(parent)?.sync_all()?;
        }
        let r = Release::load(&path)?;
        self.pin(
            &format!("pending-{id}"),
            Path::new(
                r.manifest
                    .source_release
                    .as_ref()
                    .map_or(r.manifest.host.as_str(), StorePath::as_str),
            ),
        )?;
        Ok(path)
    }

    /// Bind exact guest receipts and the retained host view into an immutable machine candidate.
    pub fn machine_bind(
        &self,
        path: &Path,
        receipts: BTreeMap<GuestName, AdmissionReceipt>,
    ) -> Result<Value> {
        let _guard = MachineLock::acquire(
            &self.state,
            "Candidate preparation",
            "Bind admitted guest artifacts to their machine release",
            MachineOperation::Candidate,
        )?;
        self.ensure_no_pruning()?;
        let r = Release::load(path)?;
        r.trust()?;
        self.ensure_available(&r)?;
        ensure!(
            r.manifest.guest_transport == Some(GuestTransport::DirectPoolV1),
            "release does not use direct pool admission"
        );
        let roots: BTreeMap<GuestName, RootDescriptor> =
            state::read(&r.path.join("root-artifacts.json"))?;
        let linux: BTreeSet<_> = r
            .topology
            .domains
            .iter()
            .filter(|(_, d)| d.backend.hermit().is_none())
            .map(|(name, _)| name)
            .collect();
        ensure!(
            receipts.keys().collect::<BTreeSet<_>>() == linux
                && roots.keys().collect::<BTreeSet<_>>() == linux,
            "admission receipts or root catalog differ from guests"
        );
        let mut manifest: Value = state::read(&r.path.join("release.json"))?;
        manifest["guestRootArtifacts"] = serde_json::to_value(&roots)?;
        manifest["guestProvenance"] = json!({});
        manifest["stagedGenerations"] = json!({});
        let requirements: BTreeMap<_, _> = r
            .topology
            .domains
            .iter()
            .filter(|(_, d)| d.backend.hermit().is_none())
            .map(|(name, d)| {
                Ok((
                    name.clone(),
                    ExpectedAdmission {
                        domain: name.clone(),
                        system: d.backend.system.source.clone(),
                        closure_source: d.backend.nixos()?.store.source.clone(),
                        root_source: d.backend.nixos()?.root.source.clone(),
                        kernel_name: d.backend.nixos()?.kernel.name.clone(),
                        source_revision: r.manifest.revision.clone(),
                        lock_hash: r.manifest.lock_hash.clone(),
                        root_artifact: roots[name].clone(),
                    },
                ))
            })
            .collect::<Result<_>>()?;
        let expected = requirements
            .values()
            .map(|e| e.evidence(r.fingerprint().as_str()))
            .collect::<Result<Vec<_>, _>>()?;
        let mut checked_receipts = BTreeMap::new();
        let mut bound = Vec::new();
        for (key, receipt) in receipts {
            ensure!(
                key == receipt.domain,
                "admission domain differs from release"
            );
            let (receipt, evidence) = self
                .receipt_identity(receipt)?
                .bind(&requirements[&key], r.fingerprint().as_str())?;
            checked_receipts.insert(key, receipt);
            bound.push(evidence);
        }
        let admissions = BoundSet::new(&expected, bound, r.fingerprint().as_str().to_owned())
            .context("incomplete or inconsistent candidate admissions")?;
        ensure!(
            admissions.candidate() == r.fingerprint().as_str(),
            "admission set names another release"
        );
        for bound in admissions.entries() {
            let source = bound.source();
            manifest["guestProvenance"][bound.guest()] =
                json!({"revision":source.revision,"lockHash":source.lock_hash});
            manifest["stagedGenerations"][bound.guest()] = json!(bound.generation());
        }
        let mut prepared = Release::load(&r.path)?;
        prepared.manifest = serde_json::from_value(manifest.clone())?;
        for (name, generation) in &prepared.manifest.staged_generations {
            self.validate_generation(&prepared, name, *generation, false)?;
        }
        r.recheck()?;

        let mut host = self.store().publish_host(&r.manifest.host)?;
        host.observation()?;
        ensure!(
            host.system == r.manifest.host,
            "published host differs from candidate"
        );
        let timings = host.timings.take().unwrap_or(json!({}));
        manifest["hostPool"] = serde_json::to_value(host)?;
        manifest["sourceRelease"] = json!(r.path);
        let path = self.publish_candidate(
            &manifest,
            &r.raw_topology,
            BTreeMap::from([("receipts.json", json!(checked_receipts))]),
        )?;
        Ok(json!({"candidate":path,"timings":timings}))
    }

    /// Create a one-guest candidate while retaining all unchanged baseline identities.
    pub fn guest_candidate(&self, receipt: AdmissionReceipt) -> Result<PathBuf> {
        let _guard = MachineLock::acquire(
            &self.state,
            "Guest preparation",
            "Bind a guest admission to the deployed machine baseline",
            MachineOperation::Candidate,
        )?;
        self.ensure_no_pruning()?;
        let checked = self.receipt_identity(receipt)?;
        let receipt = checked.receipt();
        let info = checked.info();
        let name = &receipt.domain;
        let generation = receipt.generation;
        let revision = &receipt.source_revision;
        let lock_hash = &receipt.lock_hash;
        ensure!(
            !info.selected && receipt.current_generation != Some(generation),
            "receipt generation is already active"
        );
        let baseline = self.baseline()?;
        baseline.trust()?;
        let before = baseline
            .topology
            .domains
            .get(name)
            .context("receipt target is not declared")?;
        ensure!(
            before.backend.system.source != info.system
                || before.backend.nixos()?.root.source != info.root_source,
            "admitted guest system is already selected"
        );
        let mut topology = baseline.raw_topology.clone();
        let domain = &mut topology["domains"][name.as_str()];
        domain["backend"]["system"]["source"] = json!(info.system);
        domain["backend"]["root"]["source"] = json!(info.root_source);
        domain["backend"]["store"]["source"] = json!(info.closure_source);
        if let Some(opts) = domain["prefs"]["kernelopts"].as_str() {
            let mut tokens: Vec<_> = opts.split_whitespace().map(str::to_owned).collect();
            let matches: Vec<_> = tokens
                .iter()
                .filter_map(|s| s.strip_prefix("airlock.system="))
                .collect();
            ensure!(
                matches.is_empty() || matches == [before.backend.system.source.as_str()],
                "baseline guest boot system differs from topology"
            );
            for token in &mut tokens {
                if token.starts_with("airlock.system=") {
                    *token = format!("airlock.system={system}", system = info.system);
                }
            }
            domain["prefs"]["kernelopts"] = json!(tokens.join(" "));
        }

        let mut manifest: Value = state::read(&baseline.path.join("release.json"))?;
        manifest
            .as_object_mut()
            .context("invalid baseline manifest")?
            .remove("hostRepair");
        if let Ok(program) = std::env::var("AIRLOCK_DOM0_SERVICE") {
            let _: StoreFile = program.parse()?;
            manifest["coordinator"] = json!(program);
        }
        manifest["revision"] = json!(revision);
        manifest["lockHash"] = json!(lock_hash);
        manifest["baseRelease"] = json!(baseline.path);
        manifest["retireDomains"] = json!([]);
        manifest["privateVolumeCopies"] = json!({});
        for field in ["stagedGenerations", "guestRootArtifacts", "guestProvenance"] {
            if manifest.get(field).is_none() {
                manifest[field] = json!({});
            }
        }
        manifest["stagedGenerations"][name.as_str()] = json!(generation);
        manifest["guestRootArtifacts"][name.as_str()] =
            serde_json::to_value(&receipt.root_artifact)?;
        manifest["guestProvenance"][name.as_str()] =
            json!({"revision":revision,"lockHash":lock_hash});
        manifest["guestAdmission"] =
            json!({"domain":name,"generation":generation,"manifest":info.manifest});
        let mut prepared = Release::load(&baseline.path)?;
        prepared.manifest = serde_json::from_value(manifest.clone())?;
        prepared.topology = serde_json::from_value(topology.clone())?;
        prepared.manifest.validate(&prepared.topology)?;
        self.validate_generation(&prepared, name, generation, false)?;
        self.publish_candidate(
            &manifest,
            &topology,
            BTreeMap::from([("receipt.json", serde_json::to_value(receipt)?)]),
        )
    }

    pub(super) fn preparation_state(&self) -> Result<String> {
        let live = self.runner.text("nix-store", &["--gc", "--print-live"])?;
        state::digest(
            &json!({"selection":self.selection()?,"latest":state::optional::<Value>(&self.state.join("latest.json"))?,"running":self.running()?,"host_live_paths":live.lines().collect::<BTreeSet<_>>(),"booted_host":state::host()?}),
        )
    }

    /// Revalidate admitted storage and return a mutable-state token for a later apply.
    pub fn prepared_check(&self, path: &Path) -> Result<Value> {
        let _guard = MachineLock::acquire(
            &self.state,
            "Candidate validation",
            "Validate prepared release before activation",
            MachineOperation::Candidate,
        )?;
        let r = Release::load(path)?;
        r.trust()?;
        let plan = self.plan(&r)?;
        self.supported_apply(&r, &plan)?;
        Ok(json!({"plan":plan,"state":self.preparation_state()?}))
    }
}
