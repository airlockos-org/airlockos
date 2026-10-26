use super::*;

mod completion;

pub(super) use completion::VerifiedDeployment;

impl Coordinator {
    pub(super) fn check_recorded_release(&self, r: &Release, record: &Record) -> Result<()> {
        ensure!(
            record.release.as_path() == r.path && record.revision == r.manifest.revision,
            "release source differs from journal"
        );
        if let JournalOrigin::Native(native) = &record.metadata.origin {
            ensure!(
                &native.release_fingerprint == r.fingerprint()
                    && (!record.phase.verified()
                        || record.host_selected.as_ref() == Some(&r.manifest.host)),
                "selected release changed since activation"
            );
        }
        Ok(())
    }

    pub(super) fn generation(
        &self,
        name: &GuestName,
        generation: GenerationId,
    ) -> Result<GenerationInfo> {
        let info = self.store().describe(name, generation)?;
        ensure!(
            info.status == CheckStatus::Passed,
            "{name}: invalid generation description"
        );
        Ok(info)
    }

    /// Retain the legacy validation API for admission and boot callers.
    pub(super) fn validate_generation(
        &self,
        r: &Release,
        name: &GuestName,
        generation: GenerationId,
        selected: bool,
    ) -> Result<()> {
        self.checked_generation(r, name, generation, selected)
            .map(|_| ())
    }

    fn checked_generation(
        &self,
        r: &Release,
        name: &GuestName,
        generation: GenerationId,
        selected: bool,
    ) -> Result<GenerationInfo> {
        let info = self.generation(name, generation)?;
        let b = &r.topology.domains[name].backend;
        ensure!(
            info.domain.as_str() == crate::store::runtime_namespace(name.as_str())
                && info.generation == generation,
            "{name}: generation identity differs"
        );
        ensure!(
            info.system == b.system.source,
            "{name}: generation system differs"
        );
        ensure!(
            info.root_source == b.nixos()?.root.source,
            "{name}: generation root differs"
        );
        ensure!(
            info.kernel_name == b.nixos()?.kernel.name,
            "{name}: generation kernel differs"
        );
        ensure!(
            info.closure_source == b.nixos()?.store.source,
            "{name}: generation closure differs"
        );
        ensure!(
            info.store.mountpoint == b.nixos()?.store.mountpoint
                && info.store.device == b.nixos()?.store.device
                && info.store.blob_device == b.nixos()?.store.blob_device
                && info.store.view_backend == b.nixos()?.store.view_backend,
            "{name}: storage configuration differs"
        );
        ensure!(
            info.verification.status == CheckStatus::Passed,
            "{name}: pool generation is not verified"
        );

        if let Some(artifact) = r.manifest.guest_root_artifacts.get(name) {
            ensure!(
                info.root_artifact.as_ref() == Some(artifact),
                "{name}: selected root artifact differs from release"
            );
        }

        if selected {
            ensure!(info.selected, "{name}: pool generation is not selected");
        } else {
            ensure!(
                info.retention.as_ref().is_some_and(|r| r.retain),
                "{name}: staged generation is not retained"
            );

            let artifact = r
                .manifest
                .guest_root_artifacts
                .get(name)
                .context("missing staged root artifact")?;
            ensure!(
                info.root_artifact.as_ref() == Some(artifact),
                "{name}: root artifact differs"
            );

            let approval: GenerationApproval = serde_json::from_value(info.approval.clone())
                .context("invalid generation approval")?;
            ensure!(
                approval.source == b.nixos()?.store.source,
                "{name}: generation approval differs"
            );

            let actual: GenerationProvenance = serde_json::from_value(info.provenance.clone())
                .context("invalid generation provenance")?;
            let expected = r
                .manifest
                .guest_provenance
                .get(name)
                .cloned()
                .unwrap_or(Provenance {
                    revision: r.manifest.revision.clone(),
                    lock_hash: r.manifest.lock_hash.clone(),
                });
            ensure!(
                actual.source_revision == expected.revision
                    && actual.lock_hash == expected.lock_hash,
                "{name}: generation provenance differs"
            );
        }
        Ok(info)
    }

    pub(super) fn wait_guest(&self, name: &GuestName, domain: &Domain) -> Result<StorePath> {
        let expected = &domain.backend.system.source;
        let worker = crate::readiness::worker_probe(
            domain.features.get("airlock-role").and_then(Value::as_str),
        );
        let deadline = Instant::now() + Duration::from_secs(180);
        let mut error = "guest is not running".to_owned();
        while Instant::now() < deadline {
            let remaining = deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(10));
            let probe = self.runner.run(
                "qvm-ls",
                &[
                    "--raw-data".into(),
                    "--fields".into(),
                    "NAME,STATE".into(),
                    name.as_str().into(),
                ],
                remaining,
                &[],
            );
            match probe {
                Ok(row) if row == format!("{name}|Running") => {
                    if let Some(artifact) = domain.backend.hermit() {
                        let readiness = (|| -> Result<()> {
                            let xid: u32 = self
                                .runner
                                .text("qvm-prefs", &[name.as_str(), "xid"])?
                                .parse()?;
                            crate::hermit::ready(name.as_str(), artifact, xid)
                        })();
                        match readiness {
                            Ok(()) => return Ok(expected.clone()),
                            Err(failure) => error = failure.to_string(),
                        }
                        thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                    let args = [
                        "-d".into(),
                        name.as_str().into(),
                        "user:readlink -f /run/current-system".into(),
                    ];
                    match self.runner.run(
                        "qrexec-client",
                        &args,
                        deadline
                            .saturating_duration_since(Instant::now())
                            .min(Duration::from_secs(10)),
                        &[],
                    ) {
                        Ok(s) => {
                            let actual: StorePath = s.parse()?;
                            ensure!(
                                &actual == expected,
                                "{name}: running generation differs from selected release: {actual}"
                            );
                            if let Some(command) = &worker {
                                if let Err(failure) = self.runner.run(
                                    "qrexec-client",
                                    &["-d".into(), name.as_str().into(), command.into()],
                                    deadline
                                        .saturating_duration_since(Instant::now())
                                        .min(Duration::from_secs(15)),
                                    &[],
                                ) {
                                    error = failure.to_string();
                                } else {
                                    return Ok(actual);
                                }
                            } else {
                                return Ok(actual);
                            }
                        }
                        Err(e) => error = e.to_string(),
                    }
                }
                Ok(_) => {}
                Err(e) => error = e.to_string(),
            }
            thread::sleep(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_secs(1)),
            );
        }

        bail!("{name}: readiness timed out: {error}")
    }

    pub(super) fn verify_topology(
        &self,
        r: &Release,
        required: &BTreeSet<GuestName>,
    ) -> Result<BTreeMap<GuestName, Observation>> {
        self.observe_topology(r, required)
            .map(|(observed, _)| observed)
    }

    /// Gather the original status projection and full numeric/storage facts from the same probes.
    fn observe_topology(
        &self,
        r: &Release,
        required: &BTreeSet<GuestName>,
    ) -> Result<(
        BTreeMap<GuestName, Observation>,
        Vec<airlock_deployment_core::completion::Observation>,
    )> {
        use airlock_deployment_core::completion::{
            NativeObservation, Observation as GuestObservation,
        };
        let mut facts = Vec::new();
        let mut observed = BTreeMap::new();
        for (name, d) in &r.topology.domains {
            let selected: StorePath = self
                .runner
                .text("qvm-features", &[name.as_str(), "airlock-system-source"])?
                .parse()?;
            ensure!(
                selected == d.backend.system.source,
                "{name}: selected system differs from release"
            );

            if let Some(artifact) = d.backend.hermit() {
                let descriptor = serde_json::to_string(artifact)?;
                let configured = self
                    .runner
                    .text("qvm-features", &[name.as_str(), "airlock-hermit-artifact"])?;
                ensure!(
                    configured == descriptor,
                    "{name}: selected Hermit artifact differs from release"
                );
                let actual = if required.contains(name) {
                    Some(self.wait_guest(name, d)?)
                } else {
                    None
                };
                facts.push(GuestObservation::Hermit {
                    name: name.to_string(),
                    system: selected.to_string(),
                    descriptor,
                    running_system: actual.as_ref().map(ToString::to_string),
                });
                observed.insert(
                    name.clone(),
                    Observation {
                        selected,
                        running: actual,
                    },
                );
                continue;
            }
            let text = self
                .runner
                .text("qvm-features", &[name.as_str(), "airlock-store-generation"])?;
            let generation: GenerationId = text
                .parse()
                .context("invalid selected storage generation")?;
            if let Some(expected) = r.manifest.staged_generations.get(name) {
                ensure!(
                    generation == *expected,
                    "{name}: selected pool generation differs from staged generation"
                );
            }
            let info = self.checked_generation(r, name, generation, true)?;

            let actual = if required.contains(name) {
                Some(self.wait_guest(name, d)?)
            } else {
                None
            };
            facts.push(GuestObservation::Native(Box::new(NativeObservation {
                selection: crate::store::handoff::described(&info)?,
                feature_system: selected.to_string(),
                feature_generation: generation.get(),
                pool_selected: info.selected,
                running_system: actual.as_ref().map(ToString::to_string),
            })));
            observed.insert(
                name.clone(),
                Observation {
                    selected,
                    running: actual,
                },
            );
        }

        Ok((observed, facts))
    }

    pub(super) fn expected_running(
        &self,
        r: &Release,
        record: &Record,
    ) -> Result<BTreeSet<GuestName>> {
        let mut required: BTreeSet<_> = if record.boot_id == state::boot_id()? {
            record.plan.start.iter().cloned().collect()
        } else {
            planning::plan(&r.topology, &r.topology, &BTreeSet::new(), &[], false)?
                .start
                .into_iter()
                .collect()
        };
        required.extend(
            self.running()?
                .into_iter()
                .filter(|n| r.topology.domains.contains_key(n)),
        );

        Ok(required)
    }

    /// Verify image generations or the selected deployment under exclusion.
    /// Image verification reports observations without creating a deployment transaction.
    pub fn verify(&self) -> Result<Value> {
        let mut guard = MachineLock::acquire(
            &self.state,
            "Deployment verification",
            "Verify selected and running generations",
            MachineOperation::Verify,
        )?;
        if self.selection()?.is_none() {
            return self.verify_image_baseline();
        }
        Ok(serde_json::to_value(self.verify_locked(&mut guard)?)?)
    }

    pub(super) fn verify_locked(&self, guard: &mut MachineLock) -> Result<Record> {
        let selected = self.selection()?.context("no selected deployment")?;
        let mut record = self.record(&selected.transaction)?;
        ensure!(
            record.phase.verified(),
            "unfinished deployment; resume or rollback first"
        );
        ensure!(
            record.release == selected.release && record.previous == selected.previous,
            "selected release differs from transaction"
        );
        if let Some(latest) = state::optional::<Record>(&self.state.join("latest.json"))? {
            ensure!(
                latest.id == record.id,
                "a different transaction is current; inspect recovery state"
            );
        }

        let r = Release::load(selected.release.as_path())?;
        r.trust()?;
        self.ensure_available(&r)?;
        ensure!(
            selected.profile == r.manifest.profile
                && selected.profile == state::profile()?
                && record.revision == r.manifest.revision,
            "selected source/profile differs from journal"
        );
        self.check_recorded_release(&r, &record)?;

        guard.update(Phase::Verifying, Some(&record.id))?;
        let required = self.expected_running(&r, &record)?;
        let verified = self.verify_deployment(&r, &mut record, &required)?;
        self.enforce_trash(&r.topology)?;
        r.recheck()?;

        self.complete_deployment(&r, &mut record, guard, verified)?;

        Ok(record)
    }
}
