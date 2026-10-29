use super::*;
use airlock_nix_core::runtime::progress;

struct Activation<'a> {
    // Immutable candidate whose artifacts and source were checked during preflight.
    release: &'a Release,
    // Retained prior topology supplying retirement and rollback identities.
    baseline: &'a Release,
    // Guests that must survive a GUI-provider restart without rebooting.
    snapshots: &'a BTreeMap<GuestName, GuiSnapshot>,
    // Explicit, identity-checked private-volume replacement operations.
    copies: &'a [super::migration::PrivateCopy],
    // Whether journal recovery permits an already unassigned network controller.
    recovery: bool,
}

impl Coordinator {
    pub(super) fn publish_phase(
        &self,
        record: &mut Record,
        phase: Phase,
        lock: &mut MachineLock,
    ) -> Result<()> {
        record.phase = phase;
        lock.update(phase, Some(&record.id))?;
        self.persist(record)
    }

    pub(super) fn supported_apply(&self, r: &Release, p: &Plan) -> Result<()> {
        if r.manifest.guest_transport == Some(GuestTransport::DirectPoolV1) {
            ensure!(
                r.manifest
                    .staged_generations
                    .keys()
                    .collect::<BTreeSet<_>>()
                    == r.topology
                        .domains
                        .iter()
                        .filter(|(_, domain)| domain.backend.hermit().is_none())
                        .map(|(name, _)| name)
                        .collect(),
                "direct release is missing admitted generations"
            );
        }

        let transport = r
            .manifest
            .source_release
            .as_ref()
            .unwrap_or(&r.manifest.host);
        ensure!(
            Path::new(transport.as_str()).is_dir() && Path::new(r.manifest.host.as_str()).is_dir(),
            "candidate host and transport must already exist; dom0 does not build them"
        );

        self.ensure_no_pruning()?;
        for name in &p.restore {
            let trash = self.active_trash()?;
            self.validate_restore(
                trash.get(name).context("missing restore journal")?,
                &r.topology.domains[name],
            )?;
        }
        for (name, generation) in &r.manifest.staged_generations {
            self.validate_generation(r, name, *generation, false)?;
        }

        if let Some(expected) = r.manifest.extra.get("hostPool") {
            let expected: crate::store::HostReceipt = serde_json::from_value(expected.clone())?;
            let actual = self.store().validate_host(&r.manifest.host)?;
            ensure!(
                expected.binding()? == actual.binding()?,
                "prepared host view differs from release"
            );
        }
        Ok(())
    }

    /// Activate an admitted, source-approved release under the whole-machine lock.
    ///
    /// Record durable phases before disruption; return a journal outcome without rebooting the host.
    pub fn apply(
        &self,
        path: &Path,
        mode: ApplyMode,
        expected: Option<&str>,
        administrative: bool,
    ) -> Result<Record> {
        let mut lock = MachineLock::acquire(
            &self.state,
            "Deployment",
            "Activate approved machine configuration",
            if mode.is_recovery() {
                MachineOperation::Recover
            } else {
                MachineOperation::Apply
            },
        )?;
        if let Some(expected) = expected {
            ensure!(
                self.preparation_state()? == expected,
                "prepared candidate is stale; run machine-plan again"
            );
        }
        if administrative {
            ensure!(
                rustix::process::geteuid().is_root()
                    && Path::new("/etc/airlock/dev-mode").is_file(),
                "administrative repair requires dom0 root in development mode"
            );
        }
        let path = if administrative && path.starts_with("/nix/store") {
            self.local_candidate(path)?
        } else {
            path.to_owned()
        };
        self.apply_locked(&path, mode, &mut lock, administrative)
    }

    fn apply_locked(
        &self,
        path: &Path,
        mode: ApplyMode,
        lock: &mut MachineLock,
        administrative: bool,
    ) -> Result<Record> {
        lock.update(Phase::Preflight, None)?;
        let r = Release::load(path)?;
        r.trust()?;
        self.ensure_available(&r)?;
        ensure!(
            r.path.starts_with(self.state.join("candidates"))
                || (mode.is_recovery() && r.path == self.state.join("baseline")),
            "native activation requires a root-owned local candidate"
        );

        let latest = self.current()?;
        if mode == ApplyMode::New
            && latest
                .as_ref()
                .is_some_and(|record| record.phase.verified() && record.release.as_path() == r.path)
        {
            return self.verify_locked(lock);
        }
        if mode == ApplyMode::New
            && let Some(record) = &latest
        {
            ensure!(
                record.phase == Phase::Complete,
                "older deployment is unfinished or requires reboot; resolve it before a new apply"
            );
        }

        let recovery =
            if mode.is_recovery() {
                Some(self.recovery_decision(
                    latest.as_ref().context("no transaction to recover")?,
                    mode,
                )?)
            } else {
                None
            };
        let baseline = if let Some(decision) = &recovery {
            let (target, baseline) = decision.releases();
            ensure!(
                target.matches(&super::recovery::release(&r)?),
                "recovery target differs from recorded release"
            );
            let loaded = Release::load(Path::new(baseline.path()))?;
            ensure!(
                baseline.matches(&super::recovery::release(&loaded)?),
                "recovery baseline changed"
            );
            loaded
        } else {
            self.baseline()?
        };
        baseline.trust()?;
        if recovery.is_some() {
            let previous = latest.as_ref().context("missing recovery journal")?;
            self.check_recorded_release(
                if mode == ApplyMode::Resume {
                    &r
                } else {
                    &baseline
                },
                previous,
            )?;
        }
        ensure!(
            r.manifest.profile == state::profile()?
                && baseline.manifest.profile == r.manifest.profile,
            "deployment profile differs from booted profile"
        );
        if mode == ApplyMode::New {
            ensure!(
                state::host()? == baseline.manifest.host,
                "baseline host is not running; verify the older deployment first"
            );
            if let Some(selected) = self.selection()? {
                ensure!(
                    latest.as_ref().is_some_and(
                        |r| r.id == selected.transaction && r.release == selected.release
                    ),
                    "selected and latest transaction differ"
                );
                self.check_recorded_release(
                    &baseline,
                    latest.as_ref().context("missing baseline journal")?,
                )?;
            }
        }
        if mode == ApplyMode::New {
            self.verify_topology(&baseline, &self.deployment_running()?)?;
        }

        let mut running = self.deployment_running()?;
        if mode.is_recovery() {
            running.extend(
                latest
                    .as_ref()
                    .context("no transaction to recover")?
                    .plan
                    .start
                    .iter()
                    .cloned(),
            );
        }

        let mut plan = self.make_plan(&baseline, &r, &running, mode == ApplyMode::Rollback)?;
        let actual = self.deployment_running()?;
        plan.stop.retain(|n| actual.contains(n));
        self.supported_apply(&r, &plan)?;
        let copies = self.private_copy_plan(
            &baseline,
            &r,
            latest.as_ref().filter(|_| mode.is_recovery()),
        )?;
        if !copies.is_empty() {
            plan.extra.insert("private_copies".into(), json!(copies));
        }
        let trash = self.active_trash()?;
        plan.restore = r
            .topology
            .domains
            .keys()
            .filter(|n| trash.contains_key(*n))
            .cloned()
            .collect();
        for name in &plan.restore {
            self.validate_restore(&trash[name], &r.topology.domains[name])?;
        }
        if let Some(handoff) = &plan.pci_handoff {
            self.check_pci_handoff(handoff, mode.is_recovery())?;
        }
        let fingerprint = r.fingerprint();

        if let Some(repair) = r.manifest.extra.get("hostRepair").filter(|v| !v.is_null()) {
            ensure!(
                administrative
                    && repair["baselineHost"] == json!(state::host()?)
                    && repair["topologyHash"] == state::digest(&baseline.raw_topology)?
                    && baseline.raw_topology == r.raw_topology,
                "host repair requires administrative access and an unchanged live baseline"
            );
            plan.start.retain(|n| actual.contains(n));
        }
        let previous_attempt = latest.as_ref().filter(|_| mode.is_recovery());
        let authorization =
            self.authorize(&r, &baseline, &plan, previous_attempt, administrative)?;
        let previous_gui = if mode == ApplyMode::Resume {
            latest
                .as_ref()
                .and_then(|r| r.metadata.details.gui_preserved.as_ref())
        } else {
            None
        };

        let snapshots = self.gui_snapshot(&plan, previous_gui)?;
        let id = TransactionId::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_nanos()
                .to_string(),
        )?;
        let authorization = if let Some(decision) = recovery {
            authorization.recover(&id, decision)?
        } else {
            authorization.operation(&id)?
        };
        let operation = authorization.record()?;

        let mut record = Record {
            id,
            boot_id: state::boot_id()?,
            release: ReleasePath::from_path(&r.path)?,
            previous: ReleasePath::from_path(&baseline.path)?,
            revision: r.manifest.revision.clone(),
            plan,
            phase: Phase::Preflight,
            observed: BTreeMap::new(),
            host_running: None,
            host_selected: None,
            verified_at: None,
            generation_verified_at: None,
            metadata: JournalMetadata {
                origin: JournalOrigin::Native(NativeJournal {
                    native_coordinator: NativeVersion::V3,
                    release_fingerprint: fingerprint.clone(),
                    previous_fingerprint: baseline.fingerprint().clone(),
                }),
                details: JournalDetails {
                    operation: Some(operation),
                    gui_preserved: Some(snapshots.clone()),
                    recovery_of: latest
                        .as_ref()
                        .filter(|_| mode.is_recovery())
                        .map(|r| r.id.clone()),
                    ..JournalDetails::default()
                },
            },
        };
        let pinned = self.pin_images(
            &r,
            &mut record,
            previous_attempt,
            authorization.storage_plan(),
        )?;
        if administrative {
            record
                .metadata
                .details
                .extra
                .insert("administrative".into(), json!(true));
        }

        // Finish fallible observation before consuming approval. From publication
        // onward, even an uncertain write failure is recovered through latest.json.
        r.recheck()?;
        baseline.recheck()?;
        lock.update(Phase::Preflight, Some(&record.id))?;
        let mut durable = self.publish_intent(&record, authorization)?;
        let _recording =
            match progress::record_to(&self.state.join("progress").join(record.id.as_str())) {
                Ok(recording) => Some(recording),
                Err(error) => {
                    eprintln!("progress recording unavailable: {error}");
                    None
                }
            };
        let result = progress::phase("activation", || {
            self.activate(
                Activation {
                    release: &r,
                    baseline: &baseline,
                    snapshots: &snapshots,
                    copies: &copies,
                    recovery: mode.is_recovery(),
                },
                &mut record,
                lock,
                &mut durable,
                pinned,
            )
        });
        durable.finish(result.is_ok());
        if let Err(error) = result {
            let failed = record.phase;
            record.metadata.details.error = Some(format!("{error:#}"));
            record.metadata.details.failed_phase = Some(failed);
            self.publish_phase(&mut record, Phase::Failed, lock)
                .context(format!(
                    "activation failed: {error:#}; failed to record failure"
                ))?;
            return Err(error);
        }

        if let Some(mut old) = latest.filter(|_| mode.is_recovery()) {
            old.metadata.details.recovered_by = Some(record.id.clone());
            if let Err(error) = state::save(
                &self
                    .state
                    .join("transactions")
                    .join(old.id.as_str())
                    .join("status.json"),
                &old,
            ) {
                record
                    .metadata
                    .details
                    .extra
                    .insert("recovery_history_error".into(), json!(format!("{error:#}")));
                self.persist(&record)?;
            }
        }

        Ok(record)
    }

    fn activate(
        &self,
        activation: Activation<'_>,
        record: &mut Record,
        lock: &mut MachineLock,
        durable: &mut super::approval::DurableAuthorization,
        pinned: airlock_deployment_core::storage::staging::persistence::PinnedGenerations,
    ) -> Result<()> {
        durable.begin(record)?;
        let Activation {
            release: r,
            baseline,
            copies,
            recovery,
            ..
        } = activation;
        let directory = self.state.join("transactions").join(record.id.as_str());
        self.runner.record_to(directory.join("commands"))?;
        r.recheck()?;
        self.publish_phase(record, Phase::Staging, lock)?;
        use airlock_deployment_core::host::Action as HostAction;
        self.host_effect(durable.host(record, HostAction::PinHost)?)?;
        self.host_effect(durable.host(record, HostAction::PinTransport)?)?;
        let host_generation = self.host_generation(durable.host(
            record,
            if r.manifest.extra.contains_key("hostPool") {
                HostAction::Validate
            } else {
                HostAction::Publish
            },
        )?)?;
        self.host_effect(durable.host(record, HostAction::PinController)?)?;
        self.host_effect(durable.host(record, HostAction::InstallController)?)?;
        let staged = self.stage_images(record, &directory, durable, pinned)?;

        self.publish_phase(record, Phase::HostBootPreparation, lock)?;
        for action in [
            HostAction::ProtectBoot,
            HostAction::Profile,
            HostAction::InstallBoot,
            HostAction::SealBoot,
            HostAction::Checkpoint,
        ] {
            let request = if matches!(
                action,
                HostAction::Profile | HostAction::InstallBoot | HostAction::SealBoot
            ) {
                durable.host_checked(record, action, &host_generation)?
            } else {
                durable.host(record, action)?
            };
            progress::phase("activating_host", || self.host_effect(request))?;
        }

        let mut retirement = Vec::new();
        for (index, name) in record.plan.retire.iter().enumerate() {
            retirement.push(self.prepare_retirement(
                baseline,
                r,
                name,
                super::retirement::Execution {
                    authority: durable,
                    operation: record,
                    index,
                },
            )?);
        }
        let selection = Selection {
            release: record.release.clone(),
            previous: record.previous.clone(),
            transaction: record.id.clone(),
            profile: r.manifest.profile.clone(),
            extra: BTreeMap::new(),
        };
        state::save(&self.state.join("selection.json"), &selection)?;

        self.publish_phase(record, Phase::Stopping, lock)?;
        for name in &record.plan.stop {
            let observation = self.shutdown_observation(&baseline.topology, name)?;
            progress::phase("stopping_vm", || {
                self.runner
                    .shutdown_deployment(durable.shutdown(record, name, &observation)?)
            })?;
        }

        self.require_quiescent(record)?;
        self.publish_phase(record, Phase::Retiring, lock)?;
        for (index, entry) in retirement.into_iter().enumerate() {
            self.retire(
                entry,
                super::retirement::Execution {
                    authority: durable,
                    operation: record,
                    index,
                },
            )?;
        }

        self.require_quiescent(record)?;
        self.publish_phase(record, Phase::Configuring, lock)?;
        let configuring = progress::Span::start("configuring_vms");
        self.prepare_copies(copies)?;
        if record.plan.pci_handoff.is_some() {
            self.pci_handoff(durable, record, recovery)?;
        }
        use crate::setup_config::report::{CompletedSetup, ExpectedSetup};
        use airlock_deployment_core::configuration::SetupPhase;
        let expected = ExpectedSetup::new(record.id.clone(), &r.raw_topology)?;
        let result_path = directory.join("setup/setup-config.json");
        let protocol = self
            .runner
            .configuration_protocol(durable.configuration_batch(record, SetupPhase::Protocol)?)?;
        crate::setup_config::report::clear_result(&result_path)?;
        if protocol.native() {
            self.runner
                .configuration_batch(durable.configuration_batch(record, SetupPhase::Prepare)?)?;
            crate::setup_config::reconcile::apply(
                &self.runner,
                durable.configuration_definitions(),
                Some((durable, record, &staged)),
                true,
                None,
            )?;
            self.runner
                .configuration_batch(durable.configuration_batch(record, SetupPhase::Finish)?)?;
        } else {
            // Old admitted releases remain recoverable through their explicit,
            // whole-namespace compatibility adapter, under the same durable gate.
            self.runner
                .configuration_batch(durable.configuration_batch(record, SetupPhase::Legacy)?)?;
        }

        let completed = if protocol.covered() {
            expected.complete(&result_path)?
        } else if protocol.bound() {
            expected.complete_bound(&result_path)?
        } else {
            CompletedSetup::legacy(&result_path)?
        };
        configuring.complete();
        self.finish_activation(
            activation,
            record,
            lock,
            durable,
            &completed,
            &host_generation,
        )
    }

    /// All post-configuration progress consumes a checked setup result for this attempt and topology.
    fn finish_activation(
        &self,
        activation: Activation<'_>,
        record: &mut Record,
        lock: &mut MachineLock,
        durable: &super::approval::DurableAuthorization,
        completed: &crate::setup_config::report::CompletedSetup,
        host_generation: &airlock_deployment_core::host::CheckedGeneration,
    ) -> Result<()> {
        let Activation {
            release: r,
            snapshots,
            copies,
            ..
        } = activation;
        let expected =
            crate::setup_config::report::ExpectedSetup::new(record.id.clone(), &r.raw_topology)?;
        completed.require(&expected)?;
        use airlock_deployment_core::host::Action as HostAction;

        if !copies.is_empty() {
            self.publish_phase(record, Phase::CopyingPrivate, lock)?;
            self.copy_private(copies, durable, record)?;
        }
        let trash = self.active_trash()?;
        for (index, name) in record.plan.restore.iter().enumerate() {
            self.restore(
                trash.get(name).context("missing restore journal")?.clone(),
                r,
                super::retirement::Execution {
                    authority: durable,
                    operation: record,
                    index,
                },
            )?;
        }

        self.publish_phase(record, Phase::Starting, lock)?;
        for name in &record.plan.start {
            if !self.running()?.contains(name) {
                progress::phase("starting_vm", || {
                    self.runner.start_deployment(durable.start(record, name)?)
                })?;
            }
        }

        self.publish_phase(record, Phase::Verifying, lock)?;
        let required = record.plan.start.iter().cloned().collect();
        let verified = progress::phase("verifying_deployment", || {
            self.verify_deployment(r, record, &required)
        })?;
        if !snapshots.is_empty() {
            self.publish_phase(record, Phase::GuiReconnecting, lock)?;
            record.metadata.details.gui_reconnected = Some(self.gui_verify(snapshots)?);
        }

        // The existing boot path can regenerate this optimization receipt. Never
        // leave a stale 'already configured' receipt after native convergence.
        let receipt = self.state.join("boot-configuration.json");
        if receipt.try_exists()? {
            state::trusted(&receipt)?;
            fs::remove_file(receipt)?;
            fs::File::open(&self.state)?.sync_all()?;
        }

        self.publish_phase(record, Phase::HostBootSelection, lock)?;
        r.recheck()?;
        self.host_effect(durable.host_checked(record, HostAction::Bind, host_generation)?)?;
        self.host_effect(durable.host_checked(record, HostAction::Select, host_generation)?)?;

        self.complete_deployment(r, record, lock, verified)
    }

    /// Lock before selecting the recorded native transaction, then resume it or restore its baseline.
    pub fn recover(&self, mode: ApplyMode) -> Result<Record> {
        let mut lock = MachineLock::acquire(
            &self.state,
            "Deployment recovery",
            "Recover the recorded machine transaction",
            MachineOperation::Recover,
        )?;

        let latest = self.current()?.context("no transaction to recover")?;
        ensure!(mode.is_recovery(), "recovery mode required");
        let decision = self.recovery_decision(&latest, mode)?;
        if matches!(
            decision.action(),
            airlock_deployment_core::recovery::Action::Verify
        ) {
            return self.verify_locked(&mut lock);
        }
        ensure!(
            latest.phase != Phase::Complete,
            "no unfinished deployment to recover"
        );

        let target = PathBuf::from(decision.releases().0.path());
        let administrative =
            latest.metadata.details.extra.get("administrative") == Some(&json!(true));
        if administrative {
            ensure!(
                Path::new("/etc/airlock/dev-mode").is_file(),
                "administrative recovery requires development mode"
            );
        }
        self.apply_locked(&target, mode, &mut lock, administrative)
    }
}
