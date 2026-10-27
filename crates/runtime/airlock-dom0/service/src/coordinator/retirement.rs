//! Retain removed VMs as registered, stopped trash and explicitly purge unreferenced data.
//! Every destructive step follows an identity-checked durable journal under the machine lock.

use super::*;
use crate::qubes;
use airlock_deployment_core::retirement as verified;

/// One checked operation and list coordinate; raw trash records cannot replace this authority.
pub(super) struct Execution<'a> {
    /// Executing gate and immutable approved target/configuration set.
    pub authority: &'a super::approval::DurableAuthorization,
    /// Current operation identities, rechecked before every request.
    pub operation: &'a Record,
    /// Coordinate in the exact retire or restore plan field.
    pub index: usize,
}

/// Preserve existing restoration semantics while binding complete retirement configuration.
fn configuration(domain: &Domain, kind: verified::Kind) -> Result<String> {
    state::digest(&match kind {
        verified::Kind::Retire => serde_json::to_value(domain)?,
        verified::Kind::Restore => {
            json!({"class":domain.class_name,"template":domain.template,"private":domain.backend.state()})
        }
    })
}

/// Decode immutable baseline/candidate definitions in the checked effect-field order.
pub(super) fn definitions(
    plan: &Plan,
    release: &Release,
    baseline: &Release,
    kind: verified::Kind,
    service: &str,
) -> Result<Vec<verified::Definition>> {
    let (names, topology) = match kind {
        verified::Kind::Retire => (&plan.retire, &baseline.topology),
        verified::Kind::Restore => (&plan.restore, &release.topology),
    };
    names
        .iter()
        .map(|name| {
            let domain = topology
                .domains
                .get(name)
                .context("retirement/restoration target missing from immutable topology")?;
            Ok(verified::Definition {
                name: name.as_str().into(),
                configuration: configuration(domain, kind)?,
                system: domain.backend.system.source.as_str().into(),
                baseline: baseline
                    .path
                    .to_str()
                    .context("invalid baseline path")?
                    .into(),
                service: service.into(),
            })
        })
        .collect()
}

/// Volume comparison differs intentionally: restoration may change the root but preserves private storage.
fn resource_identity(
    volumes: &BTreeMap<String, qubes::Volume>,
    kind: verified::Kind,
) -> Result<String> {
    state::digest(&match kind {
        verified::Kind::Retire => serde_json::to_value(volumes)?,
        verified::Kind::Restore => serde_json::to_value(
            volumes
                .get("private")
                .context("private volume missing from restore identity")?,
        )?,
    })
}

/// Faithfully translate protected trash fields; status and ID checks execute in the verified gate.
fn receipt(record: &TrashRecord, kind: verified::Kind) -> Result<verified::Receipt> {
    Ok(verified::Receipt {
        id: record.id.clone(),
        baseline: record
            .source_release
            .as_path()
            .to_str()
            .context("invalid retirement source release")?
            .into(),
        transaction: record.source_transaction.as_str().into(),
        name: record.domain.as_str().into(),
        uuid: record.uuid.to_string(),
        configuration: configuration(&record.domain_config, kind)?,
        resources: resource_identity(&record.storage.volumes, kind)?,
        system: record.domain_config.backend.system.source.as_str().into(),
        manifest: record.storage.pool_manifest.clone(),
        generation: record.pool_generation.to_string(),
        status: match record.status {
            TrashStatus::Planned => verified::Status::Planned,
            TrashStatus::Retiring => verified::Status::Retiring,
            TrashStatus::Trashed => verified::Status::Trashed,
            TrashStatus::Purging => verified::Status::Purging,
            TrashStatus::Purged => verified::Status::Purged,
            TrashStatus::Restored => verified::Status::Restored,
        },
    })
}

fn retention_days(r: &Release) -> Result<u32> {
    let days = r
        .manifest
        .extra
        .get("trashRetentionDays")
        .map(Value::as_u64)
        .unwrap_or(Some(30))
        .context("invalid trash retention")?;
    ensure!(
        (1..=3650).contains(&days),
        "trash retention must be 1–3650 days"
    );
    Ok(days as u32)
}

impl Coordinator {
    pub(super) fn trash_path(&self, identity: &str) -> Result<PathBuf> {
        let (transaction, name) = identity
            .split_once('-')
            .context("invalid trash record ID")?;
        let _: TransactionId = transaction.to_owned().try_into()?;
        let _: GuestName = name.parse()?;
        Ok(self.state.join("trash").join(format!("{identity}.json")))
    }

    pub(super) fn active_trash(&self) -> Result<BTreeMap<GuestName, TrashRecord>> {
        let mut result = BTreeMap::new();
        for record in self.trash()?.into_iter().filter(|r| r.status.is_active()) {
            ensure!(
                record.purge_after.is_finite()
                    && record.purge_after > 0.0
                    && (1..=3650).contains(&record.retention_days),
                "invalid trash retention record"
            );
            ensure!(
                result.insert(record.domain.clone(), record).is_none(),
                "multiple active trash records for one VM"
            );
        }
        Ok(result)
    }

    pub(super) fn registered(&self) -> Result<BTreeSet<GuestName>> {
        self.runner
            .text("qvm-ls", &["--raw-list"])?
            .lines()
            .filter(|n| *n != "dom0")
            .map(|n| Ok(n.parse()?))
            .collect()
    }

    pub(super) fn vm_uuid(&self, name: &GuestName) -> Result<BootId> {
        self.runner
            .text("qvm-prefs", &[name.as_str(), "uuid"])?
            .parse()
    }

    pub(super) fn prepare_retirement(
        &self,
        baseline: &Release,
        release: &Release,
        name: &GuestName,
        execution: Execution<'_>,
    ) -> Result<TrashRecord> {
        let id = &execution.operation.id;
        ensure!(
            Path::new("/var/lib/airlock/qubes-policy.d/05-airlock-retired.policy").is_file(),
            "retired-domain qrexec policy is not installed"
        );
        let domain = baseline
            .topology
            .domains
            .get(name)
            .context("retired VM absent from baseline")?;
        if let Some(existing) = self.active_trash()?.remove(name) {
            ensure!(
                existing.status != TrashStatus::Purging
                    && existing.domain_config == *domain
                    && existing.uuid == self.vm_uuid(name)?,
                "active trash identity differs or purge is in progress"
            );
            self.pin_retirement(&existing, &execution)?;
            return Ok(existing);
        }
        // The first attempt's protected proposal fixes the registration and storage before disruption.
        // Reuse it across retries; recapturing here could retire a replacement VM after a crash.
        let operation = &execution
            .operation
            .metadata
            .details
            .operation
            .as_ref()
            .context("missing stable retirement operation")?
            .id;
        let proposal = self
            .state
            .join("transactions")
            .join(operation.as_str())
            .join(format!("trash-{name}.json"));
        if let Some(saved) = state::optional::<TrashRecord>(&proposal)? {
            ensure!(
                saved.domain == *name
                    && saved.domain_config == *domain
                    && saved.source_release.as_path() == baseline.path
                    && saved.uuid == self.vm_uuid(name)?
                    && saved.storage.volumes == qubes::volumes(name)?,
                "retirement proposal differs from the original VM, configuration or storage"
            );
            self.pin_retirement(&saved, &execution)?;
            return Ok(saved);
        }
        let generation: GenerationId = self
            .runner
            .text("qvm-features", &[name.as_str(), "airlock-store-generation"])?
            .parse()?;
        let info = self.generation_info(name, generation)?;
        ensure!(
            info.system == domain.backend.system.source,
            "retirement pool generation differs from release"
        );
        let retention_days = retention_days(release)?;
        let record = TrashRecord {
            _schema: TrashSchema::V1,
            id: format!("{}-{name}", id.as_str()),
            domain: name.clone(),
            status: TrashStatus::Planned,
            uuid: self.vm_uuid(name)?,
            domain_config: domain.clone(),
            source_release: ReleasePath::from_path(&baseline.path)?,
            source_transaction: id.clone(),
            pool_generation: generation,
            purge_after: state::now() + f64::from(retention_days) * 86400.0,
            retention_days,
            storage: TrashStorage {
                disposition: "registered-stopped".into(),
                private: domain.backend.state()["persistent"].clone(),
                pool_manifest: info
                    .manifest
                    .to_str()
                    .context("missing pool manifest")?
                    .into(),
                volumes: qubes::volumes(name)?,
            },
            extra: BTreeMap::new(),
        };
        state::save(&proposal, &record)?;
        let attempt_proposal = self
            .state
            .join("transactions")
            .join(id.as_str())
            .join(format!("trash-{name}.json"));
        if attempt_proposal != proposal {
            state::save(&attempt_proposal, &record)?;
        }
        self.pin_retirement(&record, &execution)?;
        Ok(record)
    }

    /// Reconcile the baseline root even when a prior process died after publishing its proposal.
    fn pin_retirement(&self, record: &TrashRecord, execution: &Execution<'_>) -> Result<()> {
        if record.source_release.as_path().starts_with("/nix/store") {
            let request = execution.authority.retirement_pin(
                execution.operation,
                execution.index,
                &receipt(record, verified::Kind::Retire)?,
            )?;
            let roots = self.state.join("roots");
            state::directory(&roots)?;
            let root = roots.join(format!("trash-{id}", id = request.trash_id()));
            self.runner
                .retirement_pin(request, root.to_str().context("invalid retirement root")?)?;
        }
        Ok(())
    }

    pub(super) fn retire(
        &self,
        mut record: TrashRecord,
        execution: Execution<'_>,
    ) -> Result<TrashRecord> {
        let path = self.trash_path(&record.id)?;
        if let Some(current) = state::optional::<TrashRecord>(&path)? {
            ensure!(
                current.domain_config == record.domain_config
                    && current.uuid == record.uuid
                    && current.storage.volumes == record.storage.volumes,
                "existing trash record differs"
            );
            record = current;
        }
        let receipt = receipt(&record, verified::Kind::Retire)?;
        let observed = self.retirement_observation(&record, verified::Kind::Retire)?;
        let request = execution.authority.retirement(
            execution.operation,
            execution.index,
            verified::Kind::Retire,
            &receipt,
            &observed,
        )?;
        record.status = TrashStatus::Retiring;
        state::save(&path, &record)?;
        self.runner.retirement_deployment(&request)?;
        if record.extra.get("retired_at").is_none_or(Value::is_null) {
            record
                .extra
                .insert("retired_at".into(), json!(state::now()));
            record.purge_after = state::now() + f64::from(record.retention_days) * 86400.0;
        }
        record.status = TrashStatus::Trashed;
        state::save(&path, &record)?;
        Ok(record)
    }

    pub(super) fn validate_restore(&self, record: &TrashRecord, domain: &Domain) -> Result<()> {
        ensure!(
            record.status != TrashStatus::Purging
                && record.domain_config.class_name == domain.class_name
                && record.domain_config.template == domain.template
                && record.domain_config.backend.state() == domain.backend.state()
                && record.uuid == self.vm_uuid(&record.domain)?,
            "restore changes VM or private storage identity, or purge is in progress"
        );
        Ok(())
    }

    pub(super) fn restore(
        &self,
        mut record: TrashRecord,
        release: &Release,
        execution: Execution<'_>,
    ) -> Result<()> {
        let id = &execution.operation.id;
        self.validate_restore(&record, &release.topology.domains[&record.domain])?;
        let receipt = receipt(&record, verified::Kind::Restore)?;
        let observed = self.retirement_observation(&record, verified::Kind::Restore)?;
        let request = execution.authority.retirement(
            execution.operation,
            execution.index,
            verified::Kind::Restore,
            &receipt,
            &observed,
        )?;
        self.runner.retirement_deployment(&request)?;
        record.status = TrashStatus::Restored;
        record.storage.disposition = "active".into();
        record.extra.extend(BTreeMap::from([
            ("restored_at".into(), json!(state::now())),
            ("restored_by_release".into(), json!(release.path)),
            ("restored_by_transaction".into(), json!(id)),
        ]));
        state::save(&self.trash_path(request.trash_id())?, &record)?;
        state::unlink(
            &self
                .state
                .join("roots")
                .join(format!("trash-{id}", id = request.trash_id())),
        )
    }

    /// Observe the same registration, storage and selected generation immediately before requesting mutation.
    fn retirement_observation(
        &self,
        record: &TrashRecord,
        kind: verified::Kind,
    ) -> Result<verified::Observation> {
        let name = &record.domain;
        let (generation, system, manifest) = match kind {
            verified::Kind::Retire => {
                let generation: GenerationId = self
                    .runner
                    .text("qvm-features", &[name.as_str(), "airlock-store-generation"])?
                    .parse()?;
                let info = self.generation_info(name, generation)?;
                (
                    generation.to_string(),
                    info.system.to_string(),
                    info.manifest
                        .to_str()
                        .context("missing generation manifest")?
                        .into(),
                )
            }
            verified::Kind::Restore => (String::new(), String::new(), String::new()),
        };
        Ok(verified::Observation {
            name: name.as_str().into(),
            uuid: self.vm_uuid(name)?.to_string(),
            resources: resource_identity(&qubes::volumes(name)?, kind)?,
            generation,
            system,
            manifest,
            power: self.operation_power(name)?,
        })
    }

    /// Permanently remove one confirmed, expired and unreferenced retired VM; retries resume its journal.
    pub fn trash_purge(&self, id: &str, confirmation: &str, before_expiry: bool) -> Result<Value> {
        ensure!(
            id == confirmation,
            "trash purge confirmation does not match record ID"
        );
        let _guard = MachineLock::acquire(
            &self.state,
            "VM trash purge",
            "Permanently remove an explicitly confirmed retired VM",
            MachineOperation::Purge,
        )?;
        self.ensure_no_pruning()?;
        if let Some(latest) = state::optional::<Record>(&self.state.join("latest.json"))? {
            ensure!(
                latest.phase.verified(),
                "unfinished deployment; resume or rollback first"
            );
        }
        let path = self.trash_path(id)?;
        let mut record: TrashRecord = state::read(&path)?;
        ensure!(record.id == id, "trash record identity differs");
        if record.status == TrashStatus::Purged {
            return Ok(json!(record));
        }
        ensure!(
            matches!(record.status, TrashStatus::Trashed | TrashStatus::Purging),
            "trash record is not eligible for purge"
        );
        ensure!(
            record.purge_after.is_finite() && record.purge_after > 0.0,
            "invalid trash expiry"
        );
        let early = state::now() < record.purge_after;
        ensure!(
            !early
                || before_expiry
                || record.extra.get("purged_before_expiry") == Some(&json!(true)),
            "trash retention window has not expired"
        );
        let confirmed = airlock_deployment_core::purge::ConfirmedPurge::new(
            id,
            confirmation,
            receipt(&record, verified::Kind::Retire)?,
        )
        .context("invalid confirmed purge identity")?;
        let name = &record.domain;
        for release in self.release_inventory()?.keys() {
            if self.prune_path(release)?.try_exists()? {
                continue;
            }
            ensure!(
                !planning::references_domain(&Release::load(Path::new(release))?.topology, name)?,
                "retained deployment still references VM {name}"
            );
        }
        if let Some(selected) = self.selection()? {
            for release in [&selected.release, &selected.previous] {
                ensure!(
                    !planning::references_domain(
                        &Release::load(release.as_path())?.topology,
                        name
                    )?,
                    "retained selection still references VM {name}"
                );
            }
        }
        for host in self
            .host_profiles()?
            .values()
            .cloned()
            .chain(self.running_hosts()?)
        {
            let topology: Topology =
                state::configuration(&Path::new(&host).join("etc/airlock/qubes-topology.json"))?;
            ensure!(
                !planning::references_domain(&topology, name)?,
                "retained host profile still references VM {name}"
            );
        }
        ensure!(!self.running()?.contains(name), "cannot purge a running VM");
        let cleanup = if self.registered()?.contains(name) {
            ensure!(
                record.uuid == self.vm_uuid(name)?,
                "registered VM identity differs from trash"
            );
            let volumes = qubes::volumes(name)?;
            ensure!(
                !record.storage.volumes.is_empty() && volumes == record.storage.volumes,
                "volume identity differs from trash"
            );
            for other in self.registered()?.into_iter().filter(|n| n != name) {
                for volume in qubes::volumes(&other)?.values() {
                    for owned in volumes.values().filter(|v| v.rw || v.save_on_stop) {
                        ensure!(
                            volume.pool != owned.pool
                                || (volume.vid != owned.vid
                                    && volume.source.as_ref() != Some(&owned.vid)),
                            "private storage referenced by {other}"
                        );
                    }
                }
            }
            ensure!(
                self.runner
                    .text("qvm-tags", &[name.as_str(), "list"])?
                    .lines()
                    .any(|t| t == "airlock-retired"),
                "retirement tag is missing"
            );
            ensure!(
                self.runner
                    .text("qvm-features", &[name.as_str(), "airlock-store-generation"])?
                    == record.pool_generation.to_string(),
                "pool generation differs from trash"
            );
            let info = self.generation_info(name, record.pool_generation)?;
            ensure!(
                info.manifest == Path::new(&record.storage.pool_manifest)
                    && info.system == record.domain_config.backend.system.source,
                "pool identity differs from trash"
            );
            let observed = self.retirement_observation(&record, verified::Kind::Retire)?;
            let tags = self
                .runner
                .text("qvm-tags", &[name.as_str(), "list"])?
                .lines()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            let intent = confirmed
                .prepare(&observed, &tags)
                .context("purge requires original resources and an explicitly halted VM")?;
            record.status = TrashStatus::Purging;
            if early {
                record
                    .extra
                    .insert("purged_before_expiry".into(), json!(true));
            }
            state::save(&path, &record)?;
            self.runner.purge_remove(intent.published())?
        } else {
            let registered = self
                .registered()?
                .into_iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>();
            confirmed
                .absent(&registered)
                .context("VM disappeared before purge began")?
        };
        let (name, generation) = cleanup.storage();
        self.store()
            .retire_generation(&name.parse()?, generation.parse()?)?;
        state::unlink(
            &self
                .state
                .join("roots")
                .join(format!("trash-{id}", id = cleanup.identity())),
        )?;
        record.status = TrashStatus::Purged;
        record.storage.disposition = "purged".into();
        record.extra.insert("purged_at".into(), json!(state::now()));
        state::save(&path, &record)?;
        Ok(json!(record))
    }
}
