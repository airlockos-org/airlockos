//! Protect source-review decisions in dom0 before evaluation or artifact admission.
//! A review binds a source, target, boot and deployed baseline to the user's scope.

use super::*;
use airlock_nix_core::{
    identity::{BaselineFingerprint, GitRevision, LockHash, ReviewFingerprint, ReviewId},
    review::{Decision, Scope},
};
use serde::Deserialize;
use std::io::{BufRead, Read};

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ReviewControl {
    Context {
        // Exact committed source proposed for review.
        revision: GitRevision,
        // Dependency selection proposed for review.
        lock_hash: LockHash,
        // Whether the source changes the whole machine or one guest.
        family: ReviewFamily,
        // Null for a machine review; required guest name otherwise.
        target: Value,
    },
    Decide {
        // Protected request whose pending decision is being recorded.
        request_id: ReviewId,
        // Human answer from the trusted review window.
        decision: Decision,
        // Maximum machine effects covered by the answer.
        scope: Scope,
        // Digest of the source and effects shown to the user.
        review_fingerprint: ReviewFingerprint,
    },
    Check {
        // Previously approved request to validate without changing it.
        request_id: ReviewId,
        // Source commit the caller intends to build.
        revision: GitRevision,
        // Lock digest the caller intends to build.
        lock_hash: LockHash,
    },
    Status {
        // Protected request to observe without taking a writer lock.
        request_id: ReviewId,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReviewFamily {
    Machine,
    Guest,
}

/// Read one bounded, newline-terminated JSON control request.
pub(crate) fn input<T: serde::de::DeserializeOwned>(limit: u64) -> Result<T> {
    let mut line = Vec::new();
    std::io::stdin()
        .lock()
        .take(limit + 1)
        .read_until(b'\n', &mut line)?;
    ensure!(
        line.len() as u64 <= limit && line.ends_with(b"\n"),
        "invalid request framing"
    );
    Ok(airlock_nix_core::state::parse_json(
        &line,
        Path::new("<request>"),
    )?)
}

impl Coordinator {
    pub(super) fn review_path(&self, id: &ReviewId) -> PathBuf {
        self.state
            .join("reviews/requests")
            .join(format!("{id}.json"))
    }

    pub(super) fn review_baseline(&self) -> Result<(Release, BaselineFingerprint)> {
        if let Some(latest) = self.current()? {
            ensure!(
                latest.phase == Phase::Complete,
                "finish or recover the older deployment and required reboot before reviewing new source"
            );
            let selected = self
                .selection()?
                .context("completed deployment has no selection")?;
            ensure!(
                selected.transaction == latest.id && selected.release == latest.release,
                "deployed selection differs from current transaction"
            );
        }
        let baseline = self.baseline()?;
        baseline.trust()?;
        ensure!(
            baseline.manifest.host == state::host()?
                && baseline.manifest.profile == state::profile()?,
            "deployed baseline differs from the running host or profile"
        );
        let fingerprint = state::digest(&json!({"selection":self.selection()?,"boot_id":state::boot_id()?,"host":state::host()?,"revision":baseline.manifest.revision,"lock_hash":baseline.manifest.lock_hash}))?.parse()?;
        Ok((baseline, fingerprint))
    }

    pub(super) fn approved_review(
        &self,
        id: &ReviewId,
        revision: &GitRevision,
        lock_hash: &LockHash,
    ) -> Result<ApprovalRecord> {
        let path = self.review_path(id);
        state::trusted(&path)?;
        let record: ApprovalRecord = state::read(&path)?;
        ensure!(
            record.request_id == *id
                && record.status == ApprovalStatus::Approved
                && record.review_fingerprint.is_some(),
            "review is not approved"
        );
        ensure!(
            record.binding.revision == *revision && record.binding.lock_hash == *lock_hash,
            "source differs from approved candidate"
        );
        ensure!(
            record.baseline_state == self.review_baseline()?.1,
            "stale_review: deployed baseline changed"
        );
        Ok(record)
    }

    /// Handle a bounded protected review request; only status avoids mutation exclusion.
    pub fn review_control(&self) -> Result<Value> {
        let request: ReviewControl = input(65536)?;
        if let ReviewControl::Status { request_id } = request {
            let path = self.review_path(&request_id);
            state::trusted(&path)?;
            let record: ApprovalRecord = state::read(&path)?;
            ensure!(record.request_id == request_id, "review identity differs");
            let mut result = serde_json::to_value(record)?;
            result["lock"] = serde_json::to_value(lock::status(&self.state.join("lock"))?)?;
            return Ok(result);
        }

        let _guard = MachineLock::acquire(
            &self.state,
            "Source approval",
            "Validate or update a source review authorization",
            MachineOperation::Review,
        )?;
        match request {
            ReviewControl::Context {
                revision,
                lock_hash,
                family,
                target,
            } => {
                let target = match family {
                    ReviewFamily::Machine => {
                        ensure!(target.is_null(), "invalid machine review target");
                        ReviewTarget::Machine { target: () }
                    }
                    ReviewFamily::Guest => ReviewTarget::Guest {
                        target: serde_json::from_value(target)?,
                    },
                };
                let binding = ReviewBinding {
                    revision,
                    lock_hash,
                    target,
                    extra: BTreeMap::new(),
                };
                let (baseline, fingerprint) = self.review_baseline()?;
                let directory = self.state.join("reviews/requests");
                if directory.try_exists()? {
                    let mut paths: Vec<_> = fs::read_dir(&directory)?
                        .map(|e| e.map(|e| e.path()))
                        .collect::<std::io::Result<_>>()?;
                    paths.sort();
                    for path in paths
                        .into_iter()
                        .rev()
                        .filter(|p| p.extension().is_some_and(|e| e == "json"))
                    {
                        state::trusted(&path)?;
                        let saved: ApprovalRecord = state::read(&path)?;
                        ensure!(
                            path == self.review_path(&saved.request_id),
                            "review filename differs from identity"
                        );
                        if saved.baseline_state == fingerprint
                            && serde_json::to_value(&saved.binding)?
                                == serde_json::to_value(&binding)?
                        {
                            return Ok(serde_json::to_value(saved)?);
                        }
                    }
                }

                let mut entropy = [0u8; 32];
                fs::File::open("/dev/urandom")?.read_exact(&mut entropy)?;
                let request_id: ReviewId = entropy
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
                    .parse()?;
                let record = ApprovalRecord {
                    request_id,
                    binding,
                    review_fingerprint: None,
                    baseline_state: fingerprint,
                    scope: Scope::new(
                        baseline
                            .topology
                            .domains
                            .keys()
                            .map(|n| n.as_str().parse())
                            .collect::<airlock_nix_core::Result<_>>()?,
                        true,
                    )?,
                    status: ApprovalStatus::AwaitingApproval,
                    release: None,
                    started_at: None,
                    deployment_operation: None,
                    extra: BTreeMap::from([
                        ("baseline".into(), json!(baseline.manifest.revision)),
                        ("created_at".into(), json!(state::now())),
                    ]),
                };
                state::save(&self.review_path(&record.request_id), &record)?;
                Ok(serde_json::to_value(record)?)
            }
            ReviewControl::Decide {
                request_id,
                decision,
                scope,
                review_fingerprint,
            } => {
                let path = self.review_path(&request_id);
                state::trusted(&path)?;
                let mut record: ApprovalRecord = state::read(&path)?;
                ensure!(
                    record.request_id == request_id
                        && record.status == ApprovalStatus::AwaitingApproval,
                    "review has already been decided or differs"
                );
                if decision == Decision::Approve {
                    ensure!(
                        record.baseline_state == self.review_baseline()?.1,
                        "stale_review: deployed baseline changed before approval"
                    );
                }
                record.status = match decision {
                    Decision::Approve => ApprovalStatus::Approved,
                    Decision::Reject => ApprovalStatus::Rejected,
                    Decision::Cancelled => ApprovalStatus::Cancelled,
                };
                record.scope = scope;
                record.review_fingerprint = Some(review_fingerprint);
                record
                    .extra
                    .insert("decided_at".into(), json!(state::now()));
                state::save(&path, &record)?;
                Ok(serde_json::to_value(record)?)
            }
            ReviewControl::Check {
                request_id,
                revision,
                lock_hash,
            } => Ok(serde_json::to_value(self.approved_review(
                &request_id,
                &revision,
                &lock_hash,
            )?)?),
            ReviewControl::Status { .. } => unreachable!(),
        }
    }

    /// Bind admitted artifacts to an approved source and enforce the actual deployment scope.
    pub fn review_bind(&self, id: &ReviewId, path: &Path) -> Result<Value> {
        let _guard = MachineLock::acquire(
            &self.state,
            "Source approval",
            "Bind admitted output to its source approval",
            MachineOperation::Review,
        )?;
        let r = Release::load(path)?;
        r.trust()?;
        let mut record = self.approved_review(id, &r.manifest.revision, &r.manifest.lock_hash)?;
        if let ReviewTarget::Guest { target } = &record.binding.target {
            ensure!(
                r.manifest.guest_admission.as_ref().map(|g| &g.domain) == Some(target),
                "guest approval differs from deployment target"
            );
        }
        let plan = self.plan(&r)?;
        if let Err(error) = record
            .scope
            .check(&serde_json::from_value::<DeploymentPlan>(
                serde_json::to_value(&plan)?,
            )?)
        {
            record.status = ApprovalStatus::ScopeExceeded;
            record.extra.insert("plan".into(), json!(plan));
            state::save(&self.review_path(id), &record)?;
            return Err(anyhow::anyhow!("scope_exceeded: {error}"));
        }

        let binding = ReleaseBinding {
            request_id: id.clone(),
            release: ReleasePath::from_path(&r.path)?,
            revision: r.manifest.revision.clone(),
            lock_hash: r.manifest.lock_hash.clone(),
        };
        let key = format!(
            "{:x}",
            Sha256::digest(r.path.as_os_str().as_encoded_bytes())
        );
        state::save(
            &self
                .state
                .join("reviews/bindings")
                .join(format!("{key}.json")),
            &binding,
        )?;
        Ok(json!({"request_id":id,"status":"approved","plan":plan}))
    }
}
