//! Combine setup adapter receipts without treating logs as execution authority.

mod wire;

pub(crate) mod tasks;

pub(crate) use wire::{Counts, Mode, Phase, Schema, Scope, SetupReport};

use crate::model::CheckStatus;
use airlock_deployment_core::setup as verified;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

/// Expected setup identity, constructed from coordinator-owned invocation and configuration inputs.
pub(crate) struct ExpectedSetup {
    // Invocation propagated to setup and its helpers.
    run: crate::model::TransactionId,
    // Content identity of the effective topology rather than its filename.
    topology: airlock_nix_core::identity::LockHash,
    // Scope requested by the invoking coordinator.
    scope: Scope,
    // Effective configuration retained independently of reported task coverage.
    topology_input: Value,
}

/// Completion is native evidence or an explicitly selected admitted legacy compatibility result.
pub(crate) struct CompletedSetup {
    // Legacy records cannot claim the native run/configuration-binding guarantee.
    outcome: Completion,
}

/// The legacy branch is never selected by malformed native report contents.
enum Completion {
    /// Verus-checked outcome from a native typed report.
    Native(verified::CompletedSetup),
    /// Old admitted helper, checked under its separate compatibility contract.
    Legacy,
}

impl ExpectedSetup {
    /// Bind the current attempt to the complete effective setup input.
    pub(crate) fn new(run: crate::model::TransactionId, topology: &Value) -> Result<Self> {
        Ok(Self {
            run,
            topology: fingerprint(topology)?,
            scope: Scope::All,
            topology_input: topology.clone(),
        })
    }

    /// Allocate a fresh boot invocation independently of process ID reuse and wall-clock changes.
    pub(crate) fn fresh(topology: &Value) -> Result<Self> {
        use std::io::Read;
        let mut bytes = [0u8; 16];
        fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        Self::new(u128::from_ne_bytes(bytes).to_string().try_into()?, topology)
    }

    /// Retain the requested legacy boot partition without confusing it with the whole topology.
    pub(crate) fn scoped(mut self, scope: Scope) -> Self {
        self.scope = scope;
        self
    }

    /// Environment value propagated to the invoked native setup program.
    pub(crate) fn run(&self) -> &str {
        self.run.as_str()
    }

    /// Decode once and require same-run, same-configuration, applied final completion.
    pub(crate) fn complete(&self, path: &Path) -> Result<CompletedSetup> {
        self.complete_protocol(path, true)
    }

    /// An explicitly negotiated v3 helper retains its older bound-report guarantee.
    pub(crate) fn complete_bound(&self, path: &Path) -> Result<CompletedSetup> {
        self.complete_protocol(path, false)
    }

    fn complete_protocol(&self, path: &Path, task_coverage: bool) -> Result<CompletedSetup> {
        let report: SetupReport = crate::state::read(path)?;
        ensure!(
            report.scope == self.scope && report.rust_reconciled.as_ref() == Some(&report.run_id),
            "setup did not finalize the complete requested configuration"
        );
        let pending = report.evidence().pending;
        let domains = if task_coverage {
            tasks::domains(&self.topology_input, self.scope)?
        } else {
            Vec::new()
        };
        let outcomes = report
            .task_results
            .iter()
            .map(tasks::Outcome::verified)
            .collect::<Vec<_>>();
        let evidence = if task_coverage {
            verified::CompletedSetup::check_tasks(
                self.run.as_str(), self.topology.as_str(), self.scope.as_str(),
                report.evidence(), &domains, &outcomes,
            )
        } else {
            verified::CompletedSetup::check(
                self.run.as_str(), self.topology.as_str(), self.scope.as_str(), report.evidence(),
            )
        }
        .with_context(|| format!("setup left failed, unsupported, deferred or mismatched work: run={run} expected={expected} topology={topology} expected_topology={expected_topology} scope={scope:?} status={status:?} mode={mode:?} phase={phase:?} pending={pending} unsupported={unsupported} deferred={deferred:?}",
            run = report.run_id.as_str(), expected = self.run.as_str(), topology = report.topology_hash,
            expected_topology = self.topology, scope = report.scope, status = report.status, mode = report.mode,
            phase = report.phase, unsupported = report.counts.unsupported_domains_count,
            deferred = report.restart_actions.iter().map(|a| (&a["type"], &a["field"])).collect::<Vec<_>>()))?;
        Ok(CompletedSetup {
            outcome: Completion::Native(evidence),
        })
    }
}

impl CompletedSetup {
    /// Prevent downstream progress from substituting another attempt or effective configuration.
    pub(crate) fn require(&self, expected: &ExpectedSetup) -> Result<()> {
        match &self.outcome {
            Completion::Native(evidence) => ensure!(
                evidence.matches(
                    expected.run.as_str(),
                    expected.topology.as_str(),
                    expected.scope.as_str()
                ),
                "setup completion belongs to another attempt or configuration"
            ),
            Completion::Legacy => {}
        }
        Ok(())
    }

    /// Validate old admitted helpers without fabricating native run or configuration evidence.
    pub(crate) fn legacy(path: &Path) -> Result<Self> {
        #[derive(serde::Deserialize)]
        struct Legacy {
            // Closed legacy result envelope.
            schema: wire::Schema,
            // Explicit success is required even if the process exited successfully.
            status: CheckStatus,
            // Missing or malformed unsupported counts are never zero.
            unsupported_domains_count: u64,
            // Legacy helpers used a boolean or an array of pending work.
            restart_required: LegacyPending,
        }

        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum LegacyPending {
            // Old boolean completion flag.
            Flag(bool),
            // Old list representation; only an empty list permits completion.
            Actions(Vec<Value>),
        }

        let report: Legacy = crate::state::read(path)?;
        let _schema = report.schema;
        ensure!(
            report.status == CheckStatus::Passed
                && report.unsupported_domains_count == 0
                && match report.restart_required {
                    LegacyPending::Flag(flag) => !flag,
                    LegacyPending::Actions(actions) => actions.is_empty(),
                },
            "legacy setup left failed, unsupported or deferred work"
        );
        Ok(Self {
            outcome: Completion::Legacy,
        })
    }
}

/// Revoke earlier completion before invoking a helper that must publish a fresh result.
pub(crate) fn clear_result(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Hash the complete decoded setup configuration using deterministic JSON serialization.
/// This new protocol is independent of legacy Python-compatible approval fingerprints.
pub(crate) fn fingerprint(topology: &Value) -> Result<airlock_nix_core::identity::LockHash> {
    use sha2::{Digest, Sha256};
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(topology)?)).parse()?)
}

/// Append one informational Rust reconciliation event to the current setup log.
pub(super) fn append(directory: &Path, file: &str, event: &Value) -> Result<()> {
    fs::create_dir_all(directory)?;
    let mut output = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(directory.join(file))?;
    writeln!(output, "{event}")?;
    Ok(())
}

/// Read complete JSONL events; malformed evidence must not silently become success.
fn lines(path: &Path) -> Result<Vec<Value>> {
    if !path.try_exists()? {
        return Ok(Vec::new());
    }
    fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str(line).map_err(Into::into))
        .collect()
}

/// Merge diagnostic helper reports and require independent task outcomes for a final result.
/// Finalization is idempotent; it never changes VM or storage state.
pub(super) fn finalize(path: &Path) -> Result<()> {
    let directory = path.parent().context("setup result directory")?;
    let mut root: SetupReport = crate::state::read(path)?;
    let run = root.run_id.clone();
    if root.rust_reconciled.as_ref() == Some(&run) {
        return Ok(());
    }
    let mut evidence = root.evidence();
    let mut reports = Vec::new();
    if root.phase == Phase::FinishOnly {
        let prepared: SetupReport = crate::state::read(&directory.join("setup-prepare.json"))?;
        ensure!(
            prepared.phase == Phase::PrepareOnly && prepared.scope == root.scope,
            "setup preparation has the wrong phase or scope"
        );
        reports.push(prepared);
    }
    let mut seen = std::collections::BTreeSet::new();
    for helper in lines(&directory.join("rust-setup-helpers.jsonl"))? {
        let name = helper.as_str().context("invalid helper receipt identity")?;
        ensure!(
            !name.is_empty() && !name.contains('/') && name != "." && name != "..",
            "invalid helper receipt path"
        );
        ensure!(seen.insert(name.to_owned()), "duplicate helper receipt");
        let receipt = directory.join(name).join("setup-config.json");
        ensure!(
            root.status != CheckStatus::Passed || receipt.try_exists()?,
            "missing helper receipt"
        );
        if receipt.try_exists()? {
            let child: SetupReport = crate::state::read(&receipt)?;
            ensure!(
                matches!(child.phase, Phase::BackendOnly | Phase::DevicesOnly),
                "helper has the wrong setup phase"
            );
            reports.push(child);
        }
    }
    for child in reports {
        evidence = evidence
            .merge(&child.evidence())
            .context("setup evidence belongs to another run or configuration, or overflows")?;
        root.counts.add(&child.counts)?;
        root.live_actions.extend(child.live_actions);
        root.restart_actions.extend(child.restart_actions);
        root.unsupported_domains.extend(child.unsupported_domains);
    }
    // These security fields come from the verified merge, not from diagnostic JSON counters.
    ensure!(
        root.status != CheckStatus::Passed || evidence.passed,
        "helper did not complete successfully"
    );
    root.status = if evidence.passed {
        CheckStatus::Passed
    } else {
        CheckStatus::Failed
    };
    root.mode = if evidence.applied {
        Mode::Apply
    } else {
        Mode::Plan
    };
    root.restart_required = evidence.pending;
    root.counts.unsupported_domains_count = evidence.unsupported;
    for mut action in lines(&directory.join("rust-vm-actions.jsonl"))? {
        let restart = action
            .as_object_mut()
            .context("invalid reconciliation event")?
            .remove("restart")
            .unwrap_or(Value::Bool(false));
        let restart = restart.as_bool().context("invalid restart evidence")?;
        let action_name = action["action"]
            .as_str()
            .context("missing reconciliation action")?;
        ensure!(
            matches!(action_name, "create" | "set" | "defer" | "restart"),
            "unknown reconciliation action"
        );
        let count = match action["type"].as_str() {
            Some("domain") => "domains_changed",
            Some("domain-pref") => "prefs_changed",
            Some("domain-feature") => "features_changed",
            Some("domain-service") => "services_changed",
            Some("domain-device") => "devices_changed",
            _ => anyhow::bail!("unknown reconciliation event"),
        };
        if action_name != "defer" {
            let counter = root.counts.counter(count)?;
            *counter = counter.checked_add(1).context("setup count overflow")?;
        }
        let pending = restart || matches!(action_name, "defer" | "restart");
        root.live_actions.push(action.clone());
        evidence = evidence.with_pending(pending);
        if pending {
            action["action"] = json!("restart");
            root.restart_actions.push(action);
        }
    }
    root.restart_required = evidence.pending;
    if matches!(root.phase, Phase::All | Phase::FinishOnly) && root.status == CheckStatus::Passed {
        let topology = root
            .diagnostics
            .get("topology")
            .and_then(Value::as_str)
            .context("setup topology path is missing")?;
        let topology = crate::state::configuration(Path::new(topology))?;
        ensure!(
            fingerprint(&topology)? == root.topology_hash,
            "setup topology changed before finalization"
        );
        let required = tasks::required(&topology, root.scope)?;
        root.task_results = tasks::collect(directory, &required)?;
        for outcome in &root.task_results {
            let task = outcome.verified().evidence;
            let merged = root
                .evidence()
                .merge(&task)
                .context("setup task belongs to another run or topology")?;
            root.status = if merged.passed {
                CheckStatus::Passed
            } else {
                CheckStatus::Failed
            };
            root.mode = if merged.applied {
                Mode::Apply
            } else {
                Mode::Plan
            };
            root.restart_required = merged.pending;
            // Detailed reports already contribute their totals. Compact snapshots preserve
            // blockers when invocation logs are lost without counting the same work twice.
            root.counts.unsupported_domains_count =
                root.counts.unsupported_domains_count.max(task.unsupported);
        }
    }
    root.rust_reconciled = Some(run);
    save(path, &root)?;
    tasks::publish(directory, &root)?;
    if root.phase == Phase::PrepareOnly {
        save(&directory.join("setup-prepare.json"), &root)?;
    }
    Ok(())
}

/// Derive one fixed helper log directory; arbitrary path components are refused.
pub(crate) fn helper_directory(root: &Path, domain: &str, mode: &str) -> Result<PathBuf> {
    let run = std::env::var("AIRLOCK_SETUP_RUN_ID")
        .unwrap_or_else(|_| std::process::id().to_string())
        .try_into()?;
    helper_directory_for(root, domain, mode, &run)
}

/// In-process deployment helpers use the transaction's explicit invocation identity.
pub(crate) fn helper_directory_for(
    root: &Path,
    domain: &str,
    mode: &str,
    run: &crate::model::TransactionId,
) -> Result<PathBuf> {
    let _: airlock_nix_core::identity::GuestName = domain.parse()?;
    ensure!(
        matches!(mode, "--backend-only" | "--devices-only"),
        "invalid helper mode"
    );
    let run = run.as_str();
    ensure!(
        run.bytes().all(|b| b.is_ascii_digit()) && !run.is_empty(),
        "invalid setup run ID"
    );
    let name = format!("vm-{run}-{domain}-{mode}");
    let directory = root.join(&name);
    fs::create_dir_all(&directory)?;
    match fs::remove_file(directory.join("setup-config.json")) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    append(root, "rust-setup-helpers.jsonl", &json!(name))?;
    Ok(directory)
}

/// Replace an informational receipt atomically, independently of the trusted journal writer.
/// These root-owned progress records do not grant deployment approval. Their truthfulness
/// is trusted completion evidence; publication is atomic but does not promise crash durability.
pub(crate) fn save(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    let mut output = tempfile::NamedTempFile::new_in(path.parent().context("receipt directory")?)?;
    serde_json::to_writer_pretty(&mut output, value)?;
    writeln!(output)?;
    output.persist(path).map_err(|error| error.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal receipt keeps each merge boundary and run identity explicit.
    fn receipt(root: &Path, phase: &str) -> Value {
        let topology = json!({"schema":"test", "domains":{}});
        fs::write(
            root.join("topology.json"),
            serde_json::to_vec(&topology).unwrap(),
        )
        .unwrap();
        let mut value = serde_json::to_value(Counts::default()).unwrap();
        for (key, field) in json!({"schema":"airlock.setup-config.v1", "mode":"apply", "scope":"all",
            "topology_hash":fingerprint(&topology).unwrap(), "topology":root.join("topology.json"), "run_id":"123", "phase":phase, "status":"passed", "prefs_changed":1,
            "reason":"fixture completed", "live_actions":[{"type":"global-pref","action":"set"}], "restart_actions":[],
            "unsupported_domains":[], "restart_required":false}).as_object().unwrap() {
            value[key] = field.clone();
        }
        if matches!(phase, "all" | "prepare-only") {
            tasks::prepared(root, &serde_json::from_value(value.clone()).unwrap()).unwrap();
        }
        value
    }

    /// Preparation, one child and Rust changes are counted once across repeated finalization.
    #[test]
    fn merges_preparation_and_helpers_without_losing_restart_evidence() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        let path = root.join("setup-config.json");
        save(&path, &receipt(root, "prepare-only"))?;
        finalize(&path)?;
        fs::create_dir(root.join("child"))?;
        let mut child = receipt(root, "backend-only");
        child["restart_required"] = json!(true);
        child["restart_actions"] = json!([{"type":"domain-root","domain":"usr-home"}]);
        save(&root.join("child/setup-config.json"), &child)?;
        append(root, "rust-setup-helpers.jsonl", &json!("child"))?;
        append(
            root,
            "rust-vm-actions.jsonl",
            &json!({"type":"domain-feature","action":"set","restart":false}),
        )?;
        append(
            root,
            "rust-vm-actions.jsonl",
            &json!({"type":"domain-pref","action":"defer"}),
        )?;
        save(&path, &receipt(root, "finish-only"))?;
        finalize(&path)?;
        let result: Value = crate::state::read(&path)?;
        assert_eq!(result["prefs_changed"], 3);
        assert_eq!(result["features_changed"], 1);
        assert_eq!(result["live_actions"].as_array().unwrap().len(), 5);
        assert_eq!(result["restart_required"], true);
        assert_eq!(result["restart_actions"][0], child["restart_actions"][0]);
        assert_eq!(result["restart_actions"][1]["type"], "domain-pref");
        assert_eq!(result["restart_actions"].as_array().unwrap().len(), 2);
        let before = fs::read(&path)?;
        finalize(&path)?;
        assert_eq!(fs::read(&path)?, before);
        Ok(())
    }

    /// Incomplete, stale, failed or duplicate child evidence cannot become a passed report.
    #[test]
    fn refuses_invalid_helper_evidence() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        let path = root.join("setup-config.json");
        fs::create_dir(root.join("child"))?;
        append(root, "rust-setup-helpers.jsonl", &json!("child"))?;
        for invalid in 0..5 {
            save(&path, &receipt(root, "all"))?;
            let mut child = receipt(root, "backend-only");
            match invalid {
                0 => {}
                1 => {
                    child["run_id"] = json!("other");
                    save(&root.join("child/setup-config.json"), &child)?;
                }
                2 => {
                    child["status"] = json!("failed");
                    save(&root.join("child/setup-config.json"), &child)?;
                }
                3 => {
                    child["topology_hash"] = json!("b".repeat(64));
                    save(&root.join("child/setup-config.json"), &child)?;
                }
                _ => {
                    save(&root.join("child/setup-config.json"), &child)?;
                    append(root, "rust-setup-helpers.jsonl", &json!("child"))?;
                }
            }
            assert!(finalize(&path).is_err());
        }
        Ok(())
    }

    /// Completion rejects malformed, stale, predictive, failed and contradictory success evidence.
    #[test]
    fn completion_requires_final_applied_matching_and_unblocked_results() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        let path = root.join("setup-config.json");
        let topology = json!({"schema":"test", "domains":{}});
        let expected = ExpectedSetup::new("123".to_string().try_into()?, &topology)?;
        let mut valid = receipt(root, "all");
        valid["topology_hash"] = json!(fingerprint(&topology)?);
        save(&path, &valid)?;
        finalize(&path)?;
        let valid: Value = crate::state::read(&path)?;
        let complete = expected.complete(&path)?;
        complete.require(&expected)?;
        // A daemon restart already performed is distinct from a VM restart still required.
        let mut restarted = valid.clone();
        restarted["live_actions"] =
            json!([{"type":"systemd", "action":"restart", "service":"qubesd.service"}]);
        save(&path, &restarted)?;
        expected.complete(&path)?;
        assert!(
            complete
                .require(&ExpectedSetup::new(
                    "124".to_string().try_into()?,
                    &topology
                )?)
                .is_err()
        );

        for (field, value) in [
            ("run_id", json!("124")),
            ("topology_hash", json!("b".repeat(64))),
            ("status", json!("failed")),
            ("mode", json!("plan")),
            ("phase", json!("prepare-only")),
            ("scope", json!("single")),
            ("unsupported_domains_count", json!(1)),
            ("unsupported_domains", json!(["app"])),
            ("restart_required", json!(true)),
            ("restart_actions", json!([{"action":"restart"}])),
            ("live_actions", json!([{"action":"defer"}])),
        ] {
            let mut invalid = valid.clone();
            invalid[field] = value;
            save(&path, &invalid)?;
            assert!(expected.complete(&path).is_err(), "accepted {field}");
        }
        for field in [
            "restart_required",
            "unsupported_domains_count",
            "topology_hash",
            "run_id",
        ] {
            let mut invalid = valid.clone();
            invalid.as_object_mut().unwrap().remove(field);
            save(&path, &invalid)?;
            assert!(
                expected.complete(&path).is_err(),
                "accepted missing {field}"
            );
        }
        let mut invalid = valid.clone();
        invalid["unsupported_domains_count"] = json!("0");
        save(&path, &invalid)?;
        assert!(expected.complete(&path).is_err());
        Ok(())
    }

    /// Build independent required-work evidence without a helper invocation list.
    fn task_fixture(root: &Path) -> Result<(ExpectedSetup, Value)> {
        let mut report = receipt(root, "all");
        let topology = json!({"schema":"test", "domains":{"app":{}}});
        let topology_path = root.join("topology.json");
        fs::write(&topology_path, serde_json::to_vec(&topology)?)?;
        report["topology_hash"] = json!(fingerprint(&topology)?);
        let typed: SetupReport = serde_json::from_value(report.clone())?;
        tasks::prepared(root, &typed)?;
        for kind in [
            tasks::Kind::Configuration,
            tasks::Kind::Backend,
            tasks::Kind::Devices,
        ] {
            tasks::completed(
                root,
                &topology_path,
                &typed.run_id,
                true,
                tasks::Task::Vm {
                    domain: "app".parse()?,
                    kind,
                },
            )?;
        }
        Ok((ExpectedSetup::new(typed.run_id, &topology)?, report))
    }

    /// Independent requirements reject missing work even when no helper log was published.
    #[test]
    fn missing_task_cannot_disappear_with_the_invocation_log() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        let path = root.join("setup-config.json");
        let (expected, report) = task_fixture(root)?;
        assert!(!root.join("rust-setup-helpers.jsonl").exists());
        fs::remove_file(root.join("task-app-devices.json"))?;
        save(&path, &report)?;
        assert!(finalize(&path).is_err());
        assert!(expected.complete(&path).is_err());

        let (_, report) = task_fixture(root)?;
        fs::remove_file(root.join("task-preparation.json"))?;
        save(&path, &report)?;
        assert!(finalize(&path).is_err());

        // A repeated attempt cannot reuse an earlier successful per-VM receipt.
        let (_, report) = task_fixture(root)?;
        tasks::clear(root, "app")?;
        save(&path, &report)?;
        assert!(finalize(&path).is_err());
        Ok(())
    }

    /// The coordinator rechecks coverage even if finalization was skipped, corrupted or misimplemented.
    #[test]
    fn completion_rechecks_exact_task_identity_and_each_outcome() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        let path = root.join("setup-config.json");
        let (expected, report) = task_fixture(root)?;
        save(&path, &report)?;
        finalize(&path)?;
        expected.complete(&path)?.require(&expected)?;
        let valid: Value = crate::state::read(&path)?;
        assert_eq!(valid["task_results"].as_array().unwrap().len(), 4);
        let mut invalid = valid.clone();
        invalid["task_results"].as_array_mut().unwrap().remove(1);
        save(&path, &invalid)?;
        assert!(expected.complete(&path).is_err());
        // Negotiation, never report contents, explicitly selects the older guarantee.
        expected.complete_bound(&path)?;

        for field in [
            "task",
            "run_id",
            "topology_hash",
            "mode",
            "status",
            "pending",
            "unsupported",
        ] {
            let mut invalid = valid.clone();
            let task = &mut invalid["task_results"][1];
            task[field] = match field {
                "task" => json!({"vm":{"domain":"other","kind":"configuration"}}),
                "run_id" => json!("124"),
                "topology_hash" => json!("b".repeat(64)),
                "mode" => json!("plan"),
                "status" => json!("failed"),
                "pending" => json!(true),
                "unsupported" => json!(1),
                _ => unreachable!(),
            };
            save(&path, &invalid)?;
            assert!(expected.complete(&path).is_err(), "accepted task {field}");
        }
        for replacement in [valid["task_results"][1].clone(), json!({"unknown":true})] {
            let mut invalid = valid.clone();
            invalid["task_results"][2] = replacement;
            save(&path, &invalid)?;
            assert!(expected.complete(&path).is_err());
        }
        let mut invalid = valid.clone();
        invalid["task_results"]
            .as_array_mut()
            .unwrap()
            .push(valid["task_results"][1].clone());
        save(&path, &invalid)?;
        assert!(expected.complete(&path).is_err());
        let mut invalid = valid.clone();
        invalid["task_results"][0]["scope"] = json!("deferred");
        save(&path, &invalid)?;
        assert!(expected.complete(&path).is_err());
        Ok(())
    }

    /// Task snapshots retain deferred VM changes independently of later diagnostic-log loss.
    #[test]
    fn task_outcome_retains_pending_configuration() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path();
        let path = root.join("setup-config.json");
        let (expected, report) = task_fixture(root)?;
        append(
            root,
            "rust-vm-actions.jsonl",
            &json!({"domain":"app", "action":"defer", "restart":true}),
        )?;
        let typed: SetupReport = serde_json::from_value(report.clone())?;
        tasks::completed(
            root,
            &root.join("topology.json"),
            &typed.run_id,
            true,
            tasks::Task::Vm {
                domain: "app".parse()?,
                kind: tasks::Kind::Configuration,
            },
        )?;
        fs::remove_file(root.join("rust-vm-actions.jsonl"))?;
        save(&path, &report)?;
        finalize(&path)?;
        assert!(expected.complete(&path).is_err());
        Ok(())
    }

    /// Direct administrative helpers keep results in their own directory; nested helpers report to their root.
    #[test]
    fn helper_task_publication_stays_within_the_owning_setup_directory() -> Result<()> {
        let parent = tempfile::tempdir()?;
        let root = parent.path().join("logs");
        fs::create_dir(&root)?;
        let mut report: SetupReport = serde_json::from_value(receipt(&root, "backend-only"))?;
        report.task = Some(tasks::Task::Vm {
            domain: "app".parse()?,
            kind: tasks::Kind::Backend,
        });
        tasks::publish(&root, &report)?;
        assert!(root.join("task-app-backend.json").exists());
        assert!(!parent.path().join("task-app-backend.json").exists());
        fs::remove_file(root.join("task-app-backend.json"))?;
        let child = helper_directory_for(&root, "app", "--backend-only", &report.run_id)?;
        tasks::publish(&child, &report)?;
        assert!(root.join("task-app-backend.json").exists());
        assert!(!child.join("task-app-backend.json").exists());
        Ok(())
    }

    /// Legacy support is explicit and still refuses missing, malformed or unsuccessful outcomes.
    #[test]
    fn legacy_completion_never_defaults_missing_evidence() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("setup-config.json");
        let valid = json!({"schema":"airlock.setup-config.v1", "status":"passed",
            "unsupported_domains_count":0, "restart_required":false});
        save(&path, &valid)?;
        CompletedSetup::legacy(&path)?;
        for pending in [json!([]), json!(false)] {
            let mut value = valid.clone();
            value["restart_required"] = pending;
            save(&path, &value)?;
            CompletedSetup::legacy(&path)?;
        }
        for field in ["status", "unsupported_domains_count", "restart_required"] {
            let mut invalid = valid.clone();
            invalid.as_object_mut().unwrap().remove(field);
            save(&path, &invalid)?;
            assert!(CompletedSetup::legacy(&path).is_err());
        }
        for pending in [json!(["app"]), json!(true), json!("false")] {
            let mut invalid = valid.clone();
            invalid["restart_required"] = pending;
            save(&path, &invalid)?;
            assert!(CompletedSetup::legacy(&path).is_err());
        }
        Ok(())
    }
}
