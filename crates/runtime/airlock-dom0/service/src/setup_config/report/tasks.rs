//! Required work comes from configuration, not from the list of helpers that ran.

use super::{Mode, Phase, Scope, SetupReport};
use crate::model::{CheckStatus, TransactionId};
use airlock_deployment_core::setup::{Evidence, tasks as verified};
use airlock_nix_core::identity::{GuestName, LockHash};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};

/// A closed set of per-VM responsibilities; unknown task names cannot be ignored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Kind {
    /// VM creation and all common properties, features and services.
    Configuration,
    /// Backend reconciliation, or an explicit not-applicable outcome.
    Backend,
    /// Device reconciliation, or an explicit empty assignment outcome.
    Devices,
}

/// Nominal identity of one required task in the effective configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub(crate) enum Task {
    /// Global preparation has no VM identity and cannot be confused with a VM task.
    Preparation,
    /// Work for exactly one declared VM.
    Vm {
        /// VM identity checked independently of the receipt filename.
        domain: GuestName,
        /// Responsibility within this VM's configuration.
        kind: Kind,
    },
}

/// Compact outcome carried across process boundaries and rechecked by the coordinator.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Outcome {
    /// VM and responsibility claimed by the producer.
    pub task: Task,
    /// Invocation that performed this work.
    run_id: TransactionId,
    /// Entire effective configuration read by the producer.
    topology_hash: LockHash,
    /// Planning cannot stand in for applied work.
    mode: Mode,
    /// Global preparation must cover the requested partition, not merely the same topology.
    scope: Scope,
    /// Failed work is never complete.
    status: CheckStatus,
    /// Deferred work still requires reconciliation.
    pending: bool,
    /// Unsupported work prevents completion even if the process returned success.
    unsupported: u64,
}

impl Task {
    /// Canonical, path-safe receipt identity; scope and run are checked inside the receipt.
    pub(in crate::setup_config) fn path(&self, directory: &Path) -> PathBuf {
        match self {
            Self::Preparation => directory.join("task-preparation.json"),
            Self::Vm { domain, kind } => {
                let kind = match kind {
                    Kind::Configuration => "configuration",
                    Kind::Backend => "backend",
                    Kind::Devices => "devices",
                };
                directory.join(format!("task-{domain}-{kind}.json"))
            }
        }
    }

    /// Reduce validated wire identities to the executable Verus task representation.
    pub(super) fn verified(&self) -> verified::Task {
        match self {
            Self::Preparation => verified::Task {
                domain: String::new(),
                kind: verified::Kind::Preparation,
            },
            Self::Vm { domain, kind } => verified::Task {
                domain: domain.to_string(),
                kind: match kind {
                    Kind::Configuration => verified::Kind::Configuration,
                    Kind::Backend => verified::Kind::Backend,
                    Kind::Devices => verified::Kind::Devices,
                },
            },
        }
    }
}

impl Outcome {
    /// Preserve every blocker when extracting evidence from a helper's typed report.
    pub(super) fn from_report(task: Task, report: &SetupReport) -> Self {
        let evidence = report.evidence();
        Self {
            task,
            run_id: report.run_id.clone(),
            topology_hash: report.topology_hash.clone(),
            mode: report.mode,
            scope: report.scope,
            status: report.status,
            pending: evidence.pending,
            unsupported: evidence.unsupported,
        }
    }

    /// No caller-supplied successful flag replaces the individual task's outcome.
    pub(super) fn verified(&self) -> verified::Outcome {
        verified::Outcome {
            task: self.task.verified(),
            evidence: Evidence {
                run: self.run_id.as_str().into(),
                topology: self.topology_hash.to_string(),
                scope: self.scope.as_str().into(),
                passed: self.status == CheckStatus::Passed,
                applied: self.mode == Mode::Apply,
                final_phase: false,
                pending: self.pending,
                unsupported: self.unsupported,
            },
        }
    }
}

/// Enumerate all responsibilities for each VM in the independently selected setup scope.
/// Scope selection/JSON interpretation remain ordinary Rust; invocation logs are not inputs.
pub(super) fn domains(topology: &Value, scope: Scope) -> Result<Vec<String>> {
    ensure!(
        scope != Scope::Single,
        "single helper is not a complete setup scope"
    );
    let mut domains = super::super::run::selected(topology, scope.as_str())?;
    domains.sort();
    Ok(domains)
}

/// Expand the same independently selected namespace through the verified production function.
pub(in crate::setup_config) fn required(topology: &Value, scope: Scope) -> Result<Vec<Task>> {
    let domains = domains(topology, scope)?;
    verified::required(&domains)
        .context("too many required setup tasks")?
        .into_iter()
        .map(|task| match task.kind {
            verified::Kind::Preparation => Ok(Task::Preparation),
            kind => Ok(Task::Vm {
                domain: task.domain.parse()?,
                kind: match kind {
                    verified::Kind::Configuration => Kind::Configuration,
                    verified::Kind::Backend => Kind::Backend,
                    verified::Kind::Devices => Kind::Devices,
                    verified::Kind::Preparation => unreachable!("handled above"),
                },
            }),
        })
        .collect()
}

/// Record successful in-process reconciliation only after its adapter returned successfully.
/// Backend and device no-op paths produce explicit evidence instead of silently omitting tasks.
pub(crate) fn completed(
    directory: &Path,
    topology: &Path,
    run: &TransactionId,
    apply: bool,
    task: Task,
) -> Result<()> {
    let raw: Value = crate::state::configuration(topology)?;
    let Task::Vm { domain, .. } = &task else {
        anyhow::bail!("preparation needs its own evidence");
    };
    ensure!(
        raw["domains"].get(domain.as_str()).is_some(),
        "task VM is not declared"
    );
    ensure!(
        !matches!(
            task,
            Task::Vm {
                kind: Kind::Backend,
                ..
            }
        ) || raw["domains"][domain.as_str()]["backend"]["type"] != "nix-closure",
        "native backend requires its own reconciliation outcome"
    );
    let pending = if matches!(
        task,
        Task::Vm {
            kind: Kind::Configuration,
            ..
        }
    ) {
        configuration_pending(directory, domain)?
    } else {
        false
    };
    let outcome = Outcome {
        task,
        run_id: run.clone(),
        topology_hash: super::fingerprint(&raw)?,
        mode: if apply { Mode::Apply } else { Mode::Plan },
        scope: Scope::Single,
        status: CheckStatus::Passed,
        pending,
        unsupported: 0,
    };
    super::save(&outcome.task.path(directory), &outcome)
}

/// Revoke previous per-VM completion before starting another reconciliation attempt.
pub(crate) fn clear(directory: &Path, domain: &str) -> Result<()> {
    for kind in [Kind::Configuration, Kind::Backend, Kind::Devices] {
        let task = Task::Vm {
            domain: domain.parse()?,
            kind,
        };
        super::clear_result(&task.path(directory))?;
    }
    Ok(())
}

/// Load the required receipts directly. A missing invocation list cannot omit a required result.
pub(super) fn collect(directory: &Path, tasks: &[Task]) -> Result<Vec<Outcome>> {
    tasks
        .iter()
        .map(|task| {
            let result: Outcome = crate::state::read(&task.path(directory))
                .with_context(|| format!("missing or invalid setup task: {task:?}"))?;
            ensure!(
                result.task == *task,
                "setup task identity differs from required work"
            );
            Ok(result)
        })
        .collect()
}

/// Publish a helper's own claimed identity, not a name inferred from its output path.
pub(super) fn publish(directory: &Path, report: &SetupReport) -> Result<()> {
    if let Some(task) = &report.task {
        ensure!(
            matches!(
                (task, report.phase),
                (
                    Task::Vm {
                        kind: Kind::Backend,
                        ..
                    },
                    Phase::BackendOnly
                ) | (
                    Task::Vm {
                        kind: Kind::Devices,
                        ..
                    },
                    Phase::DevicesOnly
                )
            ),
            "setup task has the wrong phase"
        );
        let Task::Vm { domain, kind } = task else {
            unreachable!("checked helper phase");
        };
        let mode = match kind {
            Kind::Backend => "--backend-only",
            Kind::Devices => "--devices-only",
            Kind::Configuration => unreachable!("checked helper phase"),
        };
        let helper = format!("vm-{run}-{domain}-{mode}", run = report.run_id.as_str());
        // A direct administrative helper has no parent setup run. Keep its result
        // inside the requested log directory instead of writing into its parent.
        let root = if directory
            .file_name()
            .is_some_and(|name| name == helper.as_str())
        {
            directory.parent().context("helper receipt parent")?
        } else {
            directory
        };
        super::save(
            &task.path(root),
            &Outcome::from_report(task.clone(), report),
        )?;
    }
    Ok(())
}

/// Preserve preparation evidence before any per-VM reconciliation can run.
pub(in crate::setup_config) fn prepared(directory: &Path, report: &SetupReport) -> Result<()> {
    let task = Task::Preparation;
    let mut outcome = Outcome::from_report(task, report);
    outcome.status = CheckStatus::Passed;
    super::save(&outcome.task.path(directory), &outcome)
}

/// Capture deferred common settings in the task result before diagnostic logs can be lost.
fn configuration_pending(directory: &Path, domain: &GuestName) -> Result<bool> {
    let mut pending = false;
    for event in super::lines(&directory.join("rust-vm-actions.jsonl"))? {
        if event["domain"] != domain.as_str() {
            continue;
        }
        let restart = event
            .get("restart")
            .map(|value| value.as_bool().context("invalid task restart evidence"))
            .transpose()?;
        pending |= restart.unwrap_or(false)
            || matches!(event["action"].as_str(), Some("defer" | "restart"));
    }
    Ok(pending)
}
