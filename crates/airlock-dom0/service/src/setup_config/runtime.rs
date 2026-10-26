//! Shared setup session: command evidence, predicted changes and compatibility receipts.

use super::{
    policy::Paths,
    report::{Counts, Mode, Schema, SetupReport},
};
use crate::model::CheckStatus;
use crate::process::Runner;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

/// Runtime paths and informational evidence for one setup invocation.
pub(super) struct Session {
    /// Decoded desired topology; never inferred from current Qubes settings.
    pub topology: Value,
    /// Apply external changes, or only record their intended requests.
    pub apply: bool,
    /// Child/helper receipts and command evidence belonging to this invocation.
    pub directory: PathBuf,
    /// Selected policy execution paths, separate from the mutable diagnostic report.
    pub policy_paths: Paths,
    /// Mutable compatibility receipt; not an authorization or transaction record.
    pub result: SetupReport,
    /// Legacy/manual or deployment generation map; checked boot carries its selection explicitly.
    pub staged: Option<PathBuf>,
    /// Append-only command diagnostics, separate from protocol output.
    log: File,
}

/// Read an optional runtime path override without changing process-global environment.
pub(super) fn path(key: &str, default: &str) -> PathBuf {
    std::env::var_os(key).map_or_else(|| default.into(), PathBuf::from)
}

/// Render Qubes scalar settings without accepting arbitrary structured values.
pub(super) fn text(value: &Value) -> Result<String> {
    Ok(match value {
        Value::Null => "none".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        _ => anyhow::bail!("Qubes setting must be a scalar"),
    })
}

impl Session {
    /// Initialize a receipt and reset only this invocation's fixed evidence files.
    pub fn new(topology: &Path, apply: bool, scope: &str, phase: &str) -> Result<Self> {
        let directory = path("AIRLOCK_LOG_DIR", "/var/log/airlock");
        Self::at(topology, apply, scope, phase, directory)
    }

    /// Initialize an isolated child receipt without mutating the caller's environment.
    pub fn at(
        topology: &Path,
        apply: bool,
        scope: &str,
        phase: &str,
        directory: PathBuf,
    ) -> Result<Self> {
        // Decode before opening/truncating evidence: retain the actual read error.
        let decoded = crate::state::configuration(topology)?;

        fs::create_dir_all(&directory)?;
        if matches!(phase, "all" | "prepare-only") {
            let scope = serde_json::from_value(json!(scope))?;
            for task in super::report::tasks::required(&decoded, scope)? {
                super::report::clear_result(&task.path(&directory))?;
            }
        }
        for name in ["live-actions", "restart-actions", "unsupported-domains"] {
            File::create(directory.join(format!("setup-config-{name}.jsonl")))?;
        }
        if phase != "finish-only" {
            File::create(directory.join("rust-vm-actions.jsonl"))?;
            File::create(directory.join("rust-setup-helpers.jsonl"))?;
        }
        let command_log = directory.join("setup-config.commands.log");
        let log = OpenOptions::new()
            .create(true)
            .write(true)
            .append(phase == "finish-only")
            .truncate(phase != "finish-only")
            .open(&command_log)?;
        let policy_paths = Paths::configured(&directory)?;
        let result = SetupReport {
            schema: Schema::V1,
            status: CheckStatus::Failed,
            mode: if apply { Mode::Apply } else { Mode::Plan },
            scope: serde_json::from_value(json!(scope))?,
            phase: serde_json::from_value(json!(phase))?,
            run_id: std::env::var("AIRLOCK_SETUP_RUN_ID")
                .unwrap_or_else(|_| std::process::id().to_string())
                .try_into()?,
            topology_hash: super::report::fingerprint(&decoded)?,
            counts: Counts::default(),
            live_actions: Vec::new(),
            restart_actions: Vec::new(),
            unsupported_domains: Vec::new(),
            restart_required: false,
            rust_reconciled: None,
            task: None,
            task_results: Vec::new(),
            reason: "setup interrupted".into(),
            diagnostics: serde_json::from_value(json!({"topology":topology,
                "live_actions_log":directory.join("setup-config-live-actions.jsonl"), "restart_actions_log":directory.join("setup-config-restart-actions.jsonl"), "unsupported_domains_log":directory.join("setup-config-unsupported-domains.jsonl"),
                "qrexec_policy_file":policy_paths.target(), "qrexec_policy_rendered":policy_paths.rendered(), "command_log":command_log}))?,
        };
        Ok(Self {
            topology: decoded,
            policy_paths,
            apply,
            directory,
            staged: std::env::var_os("AIRLOCK_STAGED_GENERATIONS").map(PathBuf::from),
            result,
            log,
        })
    }

    /// Retain both helper streams, accepting output only after bounded successful completion.
    pub fn command(&mut self, program: &str, args: &[&str]) -> Result<String> {
        writeln!(self.log, "+ {program} {args:?}")?;
        let mut environment = vec![(
            "AIRLOCK_SETUP_RUN_ID".into(),
            self.result.run_id.as_str().into(),
        )];
        if let Some(staged) = &self.staged {
            environment.push((
                "AIRLOCK_STAGED_GENERATIONS".into(),
                staged.as_os_str().to_owned(),
            ));
        }
        let output = Runner::default().capture(
            program,
            &args.iter().map(OsString::from).collect::<Vec<_>>(),
            Duration::from_secs(600),
            &environment,
        )?;
        self.log.write_all(&output.stdout)?;
        self.log.write_all(&output.stderr)?;
        ensure!(
            !output.limited && output.status.success(),
            "{program} failed or exceeded its limits: {stdout}{stderr}",
            stdout = String::from_utf8_lossy(&output.stdout),
            stderr = String::from_utf8_lossy(&output.stderr)
        );
        Ok(String::from_utf8(output.stdout)?
            .trim_end_matches('\n')
            .into())
    }

    /// Dispatch an existing dom0 storage/setup API using the selected native helper.
    pub fn service(&mut self, args: &[&str]) -> Result<String> {
        let program = path("AIRLOCK_DOM0_SERVICE", "airlock-dom0-service");
        self.command(program.to_str().context("non-UTF-8 service path")?, args)
    }

    /// Record a mutating request in both modes; only apply mode invokes its adapter.
    pub fn change(&mut self, program: &str, args: &[&str]) -> Result<()> {
        if self.apply {
            self.command(program, args)?;
        } else {
            writeln!(self.log, "+ {program} {args:?}")?;
        }
        Ok(())
    }

    /// Increment an informational compatibility count with checked arithmetic.
    pub fn count(&mut self, name: &str) -> Result<()> {
        let counter = self.result.counts.counter(name)?;
        *counter = counter.checked_add(1).context("setup count overflow")?;
        Ok(())
    }

    /// Append an observable setup action, omitting unused optional fields.
    pub fn action(
        &mut self,
        kind: &str,
        action: &str,
        domain: &str,
        field: &str,
        value: &str,
    ) -> Result<Value> {
        let mut event = json!({"type":kind, "action":action});
        for (key, value) in [("domain", domain), ("field", field), ("value", value)] {
            if !value.is_empty() {
                event[key] = json!(value);
            }
        }
        self.result.live_actions.push(event.clone());
        super::report::append(&self.directory, "setup-config-live-actions.jsonl", &event)?;
        Ok(event)
    }

    /// Observe a VM's Qubes state without treating unavailable observations as halted.
    pub fn state(&mut self, domain: &str) -> Result<String> {
        let output = self.command(
            "qvm-ls",
            &["--raw-data", "--fields", "NAME,STATE", "--no-spinner"],
        )?;
        let mut rows = output
            .lines()
            .filter_map(|line| line.split_once('|'))
            .filter(|(name, _)| *name == domain);
        let (_, state) = rows.next().context("VM power state is missing")?;
        ensure!(rows.next().is_none(), "VM power state is ambiguous");
        Ok(state.into())
    }

    /// Defer every known active state; missing and unsupported observations are errors.
    pub fn running(&mut self, domain: &str) -> Result<bool> {
        if !self.apply {
            return Ok(false);
        }
        let state = airlock_deployment_core::inventory::PowerState::classify(&self.state(domain)?);
        ensure!(state.is_known(), "VM power state is unknown");
        Ok(!state.is_halted())
    }

    /// Preserve a storage-change restart requirement without changing the live boot identity.
    pub fn defer(&mut self, domain: &str, kind: &str, field: &str, value: &str) -> Result<()> {
        let state = self.state(domain).unwrap_or_default();
        let event = json!({"type":kind,"action":"restart","domain":domain,"field":field,"value":value,"state":state,"reason":"domain is running; stop it and re-run setup-config for this storage change to take effect"});
        self.result.restart_actions.push(event.clone());
        self.result.restart_required = true;
        super::report::append(
            &self.directory,
            "setup-config-restart-actions.jsonl",
            &event,
        )
    }

    /// Reconcile a derived boot property or feature, retaining existing restart evidence.
    pub fn setting(&mut self, program: &str, domain: &str, key: &str, value: &str) -> Result<()> {
        if self.apply
            && self.command(program, &[domain, key]).is_ok_and(|current| {
                airlock_deployment_core::configuration::value_matches(value, Some(&current))
            })
        {
            return Ok(());
        }
        self.change(program, &[domain, key, value])?;
        let feature = program == "qvm-features";
        self.count(if feature {
            "features_changed"
        } else {
            "prefs_changed"
        })?;
        let kind = if feature {
            "domain-feature"
        } else {
            "domain-pref"
        };
        let mut event = self.action(kind, "set", domain, key, value)?;
        if self.apply && self.state(domain).is_ok_and(|state| state == "Running") {
            event["action"] = json!("restart");
            event["state"] = json!("Running");
            self.result.restart_actions.push(event.clone());
            self.result.restart_required = true;
            super::report::append(
                &self.directory,
                "setup-config-restart-actions.jsonl",
                &event,
            )?;
        }
        Ok(())
    }

    /// Write the compatible result on success or failure and merge child receipts once.
    pub fn finish(&mut self, result: &Result<()>) -> Result<()> {
        self.result.status = if result.is_ok() {
            CheckStatus::Passed
        } else {
            CheckStatus::Failed
        };
        self.result.reason = match result {
            Ok(()) => "Qubes config setup completed".into(),
            Err(error) => format!("{error:#}"),
        };
        let file = self.directory.join("setup-config.json");
        super::report::save(&file, &self.result)?;
        super::report::finalize(&file)?;
        self.result = crate::state::read(&file)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compatibility diagnostics are projections of selected paths, with no reverse conversion.
    #[test]
    fn report_paths_match_the_typed_session_selection() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let topology = temporary.path().join("topology.json");
        fs::write(
            &topology,
            br#"{"schema":"airlock.qubes-topology.v1","domains":{}}"#,
        )?;
        let session = Session::at(
            &topology,
            false,
            "all",
            "all",
            temporary.path().join("logs"),
        )?;
        assert_eq!(
            session.result.diagnostics["qrexec_policy_file"],
            json!(session.policy_paths.target())
        );
        assert_eq!(
            session.result.diagnostics["qrexec_policy_rendered"],
            json!(session.policy_paths.rendered())
        );
        Ok(())
    }

    /// Invalid input retains its read diagnostic and does not truncate earlier setup evidence.
    #[test]
    fn invalid_configuration_preserves_diagnostics_and_previous_logs() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let topology = temporary.path().join("topology.json");
        let logs = temporary.path().join("logs");
        fs::create_dir(&logs)?;
        let evidence = logs.join("setup-config-live-actions.jsonl");
        fs::write(&evidence, "previous evidence\n")?;
        fs::write(&topology, b"{broken")?;
        let error = Session::at(&topology, true, "all", "all", logs)
            .err()
            .context("invalid input accepted")?;
        assert!(format!("{error:#}").contains("topology.json"));
        assert_eq!(fs::read_to_string(evidence)?, "previous evidence\n");
        Ok(())
    }
}
