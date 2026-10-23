//! Persist boot progress before hardware startup and preserve evidence after failure.
//! The runtime recovery gate disables risky startup for one boot; acknowledging its console permits the next attempt.

pub(crate) mod acceptance;

mod diagnostics;

mod model;

use crate::{coordinator::Coordinator, process::Runner, state};
use airlock_deployment_core::boot::acceptance::Scope;
use airlock_machine_core::boot::BootInputs;
use airlock_nix_core::identity::GuestName;
use airlock_nix_core::state::{OperationKind, OperationLock, OperationOwner, StateStore};
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
pub(crate) use model::GuestState;
use model::{Attempt, AttemptId, Current, Status};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

/// Boot-supervision operation selected by a trusted local unit or restricted RPC wrapper.
#[derive(Args)]
pub(crate) struct Request {
    // Boot observation or explicitly requested recovery action.
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Begin an attempt or enter recovery after an interrupted boot.
    Prepare,
    /// Record that the desktop is usable before background services start.
    DesktopReady,
    /// Record background-service failure without treating it as hardware failure.
    Degraded,
    /// Record deliberate shutdown without declaring startup successful.
    ShutdownRequested,
    /// Report desktop readiness and startup status without changing state.
    DesktopStatus,
    /// Retry the fixed background-service unit from a degraded desktop.
    RetryServices,
    /// Capture logs and fixed diagnostic commands for the current boot.
    Snapshot {
        // Single directory name beneath this boot's snapshot namespace.
        #[arg(value_parser = model::snapshot_label)]
        label: String,
    },
    /// Record the current startup checkpoint.
    Stage {
        // Checkpoint name, typically a VM or systemd unit.
        name: String,
        // Optional explanation shown in persistent diagnostics.
        #[arg(default_value = "")]
        detail: String,
    },
    /// Record one guest's checkpoint without granting a guest new control authority.
    Guest {
        // Guest selected by the trusted boot coordinator.
        name: GuestName,
        // Readiness observation, never inferred from process existence alone.
        #[arg(value_enum)]
        phase: GuestState,
        // Human-readable explanation of the observed checkpoint.
        detail: String,
    },
    /// Record a critical startup failure and capture its diagnostics.
    Fail {
        // Failed checkpoint; slashes are escaped in its snapshot name.
        name: String,
        // Optional explanation shown in persistent diagnostics.
        #[arg(default_value = "")]
        detail: String,
    },
    /// Confirm all required guests are ready and finish the attempt.
    Complete {
        // Evidence explaining why startup can now be accepted.
        #[arg(default_value = "all required guests are ready")]
        detail: String,
    },
    /// Acknowledge the safe console while keeping this boot's recovery gate.
    RecoveryAck,
}

struct Supervisor {
    // Durable per-attempt state and the marker for incomplete critical startup.
    state: PathBuf,
    // Persistent event and snapshot directory separate from authoritative state.
    logs: PathBuf,
    // Volatile recovery gate and current-attempt discovery record.
    runtime: PathBuf,
    // Read-only log source tree, overridable for isolated inspection.
    diagnostic: PathBuf,
    // Current kernel boot identity, read once for this invocation.
    id: AttemptId,
}

fn timestamp() -> Result<String> {
    Ok(time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?)
}

impl Supervisor {
    fn load() -> Result<Self> {
        fn path(key: &str, default: &str) -> PathBuf {
            std::env::var_os(key).map_or_else(|| PathBuf::from(default), PathBuf::from)
        }

        let id_file = path("AIRLOCK_BOOT_ID_FILE", "/proc/sys/kernel/random/boot_id");
        let id = fs::read_to_string(&id_file)
            .context("read kernel boot identity")?
            .trim()
            .parse()?;

        let s = Self {
            state: path("AIRLOCK_BOOT_STATE_ROOT", "/var/lib/airlock/boot-attempts"),
            logs: path("AIRLOCK_BOOT_LOG_ROOT", "/var/log/airlock/boot-attempts"),
            runtime: path("AIRLOCK_BOOT_RUN_ROOT", "/run/airlock/boot-supervisor"),
            diagnostic: path("AIRLOCK_BOOT_DIAGNOSTIC_ROOT", "/"),
            id,
        };

        for path in [&s.state, &s.logs, &s.runtime, &s.diagnostic] {
            ensure!(
                path.is_absolute()
                    && !path
                        .components()
                        .any(|c| matches!(c, std::path::Component::ParentDir)),
                "boot paths must be absolute without parent traversal"
            );
        }
        Ok(s)
    }

    fn lock(&self) -> Result<OperationLock> {
        state::directory(&self.state)?;
        let store = StateStore::initialize(&self.state)?;
        let key = "boot-supervisor".parse()?;
        let owner = OperationOwner::new(
            "airlock-dom0-service boot supervisor".into(),
            format!("record boot {} readiness and recovery state", self.id),
            OperationKind::Recovery,
        )?;

        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            match store.try_operation(&key, owner.clone()) {
                Ok(lock) => return Ok(lock),
                Err(airlock_nix_core::Error::Busy { .. }) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn read(&self, id: &AttemptId) -> Result<Option<Attempt>> {
        let path = self.state.join(id.to_string()).join("state.json");
        let value: Option<Attempt> = state::optional(&path)?;
        if let Some(value) = &value {
            value.validate(Some(id))?;
        }
        Ok(value)
    }

    fn marker(&self) -> Result<Option<Attempt>> {
        let value: Option<Attempt> = state::optional(&self.state.join("in-progress.json"))?;
        if let Some(value) = &value {
            value.validate(None)?;
        }
        Ok(value)
    }

    fn event(
        &self,
        id: &AttemptId,
        stage: &str,
        status: impl Serialize,
        detail: &str,
    ) -> Result<()> {
        let path = self.logs.join(id.to_string()).join("events.jsonl");
        state::directory(path.parent().context("event has no directory")?)?;
        let clock = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
        let value = json!({"boot_id":id,"time":timestamp()?,"monotonic_seconds":clock.tv_sec as f64 + clock.tv_nsec as f64 / 1e9,"stage":stage,"status":status,"detail":detail});
        let mut line = serde_json::to_vec(&value)?;
        line.push(b'\n');

        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(
                rustix::fs::OFlags::NOFOLLOW.bits() as i32
                    | rustix::fs::OFlags::NONBLOCK.bits() as i32,
            )
            .open(&path)?;
        state::trusted(&path)?;
        ensure!(
            file.metadata()?.is_file(),
            "event log is not a regular file"
        );
        file.write_all(&line)?;
        file.sync_all()?;
        File::open(path.parent().context("event has no directory")?)?.sync_all()?;
        Ok(())
    }

    fn write(
        &self,
        mut value: Attempt,
        stage: &str,
        status: Status,
        detail: &str,
    ) -> Result<Attempt> {
        value.updated_at = timestamp()?;
        value.stage = stage.into();
        value.status = status;
        value.detail = detail.into();
        value.validate(Some(&value.boot_id))?;
        ensure!(detail.len() <= 64 * 1024, "boot detail exceeds limit");

        state::save(
            &self
                .state
                .join(value.boot_id.to_string())
                .join("state.json"),
            &value,
        )?;
        self.event(&value.boot_id, stage, status, detail)?;
        Ok(value)
    }

    fn current(&self) -> Result<Attempt> {
        if let Some(value) = self.read(&self.id)? {
            return Ok(value);
        }

        let time = timestamp()?;
        Ok(Attempt {
            schema: "airlock.boot-attempt.v1".into(),
            boot_id: self.id.clone(),
            updated_at: time.clone(),
            started_at: time,
            stage: "prepare".into(),
            status: Status::Working,
            detail: String::new(),
            desktop_ready: false,
            guests: Default::default(),
            shutdown_requested_at: None,
            recovered_by: None,
            previous_boot_id: None,
        })
    }

    fn clear_marker(&self) -> Result<()> {
        if self.marker()?.is_some_and(|m| m.boot_id == self.id) {
            state::unlink(&self.state.join("in-progress.json"))?;
        }
        Ok(())
    }

    fn update_marker(&self, value: &Attempt) -> Result<()> {
        if self.marker()?.is_some_and(|m| m.boot_id == value.boot_id) {
            state::save(&self.state.join("in-progress.json"), value)?;
        }
        Ok(())
    }

    fn prepare(&self) -> Result<Option<AttemptId>> {
        let _lock = self.lock()?;
        state::directory(&self.runtime)?;

        // Restarting the prepare unit must not reset completed progress or its recovery gate.
        let current: Option<Current> = state::optional(&self.runtime.join("current.json"))?;
        if current.is_some_and(|value| value.boot_id == self.id) {
            ensure!(
                self.read(&self.id)?.is_some(),
                "initialized boot state is missing"
            );
            return Ok(None);
        }

        // A failed publication may have saved recovery state before current.json.
        // Resume it without resetting the recovery outcome or opening the gate.
        if let Some(current) = self.read(&self.id)?
            && let Some(recovered) = current.previous_boot_id
        {
            state::save(
                &self.runtime.join("recovery-required.json"),
                &json!({"schema":"airlock.boot-recovery.v1","failed_boot_id":recovered,"boot_id":self.id}),
            )?;
            if self.marker()?.is_some_and(|m| m.boot_id == recovered) {
                state::unlink(&self.state.join("in-progress.json"))?;
            }
            state::save(
                &self.runtime.join("current.json"),
                &Current {
                    boot_id: self.id.clone(),
                    recovered: Some(recovered.clone()),
                },
            )?;
            return Ok(Some(recovered));
        }

        let previous = self.marker()?;
        let failed = previous.filter(|p| {
            p.boot_id != self.id
                && (p.shutdown_requested_at.is_none() || p.status == Status::Failed)
        });
        let recovered = failed.as_ref().map(|p| p.boot_id.clone());
        if let Some(mut previous) = failed {
            let critical = previous.status == Status::Failed;
            let stage = previous.stage.clone();
            let detail = if critical {
                previous.detail.clone()
            } else {
                "boot ended before readiness was confirmed".into()
            };
            previous.recovered_by = Some(self.id.clone());
            self.write(
                previous,
                &stage,
                if critical {
                    Status::Failed
                } else {
                    Status::Interrupted
                },
                &detail,
            )?;

            // Publish the gate before consuming the durable evidence of interruption.
            state::save(
                &self.runtime.join("recovery-required.json"),
                &json!({"schema":"airlock.boot-recovery.v1","failed_boot_id":recovered,"boot_id":self.id}),
            )?;
            let mut current = self.current()?;
            current.previous_boot_id = recovered.clone();
            self.write(
                current,
                "recovery",
                Status::RecoveryRequired,
                &format!(
                    "previous boot {} did not complete",
                    recovered.as_ref().context("missing recovered boot")?
                ),
            )?;
            state::unlink(&self.state.join("in-progress.json"))?;
        } else {
            let current = self.write(
                self.current()?,
                "prepare",
                Status::Working,
                "boot supervision started",
            )?;
            state::save(&self.state.join("in-progress.json"), &current)?;
        }
        state::save(
            &self.runtime.join("current.json"),
            &Current {
                boot_id: self.id.clone(),
                recovered: recovered.clone(),
            },
        )?;
        Ok(recovered)
    }

    /// Observe while holding the machine lock, then serialize publication against failure handlers.
    /// Supervisor locking follows machine locking, matching setup's stage-reporting order.
    fn accept(&self, coordinator: &Coordinator, scope: Scope, detail: &str) -> Result<()> {
        let policy = acceptance::Policy::read()?;
        coordinator.accept_boot(&self.id.to_string(), scope, &policy, |accepted| {
            let _lock = self.lock()?;
            let mut value = self
                .read(&self.id)?
                .context("boot attempt has not been prepared")?;
            ensure!(
                !matches!(
                    value.status,
                    Status::Failed | Status::Interrupted | Status::RecoveryRequired
                ) && value.shutdown_requested_at.is_none()
                    && !self.runtime.join("recovery-required.json").exists(),
                "failed, shutting down or recovery-gated boot cannot be accepted"
            );
            ensure!(
                accepted.permits(&self.id.to_string(), scope),
                "boot acceptance identity differs"
            );
            value.desktop_ready = accepted.desktop();
            let (stage, status) = if scope == Scope::Desktop {
                ("services", Status::Working)
            } else {
                ("ready", Status::Complete)
            };
            self.write(value, stage, status, detail)?;
            self.clear_marker()
        })
    }

    fn finish(&self, stage: &str, status: Status, detail: &str) -> Result<()> {
        let _lock = self.lock()?;
        self.write(self.current()?, stage, status, detail)?;
        Ok(())
    }

    fn shutdown_requested(&self) -> Result<()> {
        let _lock = self.lock()?;
        let mut value = self.current()?;
        value.shutdown_requested_at = Some(timestamp()?);
        let stage = value.stage.clone();
        let detail = value.detail.clone();
        let status = value.status;
        let value = self.write(value, &stage, status, &detail)?;
        self.update_marker(&value)?;
        self.event(
            &self.id,
            "shutdown",
            "requested",
            "system shutdown requested",
        )
    }

    fn retry_services(&self) -> Result<()> {
        let _lock = self.lock()?;
        let value = self.current()?;
        ensure!(
            value.desktop_ready
                && value.status == Status::Degraded
                && value.shutdown_requested_at.is_none(),
            "background services may only be retried from a degraded desktop before shutdown"
        );

        // Clear only failed early jobs. The background coordinator will retry them
        // through its normal readiness helper; running jobs remain owned by systemd.
        let runner = Runner::default();
        let failed = runner.capture(
            "systemctl",
            &[
                "is-failed".into(),
                "--quiet".into(),
                "airlock-boot-guest@usr-assistant.service".into(),
            ],
            Duration::from_secs(10),
            &[],
        )?;
        ensure!(
            !failed.limited,
            "checking assistant startup unit exceeded limits"
        );
        if failed.status.success() {
            runner.run(
                "systemctl",
                &[
                    "reset-failed".into(),
                    "airlock-boot-guest@usr-assistant.service".into(),
                ],
                Duration::from_secs(10),
                &[],
            )?;
        }

        Runner::default().run(
            "systemctl",
            &[
                "--no-block".into(),
                "restart".into(),
                "airlock-machine-autostart.service".into(),
            ],
            Duration::from_secs(10),
            &[],
        )?;
        self.write(
            value,
            "services",
            Status::Working,
            "retrying background services",
        )?;
        Ok(())
    }

    fn recovery_ack(&self) -> Result<()> {
        let _lock = self.lock()?;
        let value = self.current()?;
        ensure!(
            value.status == Status::RecoveryRequired
                || (value.stage == "recovery" && value.status == Status::Complete),
            "this boot is not awaiting recovery acknowledgement"
        );
        self.write(
            value,
            "recovery",
            Status::Complete,
            "safe recovery console reached",
        )?;
        self.clear_marker()
    }

    fn stage(&self, name: &str, detail: &str, failed: bool) -> Result<()> {
        {
            let _lock = self.lock()?;
            let value = self.write(
                self.current()?,
                name,
                if failed {
                    Status::Failed
                } else {
                    Status::Working
                },
                detail,
            )?;
            self.update_marker(&value)?;
        }
        // Even an invalid diagnostic label must not prevent recording a critical failure.
        if failed {
            self.snapshot(
                &self.id,
                &format!("failure-{}", name.replace('/', "_")),
                None,
            )?;
        }
        Ok(())
    }

    fn guest(&self, name: GuestName, phase: GuestState, detail: &str) -> Result<()> {
        let critical = if phase == GuestState::Failed {
            let path = std::env::var_os("AIRLOCK_BOOT_TOPOLOGY")
                .map(PathBuf::from)
                .unwrap_or_else(|| "/run/airlock/startup/topology.json".into());
            if path.try_exists()? {
                let inputs = BootInputs::new(state::configuration(&path)?)?;
                !inputs
                    .topology()
                    .domains
                    .keys()
                    .any(|name| name.as_str() == "sys-gui")
                    || !inputs.topology().domains.contains_key(&name)
                    || airlock_machine_core::boot::foreground_guests(inputs.topology())?
                        .contains(&name)
            } else {
                true
            }
        } else {
            false
        };

        {
            let _lock = self.lock()?;
            let mut value = self.current()?;
            value.guests.insert(name.clone(), phase);
            let status = if critical && !value.desktop_ready {
                Status::Failed
            } else {
                value.status
            };
            let value = self.write(value, &format!("qube:{name}"), status, detail)?;
            self.update_marker(&value)?;
        }

        if phase == GuestState::Failed {
            self.snapshot(&self.id, &format!("failure-qube:{name}"), None)?;
        }

        Ok(())
    }

    fn desktop_guests(&self, current: Option<&Attempt>) -> Result<Vec<Value>> {
        let path = std::env::var_os("AIRLOCK_BOOT_TOPOLOGY")
            .map(PathBuf::from)
            .unwrap_or_else(|| "/run/airlock/startup/topology.json".into());
        if !path.try_exists()? {
            return Ok(Vec::new());
        }
        let inputs = BootInputs::new(state::configuration(&path)?)?;
        let topology = inputs.topology();
        let names =
            crate::planning::plan(topology, topology, &Default::default(), &[], false)?.start;

        Ok(names
            .into_iter()
            .map(|name| {
                let domain = &topology.domains[&name];
                let gui = domain
                    .prefs
                    .get("guivm")
                    .or_else(|| topology.prefs.get("default_guivm"));
                let applications = name.as_str() != "sys-gui"
                    && gui.and_then(Value::as_str) == Some("sys-gui")
                    && domain.features.get("internal") != Some(&Value::Bool(true));

                let phase = if current.is_some_and(|value| {
                    value.status == Status::Complete
                        || (name.as_str() == "sys-gui" && value.desktop_ready)
                }) {
                    GuestState::Ready
                } else {
                    current
                        .and_then(|value| value.guests.get(&name))
                        .copied()
                        .unwrap_or_default()
                };
                json!({"name":name,"phase":phase,"applications":applications})
            })
            .collect())
    }
}

/// Publish progress only for an active supervised boot, preserving standalone coordinator use.
pub(crate) fn guest_checkpoint(name: &GuestName, phase: GuestState, detail: &str) -> Result<()> {
    let supervisor = Supervisor::load()?;
    if !supervisor.runtime.join("current.json").try_exists()? {
        return Ok(());
    }
    let current: Current = state::read(&supervisor.runtime.join("current.json"))?;
    ensure!(
        current.boot_id == supervisor.id,
        "startup progress belongs to another boot"
    );
    supervisor.guest(name.clone(), phase, detail)
}

/// Record one boot observation or return a read-only desktop status.
pub(crate) fn execute(request: Request, coordinator: &Coordinator) -> Result<Value> {
    let s = Supervisor::load()?;
    match request.action {
        Action::Prepare => {
            if let Some(previous) = s.prepare()? {
                s.snapshot(
                    &previous,
                    &format!("recovered-on-{}", s.id),
                    Some(&previous),
                )?;
            }
        }
        Action::DesktopStatus => {
            let state = s.read(&s.id)?;
            let guests = s.desktop_guests(state.as_ref())?;
            return Ok(
                json!({"boot_id":s.id,"guests":guests,"status":state.as_ref().map_or(Status::Working, |v| v.status),
                    "desktop_ready":state.as_ref().is_some_and(|v| v.desktop_ready),
                    "stage":state.as_ref().map_or("starting", |v| v.stage.as_str()),
                    "detail":state.as_ref().map_or("", |v| v.detail.as_str())}),
            );
        }
        Action::Snapshot { label } => {
            s.snapshot(&s.id, &label, None)?;
        }
        Action::Stage { name, detail } => s.stage(&name, &detail, false)?,
        Action::Guest {
            name,
            phase,
            detail,
        } => s.guest(name, phase, &detail)?,
        Action::Fail { name, detail } => s.stage(&name, &detail, true)?,
        Action::DesktopReady => s.accept(
            coordinator,
            Scope::Desktop,
            "desktop ready; starting background services",
        )?,
        Action::Degraded => {
            s.finish(
                "services",
                Status::Degraded,
                "background services could not start",
            )?;
            s.snapshot(&s.id, "background-services-failed", None)?;
        }
        Action::Complete { detail } => {
            s.accept(coordinator, Scope::Complete, &detail)?;
            s.snapshot(&s.id, "ready", None)?;
        }
        Action::ShutdownRequested => s.shutdown_requested()?,
        Action::RetryServices => s.retry_services()?,
        Action::RecoveryAck => s.recovery_ack()?,
    }

    Ok(json!({"boot_id":s.id,"status":"recorded"}))
}
