//! Recover only from the kernel's explicit i8042 keyboard enable failure, once per boot.
//! A bound driver is evidence of initialization, never proof that physical input works.

use super::tool;
use crate::{model::BootId, process::Runner, state};
use airlock_nix_core::state::{OperationKind, OperationOwner, StateStore};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    NotApplicable,
    NoFailureDetected,
    Resetting,
    Reinitialized,
    Failed,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    // Version of the boot-local evidence record.
    schema: String,
    // Never inferred from driver binding or successful transport initialization.
    physical_input_verified: bool,
    // Persisted before sysfs mutation; survives process termination and restart.
    attempted: bool,
    // Observable recovery outcome, including interrupted or unsuccessful attempts.
    status: Status,
    // Explicit kernel failures that authorized the single recovery attempt.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    errors: Vec<String>,
    // Last checked kernel journal position, excluding earlier recovered failures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verified_cursor: Option<String>,
    // Actionable diagnostic retained after failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    // Systemd's independent result when the guard was terminated or exceeded its deadline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    service_result: Option<String>,
}

impl Default for Report {
    fn default() -> Self {
        Self {
            schema: "airlock.input-controller.v1".into(),
            physical_input_verified: false,
            attempted: false,
            status: Status::NoFailureDetected,
            errors: Vec::new(),
            verified_cursor: None,
            error: None,
            service_result: None,
        }
    }
}

struct Guard {
    // Boot-scoped evidence directory; older boots never authorize a new reset here.
    directory: PathBuf,
    // Kernel driver's sysfs directory, normally the real i8042 platform driver.
    controller: PathBuf,
}

impl Guard {
    fn load() -> Result<Self> {
        let id_file = PathBuf::from(tool(
            "AIRLOCK_INPUT_BOOT_ID_FILE",
            "/proc/sys/kernel/random/boot_id",
        ));
        let id: BootId = fs::read_to_string(id_file)?.trim().parse()?;
        let root = PathBuf::from(tool(
            "AIRLOCK_INPUT_LOG_ROOT",
            "/var/log/airlock/boot-attempts",
        ));
        let controller = PathBuf::from(tool(
            "AIRLOCK_INPUT_CONTROLLER",
            "/sys/bus/platform/drivers/i8042",
        ));
        crate::model::absolute(root.to_str().context("non-UTF-8 input log path")?)?;
        crate::model::absolute(
            controller
                .to_str()
                .context("non-UTF-8 input controller path")?,
        )?;
        Ok(Self {
            directory: root.join(id.to_string()),
            controller,
        })
    }

    fn path(&self) -> PathBuf {
        self.directory.join("input-controller.json")
    }

    fn report(&self) -> Result<Report> {
        let report = state::optional::<Report>(&self.path())?.unwrap_or_default();
        ensure!(
            report.schema == "airlock.input-controller.v1" && !report.physical_input_verified,
            "invalid input recovery record"
        );
        ensure!(
            !matches!(report.status, Status::Resetting | Status::Reinitialized) || report.attempted,
            "input recovery status lacks its durable attempt marker"
        );
        Ok(report)
    }

    fn bound(&self) -> Result<bool> {
        let device = self.controller.join("i8042");
        for port in fs::read_dir(device)? {
            let port = port?;
            if !port.file_name().to_string_lossy().starts_with("serio") {
                continue;
            }
            let driver = match fs::canonicalize(port.path().join("driver")) {
                Ok(driver) => driver,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            if driver.file_name().is_none_or(|n| n != "atkbd") {
                continue;
            }
            let inputs = match fs::read_dir(port.path().join("input")) {
                Ok(inputs) => inputs,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            for input in inputs {
                let input = input?;
                if input.file_name().to_string_lossy().starts_with("input")
                    && input.path().join("name").try_exists()?
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    fn perform(&self, report: &mut Report) -> Result<()> {
        ensure!(
            !report.attempted || report.status == Status::Reinitialized,
            "previous recovery failed or was interrupted; no second attempt this boot"
        );
        if !self.controller.join("i8042").try_exists()? {
            ensure!(
                !report.attempted,
                "controller is no longer bound after recovery"
            );
            report.status = Status::NotApplicable;
            return Ok(());
        }

        let records = journal(report.verified_cursor.as_deref())?;
        let errors = failures(&records);
        if errors.is_empty() {
            ensure!(
                !report.attempted || self.bound()?,
                "reinitialized keyboard driver is no longer bound"
            );
            report.status = if report.attempted {
                report.verified_cursor = cursor(&records)?.or(report.verified_cursor.take());
                Status::Reinitialized
            } else {
                Status::NoFailureDetected
            };
            return Ok(());
        }

        if report.attempted {
            // Keep the evidence that authorized the original reset intact.
            state::save(
                &self.directory.join("input-kernel-recurrence.json"),
                &records,
            )?;
            anyhow::bail!("keyboard initialization failed again; no second attempt this boot");
        }
        state::save(&self.directory.join("input-kernel-before.json"), &records)?;
        let before_cursor = cursor(&records)?.context("kernel failure has no journal cursor")?;
        report.status = Status::Resetting;
        report.attempted = true;
        report.errors = errors;
        // A crashed, hung or killed helper must never authorize a second reset.
        state::save(&self.path(), report)?;
        println!("{}", serde_json::to_string(report)?);

        Runner::default().run(
            std::env::current_exe()?,
            &["input".into(), "rebind".into()],
            Duration::from_secs(20),
            &[],
        )?;
        let deadline = Instant::now() + Duration::from_secs(10);
        while !self.bound()? {
            ensure!(
                Instant::now() < deadline,
                "keyboard driver did not bind after controller reinitialization"
            );
            thread::sleep(Duration::from_millis(100));
        }

        let after = journal(Some(&before_cursor))?;
        state::save(&self.directory.join("input-kernel-after.json"), &after)?;
        ensure!(
            failures(&after).is_empty(),
            "kernel reported keyboard initialization failure after recovery"
        );

        report.status = Status::Reinitialized;
        report.verified_cursor = Some(cursor(&after)?.unwrap_or(before_cursor));
        Ok(())
    }
}

fn cursor(records: &[Value]) -> Result<Option<String>> {
    records
        .last()
        .map(|record| {
            let cursor = record
                .get("__CURSOR")
                .and_then(Value::as_str)
                .context("kernel record has no cursor")?;
            ensure!(
                !cursor.is_empty() && cursor.len() <= 8192 && !cursor.chars().any(char::is_control),
                "invalid journal cursor"
            );
            Ok(cursor.to_owned())
        })
        .transpose()
}

fn failure(message: &str) -> bool {
    let Some(tail) = message.strip_prefix("atkbd serio") else {
        return false;
    };
    let Some((port, controller)) = tail.split_once(": Failed to enable keyboard on isa0060/serio")
    else {
        return false;
    };
    [port, controller]
        .into_iter()
        .all(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
}

fn failures(records: &[Value]) -> Vec<String> {
    records
        .iter()
        .filter_map(|r| r.get("MESSAGE").and_then(Value::as_str))
        .filter(|s| failure(s))
        .map(str::to_owned)
        .collect()
}

fn journal(cursor: Option<&str>) -> Result<Vec<Value>> {
    let executable = tool("AIRLOCK_INPUT_JOURNALCTL", "journalctl");
    let runner = Runner::default();
    runner.run(
        &executable,
        &["--sync".into()],
        Duration::from_secs(10),
        &[],
    )?;
    let mut args = vec![
        "--boot".into(),
        "--dmesg".into(),
        "--no-pager".into(),
        "--output=json".into(),
    ];
    if let Some(cursor) = cursor {
        args.extend(["--after-cursor".into(), cursor.into()]);
    }
    let output = runner.run(&executable, &args, Duration::from_secs(10), &[])?;
    output
        .lines()
        .filter(|l| !l.is_empty())
        .map(|line| {
            let value = airlock_nix_core::state::parse_json(
                line.as_bytes(),
                Path::new("<kernel input journal>"),
            )?;
            ensure!(
                matches!(value, Value::Object(_)),
                "invalid kernel journal record"
            );
            Ok(value)
        })
        .collect()
}

pub(super) fn check() -> Result<()> {
    let guard = Guard::load()?;
    state::directory(&guard.directory)?;
    let store = StateStore::initialize(&guard.directory)?;
    let _lock = store.try_operation(
        &"input-controller".parse()?,
        OperationOwner::new(
            "airlock-dom0-service keyboard guard".into(),
            "diagnose and permit at most one i8042 recovery this boot".into(),
            OperationKind::Recovery,
        )?,
    )?;
    let mut report = guard.report()?;
    report.error = None;
    let result = guard.perform(&mut report);
    if let Err(error) = &result {
        report.status = Status::Failed;
        report.error = Some(format!("{error:#}"));
    }
    state::save(&guard.path(), &report)?;
    println!("{}", serde_json::to_string(&report)?);
    result
}

pub(super) fn finalize() -> Result<()> {
    let result = std::env::var("SERVICE_RESULT").unwrap_or_else(|_| "unknown".into());
    if result == "success" {
        return Ok(());
    }
    let guard = Guard::load()?;
    state::directory(&guard.directory)?;
    let store = StateStore::initialize(&guard.directory)?;
    let _lock = store.try_operation(
        &"input-controller".parse()?,
        OperationOwner::new(
            "airlock-dom0-service keyboard guard finalizer".into(),
            "record systemd's unsuccessful keyboard initialization result".into(),
            OperationKind::Recovery,
        )?,
    )?;
    let mut report = guard.report()?;
    report.status = Status::Failed;
    report.service_result = Some(result);
    state::save(&guard.path(), &report)
}

pub(super) fn rebind() -> Result<()> {
    let guard = Guard::load()?;
    let store = StateStore::initialize(&guard.directory)?;
    let _lock = store.try_operation(
        &"input-rebind".parse()?,
        OperationOwner::new(
            "airlock-dom0-service keyboard rebind helper".into(),
            "consume the single prepared controller reset for this boot".into(),
            OperationKind::Recovery,
        )?,
    )?;
    let report = guard.report()?;
    ensure!(
        report.attempted && report.status == Status::Resetting,
        "no prepared keyboard recovery attempt"
    );
    let claim = guard.directory.join("input-rebind.json");
    match fs::symlink_metadata(&claim) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
        Ok(_) => anyhow::bail!("keyboard rebind already consumed this boot"),
    }

    fn attribute(path: &Path) -> Result<File> {
        let file = File::from(rustix::fs::open(
            path,
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?);
        ensure!(
            file.metadata()?.is_file(),
            "controller attribute must be a regular sysfs file"
        );
        Ok(file)
    }

    // Validate both existing attributes before disconnecting a working controller.
    // Never create, truncate or follow a replacement symlink at a sysfs control path.
    let mut unbind = attribute(&guard.controller.join("unbind"))?;
    let mut bind = attribute(&guard.controller.join("bind"))?;
    state::save(
        &claim,
        &serde_json::json!({"schema":"airlock.input-rebind.v1","consumed":true}),
    )?;

    // The durable claim remains even if either write blocks or this helper dies.
    unbind.write_all(b"i8042")?;
    bind.write_all(b"i8042")?;
    Ok(())
}
