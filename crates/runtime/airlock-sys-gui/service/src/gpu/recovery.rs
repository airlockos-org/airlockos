//! Recovery records distinguish a returned reset from a display that a person verified.
//! A reset helper owns its kernel lock through a blocked read, even after caller timeout.

use super::Action;
use airlock_nix_core::state::{OperationKind, OperationLock, OperationOwner, StateStore};
use airlock_vm_service::{
    gpu::{Observation, observe},
    support,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    io::Read,
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Component, Path, PathBuf},
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

fn path(key: &str, default: &str) -> PathBuf {
    std::env::var_os(key)
        .map(PathBuf::from)
        .unwrap_or_else(|| default.into())
}

fn root(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "GPU state path must be absolute");
    let mut current = PathBuf::from("/");
    for part in path.components().skip(1) {
        ensure!(
            matches!(part, Component::Normal(_)),
            "invalid GPU state path"
        );
        current.push(part);
        match fs::symlink_metadata(&current) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::DirBuilder::new().mode(0o700).create(&current)?
            }
            Err(e) => return Err(e.into()),
            Ok(_) => {}
        }
        let metadata = fs::symlink_metadata(&current)?;
        ensure!(
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == 0
                && metadata.mode() & 0o022 == 0,
            "unsafe GPU state directory {}",
            current.display()
        );
    }
    Ok(())
}

fn runtime() -> PathBuf {
    path("AIRLOCK_GPU_RECOVERY_RUNTIME", "/run/airlock/gpu-recovery")
}

fn logs() -> PathBuf {
    path("AIRLOCK_GPU_RECOVERY_LOGS", "/var/log/airlock/gpu-recovery")
}

fn boot() -> Result<String> {
    let value = fs::read_to_string(path(
        "AIRLOCK_GPU_BOOT_ID",
        "/proc/sys/kernel/random/boot_id",
    ))?
    .trim()
    .to_owned();
    ensure!(
        value.len() == 36
            && value
                .bytes()
                .enumerate()
                .all(|(i, b)| if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }),
        "invalid GPU recovery boot identity"
    );
    Ok(value)
}

fn lock(key: &str, reason: &str) -> Result<OperationLock> {
    let directory = runtime();
    root(&directory)?;
    let store = StateStore::initialize(&directory)?;
    Ok(store.try_operation(
        &key.parse()?,
        OperationOwner::new(
            "airlock-sys-gui-service GPU recovery".into(),
            reason.into(),
            OperationKind::Recovery,
        )?,
    )?)
}

fn device() -> Result<PathBuf> {
    let sysfs = path("AIRLOCK_GPU_SYSFS", "/sys");
    let mut matches = Vec::new();
    for entry in fs::read_dir(sysfs.join("bus/pci/devices"))? {
        let gpu = entry?.path();
        if fs::read_to_string(gpu.join("vendor"))?.trim() == "0x1002"
            && fs::read_to_string(gpu.join("device"))?.trim() == "0x1681"
            && fs::canonicalize(gpu.join("driver"))?
                .file_name()
                .is_some_and(|n| n == "amdgpu")
        {
            matches.push(gpu);
        }
    }
    ensure!(
        matches.len() == 1,
        "require exactly one amdgpu-owned lab Radeon 680M"
    );
    let name = matches[0].file_name().context("GPU address missing")?;
    let directory = path("AIRLOCK_GPU_DEBUG", "/sys/kernel/debug/dri").join(name);
    ensure!(
        directory.join("amdgpu_gpu_recover").try_exists()?,
        "exact GPU recovery interface is unavailable"
    );
    Ok(directory)
}

fn command(program: &str, args: &[&str], timeout: Duration) -> Result<Observation> {
    let executable = match program {
        "journalctl" => support::tool("AIRLOCK_GPU_JOURNALCTL", "journalctl"),
        "systemctl" => support::tool("AIRLOCK_GPU_SYSTEMCTL", "systemctl"),
        "cat" => support::tool("AIRLOCK_GPU_CAT", "cat"),
        _ => anyhow::bail!("unsupported GPU diagnostic helper"),
    };
    observe(Command::new(executable).args(args), timeout)
}

fn capture_record(record: &Path, report: &mut Value, key: &str) -> Result<()> {
    if serde_json::to_vec(report)?.len() > 8 * 1024 * 1024 {
        // Retain earlier evidence while discarding only the step that exceeded
        // the total budget. A partial capture must never authorize recovery.
        report[key] = json!({"error":"total GPU evidence limit exceeded"});
        support::save(record, report)?;
        anyhow::bail!("total GPU evidence limit exceeded");
    }
    support::save(record, report)
}

fn capture(directory: &Path, report: &mut Value, record: &Path) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(15);
    report["kernel_release"] = json!(fs::read_to_string("/proc/sys/kernel/osrelease")?.trim());
    report["cmdline"] = json!(fs::read_to_string("/proc/cmdline")?.trim());

    fn diagnostic(program: &str, args: &[&str], deadline: Instant) -> Result<Observation> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .context("GPU diagnostic capture deadline exceeded")?;
        command(program, args, remaining.min(Duration::from_secs(10)))
    }
    report["kernel"] = serde_json::to_value(diagnostic(
        "journalctl",
        &["-k", "-b", "-n", "200", "--no-pager"],
        deadline,
    )?)?;
    capture_record(record, report, "kernel")?;
    report["recent_kernel"] = serde_json::to_value(diagnostic(
        "journalctl",
        &[
            "-k",
            "-b",
            "--since",
            "5 minutes ago",
            "-n",
            "200",
            "--no-pager",
        ],
        deadline,
    )?)?;
    capture_record(record, report, "recent_kernel")?;
    report["desktop"] = serde_json::to_value(diagnostic(
        "journalctl",
        &["-b", "-u", "display-manager", "-n", "80", "--no-pager"],
        deadline,
    )?)?;
    capture_record(record, report, "desktop")?;
    for (key, name) in [
        ("fences", "amdgpu_fence_info"),
        ("firmware", "amdgpu_firmware_info"),
    ] {
        report[key] = serde_json::to_value(diagnostic(
            "cat",
            &[directory
                .join(name)
                .to_str()
                .context("non-UTF-8 GPU path")?],
            deadline,
        )?)?;
        capture_record(record, report, key)?;
    }
    report["psr"] = json!({});
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if !entry.file_name().to_string_lossy().starts_with("eDP-") {
            continue;
        }
        for name in ["psr_capability", "psr_state", "disallow_edp_enter_psr"] {
            let file = entry.path().join(name);
            if file.try_exists()? {
                let key = file.to_str().context("non-UTF-8 PSR path")?;
                report["psr"][key] = serde_json::to_value(diagnostic("cat", &[key], deadline)?)?;
                capture_record(record, report, "psr")?;
            }
        }
    }
    capture_record(record, report, "psr")?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    // Durable evidence record that must show success before desktop restart.
    report: PathBuf,
    // Runtime records from a different boot cannot authorize hardware operations.
    boot_id: String,
    // PCI identity captured before diagnostics; a different GPU cannot reuse the claim.
    gpu: String,
}

fn marker() -> Result<Marker> {
    let value: Marker = support::read(&runtime().join("reset-attempted.json"))?
        .context("capture and attempt GPU recovery before desktop restart")?;
    ensure!(
        value.boot_id == boot()?,
        "GPU recovery marker belongs to another boot"
    );
    ensure!(
        value.report.parent() == Some(logs().as_path()),
        "GPU recovery report is outside the evidence directory"
    );
    Ok(value)
}

pub(super) fn reset() -> Result<()> {
    ensure!(
        rustix::process::geteuid().is_root(),
        "GPU recovery requires root in sys-gui"
    );
    let _lock = lock(
        "reset",
        "perform the single prepared GPU reset; a blocked kernel read retains this lock",
    )?;
    let marker = marker()?;
    let report: Value = support::read(&marker.report)?.context("GPU reset report missing")?;
    ensure!(
        report["status"] == "reset-requested",
        "no prepared GPU recovery attempt"
    );
    let consumed = runtime().join("reset-started.json");
    ensure!(
        fs::symlink_metadata(&consumed).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "GPU reset already consumed this boot"
    );
    let directory = device()?;
    ensure!(
        report["boot_id"] == marker.boot_id
            && report["gpu"] == marker.gpu
            && directory.file_name().and_then(|s| s.to_str()) == Some(marker.gpu.as_str())
            && report["physical_recovery_verified"] == false,
        "GPU recovery identity changed after evidence capture"
    );
    let mut file = File::from(rustix::fs::open(
        directory.join("amdgpu_gpu_recover"),
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?);
    ensure!(
        file.metadata()?.is_file(),
        "GPU reset interface must be an existing regular debugfs file"
    );
    support::save(
        &consumed,
        &json!({"boot_id":boot()?,"report":marker.report,"pid":std::process::id()}),
    )?;
    let mut byte = [0u8; 1];
    let _ = file.read(&mut byte)?;
    Ok(())
}

pub(super) fn execute(action: Action, confirmed: bool) -> Result<()> {
    ensure!(
        rustix::process::geteuid().is_root(),
        "run as root in sys-gui using the existing administrative route"
    );
    ensure!(
        matches!(action, Action::Capture) || confirmed,
        "recovery requires --confirm-display-stall"
    );
    let _lock = lock(
        "recovery",
        "capture display evidence or perform an explicitly confirmed recovery",
    )?;
    let reset_guard = lock(
        "reset",
        "refuse further operations while a GPU reset is still pending",
    )?;
    drop(reset_guard);
    root(&logs())?;
    let directory = device()?;
    let started = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let file = logs().join(format!(
        "{}-{}.json",
        started.as_nanos(),
        std::process::id()
    ));
    let mut report = json!({"physical_recovery_verified":false,"boot_id":boot()?,"gpu":directory.file_name().and_then(|s|s.to_str())});
    report["action"] = json!(match action {
        Action::Capture => "capture",
        Action::Recover => "recover",
        Action::RestartDesktop => "restart-desktop",
        Action::Reset => unreachable!(),
    });
    report["started_at"] = json!(started.as_secs_f64());
    report["status"] = json!("capturing");
    support::save(&file, &report)?;

    let result = (|| -> Result<()> {
        capture(&directory, &mut report, &file)?;
        ensure!(
            device()? == directory,
            "GPU recovery identity changed after evidence capture"
        );

        match action {
            Action::Capture => report["status"] = json!("captured"),
            Action::Recover => {
                let recent = &report["recent_kernel"];
                ensure!(
                    recent["returncode"] == 0
                        && recent["stdout"].as_str().is_some_and(|s| [
                            "flip_done timed out",
                            "flip_done or hw_done timed out",
                            "hw_done or flip_done timed out"
                        ]
                        .iter()
                        .any(|needle| s.contains(needle))),
                    "no recent display flip timeout; reset refused"
                );
                let claim = runtime().join("reset-attempted.json");
                ensure!(
                    fs::symlink_metadata(&claim)
                        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                    "GPU reset already attempted this boot"
                );
                support::save(
                    &claim,
                    &Marker {
                        report: file.clone(),
                        boot_id: boot()?,
                        gpu: directory
                            .file_name()
                            .and_then(|s| s.to_str())
                            .context("non-UTF-8 GPU identity")?
                            .into(),
                    },
                )?;
                report["status"] = json!("reset-requested");
                support::save(&file, &report)?;
                let reset = observe(
                    Command::new(std::env::current_exe()?).args(["gpu", "reset"]),
                    Duration::from_secs(25),
                )?;
                let success = reset.returncode == Some(0) && !reset.timeout;
                report["status"] = json!(if reset.timeout {
                    "unknown"
                } else {
                    "reset-returned"
                });
                report["reset"] = serde_json::to_value(reset)?;
                support::save(&file, &report)?;
                report["after_kernel"] = serde_json::to_value(command(
                    "journalctl",
                    &["-k", "-b", "-n", "80", "--no-pager"],
                    Duration::from_secs(10),
                )?)?;
                ensure!(
                    success,
                    "reset failed or timed out; inspect {}",
                    file.display()
                );
            }
            Action::RestartDesktop => {
                let previous: Value = support::read(&marker()?.report)?
                    .context("previous GPU reset report missing")?;
                ensure!(
                    previous["boot_id"] == boot()?
                        && previous["gpu"].as_str()
                            == directory.file_name().and_then(|s| s.to_str()),
                    "GPU recovery identity changed before desktop restart"
                );
                ensure!(
                    previous["reset"]["returncode"] == 0
                        && previous["reset"]["timeout"] == false
                        && previous["reset"]["error"].is_null(),
                    "previous reset did not finish successfully; desktop restart refused"
                );
                let claim = runtime().join("desktop-restart-attempted.json");
                ensure!(
                    fs::symlink_metadata(&claim)
                        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                    "desktop restart already attempted this boot"
                );
                support::save(&claim, &json!({"report":file,"boot_id":boot()?}))?;
                let restart = command(
                    "systemctl",
                    &["restart", "display-manager"],
                    Duration::from_secs(30),
                )?;
                let success = restart.returncode == Some(0) && !restart.timeout;
                report["restart"] = serde_json::to_value(restart)?;
                report["status"] = json!("desktop-restart-returned");
                ensure!(
                    success,
                    "desktop restart failed or timed out; inspect {}",
                    file.display()
                );
            }
            Action::Reset => unreachable!(),
        }
        Ok(())
    })();
    if let Err(error) = &result {
        report["error"] = json!(format!("{error:#}"));
        if report["status"] != "unknown" {
            report["status"] = json!("failed");
        }
    }
    support::save(&file, &report)?;
    println!(
        "{}",
        json!({"report":file,"status":report["status"],"physical_recovery_verified":false})
    );
    result
}
