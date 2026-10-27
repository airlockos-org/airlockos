//! Fixed qrexec configuration operations; incoming source archives are inert data.

use super::io::{self, Operation};
use crate::process::Files;
use anyhow::{Context, Result, ensure};
use clap::ValueEnum;
use serde_json::json;
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::unix::{
        fs::{PermissionsExt, symlink},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::Command,
};

/// Administrative operations already admitted by the existing per-service Qubes policy.
#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum Action {
    /// Read configuration status without accepting input or mutating configuration.
    Status,
    /// Validate the submitted source in the existing offline validator.
    Check,
    /// Apply a submitted candidate through the fixed configuration helper.
    Apply,
    /// Restore the previous host generation using existing profile semantics.
    Rollback,
}

/// Replace one profile link without following an existing link to its target directory.
pub(super) fn link(target: &Path, path: &Path) -> Result<()> {
    fs::create_dir_all(path.parent().context("profile directory")?)?;
    let directory = tempfile::tempdir_in(path.parent().unwrap())?;
    let temporary = directory.path().join("profile");
    symlink(target, &temporary)?;
    fs::rename(temporary, path)?;
    Ok(())
}

/// Create a persistent operation directory; evidence must outlive the process and temporary input.
fn directory(action: &str) -> Result<PathBuf> {
    let base = io::path(
        "AIRLOCK_CONFIG_CONTROL_LOG_DIR",
        io::path("AIRLOCK_LOG_DIR", "/var/log/airlock").join("config-control"),
    );
    fs::create_dir_all(&base)?;
    Ok(tempfile::Builder::new()
        .prefix(&format!("{action}-"))
        .tempdir_in(base)?
        .keep())
}

/// Spool bounded request bytes without executing or extracting submitted content.
fn input(target: &Path) -> Result<()> {
    let mut source = std::io::stdin().lock();
    let mut destination = File::create(target)?;
    let copied = std::io::copy(
        &mut source.by_ref().take(8 * 1024 * 1024 * 1024 + 1),
        &mut destination,
    )?;
    ensure!(
        copied <= 8 * 1024 * 1024 * 1024,
        "candidate input exceeds its size limit"
    );
    Ok(())
}

/// Run only the fixed validator/apply helper; return its persisted receipt even when it fails.
fn submit(action: Action, operation: &str, replied: &mut bool) -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let candidate = temporary.path().join("candidate.tar");
    input(&candidate)?;
    let inspection = tempfile::tempdir()?;
    io::unpack(
        &candidate,
        inspection.path(),
        &["config.bundle", "manifest.json"],
        &[],
    )?;
    let directory = directory(operation)?;
    let (program, receipt) = match action {
        Action::Check => ("airlock-config-archive-candidate", "config-archive.json"),
        Action::Apply => ("airlock-config-apply", "config-apply.json"),
        _ => unreachable!(),
    };
    let mut args = vec!["--candidate-tar".into(), candidate.into_os_string()];
    args.push(
        if matches!(action, Action::Check) {
            "--validate-only"
        } else {
            "--apply"
        }
        .into(),
    );
    for (key, default, flag) in [
        (
            "AIRLOCK_CONFIG_STAGING_VM",
            "sys-config-staging",
            "--staging",
        ),
        (
            "AIRLOCK_CONFIG_VALIDATOR_VM",
            "sys-config-validator",
            "--validator",
        ),
        ("AIRLOCK_CONFIG_VAULT_VM", "sys-config-vault", "--vault"),
    ] {
        args.extend([flag.into(), io::setting(key, default).into()]);
    }
    let mut log = Operation::new("config-control")?;
    let result = log.transfer(
        program,
        &args,
        Files {
            input: None,
            output: &directory.join("stdout.log"),
            errors: &directory.join("stderr.log"),
            limit: 16 * 1024 * 1024,
        },
        &[("AIRLOCK_LOG_DIR".into(), directory.as_os_str().to_owned())],
    );
    let receipt = directory.join(receipt);
    *replied = true;
    if receipt.is_file() {
        std::io::stdout().write_all(&fs::read(receipt)?)?;
    } else {
        println!(
            "{receipt}",
            receipt = json!({"schema":"airlock.config-control.v1","operation":operation,"status":"failed","reason":"candidate operation did not produce result JSON"})
        );
    }
    result
}

/// Restore the selected previous host generation, retaining failures instead of reporting false success.
fn rollback() -> Result<()> {
    let directory = directory("rollback")?;
    let state = io::path("AIRLOCK_SYSTEM_STATE_DIR", "/var/lib/airlock/system");
    let profile = io::path(
        "AIRLOCK_HOST_SYSTEM_PROFILE",
        "/nix/var/nix/profiles/system",
    );
    let current_link = io::path("AIRLOCK_HOST_CURRENT_SYSTEM_LINK", "/run/current-system");
    fs::create_dir_all(&state)?;
    let current = fs::canonicalize(&profile).unwrap_or_default();
    let mut target = PathBuf::new();
    let mut method = "state";
    let mut log = Operation::new("config-control")?;
    let result = (|| {
        match fs::read_to_string(state.join("previous-host-system")) {
            Ok(previous) => {
                target = previous
                    .lines()
                    .next()
                    .context("empty previous host system")?
                    .into();
                ensure!(
                    target.is_absolute(),
                    "previous host system must be absolute"
                );
                link(&target, &profile)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                method = "nix-profile";
                log.transfer(
                    "nix-env",
                    &[
                        "-p".into(),
                        profile.as_os_str().to_owned(),
                        "--rollback".into(),
                    ],
                    Files {
                        input: None,
                        output: &directory.join("profile-rollback.log"),
                        errors: &directory.join("profile-rollback.stderr.log"),
                        limit: 16 * 1024 * 1024,
                    },
                    &[],
                )?;
                target = fs::canonicalize(&profile)?;
            }
            Err(error) => return Err(error.into()),
        }
        ensure!(
            !target.as_os_str().is_empty() && target != current,
            "no previous host system generation is available"
        );
        let switch = target.join("bin/switch-to-configuration");
        ensure!(
            switch.is_file() && switch.metadata()?.permissions().mode() & 0o111 != 0,
            "previous host system has no switch-to-configuration"
        );
        log.transfer(
            switch.to_str().context("previous switch path")?,
            &["switch".into()],
            Files {
                input: None,
                output: &directory.join("switch-to-configuration.log"),
                errors: &directory.join("switch-to-configuration.stderr.log"),
                limit: 16 * 1024 * 1024,
            },
            &[
                (
                    "AIRLOCK_SYSTEM_STATE_DIR".into(),
                    state.as_os_str().to_owned(),
                ),
                (
                    "AIRLOCK_HOST_CURRENT_SYSTEM_LINK".into(),
                    current_link.into_os_string(),
                ),
            ],
        )?;
        for (name, value) in [
            ("current-host-system", target.as_os_str()),
            ("current-host-system-profile", profile.as_os_str()),
            (
                "current-host-system-switch-action",
                std::ffi::OsStr::new("switch"),
            ),
        ] {
            let mut file = File::create(state.join(name))?;
            writeln!(file, "{value}", value = value.to_string_lossy())?;
        }
        Ok(())
    })();
    let receipt = json!({"schema":"airlock.config-rollback.v1","status":if result.is_ok() {"passed"} else {"failed"},"reason":match &result { Ok(()) => "rolled back host system profile to previous generation".into(), Err(error) => format!("{error:#}") },"method":method,"previous_current_system":current,"target_system":target,"switch_log":directory.join("switch-to-configuration.log")});
    io::save(&directory.join("config-rollback.json"), &receipt)?;
    println!("{receipt}");
    result
}

/// Keep the four existing entry points and report early input errors in the existing JSON protocol.
pub(super) fn execute(action: Action) -> Result<()> {
    if matches!(action, Action::Status) {
        return Err(Command::new("airlock-config-status").exec().into());
    }
    if matches!(action, Action::Rollback) {
        return rollback();
    }
    let operation = if matches!(action, Action::Check) {
        "check"
    } else {
        "apply"
    };
    let mut replied = false;
    let result = submit(action, operation, &mut replied);
    if let Err(error) = &result {
        if !replied {
            println!(
                "{receipt}",
                receipt = json!({"schema":"airlock.config-control.v1","operation":operation,"status":"failed","reason":format!("{error:#}")})
            );
        }
        eprintln!("airlock config control failed: {error:#}");
    }
    result
}
