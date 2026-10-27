//! Launch a fixed smoke scenario only in the explicitly selected disposable VM.

use crate::support;
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{path::Path, process::Command, time::Duration};

pub(super) fn execute(root: &Path) -> Result<()> {
    // dom0 already has the native CLI and coordinator; the test needs no copied
    // executable, Python interpreter, new RPC, or production policy exception.
    let ssh = || -> Result<Command> {
        let mut command = Command::new(std::env::current_exe()?);
        command
            .arg("--repository-root")
            .arg(root)
            .args(["with-environment", "nested", "ssh"]);
        Ok(command)
    };
    let result = airlock_nix_core::runtime::process::run(
        ssh()?.args(["sudo", "-n", "airlock-dom0-service", "pool-admission-smoke"]),
        None,
        Some(Duration::from_secs(7200)),
    )?;
    let logs = std::env::var_os("AIRLOCK_LOG_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| root.join(".airlock-logs"));
    support::atomic(
        &logs.join("pool-admission-smoke.stdout.log"),
        &result.stdout,
    )?;
    support::atomic(
        &logs.join("pool-admission-smoke.stderr.log"),
        &result.stderr,
    )?;
    let bytes = result.checked("nested pool admission smoke")?;
    let text = std::str::from_utf8(&bytes)?;
    let payload: Value = serde_json::from_str(text.lines().last().unwrap_or(""))?;
    ensure!(
        payload["schema"] == "airlock.pool-admission-smoke.v1" && payload["status"] == "passed",
        "invalid smoke result"
    );
    support::record(&logs.join("pool-admission-smoke.json"), &payload)?;
    support::print(&json!(payload))?;
    support::output(ssh()?.args(["sudo", "-n", "systemctl", "poweroff"]))?;
    Ok(())
}
