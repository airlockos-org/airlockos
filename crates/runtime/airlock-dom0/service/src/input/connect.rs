//! Enable physical forwarding only after the same running GUI VM answers readiness.

use super::tool;
use crate::process::Runner;
use airlock_machine_core::input::Receiver;
use airlock_nix_core::identity::GuestName;
use anyhow::{Context, Result, bail, ensure};
use std::{
    ffi::OsString,
    thread,
    time::{Duration, Instant},
};

/// Retry the independently managed connection job; observer cleanup may cancel that job at boot.
pub(super) fn boot_ready(target: &GuestName, timeout: u64) -> Result<()> {
    let runner = Runner::default();
    let before = instance(&runner, target)?;
    let deadline = Instant::now() + Duration::from_secs(timeout);
    let mut error = "input forwarding is not ready".to_owned();
    let mut delay = Duration::from_millis(500);
    while Instant::now() < deadline {
        let result = (|| -> Result<()> {
            runner.run(
                tool("AIRLOCK_INPUT_SYSTEMCTL", "systemctl"),
                &["start".into(), "airlock-gui-input-connect.service".into()],
                deadline.saturating_duration_since(Instant::now()),
                &[],
            )?;
            check(&runner, target)?;
            ensure!(
                instance(&runner, target)? == before,
                "{target} restarted during boot input readiness"
            );
            Ok(())
        })();
        match result {
            Ok(()) => return Ok(()),
            Err(failure) => {
                let latest = format!("{failure:#}");
                if latest != error {
                    eprintln!("Waiting for input on {target}: {latest}");
                }
                error = latest;
            }
        }
        thread::sleep(delay.min(deadline.saturating_duration_since(Instant::now())));
        delay = (delay * 2).min(Duration::from_secs(4));
    }
    bail!("{target}: boot input readiness timed out: {error}")
}

/// Invoke a fixed input helper with bounded output and owned process cleanup.
fn run(
    runner: &Runner,
    key: &str,
    program: &str,
    arguments: &[&str],
    seconds: u64,
) -> Result<String> {
    runner.run(
        tool(key, program),
        &arguments.iter().map(OsString::from).collect::<Vec<_>>(),
        Duration::from_secs(seconds),
        &[],
    )
}

/// Check running state before reading the current Xen identity; neither query starts a VM.
fn instance(runner: &Runner, target: &GuestName) -> Result<String> {
    run(
        runner,
        "AIRLOCK_INPUT_QVM_CHECK",
        "qvm-check",
        &["--running", target.as_str()],
        10,
    )?;
    let output = runner.capture(
        tool("AIRLOCK_INPUT_QVM_LS", "qvm-ls"),
        &[
            "--raw-data".into(),
            "--fields".into(),
            "XID".into(),
            target.as_str().into(),
        ],
        Duration::from_secs(10),
        &[],
    )?;
    ensure!(
        !output.limited && output.status.success(),
        "could not read the running {target} instance: {error}",
        error = String::from_utf8_lossy(&output.stderr)
    );
    let xid = String::from_utf8(output.stdout)?
        .trim_end_matches('\n')
        .to_owned();
    ensure!(
        !xid.is_empty()
            && xid.bytes().all(|byte| byte.is_ascii_digit())
            && xid.parse::<u32>().is_ok_and(|xid| xid > 0),
        "could not identify the running {target} instance"
    );
    Ok(xid)
}

/// Recheck both running state and Xen identity after readiness, then enable and verify discovery.
pub(super) fn connect(target: &GuestName) -> Result<()> {
    let runner = Runner::default();
    let before = instance(&runner, target)?;
    run(
        &runner,
        "AIRLOCK_INPUT_QREXEC",
        "qrexec-client",
        &[
            "-d",
            target.as_str(),
            "-T",
            "-w",
            "60",
            "DEFAULT:QUBESRPC airlock.InputReceiverReady dom0",
        ],
        65,
    )?;
    let after = instance(&runner, target)?;
    ensure!(after == before, "{target} restarted during input readiness");

    run(
        &runner,
        "AIRLOCK_INPUT_SYSTEMCTL",
        "systemctl",
        &["restart", "airlock-gui-input.target"],
        30,
    )?;
    run(
        &runner,
        "AIRLOCK_INPUT_SYSTEMCTL",
        "systemctl",
        &[
            "is-active",
            "--quiet",
            "airlock-gui-input-discovery.service",
        ],
        5,
    )?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last_error = None;
    loop {
        match check(&runner, target) {
            Ok(()) => break,
            Err(error) if Instant::now() >= deadline => {
                return Err(error).context("input forwarding did not become ready");
            }
            Err(error) => {
                let detail = format!("{error:#}");
                if last_error
                    .as_ref()
                    .is_none_or(|(previous, at): &(String, Instant)| {
                        previous != &detail || at.elapsed() >= Duration::from_secs(5)
                    })
                {
                    eprintln!("Waiting for forwarded devices on {target}: {detail}");
                    last_error = Some((detail, Instant::now()));
                }
            }
        }
        thread::sleep(Duration::from_millis(500));
    }
    ensure!(
        instance(&runner, target)? == before,
        "{target} restarted while connecting input"
    );
    Ok(())
}

/// Observe the daemon and kernel-registered receivers without starting or restarting anything.
pub(crate) fn check(runner: &Runner, target: &GuestName) -> Result<()> {
    run(
        runner,
        "AIRLOCK_INPUT_SYSTEMCTL",
        "systemctl",
        &[
            "is-active",
            "--quiet",
            "airlock-gui-input-discovery.service",
        ],
        5,
    )?;
    let physical = super::discovery::physical()?;
    let reply = run(
        runner,
        "AIRLOCK_INPUT_QREXEC",
        "qrexec-client",
        &[
            "-d",
            target.as_str(),
            "-T",
            "-w",
            "5",
            "DEFAULT:QUBESRPC airlock.InputReceiverReady dom0",
        ],
        10,
    )?;
    let receiver: Receiver =
        serde_json::from_str(&reply).context("invalid input receiver observation")?;
    receiver.covers(&physical).map_err(anyhow::Error::msg)
}
