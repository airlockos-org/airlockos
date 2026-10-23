//! Show background startup progress and recoverable failures through native desktop notifications.

use crate::startup;
use airlock_vm_service::support;
use anyhow::Result;
use std::{process::Command, thread, time::Duration};

/// Attribute every local desktop alert to its installed Airlock application identity.
pub(crate) fn command() -> Command {
    let mut command = Command::new(support::tool("AIRLOCK_NOTIFY_SEND", "notify-send"));
    command.args([
        "--app-name=AirlockOS".to_owned(),
        format!("--icon={icon}", icon = airlock_desktop::ICON_NAME),
        format!(
            "--hint=string:desktop-entry:{id}",
            id = airlock_desktop::DESKTOP_ID
        ),
    ]);
    command
}

fn rpc(service: &str) -> Result<support::Output> {
    support::run(
        Command::new(support::tool("AIRLOCK_QVM_RUN", "qvm-run")).args([
            "--pass-io",
            "--no-gui",
            "--service",
            "dom0",
            service,
        ]),
        None,
        Duration::from_secs(20),
    )
}

pub(crate) fn execute() -> Result<()> {
    let mut previous = String::new();
    let mut notification = None;
    loop {
        match startup::read(Duration::from_secs(20)) {
            Ok(state) => {
                if state.status == "complete" {
                    if !previous.is_empty() {
                        let _ = progress(
                            "Background startup complete",
                            "Application VMs are ready.",
                            notification,
                            false,
                        );
                    }
                    return Ok(());
                }
                if state.desktop_ready && state.status == "working" {
                    let detail = state.progress();
                    if detail != previous {
                        notification =
                            progress("Starting background services", &detail, notification, true);
                        previous = detail;
                    }
                }
                if state.desktop_ready && state.status == "degraded" {
                    let mut command = command();
                    if let Some(identifier) = notification {
                        command.arg(format!("--replace-id={identifier}"));
                    }
                    let response = support::text(command.args(["--expire-time=0", "--wait", "--action=retry=Retry", "--action=dismiss=Dismiss", "Some background services could not start", "Your desktop is ready. You can retry starting the background services."]), Duration::from_secs(24 * 60 * 60))?;
                    if response != "retry" {
                        return Ok(());
                    }
                    if let Err(error) =
                        rpc("airlock.BootRetry").and_then(|v| v.checked().map(|_| ()))
                    {
                        eprintln!("background-service retry: {error:#}");
                    }
                }
            }
            Err(error) => {
                eprintln!("boot status: {error:#}");
                let detail = "Startup status is temporarily unavailable. Waiting for the Qubes control service to recover.";
                if previous != detail {
                    notification =
                        progress("Waiting for startup status", detail, notification, true);
                    previous = detail.into();
                }
            }
        }
        thread::sleep(Duration::from_secs(5));
    }
}

/// Replace one progress notification instead of leaving a new alert for each startup checkpoint.
fn progress(summary: &str, detail: &str, previous: Option<u32>, persistent: bool) -> Option<u32> {
    let mut command = command();
    command.arg("--print-id");
    command.arg(if persistent {
        "--expire-time=0"
    } else {
        "--expire-time=5000"
    });
    if let Some(identifier) = previous {
        command.arg(format!("--replace-id={identifier}"));
    }
    match support::text(
        command.args(["--", summary, detail]),
        Duration::from_secs(5),
    ) {
        Ok(output) => output.parse().ok().or(previous),
        Err(error) => {
            eprintln!("startup notification: {error:#}");
            previous
        }
    }
}
