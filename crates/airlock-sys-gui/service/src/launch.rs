//! Retry session readiness within one deadline, then submit an application request once.

use crate::{qubes, workspace};
use airlock_nix_core::identity::GuestName;
use airlock_vm_service::support::{self, Input, Output};
use anyhow::Result;
use clap::Args;
use std::{
    os::unix::process::ExitStatusExt,
    process::Command,
    thread,
    time::{Duration, Instant},
};

/// Explicit user launch, also used without a service to start a VM for menu synchronization.
#[derive(Args)]
pub(crate) struct Request {
    /// Human-readable application name used only in failure notifications.
    pub(super) label: String,
    /// VM selected by the installed launcher or the user's explicit menu refresh.
    pub(super) target: GuestName,
    /// Qubes RPC submitted once after readiness; omission only waits for the session.
    pub(super) service: Option<String>,
    /// Reserve a GNOME workspace immediately before submitting the application.
    #[arg(long)]
    pub(super) workspace: bool,
    /// Total readiness budget, including feature discovery, qrexec, and retry delays.
    #[arg(long, default_value_t = 90, value_parser = clap::value_parser!(u64).range(1..=90))]
    pub(super) readiness_timeout: u64,
}

/// Retain bounded failure evidence even if repeated readiness helpers are noisy.
fn append(log: &mut Vec<u8>, bytes: &[u8]) {
    const LIMIT: usize = 1024 * 1024;

    log.extend_from_slice(&bytes[..bytes.len().min(LIMIT.saturating_sub(log.len()))]);
}

/// Capture both helper streams without interpreting them as executable or notification text.
fn record(log: &mut Vec<u8>, output: &Output) {
    append(log, &output.stdout);
    append(log, &output.stderr);
}

/// Preserve ordinary helper exit codes and conventional signal-derived statuses.
fn status(output: &Output) -> u8 {
    output
        .status
        .code()
        .unwrap_or_else(|| 128 + output.status.signal().unwrap_or(1)) as u8
}

/// Best-effort reporting must not replace the launch's original failure status.
fn report(request: &Request, log: Vec<u8>, detail: &str) {
    let _ = support::run(
        Command::new(support::tool("AIRLOCK_SYSTEMD_CAT", "systemd-cat"))
            .args(["-t", "airlock-app-launch"]),
        Some(Input::bytes(log)),
        Duration::from_secs(5),
    );
    // %c supplies the localized desktop name, which already has a trusted VM prefix.
    let prefix = format!("{target}: ", target = request.target);
    let label = request
        .label
        .strip_prefix(&prefix)
        .unwrap_or(&request.label);
    let _ = support::run(
        crate::notifications::command().args([
            "--",
            &format!(
                "Launch not confirmed: {label} in {target}",
                target = request.target
            ),
            detail,
        ]),
        None,
        Duration::from_secs(5),
    );
}

/// Readiness alone is retried; the same deadline bounds discovery and the guest RPC.
fn ready(request: &Request, log: &mut Vec<u8>) -> bool {
    let deadline = Instant::now() + Duration::from_secs(request.readiness_timeout);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }

        match qubes::readiness(&request.target, remaining.min(Duration::from_secs(15))) {
            Ok(supported) => {
                let service = if supported {
                    "airlock.AppSessionReady"
                } else {
                    "qubes.WaitForSession"
                };
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return false;
                }

                match support::run(
                    Command::new(support::tool("AIRLOCK_QVM_RUN", "qvm-run")).args([
                        "--auto",
                        "--gui",
                        "--pass-io",
                        "--service",
                        request.target.as_str(),
                        service,
                    ]),
                    None,
                    remaining,
                ) {
                    Ok(output) => {
                        record(log, &output);
                        if output.status.success() {
                            return true;
                        }
                    }
                    Err(error) => append(log, format!("{error:#}\n").as_bytes()),
                }
            }
            Err(error) => append(log, format!("{error:#}\n").as_bytes()),
        }

        append(
            log,
            b"Session readiness interrupted; retrying within the launch deadline.\n",
        );
        thread::sleep(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(2)),
        );
    }
}

/// Own the upstream application-lifetime channel until it exits, without imposing a startup deadline.
/// Qubes' StartApp intentionally remains connected while the application runs; readiness is bounded separately.
fn application(request: &Request, service: &str) -> Result<Output> {
    let output = airlock_nix_core::runtime::process::run(
        Command::new(support::tool("AIRLOCK_QVM_RUN", "qvm-run")).args([
            "--auto",
            "--gui",
            "--service",
            request.target.as_str(),
            service,
        ]),
        None,
        None,
    )?;
    Ok(Output {
        status: output.status,
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

/// Return the original submission status, cancelling a reserved workspace on every submission failure.
pub(crate) fn execute(request: Request) -> Result<u8> {
    let mut log = Vec::new();
    if !ready(&request, &mut log) {
        report(
            &request,
            log,
            &format!(
                "{target} did not become ready within {seconds} seconds.",
                target = request.target,
                seconds = request.readiness_timeout,
            ),
        );
        return Ok(124);
    }
    let Some(service) = request
        .service
        .as_deref()
        .filter(|service| !service.is_empty())
    else {
        return Ok(0);
    };

    log.clear();
    let reservation = if request.workspace {
        match workspace::prepare(&request.target) {
            Ok(token) => Some(token),
            Err(error) => {
                append(&mut log, format!("{error:#}\n").as_bytes());
                report(
                    &request,
                    log,
                    &format!(
                        "{target} could not prepare its workspace.",
                        target = request.target
                    ),
                );
                return Ok(1);
            }
        }
    } else {
        None
    };

    // Submission is deliberately outside the readiness retry loop. Even a timeout
    // can mean the remote application started, so never resubmit an ambiguous result.
    let (code, detail) = match application(&request, service) {
        Ok(output) => {
            record(&mut log, &output);
            let code = status(&output);
            let detail: String = String::from_utf8_lossy(&output.stderr)
                .chars()
                .filter(|character| !character.is_control())
                .take(512)
                .collect();
            let detail = if detail.is_empty() {
                format!("The application request ended with exit status {code}.")
            } else {
                detail
            };
            (code, detail)
        }
        Err(error) => {
            append(&mut log, format!("{error:#}\n").as_bytes());
            let detail = format!(
                "The launch could not be confirmed: {error:#}. The application may already be open."
            );
            (1, detail)
        }
    };
    if code != 0 {
        if let Some(token) = reservation
            && let Err(error) = workspace::cancel(token)
        {
            append(&mut log, format!("{error:#}\n").as_bytes());
        }

        report(&request, log, &detail);
    }

    Ok(code)
}

/// Start through normal readiness, then run menu synchronization with a bounded local identity.
pub(crate) fn sync_menus(target: airlock_nix_core::identity::GuestName) -> Result<u8> {
    let request = Request {
        label: "Applications".into(),
        target: target.clone(),
        service: None,
        workspace: false,
        readiness_timeout: 90,
    };
    let code = execute(request)?;
    if code != 0 {
        return Ok(code);
    }
    let output = support::run(
        Command::new(std::env::current_exe()?)
            .args(["menus", "sync", target.as_str(), "--force"])
            .env_remove("QREXEC_REMOTE_DOMAIN"),
        None,
        Duration::from_secs(90),
    )?;
    use std::io::Write;
    std::io::stdout().write_all(&output.stdout)?;
    std::io::stderr().write_all(&output.stderr)?;
    Ok(status(&output))
}
