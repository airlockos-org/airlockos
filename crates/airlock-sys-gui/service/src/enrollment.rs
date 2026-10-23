//! Keep enrollment interactive while explaining startup delays and Qubes transport failures.

use crate::{launch, startup};
use airlock_vm_service::support;
use anyhow::{Result, bail};
use std::{
    thread,
    time::{Duration, Instant},
};

/// The enrollment RPC needs its destination and the declared network path, not every app VM.
const ENROLLMENT_GUESTS: [&str; 3] = ["sys-net", "sys-firewall", "usr-assistant"];

/// Require positive per-guest readiness before sending the request through qrexec.
fn ready_for_enrollment(state: &startup::Status) -> bool {
    state.desktop_ready
        && ENROLLMENT_GUESTS.iter().all(|name| {
            state
                .guests
                .iter()
                .any(|guest| guest.name.as_str() == *name && guest.phase == "ready")
        })
}

/// Report bootstrap failures without opening a local GUI-domain terminal.
pub(crate) fn execute(timeout: u64) -> Result<u8> {
    let result = open(timeout);
    if let Err(error) = &result {
        let _ = support::run(
            crate::notifications::command().args([
                "--",
                "Tailscale could not be opened",
                &format!("{error:#}"),
            ]),
            None,
            Duration::from_secs(5),
        );
    }

    result
}

/// Wait for read-only startup evidence, then launch the assistant's application once.
fn open(timeout: u64) -> Result<u8> {
    let deadline = Instant::now() + Duration::from_secs(timeout);
    let mut previous = String::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!(
                "Network and usr-assistant were not ready within {timeout} seconds. Tailscale enrollment was not requested; retry after those services are ready."
            );
        }

        let message = match startup::read(remaining.min(Duration::from_secs(15))) {
            Ok(state)
                if matches!(state.status.as_str(), "working" | "complete" | "degraded")
                    && ready_for_enrollment(&state) =>
            {
                break;
            }
            Ok(state) if state.status == "working" => format!(
                "Waiting for network and usr-assistant: {progress}",
                progress = state.progress()
            ),
            Ok(state) => bail!(
                "Startup is {status}: {progress}. Tailscale enrollment was not requested. Resolve the startup failure and retry.",
                status = state.status,
                progress = state.progress()
            ),
            Err(error) => format!(
                "Waiting for startup status; the Qubes control service is unavailable: {error:#}"
            ),
        };
        if message != previous {
            println!("{message}");
            if previous.is_empty() {
                let _ = support::run(
                    crate::notifications::command().args([
                        "--",
                        "Preparing Tailscale",
                        "Waiting for the network and usr-assistant. The connection window will open in usr-assistant when ready.",
                    ]),
                    None,
                    Duration::from_secs(5),
                );
            }
            previous = message;
        }
        thread::sleep(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(2)),
        );
    }

    println!("Network and usr-assistant are ready. Opening Tailscale in usr-assistant...");
    // The normal launch path owns session readiness, trusted VM identity and workspace rollback.
    // Application lifetime is unbounded; enrollment itself retains its own two-minute timeout.
    let code = launch::execute(launch::Request {
        label: "usr-assistant: Connect Tailscale".into(),
        target: "usr-assistant".parse()?,
        service: Some("qubes.StartApp+airlock-tailscale".into()),
        workspace: true,
        readiness_timeout: 90,
    })?;
    match code {
        0 => {}
        124 => eprintln!(
            "The assistant's graphical session did not become ready; enrollment was not requested."
        ),
        126 => eprintln!(
            "Qubes could not complete the request. A refusal can mean a policy restriction or an interrupted control service; it does not establish that Tailscale rejected the login. Check the details above and retry after startup is stable."
        ),
        _ => eprintln!(
            "Enrollment failed (exit {code}). Check the route, DNS or HTTPS error above and the connection in sys-net/sys-firewall before retrying."
        ),
    }
    Ok(code)
}
