//! Observe the graphical user's current session without trusting a stale qrexec display environment.

use crate::support;
use anyhow::{Context, Result};
use std::{
    collections::BTreeMap,
    fs, io,
    os::unix::fs::FileTypeExt,
    path::PathBuf,
    process::Command,
    thread,
    time::{Duration, Instant},
};

/// Return the budget still available to the complete readiness operation.
fn remaining(deadline: Instant) -> Result<Duration> {
    let budget = deadline.saturating_duration_since(Instant::now());
    if budget.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "graphical session did not become ready",
        )
        .into());
    }

    Ok(budget)
}

/// Wait for the user manager's display, the session bus, its startup marker, and a successful X probe.
///
/// Return only the display/runtime/bus environment and the manager's X authority when present.
/// `bus_address` preserves an address already supplied to qrexec; omission uses the runtime
/// directory's bus. Every probe and retry shares `timeout`; expiry is an [`io::ErrorKind::TimedOut`]
/// error. This observes local session state and does not start VMs or broaden RPC authority.
pub fn environment(
    timeout: Duration,
    bus_address: Option<&str>,
) -> Result<BTreeMap<String, String>> {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(format!(
                "/run/user/{uid}",
                uid = rustix::process::getuid().as_raw()
            ))
        });
    let bus = runtime.join("bus");
    let address = bus_address
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("unix:path={bus}", bus = bus.display()));
    let deadline = Instant::now()
        .checked_add(timeout)
        .context("session timeout is too large")?;

    loop {
        let environment = support::text(
            Command::new(support::tool("AIRLOCK_SYSTEMCTL", "systemctl"))
                .args(["--user", "show-environment"])
                .env("XDG_RUNTIME_DIR", &runtime)
                .env("DBUS_SESSION_BUS_ADDRESS", &address),
            remaining(deadline)?.min(Duration::from_secs(2)),
        );
        if let Ok(environment) = environment {
            let display = environment
                .lines()
                .find_map(|line| line.strip_prefix("DISPLAY="));
            if let Some(display) = display.filter(|display| !display.is_empty())
                && runtime.join("airlock-app-session-ready").exists()
                && fs::metadata(&bus).is_ok_and(|metadata| metadata.file_type().is_socket())
            {
                let mut variables = BTreeMap::from([
                    ("DISPLAY".to_owned(), display.to_owned()),
                    (
                        "XDG_RUNTIME_DIR".to_owned(),
                        runtime.to_string_lossy().into_owned(),
                    ),
                    ("DBUS_SESSION_BUS_ADDRESS".to_owned(), address.clone()),
                ]);
                if let Some(authority) = environment
                    .lines()
                    .find_map(|line| line.strip_prefix("XAUTHORITY="))
                {
                    variables.insert("XAUTHORITY".to_owned(), authority.to_owned());
                }

                if support::run(
                    Command::new(support::tool("AIRLOCK_XDPYINFO", "xdpyinfo"))
                        .arg("-display")
                        .arg(display)
                        .envs(&variables),
                    None,
                    remaining(deadline)?.min(Duration::from_secs(2)),
                )
                .is_ok_and(|output| output.status.success())
                {
                    return Ok(variables);
                }
            }
        }

        thread::sleep(remaining(deadline)?.min(Duration::from_millis(200)));
    }
}
