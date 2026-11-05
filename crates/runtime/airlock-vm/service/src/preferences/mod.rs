//! Follow a configured GUI domain without giving its payload control over routing or commands.
//! The guest owns local GSettings, a private xsettingsd instance and baseline restoration.

mod agent;
mod assets;
mod mapping;
mod settings;
mod state;
mod xsettings;

#[cfg(test)]
mod tests;

use anyhow::Result;
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Machine-owned subscription binding. Installing this file enables the readiness gate.
pub const CONFIG: &str = "/etc/airlock/desktop-preferences.json";

/// Ordinary graphical-user operations selected by the installed session unit.
#[derive(Args)]
pub struct Request {
    /// Machine-owned source binding; never selected by a remote snapshot.
    #[arg(long, global = true, default_value = CONFIG)]
    config: PathBuf,
    /// Agent lifetime or explicit restoration operation.
    #[command(subcommand)]
    action: Action,
}

/// Fixed operations; no arbitrary GSettings keys or qrexec services are accepted.
#[derive(Subcommand)]
enum Action {
    /// Subscribe and maintain managed settings for this graphical session.
    Run,
    /// Restore the saved baseline, including recovery after an agent crash.
    Restore,
}

/// Validated deployment configuration, distinct from untrusted remote preferences.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    /// Whether this session should manage desktop preferences at all.
    enabled: bool,
    /// GUI association declared by the machine, not by the publisher's payload.
    gui_domain: airlock_nix_core::identity::GuestName,
    /// Existing integer X11 rendering scale; preference text scaling stays separate.
    window_scale: u16,
}

impl Config {
    /// Load only bounded machine configuration and constrain integer display scaling.
    fn read(path: &Path) -> Result<Self> {
        let config: Self = state::read_json(path, 4096)?;
        anyhow::ensure!(
            (1..=4).contains(&config.window_scale),
            "invalid preference window scale"
        );
        Ok(config)
    }
}

/// Execute the session agent or restore its own managed fields without contacting another VM.
pub fn execute(request: Request) -> Result<()> {
    let paths = state::Paths::new()?;
    let _lock = paths.lock()?;
    match request.action {
        Action::Run => agent::run(&request.config, paths),
        Action::Restore => {
            paths.clear_status()?;
            let mut settings = settings::Settings::new()?;
            settings.restore_saved(&paths)
        }
    }
}

/// Gate normal application launch only when preferences are configured for this VM.
///
/// The agent's initial synchronization has a ten-second budget. A missing agent
/// or offline publisher yields an explicit degraded fallback within `timeout`,
/// rather than blocking launch indefinitely. Existing VMs without configuration
/// retain their previous readiness behavior.
pub fn readiness(runtime: &Path, timeout: std::time::Duration) -> Result<()> {
    readiness_for(Path::new(CONFIG), runtime, timeout)
}

/// Match readiness to the current source/scale binding, never a previous GUI domain.
fn readiness_for(config_path: &Path, runtime: &Path, timeout: std::time::Duration) -> Result<()> {
    if !config_path.exists() {
        return Ok(());
    }
    let config = Config::read(config_path)?;
    if !config.enabled {
        return Ok(());
    }
    let deadline = std::time::Instant::now() + timeout.min(std::time::Duration::from_secs(10));
    let path = runtime.join("airlock-desktop-preferences/status.json");
    loop {
        if let Ok(status) = state::read_json::<state::Status>(&path, 32768)
            && status.config.as_ref() == Some(&config)
            && status.ready
        {
            if status.phase != "applied" {
                eprintln!("desktop preferences: startup uses degraded fallback");
            }
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            eprintln!(
                "desktop preferences: initial synchronization unavailable; using local fallback"
            );
            return Ok(());
        }
        // This is a bounded launch-readiness wait, never a preference subscription.
        std::thread::sleep(
            std::time::Duration::from_millis(50)
                .min(deadline.saturating_duration_since(std::time::Instant::now())),
        );
    }
}
