//! Narrow desktop integration entry points installed inside application VMs.

#![forbid(unsafe_code)]
mod catalog;

mod desktop;

mod clipboard;

mod diagnostics;

mod input;

mod boot_health;

mod configuration;

mod runtime;

mod worker;

mod nix;

use airlock_machine_core::services::CaptureReceiverConfig;
use airlock_vm_service::capture::{self, Kind};
use anyhow::{Result, ensure};
use clap::{Parser, Subcommand};
use std::io::{self, Write};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about)]
struct Args {
    // One operation available within this VM's existing user permissions.
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Share desktop clipboard representations through the configured Hermit service.
    Clipboard(clipboard::Args),
    /// Observe boot-critical graphical or worker services without starting them.
    BootHealth(boot_health::Request),
    /// Collect best-effort evidence after a local VM service failure.
    Diagnostics(diagnostics::Request),
    /// Run native graphical-session and development-terminal adapters.
    Desktop(desktop::Request),
    /// Observe input-device and handler readiness through the dom0-only input RPC.
    InputReceiverReady(input::Request),
    /// Keep the guest startup console visible until forwarded typing input is usable.
    WaitInputLogin(input::LoginWait),
    /// Wait for this graphical user's session through the sys-gui-only readiness RPC.
    SessionReady {
        // Complete readiness budget, shared by user-manager and display probes.
        #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..=60))]
        timeout: u64,
    },
    /// Import or build committed machine source inside the existing private worker store.
    Worker(worker::Request),
    /// Run the selected upstream Nix with the installed private-store policy.
    Nix(nix::Request),
    /// Run role-installed local Qubes setup and diagnostic commands.
    Runtime(runtime::Request),
    /// Run local configuration-role protocols under the existing VM permissions.
    Configuration(configuration::Request),
    /// Observe local GPU inventory and API initialization without assigning devices.
    GpuProbe {
        // Fail if Vulkan cannot enumerate an integrated or discrete hardware GPU.
        #[arg(long)]
        require_hardware: bool,
    },
    /// Publish the complete active-profile application catalog in Qubes format.
    Catalog,
    /// Locate an icon in active XDG themes without decoding another VM's image.
    Icon {
        // Icon name or existing absolute filename supplied to the upstream image service.
        name: String,
        // Requested display size used for theme selection.
        size: u16,
    },
    /// Import one completed capture from a configured, policy-authorized caller.
    CaptureReceive {
        // Media category fixed by the Qubes RPC argument.
        kind: Kind,
        // Installed receiver contract listing the permitted Qubes callers.
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Open a previously imported capture selected by its receipt identity.
    CaptureOpen {
        // Media category fixed by the Qubes RPC argument.
        kind: Kind,
        // Installed receiver contract listing the permitted Qubes callers.
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

/// Requires an authenticated Qubes caller allowed by the installed receiver contract.
/// Configured files fail closed on read or decoding errors; calls without a file use sys-gui.
fn authorize_capture(path: Option<&std::path::Path>) -> Result<()> {
    let config: CaptureReceiverConfig = match path {
        Some(path) => airlock_nix_core::state::parse_json(&std::fs::read(path)?, path)?,
        None => CaptureReceiverConfig {
            sources: vec!["sys-gui".parse()?],
        },
    };
    let caller = std::env::var("QREXEC_REMOTE_DOMAIN")?;
    ensure!(
        config.permits(&caller),
        "capture caller is not authorized: {caller}"
    );
    Ok(())
}

fn run(args: Args) -> Result<()> {
    match args.command {
        Action::Clipboard(args) => clipboard::run(args)?,
        Action::BootHealth(request) => boot_health::execute(request)?,
        Action::Diagnostics(request) => diagnostics::execute(request),
        Action::Desktop(request) => desktop::execute(request)?,
        Action::InputReceiverReady(request) => input::ready(request)?,
        Action::WaitInputLogin(request) => input::wait_login(request)?,
        Action::SessionReady { timeout } => {
            ensure!(
                std::env::var("QREXEC_REMOTE_DOMAIN").as_deref() == Ok("sys-gui"),
                "airlock.AppSessionReady is restricted to sys-gui"
            );
            ensure!(
                std::env::var_os("QREXEC_SERVICE_ARGUMENT").is_none_or(|value| value.is_empty()),
                "airlock.AppSessionReady does not accept arguments"
            );

            let address = std::env::var("DBUS_SESSION_BUS_ADDRESS").ok();
            airlock_vm_service::session::environment(
                std::time::Duration::from_secs(timeout),
                address.as_deref(),
            )
            .map_err(|error| {
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|error| error.kind() == io::ErrorKind::TimedOut)
                {
                    error.context(HelperExit { code: 124 })
                } else {
                    error
                }
            })?;
        }
        Action::Worker(request) => worker::execute(request)?,
        Action::Nix(request) => nix::execute(request)?,
        Action::Runtime(request) => runtime::execute(request)?,
        Action::Configuration(request) => configuration::execute(request)?,
        Action::GpuProbe { require_hardware } => {
            airlock_vm_service::gpu::inspect(require_hardware)?
        }
        Action::Catalog => io::stdout()
            .lock()
            .write_all(catalog::execute()?.as_bytes())?,
        Action::Icon { name, size } => {
            ensure!(size > 0, "icon size must be positive");
            let mut themes = vec![
                "Adwaita".to_owned(),
                "hicolor".into(),
                "gnome".into(),
                "oxygen".into(),
            ];
            let home =
                std::env::var_os("HOME").ok_or_else(|| anyhow::anyhow!("HOME is not set"))?;
            let mut roots = vec![
                std::env::var_os("XDG_DATA_HOME")
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(|| std::path::PathBuf::from(home).join(".local/share")),
            ];
            roots.extend(std::env::split_paths(
                &std::env::var_os("XDG_DATA_DIRS").unwrap_or_default(),
            ));
            for root in roots {
                if let Ok(entries) = std::fs::read_dir(root.join("icons")) {
                    let mut names = entries
                        .filter_map(Result::ok)
                        .filter(|e| e.path().is_dir())
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect::<Vec<_>>();
                    names.sort();
                    themes.extend(names);
                }
            }
            for theme in themes {
                if let Some(path) = freedesktop_icons::lookup(&name)
                    .with_size(size)
                    .with_theme(&theme)
                    .find()
                {
                    println!("{}", path.display());
                    return Ok(());
                }
            }
            anyhow::bail!("icon was not found")
        }
        Action::CaptureReceive { kind, config } => {
            authorize_capture(config.as_deref())?;
            let receipt = capture::receive(kind, &mut io::stdin().lock())?;
            println!("{}", serde_json::to_string(&receipt)?);
        }
        Action::CaptureOpen { kind, config } => {
            authorize_capture(config.as_deref())?;
            capture::open_received(kind, &mut io::stdin().lock())?;
        }
    }
    Ok(())
}

/// A helper or timeout exit status retained by a compatibility command.
#[derive(Debug)]
struct HelperExit {
    /// Exact nonzero exit code returned by the requested helper.
    code: u8,
}

impl std::fmt::Display for HelperExit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "upstream helper exited with {code}",
            code = self.code
        )
    }
}

impl std::error::Error for HelperExit {}

fn main() -> std::process::ExitCode {
    match run(Args::parse()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("airlock-vm-service: {error:#}");
            error
                .downcast_ref::<HelperExit>()
                .map(|error| std::process::ExitCode::from(error.code))
                .unwrap_or(std::process::ExitCode::FAILURE)
        }
    }
}
