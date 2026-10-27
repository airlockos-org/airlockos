//! Desktop integration entry point for sys-gui, using existing Qubes control and session APIs.

#![forbid(unsafe_code)]
mod captures;

mod gpu;

mod identity;

mod launch;

mod menus;

mod notifications;

mod startup;

mod enrollment;

mod qubes;

mod style;

mod workspace;

use airlock_sys_gui_service::command::{self, DesktopCommand};
use anyhow::Result;
use clap::{Parser, Subcommand};
use std::process::ExitCode;

#[derive(Parser)]
#[command(version, about)]
struct Args {
    // Desktop operation selected by a local session unit or restricted Qubes RPC wrapper.
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Explicitly start one VM and refresh its application menu.
    #[command(name = command::SYNC_APPMENUS)]
    SyncAppmenus {
        /// Validated VM selected by the user.
        name: airlock_nix_core::identity::GuestName,
    },
    /// Wait for an explicitly selected VM session and submit its application RPC once.
    #[command(name = command::LAUNCH)]
    Launch(launch::Request),
    /// Capture or explicitly recover the display GPU owned by this VM.
    #[command(name = command::GPU)]
    Gpu(gpu::Request),
    /// Maintain Qubes application menus without background VM starts.
    #[command(name = command::MENUS)]
    Menus {
        // Inventory reconciliation or one explicitly scoped catalog refresh.
        #[command(subcommand)]
        action: menus::Action,
    },
    /// Desktop operations shared with the configuration authoring API.
    #[command(flatten)]
    Desktop(DesktopCommand),
    /// Reserve or cancel a desktop workspace for an application launch.
    #[command(name = command::WORKSPACE)]
    Workspace {
        // Fixed session-bus workspace operation.
        #[command(subcommand)]
        action: workspace::Action,
    },
    /// Select the existing readiness RPC appropriate to this VM's advertised capabilities.
    #[command(name = command::READINESS_SERVICE)]
    ReadinessService {
        // Qubes VM whose supported RPC feature should be queried.
        name: airlock_nix_core::identity::GuestName,
    },
    /// Wait for the network path and usr-assistant before requesting Tailscale enrollment.
    #[command(name = command::TAILSCALE_ENROLLMENT)]
    TailscaleEnrollment {
        /// Maximum time to wait for the required VM readiness reports, in seconds.
        #[arg(long, default_value_t = 600, value_parser = clap::value_parser!(u64).range(1..=900))]
        startup_timeout: u64,
    },
}

fn run(args: Args) -> Result<ExitCode> {
    match args.command {
        Action::SyncAppmenus { name } => return launch::sync_menus(name).map(ExitCode::from),
        Action::TailscaleEnrollment { startup_timeout } => {
            return enrollment::execute(startup_timeout).map(ExitCode::from);
        }
        Action::Launch(request) => return launch::execute(request).map(ExitCode::from),
        Action::Gpu(request) => gpu::execute(request),
        Action::Menus { action } => menus::execute(action),
        Action::Desktop(DesktopCommand::ScreenCapture { config, action }) => {
            captures::execute(action, config.as_deref())
        }
        Action::Workspace { action } => workspace::execute(action),
        Action::Desktop(DesktopCommand::WindowIdentity { guid, xid }) => {
            identity::execute(&xid, guid)
        }
        Action::Desktop(DesktopCommand::GuiStyle { boot }) => style::execute(boot),
        Action::Desktop(DesktopCommand::BootNotification) => notifications::execute(),
        Action::Desktop(DesktopCommand::StartupStatus) => startup::panel_status(),
        Action::ReadinessService { name } => {
            let supported = qubes::readiness(&name, std::time::Duration::from_secs(15))?;
            let service = if supported {
                "airlock.AppSessionReady"
            } else {
                "qubes.WaitForSession"
            };
            println!("{service}");
            Ok(())
        }
    }?;
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(status) => status,
        Err(error) => {
            eprintln!("airlock-sys-gui-service: {error:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Action, Args};
    use airlock_sys_gui_service::command::DesktopCommand;

    /// Runtime root operations use exactly the names collected by installation authoring.
    #[test]
    fn installation_root_names_match_the_production_parser() {
        use airlock_sys_gui_service::command::root_command_names;
        use clap::CommandFactory;

        let parser = Args::command();
        let mut actual = parser
            .get_subcommands()
            .map(|child| child.get_name())
            .collect::<Vec<_>>();
        let mut declared = root_command_names().collect::<Vec<_>>();
        actual.sort_unstable();
        declared.sort_unstable();
        assert_eq!(actual, declared);
        parser.debug_assert();
    }

    /// Authored commands round-trip through the production parser with literal argument boundaries.
    #[test]
    fn authored_commands_round_trip_through_the_root_parser() {
        use airlock_machine_core::services::CaptureKind;
        use airlock_sys_gui_service::command::CaptureAction;
        use clap::Parser;

        let target = Some("usr-home".parse().unwrap());
        let filename = "/tmp/a 'quoted' $file; %name.png".into();
        let capture_actions = [
            CaptureAction::CheckConfig,
            CaptureAction::Retry { target: None },
            CaptureAction::Retry {
                target: target.clone(),
            },
            CaptureAction::Enqueue {
                kind: CaptureKind::Image,
                filename,
                target: target.clone(),
            },
            CaptureAction::Open {
                kind: CaptureKind::Video,
                filename: "/tmp/screen.webm".into(),
                target: None,
            },
            CaptureAction::Show {
                kind: CaptureKind::Image,
                filename: "/tmp/screen.png".into(),
                target,
            },
        ];
        let commands = [
            DesktopCommand::WindowIdentity {
                guid: "/tmp/a daemon/bin/qubes-guid".into(),
                xid: "0x1234".into(),
            },
            DesktopCommand::BootNotification,
            DesktopCommand::StartupStatus,
            DesktopCommand::GuiStyle { boot: true },
            DesktopCommand::GuiStyle { boot: false },
        ]
        .into_iter()
        .chain(
            capture_actions
                .into_iter()
                .map(|action| DesktopCommand::ScreenCapture {
                    config: Some("/tmp/a 'quoted' $config; %name.json".into()),
                    action,
                }),
        );
        for command in commands {
            let args = command.arguments();
            let parsed =
                Args::try_parse_from(std::iter::once("service".into()).chain(args.clone()))
                    .unwrap();
            let Action::Desktop(parsed) = parsed.command else {
                panic!("authored desktop command selected a different root operation");
            };
            assert_eq!(command, parsed);
        }
    }
}
