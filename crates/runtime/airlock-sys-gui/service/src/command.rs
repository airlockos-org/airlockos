//! Commands understood by the GUI executable and constructed by machine authors.

use airlock_machine_core::services::CaptureKind;
use airlock_nix_core::identity::GuestName;
use clap::Subcommand;
use std::path::PathBuf;

/// Installed executable name used by package metadata and command construction.
pub const EXECUTABLE: &str = "airlock-sys-gui-service";

/// Defines the root spellings once for both CLI parsers and installation contracts.
macro_rules! root_command_names {
    ($table:ident { $(#[doc = $doc:literal] $name:ident = $value:literal;)* }) => {
        $(
            #[doc = $doc]
            pub const $name: &str = $value;

        )*
        /// Root command names contributed by this part of the GUI executable.
        pub(crate) const $table: &[&str] = &[$($name),*];
    };
}

root_command_names! { RUNTIME_COMMAND_NAMES {
    /// Refresh application menus after an explicit VM start.
    SYNC_APPMENUS = "sync-appmenus";
    /// Launch an application through the selected VM's existing Qubes interface.
    LAUNCH = "launch";
    /// Run explicit local display diagnostics or recovery.
    GPU = "gpu";
    /// Maintain desktop application catalogs.
    MENUS = "menus";
    /// Reserve or cancel a desktop workspace.
    WORKSPACE = "workspace";
    /// Select the readiness RPC advertised by a VM.
    READINESS_SERVICE = "readiness-service";
    /// Request interactive enrollment when its VM and network path are ready.
    TAILSCALE_ENROLLMENT = "tailscale-enrollment";
} }

root_command_names! { DESKTOP_COMMAND_NAMES {
    /// Deliver completed screenshots and recordings to the configured personal VM.
    SCREEN_CAPTURE = "screen-capture";
    /// Apply a declarative desktop border style.
    GUI_STYLE = "gui-style";
    /// Read trusted X11 window identity for the extension adapter.
    WINDOW_IDENTITY = "window-identity";
    /// Display dom0 startup status in the desktop session.
    BOOT_NOTIFICATION = "boot-notification";
    /// Report boot checkpoints and local application publication without starting VMs.
    STARTUP_STATUS = "startup-status";
} }

/// Enumerates the executable's explicit roots, before parser-generated help.
/// Installation derives desktop roots from the parser and uses the runtime table
/// for other operations, so conflicts between those groups are checked too.
pub fn root_command_names() -> impl Iterator<Item = &'static str> {
    RUNTIME_COMMAND_NAMES
        .iter()
        .chain(DESKTOP_COMMAND_NAMES)
        .copied()
}

/// Validate the installed capture sender contract.
const CAPTURE_CHECK_CONFIG: &str = "check-config";

/// Queue a completed capture for delivery.
pub(crate) const CAPTURE_ENQUEUE: &str = "enqueue";

/// Retry pending capture deliveries.
const CAPTURE_RETRY: &str = "retry";

/// Open a previously delivered capture.
pub(crate) const CAPTURE_OPEN: &str = "open";

/// Reveal a previously delivered capture.
pub(crate) const CAPTURE_SHOW: &str = "show";

/// Desktop operations whose invocations are also authored in system configuration.
#[derive(Debug, PartialEq, Subcommand)]
pub enum DesktopCommand {
    /// Deliver GNOME captures and route their notification actions to a personal VM.
    #[command(name = SCREEN_CAPTURE)]
    ScreenCapture {
        /// Generation-provided sender contract; omission uses the CLI default.
        #[arg(long, global = true)]
        config: Option<PathBuf>,
        /// Sender operation; receiver operations belong to the personal VM service.
        #[command(subcommand)]
        action: CaptureAction,
    },
    /// Apply a declarative border-style request over existing administrator transport.
    #[command(name = GUI_STYLE)]
    GuiStyle {
        /// Restore the booted generation's default before GUI daemons start.
        #[arg(long)]
        boot: bool,
    },
    /// Read a bounded X11 window identity with GUI-daemon provenance verification.
    #[command(name = WINDOW_IDENTITY)]
    WindowIdentity {
        /// Trusted GUI daemon executable supplied by the installed generation.
        #[arg(long)]
        guid: PathBuf,
        /// X11 window identifier encoded as hexadecimal by the GNOME extension.
        xid: String,
    },
    /// Watch dom0 startup status and offer a retry notification when degraded.
    #[command(name = BOOT_NOTIFICATION)]
    BootNotification,
    /// Report boot checkpoints and local application publication without starting VMs.
    #[command(name = STARTUP_STATUS)]
    StartupStatus,
}

/// Operations accepted by the capture sender, shared by runtime parsing and authoring.
#[derive(Debug, PartialEq, Subcommand)]
pub enum CaptureAction {
    /// Validate and print sender configuration without contacting a VM or writing state.
    #[command(name = CAPTURE_CHECK_CONFIG)]
    CheckConfig,
    /// Queue a file only after GNOME has finished writing it.
    #[command(name = CAPTURE_ENQUEUE)]
    Enqueue {
        /// Capture format and corresponding GNOME source directory.
        kind: CaptureKind,
        /// Completed local file; symlinks and unrelated directories are rejected.
        filename: PathBuf,
        /// Policy-authorized personal VM receiving the bytes.
        #[arg(long)]
        target: Option<GuestName>,
    },
    /// Retry pending deliveries and backfill existing completed captures once.
    #[command(name = CAPTURE_RETRY)]
    Retry {
        /// Policy-authorized personal VM receiving the bytes.
        #[arg(long)]
        target: Option<GuestName>,
    },
    /// Open a previously delivered capture inside its receiving VM.
    #[command(name = CAPTURE_OPEN)]
    Open {
        /// Media category used to find the acknowledged delivery.
        kind: CaptureKind,
        /// Local source of a completed, previously queued capture.
        filename: PathBuf,
        /// VM in which the received capture should be opened.
        #[arg(long)]
        target: Option<GuestName>,
    },
    /// Reveal a previously delivered capture in the receiving VM's file manager.
    #[command(name = CAPTURE_SHOW)]
    Show {
        /// Media category used to find the acknowledged delivery.
        kind: CaptureKind,
        /// Local source of a completed, previously queued capture.
        filename: PathBuf,
        /// VM in which the received capture should be revealed.
        #[arg(long)]
        target: Option<GuestName>,
    },
}

impl DesktopCommand {
    /// Returns literal process arguments without shell quoting or starting a service.
    /// Paths retain their operating-system representation; authoring checks UTF-8 at its boundary.
    pub fn arguments(&self) -> Vec<std::ffi::OsString> {
        match self {
            Self::WindowIdentity { guid, xid } => vec![
                WINDOW_IDENTITY.into(),
                "--guid".into(),
                guid.as_os_str().to_owned(),
                xid.into(),
            ],
            Self::BootNotification => vec![BOOT_NOTIFICATION.into()],
            Self::StartupStatus => vec![STARTUP_STATUS.into()],
            Self::GuiStyle { boot } => {
                let mut args = vec![GUI_STYLE.into()];
                if *boot {
                    args.push("--boot".into());
                }

                args
            }
            Self::ScreenCapture { config, action } => {
                let mut args = vec![SCREEN_CAPTURE.into()];
                args.extend(action.arguments());
                if let Some(config) = config {
                    args.push("--config".into());
                    args.push(config.as_os_str().to_owned());
                }

                args
            }
        }
    }
}

impl CaptureAction {
    /// Encodes every sender operation, preserving paths as individual arguments.
    fn arguments(&self) -> Vec<std::ffi::OsString> {
        let (name, file, target) = match self {
            Self::CheckConfig => (CAPTURE_CHECK_CONFIG, None, None),
            Self::Retry { target } => (CAPTURE_RETRY, None, target.as_ref()),
            Self::Enqueue {
                kind,
                filename,
                target,
            } => (CAPTURE_ENQUEUE, Some((kind, filename)), target.as_ref()),
            Self::Open {
                kind,
                filename,
                target,
            } => (CAPTURE_OPEN, Some((kind, filename)), target.as_ref()),
            Self::Show {
                kind,
                filename,
                target,
            } => (CAPTURE_SHOW, Some((kind, filename)), target.as_ref()),
        };
        let mut args = vec![name.into()];
        if let Some((kind, filename)) = file {
            args.push(kind.as_str().into());
            args.push(filename.as_os_str().to_owned());
        }
        if let Some(target) = target {
            args.push("--target".into());
            args.push(target.as_str().into());
        }

        args
    }
}
