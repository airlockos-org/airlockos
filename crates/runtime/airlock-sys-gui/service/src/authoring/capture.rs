//! Hand completed GNOME screenshots and recordings to the GUI service for delivery to a VM.
//! Rusix declares the installation; GNOME callbacks start delivery, and an autostart entry
//! retries pending work at login.

use super::Deployment;
use crate::command::{
    CAPTURE_ENQUEUE, CAPTURE_OPEN, CAPTURE_SHOW, CaptureAction, DesktopCommand, SCREEN_CAPTURE,
};
use airlock_machine_core::services::CaptureSenderConfig;
use rusix::{
    installation::Application,
    interop::{NixAttrs, Overlay, Package, raw::NixValue},
    nix_record, nix_text,
    nixos::ModuleBody,
};

/// Destination configuration read by both capture callbacks and login retries.
const CONFIG_PATH: &str = "/etc/airlock/capture-sender.json";

impl Deployment {
    /// Declares delivery to the configured VM, GNOME capture callbacks and login retries.
    ///
    /// Use checked Rusix composition with the GUI VM's other applications to detect
    /// competing file and command declarations. The GNOME overlay follows ordinary
    /// NixOS merging, and the machine's Qubes policy must permit delivery to the destination.
    pub fn capture_sender(&self, config: &CaptureSenderConfig) -> Application {
        // The patch starts handoff only after the screenshot file or recording sink is closed.
        // Reject missing placeholders so upstream changes cannot silently leave callbacks unwired.
        let patch_substitutions = nix_text!(
            r#"
                substituteInPlace {screenshots} {screencasts} \
                  --replace-fail '@captureHelper@' '{helper}' \
                  --replace-fail '@captureCommand@' '{command}' \
                  --replace-fail '@captureEnqueue@' '{enqueue}' \
                  --replace-fail '@captureConfig@' '{config}'
                substituteInPlace {screenshots} \
                  --replace-fail '@captureOpen@' '{open}' \
                  --replace-fail '@captureShow@' '{show}'
            "#,
            screenshots = "js/ui/screenshot.js",
            screencasts = "js/dbusServices/screencast/screencastService.js",
            helper = self.executable(),
            command = SCREEN_CAPTURE,
            enqueue = CAPTURE_ENQUEUE,
            open = CAPTURE_OPEN,
            show = CAPTURE_SHOW,
            config = CONFIG_PATH,
        );

        let capture_patch = self
            .sources
            .file("patches/gnome-shell/0001-completed-capture-handoff.patch");
        let capture_overlay = Overlay::from_function(|_final, previous| {
            let gnome_shell: Package = previous.field("gnome-shell");
            let patched = gnome_shell.override_attrs(|old| {
                // Extend the upstream recipe so its existing fixes and setup still run.
                let patches = NixValue::concat_lists([
                    old.get_or("patches", NixValue::list([])),
                    NixValue::list([capture_patch]),
                ]);

                // Separate commands even when the upstream hook has no trailing newline.
                let post_patch = nix_text!(
                    r#"
                        {upstream}
                        {substitutions}
                    "#,
                    upstream = old.get_or("postPatch", ""),
                    substitutions = patch_substitutions,
                );

                NixAttrs::new([("patches", patches), ("postPatch", post_patch.into())])
            });

            NixAttrs::new([("gnome-shell", patched.into())])
        });

        // Reuse the callback destination when retrying deliveries at the next GNOME login.
        let retry_desktop_entry = nix_text!(
            r#"
                [Desktop Entry]
                Type=Application
                Name=Deliver pending screen captures
                Exec={command}
                OnlyShowIn=GNOME;
                NoDisplay=true
            "#,
            command = self.desktop_command(&DesktopCommand::ScreenCapture {
                config: Some(CONFIG_PATH.into()),
                action: CaptureAction::Retry { target: None },
            }),
        );

        let sender_config = serde_json::to_string(config).expect("capture identities serialize");

        self.installation()
            .etc_text(
                CONFIG_PATH
                    .strip_prefix("/etc/")
                    .expect("sender config is under /etc"),
                sender_config,
            )
            .etc_text(
                "xdg/autostart/airlock-capture-retry.desktop",
                retry_desktop_entry,
            )
            .module(ModuleBody::new(nix_record! {
                "nixpkgs": nix_record! { "overlays": NixValue::list([capture_overlay.into()]) },
            }))
    }
}
