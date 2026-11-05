//! Session lifetime and the fixed RPC entry point; machine composition owns routing and policy.

use super::Deployment;
use rusix::{
    installation::Application, interop::raw::NixValue, nix_record, nix_text, nixos::ModuleBody,
};

impl Deployment {
    /// Install the GNOME publisher and read-only preferences RPC, without granting a caller permission.
    ///
    /// Compose this once in the GUI VM. Qubes policy must run the RPC as the active
    /// desktop user and restrict it to the assigned GUI clients with no service
    /// argument. The launcher enters its sandbox before any guest I/O. It uses the
    /// same user's /run/user directory to find the feed, independent of D-Bus.
    /// Logout stops the writer; a crash or abrupt logout expires its last frame
    /// within five seconds. Existing exporters also expire after five minutes so
    /// reconnects pass through Qubes policy; immediate revocation needs lifecycle
    /// teardown in the machine integration, not just a policy-file update.
    pub fn desktop_preferences(&self) -> Application {
        // Boot preflight and the read-only /etc image need an executable store source.
        let exporter = self
            .pkgs
            .clone()
            .select("writeShellScript")
            .call("airlock-desktop-preferences-export")
            .call(nix_text!(
                r#"
                    exec {executable} preferences export "$@"
                "#,
                executable = self.executable(),
            ));

        self.installation().module(ModuleBody::new(nix_record! {
                "environment": nix_record! {
                    "etc": nix_record! {
                        "qubes-rpc/airlock.DesktopPreferences": nix_record! { "source": exporter },
                    },
                },
                "systemd": nix_record! {
                    "user": nix_record! {
                        "services": nix_record! {
                            "airlock-desktop-preferences": nix_record! {
                                "description": "Publish read-only GNOME desktop preferences",
                                "wantedBy": NixValue::list(["gnome-session.target".into()]),
                                "partOf": NixValue::list(["graphical-session.target".into()]),
                                "after": NixValue::list(["graphical-session-pre.target".into()]),
                                // Preserve GNOME's imported schema/override search path;
                                // explicitly load its ordinary writable dconf backend locally.
                                "environment": nix_record! {
                                    "GIO_EXTRA_MODULES": nix_text!("{dconf}/lib/gio/modules", dconf = self.pkgs.clone().select("dconf.lib")),
                                },
                                "unitConfig": nix_record! { "StartLimitIntervalSec": 0_i64 },
                                "serviceConfig": nix_record! {
                                    "ExecStart": nix_text!("{executable} preferences publish", executable = self.executable()),
                                    "Restart": "on-failure",
                                    "RestartSec": 1,
                                    "UMask": "0077",
                                    "NoNewPrivileges": true,
                                    "RestrictSUIDSGID": true,
                                    "KillMode": "control-group",
                                    "TimeoutStopSec": "15s",
                                },
                            },
                        },
                    },
                },
            }))
    }
}
