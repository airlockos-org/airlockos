//! Configure GNOME login, extension activation and the GUI VM's service boundaries.

use super::{ModuleContext, extensions::Extension};
use rusix::{
    interop::raw::{NixRepresentation, NixValue},
    nix_record, nix_text,
};

/// Enables the GNOME session and keeps ordinary applications in the selected personal VM.
/// A standalone GUI retains local core applications; both forms install Airlock's extensions.
pub(super) fn configuration(
    inputs: &ModuleContext,
    service: &super::Deployment,
    extensions: &[Extension],
) -> NixValue {
    let force = |value: NixValue| inputs.lib.clone().select("mkForce").call(value);
    let enabled = extensions
        .iter()
        .map(|extension| format!("'{id}'", id = extension.id))
        .collect::<Vec<_>>()
        .join(",");
    let mut packages = vec![service.package().as_expression()];
    packages.extend(extensions.iter().map(|extension| extension.package.clone()));
    // Accessibility controls the GUI session itself, rather than an application VM.
    packages.push(inputs.pkgs.clone().select("gnome-tecla"));

    nix_record! {
        "assertions": NixValue::list([nix_record! {
            "assertion": inputs
                .config
                .clone()
                .select("services.desktopManager.gnome.enable")
                .and(
                    inputs
                        .config
                        .clone()
                        .select("services.displayManager.defaultSession")
                        .equals("gnome"),
                ),
            "message": "The GNOME component requires an enabled GNOME session.",
        }]),
        "airlock": nix_record! {
            "sysGuiGuest": nix_record! {
                "enableXfce": force(false.into()),
            },
        },
        "services": nix_record! {
            "displayManager": nix_record! {
                "defaultSession": force("gnome".into()),
                // GDM supplies GNOME's greeter and screen locking; wait awake for login.
                "gdm": nix_record! {
                    "enable": true,
                    "autoSuspend": false,
                },
            },
            "desktopManager": nix_record! {
                "gnome": nix_record! {
                    "enable": true,
                    // Only org.gnome.shell's schema is needed by these settings.
                    "extraGSettingsOverridePackages": NixValue::list([inputs.pkgs.clone().select("gnome-shell")]),
                    "extraGSettingsOverrides": nix_text!(
                        r#"
                        [org.gnome.shell]
                        enabled-extensions=[{enabled}]
                    "#,
                        enabled = enabled,
                    ),
                },
            },
            "gnome": nix_record! {
                "core-apps": nix_record! {
                    "enable": force(
                        inputs
                            .config
                            .clone()
                            .select("airlock.sysGuiGuest.defaultApplicationVM")
                            .equals(NixValue::null()),
                    ),
                },
                // The isolated GUI must not gain network-facing desktop services.
                "gnome-initial-setup": nix_record! {
                    "enable": force(false.into()),
                },
                "gnome-remote-desktop": nix_record! {
                    "enable": force(false.into()),
                },
                "gnome-user-share": nix_record! {
                    "enable": force(false.into()),
                },
                "rygel": nix_record! {
                    "enable": force(false.into()),
                },
            },
            "avahi": nix_record! {
                "enable": force(false.into()),
            },
        },
        "environment": nix_record! {
            "systemPackages": NixValue::list(packages),
            // First-login tours are disabled while the welcome flow is being revised.
            "gnome": nix_record! {
                "excludePackages": NixValue::list([inputs.pkgs.clone().select("gnome-tour")]),
            },
        },
        "networking": nix_record! {
            "networkmanager": nix_record! {
                "enable": force(false.into()),
            },
        },
        "hardware": nix_record! {
            "bluetooth": nix_record! {
                "enable": force(false.into()),
            },
        },
    }
}
