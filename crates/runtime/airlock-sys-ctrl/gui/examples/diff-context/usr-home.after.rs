//! Configure personal applications and desktop integration inside the home VM.

use airlock_config::rusix::{
    interop::raw::NixValue,
    nix_record,
    nixos::{ModuleBody, NixosModule},
};

/// Install the home VM's applications while leaving display ownership with the GUI VM.
pub fn personal() -> NixosModule {
    NixosModule::with_context(|context| {
        let applications = [
            "gnome-text-editor",
            "nautilus",
            "evince",
            "file-roller",
            "loupe",
            "firefox",
            "vlc",
        ];
        let packages = NixValue::list(applications.map(|name| context.pkgs.clone().select(name)));

        ModuleBody::new(nix_record! {
            "environment": nix_record! {
                "systemPackages": packages,
                "sessionVariables": nix_record! {
                    "EDITOR": "gnome-text-editor",
                    "VISUAL": "gnome-text-editor",
                    "GTK_USE_PORTAL": "1",
                },
                "pathsToLink": NixValue::list([
                    "/share/applications".into(),
                    "/share/icons".into(),
                    "/share/glib-2.0/schemas".into(),
                ]),
            },
            "xdg": nix_record! {
                "mime": nix_record! {
                    "enable": true,
                    "defaultApplications": nix_record! {
                        "application/pdf": desktop("org.gnome.Evince.desktop"),
                        "application/zip": desktop("org.gnome.FileRoller.desktop"),
                        "image/jpeg": desktop("org.gnome.Loupe.desktop"),
                        "image/png": desktop("org.gnome.Loupe.desktop"),
                        "text/plain": desktop("org.gnome.TextEditor.desktop"),
                        "video/mp4": desktop("vlc.desktop"),
                    },
                },
                "portal": nix_record! {
                    "enable": true,
                    "config": nix_record! {
                        "common": nix_record! { "default": "gtk" },
                    },
                    "extraPortals": NixValue::list([
                        context.pkgs.select("xdg-desktop-portal-gtk"),
                    ]),
                },
            },
            "services": nix_record! {
                "gvfs": nix_record! { "enable": true },
                "gnome": nix_record! {
                    "gnome-keyring": nix_record! { "enable": true },
                },
                "journald": nix_record! {
                    "settings": nix_record! {
                        "Journal": nix_record! {
                            "SystemMaxUse": "512M",
                            "RuntimeMaxUse": "64M",
                            "MaxRetentionSec": "7day",
                        },
                    },
                },
            },
        })
    })
}

/// Represent one desktop file as the MIME handler list expected by NixOS.
fn desktop(name: &str) -> NixValue {
    NixValue::list([name.into()])
}
