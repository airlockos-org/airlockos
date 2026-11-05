//! Install personal applications and their portals without running a second desktop shell.

use super::app_gui;
use rusix::{
    interop::raw::NixValue,
    nix_record,
    nixos::{ContextualModule, ModuleBody},
};

/// Supply the ordinary NixOS user environment, GNOME applications and software rendering.
pub(super) fn module() -> NixValue {
    ContextualModule::new(|context| {
        let packages = |names: &[&str]| {
            NixValue::list(names.iter().map(|name| context.pkgs.clone().select(name)))
        };
        let gnome = NixValue::record(
            [
                "core-apps",
                "at-spi2-core",
                "evolution-data-server",
                "glib-networking",
                "gnome-keyring",
                "gnome-online-accounts",
                "localsearch",
                "tinysparql",
            ]
            .map(|name| {
                (
                    name,
                    nix_record! {
                        "enable": true,
                    },
                )
            }),
        );
        let mime = NixValue::record(
            [
                ("x-scheme-handler/http", "org.gnome.Epiphany.desktop"),
                ("x-scheme-handler/https", "org.gnome.Epiphany.desktop"),
                ("text/html", "org.gnome.Epiphany.desktop"),
                ("application/xhtml+xml", "org.gnome.Epiphany.desktop"),
                ("image/png", "org.gnome.Loupe.desktop"),
                ("image/jpeg", "org.gnome.Loupe.desktop"),
                ("image/webp", "org.gnome.Loupe.desktop"),
                ("image/gif", "org.gnome.Loupe.desktop"),
                ("image/svg+xml", "org.gnome.Loupe.desktop"),
                ("application/pdf", "org.gnome.Papers.desktop"),
                ("text/plain", "org.gnome.TextEditor.desktop"),
                ("inode/directory", "org.gnome.Nautilus.desktop"),
            ]
            .map(|(mime, desktop)| (mime, desktop.into())),
        );

        ModuleBody::new(nix_record! {
            "system": nix_record! {
                "etc": nix_record! {
                    "overlay": nix_record! {
                        "enable": true,
                    },
                },
                "disableInstallerTools": true,
            },
            "services": nix_record! {
                "userborn": nix_record! {
                    "enable": true,
                },
                "gnome": gnome,
                "gvfs": nix_record! {
                    "enable": true,
                },
                "flatpak": nix_record! {
                    "enable": false,
                },
            },
            // Qubes supplies Xorg; WebKit still needs Mesa/EGL for software rendering.
            "hardware": nix_record! {
                "graphics": nix_record! {
                    "enable": true,
                },
            },
            "security": nix_record! {
                "pam": nix_record! {
                    "services": nix_record! {
                        "qubes-gui-agent": nix_record! {
                            "enableGnomeKeyring": true,
                        },
                    },
                },
            },
            "environment": nix_record! {
                "systemPackages": packages(&[
                    "glib",
                    "gtk3",
                    "glycin-thumbnailer",
                    "gst-thumbnailers",
                    "xdg-user-dirs",
                    "xdg-user-dirs-gtk",
                ]),
            },
            "xdg": nix_record! {
                "portal": nix_record! {
                    // Common GUI integration supplies the Settings portal. Personal
                    // applications additionally use this session's keyring backend.
                    "config": nix_record! {
                        "common": nix_record! {
                            "org.freedesktop.impl.portal.Secret": NixValue::list(["gnome-keyring".into()]),
                        },
                    },
                },
                "mime": nix_record! {
                    "defaultApplications": mime,
                },
            },
            // Application installation belongs to the declared machine configuration.
            "nix": nix_record! {
                "enable": false,
                "channel": nix_record! {
                    "enable": false,
                },
            },
        })
        .key("airlock.vm.personal")
        .import_value(app_gui::module())
    })
    .into_expression()
}
