//! Supply local toolkit services and bind their subscriber to the Qubes graphical-session lifetime.

use airlock_build::{Application, Workspace};
use rusix::{
    interop::{
        NixPath,
        raw::{NixRepresentation, NixValue},
    },
    nix_record, nix_text,
    nixos::{ContextualModule, ModuleBody},
};

/// Install desktop adapters once in the common GUI component; a null source disables subscription.
pub(super) fn module() -> NixValue {
    ContextualModule::new(|context| {
        let pkgs = &context.pkgs;
        let package = |name| pkgs.clone().select(name);
        let source = context.config.clone().select("airlock.appGui.preferencesSource");
        let enabled = source.clone().equals(NixValue::null()).equals(false);
        let workspace = Workspace::new(NixPath::from_expression(package("airlockAppsSource")));
        let service = Application::VmService.build(pkgs, &workspace).as_expression();
        let executable = nix_text!("{service}/bin/airlock-vm-service", service = service.clone());
        let schema = nix_text!("{schemas}/share/gsettings-schemas/{name}", schemas = package("gsettings-desktop-schemas"), name = package("gsettings-desktop-schemas.name"));
        let config = NixValue::builtin("toJSON").call(nix_record! {
            "enabled": enabled.clone(),
            "gui_domain": source.clone(),
            "window_scale": context.config.clone().select("airlock.appGui.scale"),
        });
        let unit = nix_record! {
            "description": "Follow the assigned GUI VM's desktop preferences",
            "wantedBy": NixValue::list(["qubes-graphical-session.target".into()]),
            "partOf": NixValue::list(["qubes-graphical-session.target".into(), "graphical-session.target".into()]),
            // Reverse shutdown ordering keeps the bus alive for ExecStopPost's dconf restore.
            "after": NixValue::list(["graphical-session-pre.target".into(), "dbus.service".into()]),
            "path": NixValue::list([package("python3.pkgs.qubes-core-qrexec.domU")]),
            "environment": nix_record! {
                "GIO_EXTRA_MODULES": nix_text!("{dconf}/lib/gio/modules", dconf = package("dconf.lib")),
            },
            "unitConfig": nix_record! { "StartLimitIntervalSec": 0_i64 },
            "serviceConfig": nix_record! {
                "Type": "notify", "NotifyAccess": "main",
                "ExecStart": nix_text!("{executable} preferences run", executable = executable.clone()),
                "ExecStopPost": nix_text!("{executable} preferences restore", executable = executable),
                "Restart": "on-failure", "RestartSec": "2s",
                "TimeoutStartSec": "15s", "TimeoutStopSec": "15s",
                "KillMode": "control-group", "UMask": "0077",
                "NoNewPrivileges": true, "RestrictSUIDSGID": true,
            },
        };
        ModuleBody::new(nix_record! {
            "programs": nix_record! { "dconf": nix_record! { "enable": true } },
            "fonts": nix_record! { "packages": NixValue::list([package("adwaita-fonts")]) },
            "environment": nix_record! {
                "systemPackages": NixValue::list([service, package("gsettings-desktop-schemas"), package("adwaita-icon-theme")]),
                "sessionVariables": nix_record! { "XDG_DATA_DIRS": NixValue::list([schema.into()]) },
                "etc": context.lib.clone().select("mkIf").call(enabled.clone()).call(nix_record! {
                    "airlock/desktop-preferences.json": nix_record! { "text": config.clone(), "mode": "0444" },
                    // The guest has no GNOME Shell/Mutter. Prevent upstream's
                    // optional X-QUBES GNOME settings autostart from competing.
                    "xdg/autostart/org.gnome.SettingsDaemon.XSettings.desktop": nix_record! {
                        "text": nix_text!(r#"
                            [Desktop Entry]
                            Type=Application
                            Name=GNOME XSettings
                            Hidden=true
                        "#),
                    },
                }),
            },
            "xdg": nix_record! { "portal": nix_record! {
                "enable": true,
                "extraPortals": NixValue::list([package("xdg-desktop-portal-gtk")]),
                "config": nix_record! { "common": nix_record! { "default": NixValue::list(["gtk".into()]) } },
            } },
            "systemd": nix_record! { "user": nix_record! { "services": context.lib.clone().select("mkIf").call(enabled.clone()).call(nix_record! { "airlock-desktop-preferences": unit }) } },
            "assertions": NixValue::list([nix_record! {
                "assertion": NixValue::if_else(enabled, context.config.clone().select("environment.etc").select_segments(["airlock/desktop-preferences.json"]).select("text").equals(config), true),
                "message": "Desktop preferences routing must follow the declared GUI association.",
            }]),
        }).key("airlock.vm.desktop-preferences")
    }).into_expression()
}
