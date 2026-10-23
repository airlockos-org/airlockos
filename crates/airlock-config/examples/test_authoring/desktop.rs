//! Rust-authored fixtures evaluated by the native integration suite.

use super::*;

/// Describe the desktop evaluation boundary using caller-supplied source trees.
pub(super) fn expression() -> NixValue {
    NixValue::function_attrs(["lib", "configuration"], |arguments_1| {
        (
            Vec::<(&str, NixValue)>::new(),
            arguments_1
                .clone()
                .select("configuration")
                .clone()
                .select_segments(["config"])
                .bind(|cfg| desktop_expression_4(cfg, arguments_1.clone())),
        )
    })
}

/// Build the desktop expression contribution using the caller supplied deferred values.
fn desktop_expression_body(package: NixValue) -> NixValue {
    {
        let field_value = NixValue::record([
            ("drv", package.clone().select_segments(["drvPath"])),
            (
                "installPhase",
                package.clone().select_segments(["installPhase"]),
            ),
            (
                "source",
                NixValue::builtin("toString").call(package.clone().select_segments(["src"])),
            ),
            (
                "identityReader",
                package
                    .clone()
                    .attr_or(
                        "identityReader",
                        NixValue::record(Vec::<(&str, NixValue)>::new()),
                    )
                    .attr_or("text", NixValue::null()),
            ),
            (
                "hostPoweroff",
                package
                    .clone()
                    .attr_or(
                        "hostPoweroff",
                        NixValue::record(Vec::<(&str, NixValue)>::new()),
                    )
                    .attr_or("text", NixValue::null()),
            ),
        ]);

        NixValue::record([
            ("name", package.clone().select_segments(["pname"])),
            ("value", field_value),
        ])
    }
}

/// Build the desktop expression contribution using the caller supplied deferred values.
fn desktop_expression_2(
    style: NixValue,
    arguments_1: NixValue,
    cfg: NixValue,
    extensions: NixValue,
    launcher: NixValue,
    startup: NixValue,
    watcher: NixValue,
) -> NixValue {
    {
        let field_session = NixValue::record([
            (
                "default",
                cfg.clone()
                    .select_segments(["services", "displayManager", "defaultSession"]),
            ),
            (
                "gnome",
                cfg.clone()
                    .select_segments(["services", "desktopManager", "gnome", "enable"]),
            ),
            (
                "gdm",
                cfg.clone()
                    .select_segments(["services", "displayManager", "gdm", "enable"]),
            ),
            (
                "autoSuspend",
                cfg.clone()
                    .select_segments(["services", "displayManager", "gdm", "autoSuspend"]),
            ),
            (
                "coreApps",
                cfg.clone()
                    .select_segments(["services", "gnome", "core-apps", "enable"]),
            ),
            (
                "defaultApplication",
                cfg.clone()
                    .select_segments(["airlock", "sysGuiGuest", "defaultApplicationVM"]),
            ),
            (
                "xfce",
                cfg.clone()
                    .select_segments(["airlock", "sysGuiGuest", "enableXfce"]),
            ),
        ]);

        let field_disabled_services = NixValue::record([
            (
                "networkManager",
                cfg.clone()
                    .select_segments(["networking", "networkmanager", "enable"]),
            ),
            (
                "bluetooth",
                cfg.clone()
                    .select_segments(["hardware", "bluetooth", "enable"]),
            ),
            (
                "avahi",
                cfg.clone().select_segments(["services", "avahi", "enable"]),
            ),
            (
                "initialSetup",
                cfg.clone()
                    .select_segments(["services", "gnome", "gnome-initial-setup", "enable"]),
            ),
            (
                "remoteDesktop",
                cfg.clone().select_segments([
                    "services",
                    "gnome",
                    "gnome-remote-desktop",
                    "enable",
                ]),
            ),
            (
                "userShare",
                cfg.clone()
                    .select_segments(["services", "gnome", "gnome-user-share", "enable"]),
            ),
            (
                "rygel",
                cfg.clone()
                    .select_segments(["services", "gnome", "rygel", "enable"]),
            ),
        ]);

        let field_startup = arguments_1
            .clone()
            .select("lib")
            .clone()
            .select_segments(["mapAttrs"])
            .call(NixValue::function(|_| {
                NixValue::function(|entry| entry.clone().select_segments(["text"]))
            }))
            .call(startup.clone());

        let field_watcher = NixValue::record([
            (
                "description",
                watcher.clone().select_segments(["description"]),
            ),
            ("wantedBy", watcher.clone().select_segments(["wantedBy"])),
            ("after", watcher.clone().select_segments(["after"])),
            ("partOf", watcher.clone().select_segments(["partOf"])),
            (
                "unitConfig",
                watcher.clone().select_segments(["unitConfig"]),
            ),
            (
                "serviceConfig",
                watcher.clone().select_segments(["serviceConfig"]),
            ),
            (
                "path",
                NixValue::builtin("map")
                    .call(NixValue::builtin("toString"))
                    .call(watcher.clone().select_segments(["path"])),
            ),
        ]);

        let field_style = NixValue::record([
            (
                "description",
                style.clone().select_segments(["description"]),
            ),
            ("wantedBy", style.clone().select_segments(["wantedBy"])),
            ("after", style.clone().select_segments(["after"])),
            ("requires", style.clone().select_segments(["requires"])),
            ("before", style.clone().select_segments(["before"])),
            (
                "serviceConfig",
                style.clone().select_segments(["serviceConfig"]),
            ),
            ("script", style.clone().select_segments(["script"])),
        ]);

        let field_gui_daemon = NixValue::record([
            (
                "drv",
                arguments_1
                    .clone()
                    .select("configuration")
                    .clone()
                    .select_segments(["pkgs", "qubes-gui-daemon", "drvPath"]),
            ),
            (
                "patches",
                NixValue::builtin("map")
                    .call(NixValue::builtin("toString"))
                    .call(
                        arguments_1
                            .clone()
                            .select("configuration")
                            .clone()
                            .select_segments(["pkgs", "qubes-gui-daemon", "patches"]),
                    ),
            ),
            (
                "postInstall",
                arguments_1
                    .clone()
                    .select("configuration")
                    .clone()
                    .select_segments(["pkgs", "qubes-gui-daemon", "postInstall"]),
            ),
        ]);

        NixValue::record([
            ("session", field_session),
            ("disabledServices", field_disabled_services),
            (
                "extensions",
                NixValue::builtin("listToAttrs").call(
                    NixValue::builtin("map")
                        .call(NixValue::function(|package| {
                            desktop_expression_body(package)
                        }))
                        .call(extensions.clone()),
                ),
            ),
            (
                "gsettings",
                cfg.clone().select_segments([
                    "services",
                    "desktopManager",
                    "gnome",
                    "extraGSettingsOverrides",
                ]),
            ),
            (
                "schemaPackages",
                NixValue::builtin("map")
                    .call(NixValue::builtin("toString"))
                    .call(cfg.clone().select_segments([
                        "services",
                        "desktopManager",
                        "gnome",
                        "extraGSettingsOverridePackages",
                    ])),
            ),
            ("startup", field_startup),
            (
                "identities",
                NixValue::builtin("listToAttrs").call(
                    NixValue::builtin("map")
                        .call(NixValue::function(|package| {
                            rusix::nix_record! {
                                "name": package.clone().select("name"),
                                "value": package.select("text"),
                            }
                        }))
                        .call(
                            NixValue::builtin("filter")
                                .call(NixValue::function(|package| {
                                    NixValue::builtin("elem")
                                        .call(package.attr_or("name", ""))
                                        .call(NixValue::list([
                                            "org.airlockos.Setup.desktop".into(),
                                            "org.airlockos.Desktop.desktop".into(),
                                            "org.airlock.ctrl.desktop".into(),
                                        ]))
                                }))
                                .call(
                                    cfg.clone()
                                        .select_segments(["environment", "systemPackages"]),
                                ),
                        ),
                ),
            ),
            ("watcher", field_watcher),
            ("style", field_style),
            (
                "launcher",
                launcher.clone().select_segments(["airlockCommand"]),
            ),
            ("guiDaemon", field_gui_daemon),
            (
                "packages",
                NixValue::builtin("map")
                    .call(NixValue::builtin("toString"))
                    .call(
                        cfg.clone()
                            .select_segments(["environment", "systemPackages"]),
                    ),
            ),
            (
                "excludedPackages",
                NixValue::builtin("map")
                    .call(NixValue::builtin("toString"))
                    .call(
                        cfg.clone()
                            .select_segments(["environment", "gnome", "excludePackages"]),
                    ),
            ),
            (
                "system",
                cfg.clone()
                    .select_segments(["system", "build", "toplevel", "drvPath"]),
            ),
        ])
    }
}

/// Build the desktop expression contribution using the caller supplied deferred values.
fn desktop_expression_3(
    startup: NixValue,
    arguments_1: NixValue,
    cfg: NixValue,
    extensions: NixValue,
) -> NixValue {
    arguments_1
        .clone()
        .select("lib")
        .clone()
        .select_segments(["findFirst"])
        .call(NixValue::function(|package| {
            package
                .clone()
                .attr_or("name", NixValue::from(""))
                .equals(NixValue::from("airlock-launch-qube-app"))
        }))
        .call(NixValue::builtin("throw").call(NixValue::from("missing VM application launcher")))
        .call(
            cfg.clone()
                .select_segments(["environment", "systemPackages"]),
        )
        .bind(|launcher| {
            cfg.clone()
                .select_segments(["systemd", "user", "services", "airlock-gui-daemons"])
                .bind(|watcher| {
                    cfg.clone()
                        .select_segments(["systemd", "services", "airlock-gui-style-default"])
                        .bind(|style| {
                            desktop_expression_2(
                                style,
                                arguments_1.clone(),
                                cfg.clone(),
                                extensions.clone(),
                                launcher.clone(),
                                startup.clone(),
                                watcher.clone(),
                            )
                        })
                })
        })
}

/// Build the desktop expression contribution using the caller supplied deferred values.
fn desktop_expression_4(cfg: NixValue, arguments_1: NixValue) -> NixValue {
    NixValue::builtin("filter")
        .call(NixValue::function(|package| {
            arguments_1
                .clone()
                .select("lib")
                .clone()
                .select_segments(["hasPrefix"])
                .call(NixValue::from("airlock-gnome-"))
                .call(package.clone().attr_or("pname", NixValue::from("")))
        }))
        .call(
            cfg.clone()
                .select_segments(["environment", "systemPackages"]),
        )
        .bind(|extensions| {
            arguments_1
                .clone()
                .select("lib")
                .clone()
                .select_segments(["filterAttrs"])
                .call(NixValue::function(|name| {
                    NixValue::function(|_| {
                        arguments_1
                            .clone()
                            .select("lib")
                            .clone()
                            .select_segments(["hasPrefix"])
                            .call(NixValue::from("xdg/autostart/"))
                            .call(name.clone())
                    })
                }))
                .call(cfg.clone().select_segments(["environment", "etc"]))
                .bind(|startup| {
                    desktop_expression_3(
                        startup,
                        arguments_1.clone(),
                        cfg.clone(),
                        extensions.clone(),
                    )
                })
        })
}
