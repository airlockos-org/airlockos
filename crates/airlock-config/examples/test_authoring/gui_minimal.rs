//! Rust-authored fixtures evaluated by the native integration suite.

use super::*;

/// Inspect evaluated configuration for test gui minimal topology and desktop.
pub(super) fn minimal_desktop(inputs: NixValue) -> NixValue {
    NixValue::builtin("getFlake")
        .call(NixValue::concat_text([inputs
            .clone()
            .select("root")
            .to_text()]))
        .bind(|flake| {
            flake
                .clone()
                .select_segments(["nixosConfigurations", "vm-gui-minimal", "config"])
                .bind(|image| {
                    flake
                        .clone()
                        .select_segments([
                            "nixosConfigurations",
                            "airlock-domain-sys-gui-minimal",
                            "config",
                        ])
                        .bind(|vm| gui_minimal_minimal_desktop_4(vm, flake.clone(), image.clone()))
                })
        })
}

/// Build the gui minimal test gui minimal topology and desktop contribution using the caller
/// supplied deferred values.
fn gui_minimal_minimal_desktop_body(c: NixValue) -> NixValue {
    {
        let field_before_start = NixValue::concat_lists([
            c.clone().select_segments([
                "systemd",
                "services",
                "airlock-machine-autostart",
                "serviceConfig",
                "ExecStartPre",
            ]),
            c.clone().select_segments([
                "systemd",
                "services",
                "airlock-setup-config-deferred",
                "serviceConfig",
                "ExecStartPre",
            ]),
        ]);

        NixValue::record([
            (
                "failure",
                c.clone().select_segments([
                    "systemd",
                    "services",
                    "airlock-machine-autostart",
                    "unitConfig",
                    "OnFailure",
                ]),
            ),
            ("beforeStart", field_before_start),
            (
                "shutdown",
                c.clone().select_segments([
                    "systemd",
                    "services",
                    "airlock-boot-shutdown-record",
                    "serviceConfig",
                    "ExecStart",
                ]),
            ),
            (
                "criticalFailure",
                c.clone().select_segments([
                    "systemd",
                    "services",
                    "airlock-start-gui-gpu",
                    "unitConfig",
                    "OnFailure",
                ]),
            ),
            (
                "retry",
                NixValue::builtin("toString").call(c.clone().select_segments([
                    "environment",
                    "etc",
                    "qubes-rpc/airlock.BootRetry",
                    "source",
                ])),
            ),
        ])
    }
}

/// Build the gui minimal test gui minimal topology and desktop contribution using the caller
/// supplied deferred values.
fn gui_minimal_minimal_desktop_2(
    gnome_host_poweroff_extension: NixValue,
    flake: NixValue,
    gnome: NixValue,
    vm: NixValue,
    image: NixValue,
    normal: NixValue,
    sys_gui_policy: NixValue,
) -> NixValue {
    {
        let field_supervised = flake
            .clone()
            .select_segments([
                "nixosConfigurations",
                "machine",
                "config",
                "specialisation",
                "usb-lab",
                "configuration",
            ])
            .bind(gui_minimal_minimal_desktop_body);

        let extension_source = NixValue::concat_text([
            gnome_host_poweroff_extension.clone().to_text(),
            "/share/gnome-shell/extensions/airlock-host-poweroff@airlock.local/extension.js".into(),
        ]);
        let field_gnome_host_poweroff_extension_source =
            NixValue::builtin("readFile").call(extension_source);

        NixValue::record([
            (
                "topology",
                image
                    .clone()
                    .select_segments(["airlock", "qubes", "topology"]),
            ),
            (
                "setup",
                image
                    .clone()
                    .select_segments(["airlock", "qubes", "setupConfigOnBoot"]),
            ),
            (
                "setupCommand",
                image.clone().select_segments([
                    "systemd",
                    "services",
                    "airlock-setup-config",
                    "serviceConfig",
                    "ExecStart",
                ]),
            ),
            (
                "networkStartup",
                image.clone().select_segments([
                    "airlock",
                    "qubes",
                    "startNetworkProvidersOnBoot",
                    "enable",
                ]),
            ),
            (
                "deferredStartup",
                image.clone().select_segments([
                    "airlock",
                    "qubes",
                    "deferredSetupConfigOnBoot",
                    "enable",
                ]),
            ),
            (
                "configBootstrap",
                image.clone().select_segments([
                    "airlock",
                    "qubes",
                    "configCurrentBootstrapOnBoot",
                    "enable",
                ]),
            ),
            (
                "configPolicy",
                image
                    .clone()
                    .select_segments(["airlock", "qubes", "configAccessPolicy", "enable"]),
            ),
            (
                "devMode",
                image
                    .clone()
                    .select_segments(["airlock", "image", "devMode", "enable"]),
            ),
            (
                "proxy",
                image
                    .clone()
                    .select_segments(["airlock", "dom0", "devModeNetworkProxy", "enable"]),
            ),
            (
                "session",
                image
                    .clone()
                    .select_segments(["services", "displayManager", "defaultSession"]),
            ),
            (
                "guestSession",
                vm.clone()
                    .select_segments(["services", "displayManager", "defaultSession"]),
            ),
            (
                "xfce",
                vm.clone().select_segments([
                    "services",
                    "xserver",
                    "desktopManager",
                    "xfce",
                    "enable",
                ]),
            ),
            (
                "defaultApplicationVM",
                vm.clone()
                    .select_segments(["airlock", "sysGuiGuest", "defaultApplicationVM"]),
            ),
            (
                "discovery",
                vm.clone().select_segments([
                    "airlock",
                    "sysGuiGuest",
                    "applicationMenus",
                    "enable",
                ]),
            ),
            (
                "normalDefaultApplicationVM",
                normal
                    .clone()
                    .select_segments(["airlock", "sysGuiGuest", "defaultApplicationVM"]),
            ),
            ("supervised", field_supervised),
            (
                "bootNotification",
                gnome.clone().select_segments([
                    "environment",
                    "etc",
                    "xdg/autostart/airlock-boot-notification.desktop",
                    "text",
                ]),
            ),
            (
                "setupAutostart",
                gnome
                    .clone()
                    .select_segments(["environment", "etc"])
                    .has_attr("xdg/autostart/org.airlockos.Setup.desktop"),
            ),
            (
                "gnomeOverrides",
                gnome.clone().select_segments([
                    "services",
                    "desktopManager",
                    "gnome",
                    "extraGSettingsOverrides",
                ]),
            ),
            (
                "gnomeHostPoweroffExtensionSource",
                field_gnome_host_poweroff_extension_source,
            ),
            (
                "gnomeHostPoweroffHelper",
                NixValue::builtin("readFile").call(
                    gnome_host_poweroff_extension
                        .clone()
                        .select_segments(["hostPoweroff"]),
                ),
            ),
            (
                "etc",
                NixValue::builtin("attrNames")
                    .call(vm.clone().select_segments(["environment", "etc"])),
            ),
            (
                "hostEtc",
                NixValue::builtin("attrNames")
                    .call(image.clone().select_segments(["environment", "etc"])),
            ),
            (
                "hostPoweroffService",
                native_contract(image.clone().select_segments([
                    "environment",
                    "etc",
                    "qubes-rpc/airlock.Dom0Poweroff",
                    "source",
                ])),
            ),
            (
                "hostPoweroffSudoRules",
                image
                    .clone()
                    .select_segments(["security", "sudo", "extraRules"]),
            ),
            (
                "hostPoweroffPolicy",
                NixValue::builtin("readFile").call(NixValue::concat_text([
                    sys_gui_policy.clone().to_text(),
                    NixValue::from("/etc/qubes/policy.d/50-airlock-sys-gui.policy"),
                ])),
            ),
        ])
    }
}

/// Build the gui minimal test gui minimal topology and desktop contribution using the caller
/// supplied deferred values.
fn gui_minimal_minimal_desktop_3(
    sys_gui_policy: NixValue,
    flake: NixValue,
    gnome: NixValue,
    vm: NixValue,
    image: NixValue,
    normal: NixValue,
) -> NixValue {
    NixValue::builtin("head")
        .call(
            NixValue::builtin("filter")
                .call(NixValue::function(|package| {
                    package
                        .clone()
                        .attr_or("pname", package.clone().select_segments(["name"]))
                        .equals(NixValue::from("airlock-gnome-host-poweroff-1"))
                        .or(package
                            .clone()
                            .attr_or("pname", NixValue::from(""))
                            .equals(NixValue::from("airlock-gnome-host-poweroff")))
                }))
                .call(
                    gnome
                        .clone()
                        .select_segments(["environment", "systemPackages"]),
                ),
        )
        .bind(|gnome_host_poweroff_extension| {
            gui_minimal_minimal_desktop_2(
                gnome_host_poweroff_extension,
                flake.clone(),
                gnome.clone(),
                vm.clone(),
                image.clone(),
                normal.clone(),
                sys_gui_policy.clone(),
            )
        })
}

/// Build the gui minimal test gui minimal topology and desktop contribution using the caller
/// supplied deferred values.
fn gui_minimal_minimal_desktop_4(vm: NixValue, flake: NixValue, image: NixValue) -> NixValue {
    flake
        .clone()
        .select_segments(["nixosConfigurations", "airlock-domain-sys-gui", "config"])
        .bind(|normal| {
            flake
                .clone()
                .select_segments([
                    "nixosConfigurations",
                    "airlock-domain-sys-gui-usb-lab",
                    "config",
                ])
                .bind(|gnome| {
                    NixValue::builtin("head")
                        .call(
                            NixValue::builtin("filter")
                                .call(NixValue::function(|package| {
                                    package
                                        .clone()
                                        .attr_or("pname", package.clone().select_segments(["name"]))
                                        .equals(NixValue::from("50-airlock-sys-gui.policy"))
                                }))
                                .call(image.clone().select_segments([
                                    "virtualisation",
                                    "qubes",
                                    "packages",
                                ])),
                        )
                        .bind(|sys_gui_policy| {
                            gui_minimal_minimal_desktop_3(
                                sys_gui_policy,
                                flake.clone(),
                                gnome.clone(),
                                vm.clone(),
                                image.clone(),
                                normal.clone(),
                            )
                        })
                })
        })
}
