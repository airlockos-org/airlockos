//! Rust-authored fixtures evaluated by the native integration suite.

use super::*;

/// Inspect evaluated configuration for test nix selection drives reservation assignment and start.
pub(super) fn gpu_selection(inputs: NixValue) -> NixValue {
    NixValue::builtin("getFlake")
        .call(NixValue::concat_text([inputs
            .clone()
            .select("root")
            .to_text()]))
        .bind(gui_gpu_assignment_gpu_selection_5)
}

/// Inspect login's live-storage gates without realizing packages or service-script contents.
pub(super) fn private_storage(inputs: NixValue) -> NixValue {
    let configurations = NixValue::builtin("getFlake")
        .call(inputs.select("root").to_text())
        .select("nixosConfigurations");
    let service = |config: NixValue, name: &str| {
        let unit = config.select_segments(["systemd", "services", name]);
        NixValue::record([
            ("requires", unit.clone().select("requires")),
            ("after", unit.clone().select("after")),
            (
                "check",
                unit.select_segments(["serviceConfig", "ExecStartPre"]),
            ),
        ])
    };
    let mut profiles = Vec::new();
    for (profile, configuration, graphical) in [
        ("physical", "airlock-domain-sys-gui-usb-gui-lab", true),
        ("hybrid", "airlock-domain-sys-gui-usb", true),
        ("personal", "airlock-domain-usr-home", false),
    ] {
        let config = configurations
            .clone()
            .select(configuration)
            .select("config");
        let mut services = vec![("sessions", service(config.clone(), "systemd-user-sessions"))];
        if graphical {
            services.push(("display", service(config, "display-manager")));
        }
        profiles.push((profile, NixValue::record(services)));
    }
    NixValue::record(profiles)
}

/// Inspect evaluated configuration for test machine hardware module replaces lab gpu assignment.
pub(super) fn hardware_override(inputs: NixValue) -> NixValue {
    NixValue::builtin("getFlake")
        .call(NixValue::concat_text([inputs
            .clone()
            .select("root")
            .to_text()]))
        .bind(gui_gpu_assignment_hardware_override_body)
}

/// Inspect evaluated configuration for test laptop read only preflight.
pub(super) fn preflight_selection(_inputs: NixValue) -> NixValue {
    NixValue::function(|c| {
        NixValue::record([
            (
                "selection",
                NixValue::builtin("fromJSON").call(c.clone().select_segments([
                    "environment",
                    "etc",
                    "airlock/gui-gpu.json",
                    "text",
                ])),
            ),
            (
                "topology",
                c.clone().select_segments(["airlock", "qubes", "topology"]),
            ),
        ])
    })
}

/// Project a prepared physical configuration into read-only live validation inputs.
pub(super) fn live_preflight(inputs: NixValue) -> NixValue {
    let configuration = NixValue::builtin("getFlake")
        .call(inputs.clone().select("root").to_text())
        .select_segments([
            "nixosConfigurations",
            "machine",
            "config",
            "specialisation",
            "usb-gui-lab",
            "configuration",
        ]);
    preflight_selection(inputs).call(configuration)
}

/// Build the gui gpu assignment test nix selection drives reservation assignment and start
/// contribution using the caller supplied deferred values.
fn gui_gpu_assignment_gpu_selection_body(c: NixValue) -> NixValue {
    {
        let field_failed = NixValue::builtin("map")
            .call(NixValue::function(|a| {
                a.clone().select_segments(["message"])
            }))
            .call(
                NixValue::builtin("filter")
                    .call(NixValue::function(|a| {
                        !a.clone().select_segments(["assertion"])
                    }))
                    .call(c.clone().select_segments(["assertions"])),
            );

        NixValue::record([
            (
                "enabled",
                c.clone().select_segments(["airlock", "guiGpu", "enable"]),
            ),
            (
                "device",
                c.clone().select_segments(["airlock", "guiGpu", "device"]),
            ),
            (
                "pci",
                c.clone().select_segments([
                    "airlock", "qubes", "topology", "domains", "sys-gui", "devices", "pci",
                ]),
            ),
            (
                "params",
                c.clone().select_segments(["boot", "kernelParams"]),
            ),
            (
                "early",
                c.clone()
                    .select_segments(["boot", "initrd", "kernelModules"]),
            ),
            (
                "xenParams",
                c.clone()
                    .select_segments(["virtualisation", "xen", "boot", "params"]),
            ),
            ("failed", field_failed),
        ])
    }
}

/// Build the gui gpu assignment test nix selection drives reservation assignment and start
/// contribution using the caller supplied deferred values.
fn gui_gpu_assignment_gpu_selection_2(c: NixValue) -> NixValue {
    {
        let field_failed = NixValue::builtin("map")
            .call(NixValue::function(|a| {
                a.clone().select_segments(["message"])
            }))
            .call(
                NixValue::builtin("filter")
                    .call(NixValue::function(|a| {
                        !a.clone().select_segments(["assertion"])
                    }))
                    .call(c.clone().select_segments(["assertions"])),
            );

        NixValue::record([
            (
                "defaultUnit",
                c.clone().select_segments(["systemd", "defaultUnit"]),
            ),
            (
                "displayWantedBy",
                c.clone()
                    .select_segments(["systemd", "services", "display-manager", "wantedBy"]),
            ),
            (
                "session",
                c.clone()
                    .select_segments(["services", "displayManager", "defaultSession"]),
            ),
            (
                "gdm",
                c.clone()
                    .select_segments(["services", "displayManager", "gdm", "enable"]),
            ),
            (
                "lightdm",
                c.clone().select_segments([
                    "services",
                    "xserver",
                    "displayManager",
                    "lightdm",
                    "enable",
                ]),
            ),
            (
                "receiver",
                c.clone()
                    .select_segments(["airlock", "inputProxy", "receiver", "enable"]),
            ),
            (
                "guiAgent",
                c.clone()
                    .select_segments(["systemd", "services", "qubes-gui-agent", "enable"]),
            ),
            ("failed", field_failed),
        ])
    }
}

/// Build the gui gpu assignment test machine hardware module replaces lab gpu assignment
/// contribution using the caller supplied deferred values.
fn gui_gpu_assignment_hardware_override_body(f: NixValue) -> NixValue {
    {
        let receiver = f
            .clone()
            .select_segments(["lib", "mkMachineConfiguration"])
            .call({
                let field_hardware_modules = NixValue::list([NixValue::function_attrs_open(
                    std::iter::empty::<&str>(),
                    |_arguments_1| {
                        (
                            Vec::<(&str, NixValue)>::new(),
                            field(
                                ["airlock", "guiGpu", "device"],
                                NixValue::record([
                                    ("bdf", NixValue::from("0000:09:03.0")),
                                    ("port", NixValue::from("00_03.1-00_00.0")),
                                    ("vendor", NixValue::from("8086")),
                                    ("device", NixValue::from("1234")),
                                    ("driver", NixValue::from("i915")),
                                ]),
                            ),
                        )
                    },
                )]);

                NixValue::record([
                    ("includeRelease", NixValue::from(false)),
                    ("includeAlternativeGuiProfiles", NixValue::from(false)),
                    ("hardwareModules", field_hardware_modules),
                ])
            });

        receiver.bind(|machine| {
            machine
                .clone()
                .select_segments(["config", "specialisation", "usb-lab", "configuration"])
                .bind(|cfg| {
                    NixValue::record([
                        (
                            "device",
                            cfg.clone().select_segments(["airlock", "guiGpu", "device"]),
                        ),
                        (
                            "assignments",
                            cfg.clone().select_segments([
                                "airlock", "qubes", "domains", "sys-gui", "devices", "pci",
                            ]),
                        ),
                        (
                            "firmwareTemplate",
                            NixValue::builtin("readFile").call(cfg.clone().select_segments([
                                "environment",
                                "etc",
                                "qubes/templates/libvirt/xen/by-name/sys-gui.xml",
                                "source",
                            ])),
                        ),
                    ])
                })
        })
    }
}

/// Build the gui gpu assignment test nix selection drives reservation assignment and start
/// contribution using the caller supplied deferred values.
fn gui_gpu_assignment_gpu_selection_3(lab: NixValue, captures: Bindings) -> NixValue {
    let alternate = captures.get("alternate");
    let base = captures.get("base");
    let f = captures.get("f");
    let vm_base = captures.get("vm_base");
    let guest_report = captures.get("guest_report");
    let normal = captures.get("normal");
    let report = captures.get("report");

    {
        let field_service = NixValue::record([
            (
                "requires",
                lab.clone().select_segments([
                    "systemd",
                    "services",
                    "airlock-start-gui-gpu",
                    "requires",
                ]),
            ),
            (
                "wants",
                lab.clone().select_segments([
                    "systemd",
                    "services",
                    "airlock-start-gui-gpu",
                    "wants",
                ]),
            ),
            (
                "after",
                lab.clone().select_segments([
                    "systemd",
                    "services",
                    "airlock-start-gui-gpu",
                    "after",
                ]),
            ),
            (
                "serviceConfig",
                lab.clone().select_segments([
                    "systemd",
                    "services",
                    "airlock-start-gui-gpu",
                    "serviceConfig",
                ]),
            ),
        ]);

        let field_input_events = NixValue::record([
            (
                "wantedBy",
                lab.clone().select_segments([
                    "systemd",
                    "services",
                    "airlock-gui-input-events",
                    "wantedBy",
                ]),
            ),
            (
                "requires",
                lab.clone().select_segments([
                    "systemd",
                    "services",
                    "airlock-gui-input-events",
                    "requires",
                ]),
            ),
            (
                "wants",
                lab.clone().select_segments([
                    "systemd",
                    "services",
                    "airlock-gui-input-events",
                    "wants",
                ]),
            ),
            (
                "after",
                lab.clone().select_segments([
                    "systemd",
                    "services",
                    "airlock-gui-input-events",
                    "after",
                ]),
            ),
            (
                "serviceConfig",
                lab.clone().select_segments([
                    "systemd",
                    "services",
                    "airlock-gui-input-events",
                    "serviceConfig",
                ]),
            ),
        ]);

        let field_input_connect = lab
            .clone()
            .select_segments([
                "systemd",
                "services",
                "airlock-gui-input-connect",
                "serviceConfig",
            ])
            .merge_attrs(NixValue::record([
                (
                    "script",
                    native_contract(lab.clone().select_segments([
                        "systemd",
                        "services",
                        "airlock-gui-input-connect",
                        "serviceConfig",
                        "ExecStart",
                    ])),
                ),
                (
                    "requires",
                    lab.clone().select_segments([
                        "systemd",
                        "services",
                        "airlock-gui-input-connect",
                        "requires",
                    ]),
                ),
            ]));

        let field_input_guard = NixValue::record([
            (
                "before",
                lab.clone().select_segments([
                    "systemd",
                    "services",
                    "airlock-input-boot-guard",
                    "before",
                ]),
            ),
            (
                "after",
                lab.clone().select_segments([
                    "systemd",
                    "services",
                    "airlock-input-boot-guard",
                    "after",
                ]),
            ),
            (
                "unitConfig",
                lab.clone().select_segments([
                    "systemd",
                    "services",
                    "airlock-input-boot-guard",
                    "unitConfig",
                ]),
            ),
            (
                "serviceConfig",
                lab.clone().select_segments([
                    "systemd",
                    "services",
                    "airlock-input-boot-guard",
                    "serviceConfig",
                ]),
            ),
        ]);

        let field_input_policy = NixValue::builtin("head")
            .call(
                NixValue::builtin("filter")
                    .call(NixValue::function(|candidate| {
                        candidate
                            .clone()
                            .attr_or("name", NixValue::from(""))
                            .equals(NixValue::from("airlock-gui-input-policy"))
                    }))
                    .call(
                        lab.clone()
                            .select_segments(["virtualisation", "qubes", "packages"]),
                    ),
            )
            .bind(|package| {
                NixValue::builtin("readFile").call(NixValue::concat_text([
                    package.clone().to_text(),
                    NixValue::from("/etc/qubes/policy.d/40-airlock-gui-input.policy"),
                ]))
            });

        let field_framebuffer = NixValue::record([
            (
                "enabled",
                lab.clone()
                    .select_segments(["airlock", "guiGpu", "bootFramebuffer", "enable"]),
            ),
            (
                "statusDevice",
                lab.clone().select_segments([
                    "airlock",
                    "qubes",
                    "setupConfigOnBoot",
                    "statusDevice",
                ]),
            ),
            (
                "getty",
                lab.clone()
                    .select_segments(["systemd", "services", "getty@tty1", "enable"]),
            ),
            (
                "displayManager",
                lab.clone()
                    .select_segments(["systemd", "services", "display-manager", "enable"]),
            ),
            (
                "prepare",
                lab.clone().select_segments([
                    "systemd",
                    "services",
                    "airlock-setup-config",
                    "serviceConfig",
                    "ExecStartPre",
                ]),
            ),
        ]);

        let field_dark = report.clone().call(
            base.clone()
                .select_segments(["extendModules"])
                .call({
                    let field_modules =
                        NixValue::list([NixValue::function_attrs_open(["lib"], |arguments_2| {
                            (Vec::<(&str, NixValue)>::new(), {
                                let field_specialisation = field(
                                    [
                                        "usb-gui-lab",
                                        "configuration",
                                        "airlock",
                                        "guiGpu",
                                        "bootFramebuffer",
                                        "enable",
                                    ],
                                    arguments_2
                                        .clone()
                                        .select("lib")
                                        .clone()
                                        .select_segments(["mkForce"])
                                        .call(NixValue::from(false)),
                                );

                                field(["specialisation"], field_specialisation)
                            })
                        })]);

                    field(["modules"], field_modules)
                })
                .select_segments(["config", "specialisation", "usb-gui-lab", "configuration"]),
        );

        let field_diagnostic_guest = guest_report.clone().call(
            vm_base
                .clone()
                .select_segments(["extendModules"])
                .call({
                    let field_modules =
                        NixValue::list([NixValue::function_attrs_open(["lib"], |arguments_3| {
                            (
                                Vec::<(&str, NixValue)>::new(),
                                field(
                                    ["airlock", "sysGuiGuest", "physicalDesktopOnBoot"],
                                    arguments_3
                                        .clone()
                                        .select("lib")
                                        .clone()
                                        .select_segments(["mkForce"])
                                        .call(NixValue::from(false)),
                                ),
                            )
                        })]);

                    field(["modules"], field_modules)
                })
                .select_segments(["config"]),
        );

        let field_recovery_sender = normal
            .clone()
            .attr_or(
                "specialisation",
                NixValue::record(Vec::<(&str, NixValue)>::new()),
            )
            .attr_or(
                "usb-text-recovery",
                NixValue::record(Vec::<(&str, NixValue)>::new()),
            )
            .attr_or(
                "configuration",
                NixValue::record(Vec::<(&str, NixValue)>::new()),
            )
            .attr_or("airlock", NixValue::record(Vec::<(&str, NixValue)>::new()))
            .attr_or(
                "inputProxy",
                NixValue::record(Vec::<(&str, NixValue)>::new()),
            )
            .attr_or("sender", NixValue::record(Vec::<(&str, NixValue)>::new()))
            .attr_or("enable", NixValue::from(false));

        NixValue::record([
            ("normal", report.clone().call(normal.clone())),
            ("lab", report.clone().call(lab.clone())),
            ("alternate", report.clone().call(alternate.clone())),
            ("service", field_service),
            ("inputEvents", field_input_events),
            ("inputConnect", field_input_connect),
            ("inputGuard", field_input_guard),
            (
                "inputReceiverReady",
                native_contract(vm_base.clone().select_segments([
                    "config",
                    "environment",
                    "etc",
                    "qubes-rpc/airlock.InputReceiverReady",
                    "source",
                ])),
            ),
            (
                "inputReceiverReadyConfig",
                vm_base.clone().select_segments([
                    "config",
                    "environment",
                    "etc",
                    "qubes/rpc-config/airlock.InputReceiverReady",
                    "text",
                ]),
            ),
            ("inputPolicy", field_input_policy),
            (
                "discovery",
                lab.clone().select_segments([
                    "systemd",
                    "services",
                    "airlock-gui-input-discovery",
                    "serviceConfig",
                ]),
            ),
            (
                "deviceReceiver",
                native_contract(vm_base.clone().select_segments([
                    "config",
                    "environment",
                    "etc",
                    "qubes-rpc/airlock.InputDevice",
                    "source",
                ])),
            ),
            (
                "deviceReceiverConfig",
                vm_base.clone().select_segments([
                    "config",
                    "environment",
                    "etc",
                    "qubes/rpc-config/airlock.InputDevice",
                    "text",
                ]),
            ),
            (
                "noBypass",
                !lab.clone()
                    .select_segments(["systemd", "services", "qubes-vm@sys-gui", "enable"]),
            ),
            (
                "normalGuard",
                NixValue::builtin("fromJSON").call(normal.clone().select_segments([
                    "environment",
                    "etc",
                    "airlock/gui-gpu.json",
                    "text",
                ])),
            ),
            ("framebuffer", field_framebuffer),
            ("dark", field_dark),
            (
                "guest",
                guest_report
                    .clone()
                    .call(vm_base.clone().select_segments(["config"])),
            ),
            ("diagnosticGuest", field_diagnostic_guest),
            (
                "hybridGuest",
                guest_report.clone().call(f.clone().select_segments([
                    "nixosConfigurations",
                    "airlock-domain-sys-gui-usb",
                    "config",
                ])),
            ),
            (
                "normalSender",
                normal
                    .clone()
                    .select_segments(["airlock", "inputProxy", "sender", "enable"]),
            ),
            ("recoverySender", field_recovery_sender),
            (
                "inputTarget",
                lab.clone().select_segments([
                    "systemd",
                    "targets",
                    "airlock-gui-input",
                    "wantedBy",
                ]),
            ),
            (
                "inputServices",
                lab.clone()
                    .select_segments(["systemd", "targets", "airlock-gui-input", "wants"]),
            ),
            (
                "udevRules",
                lab.clone()
                    .select_segments(["services", "udev", "extraRules"]),
            ),
        ])
    }
}

/// Build the gui gpu assignment test nix selection drives reservation assignment and start
/// contribution using the caller supplied deferred values.
fn gui_gpu_assignment_gpu_selection_4(
    normal: NixValue,
    base: NixValue,
    f: NixValue,
    vm_base: NixValue,
    guest_report: NixValue,
    report: NixValue,
) -> NixValue {
    {
        let receiver = {
            let receiver = {
                let argument_1 = {
                    let field_modules =
                        NixValue::list([NixValue::function_attrs_open(["lib"], |arguments_1| {
                            (Vec::<(&str, NixValue)>::new(), {
                                let field_specialisation = {
                                    let field_usb_gui_lab = {
                                        let field_configuration = {
                                            let field_airlock = {
                                                let field_gui_gpu = field(
                                                    ["device"],
                                                    arguments_1
                                                        .clone()
                                                        .select("lib")
                                                        .clone()
                                                        .select_segments(["mkForce"])
                                                        .call(NixValue::record([
                                                            ("bdf", NixValue::from("0000:09:03.0")),
                                                            (
                                                                "port",
                                                                NixValue::from("00_03.1-00_00.0"),
                                                            ),
                                                            ("vendor", NixValue::from("1002")),
                                                            ("device", NixValue::from("9999")),
                                                            ("driver", NixValue::from("amdgpu")),
                                                        ])),
                                                );

                                                field(["guiGpu"], field_gui_gpu)
                                            };

                                            field(["airlock"], field_airlock)
                                        };

                                        field(["configuration"], field_configuration)
                                    };

                                    field(["usb-gui-lab"], field_usb_gui_lab)
                                };

                                field(["specialisation"], field_specialisation)
                            })
                        })]);

                    field(["modules"], field_modules)
                };

                base.clone()
                    .select_segments(["extendModules"])
                    .call(argument_1)
            };

            receiver.select_segments(["config", "specialisation", "usb-gui-lab", "configuration"])
        };

        receiver.bind(|alternate| {
            normal
                .clone()
                .select_segments(["specialisation", "usb-gui-lab", "configuration"])
                .bind(|lab| {
                    gui_gpu_assignment_gpu_selection_3(
                        lab,
                        Bindings::new([
                            ("alternate", alternate.clone()),
                            ("base", base.clone()),
                            ("f", f.clone()),
                            ("vm_base", vm_base.clone()),
                            ("guest_report", guest_report.clone()),
                            ("normal", normal.clone()),
                            ("report", report.clone()),
                        ]),
                    )
                })
        })
    }
}

/// Build the gui gpu assignment test nix selection drives reservation assignment and start
/// contribution using the caller supplied deferred values.
fn gui_gpu_assignment_gpu_selection_5(f: NixValue) -> NixValue {
    NixValue::function(gui_gpu_assignment_gpu_selection_2).bind(|guest_report| {
        NixValue::function(gui_gpu_assignment_gpu_selection_body).bind(|report| {
            f.clone()
                .select_segments(["nixosConfigurations", "machine"])
                .bind(|base| {
                    f.clone()
                        .select_segments([
                            "nixosConfigurations",
                            "airlock-domain-sys-gui-usb-gui-lab",
                        ])
                        .bind(|vm_base| {
                            base.clone().select_segments(["config"]).bind(|normal| {
                                gui_gpu_assignment_gpu_selection_4(
                                    normal,
                                    base.clone(),
                                    f.clone(),
                                    vm_base.clone(),
                                    guest_report.clone(),
                                    report.clone(),
                                )
                            })
                        })
                })
        })
    })
}
