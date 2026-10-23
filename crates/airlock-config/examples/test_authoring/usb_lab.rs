//! Rust-authored fixtures evaluated by the native integration suite.

use super::*;

/// Inspect startup ordering and deadlines without realizing service packages or reading their scripts.
pub(super) fn startup_contract(inputs: NixValue) -> NixValue {
    NixValue::builtin("getFlake")
        .call(inputs.select("root"))
        .select_segments([
            "nixosConfigurations",
            "usb-dev",
            "config",
            "specialisation",
            "usb-lab",
            "configuration",
        ])
        .bind(|host| {
            let services = host.clone().select_segments(["systemd", "services"]);
            let units = [
                "airlock-setup-config",
                "airlock-boot-guest@",
                "airlock-input-boot-guard",
                "airlock-start-gui-gpu",
                "airlock-gui-input-events",
                "airlock-gui-input-connect",
                "airlock-gui-input-boot-ready",
                "airlock-desktop-ready",
                "airlock-setup-config-deferred",
                "airlock-start-network-providers",
                "airlock-machine-autostart",
            ]
            .into_iter()
            .map(|name| {
                let unit = services.clone().select(name);
                let config = unit.clone().select("serviceConfig");
                (
                    format!("{name}.service"),
                    NixValue::record([
                        ("after", unit.clone().select("after")),
                        ("before", unit.clone().select("before")),
                        ("requires", unit.clone().select("requires")),
                        ("wantedBy", unit.clone().select("wantedBy")),
                        (
                            "failure",
                            unit.select("unitConfig")
                                .attr_or("OnFailure", NixValue::list([])),
                        ),
                        ("start", config.clone().select("ExecStart")),
                        ("type", config.clone().attr_or("Type", NixValue::null())),
                        ("remain", config.clone().attr_or("RemainAfterExit", false)),
                        (
                            "condition",
                            config.clone().attr_or("ExecCondition", NixValue::list([])),
                        ),
                        (
                            "pre",
                            config.clone().attr_or("ExecStartPre", NixValue::list([])),
                        ),
                        (
                            "post",
                            config.clone().attr_or("ExecStartPost", NixValue::list([])),
                        ),
                        (
                            "timeout",
                            config.attr_or("TimeoutStartSec", NixValue::null()),
                        ),
                    ]),
                )
            });
            NixValue::record([
                (
                    "readiness",
                    NixValue::builtin("fromJSON").call(host.clone().select_segments([
                        "environment",
                        "etc",
                        "airlock/boot-readiness.json",
                        "text",
                    ])),
                ),
                ("units", NixValue::record(units)),
                (
                    "domains",
                    NixValue::builtin("attrNames")
                        .call(host.select_segments(["airlock", "qubes", "domains"])),
                ),
            ])
        })
}

/// Inspect evaluated configuration for test usb image embeds machine source separately from
/// parent boot label.
pub(super) fn source_metadata(inputs: NixValue) -> NixValue {
    NixValue::builtin("getFlake")
        .call(NixValue::concat_text([inputs
            .clone()
            .select("flake")
            .to_text()]))
        .bind(|f| {
            NixValue::builtin("getAttr")
                .call(inputs.clone().select("configuration"))
                .call(f.clone().select_segments(["nixosConfigurations"]))
                .select_segments(["config", "specialisation", "usb-lab", "configuration"])
                .bind(|host| {
                    NixValue::record([
                        (
                            "source",
                            NixValue::builtin("fromJSON").call(host.clone().select_segments([
                                "environment",
                                "etc",
                                "airlock/machine-source.json",
                                "text",
                            ])),
                        ),
                        (
                            "boot",
                            NixValue::builtin("fromJSON").call(host.clone().select_segments([
                                "environment",
                                "etc",
                                "airlock/boot-source.json",
                                "text",
                            ])),
                        ),
                        (
                            "parentRevision",
                            f.clone().attr_or("rev", NixValue::from("dirty")),
                        ),
                    ])
                })
        })
}

/// Inspect evaluated configuration for test usb lab routes usr assistant through firewall and
/// retains development access.
pub(super) fn network_and_development_access(inputs: NixValue) -> NixValue {
    NixValue::builtin("getFlake")
        .call(NixValue::concat_text([inputs
            .clone()
            .select("root")
            .to_text()]))
        .bind(usb_lab_network_and_development_access_5)
}

/// Inspect evaluated configuration for test image and release embed their own committed boot
/// source.
pub(super) fn boot_source_metadata(inputs: NixValue) -> NixValue {
    NixValue::builtin("getFlake")
        .call(NixValue::concat_text([inputs
            .clone()
            .select("repo")
            .to_text()]))
        .bind(|f| {
            NixValue::builtin("getAttr")
                .call(inputs.clone().select("configuration"))
                .call(f.clone().select_segments(["nixosConfigurations"]))
                .select_segments(["config"])
                .bind(usb_lab_boot_source_metadata_body)
        })
}

/// Build the usb lab test image and release embed their own committed boot source contribution
/// using the caller supplied deferred values.
fn usb_lab_boot_source_metadata_body(config: NixValue) -> NixValue {
    {
        let field_recovery = NixValue::builtin("fromJSON").call(config.clone().select_segments([
            "specialisation",
            "usb-text-recovery",
            "configuration",
            "environment",
            "etc",
            "airlock/boot-source.json",
            "text",
        ]));

        NixValue::record([
            (
                "normal",
                NixValue::builtin("fromJSON").call(config.clone().select_segments([
                    "specialisation",
                    "usb-lab",
                    "configuration",
                    "environment",
                    "etc",
                    "airlock/boot-source.json",
                    "text",
                ])),
            ),
            ("recovery", field_recovery),
            (
                "consoleMode",
                config.clone().select_segments([
                    "specialisation",
                    "usb-lab",
                    "configuration",
                    "boot",
                    "loader",
                    "systemd-boot",
                    "consoleMode",
                ]),
            ),
        ])
    }
}

/// Build the usb lab test usb lab routes usr assistant through firewall and retains development
/// access contribution using the caller supplied deferred values.
fn usb_lab_network_and_development_access_body(captures: Bindings) -> NixValue {
    let ctrl = captures.get("ctrl");
    let dev = captures.get("dev");
    let gui = captures.get("gui");
    let host = captures.get("host");
    let lab_gui = captures.get("lab_gui");
    let policy = captures.get("policy");
    let retired_policy = captures.get("retired_policy");
    let tailscale_desktop = captures.get("tailscale_desktop");
    let tailscale_launcher = captures.get("tailscale_launcher");

    {
        let assistant_package = |name: &str| {
            NixValue::builtin("head").call(
                NixValue::builtin("filter")
                    .call(NixValue::function(|package| {
                        package.attr_or("name", "").equals(name)
                    }))
                    .call(
                        dev.clone()
                            .select_segments(["environment", "systemPackages"]),
                    ),
            )
        };
        let assistant_window =
            assistant_package("airlock-connect-tailscale").select("airlockCommand");
        let local_enrollment = NixValue::builtin("elemAt")
            .call(assistant_window.clone().select("args"))
            .call(
                NixValue::builtin("sub")
                    .call(NixValue::builtin("length").call(assistant_window.clone().select("args")))
                    .call(1_i64),
            );
        let assistant_desktop = NixValue::builtin("readFile").call(NixValue::concat_text([
            assistant_package("airlock-tailscale.desktop").to_text(),
            "/share/applications/airlock-tailscale.desktop".into(),
        ]));

        let field_tailscale_desktop = NixValue::builtin("readFile").call(NixValue::concat_text([
            tailscale_desktop.clone().to_text(),
            NixValue::from("/share/applications/airlock-start-usr-assistant-tailscale.desktop"),
        ]));

        let field_tailscale_policy = NixValue::builtin("readFile").call(NixValue::concat_text([
            host.clone()
                .select_segments(["environment", "etc", "qubes/policy.d", "source"])
                .to_text(),
            NixValue::from("/40-airlock-dev-tailscale.policy"),
        ]));

        let field_autostart = NixValue::record([
            (
                "after",
                host.clone().select_segments([
                    "systemd",
                    "services",
                    "airlock-machine-autostart",
                    "after",
                ]),
            ),
            (
                "requires",
                host.clone().select_segments([
                    "systemd",
                    "services",
                    "airlock-machine-autostart",
                    "requires",
                ]),
            ),
            (
                "wantedBy",
                host.clone().select_segments([
                    "systemd",
                    "services",
                    "airlock-machine-autostart",
                    "wantedBy",
                ]),
            ),
            (
                "command",
                host.clone().select_segments([
                    "systemd",
                    "services",
                    "airlock-machine-autostart",
                    "serviceConfig",
                    "ExecStart",
                ]),
            ),
            (
                "sync",
                host.clone().select_segments([
                    "systemd",
                    "services",
                    "airlock-machine-autostart",
                    "serviceConfig",
                    "ExecStartPost",
                ]),
            ),
        ]);

        let field_boot_supervisor = {
            let field_prepare = NixValue::record([
                (
                    "before",
                    host.clone().select_segments([
                        "systemd",
                        "services",
                        "airlock-boot-attempt-prepare",
                        "before",
                    ]),
                ),
                (
                    "wantedBy",
                    host.clone().select_segments([
                        "systemd",
                        "services",
                        "airlock-boot-attempt-prepare",
                        "wantedBy",
                    ]),
                ),
            ]);

            let field_setup = NixValue::record([
                (
                    "unitConfig",
                    host.clone().select_segments([
                        "systemd",
                        "services",
                        "airlock-setup-config",
                        "unitConfig",
                    ]),
                ),
                (
                    "serviceConfig",
                    host.clone().select_segments([
                        "systemd",
                        "services",
                        "airlock-setup-config",
                        "serviceConfig",
                    ]),
                ),
            ]);

            let field_deferred_setup = NixValue::record([
                (
                    "unitConfig",
                    host.clone().select_segments([
                        "systemd",
                        "services",
                        "airlock-setup-config-deferred",
                        "unitConfig",
                    ]),
                ),
                (
                    "serviceConfig",
                    host.clone().select_segments([
                        "systemd",
                        "services",
                        "airlock-setup-config-deferred",
                        "serviceConfig",
                    ]),
                ),
            ]);

            let field_network = NixValue::record([
                (
                    "unitConfig",
                    host.clone().select_segments([
                        "systemd",
                        "services",
                        "airlock-start-network-providers",
                        "unitConfig",
                    ]),
                ),
                (
                    "serviceConfig",
                    host.clone().select_segments([
                        "systemd",
                        "services",
                        "airlock-start-network-providers",
                        "serviceConfig",
                    ]),
                ),
            ]);

            let field_gui = NixValue::record([
                (
                    "unitConfig",
                    host.clone().select_segments([
                        "systemd",
                        "services",
                        "airlock-start-gui-gpu",
                        "unitConfig",
                    ]),
                ),
                (
                    "serviceConfig",
                    host.clone().select_segments([
                        "systemd",
                        "services",
                        "airlock-start-gui-gpu",
                        "serviceConfig",
                    ]),
                ),
            ]);

            let field_autostart = NixValue::record([
                (
                    "unitConfig",
                    host.clone().select_segments([
                        "systemd",
                        "services",
                        "airlock-machine-autostart",
                        "unitConfig",
                    ]),
                ),
                (
                    "serviceConfig",
                    host.clone().select_segments([
                        "systemd",
                        "services",
                        "airlock-machine-autostart",
                        "serviceConfig",
                    ]),
                ),
            ]);

            NixValue::record([
                (
                    "enabled",
                    host.clone()
                        .select_segments(["airlock", "bootSupervisor", "enable"]),
                ),
                ("prepare", field_prepare),
                (
                    "recoveryCondition",
                    host.clone().select_segments([
                        "systemd",
                        "services",
                        "airlock-boot-recovery-console",
                        "unitConfig",
                        "ConditionPathExists",
                    ]),
                ),
                (
                    "failureCapture",
                    host.clone().select_segments([
                        "systemd",
                        "services",
                        "airlock-boot-failure@",
                        "serviceConfig",
                        "ExecStart",
                    ]),
                ),
                (
                    "failureFinally",
                    host.clone().select_segments([
                        "systemd",
                        "services",
                        "airlock-boot-failure@",
                        "serviceConfig",
                        "ExecStopPost",
                    ]),
                ),
                (
                    "tty1",
                    host.clone().select_segments([
                        "systemd",
                        "units",
                        "getty@tty1.service",
                        "enable",
                    ]),
                ),
                (
                    "autoTty1",
                    host.clone().select_segments([
                        "systemd",
                        "units",
                        "autovt@tty1.service",
                        "enable",
                    ]),
                ),
                (
                    "failureConsole",
                    host.clone().select_segments([
                        "systemd",
                        "services",
                        "airlock-boot-failure-console",
                        "serviceConfig",
                    ]),
                ),
                ("setup", field_setup),
                ("deferredSetup", field_deferred_setup),
                ("network", field_network),
                ("gui", field_gui),
                ("autostart", field_autostart),
            ])
        };

        let field_pool_admission_policy =
            NixValue::builtin("readFile").call(NixValue::concat_text([
                host.clone()
                    .select_segments(["environment", "etc", "qubes/policy.d", "source"])
                    .to_text(),
                NixValue::from("/42-airlock-pool-admission.policy"),
            ]));

        let field_dev = {
            let argument_1 = [
                (
                    "role",
                    dev.clone()
                        .select_segments(["airlock", "qubeGuest", "role"]),
                ),
                (
                    "tailscale",
                    dev.clone()
                        .select_segments(["services", "tailscale", "enable"]),
                ),
                (
                    "tailscaleSsh",
                    dev.clone()
                        .select_segments(["services", "tailscale", "extraUpFlags"]),
                ),
                (
                    "dom0Shell",
                    dev.clone()
                        .select_segments(["airlock", "devDom0Terminal", "guest", "enable"]),
                ),
                (
                    "networkManager",
                    dev.clone()
                        .select_segments(["networking", "networkmanager", "enable"]),
                ),
                (
                    "configNixStoreRoot",
                    dev.clone()
                        .select_segments(["airlock", "qubeGuest", "configNixStoreRoot"]),
                ),
                (
                    "poolInit",
                    dev.clone().select_segments([
                        "systemd",
                        "services",
                        "airlock-usr-assistant-build-store",
                        "serviceConfig",
                    ]),
                ),
                (
                    "poolDevices",
                    dev.clone().select_segments([
                        "systemd",
                        "services",
                        "airlock-usr-assistant-build-store",
                        "requires",
                    ]),
                ),
                (
                    "userSelection",
                    dev.clone().select_segments([
                        "airlock",
                        "qubeGuest",
                        "allowQrexecUserSelection",
                    ]),
                ),
                (
                    "providesNetwork",
                    host.clone().select_segments([
                        "airlock",
                        "qubes",
                        "domains",
                        "usr-assistant",
                        "prefs",
                        "provides_network",
                    ]),
                ),
            ];

            NixValue::record(argument_1)
        };

        NixValue::record([
            (
                "domains",
                NixValue::builtin("attrNames").call(
                    host.clone()
                        .select_segments(["airlock", "qubes", "domains"]),
                ),
            ),
            (
                "bootRole",
                host.clone()
                    .select_segments(["environment", "etc", "airlock/boot-role", "text"]),
            ),
            (
                "default_netvm",
                host.clone()
                    .select_segments(["airlock", "qubes", "prefs", "default_netvm"]),
            ),
            (
                "devNetvm",
                host.clone().select_segments([
                    "airlock",
                    "qubes",
                    "domains",
                    "usr-assistant",
                    "netvm",
                ]),
            ),
            (
                "ctrlNetvm",
                host.clone()
                    .select_segments(["airlock", "qubes", "domains", "sys-ctrl", "netvm"]),
            ),
            (
                "firewallNetvm",
                host.clone().select_segments([
                    "airlock",
                    "qubes",
                    "domains",
                    "sys-firewall",
                    "netvm",
                ]),
            ),
            (
                "netNetvm",
                host.clone()
                    .select_segments(["airlock", "qubes", "domains", "sys-net", "netvm"]),
            ),
            (
                "homeNetvm",
                host.clone()
                    .select_segments(["airlock", "qubes", "domains", "usr-home", "netvm"]),
            ),
            (
                "devProvider",
                host.clone().select_segments([
                    "airlock",
                    "qubes",
                    "domains",
                    "usr-assistant",
                    "prefs",
                    "provides_network",
                ]),
            ),
            (
                "netProvider",
                host.clone().select_segments([
                    "airlock",
                    "qubes",
                    "domains",
                    "sys-net",
                    "prefs",
                    "provides_network",
                ]),
            ),
            (
                "firewallProvider",
                host.clone().select_segments([
                    "airlock",
                    "qubes",
                    "domains",
                    "sys-firewall",
                    "prefs",
                    "provides_network",
                ]),
            ),
            (
                "devPci",
                host.clone().select_segments([
                    "airlock",
                    "qubes",
                    "domains",
                    "usr-assistant",
                    "devices",
                    "pci",
                ]),
            ),
            (
                "netPci",
                host.clone()
                    .select_segments(["airlock", "qubes", "domains", "sys-net", "devices", "pci"]),
            ),
            (
                "devAutoPci",
                host.clone().select_segments([
                    "airlock",
                    "qubes",
                    "domains",
                    "usr-assistant",
                    "features",
                    "airlock-auto-network-pci",
                ]),
            ),
            (
                "netAutoPci",
                host.clone().select_segments([
                    "airlock",
                    "qubes",
                    "domains",
                    "sys-net",
                    "features",
                    "airlock-auto-network-pci",
                ]),
            ),
            (
                "devMemory",
                host.clone().select_segments([
                    "airlock",
                    "qubes",
                    "domains",
                    "usr-assistant",
                    "prefs",
                    "memory",
                ]),
            ),
            (
                "devMaxmem",
                host.clone().select_segments([
                    "airlock",
                    "qubes",
                    "domains",
                    "usr-assistant",
                    "prefs",
                    "maxmem",
                ]),
            ),
            (
                "ctrlMemory",
                host.clone().select_segments([
                    "airlock", "qubes", "domains", "sys-ctrl", "prefs", "memory",
                ]),
            ),
            (
                "ctrlMaxmem",
                host.clone().select_segments([
                    "airlock", "qubes", "domains", "sys-ctrl", "prefs", "maxmem",
                ]),
            ),
            (
                "ctrlBuildJobs",
                ctrl.clone()
                    .select_segments(["nix", "settings", "max-jobs"]),
            ),
            (
                "guiPci",
                host.clone()
                    .select_segments(["airlock", "qubes", "domains", "sys-gui", "devices", "pci"]),
            ),
            (
                "guiHostname",
                gui.clone().select_segments(["networking", "hostName"]),
            ),
            (
                "labGuiHasDom0Terminal",
                lab_gui
                    .clone()
                    .select_segments(["airlock", "devDom0Terminal", "guest", "enable"]),
            ),
            (
                "tailscaleLauncher",
                native_contract(NixValue::concat_text([
                    tailscale_launcher.clone().to_text(),
                    NixValue::from("/bin/airlock-start-usr-assistant-tailscale"),
                ])),
            ),
            ("tailscaleDesktop", field_tailscale_desktop),
            ("tailscaleAssistantDesktop", assistant_desktop),
            ("tailscaleWindow", assistant_window),
            ("tailscaleLocalHelper", local_enrollment.clone()),
            (
                "tailscaleLocalEnrollment",
                native_contract(local_enrollment),
            ),
            (
                "tailscaleSudo",
                dev.clone()
                    .select_segments(["security", "sudo", "extraRules"]),
            ),
            (
                "tailscaleHandler",
                native_contract(dev.clone().select_segments([
                    "environment",
                    "etc",
                    "qubes-rpc/airlock.DevTailscaleUp",
                    "source",
                ])),
            ),
            (
                "tailscaleRpcConfig",
                dev.clone().select_segments([
                    "environment",
                    "etc",
                    "qubes/rpc-config/airlock.DevTailscaleUp",
                    "text",
                ]),
            ),
            ("tailscalePolicy", field_tailscale_policy),
            (
                "hostNetworkManager",
                host.clone()
                    .select_segments(["networking", "networkmanager", "enable"]),
            ),
            (
                "hostTailscale",
                host.clone()
                    .select_segments(["services", "tailscale", "enable"]),
            ),
            (
                "hostSsh",
                host.clone()
                    .select_segments(["services", "openssh", "enable"]),
            ),
            ("autostart", field_autostart),
            ("bootSupervisor", field_boot_supervisor),
            (
                "setupSync",
                host.clone().select_segments([
                    "systemd",
                    "services",
                    "airlock-setup-config",
                    "serviceConfig",
                    "ExecStartPost",
                ]),
            ),
            (
                "callers",
                host.clone()
                    .select_segments(["airlock", "devDom0Terminal", "callers"]),
            ),
            (
                "policy",
                NixValue::builtin("readFile").call(NixValue::concat_text([
                    policy.clone().to_text(),
                    NixValue::from("/etc/qubes/policy.d/40-airlock-dev-dom0-terminal.policy"),
                ])),
            ),
            (
                "capturePolicy",
                NixValue::builtin("readFile").call(NixValue::concat_text([
                    host.clone()
                        .select_segments(["environment", "etc", "qubes/policy.d", "source"])
                        .to_text(),
                    "/45-airlock-screen-capture.policy".into(),
                ])),
            ),
            (
                "retiredPolicy",
                NixValue::builtin("readFile").call(NixValue::concat_text([
                    retired_policy.clone().to_text(),
                    NixValue::from("/etc/qubes/policy.d/05-airlock-retired.policy"),
                ])),
            ),
            (
                "retireDomains",
                host.clone()
                    .select_segments(["airlock", "machineDeployment", "retireDomains"]),
            ),
            (
                "trashRetentionDays",
                host.clone().select_segments([
                    "airlock",
                    "machineDeployment",
                    "trashRetentionDays",
                ]),
            ),
            (
                "poolAdmission",
                host.clone().select_segments(["airlock", "poolAdmission"]),
            ),
            (
                "poolAdmissionHandler",
                native_contract(host.clone().select_segments([
                    "environment",
                    "etc",
                    "qubes-rpc/airlock.Pool.Admit",
                    "source",
                ])),
            ),
            (
                "poolAdmissionMode",
                host.clone().select_segments([
                    "environment",
                    "etc",
                    "qubes-rpc/airlock.Pool.Admit",
                    "mode",
                ]),
            ),
            ("poolAdmissionPolicy", field_pool_admission_policy),
            ("dev", field_dev),
        ])
    }
}

/// Build the usb lab test usb lab routes usr assistant through firewall and retains development
/// access contribution using the caller supplied deferred values.
fn usb_lab_network_and_development_access_2(policy: NixValue, captures: Bindings) -> NixValue {
    let ctrl = captures.get("ctrl");
    let dev = captures.get("dev");
    let gui = captures.get("gui");
    let host = captures.get("host");
    let lab_gui = captures.get("lab_gui");
    let tailscale_desktop = captures.get("tailscale_desktop");
    let tailscale_launcher = captures.get("tailscale_launcher");

    {
        let receiver = NixValue::builtin("head").call(
            NixValue::builtin("filter")
                .call(NixValue::function(|p| {
                    NixValue::builtin("pathExists").call(NixValue::concat_text([
                        p.clone().to_text(),
                        NixValue::from("/etc/qubes/policy.d/05-airlock-retired.policy"),
                    ]))
                }))
                .call(
                    host.clone()
                        .select_segments(["virtualisation", "qubes", "packages"]),
                ),
        );

        receiver.bind(|retired_policy| {
            usb_lab_network_and_development_access_body(Bindings::new([
                ("ctrl", ctrl.clone()),
                ("dev", dev.clone()),
                ("gui", gui.clone()),
                ("host", host.clone()),
                ("lab_gui", lab_gui.clone()),
                ("policy", policy.clone()),
                ("retired_policy", retired_policy.clone()),
                ("tailscale_desktop", tailscale_desktop.clone()),
                ("tailscale_launcher", tailscale_launcher.clone()),
            ]))
        })
    }
}

/// Build the usb lab test usb lab routes usr assistant through firewall and retains development
/// access contribution using the caller supplied deferred values.
fn usb_lab_network_and_development_access_3(
    tailscale_launcher: NixValue,
    ctrl: NixValue,
    dev: NixValue,
    gui: NixValue,
    host: NixValue,
    lab_gui: NixValue,
) -> NixValue {
    NixValue::builtin("head")
        .call(
            NixValue::builtin("filter")
                .call(NixValue::function(|package| {
                    package
                        .clone()
                        .attr_or("pname", package.clone().select_segments(["name"]))
                        .equals(NixValue::from(
                            "airlock-start-usr-assistant-tailscale.desktop",
                        ))
                }))
                .call(
                    lab_gui
                        .clone()
                        .select_segments(["environment", "systemPackages"]),
                ),
        )
        .bind(|tailscale_desktop| {
            NixValue::builtin("head")
                .call(
                    NixValue::builtin("filter")
                        .call(NixValue::function(|p| {
                            p.clone()
                                .attr_or("name", NixValue::from(""))
                                .equals(NixValue::from("airlock-dev-dom0-terminal-policy"))
                        }))
                        .call(host.clone().select_segments([
                            "virtualisation",
                            "qubes",
                            "packages",
                        ])),
                )
                .bind(|policy| {
                    usb_lab_network_and_development_access_2(
                        policy,
                        Bindings::new([
                            ("ctrl", ctrl.clone()),
                            ("dev", dev.clone()),
                            ("gui", gui.clone()),
                            ("host", host.clone()),
                            ("lab_gui", lab_gui.clone()),
                            ("tailscale_desktop", tailscale_desktop.clone()),
                            ("tailscale_launcher", tailscale_launcher.clone()),
                        ]),
                    )
                })
        })
}

/// Build the usb lab test usb lab routes usr assistant through firewall and retains development
/// access contribution using the caller supplied deferred values.
fn usb_lab_network_and_development_access_4(
    gui: NixValue,
    ctrl: NixValue,
    dev: NixValue,
    f: NixValue,
    host: NixValue,
) -> NixValue {
    f.clone()
        .select_segments([
            "nixosConfigurations",
            "airlock-domain-sys-gui-usb-lab",
            "config",
        ])
        .bind(|lab_gui| {
            NixValue::builtin("head")
                .call(
                    NixValue::builtin("filter")
                        .call(NixValue::function(|package| {
                            package
                                .clone()
                                .attr_or("pname", package.clone().select_segments(["name"]))
                                .equals(NixValue::from("airlock-start-usr-assistant-tailscale"))
                        }))
                        .call(
                            lab_gui
                                .clone()
                                .select_segments(["environment", "systemPackages"]),
                        ),
                )
                .bind(|tailscale_launcher| {
                    usb_lab_network_and_development_access_3(
                        tailscale_launcher,
                        ctrl.clone(),
                        dev.clone(),
                        gui.clone(),
                        host.clone(),
                        lab_gui.clone(),
                    )
                })
        })
}

/// Build the usb lab test usb lab routes usr assistant through firewall and retains development
/// access contribution using the caller supplied deferred values.
fn usb_lab_network_and_development_access_5(f: NixValue) -> NixValue {
    f.clone()
        .select_segments([
            "nixosConfigurations",
            "usb-dev",
            "config",
            "specialisation",
            "usb-lab",
            "configuration",
        ])
        .bind(|host| {
            f.clone()
                .select_segments([
                    "nixosConfigurations",
                    "airlock-domain-usr-assistant",
                    "config",
                ])
                .bind(|dev| {
                    f.clone()
                        .select_segments([
                            "nixosConfigurations",
                            "airlock-domain-sys-ctrl",
                            "config",
                        ])
                        .bind(|ctrl| {
                            f.clone()
                                .select_segments([
                                    "nixosConfigurations",
                                    "airlock-domain-sys-gui-usb-gui-lab",
                                    "config",
                                ])
                                .bind(|gui| {
                                    usb_lab_network_and_development_access_4(
                                        gui,
                                        ctrl.clone(),
                                        dev.clone(),
                                        f.clone(),
                                        host.clone(),
                                    )
                                })
                        })
                })
        })
}
