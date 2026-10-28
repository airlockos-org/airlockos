//! Reserve the selected physical GPU for the GUI VM and perform one guarded boot handoff.

use airlock_build::{Workspace, tools::Tool};
use rusix::{
    interop::{
        NixExpression, NixPath,
        raw::{NixRepresentation, NixValue},
    },
    nix_record, nix_text,
    nixos::{ContextualModule, ModuleBody, ModuleContext},
};

/// Keep GPU assignment, Xen reservation and boot ordering in one machine-owned contribution.
pub(super) fn module(source: &NixPath, workspace: &Workspace) -> NixValue {
    ContextualModule::new(|context| {
        let cfg = context.config.clone().select("airlock.guiGpu");
        let gpu = cfg.clone().select("device");
        let service = Tool::Dom0
            .build(&context.pkgs, workspace, source)
            .as_expression();
        let start = Tool::StartReady
            .build(&context.pkgs, workspace, source)
            .as_expression();
        let config = service.bind(|service| configuration(&context, &cfg, &gpu, service, start));

        ModuleBody::new(config)
            .key("airlock.host.gui-gpu")
            .import_value(options(&context))
    })
    .into_expression()
}

/// Validate hardware identifiers before using them in Xen boot parameters or Qubes assignments.
fn options(context: &ModuleContext) -> NixValue {
    let lib = &context.lib;
    let enable = |description| lib.clone().select("mkEnableOption").call(description);
    let mut fields = Vec::new();
    for (name, pattern, description) in [
        (
            "bdf",
            r"0000:[0-9a-f]{2}:[0-1][0-9a-f]\.[0-7]",
            "Host segment-zero PCI address reserved for Xen.",
        ),
        (
            "port",
            "[0-9a-f_.-]+",
            "Qubes PCI port from this machine's hardware inventory.",
        ),
        (
            "vendor",
            "[0-9a-f]{4}",
            "Expected hexadecimal PCI vendor identity.",
        ),
        (
            "device",
            "[0-9a-f]{4}",
            "Expected hexadecimal PCI device identity.",
        ),
    ] {
        fields.push((
            name,
            lib.clone().select("mkOption").call(nix_record! {
                "type": lib.clone().select("types.strMatching").call(pattern),
                "description": description,
            }),
        ));
    }
    fields.push((
        "driver",
        lib.clone().select("mkOption").call(nix_record! {
            "type": lib
                .clone()
                .select("types.enum")
                .call(strings(&["amdgpu", "i915", "xe", "nouveau", "nvidia"])),
            "description": "Dom0 graphics driver excluded from the initrd and blacklisted.",
        }),
    ));

    nix_record! {
        "options": nix_record! {
            "airlock": nix_record! {
                "guiGpu": nix_record! {
                    "enable": enable("declarative physical GUI VM GPU ownership"),
                    "startOnBoot": enable("one GUI VM start after validated bootstrap"),
                    "bootFramebuffer": nix_record! {
                        "enable": enable("a temporary firmware console detached before GPU handoff"),
                    },
                    "device": lib.clone().select("mkOption").call(nix_record! {
                        "default": NixValue::null(),
                        "description": "Machine GPU selection; selection alone does not reserve hardware.",
                        "type": lib.clone().select("types.nullOr").call(
                            lib.clone().select("types.submodule").call(nix_record! {
                                "options": NixValue::record(fields),
                            }),
                        ),
                    }),
                },
            },
        },
    }
}

/// Record selection even when disabled, so switching profiles cannot hide persistent PCI ownership.
fn configuration(
    context: &ModuleContext,
    cfg: &NixValue,
    gpu: &NixValue,
    service: NixValue,
    start: NixValue,
) -> NixValue {
    let when = |condition, value| {
        context
            .lib
            .clone()
            .select("mkIf")
            .call(condition)
            .call(value)
    };
    let selected = gpu.clone().equals(NixValue::null()).equals(false);
    let split = context
        .config
        .clone()
        .select("airlock.machineDeployment.enable");
    let gui = context
        .config
        .clone()
        .select("airlock.qubes.domains")
        .attr_or("sys-gui", nix_record! {});
    let prefs = gui.clone().attr_or("prefs", nix_record! {});
    let features = gui.attr_or("features", nix_record! {});
    let checks = nix_record! {
        "assertions": NixValue::list([
            assertion(
                cfg.clone()
                    .select("bootFramebuffer.enable")
                    .equals(false)
                    .or(cfg.clone().select("startOnBoot")),
                "The boot framebuffer requires ordered GPU startup and handoff.",
            ),
            assertion(
                selected.clone(),
                "The physical GUI requires an explicit machine GPU selection.",
            ),
            assertion(
                selected.clone().equals(false).or(NixValue::builtin("elem")
                    .call(gpu.clone().select("driver"))
                    .call(context.config.clone().select("boot.initrd.kernelModules"))
                    .equals(false)),
                "Remove the selected GPU driver from explicit initrd kernel modules.",
            ),
            assertion(
                context
                    .config
                    .clone()
                    .select("virtualisation.qubes.dom0.enable")
                    .and(
                        context
                            .config
                            .clone()
                            .select("airlock.qubes.setupConfigOnBoot.enable"),
                    )
                    .and(
                        split.clone().or(context
                            .config
                            .clone()
                            .select("airlock.qubes.setupConfigOnBoot.scope")
                            .equals("all")),
                    ),
                "Physical GPU assignment requires dom0 and guarded GUI or full topology setup.",
            ),
            assertion(
                context
                    .config
                    .clone()
                    .select("airlock.qubes.domains")
                    .has_attr("sys-gui")
                    .and(prefs.clone().attr_or("virt_mode", "").equals("hvm"))
                    .and(features.attr_or("video-model", "").equals("none"))
                    .and(prefs.attr_or("autostart", false).equals(false)),
                "Physical sys-gui requires HVM, video-model=none and autostart=false; use guarded startup.",
            ),
        ]),
    };

    context.lib.clone().select("mkMerge").call(NixValue::list([
        when(
            selected.clone(),
            nix_record! {
                "environment": nix_record! {
                    "etc": nix_record! {
                        "airlock/gui-gpu.json": nix_record! {
                            "text": NixValue::builtin("toJSON").call(gpu.clone().merge_attrs(nix_record! {
                                "enable": cfg.clone().select("enable"),
                            })),
                        },
                    },
                },
            },
        ),
        when(
            cfg.clone().select("enable"),
            context.lib.clone().select("mkMerge").call(NixValue::list([
                checks,
                when(
                    selected,
                    reservation(context, cfg, gpu, split, service, start),
                ),
            ])),
        ),
    ]))
}

/// Reserve PCI before the host driver loads, then start the GUI only after bootstrap validation.
fn reservation(
    context: &ModuleContext,
    cfg: &NixValue,
    gpu: &NixValue,
    split: NixValue,
    service: NixValue,
    start: NixValue,
) -> NixValue {
    let framebuffer = cfg.clone().select("bootFramebuffer.enable");
    let when = |condition, value| {
        context
            .lib
            .clone()
            .select("mkIf")
            .call(condition)
            .call(value)
    };
    let force = |value| context.lib.clone().select("mkForce").call(value);
    let topology = NixValue::if_else(
        split.clone(),
        "/run/airlock/startup/topology.json",
        "/var/lib/airlock/system/current-topology.json",
    );
    let network = NixValue::if_else(
        split.clone().equals(false).and(
            context
                .config
                .clone()
                .select("airlock.qubes.startNetworkProvidersOnBoot.enable"),
        ),
        strings(&["airlock-start-network-providers.service"]),
        NixValue::list([]),
    );
    let executable: NixValue = nix_text!(
        "{service}/bin/airlock-dom0-service",
        service = service.clone(),
    )
    .into();
    let sync: NixValue = nix_text!(
        "{systemd}/bin/journalctl --sync",
        systemd = context.pkgs.clone().select("systemd"),
    )
    .into();
    let foreground: NixValue = nix_text!(
        "{executable} boot-foreground --topology {topology}",
        executable = executable.clone(),
        topology = topology.clone(),
    )
    .into();
    let service_config = nix_record! {
        "Type": "oneshot",
        "RemainAfterExit": true,
        "ExecStartPre": NixValue::concat_lists([
            NixValue::list([
                nix_text!(
                    "{executable} boot-supervisor stage gui 'starting and verifying sys-gui'",
                    executable = executable.clone(),
                )
                .into(),
                nix_text!(
                    "{systemd}/bin/systemctl is-active --quiet qubesd.service",
                    systemd = context.pkgs.clone().select("systemd"),
                )
                .into(),
                nix_text!(
                    "{executable} gpu check --topology {topology} --phase start",
                    executable = executable.clone(),
                    topology = topology.clone(),
                )
                .into(),
            ]),
            NixValue::if_else(
                framebuffer.clone(),
                NixValue::list([nix_text!(
                    "{executable} gpu framebuffer --gpu {bdf} --report /var/log/airlock/boot-framebuffer-handoff.json",
                    executable = executable,
                    bdf = gpu.clone().select("bdf"),
                )
                .into()]),
                NixValue::list([]),
            ),
            NixValue::list([sync.clone()]),
        ]),
        "ExecStart": nix_text!(
            "{start}/bin/airlock-start-qube-ready sys-gui {topology}",
            start = start,
            topology = topology,
        ),
        "ExecStartPost": NixValue::concat_lists([
            NixValue::if_else(
                split.clone(),
                NixValue::list([foreground]),
                NixValue::list([]),
            ),
            NixValue::list([sync]),
        ]),
        "Restart": "no",
    };

    nix_record! {
        "boot": nix_record! {
            "blacklistedKernelModules": NixValue::list([gpu.clone().select("driver")]),
            "initrd": nix_record! {
                "kernelModules": strings(&["xen-pciback"]),
                "availableKernelModules": NixValue::if_else(
                    framebuffer.clone(),
                    strings(&["simpledrm"]),
                    NixValue::list([]),
                ),
            },
            "kernelParams": NixValue::concat_lists([
                NixValue::list([
                    nix_text!("xen-pciback.hide=({bdf})", bdf = gpu.clone().select("bdf")).into(),
                ]),
                NixValue::if_else(
                    framebuffer.clone(),
                    strings(&["fbcon=nodefer"]),
                    strings(&["initcall_blacklist=sysfb_init", "video=efifb:off"]),
                ),
            ]),
        },
        "virtualisation": nix_record! {
            "xen": nix_record! {
                "boot": nix_record! {
                    "params": NixValue::concat_lists([
                        strings(&["iommu=required"]),
                        NixValue::if_else(
                            framebuffer.clone(),
                            strings(&["vga=current"]),
                            NixValue::list([]),
                        ),
                    ]),
                },
            },
        },
        "airlock": nix_record! {
            "qubes": nix_record! {
                "setupConfigOnBoot": nix_record! {
                    "statusDevice": when(framebuffer.clone(), "/dev/tty1".into()),
                },
                "domains": nix_record! {
                    "sys-gui": nix_record! {
                        "devices": nix_record! {
                            "pci": force(NixValue::list([nix_record! {
                                "backend": "dom0",
                                "id": gpu.clone().select("port"),
                                "mode": "required",
                                "match": "port",
                                "options": nix_record! {},
                            }])),
                        },
                    },
                },
            },
        },
        "environment": nix_record! {
            "systemPackages": NixValue::list([service]),
        },
        "systemd": nix_record! {
            "services": nix_record! {
                "getty@tty1": nix_record! {
                    "enable": when(framebuffer.clone(), false.into()),
                },
                "airlock-setup-config": nix_record! {
                    "serviceConfig": nix_record! {
                        "ExecStartPre": when(
                            framebuffer,
                            NixValue::list([nix_text!(
                                "-{kbd}/bin/chvt 1",
                                kbd = context.pkgs.clone().select("kbd"),
                            )
                            .into()]),
                        ),
                    },
                },
                "qubes-vm@sys-gui": nix_record! {
                    "enable": force(false.into()),
                },
                "airlock-start-gui-gpu": when(
                    cfg.clone().select("startOnBoot"),
                    nix_record! {
                        "description": "Validate and start the physical sys-gui GPU once",
                        "wantedBy": strings(&["multi-user.target"]),
                        "requires": NixValue::concat_lists([
                            strings(&["airlock-setup-config.service"]),
                            network.clone(),
                        ]),
                        // Bootstrap restarts qubesd; Requires would cancel this pending start.
                        "wants": strings(&["qubesd.service"]),
                        "after": NixValue::concat_lists([
                            strings(&["airlock-setup-config.service", "qubesd.service"]),
                            network,
                        ]),
                        "restartIfChanged": false,
                        "stopIfChanged": false,
                        "serviceConfig": service_config,
                    },
                ),
            },
        },
    }
}

/// Pair a deferred machine invariant with the error presented by NixOS evaluation.
fn assertion(condition: NixValue, message: &str) -> NixValue {
    nix_record! {
        "assertion": condition,
        "message": message,
    }
}

/// Preserve static dependency and kernel-parameter order.
fn strings(values: &[&str]) -> NixValue {
    NixValue::list(values.iter().map(|value| (*value).into()))
}
