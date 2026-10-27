//! Compose the physical USB machine and its boot specialisations from one VM snapshot.

use crate::assembly::PhysicalBuild;
use crate::model::{HostSnapshot, MachineSnapshot, Role};
use rusix::{
    interop::raw::NixValue,
    nix_record, nix_text,
    nixos::{ContextualModule, ModuleBody, ModuleContext, NixosModule},
};

mod base;

mod recovery;

/// Compose normal, graphics-validation and independent recovery boot configurations.
/// VM descriptors already include any prepared-store substitutions made by the image builder.
pub(crate) fn module(
    host: &HostSnapshot,
    machine: &MachineSnapshot,
    build: &PhysicalBuild,
) -> Result<NixValue, String> {
    let assistants = machine
        .vms()
        .filter(|vm| matches!(vm.role, Role::Assistant { .. }))
        .collect::<Vec<_>>();
    let [assistant] = assistants.as_slice() else {
        return Err("the physical USB host requires exactly one development VM".into());
    };

    Ok(ContextualModule::new(|inputs| {
        let force = |value: NixValue| inputs.lib.clone().select("mkForce").call(value);
        let alternatives = build.alternatives.clone();
        let source = build.boot_source.clone();
        // Apply the hardware-selected GPU to the snapshot’s GUI declaration.
        let gui = build.domain(&host.gui);
        let gpu = inputs.config.clone().select("airlock.guiGpu.device");
        let assignment = inputs
            .lib
            .clone()
            .select("optionals")
            .call(gpu.clone().equals(NixValue::null()).equals(false))
            .call(NixValue::list([nix_record! {
                "backend": "dom0",
                "id": gpu.select("port"),
                "mode": "required",
                "match": "port",
                "options": nix_record! {},
            }]));
        // The forced descriptor must retain the physical assignment through specialisation merging.
        let gui = NixValue::builtin("removeAttrs")
            .call(gui)
            .call(NixValue::list(["devices".into()]))
            .merge_attrs(nix_record! {
                "devices": nix_record! {
                    "pci": assignment,
                },
            });
        let normal_domains = NixValue::record(machine.vms().map(|vm| {
            let domain = if vm.name == host.gui {
                gui.clone()
            } else {
                build.domain(&vm.name)
            };

            (vm.name.to_string(), force(domain))
        }));

        let standalone = NixValue::builtin("removeAttrs")
            .call(build.standalone_gui.clone())
            .call(NixValue::list(["devices".into()]));
        let standalone = inputs
            .lib
            .clone()
            .select("mapAttrs")
            .call(NixValue::function(|_| NixValue::function(force)))
            .call(standalone);

        let recovery = recovery::module(&inputs, build, source.clone());
        let graphics = graphics(&inputs);
        let normal = normal(&inputs, host, machine, assistant.name.as_str());

        let composition = nix_record! {
            "airlock": nix_record! {
                "dom0": nix_record! {
                    "bootMenu": nix_record! {
                        "source": source,
                    },
                },
                "machineDeployment": nix_record! {
                    "enable": true,
                    "profile": "usb-dev",
                    "initialSource": build.machine_source.clone(),
                },
                "qubes": nix_record! {
                    "setupConfigOnBoot": nix_record! {
                        "enable": inputs
                            .lib
                            .clone()
                            .select("mkIf")
                            .call(
                                alternatives.clone().equals(false).and(
                                    inputs
                                        .config
                                        .clone()
                                        .select("specialisation")
                                        .equals(nix_record! {})
                                        .equals(false),
                                ),
                            )
                            .call(force(false.into())),
                    },
                },
            },
            "specialisation": nix_record! {
                "usb-text-recovery": nix_record! {
                    "inheritParentConfig": false,
                    "configuration": recovery,
                },
                "usb-gui-lab": inputs
                    .lib
                    .clone()
                    .select("mkIf")
                    .call(alternatives.clone())
                    .call(nix_record! {
                        "configuration": nix_record! {
                            "imports": NixValue::list([graphics.clone()]),
                            "airlock": nix_record! {
                                "machineDeployment": nix_record! {
                                    "profile": force("usb-gui-lab".into()),
                                },
                                "qubes": nix_record! {
                                    "domains": NixValue::record([(host.gui.as_str(), standalone)]),
                                },
                            },
                        },
                    }),
                "usb-lab": nix_record! {
                    "configuration": nix_record! {
                        "imports": NixValue::list([graphics, normal]),
                        "airlock": nix_record! {
                            "machineDeployment": nix_record! {
                                "profile": force("usb-lab".into()),
                                "retireDomains": NixValue::list([]),
                            },
                            "qubes": nix_record! {
                                "domains": normal_domains,
                            },
                        },
                    },
                },
            },
        };

        let mut body = ModuleBody::empty().import_value(crate::components::clipboard::host_module(
            machine.clipboard_connections(),
            build.workspace.clone(),
            true,
        ));
        if let Some(access) = machine.diagnostic_access() {
            body = body.import_value(crate::components::diagnostics::host_module(
                access,
                build.workspace.clone(),
            ));
        }

        body.key("airlock-config.physical-host")
            .import_value(super::deployment::module(&build.source, &build.workspace))
            .import_value(super::store::module(&build.workspace))
            .module(base::module(&inputs))
            .module(ModuleBody::new(
                inputs
                    .lib
                    .clone()
                    .select("mkIf")
                    .call(alternatives.equals(false))
                    .call(headless(&inputs)),
            ))
            .module(ModuleBody::new(composition))
    })
    .into_expression())
}

/// Disable dom0's local display transport while preserving its Qubes control services.
fn headless(inputs: &ModuleContext) -> NixValue {
    let off = inputs.lib.clone().select("mkForce").call(false);

    nix_record! {
        "services": nix_record! {
            "xserver": nix_record! {
                "enable": off.clone(),
                "displayManager": nix_record! {
                    "lightdm": nix_record! {
                        "enable": off.clone(),
                    },
                },
            },
            "displayManager": nix_record! {
                "autoLogin": nix_record! {
                    "enable": off.clone(),
                },
            },
        },
        "systemd": nix_record! {
            "defaultUnit": "multi-user.target",
            "services": nix_record! {
                "display-manager": nix_record! {
                    "enable": off,
                },
            },
        },
    }
}

/// Enable physical GPU handoff and input forwarding using the existing dom0 services.
fn graphics(inputs: &ModuleContext) -> NixValue {
    nix_record! {
        "imports": NixValue::list([headless(inputs)]),
        "airlock": nix_record! {
            "bootSupervisor": nix_record! {
                "enable": true,
            },
            // Deferred setup requires this phase even when the graphics-only profile has no providers.
            "qubes": nix_record! {
                "startNetworkProvidersOnBoot": nix_record! {
                    "enable": inputs.lib.clone().select("mkForce").call(true),
                },
            },
            "inputProxy": nix_record! {
                "sender": nix_record! {
                    "enable": true,
                },
            },
            "guiGpu": nix_record! {
                "enable": true,
                "startOnBoot": true,
                "bootFramebuffer": nix_record! {
                    "enable": true,
                },
            },
            "amdVbios": nix_record! {
                "enable": true,
                "domains": nix_record! {
                    "sys-gui": nix_record! {},
                },
            },
        },
        "environment": nix_record! {
            "etc": nix_record! {
                "airlock/usb-gui-lab": nix_record! {
                    "text": "experimental; declarative GPU assignment and one boot start\n",
                },
            },
        },
    }
}

/// Route network and development access through the selected VMs and install capture policy.
fn normal(
    inputs: &ModuleContext,
    host: &HostSnapshot,
    machine: &MachineSnapshot,
    assistant: &str,
) -> NixValue {
    let force = |value: NixValue| inputs.lib.clone().select("mkForce").call(value);
    let mut targets = machine.vms().collect::<Vec<_>>();
    // Preserve the admission list's established role order while deriving identities from the snapshot.
    targets.sort_by_key(|vm| match vm.role {
        Role::Gui { .. } => 0,
        Role::Assistant { .. } => 1,
        Role::Controller { .. } => 2,
        Role::NetworkDriver { .. } => 3,
        Role::Firewall { .. } => 4,
        Role::Personal { .. } => 5,
        Role::Command { .. } | Role::Service | Role::Isolated { .. } => 6,
    });
    let route = format!(
        "{assistant} provides Tailnet development access through {firewall}",
        firewall = host.network.as_str(),
    );
    let policy = inputs
        .pkgs
        .clone()
        .select("writeTextDir")
        .call("etc/qubes/policy.d/40-airlock-dev-tailscale.policy")
        .call(nix_text!(
            r#"
            airlock.DevTailscaleUp + {gui} {assistant} allow user=root
            airlock.DevTailscaleUp * @anyvm @anyvm deny
        "#,
            gui = host.gui.as_str(),
            assistant = assistant,
        ));

    // Upstream owns policy.d as one joined directory; individual entries belong in its packages.
    let capture_policy = inputs
        .pkgs
        .clone()
        .select("writeTextDir")
        .call("etc/qubes/policy.d/45-airlock-screen-capture.policy")
        .call(crate::components::screen_capture::policy(
            machine.capture_connections(),
        ));

    nix_record! {
        "airlock": nix_record! {
            "devDom0Terminal": nix_record! {
                "host": nix_record! {
                    "enable": true,
                },
                "callers": force(NixValue::list([assistant.into()])),
            },
            "poolAdmission": nix_record! {
                "enable": true,
                "caller": host.controller.as_str(),
                "targets": NixValue::list(targets.iter().map(|vm| vm.name.as_str().into())),
            },
            "qubes": nix_record! {
                "startNetworkProvidersOnBoot": nix_record! {
                    "enable": force(true.into()),
                },
                "prefs": nix_record! {
                    "default_netvm": force(host.network.as_str().into()),
                },
            },
        },
        "networking": nix_record! {
            "networkmanager": nix_record! {
                "enable": force(false.into()),
            },
        },
        "services": nix_record! {
            "tailscale": nix_record! {
                "enable": force(false.into()),
            },
            "openssh": nix_record! {
                "enable": force(false.into()),
            },
        },
        "virtualisation": nix_record! {
            "qubes": nix_record! {
                "packages": NixValue::list([policy, capture_policy]),
            },
        },
        "environment": nix_record! {
            "etc": nix_record! {
                "airlock/usb-lab": nix_record! {
                    "text": nix_text!(
                        r#"
                experimental general USB lab
                sys-net owns physical networking; {route}
                run: tailscale ssh user@{assistant}; then airlock-dom0-shell
            "#,
                        assistant = assistant,
                        route = route,
                    ),
                },
                "airlock/boot-role": nix_record! {
                    "text": "normal\n",
                },
            },
        },
    }
}

/// Describe the ThinkPad's hardware inventory without assigning devices outside the GUI profile.
pub(crate) fn hardware() -> NixosModule {
    NixosModule::with_context(|inputs| {
        ModuleBody::new(nix_record! {
            "hardware": nix_record! {
                "cpu": nix_record! {
                    "amd": nix_record! {
                        "updateMicrocode": true,
                    },
                },
                "enableRedistributableFirmware": true,
                "graphics": nix_record! {
                    "enable": true,
                },
            },
            "boot": nix_record! {
                "initrd": nix_record! {
                    "availableKernelModules": NixValue::list(
                        ["xhci_pci", "usb_storage", "uas", "sd_mod"].map(Into::into),
                    ),
                    "kernelModules": inputs
                        .lib
                        .clone()
                        .select("optional")
                        .call(
                            inputs
                                .config
                                .clone()
                                .select("airlock.guiGpu.enable")
                                .equals(false),
                        )
                        .call("amdgpu"),
                },
                "kernelModules": NixValue::list(["thinkpad_acpi", "r8169", "ath11k_pci"].map(Into::into)),
            },
            "services": nix_record! {
                "xserver": nix_record! {
                    "videoDrivers": NixValue::list(["amdgpu".into()]),
                },
            },
            "airlock": nix_record! {
                "guiGpu": nix_record! {
                    "device": nix_record! {
                        "bdf": "0000:04:00.0",
                        "port": "00_08.1-00_00.0",
                        "vendor": "1002",
                        "device": "1681",
                        "driver": "amdgpu",
                    },
                },
            },
            "environment": nix_record! {
                "systemPackages": NixValue::list([
                    inputs.pkgs.clone().select("pciutils"),
                    inputs.pkgs.clone().select("usbutils"),
                ]),
            },
        })
    })
}
