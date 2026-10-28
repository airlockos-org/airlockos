//! Build isolated GUI environments for nested and physical graphics validation.
//! These environments reuse the bootstrap GUI's resources and the physical desktop services.

use crate::{inputs::args, lowering, model::Role, profiles};
use rusix::{
    IntoRusixValue,
    interop::{
        PackageFunction,
        raw::{NixRepresentation, NixValue},
    },
    nix_record,
    nixos::{ContextualModule, ModuleBody},
};

/// The existing graphics validation environments exposed by the machine flake.
#[derive(Clone, Copy)]
enum Display {
    /// Nested GUI forwarding without a default application VM.
    Minimal,
    /// USB host forwarding with a development terminal to dom0.
    Hybrid,
    /// Physical AMD display with local GNOME applications and no application VM.
    Standalone,
}

impl Display {
    /// Return the stable configuration name used by image and validation callers.
    fn configuration_name(self) -> &'static str {
        match self {
            Self::Minimal => "airlock-domain-sys-gui-minimal",
            Self::Hybrid => "airlock-domain-sys-gui-usb",
            Self::Standalone => "airlock-domain-sys-gui-usb-gui-lab",
        }
    }
}

/// Export lazy GUI factories with the same source and package dependencies as ordinary VMs.
pub(crate) fn builders() -> PackageFunction {
    let machine = profiles::bootstrap::machine().expect("the bootstrap machine is valid");
    let gui = machine
        .vms()
        .find(|vm| matches!(vm.role, Role::Gui { .. }))
        .expect("the bootstrap machine declares a GUI");

    PackageFunction::from_function_attrs(args::argument_names().iter().copied(), |arguments| {
        let inputs = args::from_value(arguments.clone());
        let base = lowering::domain(&inputs, gui)
            .try_into_nix_value()
            .expect("the GUI builder arguments are structurally valid");
        let factories = [
            ("minimal", Display::Minimal),
            ("hybrid", Display::Hybrid),
            ("standalone", Display::Standalone),
        ]
        .map(|(name, display)| {
            let request = request(&inputs, base.clone(), display);
            let factory = NixValue::function(|system| {
                arguments
                    .clone()
                    .select("mkAirlockQubeBuilders")
                    .call(system)
                    .select("mkNixNativeDomain")
                    .call(request)
            });

            (name, factory)
        });

        (
            vec![
                ("networkDebug", false.into()),
                ("modulesDirectory", NixValue::null()),
                ("airlockApps", NixValue::null()),
                ("extraVmSpecialArgs", nix_record! {}),
            ],
            NixValue::record(factories).merge_attrs(nix_record! {
                "gpu": gpu_probe(&arguments),
            }),
        )
    })
}

/// Select resources and modules before constructing the system and all its boot artifacts.
fn request(inputs: &args::Inputs, base: NixValue, display: Display) -> NixValue {
    let standalone = matches!(display, Display::Standalone);
    let mut modules = Vec::new();
    if standalone {
        modules.push(crate::vm_modules::amd_panel());
        modules.push(crate::components::desktop::expression());
    }

    modules.push(configuration(display));

    let request = base.clone().merge_attrs(nix_record! {
        "configurationName": display.configuration_name(),
        "modules": NixValue::list(modules),
        "extraSpecialArgs": nix_record! {
            "airlockSupport": inputs.airlock_support(),
        },
    });
    if !standalone {
        return request;
    }

    // A passed-through GPU needs HVM and a fixed memory allocation without a virtual video device.
    request.merge_attrs(nix_record! {
        "prefs": nix_record! {
            "autostart": false,
            "guivm": NixValue::null(),
            "audiovm": NixValue::null(),
            "virt_mode": "hvm",
            "memory": 4096_i64,
            "maxmem": 4096_i64,
            "vcpus": 4_i64,
        },
        "features": nix_record! {
            "video-model": "none",
            "airlock-role": "sys-gui",
        },
        "services": nix_record! {
            "guivm": true,
            "guivm-gui-agent": false,
        },
        "devices": nix_record! {
            "pci": NixValue::list([]),
        },
    })
}

/// Configure login, local application routing and physical graphics for the selected environment.
fn configuration(display: Display) -> NixValue {
    ContextualModule::new(|context| {
        let mut config = nix_record! {
            "networking": nix_record! {
                "hostName": "sys-gui",
            },
            "airlock": nix_record! {
                "sysGuiGuest": nix_record! {
                    "defaultApplicationVM": NixValue::null(),
                },
            },
        };
        let users = if matches!(display, Display::Minimal) {
            nix_record! {
                "users": nix_record! {
                    "user": nix_record! {
                        "initialPassword": "airlock",
                    },
                },
            }
        } else {
            let force = |value: NixValue| context.lib.clone().select("mkForce").call(value);
            nix_record! {
                "mutableUsers": force(false.into()),
                "users": nix_record! {
                    "user": nix_record! {
                        "initialPassword": force("password".into()),
                        "initialHashedPassword": force(NixValue::null()),
                    },
                },
            }
        };
        config = config.merge_attrs(nix_record! {
            "users": users,
        });

        if !matches!(display, Display::Minimal) {
            config = config.clone().merge_attrs(nix_record! {
                "airlock": config.select("airlock").merge_attrs(nix_record! {
                    "devDom0Terminal": nix_record! {
                        "guest": nix_record! {
                            "enable": true,
                        },
                    },
                }),
            });
        }

        if matches!(display, Display::Standalone) {
            let airlock = config.clone().select("airlock");
            config = config.merge_attrs(nix_record! {
                "airlock": airlock.clone().merge_attrs(nix_record! {
                    "sysGuiGuest": airlock.select("sysGuiGuest").merge_attrs(nix_record! {
                        "displayMode": "physical-amd-lab",
                        "physicalDesktopOnBoot": true,
                    }),
                }),
                "hardware": nix_record! {
                    "enableRedistributableFirmware": true,
                    "graphics": nix_record! {
                        "enable": true,
                    },
                },
                "services": nix_record! {
                    "xserver": nix_record! {
                        "videoDrivers": NixValue::list(["amdgpu".into()]),
                    },
                },
                "boot": nix_record! {
                    "kernelModules": NixValue::list(["amdgpu".into()]),
                },
                "environment": nix_record! {
                    "systemPackages": NixValue::list([
                        context.pkgs.clone().select("pciutils"),
                        context.pkgs.select("mesa-demos"),
                    ]),
                },
            });
        }

        ModuleBody::new(config)
    })
    .into_expression()
}

/// Build the isolated GPU diagnostic VM, leaving device assignment to the hardware configuration.
fn gpu_probe(inputs: &NixValue) -> NixValue {
    let workspace = airlock_build::Workspace::new(rusix::interop::NixPath::from_expression(
        inputs.clone().select("airlockApps"),
    ));
    let module = ContextualModule::new(|context| {
        let service = airlock_build::Application::VmService.build(&context.pkgs, &workspace);

        ModuleBody::new(nix_record! {
            "networking": nix_record! {
                "hostName": "sys-gpu",
            },
            "hardware": nix_record! {
                "graphics": nix_record! {
                    "enable": true,
                },
            },
            "environment": nix_record! {
                "systemPackages": NixValue::list([
                    service.as_expression(),
                    context.pkgs.clone().select("mesa-demos"),
                    context.pkgs.clone().select("vulkan-tools"),
                    context.pkgs.select("pciutils"),
                ]),
            },
            // Render-node access grants neither Qubes administration nor device assignment.
            "users": nix_record! {
                "users": nix_record! {
                    "user": nix_record! {
                        "extraGroups": NixValue::list(["render".into()]),
                    },
                },
            },
        })
        .key("airlock.vm.gpu-probe")
    })
    .into_expression();

    NixValue::function(|system| {
        inputs
            .clone()
            .select("mkAirlockQubeBuilders")
            .call(system)
            .select("mkNixNativeDomain")
            .call(nix_record! {
                "name": "sys-gpu",
                "configurationName": "airlock-domain-sys-gpu",
                "guestRole": "base",
                "kernelName": inputs.clone().select("airlockQubesVmKernelName"),
                "modules": NixValue::list([module]),
                "label": "red",
                "netvm": NixValue::null(),
                "prefs": nix_record! {
                    "autostart": false,
                    "guivm": NixValue::null(),
                    "memory": 2048_i64,
                    "maxmem": 2048_i64,
                    "vcpus": 2_i64,
                    "virt_mode": "hvm",
                },
                "features": nix_record! {
                    "airlock-role": "sys-gpu",
                    "airlock-gpu-experiment": "1",
                    "servicevm": "1",
                    "gui": "0",
                },
                "services": nix_record! {
                    "network-manager": false,
                },
                "devices": nix_record! {
                    "pci": NixValue::list([]),
                },
            })
    })
}
