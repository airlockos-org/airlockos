//! Supplies role-specific NixOS contributions while reusing Airlock's implementation modules.
//! Named open arguments let NixOS inject each VM's own library and package set.

use crate::inputs::args::Inputs;
use crate::model::{Role, VmSnapshot};
use rusix::interop::raw::{NixRepresentation, NixValue};
use rusix::interop::{NixAttrs, PackageFunction};
use rusix::nix_record;

/// Builds the inline NixOS module that supplies a VM's hostname and role settings.
/// Named arguments request each VM's own library or package set where needed;
/// outer builder inputs remain deferred until Nix evaluates the returned module.
pub(crate) fn inline(inputs: &Inputs, vm: &VmSnapshot) -> PackageFunction {
    let role = &vm.role;
    let name = &vm.name;
    let arguments: &[&str] = match role {
        Role::Controller { .. } => &["pkgs"],
        Role::Assistant { .. } => &["lib", "pkgs"],
        Role::Personal { .. } => &["lib"],
        _ => &[],
    };

    // NixOS supplies _module.args (notably pkgs) by inspecting named arguments.
    // A bare `args: ...` lambda cannot request the module's package set.
    PackageFunction::from_function_attrs_open(arguments.iter().copied(), |module_arguments| {
        let hostname = NixAttrs::from_expression(nix_record! {
            "networking": nix_record! {
                "hostName": name.as_str(),
            },
        });

        let config = match role {
            Role::NetworkDriver { .. } => {
                let debug = nix_record! {
                    "airlock": nix_record! {
                        "qubeGuest": nix_record! {
                            "allowQrexecUserSelection": true,
                        },
                    },
                    "systemd": nix_record! {
                        "services": nix_record! {
                            "NetworkManager": nix_record! {
                                "wantedBy": inputs.lib.mk_force().call(NixValue::list([])),
                            },
                        },
                    },
                };

                hostname.merge(
                    inputs
                        .lib
                        .optional_attrs()
                        .call(inputs.network_debug())
                        .call(debug),
                )
            }
            Role::Service
            | Role::Isolated { .. }
            | Role::Firewall { .. }
            | Role::Command { .. } => hostname,
            Role::Gui {
                default_application,
                ..
            } => hostname.merge(NixAttrs::from_expression(nix_record! {
                "airlock": nix_record! {
                    "sysGuiGuest": nix_record! {
                        "defaultApplicationVM": default_application.as_str(),
                    },
                },
                "users": nix_record! {
                    "users": nix_record! {
                        "user": nix_record! {
                            "initialPassword": "airlock",
                        },
                    },
                },
            })),
            Role::Controller { .. } => {
                let workspace = airlock_build::Workspace::new(inputs.airlock_apps());
                let package = |application: airlock_build::Application| {
                    application.build(&module_arguments.clone().select("pkgs"), &workspace)
                };

                hostname.merge(NixAttrs::from_expression(nix_record! {
                    "airlock": nix_record! {
                        "qubeGuest": nix_record! {
                            "configRepoPath": "/home/user/dev/airlockos-machine",
                            "configNixPackage": package(airlock_build::Application::ControllerService),
                        },
                        "appGui": nix_record! {
                            "scale": inputs.lib.mk_default().call(3_i64),
                        },
                    },
                    "nix": nix_record! {
                        "settings": nix_record! {
                            "max-jobs": 1_i64,
                            "sandbox": true,
                        },
                    },
                    "hardware": nix_record! {
                        "graphics": nix_record! {
                            "enable": true,
                        },
                    },
                    "environment": nix_record! {
                        "systemPackages": NixValue::list([
                            package(airlock_build::Application::ControllerGui).as_expression()
                        ]),
                        "etc": nix_record! {
                            "airlock/ctrl-app-source": nix_record! {
                                "source": airlock_build::Workspace::new(inputs.airlock_apps()).root(),
                            },
                        },
                    },
                }))
            }
            Role::Personal { .. } | Role::Assistant { .. } => {
                // The original personal module uses its own module-system lib;
                // preserve that distinction from the outer factory's lib.
                let default = module_arguments.clone().select("lib.mkDefault").call(3_i64);
                let mut airlock: NixAttrs = NixAttrs::from_expression(nix_record! {
                    "appGui": nix_record! {
                        "scale": default,
                    },
                });
                if matches!(role, Role::Assistant { .. }) {
                    airlock = airlock.merge(NixAttrs::from_expression(nix_record! {
                        "qubeGuest": nix_record! {
                            "configNixPackage": airlock_build::Application::Cli.build(
                                &module_arguments.select("pkgs"),
                                &airlock_build::Workspace::new(inputs.airlock_apps()),
                            ),
                        },
                    }));
                }

                hostname.merge(NixAttrs::from_expression(nix_record! {
                    "airlock": airlock,
                }))
            }
        };

        (Vec::<(&str, NixValue)>::new(), config.as_expression())
    })
}

/// Supplies the USB lab GUI's account, hardware and display configuration.
/// Host-side PCI assignment stays with the machine hardware profile. The final
/// element contains display settings, appended after desktop modules during lowering.
pub(crate) fn physical_gui(inputs: &Inputs, vm: &VmSnapshot) -> Vec<NixValue> {
    let Role::Gui {
        default_application,
        ..
    } = &vm.role
    else {
        unreachable!("physical GUI modules require a GUI role");
    };

    let force = |value: NixValue| inputs.lib.mk_force().call(value);
    let login = nix_record! {
        "users": nix_record! {
            "mutableUsers": force(false.into()),
            "users": nix_record! {
                "user": nix_record! {
                    "initialPassword": force("password".into()),
                    "initialHashedPassword": force(NixValue::null()),
                },
            },
        },
    };

    let configuration = PackageFunction::from_function_attrs_open(["pkgs"], |arguments| {
        let pkgs = arguments.select("pkgs");
        let config = nix_record! {
            "networking": nix_record! {
                "hostName": vm.name.as_str(),
            },
            "airlock": nix_record! {
                "sysGuiGuest": nix_record! {
                    "displayMode": "physical-amd-lab",
                    "physicalDesktopOnBoot": true,
                    "defaultApplicationVM": default_application.as_str(),
                    "usrAssistantTailscaleShortcut": nix_record! {
                        "enable": true,
                    },
                },
                "devDom0Terminal": nix_record! {
                    "guest": nix_record! {
                        "enable": false,
                    },
                },
            },
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
                "systemPackages": NixValue::list([pkgs.clone().select("pciutils"), pkgs.select("mesa-demos")]),
            },
        };

        (Vec::<(&str, NixValue)>::new(), config)
    });

    vec![login, amd_panel(), configuration.as_expression()]
}

/// Disable panel self-refresh on the lab's internal AMD display to avoid DMCUB/flip stalls.
/// This contributes one kernel argument without replacing Qubes boot parameters.
pub(crate) fn amd_panel() -> NixValue {
    nix_record! {
        "boot": nix_record! {
            "kernelParams": NixValue::list(["amdgpu.dcdebugmask=0x10".into()]),
        },
    }
}
