//! Assemble the machine flake from native VM, host, package and release constructors.

mod nested;

mod qemu_lab;

mod packages;

mod checks;

mod uplink;

mod input;

use airlock_build::{Workspace, overlays};
use rusix::{
    interop::{
        NixExpression, NixPath,
        raw::{NixRepresentation, NixValue},
    },
    nix_record,
    nixos::{ContextualModule, ModuleBody},
};

/// Keep input declarations static so Nix can resolve and lock them before evaluating outputs.
pub(super) fn inputs(revision: &str) -> NixValue {
    nix_record! {
        "hermit-xen": crate::hermit_build::input(),
        "airlock-apps": nix_record! {
            "flake": false,
            "type": "git",
            "url": "https://github.com/airlockos-org/airlockos.git",
            "dir": "crates",
            "ref": "main",
            "rev": revision,
        },
        "nixpkgs": nix_record! {
            "url": "github:NixOS/nixpkgs/nixos-unstable",
        },
        "nixpkgs-libvirt_10_5": nix_record! {
            "url": "github:NixOS/nixpkgs/e0464e47880a69896f0fb1810f00e0de469f770a",
        },
        "nixos-qubes": nix_record! {
            // Share the application's Git snapshot so compatibility fixes cannot drift from it.
            "type": "git",
            "url": "https://github.com/airlockos-org/airlockos.git",
            "dir": "crates/vendor/nixos-qubes",
            "ref": "main",
            "rev": revision,
            "inputs": nix_record! {
                "nixpkgs": nix_record! {
                    "follows": "nixpkgs",
                },
                "nixpkgs-libvirt_10_5": nix_record! {
                    "follows": "nixpkgs-libvirt_10_5",
                },
            },
        },
    }
}

/// Source and package identities shared by every output of this machine flake.
struct Build {
    /// Complete flake input set, including self metadata and upstream Qubes.
    inputs: NixValue,
    /// Authoritative NixOS library from the pinned nixpkgs input.
    lib: NixValue,
    /// Machine-owned integration assets and generated authoring exports.
    source: NixPath,
    /// Admitted native application source workspace.
    workspace: Workspace,
    /// Lazy platform package sets, VM-builder functions and finalized VM factory sets.
    shared: NixValue,
}

impl Build {
    /// Return the machine flake's recursive output reference.
    fn output(&self, path: &str) -> NixValue {
        self.inputs.clone().select("self").select(path)
    }

    /// Select host packages with the pinned upstream overlays and Airlock integration patches.
    fn pkgs(&self, system: NixValue) -> NixValue {
        NixValue::builtin("getAttr")
            .call(system)
            .call(self.shared.clone().select("pkgs"))
    }

    /// Resolve one source-relative implementation asset.
    fn file(&self, path: &str) -> NixValue {
        self.source.join_relative(path).unwrap().as_expression()
    }

    /// Keep the VM kernel identity identical in descriptors, Qubes setup and exported packages.
    fn kernel(&self, system: NixValue) -> NixValue {
        nix_record! {
            "name": crate::vm_build::KERNEL_NAME,
            "package": NixValue::builtin("getAttr")
                .call(system)
                .call(self.output("packages"))
                .select("airlock-qubes-vm-kernel"),
        }
    }

    /// Bind the native factories to a target platform without realizing their artifacts.
    fn bootstrap_entries(&self, system: NixValue, diagnostics: bool) -> NixValue {
        let factories = self.shared.clone().select(if diagnostics {
            "diagnostics"
        } else {
            "bootstrap"
        });

        NixValue::builtin("mapAttrs")
            .call(NixValue::function(|_| {
                NixValue::function(|factory| factory.call(system))
            }))
            .call(factories)
    }

    /// Lower VM artifact dependencies to the format installed by the Qubes topology service.
    fn domains(&self, system: NixValue, diagnostics: bool) -> NixValue {
        NixValue::builtin("mapAttrs")
            .call(NixValue::function(|_| {
                NixValue::function(|entry| crate::assembly::materialize(entry, &nix_record! {}, ""))
            }))
            .call(self.bootstrap_entries(system, diagnostics))
    }

    /// Filter configuration inputs to machine assets that the isolated builder actually needs.
    fn configuration_inputs(&self) -> NixValue {
        let source = self.source.as_expression();
        let filter = NixValue::function(|path| {
            NixValue::function(|_| {
                let relative = self
                    .lib
                    .clone()
                    .select("removePrefix")
                    .call(rusix::nix_text!("{source}/", source = source.clone()))
                    .call(path.to_text());
                [
                    "assets",
                    "bootstrap",
                    "scripts",
                    "patches",
                    "generated",
                    "src",
                    ".cargo",
                ]
                .into_iter()
                .fold(
                    NixValue::builtin("elem")
                        .call(relative.clone())
                        .call(NixValue::list([
                            "flake.nix".into(),
                            "flake.lock".into(),
                            "Cargo.toml".into(),
                            "Cargo.lock".into(),
                            "application-revision".into(),
                        ])),
                    |condition, directory| {
                        condition.or(relative.clone().equals(directory)).or(self
                            .lib
                            .clone()
                            .select("hasPrefix")
                            .call(format!("{directory}/"))
                            .call(relative.clone()))
                    },
                )
            })
        });
        let support = self
            .lib
            .clone()
            .select("cleanSourceWith")
            .call(nix_record! {
                "name": "airlock-support-config-input-source",
                "src": source,
                "filter": filter,
            });

        nix_record! {
            "nixpkgs": self.inputs.clone().select("nixpkgs").to_text(),
            "nixpkgsLibvirt105": self.inputs.clone().select("nixpkgs-libvirt_10_5").to_text(),
            "nixosQubes": self.inputs.clone().select("nixos-qubes").to_text(),
            "airlockSupport": support.to_text(),
            "airlockApps": self.workspace.root().as_expression().to_text(),
        }
    }

    /// Compose upstream Qubes, the Airlock host services and native topology validation.
    fn dom0(&self) -> NixValue {
        ContextualModule::new(|context| {
            ModuleBody::new(nix_record! {
                "nixpkgs": nix_record! {
                    "overlays": context.lib.select("mkAfter").call(NixValue::list([
                        self.output("overlays.airlockApps"),
                        self.output("overlays.airlockQubesGuiWindowState"),
                        self.output("overlays.airlockImageBuildTools"),
                        self.output("overlays.airlockQubesStartup"),
                    ])),
                },
            })
            .key("airlock.machine.dom0")
            .import_value(self.inputs.clone().select("nixos-qubes.nixosModules.qubes"))
            .import_value(
                self.shared
                    .clone()
                    .select("modules.dom0")
                    .call(self.workspace.root()),
            )
            .import_value(
                self.shared
                    .clone()
                    .select("modules.topology")
                    .call(self.workspace.root()),
            )
        })
        .into_expression()
    }
}

/// Build outputs from a single lazy scope shared by machine assembly and artifact exports.
pub(super) fn outputs() -> NixValue {
    NixValue::function_attrs_open(
        [
            "self",
            "nixpkgs",
            "nixpkgs-libvirt_10_5",
            "nixos-qubes",
            "airlock-apps",
            "hermit-xen",
        ],
        |inputs| {
            let source = NixPath::from_source_text(
                inputs
                    .clone()
                    .select("self")
                    .to_text()
                    .into_expr::<String>(),
            );
            let workspace = Workspace::new(NixPath::from_expression(
                inputs.clone().select("airlock-apps"),
            ));
            let lib = inputs.clone().select("nixpkgs.lib");
            let constructors = nix_record! {
                "modules": crate::vm::module_constructors().call(source.clone()),
                "template": crate::vm_build::constructors().as_expression(),
                "windowState": overlays::gui_window_state(&workspace),
                "imageTools": overlays::image_tools(&workspace),
                "qubesStartup": overlays::qubes_startup(),
                "identity": super::source_identity(&inputs.clone().select("self")),
            };
            let result = constructors.bind(|constructors| {
                let apps_overlay = NixValue::function(|_| {
                    NixValue::function(|_| {
                        nix_record! {
                            "airlockAppsSource": workspace.root().as_expression().to_text(),
                        }
                    })
                });
                // A function is shared, but applying it repeatedly does not memoize
                // its result. Keep one lazy package set per supported platform.
                let packages = super::systems(|system| {
                    NixValue::builtin("import")
                        .call(inputs.clone().select("nixpkgs"))
                        .call(nix_record! {
                            "system": system,
                            "overlays": NixValue::list([
                                inputs.clone().select("nixos-qubes.overlays.default"),
                                apps_overlay.clone(),
                                constructors.clone().select("windowState"),
                                overlays::codex(),
                                overlays::memory_accounting(&workspace),
                                constructors.clone().select("imageTools"),
                                constructors.clone().select("qubesStartup"),
                            ]),
                            "config": nix_record! {
                                "allowUnfreePredicate": super::allow_unfree(&lib),
                            },
                        })
                });
                let builders = NixValue::function(|system| {
                    constructors.clone().select("template")
                        .call(nix_record! {
                            "nixpkgs": inputs.clone().select("nixpkgs"),
                            "system": system,
                            "nixpkgsLibvirt105Source": inputs.clone()
                                .select("nixpkgs-libvirt_10_5")
                                .to_text(),
                            "airlockSupport": source.clone(),
                            "airlockAppsSource": workspace.root(),
                            "nixosQubesSource": inputs.clone().select("nixos-qubes").to_text(),
                            "hermitXen": inputs.clone().select("hermit-xen"),
                            "applicationRevision": inputs.clone().select("airlock-apps.rev"),
                        })
                });
                builders.bind(|builders| {
                    let factory_inputs = nix_record! {
                        "lib": lib.clone(),
                        "mkAirlockQubeBuilders": builders.clone(),
                        "airlockQubesVmKernelName": crate::vm_build::KERNEL_NAME,
                        "airlockApps": workspace.root(),
                        "airlockSupport": source.clone(),
                    };
                    let factories = nix_record! {
                        "pkgs": packages,
                        "builders": builders,
                        "modules": constructors.clone().select("modules"),
                        "profiles": constructors.clone().select("modules")
                            .select("profiles")
                            .call(workspace.root()),
                        "bootstrap": NixValue::builtin("import")
                            .call(
                                source
                                    .join_relative("generated/bootstrap/default.nix")
                                    .unwrap(),
                            )
                            .select("builders")
                            .call(factory_inputs.clone().merge_attrs(nix_record! {
                                "modulesDirectory": source.join_relative("generated/bootstrap").unwrap(),
                            })),
                        "diagnostics": NixValue::builtin("import")
                            .call(
                                source
                                    .join_relative("generated/bootstrap/default.nix")
                                    .unwrap(),
                            )
                            .select("builders")
                            .call(factory_inputs.clone().merge_attrs(nix_record! {
                                "networkDebug": true,
                                "modulesDirectory": source.join_relative("generated/bootstrap").unwrap(),
                            })),
                        "displays": crate::displays::builders().as_expression()
                            .call(factory_inputs.clone()),
                    };

                    factories.bind(|shared| {
                        let build = Build {
                            inputs: inputs.clone(),
                            lib: lib.clone(),
                            source: source.clone(),
                            workspace: workspace.clone(),
                            shared,
                        };
                        let assembly = NixValue::builtin("import")
                            .call(
                                source
                                    .join_relative("generated/machine/default.nix")
                                    .unwrap(),
                            )
                            .select("assembly")
                            .call(
                                factory_inputs.merge_attrs(nix_record! {
                                    "modulesDirectory": source.join_relative("generated/machine").unwrap(),
                                    "kernelPackage": build.kernel("x86_64-linux".into()).select("package"),
                                    "dom0Module": build.output("nixosModules.dom0"),
                                    "hybridGui": build.shared.clone().select("displays.hybrid"),
                                    "standaloneGui": build.shared.clone().select("displays.standalone"),
                                    "revision": constructors.clone()
                                        .select("identity")
                                        .select("revision"),
                                    "timestamp": constructors.clone().select("identity").select("timestamp"),
                                    "machineSource": NixValue::if_else(
                                        constructors.clone().select("identity").select("dirty").equals(false),
                                        nix_record! {
                                            "revision": constructors.clone()
                                                .select("identity")
                                                .select("revision"),
                                            "lockHash": NixValue::builtin("hashFile")
                                                .call("sha256")
                                                .call(build.file("flake.lock")),
                                        },
                                        NixValue::null(),
                                    ),
                                }),
                            );

                        assembly.bind(|assembly| nix_record! {
                            "lib": nix_record! {
                                "airlockSystem": NixValue::builtin("import")
                                    .call(build.file("generated/schemas.nix"))
                                    .select("system")
                                    .call(lib.clone()),
                                "airlockTopology": NixValue::builtin("import")
                                    .call(build.file("generated/schemas.nix"))
                                    .select("topology")
                                    .call(lib),
                                "airlockQubeTemplate": constructors.clone().select("template"),
                                "mkMachineGuestEntries": assembly.clone().select("entries"),
                                "machineGuestEntries": NixValue::function(|system| {
                                    assembly.clone().select("entries").call(system).call(nix_record! {})
                                }),
                                "mkMachineConfiguration": assembly.clone().select("configuration"),
                                "bootstrapEntries": NixValue::function(|system| {
                                    build.bootstrap_entries(system, false)
                                }),
                            },
                            "airlock": nix_record! {
                                "configInputs": build.configuration_inputs(),
                                "tests": nix_record! {
                                    "uplinkHotplug": uplink::fixture(&build),
                                    "inputReceiver": input::fixture(&build),
                                },
                            },
                            "overlays": nix_record! {
                                "airlockApps": exported_overlay(&build, apps_overlay),
                                "airlockImageBuildTools": exported_overlay(&build, constructors.clone().select("imageTools")),
                                "airlockQubesGuiWindowState": exported_overlay(&build, constructors.clone().select("windowState")),
                                "airlockQubesStartup": exported_overlay(&build, constructors.clone().select("qubesStartup")),
                            },
                            "nixosModules": nix_record! {
                                "dom0": build.dom0(),
                                "default": build.output("nixosModules.dom0"),
                            },
                            "nixosConfigurations": nested::configurations(&build, &assembly),
                            "packages": super::systems(|system| packages::outputs(&build, system)),
                            "checks": super::systems(|system| checks::outputs(&build, system)),
                        })
                    })
                })
            });

            (Vec::<(&str, NixValue)>::new(), result)
        },
    )
}

/// Retain upstream's conventional final/prev parameters for Nix's exported-overlay checks.
fn exported_overlay(build: &Build, overlay: NixValue) -> NixValue {
    build
        .lib
        .clone()
        .select("composeManyExtensions")
        .call(NixValue::list([overlay]))
}
