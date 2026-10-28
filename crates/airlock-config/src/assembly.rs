//! Assemble VM artifacts and host systems without exposing build wiring as module arguments.

use crate::model::MachineSnapshot;
use airlock_nix_core::identity::GuestName as VmName;
use rusix::{
    interop::{
        NixExpression, NixPath, PackageFunction,
        raw::{NixRepresentation, NixValue},
    },
    nix_record, nix_text,
};
use std::collections::BTreeMap;

/// Source and artifact dependencies captured by the physical host's module closure.
pub(crate) struct PhysicalBuild {
    /// Source tree containing machine integration assets.
    pub source: NixPath,
    /// Native application sources captured before NixOS evaluates the host module graph.
    pub workspace: airlock_build::Workspace,
    /// Materialized runtime descriptors, indexed by the snapshot's validated VM identities.
    pub domains: BTreeMap<VmName, NixValue>,
    /// Isolated graphics profile's descriptor; it is evaluated only when selected.
    pub standalone_gui: NixValue,
    /// Whether the caller requests the alternative graphics boot profile.
    pub alternatives: NixValue,
    /// Admitted machine source, including its lock hash, or null for uncommitted inputs.
    pub machine_source: NixValue,
    /// Boot menu revision and timestamp, which may describe the enclosing image project.
    pub boot_source: NixValue,
}

impl PhysicalBuild {
    /// Retrieve a descriptor for an identity already validated in this machine.
    pub fn domain(&self, name: &VmName) -> NixValue {
        self.domains[name].clone()
    }
}

/// Exports the machine constructor and VM artifacts from one shared build scope.
/// Platform, package builds and store locations remain deferred until Nix evaluation.
pub(crate) fn entry_points(machine: &MachineSnapshot) -> Result<PackageFunction, String> {
    if machine
        .vms()
        .filter(|vm| matches!(vm.role, crate::model::Role::Assistant { .. }))
        .count()
        != 1
    {
        return Err("the physical USB host requires exactly one development VM".into());
    }

    Ok(PackageFunction::from_function_attrs(
        [
            "lib",
            "mkAirlockQubeBuilders",
            "airlockQubesVmKernelName",
            "airlockSupport",
            "airlockApps",
            "modulesDirectory",
            "userModulesDirectory",
            "kernelPackage",
            "dom0Module",
            "hybridGui",
            "standaloneGui",
            "revision",
            "timestamp",
            "machineSource",
        ],
        |inputs| {
            let entries = NixValue::function(|system| {
                NixValue::function(|extra| {
                    let factories = crate::lowering::builders(machine)
                        .as_expression()
                        .call(nix_record! {
                            "lib": inputs.clone().select("lib"),
                            "mkAirlockQubeBuilders": inputs.clone().select("mkAirlockQubeBuilders"),
                            "airlockQubesVmKernelName": inputs.clone().select("airlockQubesVmKernelName"),
                            "airlockSupport": inputs.clone().select("airlockSupport"),
                            "airlockApps": inputs.clone().select("airlockApps"),
                            "modulesDirectory": inputs.clone().select("modulesDirectory"),
                            "userModulesDirectory": inputs.clone().select("userModulesDirectory"),
                            "extraVmSpecialArgs": extra,
                        });
                    let normal = factories.bind(|factories| {
                        NixValue::record(machine.vms().map(|vm| {
                            let entry = factories
                                .clone()
                                .select_segments([vm.name.as_str()])
                                .call(system.clone());
                            let entry = if vm.name == machine.host().unwrap().gui {
                                entry
                            } else {
                                entry.merge_attrs(nix_record! {
                                    "preparedDomainName": vm.name.as_str(),
                                })
                            };

                            (vm.name.as_str(), entry)
                        }))
                    });

                    normal.merge_attrs(nix_record! {
                        "sys-gui-hybrid": inputs.clone().select("hybridGui").call(system.clone()),
                        "sys-gui-standalone": inputs.clone().select("standaloneGui").call(system),
                    })
                })
            });

            let result = entries.bind(|entries| {
                nix_record! {
                    "entries": entries.clone(),
                    "configuration": configuration(machine, &inputs, entries),
                }
            });

            (vec![("userModulesDirectory", NixValue::null())], result)
        },
    ))
}

/// Materialize a VM's Qubes descriptor while retaining the selected store artifact dependency.
pub(crate) fn materialize(entry: NixValue, store_sources: &NixValue, name: &str) -> NixValue {
    entry.bind(|entry| {
        let domain = entry.clone().select("domain");
        let backend = domain.clone().select("backend");
        let store = backend.clone().select("store");
        let source = store_sources
            .clone()
            .attr_or(name, entry.clone().select("storeArtifact").to_text());

        let preferences = domain.clone().select("prefs");

        let linux = domain.clone().merge_attrs(nix_record! {
            "prefs": preferences.merge_attrs(nix_record! {
                "kernelopts": entry.clone().select("kernelopts"),
            }),
            "backend": backend.clone().merge_attrs(nix_record! {
                "system": backend.clone().select("system").merge_attrs(nix_record! {
                    "source": entry
                        .clone()
                        .select("configuration.config.system.build.toplevel")
                        .to_text(),
                    "sourceRef": NixValue::null(),
                }),
                "root": backend.clone().select("root").merge_attrs(nix_record! {
                    "source": nix_text!(
                        "{image}/root.img",
                        image = entry.clone().select("rootImage"),
                    ),
                    "sourceRef": NixValue::null(),
                }),
                "store": store.merge_attrs(nix_record! {
                    "source": source,
                    "sourceRef": NixValue::null(),
                }),
            }),
        });
        NixValue::if_else(backend.select("type").equals("hermit"), domain, linux)
    })
}

/// Build the physical system with caller-selected transport, hardware and source metadata.
fn configuration(machine: &MachineSnapshot, inputs: &NixValue, factories: NixValue) -> NixValue {
    NixValue::function_attrs_open(
        [
            "system",
            "storeSources",
            "includeRelease",
            "includeAlternativeGuiProfiles",
            "extraModules",
            "hardwareModules",
            "machineEntries",
            "extraSpecialArgs",
            "extraGuestSpecialArgs",
        ],
        |request| {
            let source = NixPath::from_expression(inputs.clone().select("airlockSupport"));
            let directory = NixPath::from_expression(inputs.clone().select("modulesDirectory"));
            let file = |path| source.join_relative(path).unwrap().as_expression();
            let defaults = vec![
                ("system", "x86_64-linux".into()),
                ("storeSources", nix_record! {}),
                ("includeRelease", true.into()),
                ("includeAlternativeGuiProfiles", true.into()),
                ("extraModules", NixValue::list([])),
                (
                    "hardwareModules",
                    NixValue::list([directory
                        .join_relative("hardware.nix")
                        .unwrap()
                        .as_expression()]),
                ),
                ("machineEntries", NixValue::null()),
                ("extraSpecialArgs", nix_record! {}),
                ("extraGuestSpecialArgs", nix_record! {}),
            ];
            let selected = request.clone().select("machineEntries");
            let entries = NixValue::if_else(
                selected.clone().equals(NixValue::null()),
                factories
                    .call(request.clone().select("system"))
                    .call(request.clone().select("extraGuestSpecialArgs")),
                selected,
            );
            let alternatives = request.clone().select("includeAlternativeGuiProfiles");
            let entries = NixValue::if_else(
                alternatives.clone(),
                entries.clone(),
                NixValue::builtin("removeAttrs")
                    .call(entries)
                    .call(NixValue::list([
                        "sys-gui-hybrid".into(),
                        "sys-gui-standalone".into(),
                    ])),
            );

            let result = entries.bind(|entries| {
                let stores = request.clone().select("storeSources");
                let descriptor = |name: &str| {
                    materialize(entries.clone().select_segments([name]), &stores, name)
                };
                let extra = request.clone().select("extraSpecialArgs");
                let build = PhysicalBuild {
                    source: source.clone(),
                    workspace: airlock_build::Workspace::new(NixPath::from_expression(
                        inputs.clone().select("airlockApps"),
                    )),
                    domains: machine
                        .vms()
                        .map(|vm| (vm.name.clone(), descriptor(vm.name.as_str())))
                        .collect(),
                    standalone_gui: descriptor("sys-gui-standalone"),
                    alternatives: alternatives.clone(),
                    machine_source: extra.clone().attr_or(
                        "airlockMachineSource",
                        inputs.clone().select("machineSource"),
                    ),
                    boot_source: nix_record! {
                        "revision": extra
                            .clone()
                            .attr_or("airlockSourceRevision", inputs.clone().select("revision")),
                        "timestamp": extra
                            .clone()
                            .attr_or("airlockSourceTimestamp", inputs.clone().select("timestamp")),
                    },
                };
                let host = crate::host::physical::module(machine.host().unwrap(), machine, &build)
                    .expect("validated physical machine");
                let release = crate::release::module(&crate::release::Build {
                    source: source.clone(),
                    workspace: build.workspace.clone(),
                    entries: entries.clone(),
                    metadata: build.boot_source.clone().merge_attrs(nix_record! {
                        "lockHash": extra.clone().attr_or(
                            "airlockSourceLockHash",
                            NixValue::builtin("hashFile")
                                .call("sha256")
                                .call(file("flake.lock")),
                        ),
                    }),
                });
                let special = nix_record! {
                    "airlockQubeKernel": nix_record! {
                        "name": inputs.clone().select("airlockQubesVmKernelName"),
                        "package": inputs.clone().select("kernelPackage"),
                    },
                    "airlockGuiDomain": NixValue::if_else(
                        alternatives.clone(),
                        descriptor("sys-gui-hybrid"),
                        build.domain(&machine.host().unwrap().gui),
                    ),
                    "airlockAppsSource": inputs.clone().select("airlockApps").to_text(),
                }
                .merge_attrs(extra);
                let modules = NixValue::concat_lists([
                    NixValue::list([inputs.clone().select("dom0Module"), host]),
                    NixValue::if_else(
                        request.clone().select("includeRelease"),
                        NixValue::list([release]),
                        NixValue::list([]),
                    ),
                    request.clone().select("hardwareModules"),
                    request.clone().select("extraModules"),
                ]);

                inputs.clone().select("lib.nixosSystem").call(nix_record! {
                    "system": request.clone().select("system"),
                    "specialArgs": special,
                    "modules": modules,
                })
            });

            (defaults, result)
        },
    )
}
