//! Assemble one interactive QEMU machine from the normal typed authoring output.
//! The image includes the VM artifacts consumed by the existing boot setup service.

use super::Build;
use rusix::{
    interop::{NixExpression, NixPath, raw::NixValue},
    nix_record, nix_text,
    nixos::{ContextualModule, ModuleBody},
};

/// Build the normal QEMU lab release without copying VM payloads into dom0.
pub(super) fn configuration(build: &Build) -> NixValue {
    host(build, entries(build, "x86_64-linux".into()), None)
}

/// Prepare the initial VM pool and state only when assembling a fresh disk image.
pub(super) fn image(build: &Build) -> NixValue {
    entries(build, "x86_64-linux".into()).bind(|entries| {
        crate::image::prepared_store(
            &build.pkgs("x86_64-linux".into()),
            &build.workspace,
            entries.clone(),
            seed_inputs().select("airlockMachineOfflineInputs"),
        )
        .bind(|prepared| host(build, entries, Some(prepared)))
    })
}

/// Share the authored host and VM graph between ordinary releases and the initial carrier image.
fn host(build: &Build, entries: NixValue, prepared: Option<NixValue>) -> NixValue {
    let generated = NixValue::builtin("import").call(
        build
            .source
            .join_relative("generated/qemu-lab/default.nix")
            .unwrap(),
    );
    entries.bind(|entries| {
        let stores = prepared.as_ref().map_or_else(|| nix_record! {}, |prepared| {
            NixValue::builtin("mapAttrs")
                .call(NixValue::function(|name| NixValue::function(|_| {
                    nix_text!("{descriptors}/{name}", descriptors = prepared.clone().select("descriptors"), name = name.clone()).into()
                })))
                .call(entries.clone())
        });
        let machine = crate::profiles::qemu_lab::machine().expect("valid QEMU lab");
        let domains = NixValue::record(machine.vms().map(|vm| (
            vm.name.as_str(),
            crate::assembly::materialize(entries.clone().select(vm.name.as_str()), &stores, vm.name.as_str()),
        )));
        let kernel = build.kernel("x86_64-linux".into());
        let host = generated.clone().select("hostModules").call(nix_record! {
            "lib": build.lib.clone(),
            "airlockConfigDomains": domains,
            "airlockKernels": NixValue::record([(crate::vm_build::KERNEL_NAME, nix_record! {
                "source": kernel.clone().select("package").to_text(),
            })]),
            "airlockSupport": build.source.clone(),
            "airlockApps": build.workspace.root(),
        });
        let identity = super::super::source_identity(&build.inputs.clone().select("self"));
        let release = crate::release::module(&crate::release::Build {
            source: build.source.clone(), workspace: build.workspace.clone(), entries: entries.clone(),
            metadata: identity.clone().merge_attrs(nix_record! {
                "lockHash": NixValue::builtin("hashFile").call("sha256").call(build.file("flake.lock")),
            }),
        });
        let mut modules = vec![
            build.output("nixosModules.dom0"), build.shared.clone().select("profiles.development"),
            settings(&identity, &build.source), release,
            nix_record! { "system": nix_record! { "extraDependencies": NixValue::list([kernel.clone().select("package")]) } },
        ];
        if let Some(prepared) = prepared {
            modules.push(crate::image::local_module(&build.workspace, prepared));
        }
        build.lib.clone().select("nixosSystem").call(nix_record! {
            "system": "x86_64-linux",
            "specialArgs": nix_record! {
                "airlockQubeKernel": kernel,
                "airlockAppsSource": build.workspace.root(),
                "airlockConfigInputs": build.configuration_inputs(),
            },
            "modules": NixValue::concat_lists([NixValue::list(modules), host]),
        })
    })
}

/// Select the lab's source identity and the second virtual NIC already provided by the runner.
fn settings(identity: &NixValue, source: &NixPath) -> NixValue {
    ContextualModule::new(|context| {
        let force = |value: NixValue| context.lib.clone().select("mkForce").call(value);
        ModuleBody::new(nix_record! {
            "image": nix_record! {
                "baseName": force("airlock-qemu-lab".into()),
            },
            "airlock": nix_record! {
                "machineDeployment": nix_record! {
                    "profile": force("qemu-lab".into()),
                    "initialSource": NixValue::if_else(
                        identity.clone().select("dirty"),
                        NixValue::null(),
                        nix_record! {
                            "revision": identity.clone().select("revision"),
                            "lockHash": NixValue::builtin("hashFile").call("sha256")
                                .call(source.join_relative("flake.lock").unwrap()),
                        },
                    ),
                },
                "qubes": nix_record! {
                    "domains": nix_record! {
                        "sys-net": nix_record! {
                            "devices": nix_record! {
                                "pci": NixValue::list([nix_record! {
                                    "backend": "dom0",
                                    "id": "00_03.0",
                                    "match": "port",
                                    "mode": "required",
                                    "options": nix_record! {
                                        "no-strict-reset": true,
                                    },
                                }]),
                            },
                        },
                    },
                },
            },
        })
        .key("airlock.host.qemu-lab")
    })
    .into_expression()
}

/// Expose the exact guest systems used by the QEMU lab for normal guest admission.
pub(super) fn entries(build: &Build, system: NixValue) -> NixValue {
    let directory = build.source.join_relative("generated/qemu-lab").unwrap();
    let generated =
        NixValue::builtin("import").call(directory.join_relative("default.nix").unwrap());
    let factories = generated.clone().select("builders").call(nix_record! {
        "lib": build.lib.clone(),
        "mkAirlockQubeBuilders": build.shared.clone().select("builders"),
        "airlockQubesVmKernelName": crate::vm_build::KERNEL_NAME,
        "airlockApps": build.workspace.root(),
        "airlockSupport": build.source.clone(),
        "modulesDirectory": directory,
        "extraVmSpecialArgs": seed_inputs(),
    });
    NixValue::builtin("mapAttrs")
        .call(NixValue::function(|name| {
            NixValue::function(|factory| {
                factory.call(system.clone()).merge_attrs(nix_record! {
                    "preparedDomainName": name.clone(),
                })
            })
        }))
        .call(factories)
}

/// Reuse the production source seed inputs while keeping image-only paths outside machine configuration.
fn seed_inputs() -> NixValue {
    let archive = NixValue::builtin("getEnv").call("AIRLOCK_MACHINE_SEED_ARCHIVE");
    let offline = NixValue::builtin("getEnv").call("AIRLOCK_MACHINE_OFFLINE_INPUTS");
    nix_record! {
        "airlockMachineSeedArchive": NixValue::if_else(
            archive.clone().equals(""), NixValue::null(),
            NixValue::builtin("path").call(nix_record! {
                "path": archive,
                "name": "airlock-machine-seed.tar.gz",
            }),
        ),
        "airlockMachineOfflineInputs": NixValue::if_else(
            offline.clone().equals(""), NixValue::null(),
            NixValue::builtin("fromJSON").call(NixValue::builtin("readFile").call(offline)),
        ),
    }
}
