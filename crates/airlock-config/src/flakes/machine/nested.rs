//! Select explicit nested validation environments without changing the physical machine definition.

use super::Build;
use airlock_build::tools::Tool;
use rusix::{
    interop::raw::{NixRepresentation, NixValue},
    nix_record,
    nixos::{ContextualModule, ModuleBody},
};

/// Independent capabilities used by the existing nested integration environments.
#[derive(Default)]
struct Scenario {
    /// Forward the host display to a GUI VM.
    gui: bool,
    /// Install all bootstrap VMs and the controller workflow.
    controller: bool,
    /// Enable disposable-machine development access and the network proxy.
    development: bool,
    /// Keep network startup disabled for targeted firewall diagnosis.
    network_diagnostics: bool,
    /// Add an isolated GPU probe VM without physical assignments.
    gpu: bool,
    /// Start only the display relay, excluding the controller topology.
    minimal: bool,
    /// Allow the development VM to exercise its narrow pool-admission interface.
    admission: bool,
}

/// Export the physical host, nested scenarios and independently buildable VM systems.
pub(super) fn configurations(build: &Build, assembly: &NixValue) -> NixValue {
    let profiles = build.shared.clone().select("profiles");
    let mut configurations = vec![
        ("local-lab".to_owned(), super::local_lab::configuration(build)),
        (
            "test".to_owned(),
            build.lib.clone().select("nixosSystem").call(nix_record! {
                "system": "x86_64-linux",
                "modules": NixValue::list([build.output("nixosModules.dom0"), profiles.select("test")]),
            }),
        ),
        (
            "machine".to_owned(),
            assembly.clone().select("configuration").call(nix_record! {}),
        ),
    ];
    let local = super::local_lab::entries(build, "x86_64-linux".into());
    for vm in crate::profiles::local_lab::machine()
        .expect("valid local lab")
        .vms()
    {
        if matches!(vm.backend, crate::model::GuestBackend::Nixos) {
            configurations.push((
                format!("airlock-local-lab-domain-{name}", name = vm.name),
                local
                    .clone()
                    .select(vm.name.as_str())
                    .select("configuration"),
            ));
        }
    }
    for (name, scenario) in [
        (
            "vm-dev",
            Scenario {
                development: true,
                ..Scenario::default()
            },
        ),
        ("vm-release", Scenario::default()),
        (
            "vm-gui-dev",
            Scenario {
                gui: true,
                development: true,
                ..Scenario::default()
            },
        ),
        (
            "vm-gui-release",
            Scenario {
                gui: true,
                ..Scenario::default()
            },
        ),
        (
            "vm-gui-minimal",
            Scenario {
                gui: true,
                minimal: true,
                ..Scenario::default()
            },
        ),
        (
            "vm-gui-config-dev",
            Scenario {
                gui: true,
                controller: true,
                development: true,
                ..Scenario::default()
            },
        ),
        (
            "vm-gui-config-release",
            Scenario {
                gui: true,
                controller: true,
                ..Scenario::default()
            },
        ),
        (
            "vm-gui-config-network-debug",
            Scenario {
                gui: true,
                controller: true,
                development: true,
                network_diagnostics: true,
                ..Scenario::default()
            },
        ),
        (
            "vm-pool-admission-test",
            Scenario {
                gui: true,
                controller: true,
                development: true,
                admission: true,
                ..Scenario::default()
            },
        ),
        (
            "vm-gpu-lab",
            Scenario {
                gui: true,
                controller: true,
                development: true,
                gpu: true,
                ..Scenario::default()
            },
        ),
    ] {
        configurations.push((name.to_owned(), configuration(build, &scenario)));
    }
    for (name, display) in [
        ("sys-gui-usb", "hybrid"),
        ("sys-gui-usb-gui-lab", "standalone"),
        ("sys-gui-minimal", "minimal"),
        ("sys-gpu", "gpu"),
    ] {
        configurations.push((
            format!("airlock-domain-{name}"),
            build
                .shared
                .clone()
                .select("displays")
                .select(display)
                .call("x86_64-linux")
                .select("configuration"),
        ));
    }
    for name in [
        "sys-net",
        "sys-firewall",
        "usr-assistant",
        "sys-ctrl",
        "sys-gui",
    ] {
        configurations.push((
            format!("airlock-domain-{name}"),
            build
                .shared
                .clone()
                .select("bootstrap")
                .select(name)
                .call("x86_64-linux")
                .select("configuration"),
        ));
    }
    configurations.push((
        "airlock-domain-sys-net-network-debug".into(),
        build
            .shared
            .clone()
            .select("diagnostics.sys-net")
            .call("x86_64-linux")
            .select("configuration"),
    ));
    for (name, identity) in [("sys-gui-usb-lab", "sys-gui"), ("usr-home", "usr-home")] {
        configurations.push((
            format!("airlock-domain-{name}"),
            assembly
                .clone()
                .select("entries")
                .call("x86_64-linux")
                .call(nix_record! {})
                .select(identity)
                .select("configuration"),
        ));
    }

    NixValue::record(configurations)
}

/// Assemble scenario-specific domains and explicit module contributions around upstream Xen.
fn configuration(build: &Build, scenario: &Scenario) -> NixValue {
    let system: NixValue = "x86_64-linux".into();
    let profiles = build.shared.clone().select("profiles");
    let mut special = nix_record! {
        "airlockAppsSource": build.workspace.root(),
    };
    let mut modules = vec![
        build.output("nixosModules.dom0"),
        profiles
            .clone()
            .select(if scenario.gui { "vmGui" } else { "vm" }),
    ];
    if scenario.controller {
        let mut domains = build.domains(system.clone(), scenario.network_diagnostics);
        if scenario.gpu {
            domains = domains.merge_attrs(nix_record! {
                "sys-gpu": crate::assembly::materialize(
                    build
                        .shared
                        .clone()
                        .select("displays.gpu")
                        .call(system.clone()),
                    &nix_record! {},
                    "",
                ),
            });
        }
        if scenario.admission {
            let entry = build
                .shared
                .clone()
                .select("bootstrap.usr-assistant")
                .call(system.clone());
            let domain = entry.clone().select("domain");
            let entry = entry.merge_attrs(nix_record! {
                "domain": domain.clone().merge_attrs(nix_record! {
                    "prefs": domain.clone().select("prefs").merge_attrs(nix_record! {
                        "autostart": false,
                    }),
                    "features": NixValue::builtin("removeAttrs")
                        .call(domain.select("features"))
                        .call(NixValue::list(["airlock-auto-network-pci".into()])),
                }),
            });
            domains = domains.merge_attrs(nix_record! {
                "usr-assistant": crate::assembly::materialize(entry, &nix_record! {}, ""),
            });
        }
        special = special.merge_attrs(nix_record! {
            "airlockQubeKernel": build.kernel(system.clone()),
            "airlockConfigDomains": domains,
            "airlockConfigInputs": build.configuration_inputs(),
        });
        modules.push(profiles.clone().select("configSystem"));
    }
    if scenario.minimal {
        special = special.merge_attrs(nix_record! {
            "airlockQubeKernel": build.kernel(system.clone()),
            "airlockGuiDomain": crate::assembly::materialize(
                build
                    .shared
                    .clone()
                    .select("displays.minimal")
                    .call(system.clone()),
                &nix_record! {},
                "",
            ),
        });
        modules.push(profiles.clone().select("guiMinimal"));
    }
    if scenario.development {
        modules.push(profiles.select("development"));
    }
    if scenario.admission {
        modules.push(
            ContextualModule::new(|context| {
                ModuleBody::new(nix_record! {
                    "airlock": nix_record! {
                        "poolAdmission": nix_record! {
                            "enable": true,
                            "caller": "usr-assistant",
                            "targets": NixValue::list(["usr-assistant".into()]),
                        },
                    },
                    "environment": nix_record! {
                        "systemPackages": NixValue::list([Tool::Dom0
                            .build(&context.pkgs, &build.workspace, &build.source)
                            .as_expression()]),
                        "etc": nix_record! {
                            "airlock/machine-profile": nix_record! {
                                "text": "vm-pool-admission-test\n",
                            },
                        },
                    },
                })
            })
            .into_expression(),
        );
    }
    if scenario.controller && scenario.development {
        // QEMU exposes the first virtio NIC for host SSH and the second for the network VM.
        modules.push(nix_record! {
            "airlock": nix_record! {
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
        });
    }

    build.lib.clone().select("nixosSystem").call(nix_record! {
        "system": system,
        "specialArgs": special,
        "modules": NixValue::list(modules),
    })
}
