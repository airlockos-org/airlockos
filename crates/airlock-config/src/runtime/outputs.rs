//! Compile candidate machine intent into the existing topology, system plan and artifact exports.

use super::{Candidate, Sources};
use airlock_build::Workspace;
use rusix::{
    interop::{
        NixExpression, NixPath,
        raw::{NixRepresentation, NixValue},
    },
    nix_record, nix_text,
    nixos::{ContextualModule, ModuleBody},
};

/// Bind sources once and defer every target-system build to Nix evaluation.
pub(super) fn configuration(candidate: &Candidate, sources: &Sources) -> NixValue {
    let mut arguments = vec!["self", "nixpkgs"];
    if candidate.has_hermit() {
        arguments.push("hermit-xen");
    }

    NixValue::function_attrs(arguments, |inputs| {
        let source = NixPath::from_source_text(sources.machine.clone());
        let workspace = Workspace::new(NixPath::from_source_text(sources.applications.clone()));
        let kernel_name = crate::vm_build::KERNEL_NAME;
        let config_inputs = nix_record! {
            "nixpkgs": inputs.clone().select("nixpkgs").to_text(),
            "nixpkgsLibvirt105": sources.libvirt.clone(),
            "nixosQubes": sources.qubes.clone(),
            "airlockSupport": source.clone(),
            "airlockApps": workspace.root(),
        };
        let builders = NixValue::function(|system| {
            crate::vm_build::constructors()
                .as_expression()
                .call(nix_record! {
                    "nixpkgs": inputs.clone().select("nixpkgs"),
                    "system": system,
                    "airlockSupport": source.clone(),
                    "airlockAppsSource": workspace.root(),
                    "hermitXen": inputs.clone().attr_or("hermit-xen", NixValue::null()),
                    "applicationRevision": NixValue::builtin("replaceStrings").call(NixValue::list(["\n".into()])).call(NixValue::list(["".into()])).call(
                        NixValue::builtin("readFile").call(source.join_relative("application-revision").unwrap())
                    ),
                    "nixpkgsLibvirt105Source": sources.libvirt.clone(),
                    "nixosQubesSource": sources.qubes.clone(),
                })
        });
        let factories = crate::lowering::builders(&candidate.machine)
            .as_expression()
            .call(nix_record! {
                "lib": inputs.clone().select("nixpkgs.lib"),
                "mkAirlockQubeBuilders": builders.clone(),
                "airlockQubesVmKernelName": kernel_name,
                "airlockSupport": source.clone(),
                "airlockApps": workspace.root(),
                "modulesDirectory": NixPath::from_expression(inputs.clone().select("self"))
                    .join_relative("generated")
                    .unwrap(),
                "userModulesDirectory": NixPath::from_expression(inputs.clone().select("self"))
                    .join_relative("vms")
                    .unwrap(),
                "extraVmSpecialArgs": nix_record! {
                    "airlockConfigInputs": config_inputs.clone(),
                },
            });
        let entries = NixValue::builtin("mapAttrs")
            .call(NixValue::function(|_| {
                NixValue::function(|factory| factory.call("x86_64-linux"))
            }))
            .call(factories);

        let output = entries.bind(|entries| {
            let target = builders.call("x86_64-linux");
            target.bind(|target| {
                let pkgs = target.clone().select("pkgs");
                let lib = inputs.clone().select("nixpkgs.lib");
                let config = topology(candidate, &entries);
                let normalized = crate::topology::library()
                    .call(lib.clone())
                    .select("mkTopology")
                    .call(config.clone());
                let system = system_plan(candidate, &lib);
                let configurations = NixValue::record(
                    candidate
                        .machine
                        .vms()
                        .filter(|vm| matches!(vm.backend, crate::model::GuestBackend::Nixos))
                        .map(|vm| {
                            (
                                format!("airlock-domain-{name}", name = vm.name),
                                entries
                                    .clone()
                                    .select(vm.name.as_str())
                                    .select("configuration"),
                            )
                        }),
                );

                let mut packages = Vec::new();
                for vm in candidate.machine.vms() {
                    let entry = entries.clone().select(vm.name.as_str());
                    if matches!(vm.backend, crate::model::GuestBackend::Hermit { .. }) {
                        packages.push((
                            format!("airlock-domain-{name}-hermit", name = vm.name),
                            entry.select("executable"),
                        ));
                        continue;
                    }
                    for (suffix, attribute) in [
                        ("root-image", "rootImage"),
                        ("store-closure", "storeArtifact"),
                    ] {
                        packages.push((
                            format!("airlock-domain-{name}-{suffix}", name = vm.name),
                            entry.clone().select(attribute),
                        ));
                    }
                }

                packages.push((
                    "airlock-dom0-profile".into(),
                    profile(&pkgs, &candidate.message),
                ));

                let directory = NixPath::from_expression(inputs.clone().select("self"))
                    .join_relative("generated")
                    .unwrap();
                let host = host(
                    candidate,
                    &entries,
                    &lib,
                    &target,
                    &HostSources {
                        source: &source,
                        workspace: &workspace,
                        directory: &directory,
                    },
                    config_inputs,
                );
                let controller = &candidate.machine.host().unwrap().controller;

                nix_record! {
                    "packages": nix_record! {
                        "x86_64-linux": NixValue::record(packages),
                    },
                    "checks": nix_record! {
                        "x86_64-linux": nix_record! {
                            "topology": json_check(&pkgs, "topology", normalized.clone()),
                            "system": json_check(&pkgs, "system", system.clone()),
                        },
                    },
                    "airlock": nix_record! {
                        "metadata": nix_record! {
                            "schema": "airlock.config-repo.v1",
                            "purpose": "candidate",
                            "topology_schema": airlock_machine_core::model::TOPOLOGY_SCHEMA,
                            "system_schema": "airlock.system.v1",
                        },
                        "config": config,
                        "configRoleConfigurations": NixValue::record([(
                            controller.as_str(),
                            entries.select(controller.as_str()).select("configuration"),
                        )]),
                        "nixNativeConfigurations": configurations.clone(),
                        "system": system,
                        "topology": normalized,
                    },
                    "nixosConfigurations": configurations.merge_attrs(nix_record! {
                        "airlock-dom0": host,
                    }),
                }
            })
        });

        (Vec::<(&str, NixValue)>::new(), output)
    })
}

/// Preserve deferred artifact references in the exported plan; host assembly receives materialized paths.
fn topology(candidate: &Candidate, entries: &NixValue) -> NixValue {
    let host = candidate.machine.host().unwrap();
    let domains = NixValue::builtin("mapAttrs")
        .call(NixValue::function(|_| {
            NixValue::function(|entry| entry.select("domain"))
        }))
        .call(entries.clone());

    let mut rules = vec![nix_record! {
        "service": "airlock.PolicyProbe",
        "source": "dom0",
        "target": host.controller.as_str(),
        "action": "allow",
    }];
    for (service, targets) in &candidate.host_calls {
        rules.extend(targets.iter().map(|target| {
            nix_record! {
                "service": service.as_str(),
                "source": "dom0",
                "target": target.as_str(),
                "action": "allow",
            }
        }));
    }

    nix_record! {
        "templates": nix_record! {},
        "kernels": nix_record! {},
        "prefs": nix_record! {
            "default_kernel": "",
            "default_guivm": host.gui.as_str(),
            "default_netvm": host.network.as_str(),
        },
        "domains": domains,
        "qrexecPolicy": nix_record! {
            "rules": NixValue::list(rules),
        },
    }
}

/// Record the requested host switch separately from its lazily built system derivation.
fn system_plan(candidate: &Candidate, lib: &NixValue) -> NixValue {
    let services = candidate.services.iter().map(|(name, request)| {
        let action = match request.action {
            super::ServiceAction::Restart => "restart",
            super::ServiceAction::Reload => "reload",
        };

        (
            name.as_str(),
            nix_record! {
                "action": action,
                "reason": request.reason.clone(),
            },
        )
    });
    let plan = nix_record! {
        "dom0": nix_record! {
            "profile": nix_record! {
                "sourceRef": nix_record! {
                    "build": "packages.x86_64-linux.airlock-dom0-profile",
                },
                "activationCommand": "bin/airlock-dom0-profile-activate",
                "activationAction": "run",
                "message": candidate.message.clone(),
            },
            "packages": NixValue::list([nix_record! {
                "name": "airlock-dom0-profile",
            }]),
            "systemd": nix_record! {
                "services": NixValue::record(services),
            },
            "nixos": nix_record! {
                "system": nix_record! {
                    "sourceRef": nix_record! {
                        "build": "nixosConfigurations.airlock-dom0.config.system.build.toplevel",
                    },
                    "switchAction": candidate.switch_action(),
                    "reason": candidate.reason(),
                },
            },
        },
    };

    crate::system_plan::library()
        .call(lib.clone())
        .select("mkSystem")
        .call(plan)
}

/// Source trees captured by the candidate host, separate from its target package set.
struct HostSources<'a> {
    /// Machine integration assets admitted with the candidate.
    source: &'a NixPath,
    /// Application workspace supplying the shared host modules.
    workspace: &'a Workspace,
    /// Candidate-owned generated modules, including its host additions.
    directory: &'a NixPath,
}

/// Assemble the controller host with validated relationships and explicit source dependencies.
fn host(
    candidate: &Candidate,
    entries: &NixValue,
    lib: &NixValue,
    target: &NixValue,
    sources: &HostSources<'_>,
    config_inputs: NixValue,
) -> NixValue {
    let HostSources {
        source,
        workspace,
        directory,
    } = *sources;
    let materialized = NixValue::builtin("mapAttrs")
        .call(NixValue::function(|_| {
            NixValue::function(|entry| crate::assembly::materialize(entry, &nix_record! {}, ""))
        }))
        .call(entries.clone());
    let kernels = nix_record! {
        "name": crate::vm_build::KERNEL_NAME,
        "package": crate::vm_build::kernel(&target.clone().select("pkgs")),
    };
    let kernel_records = NixValue::record([(
        crate::vm_build::KERNEL_NAME,
        nix_record! {
            "source": kernels.clone().select("package").to_text(),
        },
    )]);
    let base = NixValue::builtin("import")
        .call(directory.join_relative("default.nix").unwrap())
        .select("hostModules")
        .call(nix_record! {
            "lib": lib.clone(),
            "airlockConfigDomains": materialized,
            "airlockKernels": kernel_records,
            "airlockSupport": source.clone(),
            "airlockApps": workspace.root(),
        });
    let authored = ContextualModule::new(|context| {
        let package_list = candidate
            .packages
            .iter()
            .map(|attribute| context.pkgs.clone().select(attribute));
        let mut files = candidate
            .files
            .iter()
            .map(|(name, text)| {
                (
                    name.as_str(),
                    nix_record! {
                        "text": text.clone(),
                    },
                )
            })
            .collect::<Vec<_>>();
        files.push((
            "airlock/inside-config-applied-message",
            nix_record! {
                "text": format!("{message}\n", message = candidate.message),
            },
        ));

        ModuleBody::new(nix_record! {
            "airlock": nix_record! {
                "qubes": nix_record! {
                    "qrexecPolicy": topology(candidate, entries).select("qrexecPolicy"),
                },
            },
            "environment": nix_record! {
                "systemPackages": NixValue::list(package_list),
                "etc": NixValue::record(files),
            },
            "system": nix_record! {
                "nixos": nix_record! {
                    "tags": NixValue::list(["airlock-inside-config".into()]),
                },
            },
            "networking": nix_record! {
                "hostName": context.lib.select("mkDefault").call("dom0"),
            },
        })
    })
    .into_expression();
    let additions = candidate.modules.iter().enumerate().map(|(index, _)| {
        directory
            .join_relative(&format!("host-{index}.nix"))
            .unwrap()
            .as_expression()
    });
    let modules = NixValue::concat_lists([
        NixValue::list([
            target.clone().select("qubesModule"),
            crate::vm::module_constructors()
                .call(source.clone())
                .select("dom0")
                .call(workspace.root()),
            crate::vm::module_constructors()
                .call(source.clone())
                .select("topology")
                .call(workspace.root()),
            nix_record! {
                "nixpkgs": nix_record! {
                    "overlays": target.clone().select("qubesOverlays"),
                },
            },
            nix_record! {
                "airlock": nix_record! {
                    "image": nix_record! {
                        "devMode": nix_record! {
                            "enable": true,
                        },
                    },
                },
            },
            authored,
        ]),
        base,
        NixValue::list(additions),
    ]);

    lib.clone().select("nixosSystem").call(nix_record! {
        "system": "x86_64-linux",
        "specialArgs": nix_record! {
            "airlockQubeKernel": kernels,
            "airlockAppsSource": workspace.root(),
            "airlockConfigInputs": config_inputs,
        },
        "modules": modules,
    })
}

/// Keep the opt-in candidate checks as small serialized protocol artifacts.
fn json_check(pkgs: &NixValue, name: &str, value: NixValue) -> NixValue {
    pkgs.clone()
        .select("runCommand")
        .call(format!("airlock-config-{name}-check"))
        .call(nix_record! {
            "document": NixValue::builtin("toJSON").call(value),
        })
        .call(
            r#"
            printf '%s\n' "$document" > "$out"
        "#,
        )
}

/// Install host profile receipt handling without granting the candidate additional control authority.
fn profile(pkgs: &NixValue, message: &str) -> NixValue {
    let data = pkgs
        .clone()
        .select("writeText")
        .call("airlock-profile.json")
        .call(NixValue::builtin("toJSON").call(nix_record! {
            "schema": "airlock.dom0-profile.v1",
            "message": message,
            "built_by": "sys-ctrl",
        }));
    let executable = pkgs
        .clone()
        .select("writeShellScriptBin")
        .call("airlock-dom0-profile-activate")
        .call(nix_text!(
            r#"
        set -eu
        state_dir="${{AIRLOCK_SYSTEM_STATE_DIR:-/var/lib/airlock/system}}"
        etc_dir="${{AIRLOCK_SYSTEM_ETC_DIR:-/etc/airlock}}"
        {coreutils}/bin/install -d -m 0755 "$state_dir" "$etc_dir"
        {coreutils}/bin/cp {data} "$state_dir/current-profile.json"
        {coreutils}/bin/cp {data} "$etc_dir/system-profile.json"

        if [ -n "${{AIRLOCK_SYSTEM_JSON:-}}" ]; then
          {coreutils}/bin/cp "$AIRLOCK_SYSTEM_JSON" "$state_dir/current-system.json"
        fi
        if [ -n "${{AIRLOCK_SYSTEM_PLAN_JSON:-}}" ]; then
          {coreutils}/bin/cp "$AIRLOCK_SYSTEM_PLAN_JSON" "$state_dir/current-plan.json"
        fi
        if [ -n "${{AIRLOCK_SYSTEM_PROFILE:-}}" ]; then
          printf '%s\n' "$AIRLOCK_SYSTEM_PROFILE" > "$state_dir/current-profile-link"
        fi
    "#,
            coreutils = pkgs.clone().select("coreutils"),
            data = data.clone(),
        ));

    pkgs.clone()
        .select("runCommand")
        .call("airlock-dom0-profile")
        .call(nix_record! {
            "preferLocalBuild": true,
            "allowSubstitutes": false,
        })
        .call(nix_text!(
            r#"
        mkdir -p "$out/bin" "$out/share/airlock"
        ln -s {executable}/bin/airlock-dom0-profile-activate "$out/bin/airlock-dom0-profile-activate"
        cp {data} "$out/share/airlock/profile.json"
    "#,
            executable = executable,
            data = data,
        ))
}
