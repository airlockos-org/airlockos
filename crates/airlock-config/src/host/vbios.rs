//! Deliver AMD firmware tables through the existing Qubes libvirt integration.

use airlock_build::{Workspace, adapters};
use rusix::{
    interop::raw::{NixRepresentation, NixValue},
    nix_record,
    nixos::{ContextualModule, ModuleBody},
};

/// Select explicit HVM firmware recipients while Qubes remains responsible for PCI assignment.
pub(super) fn module(workspace: &Workspace) -> NixValue {
    ContextualModule::new(|context| {
        let cfg = context.config.clone().select("airlock.amdVbios");
        let package = adapters::gpu(&context.pkgs, workspace).as_expression();
        let domains = cfg.clone().select("domains");
        let option = |value| context.lib.clone().select("mkOption").call(value);
        let options = nix_record! {
            "options": nix_record! {
                "airlock": nix_record! {
                    "amdVbios": nix_record! {
                        "enable": context
                            .lib
                            .clone()
                            .select("mkEnableOption")
                            .call("automatic AMD VFCT delivery through Qubes startup"),
                        "domains": option(nix_record! {
                            "default": nix_record! {},
                            "description": "Opted-in HVM VMs; Qubes manages PCI assignment.",
                            "type": context.lib.clone().select("types.attrsOf").call(
                                context.lib.clone().select("types.submodule").call(nix_record! {
                                    "options": nix_record! {
                                        "guestSlot": option(nix_record! {
                                            "type": context
                                                .lib
                                                .clone()
                                                .select("types.ints.between")
                                                .call(8_i64)
                                                .call(31_i64),
                                            "default": 16_i64,
                                            "description": "VM bus-zero PCI slot shared by libvirt and VFCT.",
                                        }),
                                    },
                                }),
                            ),
                        }),
                        "package": option(nix_record! {
                            "type": context.lib.clone().select("types.package"),
                            "readOnly": true,
                            "default": package.clone(),
                            "description": "Qubes extension and offline firmware validator.",
                        }),
                    },
                },
            },
        };
        let valid = context
            .lib
            .clone()
            .select("all")
            .call(NixValue::function(|name| {
                name.clone().equals("dom0").equals(false).and(
                    NixValue::builtin("match")
                        .call("[a-zA-Z][a-zA-Z0-9_-]*")
                        .call(name)
                        .equals(NixValue::null())
                        .equals(false),
                )
            }))
            .call(NixValue::builtin("attrNames").call(domains.clone()));
        let templates = context
            .lib
            .clone()
            .select("mapAttrs'")
            .call(NixValue::function(|name| {
                NixValue::function(|_| nix_record! {
                    "name": rusix::nix_text!("qubes/templates/libvirt/xen/by-name/{name}.xml", name = name),
                    "value": nix_record! {
                        "source": workspace.file("runtime/airlock-qubes-python/assets/amd-vbios.xml").snapshot(),
                    },
                })
            }))
            .call(domains.clone());
        let config = nix_record! {
            "assertions": NixValue::list([
                nix_record! {
                    "assertion": context.config.clone().select("virtualisation.qubes.dom0.enable"),
                    "message": "AMD VFCT preparation requires Qubes dom0.",
                },
                nix_record! {
                    "assertion": domains.clone().equals(nix_record! {}).equals(false).and(valid),
                    "message": "AMD VFCT requires explicit, valid VM names.",
                },
            ]),
            "environment": nix_record! {
                "systemPackages": NixValue::list([package]),
                "etc": nix_record! {
                    "airlock/amd-vbios.json": nix_record! {
                        "text": NixValue::builtin("toJSON").call(nix_record! {
                            "domains": domains,
                        }),
                    },
                }
                .merge_attrs(templates),
            },
            "systemd": nix_record! {
                "tmpfiles": nix_record! {
                    "rules": NixValue::list(["d /run/airlock-amd-vbios 0700 root root - -".into()]),
                },
            },
        };

        ModuleBody::new(context.lib.select("mkIf").call(cfg.select("enable")).call(config))
            .key("airlock.host.amd-vbios")
            .import_value(options)
    })
    .into_expression()
}
