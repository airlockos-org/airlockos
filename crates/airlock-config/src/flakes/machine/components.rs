//! Expose one guest build and a host assembly that consumes realized guest descriptors.
//! Nix's output context preserves the original recipes through the release build graph.

use super::{Build, qemu_lab};
use rusix::{
    interop::{NixExpression, raw::NixValue},
    nix_record,
};

/// Restore a verified output's Nix recipe dependency without evaluating its original expression.
/// The worker has realized this exact named output before giving it to the constructor.
fn output(reference: &NixValue) -> NixValue {
    let context = NixValue::builtin("listToAttrs").call(NixValue::list([nix_record! {
        "name": reference.clone().select("derivation"),
        "value": nix_record! { "outputs": NixValue::list(["out".into()]) },
    }]));
    NixValue::builtin("appendContext")
        .call(reference.clone().select("output"))
        .call(context)
}

/// Evaluate one production factory and serialize only its deployable artifacts.
pub(super) fn guest(build: &Build, assembly: &NixValue) -> NixValue {
    NixValue::function(|request| {
        let name = request.clone().select("name");
        let compiled = request.clone().select("native");
        let extra = NixValue::if_else(
            compiled.clone().equals(NixValue::null()),
            nix_record! {},
            nix_record! {
                "airlockCompiledApplications": NixValue::builtin("listToAttrs").call(NixValue::list([nix_record! {
                    "name": name.clone(), "value": output(&compiled),
                }])),
            },
        );
        let entries = NixValue::if_else(
            request.select("profile").equals("qemu-lab"),
            qemu_lab::entries_with(build, "x86_64-linux".into(), extra.clone()),
            assembly
                .clone()
                .select("entries")
                .call("x86_64-linux")
                .call(extra),
        );
        let entry = NixValue::builtin("getAttr").call(name).call(entries);
        entry.bind(|entry| {
            let hermit = entry.clone().attr_or("backendType", "nix-closure").equals("hermit");
            let domain = crate::assembly::materialize(entry.clone(), &nix_record! {}, "");
            let body = nix_record! {
                "domain": domain,
                "rootMetadata": NixValue::if_else(hermit, NixValue::null(), entry.select("rootImage.metadata").to_text()),
            };
            build.pkgs("x86_64-linux".into()).select("writeText")
                .call("airlock-component.json")
                .call(NixValue::builtin("toJSON").call(body))
        })
    })
}

/// Reconstruct the small artifact portion of the existing entry interface.
/// Every path carries the bundle recipe context, so host/release builders keep
/// dependencies on the real VM recipes even after the descriptor crosses JSON.
fn entry(reference: NixValue) -> NixValue {
    output(&reference).bind(|bundle| {
        let context = NixValue::builtin("getContext").call(bundle.clone());
        let retain = |value| NixValue::builtin("appendContext").call(value).call(context.clone());
        // readFile propagates the descriptor's runtime references. Nix's JSON
        // decoder accepts plain text; attach the checked recipe to the paths
        // consumed below rather than dropping their build dependencies.
        let text = NixValue::builtin("unsafeDiscardStringContext")
            .call(NixValue::builtin("readFile").call(bundle));
        NixValue::builtin("fromJSON").call(text).bind(|payload| {
            let domain = payload.clone().select("domain");
            let backend = domain.clone().select("backend");
            let system = retain(backend.clone().select("system.source"));
            let linux = nix_record! {
                "completed": true,
                "domain": domain.clone(),
                "configuration": nix_record! { "config": nix_record! { "system": nix_record! { "build": nix_record! {
                    "toplevel": system.clone(),
                } } } },
                "rootImage": nix_record! {
                    "outPath": retain(NixValue::builtin("dirOf").call(backend.clone().select("root.source"))),
                    "metadata": retain(payload.select("rootMetadata")),
                },
                "storeArtifact": retain(backend.clone().select("store.source")),
                "kernelopts": retain(domain.clone().select("prefs.kernelopts")),
            };
            let native = nix_record! {
                "completed": true,
                "backendType": "hermit",
                "domain": domain.merge_attrs(nix_record! {
                    "backend": backend.clone().merge_attrs(nix_record! {
                        "system": backend.clone().select("system").merge_attrs(nix_record! { "source": system }),
                        "artifact": backend.clone().select("artifact").merge_attrs(nix_record! {
                            "executable": retain(backend.clone().select("artifact.executable")),
                        }),
                    }),
                }),
            };
            NixValue::if_else(backend.select("type").equals("hermit"), native, linux)
        })
    })
}

/// Assemble the original USB or QEMU release using only completed guest entries.
pub(super) fn release(build: &Build, assembly: &NixValue) -> NixValue {
    NixValue::function(|request| {
        let completed = NixValue::builtin("mapAttrs")
            .call(NixValue::function(|_| NixValue::function(entry)))
            .call(request.clone().select("guests"));
        let evidence = request.clone().select("evidence");
        // Preserve the existing lazy alternative boot entries. The selected USB
        // release uses its named completed entries; alternatives are not searched.
        let alternatives = assembly
            .clone()
            .select("entries")
            .call("x86_64-linux")
            .call(nix_record! {});
        let usb = assembly
            .clone()
            .select("configuration")
            .call(nix_record! {
                "machineEntries": completed.clone().merge_attrs(nix_record! {
                    "sys-gui-hybrid": alternatives.clone().select("sys-gui-hybrid"),
                    "sys-gui-standalone": alternatives.select("sys-gui-standalone"),
                }),
                "componentEvidence": evidence.clone(),
            })
            .select(
                "config.specialisation.usb-lab.configuration.system.build.airlockMachineRelease",
            );
        let qemu = qemu_lab::completed(build, completed, evidence)
            .select("config.system.build.airlockMachineRelease");
        NixValue::if_else(request.select("profile").equals("qemu-lab"), qemu, usb)
    })
}
