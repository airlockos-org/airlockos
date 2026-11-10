//! Author flake entry points as Rust expressions while retaining Nix's input locking and evaluation.

mod applications;

mod machine;

mod development;

mod verification;

use rusix::{Config, interop::raw::NixValue, nix_record};

/// Select the source-owned entry point to emit; every output remains ordinary Nix flake data.
pub(crate) fn configuration(kind: &str) -> Result<Config, String> {
    let (description, inputs, outputs) = match kind {
        "applications" => (
            "Standalone Airlock application builds and previews",
            nix_record! {
                "self": nix_record! {
                    "submodules": false,
                },
                "nixpkgs": nix_record! {
                    "url": "github:NixOS/nixpkgs/nixos-unstable",
                },
            },
            applications::outputs(),
        ),
        "development" => (
            "Airlock development, USB image, and integration tooling",
            nix_record! {
                "self": nix_record! {
                    "submodules": true,
                },
                "airlock-machine": nix_record! {
                    "url": "path:./airlock-machine",
                },
                "nixpkgs": nix_record! {
                    "follows": "airlock-machine/nixpkgs",
                },
                "nixos-qubes": nix_record! {
                    "follows": "airlock-machine/nixos-qubes",
                },
            },
            development::outputs(),
        ),
        _ => return Err(format!("unknown flake kind: {kind}")),
    };

    Ok(Config::new()
        .set_dynamic("description", description)
        .set_dynamic("inputs", inputs)
        .set_dynamic("outputs", outputs))
}

/// Evaluate a factory once for each supported platform without fixing package derivations in Rust.
pub(crate) fn systems(factory: impl FnOnce(NixValue) -> NixValue) -> NixValue {
    nix_record! {
        "x86_64-linux": factory("x86_64-linux".into()),
    }
}

/// Keep proprietary Qubes artwork and stub domains permitted without enabling unrelated unfree packages.
pub(crate) fn allow_unfree(lib: &NixValue) -> NixValue {
    NixValue::function(|package| {
        let name = package
            .clone()
            .attr_or("pname", lib.clone().select("getName").call(package));

        NixValue::builtin("elem").call(name).call(NixValue::list([
            "qubes-artwork".into(),
            "qubes-vmm-stubdom-linux".into(),
        ]))
    })
}

/// Compile source-owned machine declarations with the common flake wiring.
pub(crate) fn machine_configuration(revision: &str) -> Config {
    Config::new()
        .set_dynamic(
            "description",
            "Airlock: Qubes control stack on NixOS Xen dom0",
        )
        .set_dynamic("inputs", machine::inputs(revision))
        .set_dynamic("outputs", machine::outputs())
}

/// Recover source identity after Git metadata has been excluded from a prepared build tree.
/// Plain inspection exports without a receipt retain Nix's ordinary self metadata.
pub(crate) fn source_identity(
    source: &rusix::interop::raw::NixValue,
) -> rusix::interop::raw::NixValue {
    let metadata = rusix::nix_text!("{source}/airlock-source.json", source = source.clone());
    let recorded = rusix::interop::raw::NixValue::builtin("fromJSON")
        .call(rusix::interop::raw::NixValue::builtin("readFile").call(metadata.clone()));

    let evaluated = rusix::nix_record! {
        "revision": source.clone().attr_or("rev", "dirty"),
        "timestamp": source.clone().attr_or("lastModified", 0_i64),
        "dirty": source.clone().has_attr("rev").equals(false),
    };

    rusix::interop::raw::NixValue::if_else(
        source.clone().has_attr("rev"),
        evaluated.clone(),
        rusix::interop::raw::NixValue::if_else(
            rusix::interop::raw::NixValue::builtin("pathExists").call(metadata),
            recorded,
            evaluated,
        ),
    )
}
