//! Compare shared package values against the original recipes and extended package sets.

use super::*;
use airlock_build::{Application, Workspace};
use rusix::nix_record;

/// Retain executable and offline-input identities without realizing build outputs.
fn identities(pkgs: &NixValue, workspace: &Workspace) -> NixValue {
    NixValue::list(
        [
            Application::Cli,
            Application::VmService,
            Application::VmInit,
            Application::Dom0,
            Application::Dom0Qubes,
            Application::StorePacker,
        ]
        .map(|application| {
            let package = application.build(pkgs, workspace).as_expression();
            nix_record! {
                "derivation": package.clone().select("drvPath"),
                "output": package.clone().to_text(),
                "inputs": NixValue::builtin("map").call(NixValue::function(|input| input.to_text()))
                    .call(package.select("buildArtifacts")),
            }
        }),
    )
}

/// Check real feature/static variants, source mismatches and Nixpkgs extensions.
pub(super) fn expression(inputs: NixValue) -> NixValue {
    NixValue::builtin("getFlake").call(inputs.clone().select("root")).bind(|flake| {
        let workspace = Workspace::new(NixPath::from_source_text(
            inputs.select("apps").to_text().into_expr::<String>(),
        ));
        let pkgs = flake.clone().select("inputs.nixpkgs.legacyPackages.x86_64-linux")
            .select("extend").call(flake.select("inputs.nixos-qubes.overlays.default"));
        pkgs.bind(|pkgs| {
            let shared = pkgs.clone().select("extend").call(Application::overlay(&workspace));
            shared.bind(|shared| {
                let override_compiler = NixValue::function(|_| NixValue::function(|previous| {
                    nix_record! { "rustc": previous.select("rustc").select("overrideAttrs")
                        .call(NixValue::function(|_| nix_record! { "name": "rustc-sharing-check" })) }
                }));
                let mismatch = shared.clone().merge_attrs(nix_record! {
                    "airlockApplicationPackages": nix_record! {
                        "source": "/different-source",
                        "packages": NixValue::builtin("throw").call("mismatched catalogue was used"),
                    },
                });
                nix_record! {
                    "original": identities(&pkgs, &workspace),
                    "shared": identities(&shared, &workspace),
                    "mismatch": identities(&mismatch, &workspace),
                    "extendedOriginal": identities(&pkgs.select("extend").call(override_compiler.clone()), &workspace),
                    "extendedShared": identities(&shared.select("extend").call(override_compiler), &workspace),
                }
            })
        })
    })
}
