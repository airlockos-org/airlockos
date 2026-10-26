//! Cache immutable package serialization and common EROFS indexes at Nix derivation boundaries.
//! Closure discovery is confined to image preparation: reading a closureInfo list realizes that input first.

use crate::{Application, Workspace};
use rusix::{
    interop::{
        NixExpression, Package,
        raw::{NixRepresentation, NixValue},
    },
    nix_record, nix_text,
};

/// Build the format-only tool from an independently locked source root.
/// Application manifests, lockfile, feature graph and authoring code never enter this derivation.
pub(crate) fn packer(pkgs: &NixValue, workspace: &Workspace) -> Package {
    let root = workspace.file("airlock-store-packer");
    let manifest: toml::Value =
        toml::from_str(include_str!("../../../airlock-store-packer/Cargo.toml"))
            .expect("valid standalone packer manifest");
    let source = pkgs
        .clone()
        .select("lib.fileset.toSource")
        .call(nix_record! {
            "root": root.clone(),
            "fileset": pkgs.clone().select("lib.fileset.unions").call(NixValue::list([
                root.join_relative("Cargo.toml").unwrap().as_expression(),
                root.join_relative("Cargo.lock").unwrap().as_expression(),
                root.join_relative("src").unwrap().as_expression(),
            ])),
        });

    Package::from_expression(pkgs.clone().select("rustPlatform.buildRustPackage").call(nix_record! {
        "pname": "airlock-store-packer",
        "version": manifest["package"]["version"].as_str().unwrap(),
        "src": source,
        "cargoLock": nix_record! { "lockFile": root.join_relative("Cargo.lock").unwrap().snapshot() },
        "cargoBuildFlags": NixValue::list(["--bin".into(), "airlock-store-packer".into()]),
        "doCheck": false,
        "meta": nix_record! {
            "description": "Canonical immutable package fragment packing",
            "mainProgram": "airlock-store-packer",
            "license": pkgs.clone().select("lib.licenses.mit"),
            "platforms": pkgs.clone().select("lib.platforms.linux"),
        },
    }))
}

/// Restore a known realized store root's dependency context without copying or renaming its contents.
fn store_path(path: NixValue) -> NixValue {
    NixValue::builtin("appendContext").call(path.clone()).call(
        NixValue::builtin("listToAttrs").call(NixValue::list([nix_record! {
            "name": path,
            "value": nix_record! { "path": true },
        }])),
    )
}

/// Write a derivation-aware JSON input; embedded artifact paths retain their build dependencies.
fn json(pkgs: &NixValue, name: &str, value: NixValue) -> NixValue {
    pkgs.clone()
        .select("writeText")
        .call(name)
        .call(NixValue::builtin("toJSON").call(value))
}

/// Cache one fragment per exact Nix package, with no dependency on dom0, guest names or the Airlock revision.
fn fragment(pkgs: &NixValue, tool: &NixValue, logical: NixValue) -> NixValue {
    let source = store_path(logical.clone());
    pkgs.clone()
        .select("runCommand")
        .call(nix_text!(
            "airlock-store-fragment-{name}",
            name = NixValue::builtin("baseNameOf").call(logical.clone()),
        ))
        .call(nix_record! {
            "__structuredAttrs": true,
            // Store paths inside tar bytes are image data, not roots of the assembler's Nix closure.
            "unsafeDiscardReferences": nix_record! { "out": true },
            "nativeBuildInputs": NixValue::list([pkgs.clone().select("gnutar")]),
        })
        .call(nix_text!(
            r#"
        exec {tool}/bin/airlock-store-packer fragment {logical} {source} "$out"
    "#,
            tool = tool.clone(),
            logical = pkgs.clone().select("lib.escapeShellArg").call(logical),
            source = source,
        ))
}

/// Index only the selected fragments; the consuming pool's placement is absent from these inputs.
fn index(pkgs: &NixValue, tool: &NixValue, fragments: NixValue) -> NixValue {
    let manifest = json(pkgs, "airlock-store-index-inputs.json", fragments);
    pkgs.clone()
        .select("runCommand")
        .call("airlock-store-index")
        .call(nix_record! {
            "__structuredAttrs": true,
            "unsafeDiscardReferences": nix_record! { "out": true },
        })
        .call(nix_text!(
            r#"
            exec {tool}/bin/airlock-store-cache index {manifest} "$out" {erofs}/bin/mkfs.erofs
        "#,
            tool = tool.clone(),
            manifest = manifest,
            erofs = pkgs.clone().select("erofs-utils"),
        ))
}

/// Build a cache manifest for complete closureInfo-style inputs containing sorted `store-paths` files.
///
/// Each package's fragment depends on its source, GNU tar and the packing executable only.
/// Each index depends on its complete fragment set and the patched EROFS tool. Nix can therefore
/// reuse both across image builds even when the consuming dom0 service or VM identity changes.
/// Resolving the package list realizes the supplied closures during image evaluation; callers
/// must keep this out of normal machine evaluation and live deployment paths.
pub fn image_cache(pkgs: &NixValue, workspace: &Workspace, closures: NixValue) -> NixValue {
    let lib = pkgs.clone().select("lib");
    let tool = Application::StoreCache
        .build(pkgs, workspace)
        .as_expression();
    let packer = Application::StorePacker
        .build(pkgs, workspace)
        .as_expression();
    let path_sets = NixValue::builtin("map")
        .call(NixValue::function(|closure| {
            let paths = lib
                .clone()
                .select("filter")
                .call(NixValue::function(|path| !path.equals("")))
                .call(
                    lib.clone().select("splitString").call("\n").call(
                        NixValue::builtin("readFile")
                            .call(nix_text!("{closure}/store-paths", closure = closure)),
                    ),
                );
            // A closure manifest must not become every fragment's dependency. Restore
            // each package's own store context only at its serialization boundary.
            NixValue::builtin("map")
                .call(NixValue::builtin("unsafeDiscardStringContext"))
                .call(paths)
        }))
        .call(closures);
    path_sets.bind(|path_sets| {
        let paths = lib
            .clone()
            .select("unique")
            .call(NixValue::builtin("concatLists").call(path_sets.clone()));
        let fragments = lib
            .clone()
            .select("genAttrs")
            .call(paths)
            .call(NixValue::function(|path| fragment(pkgs, &packer, path)));

        fragments.bind(|fragments| {
            let indexes = NixValue::builtin("map")
                .call(NixValue::function(|paths| {
                    let selected =
                        lib.clone()
                            .select("genAttrs")
                            .call(paths)
                            .call(NixValue::function(|path| {
                                NixValue::builtin("getAttr")
                                    .call(path)
                                    .call(fragments.clone())
                            }));
                    index(pkgs, &tool, selected)
                }))
                .call(path_sets);

            json(
                pkgs,
                "airlock-image-cache.json",
                nix_record! {
                    "schema": "airlock.image-cache.v1",
                    "fragments": fragments,
                    "indexes": indexes,
                },
            )
        })
    })
}
