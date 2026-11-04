//! Integrate the upstream crate graph with Airlock source and installation boundaries.

use crate::Workspace;
use rusix::{
    interop::raw::{NixRepresentation, NixValue},
    interop::{NixExpression, NixPath},
    nix_record, nix_text,
};

/// Generator release whose metadata and template contracts preparation relies on.
pub const VERSION: &str = "0.15.0";

/// Select crate2nix from the caller's locked Nixpkgs, refusing an unnoticed version change.
pub fn generator(pkgs: &NixValue) -> NixValue {
    let package = pkgs.clone().select("crate2nix");
    NixValue::if_else(
        package.clone().select("version").equals(VERSION),
        package,
        NixValue::builtin("throw").call("Airlock preparation requires crate2nix 0.15.0"),
    )
}

/// Package selection and application-specific installation attributes.
pub struct Build<'a> {
    /// Workspace member name; None selects the independent root package.
    pub member: Option<&'a str>,
    /// Actual production features, including "default" only when requested.
    pub features: &'a [&'a str],
    /// Selected executables; an empty list builds only the library.
    pub binaries: &'a [&'a str],
    /// Root-only native inputs, installation hooks and package metadata.
    pub attributes: NixValue,
}

/// Select one upstream crate graph package while preserving compatible dependency derivations.
/// The generator owns feature/target resolution. Local source projections keep only a
/// crate's own implementation and the external files it explicitly embeds.
pub fn package(pkgs: &NixValue, workspace: &Workspace, request: Build<'_>) -> NixValue {
    NixValue::builtin("import")
        .call(workspace.file("airlock-crate-build.nix"))
        .call(nix_record! {
            "pkgs": pkgs.clone(),
            "source": workspace.root(),
            "member": request.member.map(NixValue::from).unwrap_or_else(NixValue::null),
            "features": NixValue::list(request.features.iter().copied().map(NixValue::from)),
            "binaries": NixValue::list(request.binaries.iter().copied().map(NixValue::from)),
            "attributes": request.attributes,
        })
}

/// Describe the shared constructor emitted once beside each prepared Cargo graph.
/// Package expressions import it so composing VM modules does not copy its implementation.
pub fn constructor() -> NixValue {
    NixValue::function(|arguments| {
        let pkgs = arguments.clone().select("pkgs");
        let root = arguments.clone().select("source");
        let workspace = Workspace::new(NixPath::from_source_text(
            root.clone().to_text().into_expr::<String>(),
        ));
        let lib = pkgs.clone().select("lib");
        let manifest = NixValue::builtin("fromTOML")
            .call(NixValue::builtin("readFile").call(workspace.file("Cargo.toml")));
        let members = manifest
            .clone()
            .attr_or("workspace", nix_record! {})
            .attr_or("members", NixValue::list([]));
        let locations = NixValue::builtin("listToAttrs").call(
            NixValue::builtin("map")
                .call(NixValue::function(|directory| {
                    let manifest = NixValue::builtin("fromTOML").call(
                        NixValue::builtin("readFile").call(nix_text!(
                            "{root}/{directory}/Cargo.toml",
                            root = root.clone(),
                            directory = directory.clone()
                        )),
                    );
                    nix_record! { "name": manifest.select("package.name"), "value": directory }
                }))
                .call(members.clone()),
        );
        let locations = NixValue::if_else(
            manifest.clone().has_attr("package"),
            nix_record! { "name": manifest.select("package.name"), "value": "." }
                .bind(|entry| NixValue::builtin("listToAttrs").call(NixValue::list([entry]))),
            locations,
        );
        let selected = NixValue::if_else(
            arguments.clone().select("member").equals(NixValue::null()),
            NixValue::builtin("head").call(NixValue::builtin("attrNames").call(locations.clone())),
            arguments.clone().select("member"),
        );
        let builder = NixValue::function(|target_pkgs| {
            NixValue::function(|attributes| {
                let name = attributes.clone().select("crateName");
                let directory = NixValue::builtin("getAttr")
                    .call(name.clone())
                    .call(locations.clone());
                let path = |relative: NixValue| {
                    NixPath::from_source_text(nix_text!(
                        "{root}/{relative}",
                        root = root.clone(),
                        relative = relative
                    ))
                    .as_expression()
                };
                let mut embedded = vec![path(directory.clone())];
                let manifests = NixValue::builtin("map")
                    .call(NixValue::function(|member| {
                        path(nix_text!("{member}/Cargo.toml", member = member).into())
                    }))
                    .call(members.clone());
                embedded.push(NixValue::if_else(
                    name.clone().equals("airlock-build"),
                    lib.clone()
                        .select("fileset.unions")
                        .call(NixValue::concat_lists([
                            manifests,
                            NixValue::list([
                                workspace.file("Cargo.toml").as_expression(),
                                workspace
                                    .file("tooling/airlock-store-packer/Cargo.toml")
                                    .as_expression(),
                                workspace
                                    .file("airlock-tests/fixtures/memory_accounting.c")
                                    .as_expression(),
                            ]),
                        ])),
                    lib.clone()
                        .select("fileset.unions")
                        .call(NixValue::list([])),
                ));
                embedded.push(NixValue::if_else(
                    name.clone().equals("airlock-config"),
                    workspace.file("verus.json").as_expression(),
                    lib.clone()
                        .select("fileset.unions")
                        .call(NixValue::list([])),
                ));
                let local = nix_record! {
                    "src": target_pkgs.clone().select("lib.fileset.toSource").call(nix_record! {"root":root.clone(),"fileset":lib.clone().select("fileset.unions").call(NixValue::list(embedded))}),
                    "workspace_member": directory,
                };
                let bins = NixValue::builtin("filter")
                    .call(NixValue::function(|bin| {
                        NixValue::builtin("elem")
                            .call(bin.select("name"))
                            .call(arguments.clone().select("binaries"))
                    }))
                    .call(attributes.clone().attr_or("crateBin", NixValue::list([])));
                let configured = attributes
                    .clone()
                    .merge_attrs(nix_record! {"crateBin":NixValue::list([])})
                    .merge_attrs(NixValue::if_else(
                        NixValue::builtin("hasAttr")
                            .call(name.clone())
                            .call(locations.clone()),
                        local,
                        nix_record! {},
                    ));
                let python = NixValue::if_else(
                    NixValue::builtin("elem")
                        .call(name.clone())
                        .call(NixValue::list([
                            "pyo3-build-config".into(),
                            "pyo3-ffi".into(),
                            "pyo3".into(),
                        ])),
                    nix_record! {
                        "PYO3_PYTHON":nix_text!("{python}/bin/python3",python=target_pkgs.clone().select("python3")),
                    },
                    nix_record! {},
                );
                // The pinned buildRustCrate names metadata after the crate rather than
                // Cargo's `links` key. PyO3 0.29 consumes the latter spelling.
                let python_metadata = NixValue::if_else(
                    name.clone().equals("pyo3-ffi"),
                    nix_record! { "postConfigure": r#"
                        printf '%s\n' 'export DEP_PYTHON_PYO3_CONFIG="$DEP_PYO3_FFI_PYO3_CONFIG"' >> target/env
                    "# },
                    NixValue::if_else(
                        name.clone().equals("pyo3"),
                        nix_record! { "postConfigure": r#"
                            printf '%s\n' 'export DEP_PYO3_PYTHON_PYO3_CONFIG="$DEP_PYO3_PYO3_CONFIG"' >> target/env
                        "# },
                        nix_record! {},
                    ),
                );
                let native = NixValue::if_else(
                    name.clone().equals("libadwaita-sys"),
                    nix_record! {
                        "nativeBuildInputs": NixValue::list([target_pkgs.clone().select("pkg-config")]),
                        "buildInputs": NixValue::list([target_pkgs.clone().select("libadwaita")]),
                    },
                    nix_record! {},
                );
                target_pkgs.select("buildRustCrate").call(
                    configured
                        .merge_attrs(python)
                        .merge_attrs(python_metadata)
                        .merge_attrs(native)
                        .merge_attrs(NixValue::if_else(
                            name.equals(selected.clone()),
                            arguments
                                .clone()
                                .select("attributes")
                                .merge_attrs(nix_record! {
                                    "crateBin": bins,
                                    "AIRLOCK_BUILD_ARTIFACT": "1",
                                }),
                            nix_record! {},
                        )),
                )
            })
        });
        let graph = NixValue::builtin("import")
            .call(workspace.file("Cargo.nix"))
            .call(nix_record! {
                "pkgs":pkgs.clone(),"buildRustCrateForPkgs":builder,
                "rootFeatures":arguments.clone().select("features"),
            });
        let native = NixValue::if_else(
            arguments.clone().select("member").equals(NixValue::null()),
            graph.clone().select("rootCrate.build"),
            NixValue::builtin("getAttr")
                .call(arguments.clone().select("member"))
                .call(graph.select("workspaceMembers"))
                .select("build"),
        );
        native.bind(|native| {
            let crates = NixValue::concat_lists([
                NixValue::list([native.clone()]),
                native.clone().select("completeDeps"),
                native.clone().select("completeBuildDeps"),
            ]);
            let crates = lib
                .clone()
                .select("concatMap")
                .call(NixValue::function(|dependency| {
                    NixValue::concat_lists([
                        NixValue::list([dependency.clone()]),
                        dependency.select("completeBuildDeps"),
                    ])
                }))
                .call(crates);
            let inputs = lib
                .clone()
                .select("concatMap")
                .call(NixValue::function(|dependency| {
                    NixValue::concat_lists([
                        NixValue::list([
                            dependency.clone(),
                            dependency.clone().select("lib"),
                            dependency.clone().select("src"),
                        ]),
                        dependency.clone().select("nativeBuildInputs"),
                        dependency.select("buildInputs"),
                    ])
                }))
                .call(crates);
            // These are explicit retention inputs, not permission to publish a build.
            native
                .clone()
                .merge_attrs(nix_record! { "buildArtifacts": lib.select("unique").call(inputs) })
        })
    })
}
