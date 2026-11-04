//! Package a native extension discovered through Qubes' existing Python entry points.

use crate::Workspace;
use rusix::{
    interop::{
        Package,
        raw::{NixRepresentation, NixValue},
    },
    nix_record, nix_text,
};

/// Build Rust pool, volume and GPU callbacks for the package set's exact Python interpreter.
/// Linking the pinned libpython supports both Qubes imports and embedded offline image calls.
pub fn qubes(pkgs: &NixValue, workspace: &Workspace) -> Package {
    let python = pkgs.clone().select("python3");
    let native = crate::crate_graph::package(
        pkgs,
        workspace,
        crate::crate_graph::Build {
            member: Some("airlock-qubes-python"),
            features: &["default"],
            binaries: &[],
            attributes: nix_record! {
                "pname": "airlock-qubes", "version": env!("CARGO_PKG_VERSION"),
                "nativeBuildInputs": NixValue::list([pkgs.clone().select("pkg-config")]),
                "buildInputs": NixValue::list([python.clone(), pkgs.clone().select("udev")]),
                "PYO3_PYTHON": nix_text!("{python}/bin/python3", python = python.clone()),
                "doCheck": false,
                "postInstall": nix_text!(r#"
            site="$out/{site_packages}"
            mkdir -p "$site/airlock_qubes-0.1.0.dist-info"
            cp "$lib/lib/libairlock_qubes_native.so" "$site/airlock_qubes.so"
            cat > "$site/airlock_qubes-0.1.0.dist-info/METADATA" <<'METADATA'
            Metadata-Version: 2.1
            Name: airlock-qubes
            Version: 0.1.0
            METADATA
            cat > "$site/airlock_qubes-0.1.0.dist-info/entry_points.txt" <<'ENTRY_POINTS'
            [qubes.storage]
            airlock-closure = airlock_qubes:ClosurePool
            [qubes.vm]
            HermitVM = airlock_qubes:HermitVM
            [qubes.ext]
            airlock-hermit-network = airlock_qubes:HermitNetworking
            ENTRY_POINTS
        "#, site_packages = pkgs.clone().select("python3.sitePackages")),
                "meta": nix_record! {
                    "description": "Native Airlock plugins for upstream Qubes storage and lifecycle APIs",
                    "license": pkgs.clone().select("lib.licenses.mit"),
                    "platforms": pkgs.clone().select("lib.platforms.linux"),
                },
            },
        },
    );

    Package::from_expression(
        pkgs.clone()
            .select("python3.pkgs.toPythonModule")
            .call(native.clone())
            .merge_attrs(nix_record! { "buildArtifacts": native.select("buildArtifacts") }),
    )
}

/// Register GPU hooks only for machines that explicitly enable AMD firmware delivery.
/// The shared native module remains available to storage without enabling GPU lifecycle hooks.
pub fn gpu(pkgs: &NixValue, workspace: &Workspace) -> Package {
    let package = pkgs
        .clone()
        .select("runCommand")
        .call("airlock-qubes-gpu-hooks")
        .call(nix_record! {
            "propagatedBuildInputs": NixValue::list([qubes(pkgs, workspace).as_expression()]),
        })
        .call(nix_text!(
            r#"
            metadata="$out/{site_packages}/airlock_qubes_gpu-0.1.0.dist-info"
            mkdir -p "$metadata"
            cat > "$metadata/METADATA" <<'METADATA'
            Metadata-Version: 2.1
            Name: airlock-qubes-gpu
            Version: 0.1.0
            METADATA
            cat > "$metadata/entry_points.txt" <<'ENTRY_POINTS'
            [qubes.ext]
            airlock-amd-vbios = airlock_qubes:AMDVBIOS
            ENTRY_POINTS
        "#,
            site_packages = pkgs.clone().select("python3.sitePackages")
        ));

    Package::from_expression(
        pkgs.clone()
            .select("python3.pkgs.toPythonModule")
            .call(package),
    )
}
