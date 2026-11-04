//! Package the native executable and its upstream Qubes desktop integration.

use super::Sources;
use crate::command::EXECUTABLE;
use rusix::{
    interop::{
        NixPath, Package,
        raw::{NixRepresentation, NixValue},
    },
    nix_record, nix_text,
};

/// Builds the service binary with the Cargo lockfile and its native runtime tools.
pub(super) fn native(pkgs: &NixValue, apps: &NixPath) -> Package {
    let lib = pkgs.clone().select("lib");
    let workspace = airlock_build::Workspace::new(apps.clone());

    let tools = NixValue::list(
        [
            "glib",
            "libnotify",
            "xdg-user-dirs",
            "ffmpeg-headless",
            "systemd",
            "coreutils",
            "bubblewrap",
        ]
        .map(|name| pkgs.clone().select(name)),
    );
    let install = nix_text!(
        r#"
            wrapProgram "$out/bin/{executable}" \
              --prefix PATH : {tools} \
              --set AIRLOCK_PREFERENCES_BWRAP {bubblewrap}/bin/bwrap
        "#,
        executable = EXECUTABLE,
        tools = lib.clone().select("makeBinPath").call(tools),
        bubblewrap = pkgs.clone().select("bubblewrap"),
    );

    Package::from_expression(airlock_build::crate_graph::package(
        pkgs,
        &workspace,
        airlock_build::crate_graph::Build {
            member: Some(EXECUTABLE),
            features: &["default"],
            binaries: &[EXECUTABLE],
            attributes: nix_record! {
                "pname": EXECUTABLE,
                "version": env!("CARGO_PKG_VERSION"),
                "doCheck": false,
                "nativeBuildInputs": NixValue::list([pkgs.clone().select("makeWrapper"), pkgs.clone().select("pkg-config")]),
                "buildInputs": NixValue::list([pkgs.clone().select("glib")]),
                "postInstall": install,
                "meta": nix_record! {
                    "description": "Airlock desktop integration in sys-gui",
                    "mainProgram": EXECUTABLE,
                    "license": lib.clone().select("licenses.mit"),
                    "platforms": lib.select("platforms.linux"),
                },
            },
        },
    ))
}

/// Install the native desktop implementation with Qubes' C RPC client and QubesDB identity reader.
pub(super) fn wrapped(pkgs: &NixValue, sources: &Sources) -> Package {
    let native = native(pkgs, &sources.apps);
    let artifacts = native.as_expression().select("buildArtifacts");
    Package::from_expression(
        pkgs.clone()
            .select("writeShellApplication")
            .call(nix_record! {
                "name": EXECUTABLE,
                "runtimeInputs": NixValue::list([
                    pkgs.clone().select("python3.pkgs.qubes-core-admin-client"),
                    pkgs.clone().select("python3.pkgs.qubes-core-qrexec.domU"),
                    pkgs.clone().select("qubes-core-qubesdb"),
                ]),
                "text": nix_text!(
                    r#"
                exec {native}/bin/{executable} "$@"
            "#,
                    native = native,
                    executable = EXECUTABLE,
                ),
                "meta": nix_record! {
                    "description": "Airlock desktop integration in sys-gui",
                    "license": pkgs.clone().select("lib.licenses.mit"),
                },
            })
            .merge_attrs(nix_record! { "buildArtifacts": artifacts }),
    )
}
