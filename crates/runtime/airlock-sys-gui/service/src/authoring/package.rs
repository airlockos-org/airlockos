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
    let source = workspace.package_source(EXECUTABLE, true, &[]);
    let mut flags: Vec<NixValue> = source.arguments().into_iter().map(NixValue::from).collect();
    flags.extend(["--bin".into(), EXECUTABLE.into()]);

    let tools = NixValue::list(
        [
            "glib",
            "libnotify",
            "xdg-user-dirs",
            "ffmpeg-headless",
            "systemd",
            "coreutils",
        ]
        .map(|name| pkgs.clone().select(name)),
    );
    let install = nix_text!(
        r#"
            wrapProgram "$out/bin/{executable}" \
              --prefix PATH : {tools}
        "#,
        executable = EXECUTABLE,
        tools = lib.clone().select("makeBinPath").call(tools),
    );

    Package::from_expression(pkgs.clone().select("rustPlatform.buildRustPackage").call(
        nix_record! {
            "pname": EXECUTABLE,
            "version": env!("CARGO_PKG_VERSION"),
            "src": source.source(&lib),
            "cargoLock": workspace.cargo_lock(),
            "cargoBuildFlags": NixValue::list(flags),
            "doCheck": false,
            "nativeBuildInputs": NixValue::list([pkgs.clone().select("makeWrapper")]),
            "postInstall": install,
            "meta": nix_record! {
                "description": "Airlock desktop integration in sys-gui",
                "mainProgram": EXECUTABLE,
                "license": lib.clone().select("licenses.mit"),
                "platforms": lib.select("platforms.linux"),
            },
        },
    ))
}

/// Install the native desktop implementation with Qubes' C RPC client and QubesDB identity reader.
pub(super) fn wrapped(pkgs: &NixValue, sources: &Sources) -> Package {
    let native = native(pkgs, &sources.apps);
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
            }),
    )
}
