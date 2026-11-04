//! Package fixed executable contracts as native launchers with explicit Nix dependencies.
//! The JSON contract is stored beside a copy of the launcher, so RPC arguments cannot replace it.

use crate::{Application, Workspace};
use rusix::{
    interop::{
        NixPath, Package,
        raw::{NixRepresentation, NixValue},
    },
    nix_record, nix_text,
};

/// Install a native command and its immutable arguments/environment contract.
/// The `airlockCommand` passthru exposes that contract for read-only inspection.
/// Link the executable into `/etc` rather than copying it: the launcher locates
/// its JSON beside its resolved executable, so both must stay in this package.
pub fn package(pkgs: &NixValue, workspace: &Workspace, name: &str, contract: NixValue) -> Package {
    let launcher = Application::Launcher.build(pkgs, workspace);
    let configuration = pkgs
        .clone()
        .select("writeText")
        .call(format!("{name}.json"))
        .call(NixValue::builtin("toJSON").call(contract.clone()));
    Package::from_expression(
        pkgs.clone()
            .select("runCommand")
            .call(name)
            .call(nix_record! { "passthru": nix_record! {
                "airlockCommand": contract.clone(),
                "buildArtifacts": launcher.as_expression().select("buildArtifacts"),
            } })
            .call(nix_text!(
                r#"
            install -Dm555 {launcher}/bin/airlock-exec "$out/bin/{name}"
            install -Dm444 {configuration} "$out/bin/{name}.json"
        "#,
                launcher = launcher,
                configuration = configuration,
                name = name
            )),
    )
}

/// Use the application source selected by the enclosing NixOS package set.
pub fn workspace(pkgs: &NixValue) -> Workspace {
    Workspace::new(NixPath::from_source_text(
        pkgs.clone()
            .select("airlockAppsSource")
            .to_text()
            .into_expr::<String>(),
    ))
}

/// Return either the package or its executable path for a fixed native contract.
pub fn command(pkgs: &NixValue, name: &str, contract: NixValue, bin: bool) -> NixValue {
    let package = package(pkgs, &workspace(pkgs), name, contract);
    if bin {
        package.as_expression()
    } else {
        nix_text!("{package}/bin/{name}", package = package, name = name).into()
    }
}

/// Adapt mixed authoring sites: native contracts install binaries; upstream shell stays shell.
pub fn writer(pkgs: &NixValue, bin: bool) -> NixValue {
    NixValue::function(|name| {
        NixValue::function(|body| {
            let launcher = Application::Launcher.build(pkgs, &workspace(pkgs));
            let configuration = pkgs
                .clone()
                .select("writeText")
                .call("airlock-command.json")
                .call(NixValue::builtin("toJSON").call(body.clone()));
            let package = pkgs
                .clone()
                .select("runCommand")
                .call(name.clone())
                .call(nix_record! { "passthru": nix_record! {
                    "airlockCommand": body.clone(),
                    "buildArtifacts": launcher.as_expression().select("buildArtifacts"),
                } })
                .call(nix_text!(
                    r#"
                install -Dm555 {launcher}/bin/airlock-exec "$out/bin/{name}"
                install -Dm444 {configuration} "$out/bin/{name}.json"
            "#,
                    launcher = launcher,
                    name = name.clone(),
                    configuration = configuration
                ));
            let native = if bin {
                package
            } else {
                nix_text!(
                    "{package}/bin/{name}",
                    package = package,
                    name = name.clone()
                )
                .into()
            };
            NixValue::if_else(
                NixValue::builtin("isAttrs").call(body.clone()),
                native,
                pkgs.clone()
                    .select(if bin {
                        "writeShellScriptBin"
                    } else {
                        "writeShellScript"
                    })
                    .call(name)
                    .call(body),
            )
        })
    })
}

/// Invoke a fixed native command from a NixOS lifecycle hook that requires shell text.
pub fn hook(pkgs: &NixValue, name: &str, contract: NixValue) -> NixValue {
    let command = command(pkgs, name, contract, false);
    nix_text!(
        r#"
        exec {command} "$@"
    "#,
        command = command
    )
    .into()
}
