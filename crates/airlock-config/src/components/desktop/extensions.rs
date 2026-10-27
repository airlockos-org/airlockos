//! Package Airlock's GNOME Shell extensions while keeping their JavaScript and CSS as assets.
//! Assets live beside the sys-gui crates, outside their filtered Rust build inputs.
//! Extension order is shared by installation and GNOME's enabled-extension setting.

use super::{ModuleContext, machine_source};
use airlock_sys_gui_service::command::DesktopCommand;
use rusix::{
    interop::{
        NixPath, Package,
        raw::{NixRepresentation, NixValue},
    },
    nix_record, nix_text,
};

/// A Shell extension's installed identity and package, kept together for session configuration.
pub(super) struct Extension {
    /// GNOME UUID matching the extension's metadata and installation directory.
    pub id: String,
    /// Derivation containing the extension and any substituted native helper paths.
    pub package: NixValue,
}

/// Builds the extensions in their activation order using the final GUI package set.
pub(super) fn packages(inputs: &ModuleContext, service: &super::Deployment) -> [Extension; 5] {
    let identity_reader = service.window_identity_reader(Package::from_expression(
        inputs.pkgs.clone().select("qubes-gui-daemon"),
    ));

    [
        host_poweroff(inputs),
        startup_progress(inputs, service),
        focused_vm(inputs, &identity_reader),
        vm_search(inputs),
        vm_workspaces(inputs, &identity_reader),
    ]
}

/// Install a persistent startup indicator backed by the existing read-only boot-status transport.
fn startup_progress(inputs: &ModuleContext, service: &super::Deployment) -> Extension {
    let reader = inputs
        .pkgs
        .clone()
        .select("writeShellScript")
        .call("airlock-startup-panel-status")
        .call(nix_text!(
            r#"
                exec {command}
            "#,
            command = service.shell_command(&DesktopCommand::StartupStatus),
        ));

    extension(
        inputs,
        "startup-progress",
        nix_text!(
            r#"
                cp extension.js model.js metadata.json stylesheet.css "$extension_dir/"
                substituteInPlace "$extension_dir/extension.js" \
                  --replace-fail '@statusReader@' '{reader}'
            "#,
            reader = reader.clone(),
        )
        .into(),
        nix_record! { "statusReader": reader },
    )
}

/// Installs the host power-off action through Qubes' existing dom0 RPC service.
fn host_poweroff(inputs: &ModuleContext) -> Extension {
    let host_poweroff = inputs
        .pkgs
        .clone()
        .select("writeShellScript")
        .call("airlock-gnome-host-poweroff")
        .call(nix_text!(
            r#"
                exec {client}/bin/qvm-run \
                  --pass-io --no-gui --service dom0 airlock.Dom0Poweroff
            "#,
            client = inputs
                .pkgs
                .clone()
                .select("python3.pkgs.qubes-core-admin-client"),
        ));
    let install = nix_text!(
        r#"
            cp extension.js metadata.json "$extension_dir/"
            substituteInPlace "$extension_dir/extension.js" \
              --replace-fail '@hostPoweroff@' '{host_poweroff}'
        "#,
        host_poweroff = host_poweroff.clone(),
    );

    extension(
        inputs,
        "host-poweroff",
        install.into(),
        nix_record! {
            "hostPoweroff": host_poweroff,
        },
    )
}

/// Installs focused-window identity using the native Qubes window-identity reader.
fn focused_vm(inputs: &ModuleContext, identity_reader: &NixValue) -> Extension {
    let install = nix_text!(
        r#"
            cp extension.js state.js metadata.json stylesheet.css "$extension_dir/"
            substituteInPlace "$extension_dir/extension.js" \
              --replace-fail '@identityReader@' '{identity_reader}'
        "#,
        identity_reader = identity_reader.clone(),
    );

    extension(
        inputs,
        "focused-vm",
        install.into(),
        nix_record! {
            "identityReader": identity_reader.clone(),
        },
    )
}

/// Installs VM search using the Shell extension's existing inventory model.
fn vm_search(inputs: &ModuleContext) -> Extension {
    extension(
        inputs,
        "vm-search",
        nix_text!(
            r#"
                cp extension.js model.js metadata.json stylesheet.css "$extension_dir/"
            "#
        )
        .into(),
        nix_record! {},
    )
}

/// Installs workspace placement with the shared identity and inventory JavaScript models.
fn vm_workspaces(inputs: &ModuleContext, identity_reader: &NixValue) -> Extension {
    // Snapshot each shared model independently so sandboxed builds receive its contents.
    // Converting a source path to plain text would retain an inaccessible checkout path.
    let install = nix_text!(
        r#"
            cp extension.js model.js metadata.json stylesheet.css "$extension_dir/"
            cp {identity_model} "$extension_dir/identity.js"
            cp {inventory_model} "$extension_dir/inventory.js"
            substituteInPlace "$extension_dir/extension.js" \
              --replace-fail '@identityReader@' '{identity_reader}'
        "#,
        identity_model =
            NixPath::from_expression(asset(inputs, "focused-vm-extension/state.js")).snapshot(),
        inventory_model =
            NixPath::from_expression(asset(inputs, "vm-search-extension/model.js")).snapshot(),
        identity_reader = identity_reader.clone(),
    );

    extension(inputs, "vm-workspaces", install.into(), nix_record! {})
}

/// Packages an extension directory with its UUID and native-helper metadata.
/// Install commands end with a newline so the post-install hook starts on its own line.
fn extension(
    inputs: &ModuleContext,
    name: &str,
    install: NixValue,
    passthru: NixValue,
) -> Extension {
    let id = format!("airlock-{name}@airlock.local");
    let install_phase = NixValue::concat_text([
        nix_text!(
            r#"
                runHook preInstall
                extension_dir="$out/share/gnome-shell/extensions/{id}"
                mkdir -p "$extension_dir"
            "#,
            id = id.as_str(),
        )
        .into(),
        install,
        nix_text!(
            r#"
                runHook postInstall
            "#
        )
        .into(),
    ]);
    let package = inputs
        .pkgs
        .clone()
        .select("stdenvNoCC.mkDerivation")
        .call(nix_record! {
            "pname": format!("airlock-gnome-{name}"),
            "version": "1",
            "src": NixPath::from_expression(asset(inputs, &format!("{name}-extension"))).snapshot(),
            "dontBuild": true,
            "installPhase": install_phase,
            "passthru": passthru,
        });

    Extension { id, package }
}

/// Resolves GNOME implementation assets from the admitted application source with Nix path context.
fn asset(inputs: &ModuleContext, relative: &str) -> NixValue {
    machine_source::application_source(inputs)
        .join_relative(&format!("runtime/airlock-sys-gui/gnome/{relative}"))
        .expect("extension asset paths are static and relative")
        .as_expression()
}
