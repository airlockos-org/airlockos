//! Populate a QEMU disk with the production VM store and offline Qubes state.
//! The carrier keeps the ordinary dom0 Nix store; guest payloads use the shared pool.

use super::{store, usb};
use airlock_build::{Application, Workspace};
use rusix::{
    interop::raw::{NixRepresentation, NixValue},
    nix_record, nix_text,
    nixos::{ContextualModule, ModuleBody},
};

/// Seed the normal Qubes database and guest storage before the first nested boot.
pub(crate) fn module(workspace: &Workspace, prepared: NixValue) -> NixValue {
    ContextualModule::with_arguments(["modulesPath"], |context| {
        let runtime = store::runtime(
            &context.pkgs,
            workspace,
            context.config.clone().select("airlock.qubes.topology"),
            prepared.clone(),
        );
        let native = Application::Dom0.build(&context.pkgs, workspace).as_expression();
        let image = usb::disk_builder(&context).call(
            usb::disk_arguments(&context, "nixos").merge_attrs(nix_record! { "copyChannel": false }),
        );
        let install = nix_text!(r#"
            echo "Local image: installing prepared Qubes runtime state" >&2
            if test -e /mnt/var/lib/qubes/qubes.xml; then
              echo "Refusing to replace an existing Qubes database during image preparation" >&2
              exit 1
            fi
            mkdir -p /mnt/var/lib/airlock/closure-store /mnt/var/lib/qubes
            {native}/bin/airlock-dom0-service storage build-progress --label "Local image: copying VM store" -- \
              cp -a --sparse=always {prepared}/pool/. /mnt/var/lib/airlock/closure-store/
            chmod -R go-rwx /mnt/var/lib/airlock/closure-store
            cp -a --sparse=always {runtime}/qubes/. /mnt/var/lib/qubes/
            cp -a {runtime}/pool-selections/. /mnt/var/lib/airlock/closure-store/
            chmod -R u+rwX /mnt/var/lib/qubes
            cp {runtime}/receipt.json /mnt/var/lib/airlock/prepared-runtime.json
        "#, native = native, prepared = prepared.clone(), runtime = runtime.clone());
        let ownership = r#"
            nixos-enter --root /mnt -- chown -R root:qubes /var/lib/qubes
            chmod 0660 /mnt/var/lib/qubes/qubes.xml
        "#;
        let image = context.lib.clone().select("overrideDerivation").call(image)
            .call(NixValue::function(|old| {
                let command = old.clone().select("buildCommand");
                let mounted = "mount $rootDisk $mountPoint";
                let unmount = "umount -R /mnt";
                let activate = "-- /nix/var/nix/profiles/system/bin/switch-to-configuration boot";
                let valid = [mounted, unmount, activate].into_iter().fold(true.into(), |valid: NixValue, hook| {
                    valid.and(context.lib.clone().select("hasInfix").call(hook).call(command.clone()))
                });
                let command = NixValue::builtin("replaceStrings")
                    .call(NixValue::list([mounted.into(), unmount.into(), activate.into()]))
                    .call(NixValue::list([
                        NixValue::concat_text([mounted.into(), "\n".into(), install.into()]),
                        NixValue::concat_text([ownership.into(), "\n".into(), unmount.into()]),
                        "-- env NIX_REMOTE=local NIX_CONFIG='store = local' /nix/var/nix/profiles/system/bin/switch-to-configuration boot".into(),
                    ]))
                    .call(command);
                NixValue::if_else(valid, nix_record! {
                    "buildCommand": command,
                    "preVM": NixValue::concat_text([
                        nix_text!("{check}\n", check = prepared.clone().select("checkCommand")).into(),
                        old.select("preVM"),
                    ]),
                }, NixValue::builtin("throw").call("Upstream disk assembly no longer exposes the checked runtime installation hooks."))
            }));

        ModuleBody::new(nix_record! {
            "system": nix_record! {
                "build": nix_record! {
                    "image": context.lib.clone().select("mkForce").call(image),
                    "localPreparedRuntime": runtime,
                },
            },
        }).module(ModuleBody::new(usb::prepared_configuration(&context, workspace, prepared)))
            .key("airlock.image.local")
    }).into_expression()
}
