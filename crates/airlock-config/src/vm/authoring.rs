//! Supply the admitted Rust toolchain and dependency vendor tree to machine-authoring VMs.

use airlock_build::Workspace;
use rusix::{
    interop::{NixPath, raw::NixValue},
    nix_record,
    nixos::{ContextualModule, ModuleBody},
};

/// Keep authoring offline and reproducible without provisioning tools in quick tests or on dom0.
pub(super) fn module(workspace: &Workspace) -> NixValue {
    ContextualModule::new(|context| {
        let role = context.config.clone().select("airlock.qubeGuest.role");
        let enabled = NixValue::builtin("elem").call(role).call(NixValue::list([
            "sys-ctrl".into(),
            "usr-assistant".into(),
            "sys-config-vault".into(),
            "sys-config-staging".into(),
            "sys-config-validator".into(),
        ]));
        let settings = nix_record! {
            "environment": nix_record! {
                "systemPackages": NixValue::list(
                    ["cargo", "rustc", "stdenv.cc", "pkg-config", "gitMinimal", "gnumake"]
                        .map(|name| context.pkgs.clone().select(name)),
                ),
                "etc": nix_record! {
                    "airlock/authoring/vendor": nix_record! {
                        "source": dependencies(&context.pkgs, &workspace.root()),
                    },
                    "airlock/config-inputs/airlock-apps": nix_record! {
                        "source": workspace.root(),
                    },
                },
            },
        };

        ModuleBody::new(context.lib.select("mkIf").call(enabled).call(settings))
            .key("airlock.vm.authoring")
    })
    .into_expression()
}

/// Vendor the pinned application workspace dependencies for machine and candidate compilation.
pub(crate) fn dependencies(pkgs: &NixValue, applications: &NixPath) -> NixValue {
    pkgs.clone()
        .select("rustPlatform.importCargoLock")
        .call(Workspace::new(applications.clone()).cargo_lock())
}
