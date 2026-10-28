//! Supply the admitted Rust toolchain and dependency vendor tree to machine-authoring VMs.

use airlock_build::Workspace;
use rusix::{
    interop::{NixPath, raw::NixValue},
    nix_record, nix_text,
    nixos::{ContextualModule, ModuleBody},
};

/// Keep authoring offline and reproducible without provisioning tools in quick tests or on dom0.
pub(super) fn module(machine: &NixPath, workspace: &Workspace) -> NixValue {
    ContextualModule::new(|context| {
        let role = context.config.clone().select("airlock.qubeGuest.role");
        let enabled = NixValue::builtin("elem").call(role.clone()).call(NixValue::list([
            "sys-ctrl".into(),
            "usr-assistant".into(),
            "sys-config-vault".into(),
            "sys-config-staging".into(),
            "sys-config-validator".into(),
        ]));
        let manifest = machine.join_relative("Cargo.toml").unwrap();
        let machine_compiler = NixValue::builtin("pathExists").call(manifest.clone()).and(
            NixValue::builtin("fromTOML")
                .call(NixValue::builtin("readFile").call(manifest))
                .select("package.name").equals("airlock-machine-config"),
        );
        let settings = nix_record! {
            "environment": nix_record! {
                "systemPackages": NixValue::list(
                    ["cargo", "rustc", "stdenv.cc", "pkg-config", "gitMinimal", "gnumake"]
                        .map(|name| context.pkgs.clone().select(name)),
                ),
                "etc": (nix_record! {
                    "airlock/authoring/vendor": nix_record! {
                        "source": dependencies(&context.pkgs, &workspace.root()),
                    },
                    "airlock/config-inputs/airlock-apps": nix_record! {
                        "source": workspace.root(),
                    },
                }).merge_attrs(context.lib.clone().select("optionalAttrs").call(role.equals("sys-ctrl").and(machine_compiler)).call(nix_record! {
                    "airlock/authoring/compiler": nix_record! {
                        "source": compiler(&context.pkgs, workspace, machine),
                    },
                })),
            },
        };

        ModuleBody::new(context.lib.select("mkIf").call(enabled).call(settings))
            .key("airlock.vm.authoring")
    })
    .into_expression()
}

/// Compile the installed machine during image/release construction, before its first user request.
/// This is a build-time executable and source receipt; no build cache is imported from usr-assistant.
pub(crate) fn compiler(pkgs: &NixValue, workspace: &Workspace, machine: &NixPath) -> NixValue {
    // Flake self paths can be context-free strings. Capture an actual store input for the sandbox.
    let source = NixValue::builtin("path").call(nix_record! {
        "path": machine.clone(), "name": "airlock-machine-compiler-source",
    });
    let applications = NixValue::builtin("path").call(nix_record! {
        "path": workspace.root(), "name": "airlock-machine-compiler-apps",
    });
    pkgs.clone().select("runCommand").call("airlock-installed-machine-compiler")
        .call(nix_record! {
            "nativeBuildInputs": NixValue::list(["cargo", "rustc", "stdenv.cc"].map(|name| pkgs.clone().select(name))),
            "AIRLOCK_ADMITTED_APPS": workspace.root(),
        })
        .call(nix_text!(r#"
            cp -r {source} source
            chmod -R u+w source
            cd source
            export CARGO_HOME="$TMPDIR/cargo"
            mkdir -p "$CARGO_HOME"
            cargo_args=(
              --config 'patch.crates-io.airlock-config.path="{apps}/airlock-config"'
              --config 'source.airlock-admitted.directory="{vendor}"'
            )
            cargo "${{cargo_args[@]}}" build --release --locked --offline
            cargo "${{cargo_args[@]}}" metadata --locked --offline --no-deps --format-version 1 > "$TMPDIR/metadata.json"
            target/release/airlock-machine-config package-compiler "$out" "$TMPDIR/metadata.json"
        "#, source = source, apps = applications, vendor = dependencies(pkgs, &workspace.root())))
}

/// Vendor the pinned application workspace dependencies for machine and candidate compilation.
pub(crate) fn dependencies(pkgs: &NixValue, applications: &NixPath) -> NixValue {
    pkgs.clone()
        .select("rustPlatform.importCargoLock")
        .call(Workspace::new(applications.clone()).cargo_lock())
}
