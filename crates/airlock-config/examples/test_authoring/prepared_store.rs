//! Rust-authored fixtures evaluated by the native integration suite.

use super::*;

/// Evaluate real upstream host-side disk hooks without building a system, disk or assembly VM.
pub(super) fn raw_disk_hooks(inputs: NixValue) -> NixValue {
    let source = inputs.clone().select("nixpkgs");
    let pkgs = NixValue::builtin("import")
        .call(source.clone())
        .call(rusix::nix_record! {
            "system": "x86_64-linux",
        });
    pkgs.bind(|pkgs| {
        let image = NixValue::builtin("import")
            .call(add(source, "/nixos/lib/make-disk-image.nix".into()))
            .call(rusix::nix_record! {
                "pkgs": pkgs.clone(),
                "lib": pkgs.clone().select("lib"),
                "config": rusix::nix_record! {
                    "system": rusix::nix_record! {
                        "build": rusix::nix_record! {
                            "toplevel": pkgs.clone().select("writeText").call("unbuilt-system").call(""),
                            "nixos-install": pkgs.clone().select("coreutils"),
                        },
                    },
                },
                "baseName": "airlock-staging-fixture",
                "format": "raw",
                "partitionTableType": "efi",
                "diskSize": 64_i64,
                "installBootLoader": false,
                "copyChannel": false,
            });
        let image = NixValue::if_else(
            inputs.select("changedUpstream"),
            image.clone().override_attrs(NixValue::function(|_| rusix::nix_record! {
                "preVM": r#"
                    mkdir $out
                    diskImage=changed.raw
                "#,
            })),
            image,
        );
        let image = airlock_build::vm::raw_disk_in_output(&pkgs.select("lib"), image);

        rusix::nix_record! {
            "preVM": image.clone().select("preVM"),
            "postVM": image.select("postVM"),
        }
    })
}

/// Exercise real cache derivations with two tiny package closures instead of an image or VM build.
pub(super) fn cache(inputs: NixValue) -> NixValue {
    let workspace = airlock_build::Workspace::new(NixPath::from_source_text(
        inputs
            .clone()
            .select("apps")
            .to_text()
            .into_expr::<String>(),
    ));
    let pkgs = NixValue::builtin("import")
        .call(inputs.clone().select("nixpkgs"))
        .call(rusix::nix_record! {
            "system": "x86_64-linux",
            "overlays": NixValue::list([airlock_build::overlays::image_tools(&workspace)]),
        });
    pkgs.bind(|pkgs| {
        let left = pkgs
            .clone()
            .select("writeText")
            .call("airlock-cache-left")
            .call("unchanged package");
        let right = pkgs
            .clone()
            .select("writeText")
            .call("airlock-cache-right")
            .call(inputs.clone().select("variant"));
        let closure = |roots| {
            pkgs.clone()
                .select("closureInfo")
                .call(rusix::nix_record! { "rootPaths": roots })
        };
        airlock_build::store::image_cache(
            &pkgs,
            &workspace,
            NixValue::list([
                closure(NixValue::list([left.clone()])),
                closure(NixValue::list([left, right])),
            ]),
        )
    })
}

/// Inspect evaluated configuration for test usb prepared store preserves sealed view mode.
pub(super) fn sealed_store(inputs: NixValue) -> NixValue {
    NixValue::builtin("getFlake")
        .call(NixValue::concat_text([inputs
            .clone()
            .select("root")
            .to_text()]))
        .select_segments(["nixosConfigurations", "usb-dev", "config"])
        .bind(prepared_store_sealed_store_body)
}

/// Build the prepared store test usb prepared store preserves sealed view mode contribution using
/// the caller supplied deferred values.
fn prepared_store_sealed_store_body(config: NixValue) -> NixValue {
    {
        let boot = config
            .clone()
            .select("specialisation.usb-lab.configuration");
        let field_recovery_recorder = config.clone().select_segments([
            "specialisation",
            "usb-text-recovery",
            "configuration",
            "boot",
            "initrd",
            "systemd",
            "services",
            "airlock-boot-journal",
            "serviceConfig",
            "ExecStart",
        ]);

        NixValue::record([
            (
                "mode",
                config
                    .clone()
                    .select_segments(["airlock", "image", "preparedStoreMode"]),
            ),
            (
                "image",
                config
                    .clone()
                    .select_segments(["system", "build", "image", "drvPath"]),
            ),
            (
                "validation",
                config.clone().select_segments([
                    "system",
                    "build",
                    "usbPreparedGuestStore",
                    "validation",
                    "outPath",
                ]),
            ),
            (
                "checkCommand",
                config.clone().select_segments([
                    "system",
                    "build",
                    "usbPreparedGuestStore",
                    "checkCommand",
                ]),
            ),
            (
                "preVM",
                config
                    .clone()
                    .select_segments(["system", "build", "image", "preVM"]),
            ),
            (
                "imageCommand",
                config
                    .clone()
                    .select_segments(["system", "build", "image", "buildCommand"]),
            ),
            (
                "runtimeSeed",
                config.clone().select_segments([
                    "system",
                    "build",
                    "usbPreparedRuntime",
                    "outPath",
                ]),
            ),
            (
                "dependencies",
                NixValue::builtin("map")
                    .call(NixValue::builtin("toString"))
                    .call(
                        config
                            .clone()
                            .select_segments(["system", "extraDependencies"]),
                    ),
            ),
            (
                "bootDependencies",
                NixValue::builtin("map")
                    .call(NixValue::builtin("toString"))
                    .call(boot.clone().select("system.extraDependencies")),
            ),
            (
                "hermitExecutables",
                NixValue::builtin("map")
                    .call(NixValue::function(|domain| {
                        domain.select("backend.system.source")
                    }))
                    .call(
                        NixValue::builtin("filter")
                            .call(NixValue::function(|domain| {
                                domain.clone().select("backend.type").equals("hermit")
                            }))
                            .call(
                                NixValue::builtin("attrValues")
                                    .call(boot.select("airlock.qubes.topology.domains")),
                            ),
                    ),
            ),
            (
                "hostOrdering",
                config.clone().select_segments([
                    "boot",
                    "initrd",
                    "systemd",
                    "services",
                    "initrd-find-nixos-closure",
                    "after",
                ]),
            ),
            (
                "earlyLogs",
                config.clone().select_segments([
                    "boot",
                    "initrd",
                    "systemd",
                    "services",
                    "airlock-boot-journal",
                    "serviceConfig",
                    "ExecStart",
                ]),
            ),
            (
                "recoveryLogs",
                config
                    .clone()
                    .select_segments([
                        "specialisation",
                        "usb-text-recovery",
                        "configuration",
                        "boot",
                        "initrd",
                        "systemd",
                        "services",
                    ])
                    .has_attr("airlock-boot-journal"),
            ),
            ("recoveryRecorder", field_recovery_recorder),
            (
                "journalConfig",
                config
                    .clone()
                    .select_segments(["services", "journald", "settings", "Journal"]),
            ),
            (
                "daemonConfig",
                config.clone().select_segments([
                    "systemd",
                    "services",
                    "nix-daemon",
                    "environment",
                    "NIX_CONFIG",
                ]),
            ),
        ])
    }
}
