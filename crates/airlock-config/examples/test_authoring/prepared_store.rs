//! Rust-authored fixtures evaluated by the native integration suite.

use super::*;

/// Exercise the production reference-detachment recipe with the already Cargo-built native tool.
/// Tiny executable/kernel fixtures test store references; ELF admission is covered separately.
pub(super) fn retention(inputs: NixValue) -> NixValue {
    let pkgs = NixValue::builtin("import")
        .call(inputs.clone().select("nixpkgs"))
        .call(rusix::nix_record! { "system": "x86_64-linux" });
    pkgs.bind(|pkgs| {
        let binary = NixValue::builtin("path").call(rusix::nix_record! {
            "path": NixPath::from_source_text(inputs.clone().select("native").into_expr::<String>()),
            "name": "airlock-dom0-cargo",
        });
        let native = pkgs.clone().select("runCommand").call("airlock-retention-native").call(rusix::nix_record! {
            "buildInputs": NixValue::list([
                pkgs.clone().select("lib.getLib").call(pkgs.clone().select("udev")),
                pkgs.clone().select("stdenv.cc.cc.lib"),
                pkgs.clone().select("python3"),
            ]),
        }).call(rusix::nix_text!(r#"
            mkdir -p "$out/bin"
            cp {binary} "$out/bin/airlock-dom0-service"
            chmod 0555 "$out/bin/airlock-dom0-service"
        "#, binary = binary));
        let executable = pkgs.clone().select("writeTextDir").call("kernel.elf").call("executable fixture");
        let kernel = pkgs.clone().select("writeTextDir").call("vmlinuz").call("kernel fixture");
        let guest = pkgs.clone().select("writeTextDir").call("root.img").call("Linux guest payload");
        let topology = rusix::nix_record! {
            "schema":"airlock.qubes-topology.v1",
            "kernels":rusix::nix_record! { "qubes-kernel":rusix::nix_record! { "source":kernel.clone().to_text() } },
            "domains":rusix::nix_record! {
                "sys-clipboard":rusix::nix_record! {
                    "class":"HermitVM", "netvm":NixValue::null(), "template":NixValue::null(),
                    "features":rusix::nix_record! { "qrexec":"", "gui":"" },
                    "prefs":rusix::nix_record! { "memory":32_i64,"maxmem":32_i64,"vcpus":1_i64,
                        "virt_mode":"pvh","kernel":"","guivm":NixValue::null(),"audiovm":NixValue::null() },
                    "backend":rusix::nix_record! { "type":"hermit","system":rusix::nix_record! { "source":executable.clone().to_text() },
                        "artifact":rusix::nix_record! { "schema":"airlock.hermit-pvh.v1", "executable":rusix::nix_text!("{image}/kernel.elf",image=executable.clone()),
                            "bytes":64_i64,"sha256":"a".repeat(64),"source_revision":"b".repeat(40),
                            "integration_revision":"c".repeat(40),"build_lock":"d".repeat(64),"authority":"disconnected" } },
                },
                "usr-home":rusix::nix_record! {
                    "class":"StandaloneVM", "netvm":NixValue::null(),"template":NixValue::null(),
                    "backend":rusix::nix_record! { "type":"nix-closure", "system":rusix::nix_record! { "source":guest.clone().to_text() },
                        "root":rusix::nix_record! { "source":rusix::nix_text!("{guest}/root.img",guest=guest.clone()) },
                        "kernel":rusix::nix_record! { "name":"qubes-kernel" },
                        "store":rusix::nix_record! { "source":guest.clone().to_text(),"mode":"shared-closure",
                            "device":"/dev/xvde","blobDevice":"/dev/xvdf","mountpoint":"/nix/store","viewBackend":"erofs-objectmap" } },
                },
            },
        };
        let topology = pkgs.clone().select("writeText").call("mixed-boot-topology.json").call(NixValue::builtin("toJSON").call(topology));
        let detached = airlock_build::store::detached_boot_topology(&pkgs, &native, topology, "".into());
        let required = detached.clone().select("requirements");
        let system = pkgs.clone().select("runCommand").call("airlock-retained-host").call(rusix::nix_record! {})
            .call(rusix::nix_text!(r#"
                mkdir -p "$out"
                ln -s {required} "$out/boot-requirements"
            "#, required=required.clone()));
        rusix::nix_record! {
            "system":system,
            "report":rusix::nix_record! { "executable":executable.to_text(),"kernel":kernel.to_text(),
                "guest":guest.to_text(),"requirements":required.to_text(),"detached":detached.to_text(),"native":native.to_text() },
        }
    })
}

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
            "checkedBuilder": airlock_build::vm::checked_image_builder(
                &"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-native".into(),
                &"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-seed".into(),
                &"/nix/store/cccccccccccccccccccccccccccccccc-topology".into(),
                &"/nix/store/dddddddddddddddddddddddddddddddd-host".into(),
                &rusix::nix_record! { "builder": "/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-builder", "args": NixValue::list(["-e".into(), "upstream.sh".into()]) },
            ),
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
                "requiredBootArtifacts",
                boot.clone()
                    .select("system.build.requiredBootArtifacts")
                    .to_text(),
            ),
            (
                "bootArtifactReport",
                NixValue::builtin("fromJSON").call(
                    NixValue::builtin("unsafeDiscardStringContext").call(
                        NixValue::builtin("readFile")
                            .call(boot.clone().select("system.build.requiredBootArtifacts")),
                    ),
                ),
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
