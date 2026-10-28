//! Prepare shared VM payloads and host closures without retaining a second store on dom0.

use airlock_build::{Application, Workspace, adapters};
use rusix::{
    interop::{
        NixExpression,
        raw::{NixRepresentation, NixValue},
    },
    nix_record, nix_text,
};

/// Materialize VM descriptors, immutable payload objects and independent builder views.
pub(crate) fn prepared(
    pkgs: &NixValue,
    workspace: &Workspace,
    entries: NixValue,
    offline: NixValue,
) -> NixValue {
    let lib = pkgs.clone().select("lib");
    let entries = lib
        .clone()
        .select("filterAttrs")
        .call(NixValue::function(|_| {
            NixValue::function(|entry| {
                entry
                    .attr_or("backendType", "nix-closure")
                    .equals("nix-closure")
            })
        }))
        .call(entries);
    let native = Application::Dom0.build(pkgs, workspace).as_expression();
    let specs = lib
        .clone()
        .select("mapAttrsToList")
        .call(NixValue::function(|name| {
            NixValue::function(|entry| {
                nix_record! {
                    "name": name,
                    "domain": nix_text!(
                        "{domain}-runtime-store",
                        domain = entry.clone().attr_or("preparedDomainName", "sys-gui"),
                    ),
                    "system": entry
                        .clone()
                        .select("configuration.config.system.build.toplevel")
                        .to_text(),
                    "root_source": nix_text!(
                        "{image}/root.img",
                        image = entry.clone().select("rootImage"),
                    ),
                    "kernel_name": entry.clone().select("domain.backend.kernel.name"),
                    "closure_source": entry.select("storeArtifact").to_text(),
                }
            })
        }))
        .call(entries.clone());
    // VM build hooks must come from that VM's package set, not the image assembler's EROFS overlay.
    let build_pkgs = NixValue::if_else(
        entries.clone().has_attr("usr-home"),
        entries.clone().select("usr-home.configuration.pkgs"),
        pkgs.clone(),
    );
    let routine = NixValue::list(
        [
            "composefs",
            "composefs.lib",
            "composefs.dev",
            "dieHook",
            "file",
            "gnu-config",
            "libcap",
            "libcap-text-verifier",
            "makeShellWrapper",
            "patchelf",
            "stdenvNoCC",
            "updateAutotoolsGnuConfigScriptsHook",
        ]
        .map(|name| build_pkgs.clone().select(name)),
    );
    let sources = lib.clone().select("unique").call(
        lib.clone()
            .select("mapAttrsToList")
            .call(NixValue::function(|_| {
                NixValue::function(|source| {
                    NixValue::builtin("elemAt")
                        .call(
                            NixValue::builtin("match")
                                .call("(/nix/store/[^/]+)(/.*)?")
                                .call(source),
                        )
                        .call(0_i64)
                })
            }))
            .call(offline.clone().select("inputs")),
    );
    let sources = NixValue::if_else(
        offline.clone().equals(NixValue::null()),
        NixValue::list([]),
        NixValue::builtin("map")
            .call(NixValue::function(|path| {
                NixValue::builtin("storePath").call(path)
            }))
            .call(sources),
    );
    let systems = NixValue::builtin("map")
        .call(NixValue::function(|entry| {
            entry.select("configuration.config.system.build.toplevel")
        }))
        .call(NixValue::builtin("attrValues").call(entries.clone()));
    let roots = NixValue::concat_lists([
        systems,
        NixValue::if_else(
            entries.clone().has_attr("usr-assistant"),
            NixValue::concat_lists([routine, sources]),
            NixValue::list([]),
        ),
    ]);
    let closure = pkgs.clone().select("closureInfo").call(nix_record! {
        "rootPaths": roots.clone(),
    });
    let copy_inputs = NixValue::if_else(
        offline.clone().equals(NixValue::null()),
        "",
        nix_text!(
            r#"
            cp {inputs} "$out/flake-inputs.json"
        "#,
            inputs = json(pkgs, "airlock-offline-inputs.json", offline),
        ),
    );
    let manifest = pkgs
        .clone()
        .select("runCommand")
        .call("usr-assistant-build-store-closure")
        .call(nix_record! {})
        .call(nix_text!(
            r#"
            mkdir -p "$out"
            cp {closure}/store-paths {closure}/registration "$out/"
            echo '{{}}' > "$out/manifest.json"
            {copy_inputs}
        "#,
            closure = closure.clone(),
            copy_inputs = copy_inputs,
        ));
    let builders = NixValue::builtin("filter")
        .call(NixValue::function(|role| entries.clone().has_attr(role)))
        .call(NixValue::list(["usr-assistant".into(), "sys-ctrl".into()]));
    let builder_specs = NixValue::builtin("map")
        .call(NixValue::function(|role| {
            let name: NixValue = nix_text!("{role}-build-store", role = role.clone()).into();
            let entry = NixValue::builtin("getAttr")
                .call(role)
                .call(entries.clone());

            nix_record! {
                "name": name.clone(),
                "domain": name,
                "system": entry
                    .select("configuration.config.system.build.toplevel")
                    .to_text(),
                "root_source": "",
                "kernel_name": "",
                "closure_source": manifest.to_text(),
                "builder": true,
            }
        }))
        .call(builders);
    let specs = json(
        pkgs,
        "prepared-guest-specs.json",
        NixValue::concat_lists([specs, builder_specs]),
    );
    let guest_closures = NixValue::builtin("map")
        .call(NixValue::function(|entry| {
            pkgs.clone().select("closureInfo").call(nix_record! {
                "rootPaths": NixValue::list([entry.select("configuration.config.system.build.toplevel")]),
            })
        }))
        .call(NixValue::builtin("attrValues").call(entries.clone()));
    let cache = airlock_build::store::image_cache(
        pkgs,
        workspace,
        NixValue::concat_lists([guest_closures, NixValue::list([closure.clone()])]),
    );
    let seed = pkgs
        .clone()
        .select("runCommand")
        .call("airlock-usb-prepared-guest-store")
        .call(nix_record! {
            "__structuredAttrs": true,
            "outputs": NixValue::list(["out".into(), "descriptors".into()]),
            "nativeBuildInputs": NixValue::list([
                native.clone(),
                pkgs.clone().select("erofs-utils"),
                pkgs.clone().select("gnutar"),
            ]),
            // Store paths inside the payload identify installed VM objects; they are not dom0 closure roots.
            "unsafeDiscardReferences": nix_record! {
                "out": true,
                "descriptors": true,
            },
            "passthru": nix_record! {
                "builderInputClosure": closure,
                "builderInputRoots": roots,
                "builderNix": entries.select("usr-assistant.configuration.pkgs.nix"),
            },
            "AIRLOCK_CLOSURE_STORE_INDEX_SOURCE": "file",
        })
        .call(nix_text!(
            r#"
        airlock-dom0-service storage image prepare-pool \
          "$out/pool" "$descriptors" {specs} /var/lib/airlock/closure-store \
          --cache {cache}
    "#,
            specs = specs,
            cache = cache.clone(),
        ));

    seed.bind(|seed| {
        let check: NixValue = nix_text!(
            "{native}/bin/airlock-dom0-service storage image verify-outputs {seed}/pool {descriptors}",
            native = native.clone(),
            seed = seed.clone(),
            descriptors = seed.clone().select("descriptors"),
        )
        .into();
        let validation = pkgs
            .clone()
            .select("runCommand")
            .call("airlock-usb-prepared-store-validation")
            .call(nix_record! {
                "nativeBuildInputs": NixValue::list([native]),
            })
            .call(nix_text!(
                r#"
                {check} > "$out"
            "#,
                check = check.clone(),
            ));

        seed.merge_attrs(nix_record! {
            "checkCommand": check,
            "validation": validation,
            "imageCache": cache,
        })
    })
}

/// Select the normal USB boot topology rather than the carrier's recovery-only declarations.
pub(super) fn boot_topology(config: &NixValue) -> NixValue {
    NixValue::if_else(
        config.clone().select("specialisation").has_attr("usb-lab"),
        config
            .clone()
            .select("specialisation.usb-lab.configuration.airlock.qubes.topology"),
        config.clone().select("airlock.qubes.topology"),
    )
}

/// Add the host and alternative boot generations to the same immutable object pool.
pub(super) fn unified(
    pkgs: &NixValue,
    workspace: &Workspace,
    config: &NixValue,
    vm_store: NixValue,
) -> NixValue {
    let native = Application::Dom0.build(pkgs, workspace).as_expression();
    let system = config.clone().select("system.build.toplevel");
    let closure = pkgs.clone().select("closureInfo").call(nix_record! {
        "rootPaths": NixValue::list([system.clone()]),
    });
    let builder_closure = pkgs.clone().select("closureInfo").call(nix_record! {
        "rootPaths": NixValue::concat_lists([
            vm_store.clone().select("builderInputRoots"),
            NixValue::list([system.clone()]),
        ]),
    });
    let cache = airlock_build::store::image_cache(
        pkgs,
        workspace,
        NixValue::list([closure.clone(), builder_closure]),
    );
    let choices = pkgs
        .clone()
        .select("lib.mapAttrs'")
        .call(NixValue::function(|name| {
            NixValue::function(|value| {
                nix_record! {
                    // Attribute names cannot retain dependency context.
                    // The explicit closure inputs retain the parent system.
                    "name": NixValue::builtin("unsafeDiscardStringContext").call(nix_text!(
                        "{system}/specialisation/{name}",
                        system = system.clone(),
                        name = name,
                    )),
                    "value": value
                        .select("configuration.system.build.toplevel")
                        .to_text(),
                }
            })
        }))
        .call(config.clone().select("specialisation"));
    let preflight = json(
        pkgs,
        "airlock-host-preflight.json",
        nix_record! {
            "name": "host-boot",
            "device": "/nix/store",
            "mountpoint": "/nix/store",
            "root_paths": NixValue::concat_lists([
                NixValue::list([system.clone().to_text()]),
                NixValue::builtin("attrValues").call(choices.clone()),
            ]),
        },
    );
    let seed = pkgs
        .clone()
        .select("runCommand")
        .call("airlock-unified-store-seed")
        .call(nix_record! {
            "__structuredAttrs": true,
            "unsafeDiscardReferences": nix_record! {
                "out": true,
            },
            "buildInputs": NixValue::list([vm_store.clone().select("builderInputClosure")]),
            "exportReferencesGraph": nix_record! {
                "builder": vm_store.clone().select("builderInputRoots"),
            },
            "nativeBuildInputs": NixValue::list([native.clone()]),
            "AIRLOCK_CLOSURE_STORE_INDEX_SOURCE": "file",
        })
        .call(nix_text!(
            r#"
        {preparer}/bin/airlock-prepare-boot manifest --out "$TMPDIR/airlock-host-preflight" \
          --paths {closure}/store-paths --settings {preflight} \
          --launcher {launcher}/bin/airlock-exec --readelf {binutils}/bin/readelf
        airlock-dom0-service storage image prepare-host {vm_store} "$out" \
          {closure}/registration {system} {choices} --cache {cache}
        cp "$TMPDIR/airlock-host-preflight/boot-preflight.json" "$out/boot-preflight.json"
    "#,
            vm_store = vm_store.clone(),
            closure = closure,
            system = system,
            choices = json(pkgs, "airlock-host-boot-choices.json", choices),
            cache = cache.clone(),
            preparer = Application::PrepareBoot.build(pkgs, workspace),
            launcher = Application::Launcher.build(pkgs, workspace),
            binutils = pkgs.clone().select("binutils"),
            preflight = preflight,
        ));

    seed.bind(|seed| {
        let topology = json(pkgs, "airlock-host-topology.json", boot_topology(config));
        let system = NixValue::if_else(
            config.clone().select("specialisation").has_attr("usb-lab"),
            config.clone().select("specialisation.usb-lab.configuration.system.build.toplevel"),
            config.clone().select("system.build.toplevel"),
        );
        let check = nix_text!(
            r#"
            {vm_check}
            {native}/bin/airlock-dom0-service storage image verify-host {seed} {topology} --profile normal --host {system}
        "#,
            vm_check = vm_store.clone().select("checkCommand"),
            native = native,
            seed = seed.clone(),
            topology = topology.clone(),
            system = system.clone(),
        );

        seed.merge_attrs(nix_record! {
            "descriptors": vm_store.clone().select("descriptors"),
            "checkCommand": check,
            "guestCheckCommand": vm_store.clone().select("checkCommand"),
            "bootTopology": topology,
            "bootSystem": system,
            "imageCaches": NixValue::list([vm_store.clone().select("imageCache"), cache]),
        })
    })
}

/// Supply upstream Qubes modules to the runtime preparer's embedded Python interpreter.
pub(crate) fn runtime_tool(pkgs: &NixValue, workspace: &Workspace) -> NixValue {
    let native = Application::PrepareRuntime
        .build(pkgs, workspace)
        .as_expression();
    let storage = Application::Dom0.build(pkgs, workspace).as_expression();
    let adapter = adapters::qubes(pkgs, workspace).as_expression();
    let python = pkgs
        .clone()
        .select("python3.withPackages")
        .call(NixValue::function(|packages| {
            NixValue::list([packages.select("qubes-core-admin"), adapter])
        }));
    let path = pkgs.clone().select("lib.makeBinPath").call(NixValue::list([
        storage,
        pkgs.clone().select("coreutils"),
        pkgs.clone().select("e2fsprogs"),
    ]));

    pkgs.clone()
        .select("writeShellScriptBin")
        .call("airlock-prepare-runtime")
        .call(nix_text!(
            r#"
        export PATH={path}:$PATH
        export PYTHONPATH={python}/{site_packages}
        export PYTHONNOUSERSITE=1
        export PYTHONSAFEPATH=1
        exec {native}/bin/airlock-prepare-runtime "$@"
    "#,
            path = path,
            python = python,
            site_packages = pkgs.clone().select("python3.sitePackages"),
            native = native,
        ))
}

/// Seed the Qubes database from verified physical payloads without retaining VM closure references.
pub(super) fn runtime(
    pkgs: &NixValue,
    workspace: &Workspace,
    topology: NixValue,
    prepared: NixValue,
) -> NixValue {
    let tool = runtime_tool(pkgs, workspace);

    pkgs.clone()
        .select("runCommand")
        .call("airlock-usb-prepared-runtime")
        .call(nix_record! {
            "__structuredAttrs": true,
            "unsafeDiscardReferences": nix_record! {
                "out": true,
            },
        })
        .call(nix_text!(
            r#"
        {check}
        {tool}/bin/airlock-prepare-runtime {topology} {prepared}/pool "$TMPDIR/runtime"
        mv "$TMPDIR/runtime" "$out"
    "#,
            check = prepared.clone().select("checkCommand"),
            tool = tool,
            topology = json(pkgs, "airlock-prepared-runtime-topology.json", topology),
            prepared = prepared,
        ))
}

/// Serialize build-time metadata while preserving artifact dependency contexts.
pub(super) fn json(pkgs: &NixValue, name: &str, value: NixValue) -> NixValue {
    pkgs.clone()
        .select("writeText")
        .call(name)
        .call(NixValue::builtin("toJSON").call(value))
}
