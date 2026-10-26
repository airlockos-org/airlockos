//! Construct NixOS VM systems and their Qubes storage descriptors from explicit build inputs.
//! Package and module evaluation stays lazy so one VM can be built without evaluating the host.

use airlock_build::{Workspace, overlays, vm::Images};
use rusix::{
    interop::{
        NixExpression, NixPath, PackageFunction,
        raw::{NixRepresentation, NixValue},
    },
    nix_record, nix_text,
};

/// Pinned source trees and target platform used by every artifact in a VM build.
struct Sources {
    /// Nixpkgs flake value, providing both its source path and extended NixOS library.
    nixpkgs: NixValue,
    /// Pinned older nixpkgs tree supplying the Qubes-compatible libvirt release.
    libvirt: NixPath,
    /// Upstream Qubes NixOS modules and package overlays.
    qubes: NixPath,
    /// Machine-owned modules, protocol patches and runtime assets.
    machine: NixPath,
    /// Native application package sources.
    apps: Workspace,
    /// Nix system identifier selected by the caller.
    system: NixValue,
}

impl Sources {
    /// Capture symbolic inputs; existing source strings become paths before fileset selection.
    fn from_arguments(arguments: &NixValue) -> Self {
        let source = |name| {
            NixPath::from_source_text(
                arguments
                    .clone()
                    .select(name)
                    .to_text()
                    .into_expr::<String>(),
            )
        };

        Self {
            nixpkgs: arguments.clone().select("nixpkgs"),
            libvirt: source("nixpkgsLibvirt105Source"),
            qubes: source("nixosQubesSource"),
            machine: source("airlockSupport"),
            apps: Workspace::new(source("airlockAppsSource")),
            system: arguments.clone().select("system"),
        }
    }

    /// Assemble upstream and Airlock overlays in their dependency order.
    fn overlays(&self) -> NixValue {
        let import = NixValue::builtin("import");
        let qubes = |relative| self.qubes.join_relative(relative).unwrap().as_expression();
        let libvirt = NixValue::function(|pkgs| {
            NixValue::function(|_| {
                nix_record! {
                    "libvirt_10_5": pkgs
                        .clone()
                        .select("callPackage")
                        .call(
                            self.libvirt
                                .join_relative("pkgs/development/libraries/libvirt")
                                .unwrap(),
                        )
                        .call(nix_record! {
                            "substituteAll": NixValue::function(|arguments| {
                                pkgs.clone()
                                    .select("replaceVars")
                                    .call(arguments.clone().select("src"))
                                    .call(
                                        NixValue::builtin("removeAttrs")
                                            .call(arguments)
                                            .call(NixValue::list(["src".into()])),
                                    )
                            }),
                            "xhtml1": NixValue::null(),
                            "AppKit": NixValue::null(),
                            "Carbon": NixValue::null(),
                        }),
                }
            })
        });
        let xwayland =
            NixValue::function(|pkgs| {
                NixValue::function(|previous| {
                    // Mutter embeds Xwayland's path, so changing the top-level package is insufficient.
                    let xwayland =
                    pkgs.select("qubes-gui-daemon.xwayland")
                        .override_attrs(NixValue::function(|old| nix_record! {
                            "meta": old.attr_or("meta", nix_record! {}).merge_attrs(nix_record! {
                                "mainProgram": "Xwayland",
                            }),
                        }));

                    nix_record! {
                        "mutter": previous.select("mutter").override_args(nix_record! {
                            "xwayland": xwayland,
                        }),
                    }
                })
            });
        let image_tools = NixValue::function(|_| {
            NixValue::function(|previous| {
                nix_record! {
                    "lkl": previous.select("lkl").override_attrs(NixValue::function(|old| nix_record! {
                        "postPatch": NixValue::concat_text([
                            old.attr_or("postPatch", ""),
                            nix_text!(r#"
                                    substituteInPlace tools/lkl/cptofs.c \
                          --replace-fail 'lkl_start_kernel("mem=100M")' 'lkl_start_kernel("mem=1024M")'
                    "#)
                            .into(),
                        ]),
                    })),
                }
            })
        });
        let by_name = nix_text!(
            "{nixpkgs}/pkgs/top-level/by-name-overlay.nix",
            nixpkgs = self.nixpkgs.clone(),
        );

        NixValue::list([
            NixValue::function(|_| {
                NixValue::function(|_| {
                    nix_record! {
                        "airlockAppsSource": self.apps.root().as_expression().to_text(),
                    }
                })
            }),
            image_tools,
            import.clone().call(qubes("pkgs/top-level/overlay.nix")),
            import.clone().call(by_name).call(qubes("pkgs/by-name")),
            libvirt,
            import.call(qubes("nix/overlay.nix")),
            overlays::gui_window_state(&self.apps),
            overlays::codex(),
            overlays::memory_accounting(&self.apps),
            overlays::template_tools(),
            xwayland,
        ])
    }

    /// Import target packages with Qubes' required proprietary artwork and stub domain allowed.
    fn packages(&self, overlays: NixValue) -> NixValue {
        let lib = self.nixpkgs.clone().select("lib");
        let unfree = NixValue::function(|package| {
            NixValue::builtin("elem")
                .call(
                    package
                        .clone()
                        .attr_or("pname", lib.select("getName").call(package)),
                )
                .call(NixValue::list([
                    "qubes-artwork".into(),
                    "qubes-vmm-stubdom-linux".into(),
                ]))
        });

        NixValue::builtin("import")
            .call(self.nixpkgs.clone())
            .call(nix_record! {
                "system": self.system.clone(),
                "overlays": overlays,
                "config": nix_record! {
                    "allowUnfreePredicate": unfree,
                },
            })
    }
}

/// Export build constructors for the flake boundary and bootstrap configuration compiler.
pub(crate) fn constructors() -> PackageFunction {
    PackageFunction::from_function_attrs(
        [
            "nixpkgs",
            "nixpkgsLibvirt105Source",
            "nixosQubesSource",
            "airlockSupport",
            "airlockAppsSource",
            "system",
            "hermitXen",
            "applicationRevision",
        ],
        |arguments| {
            let sources = Sources::from_arguments(&arguments);
            let result = sources.overlays().bind(|overlays| {
                sources.packages(overlays.clone()).bind(|pkgs| {
                    let images = Images {
                        pkgs: &pkgs,
                        workspace: &sources.apps,
                    };
                    nix_record! {
                        "pkgs": pkgs.clone(),
                        "qubesOverlays": overlays,
                        "qubesModule": sources
                            .qubes
                            .join_relative("nixos/modules/virtualisation/qubes")
                            .unwrap(),
                        "mkQubeKernelOpts": NixValue::function(base_kernel_options),
                        "mkNixClosureKernelOpts": NixValue::function(|configuration| {
                            NixValue::function_attrs(
                                ["storeDevice", "storeFormat", "storeBlobDevice"],
                                |store| {
                                    (
                                        vec![
                                            ("storeDevice", "/dev/xvde".into()),
                                            ("storeFormat", "ext4".into()),
                                            ("storeBlobDevice", NixValue::null()),
                                        ],
                                        kernel_options(configuration, &store),
                                    )
                                },
                            )
                        }),
                        "mkNixClosureRootImage": NixValue::function_attrs(
                            ["imageName", "rootImageSizeMiB"],
                            |request| {
                                (
                                    vec![("rootImageSizeMiB", 512_i64.into())],
                                    images
                                        .root(request.select("rootImageSizeMiB"))
                                        .as_expression(),
                                )
                            },
                        ),
                        "mkNixStoreClosureManifest": NixValue::function_attrs(
                            ["name", "rootPaths", "device", "mountpoint"],
                            |request| {
                                (
                                    vec![
                                        ("device", "/dev/xvde".into()),
                                        ("mountpoint", "/nix/store".into()),
                                    ],
                                    images
                                        .manifest(
                                            request.clone().select("name"),
                                            request.clone().select("rootPaths"),
                                            request.clone().select("device"),
                                            request.select("mountpoint"),
                                        )
                                        .as_expression(),
                                )
                            },
                        ),
                        "mkNixNativeDomain": domain_constructor(&sources, &pkgs),
                        "mkHermitDomain": crate::hermit_build::constructor(&pkgs, &sources.apps,
                            arguments.clone().select("hermitXen"), arguments.clone().select("applicationRevision")),
                    }
                })
            });

            (
                vec![
                    ("system", "x86_64-linux".into()),
                    ("hermitXen", NixValue::null()),
                    ("applicationRevision", NixValue::null()),
                ],
                result,
            )
        },
    )
}

/// Remove NixOS's root parameter because Qubes mounts the boot filesystem independently.
fn base_kernel_options(configuration: NixValue) -> NixValue {
    let parameters = configuration.select("config.boot.kernelParams");
    let keep = NixValue::function(|parameter| {
        NixValue::builtin("substring")
            .call(0_i64)
            .call(5_i64)
            .call(parameter)
            .equals("root=")
            .equals(false)
    });

    NixValue::join_text(
        " ",
        NixValue::concat_lists([
            NixValue::builtin("filter").call(keep).call(parameters),
            NixValue::list(["init=/sbin/init".into()]),
        ]),
    )
}

/// Bind the booted NixOS system to its read-only store and optional EROFS blob device.
fn kernel_options(configuration: NixValue, store: &NixValue) -> NixValue {
    let blob = store.clone().select("storeBlobDevice");
    NixValue::join_text(
        " ",
        NixValue::concat_lists([
            NixValue::list([
                base_kernel_options(configuration.clone()),
                nix_text!(
                    "airlock.system={system}",
                    system = configuration.select("config.system.build.toplevel"),
                )
                .into(),
                nix_text!(
                    "airlock.storedev={device}",
                    device = store.clone().select("storeDevice"),
                )
                .into(),
                nix_text!(
                    "airlock.storefmt={format}",
                    format = store.clone().select("storeFormat"),
                )
                .into(),
            ]),
            NixValue::if_else(
                blob.clone().equals(NixValue::null()),
                NixValue::list([]),
                NixValue::list([nix_text!("airlock.storeblobdev={blob}", blob = blob).into()]),
            ),
        ]),
    )
}

/// Accept the deferred module boundary while supplying all VM defaults in one place.
fn domain_constructor(sources: &Sources, pkgs: &NixValue) -> NixValue {
    NixValue::function_attrs(
        [
            "name",
            "modules",
            "guestRole",
            "minimal",
            "airlockConfigInputs",
            "airlockPrebuiltTemplateSources",
            "extraSpecialArgs",
            "additionalRootSpace",
            "configurationName",
            "rootImageName",
            "storeArtifactName",
            "kernelName",
            "label",
            "netvm",
            "prefs",
            "features",
            "services",
            "devices",
            "state",
            "rootImageSizeMiB",
            "storeDevice",
            "storeBlobDevice",
        ],
        |request| {
            let name = request.clone().select("configurationName");
            let defaults = vec![
                ("guestRole", "base".into()),
                ("minimal", true.into()),
                ("airlockConfigInputs", NixValue::null()),
                ("airlockPrebuiltTemplateSources", nix_record! {}),
                ("extraSpecialArgs", nix_record! {}),
                ("additionalRootSpace", NixValue::null()),
                (
                    "configurationName",
                    nix_text!(
                        "airlock-domain-{name}",
                        name = NixValue::builtin("replaceStrings")
                            .call(NixValue::list([".".into()]))
                            .call(NixValue::list(["-".into()]))
                            .call(request.clone().select("name")),
                    )
                    .into(),
                ),
                (
                    "rootImageName",
                    nix_text!("{name}-root-image", name = name.clone()).into(),
                ),
                (
                    "storeArtifactName",
                    nix_text!("{name}-store-closure", name = name).into(),
                ),
                ("kernelName", "6.12.64-1.fc41".into()),
                ("label", "green".into()),
                ("netvm", NixValue::null()),
                ("prefs", nix_record! {}),
                ("features", nix_record! {}),
                ("services", nix_record! {}),
                ("devices", nix_record! {}),
                ("state", nix_record! {}),
                ("rootImageSizeMiB", 512_i64.into()),
                ("storeDevice", "/dev/xvde".into()),
                ("storeBlobDevice", "/dev/xvdf".into()),
            ];
            let configuration = sources.nixpkgs.clone().select("lib.nixosSystem").call(nix_record! {
                "system": sources.system.clone(),
                "specialArgs": nix_record! {
                    "airlockAppsSource": sources.apps.root(),
                    "airlockConfigInputs": request.clone().select("airlockConfigInputs"),
                    "airlockPrebuiltTemplateSources": request.clone().select("airlockPrebuiltTemplateSources"),
                }
                .merge_attrs(request.clone().select("extraSpecialArgs")),
                "modules": NixValue::concat_lists([
                    NixValue::list([
                        crate::vm::minimal(
                            request.clone().select("minimal"),
                            request.clone().select("guestRole"),
                        ),
                        sources
                            .qubes
                            .join_relative("nixos/modules/virtualisation/qubes")
                            .unwrap()
                            .as_expression(),
                        crate::vm::system(&sources.machine, &sources.apps),
                        nix_record! {
                            "nixpkgs": nix_record! {
                                "pkgs": pkgs.clone(),
                            },
                            "airlock": nix_record! {
                                "qubeGuest": nix_record! {
                                    "enable": true,
                                    "role": request.clone().select("guestRole"),
                                },
                            },
                            "system": nix_record! {
                                "nixos": nix_record! {
                                    "versionSuffix": sources.nixpkgs.clone().select("lib.mkForce").call(""),
                                },
                            },
                        },
                    ]),
                    request.clone().select("modules"),
                ]),
            });
            let result = configuration.bind(|configuration| {
                let images = Images {
                    pkgs,
                    workspace: &sources.apps,
                };
                let options = kernel_options(
                    configuration.clone(),
                    &request.clone().merge_attrs(nix_record! {
                        "storeFormat": "erofs",
                    }),
                );

                options.bind(|options| {
                    nix_record! {
                        "configuration": configuration.clone(),
                        "configurationName": request.clone().select("configurationName"),
                        "rootImageName": request.clone().select("rootImageName"),
                        "storeArtifactName": request.clone().select("storeArtifactName"),
                        "rootImage": images.root(root_capacity(sources, &request)),
                        "storeArtifact": images.boot_manifest(
                            request.clone().select("storeArtifactName"),
                            NixValue::list([configuration
                                .clone()
                                .select("config.system.build.toplevel")]),
                            request.clone().select("storeDevice"),
                            "/nix/store".into(),
                        ),
                        "kernelopts": options.clone(),
                        "domain": descriptor(sources, &request, configuration, options),
                    }
                })
            });

            (defaults, result)
        },
    )
}

/// Interpret the bootstrap input's optional MiB/GiB capacity without changing stored definitions.
fn root_capacity(sources: &Sources, request: &NixValue) -> NixValue {
    let space = request.clone().select("additionalRootSpace");
    let lib = sources.nixpkgs.clone().select("lib");
    let suffix = |unit| {
        lib.clone()
            .select("hasSuffix")
            .call(unit)
            .call(space.clone())
    };
    let amount = |unit| {
        NixValue::builtin("fromJSON").call(
            lib.clone()
                .select("removeSuffix")
                .call(unit)
                .call(space.clone()),
        )
    };
    let invalid = NixValue::builtin("throw")
        .call("VM root capacity must be an integer MiB value or a string ending in M/G");
    let string = NixValue::if_else(
        suffix("M"),
        amount("M"),
        NixValue::if_else(
            suffix("G"),
            NixValue::builtin("mul").call(amount("G")).call(1024_i64),
            invalid.clone(),
        ),
    );

    NixValue::if_else(
        space.clone().equals(NixValue::null()),
        request.clone().select("rootImageSizeMiB"),
        NixValue::if_else(
            NixValue::builtin("isInt").call(space.clone()),
            space.clone(),
            NixValue::if_else(NixValue::builtin("isString").call(space), string, invalid),
        ),
    )
}

/// Describe the VM for Qubes while retaining build references until machine materialization.
fn descriptor(
    sources: &Sources,
    request: &NixValue,
    configuration: NixValue,
    options: NixValue,
) -> NixValue {
    let get = |name| request.clone().select(name);
    let system = &sources.system;
    let preferences = nix_record! {
        "autostart": false,
        "default_user": "user",
        "include_in_backups": true,
        "kernel": get("kernelName"),
        "kernelopts": options,
        "memory": 1024_i64,
        "maxmem": 2048_i64,
        "qrexec_timeout": 120_i64,
        "vcpus": 1_i64,
        "virt_mode": "pvh",
    }
    .merge_attrs(get("prefs"));
    let features = nix_record! {
        "airlock-backend": "nix-closure",
        "airlock-managed": "1",
        "airlock-role": "nix-native",
        "os": "Linux",
        "qrexec": "1",
        "menu-items": "*",
        "supported-rpc.airlock.AppSessionReady": NixValue::if_else(
            configuration
                .select("config.environment.etc")
                .has_attr("qubes-rpc/airlock.AppSessionReady"),
            "1",
            "0",
        ),
    }
    .merge_attrs(get("features"));

    nix_record! {
        "label": get("label"),
        "netvm": get("netvm"),
        "services": get("services"),
        "devices": get("devices"),
        "class": "StandaloneVM",
        "template": NixValue::null(),
        "prefs": preferences,
        "features": features,
        "backend": nix_record! {
            "type": "nix-closure",
            "system": nix_record! {
                "sourceRef": nix_record! {
                    "build": nix_text!(
                        "nixosConfigurations.{name}.config.system.build.toplevel",
                        name = get("configurationName"),
                    ),
                },
            },
            "kernel": nix_record! {
                "name": get("kernelName"),
            },
            "root": nix_record! {
                "mode": "qubes-root-image",
                "sourceRef": nix_record! {
                    "build": nix_text!(
                        "packages.{system}.{name}",
                        system = system.clone(),
                        name = get("rootImageName"),
                    ),
                    "subpath": "root.img",
                },
            },
            "store": nix_record! {
                "mode": "shared-closure",
                "sourceRef": nix_record! {
                    "build": nix_text!(
                        "packages.{system}.{name}",
                        system = system.clone(),
                        name = get("storeArtifactName"),
                    ),
                    "subpath": "",
                },
                "mountpoint": "/nix/store",
                "device": get("storeDevice"),
                "blobDevice": get("storeBlobDevice"),
                "viewBackend": "erofs-objectmap",
                "readOnly": true,
            },
            "state": nix_record! {
                "persistent": nix_text!("{name}-private", name = get("name")),
                "volatile": NixValue::null(),
            }
            .merge_attrs(get("state")),
        },
    }
}

/// Upstream kernel identity stored in the Qubes VM database.
pub(crate) const KERNEL_NAME: &str = "6.12.64-1.fc41";

/// Repack the pinned Qubes VM kernel and modules using the caller's upstream package recipe.
pub(crate) fn kernel(pkgs: &NixValue) -> NixValue {
    let fetch = |file: &str, hash: &str| {
        pkgs.clone().select("fetchurl").call(nix_record! {
            "url": format!("https://ftp.qubes-os.org/repo/yum/r4.3/current/dom0/fc41/rpm/{file}"),
            "hash": hash,
        })
    };

    pkgs.clone().select("repackRpmKernel").call(nix_record! {
        "kernelSrc": fetch(
            "kernel-qubes-vm-6.12.64-1.qubes.fc41.x86_64.rpm",
            "sha256-nK0KbnT8hUwIZPhUgW8nSRNAbZDgjexHWfeeYDiFxsU=",
        ),
        "modulesSrc": fetch(
            "kernel-modules-6.12.64-1.qubes.fc41.x86_64.rpm",
            "sha256-JBPQM27u/nQwKnfGGDLpQ35BhRwSpy+vcZLUlI06ELo=",
        ),
        "kernelVersion": "6.12.64-1",
        "fedoraVersion": "fc41",
    })
}
