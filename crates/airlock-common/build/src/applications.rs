//! Package the native applications with their build dependencies and runtime executables.

use crate::Workspace;
use rusix::{
    interop::{
        Package,
        raw::{NixRepresentation, NixValue},
    },
    nix_record, nix_text,
};

/// A supported application build, including the installation-media executables built separately.
#[derive(Clone, Copy)]
pub enum Application {
    /// Build-directory VM boot filesystems and closure manifests.
    PrepareBoot,
    /// Independently cacheable package fragments and common store indexes used only during image builds.
    StoreCache,
    /// Canonical package packing with its own workspace and lockfile, independent of runtime policy.
    StorePacker,
    /// Read-only host observation with no Qubes control implementation.
    Observation,
    /// Scoped diagnostic evidence endpoint without deployment authority.
    Diagnostics,
    /// Fixed native argument and environment adapters.
    Launcher,
    /// Disposable NixOS test-VM systemd/udev regression, never installed in production VMs.
    UplinkTest,
    /// Disposable VM input protocol regression; never installed in production guests.
    InputTest,
    /// Explicit smoke-test orchestration and read-only structured evidence helpers.
    TestReport,
    /// Development-only probes of upstream Qubes Python interfaces and event ordering.
    QubesProbe,
    /// User-facing command dispatcher.
    Cli,
    /// Workstation-only build and deployment operations.
    Development,
    /// Native host service and its early-boot journal reader.
    Dom0,
    /// Host command service with embedded access to upstream Qubes Python objects.
    Dom0Qubes,
    /// Controller's configuration and review service.
    ControllerService,
    /// Controller's graphical review interface.
    ControllerGui,
    /// Per-VM desktop integration and screen-capture receiver.
    VmService,
    /// Static bootstrap init that makes the VM's read-only store available before NixOS starts.
    VmInit,
    /// First-login setup window.
    GuiSetup,
    /// USB provisioning and image validation tools together.
    Image,
    /// USB provisioning executable without the image validator.
    Usb,
    /// Image-store preparation executable used inside the image builder.
    PrepareRuntime,
}

impl Application {
    /// Construct the application with the target's packages, preserving lazy build dependencies.
    /// This describes a derivation; Rust neither invokes Cargo nor realizes its output.
    pub fn build(self, pkgs: &NixValue, workspace: &Workspace) -> Package {
        if matches!(self, Self::StorePacker) {
            return crate::store::packer(pkgs, workspace);
        }

        let package_set = if matches!(self, Self::VmInit) {
            pkgs.clone().select("pkgsStatic")
        } else {
            pkgs.clone()
        };
        let pkgs = &package_set;

        let (package, name, description, binaries): (&str, &str, &str, &[&str]) = match self {
            Self::StorePacker => {
                unreachable!("the independent packer uses its own Cargo workspace")
            }
            Self::StoreCache => (
                "airlock-nix-core",
                "airlock-store-cache",
                "Cacheable immutable store preparation",
                &["airlock-store-cache"],
            ),
            Self::PrepareBoot => (
                "airlock-image",
                "airlock-prepare-boot",
                "VM boot filesystem preparation",
                &["airlock-prepare-boot"],
            ),
            Self::Observation => (
                "airlock-nix-core",
                "airlock-observe-dom0",
                "Read-only dom0 observations",
                &["airlock-observe-dom0"],
            ),
            Self::Diagnostics => (
                "airlock-diagnostics",
                "airlock-diagnostics",
                "Scoped read-only diagnostic evidence",
                &["airlock-diagnostics", "airlock-diagnostics-relay"],
            ),
            Self::Launcher => (
                "airlock-nix-core",
                "airlock-exec",
                "Native fixed command launchers",
                &["airlock-exec"],
            ),
            Self::TestReport => (
                "airlock-tests",
                "airlock-test-report",
                "Airlock native smoke-test evidence",
                &["airlock-test-report", "airlock-smoke"],
            ),
            Self::QubesProbe => (
                "airlock-tests",
                "airlock-qubes-probe",
                "Airlock upstream Qubes interface probes",
                &["airlock-qubes-probe"],
            ),
            Self::InputTest => (
                "airlock-tests",
                "airlock-input-test",
                "Airlock installed input RPC regression",
                &["airlock-input-probe"],
            ),
            Self::UplinkTest => (
                "airlock-tests",
                "airlock-uplink-probe",
                "Airlock disposable uplink regression",
                &["airlock-uplink-probe"],
            ),
            Self::Cli => (
                "airlock-cli",
                "airlock-cli",
                "Airlock command line interface",
                &["airlock"],
            ),
            Self::Development => (
                "airlock-dev",
                "airlock-dev",
                "Airlock development workstation operations",
                &["airlock-dev"],
            ),
            Self::Dom0 | Self::Dom0Qubes => (
                "airlock-dom0-service",
                "airlock-dom0-service",
                "Airlock system services for dom0",
                &["airlock-dom0-service", "airlock-boot-journal"],
            ),
            Self::ControllerService => (
                "airlock-sys-ctrl-service",
                "airlock-sys-ctrl-service",
                "Airlock system services for sys-ctrl",
                &["airlock-sys-ctrl-service"],
            ),
            Self::ControllerGui => (
                "airlock-sys-ctrl-gui",
                "airlock-sys-ctrl-gui",
                "Airlock graphical interface for sys-ctrl",
                &[],
            ),
            Self::VmService => (
                "airlock-vm-service",
                "airlock-vm-service",
                "Airlock desktop integration inside individual VMs",
                &["airlock-vm-service"],
            ),
            Self::VmInit => (
                "airlock-vm-init",
                "airlock-vm-init",
                "Static Airlock VM bootstrap init",
                &["airlock-vm-init"],
            ),
            Self::GuiSetup => (
                "airlock-sys-gui-setup",
                "airlock-sys-gui-setup",
                "Airlock first-run welcome interface",
                &["airlock-sys-gui-setup"],
            ),
            Self::Image => (
                "airlock-image",
                "airlock-image",
                "Airlock installation media preparation and provisioning",
                &["airlock-usb", "airlock-image-check"],
            ),
            Self::Usb => (
                "airlock-image",
                "airlock-usb",
                "Airlock installation media preparation and provisioning",
                &["airlock-usb"],
            ),
            Self::PrepareRuntime => (
                "airlock-image",
                "airlock-prepare-runtime",
                "Airlock installation media preparation and provisioning",
                &["airlock-prepare-runtime"],
            ),
        };
        let lib = pkgs.clone().select("lib");
        let default_features = !matches!(
            self,
            Self::Image
                | Self::Usb
                | Self::Dom0
                | Self::TestReport
                | Self::InputTest
                | Self::UplinkTest
                | Self::PrepareBoot
        );
        let features: &[&str] = if matches!(self, Self::StoreCache) {
            &["artifacts"]
        } else if matches!(self, Self::Diagnostics) {
            &["runtime"]
        } else {
            &[]
        };
        let source = workspace.package_source(package, default_features, features);
        let mut flags: Vec<NixValue> = source.arguments().into_iter().map(NixValue::from).collect();
        for binary in binaries {
            flags.extend(["--bin".into(), (*binary).into()]);
        }
        let mut attributes = vec![
            ("pname", name.into()),
            ("version", env!("CARGO_PKG_VERSION").into()),
            ("src", source.source(&lib)),
            (
                "cargoLock",
                nix_record! { "lockFile": workspace.file("Cargo.lock").snapshot() },
            ),
            ("cargoBuildFlags", NixValue::list(flags)),
            // Behavioral checks run through Cargo against explicitly prepared binaries.
            ("doCheck", false.into()),
            (
                "meta",
                nix_record! {
                    "description": description,
                    "mainProgram": binaries.first().copied().unwrap_or(name),
                    "license": lib.clone().select("licenses.mit"),
                    "platforms": lib.clone().select("platforms.linux"),
                },
            ),
        ];
        let packages =
            |names: &[&str]| NixValue::list(names.iter().map(|name| pkgs.clone().select(name)));
        match self {
            Self::Dom0 | Self::Dom0Qubes | Self::QubesProbe => {
                attributes.extend([
                    ("nativeBuildInputs", packages(&["pkg-config"])),
                    (
                        "buildInputs",
                        packages(if matches!(self, Self::Dom0Qubes | Self::QubesProbe) {
                            &["udev", "python3"]
                        } else {
                            &["udev"]
                        }),
                    ),
                ]);
            }
            Self::GuiSetup => {
                attributes.extend([
                    (
                        "nativeBuildInputs",
                        packages(&["pkg-config", "wrapGAppsHook4", "makeWrapper"]),
                    ),
                    ("buildInputs", packages(&["gtk4", "libadwaita"])),
                    (
                        "preFixup",
                        nix_text!(
                            r#"
                        gappsWrapperArgs+=(--set AIRLOCK_GNOME_TOUR_EXEC {tour}/bin/gnome-tour)
                    "#,
                            tour = pkgs.clone().select("gnome-tour")
                        )
                        .into(),
                    ),
                ]);
            }
            Self::Development
            | Self::ControllerGui
            | Self::VmService
            | Self::Image
            | Self::Usb
            | Self::PrepareRuntime => {
                let executables = if binaries.is_empty() {
                    vec![name]
                } else {
                    binaries.to_vec()
                };
                let scripts = executables.into_iter().map(|binary| {
                    let tools: &[&str] = match self {
                        Self::Development => &[
                            "git",
                            "nix",
                            "openssh",
                            "coreutils",
                            "gzip",
                            "bash",
                            "systemd",
                        ],
                        Self::ControllerGui => &["git", "dbus", "glib", "fontconfig"],
                        Self::VmService => &["xdg-user-dirs", "glib", "systemd", "xdpyinfo"],
                        _ if binary == "airlock-usb" => &[
                            "coreutils",
                            "util-linux",
                            "e2fsprogs",
                            "systemd",
                            "git",
                            "openssh",
                            "openssl",
                        ],
                        _ if binary == "airlock-image-check" => {
                            &["coreutils", "git", "nix", "bubblewrap"]
                        }
                        _ => &["coreutils", "e2fsprogs"],
                    };
                    let path = lib.clone().select("makeBinPath").call(packages(tools));
                    if matches!(self, Self::ControllerGui) {
                        nix_text!(
                            r#"
                            wrapProgram "$out/bin/{binary}" \
                              --prefix PATH : {path} \
                              --prefix LD_LIBRARY_PATH : {libraries}
                        "#,
                            binary = binary,
                            path = path,
                            libraries = lib.clone().select("makeLibraryPath").call(packages(&[
                                "libGL",
                                "libxkbcommon",
                                "wayland",
                                "libx11",
                                "libxcursor",
                                "libxi",
                                "libxrandr",
                            ]))
                        )
                        .into()
                    } else {
                        nix_text!(
                            r#"
                            wrapProgram "$out/bin/{binary}" --prefix PATH : {path}
                        "#,
                            binary = binary,
                            path = path
                        )
                        .into()
                    }
                });
                attributes.extend([
                    ("nativeBuildInputs", packages(&["makeWrapper"])),
                    (
                        "postInstall",
                        NixValue::join_text("\n", NixValue::list(scripts)),
                    ),
                ]);
            }
            Self::PrepareBoot
            | Self::StoreCache
            | Self::StorePacker
            | Self::Observation
            | Self::Launcher
            | Self::Cli
            | Self::ControllerService
            | Self::InputTest
            | Self::UplinkTest
            | Self::TestReport
            | Self::VmInit
            | Self::Diagnostics => {}
        }

        if matches!(self, Self::PrepareRuntime) {
            attributes.push(("buildInputs", packages(&["python3"])));
        }
        if matches!(
            self,
            Self::PrepareRuntime | Self::Dom0Qubes | Self::QubesProbe
        ) {
            attributes.extend([(
                "PYO3_PYTHON",
                nix_text!(
                    "{python}/bin/python3",
                    python = pkgs.clone().select("python3")
                )
                .into(),
            )]);
        }

        let native = pkgs
            .clone()
            .select("rustPlatform.buildRustPackage")
            .call(NixValue::record(attributes));
        if matches!(self, Self::QubesProbe) {
            let python = pkgs
                .clone()
                .select("python3.withPackages")
                .call(NixValue::function(|packages| {
                    NixValue::list([
                        packages.clone().select("qubes-core-admin"),
                        packages.select("qubes-core-admin-client"),
                        crate::adapters::qubes(pkgs, workspace).as_expression(),
                        crate::adapters::gpu(pkgs, workspace).as_expression(),
                    ])
                }));
            return Package::from_expression(
                pkgs.clone()
                    .select("writeShellScriptBin")
                    .call("airlock-qubes-probe")
                    .call(nix_text!(
                        r#"
                    export PYTHONPATH={python}/{site_packages}
                    export PYTHONNOUSERSITE=1
                    export PYTHONSAFEPATH=1
                    exec {native}/bin/airlock-qubes-probe "$@"
                "#,
                        python = python,
                        site_packages = pkgs.clone().select("python3.sitePackages"),
                        native = native
                    )),
            );
        }

        let package = if matches!(self, Self::Dom0 | Self::Dom0Qubes) {
            let tools = lib.select("makeBinPath").call(packages(&[
                "nix",
                "erofs-utils",
                "gnutar",
                "lvm2",
                "util-linux",
                "coreutils",
                "systemd",
            ]));
            pkgs.clone().select("symlinkJoin").call(nix_record! {
                "name": name,
                "paths": NixValue::list([native.clone()]),
                "nativeBuildInputs": packages(&["makeWrapper"]),
                "postBuild": nix_text!(r#"
                    wrapProgram "$out/bin/airlock-dom0-service" \
                      --prefix PATH : {tools}
                "#, tools = tools),
                // Initramfs supplies only its required helpers, avoiding the full tool closure.
                "passthru": nix_record! { "unwrapped": native.clone() },
                "meta": native.select("meta"),
            })
        } else {
            native
        };

        let package = if matches!(self, Self::ControllerGui | Self::GuiSetup) {
            let mut paths = vec![package.clone(), crate::desktop::icons(pkgs).as_expression()];
            if matches!(self, Self::ControllerGui) {
                paths.push(crate::desktop::identity(
                    pkgs,
                    crate::desktop::CONTROL_ID,
                    "Airlock Control",
                    crate::desktop::CONTROL_ID,
                ));
            }

            pkgs.clone().select("symlinkJoin").call(nix_record! {
                "name": name,
                "paths": NixValue::list(paths),
                "meta": package.select("meta"),
            })
        } else {
            package
        };

        Package::from_expression(package)
    }
}
