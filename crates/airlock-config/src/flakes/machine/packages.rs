//! Expose native tools, VM artifacts and release images under the existing flake package names.

use super::Build;
use airlock_build::{Application, adapters, tools::Tool, upstream};
use rusix::{
    interop::{
        NixExpression,
        raw::{NixRepresentation, NixValue},
    },
    nix_record,
};

/// Build one platform's package catalogue from shared native recipes.
pub(super) fn outputs(build: &Build, system: NixValue) -> NixValue {
    build.pkgs(system.clone()).bind(|pkgs| {
        let tools = Tool::packages(&pkgs, &build.workspace, &build.source);
        tools.bind(|tools| {
            let mut packages = Tool::ALL
                .iter()
                .map(|tool| {
                    let name = if *tool == Tool::Archive {
                        "airlock-config-archive-candidate"
                    } else {
                        tool.export_name()
                    };

                    (name.to_owned(), tools.clone().select(tool.export_name()))
                })
                .collect::<Vec<_>>();
            for (name, application) in [
                ("airlock", Application::Cli),
                ("airlock-vm-service", Application::VmService),
                ("airlock-vm-init", Application::VmInit),
                ("airlock-sys-gui-setup", Application::GuiSetup),
            ] {
                packages.push((
                    name.to_owned(),
                    application.build(&pkgs, &build.workspace).as_expression(),
                ));
            }
            for (name, attribute) in [
                ("codex", "codex"),
                ("zellij", "zellij"),
                ("qubes-linux-utils", "qubes-linux-utils"),
                ("airlock-erofs-utils", "erofs-utils"),
                ("qubes-gui-agent-linux", "qubes-gui-agent-linux"),
                ("qubes-gui-daemon", "qubes-gui-daemon"),
                ("ovmf-fd", "OVMF.fd"),
                ("qemu-kvm", "qemu_kvm"),
                ("qemu-utils", "qemu-utils"),
            ] {
                packages.push((name.to_owned(), pkgs.clone().select(attribute)));
            }
            let gui = airlock_sys_gui_service::authoring::Sources::new(build.workspace.root());
            packages.extend([
                (
                    "airlock-local-lab-image".into(),
                    build.output("nixosConfigurations.local-lab-image.config.system.build.image"),
                ),
                (
                    "airlock-machine-release-local-lab".into(),
                    build.output(
                        "nixosConfigurations.local-lab.config.system.build.airlockMachineRelease",
                    ),
                ),
                (
                    "qubes-input-proxy".into(),
                    upstream::input_proxy(&pkgs).as_expression(),
                ),
                (
                    "airlock-observe-dom0".into(),
                    upstream::observation(&pkgs).as_expression(),
                ),
                (
                    "default".into(),
                    upstream::observation(&pkgs).as_expression(),
                ),
                (
                    "airlock-sys-gui-service".into(),
                    airlock_sys_gui_service::authoring::deployment(&pkgs, &gui)
                        .package()
                        .as_expression(),
                ),
                (
                    "airlock-qubes".into(),
                    adapters::qubes(&pkgs, &build.workspace).as_expression(),
                ),
                (
                    "airlock-authoring-dependencies".into(),
                    crate::vm::authoring::dependencies(&pkgs, &build.workspace.root()),
                ),
                (
                    "airlock-qubes-vm-kernel".into(),
                    crate::vm_build::kernel(&pkgs),
                ),
            ]);
            for (name, display) in [("sys-gpu", "gpu"), ("sys-gui-minimal", "minimal")] {
                let entry = build
                    .shared
                    .clone()
                    .select("displays")
                    .select(display)
                    .call(system.clone());
                packages.extend([
                    (
                        format!("airlock-domain-{name}-root-image"),
                        entry.clone().select("rootImage"),
                    ),
                    (
                        format!("airlock-domain-{name}-store-closure"),
                        entry.select("storeArtifact"),
                    ),
                ]);
            }
            for profile in ["usb-lab", "usb-gui-lab"] {
                packages.push((
                    format!("airlock-machine-release-{profile}"),
                    build
                        .output("nixosConfigurations.machine.config.specialisation")
                        .select(profile)
                        .select("configuration.system.build.airlockMachineRelease"),
                ));
            }
            for scenario in [
                "vm-dev",
                "vm-release",
                "vm-gui-dev",
                "vm-gui-release",
                "vm-gui-config-dev",
                "vm-gui-config-release",
                "vm-gui-config-network-debug",
                "vm-pool-admission-test",
                "vm-gpu-lab",
                "vm-gui-minimal",
            ] {
                packages.push((
                    format!("airlock-{scenario}-image"),
                    build
                        .output("nixosConfigurations")
                        .select(scenario)
                        .select("config.system.build.image"),
                ));
            }
            let builders = build.shared.clone().select("builders").call(system);
            packages.push((
                "airlock-nix-closure-root-image-test".into(),
                builders
                    .clone()
                    .select("mkNixClosureRootImage")
                    .call(nix_record! {
                        "imageName": "airlock-nix-closure-root-image-test",
                        "rootImageSizeMiB": 64_i64,
                    }),
            ));
            packages.push((
                "airlock-nix-closure-store-manifest-test".into(),
                builders
                    .select("mkNixStoreClosureManifest")
                    .call(nix_record! {
                        "name": "airlock-nix-closure-store-manifest-test",
                        "rootPaths": NixValue::list([pkgs
                            .select("writeText")
                            .call("airlock-store-manifest-test-root")
                            .call("airlock-store-manifest-test\n")]),
                    }),
            ));

            NixValue::record(packages)
        })
    })
}
