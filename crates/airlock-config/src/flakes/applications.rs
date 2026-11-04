//! Expose standalone application builds and an explicitly entered desktop development environment.

use airlock_build::{Application, Workspace, adapters};
use rusix::{
    interop::{
        NixExpression, NixPath,
        raw::{NixRepresentation, NixValue},
    },
    nix_record, nix_text,
};

/// Describe application outputs without importing generated package catalogues back into authoring.
pub(super) fn outputs() -> NixValue {
    NixValue::function_attrs(["self", "nixpkgs"], |inputs| {
        let workspace = Workspace::new(NixPath::from_expression(inputs.clone().select("self")));
        let packages = super::systems(|system| {
            NixValue::builtin("import")
                .call(inputs.clone().select("nixpkgs"))
                .call(nix_record! {
                    "system": system,
                })
                .bind(|pkgs| {
                    let mut packages = [
                        ("airlock-sys-ctrl-gui", Application::ControllerGui),
                        ("airlock-dom0-service", Application::Dom0),
                        ("airlock-dev", Application::Development),
                        ("airlock-image", Application::Image),
                        ("airlock-cli", Application::Cli),
                        ("airlock-diagnostics", Application::Diagnostics),
                        ("airlock-sys-ctrl-service", Application::ControllerService),
                        ("airlock-vm-service", Application::VmService),
                        ("airlock-vm-init", Application::VmInit),
                        ("airlock-sys-gui-setup", Application::GuiSetup),
                    ]
                    .map(|(name, application)| {
                        (name, application.build(&pkgs, &workspace).as_expression())
                    })
                    .to_vec();
                    packages.push((
                        "airlock-qubes",
                        adapters::qubes(&pkgs, &workspace).as_expression(),
                    ));
                    packages.push((
                        "airlock-sys-gui-service",
                        airlock_sys_gui_service::authoring::native(&pkgs, &workspace.root())
                            .as_expression(),
                    ));
                    packages.push((
                        "airlock-authoring-dependencies",
                        crate::vm::authoring::dependencies(&pkgs, &workspace.root()),
                    ));
                    packages.push((
                        "airlock-packer-dependencies",
                        crate::vm::authoring::packer_dependencies(&pkgs, &workspace.root()),
                    ));
                    packages.push(("crate2nix", airlock_build::crate_graph::generator(&pkgs)));
                    packages.push((
                        "default",
                        Application::ControllerGui
                            .build(&pkgs, &workspace)
                            .as_expression(),
                    ));

                    NixValue::record(packages)
                })
        });
        let shells = super::systems(|system| {
            NixValue::builtin("import")
                .call(inputs.select("nixpkgs"))
                .call(nix_record! {
                    "system": system,
                })
                .bind(|pkgs| nix_record! {
                    "verification": super::verification::shell(&pkgs),
                    "desktop": pkgs.clone().select("mkShell").call(nix_record! {
                        "AIRLOCK_TEST_XSETTINGSD": nix_text!("{package}/bin/xsettingsd", package = airlock_build::desktop::settings_provider(&pkgs)),
                        "AIRLOCK_TEST_GSETTINGS_SCHEMAS": nix_text!("{package}/share/gsettings-schemas/{name}/glib-2.0/schemas", package = pkgs.clone().select("gsettings-desktop-schemas"), name = pkgs.clone().select("gsettings-desktop-schemas.name")),
                        "AIRLOCK_TEST_DCONF_MODULES": nix_text!("{package}/lib/gio/modules", package = pkgs.clone().select("dconf.lib")),
                        "AIRLOCK_TEST_DCONF_SERVICE": nix_text!("{package}/libexec/dconf-service", package = pkgs.clone().select("dconf.lib")),
                        "AIRLOCK_TEST_GTK_PORTAL": nix_text!("{package}/libexec/xdg-desktop-portal-gtk", package = pkgs.clone().select("xdg-desktop-portal-gtk")),
                        "AIRLOCK_TEST_PORTAL": nix_text!("{package}/libexec/xdg-desktop-portal", package = pkgs.clone().select("xdg-desktop-portal")),
                        "AIRLOCK_TEST_FONTS": pkgs.clone().select("adwaita-fonts").to_text(),
                        "AIRLOCK_TEST_ICONS": pkgs.clone().select("adwaita-icon-theme").to_text(),
                        "AIRLOCK_CRATE2NIX": rusix::nix_text!("{generator}/bin/crate2nix", generator = airlock_build::crate_graph::generator(&pkgs)),
                        "nativeBuildInputs": NixValue::list([pkgs.clone().select("pkg-config"), airlock_build::crate_graph::generator(&pkgs)]),
                        "PYO3_PYTHON": rusix::nix_text!(
                            "{python}/bin/python3",
                            python = pkgs.clone().select("python3"),
                        ),
                        "buildInputs": NixValue::list([
                            pkgs.clone().select("gtk4"),
                            airlock_build::desktop::settings_provider(&pkgs).as_expression(),
                            pkgs.clone().select("xvfb"),
                            pkgs.clone().select("xdg-desktop-portal-gtk"),
                            pkgs.clone().select("libadwaita"),
                            pkgs.clone().select("python3"),
                            pkgs.select("udev"),
                        ]),
                    }),
                })
        });

        (
            Vec::<(&str, NixValue)>::new(),
            nix_record! {
                "packages": packages,
                "devShells": shells,
            },
        )
    })
}
