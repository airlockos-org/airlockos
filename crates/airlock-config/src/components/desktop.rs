//! Configure the GNOME session, Airlock extensions and first-login integration.
//! Qubes supplies VM display forwarding; NixOS builds and installs the authored configuration.

use super::machine_source::{self, MachineFiles};
use crate::model::VmModule;
use airlock_sys_gui_service::authoring::Deployment;
use rusix::nixos::{ModuleBody, ModuleContext, NixosModule};

mod extensions;

mod session;

mod setup;

mod windows;

/// Installs GNOME and records its completion capability for screen-capture connections.
/// Airlock's session settings, extension packages and startup services are authored here.
pub fn gnome() -> VmModule {
    VmModule::from(module()).with_gnome()
}

/// Composes the GNOME implementation for both Rust and Nix machine authors.
/// Contributions share the VM's package set, including its final overlays.
pub(crate) fn module() -> NixosModule {
    NixosModule::with_arguments([machine_source::ARGUMENT], body)
}

/// Embed the GNOME configuration in a containing Rust-authored flake.
pub(crate) fn expression() -> rusix::interop::raw::NixValue {
    rusix::nixos::ContextualModule::with_arguments([machine_source::ARGUMENT], body)
        .into_expression()
}

/// Build the shared GNOME contributions while preserving each Rust definition's source location.
fn body(inputs: ModuleContext) -> ModuleBody {
    let service = airlock_sys_gui_service::authoring::deployment(
        &inputs.pkgs,
        &machine_source::service_sources(&inputs),
    );
    let extensions = extensions::packages(&inputs, &service);
    let session = ModuleBody::new(session::configuration(&inputs, &service, &extensions));
    let windows = ModuleBody::new(windows::configuration(&inputs, &service));
    let setup =
        ModuleBody::new(setup::configuration(&inputs, &service)).key("airlock-config.gnome.setup");
    let preferences = rusix::installation::compose(
        "gnome-preferences",
        rusix::installation::CollisionChecks::Enabled,
        [service.desktop_preferences()],
    )
    .expect("fixed GNOME preferences installation");

    // NixOS collects imports in reverse order: setup packages precede session packages.
    let gnome = ModuleBody::empty()
        .key("airlock-config.gnome")
        .module(preferences)
        .module(windows)
        .module(session)
        .module(setup);

    ModuleBody::empty()
        .key("airlock-config.desktop")
        .module(gnome)
}
