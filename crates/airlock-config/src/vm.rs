//! Configure VM userspace, desktop forwarding and private configuration-build services.
//! Rust selects capabilities; upstream NixOS and Qubes supply their implementation services.

mod worker;

mod development;

mod app_gui;

mod preferences;

mod personal;

mod minimal;

mod network;

mod private_store;

mod configuration;

mod seed;

pub(crate) mod authoring;

mod system;

mod gui;

use rusix::{
    Config,
    interop::{NixPath, raw::NixValue},
};

/// Build-worker capabilities selected by the machine's declared VM role.
#[derive(Clone, Copy)]
pub(crate) enum WorkerRole {
    /// Interactive development VM with the Airlock CLI and persistent workspace.
    Development,
    /// Controller that reviews changes and records authoritative deployment outcomes.
    Controller,
}

impl WorkerRole {
    /// Return the role identity used by the existing Qubes service and storage contracts.
    fn identity(self) -> &'static str {
        match self {
            Self::Development => "usr-assistant",
            Self::Controller => "sys-ctrl",
        }
    }
}

/// Export the machine's module entry points while Rust compositions call their constructors.
pub(crate) fn module_constructors() -> NixValue {
    NixValue::function(|source| {
        let source = NixPath::from_source_text(source.to_text().into_expr::<String>());
        rusix::nix_record! {
            "profiles": NixValue::function(|apps| {
                let apps = NixPath::from_source_text(apps.to_text().into_expr::<String>());
                crate::host::nested::profiles(&source, &airlock_build::Workspace::new(apps))
            }),
            "topology": NixValue::function(|apps| {
                let apps = NixPath::from_source_text(apps.to_text().into_expr::<String>());
                crate::topology::module(&source, &airlock_build::Workspace::new(apps))
            }),
            "deployment": NixValue::function(|apps| {
                let apps = NixPath::from_source_text(apps.to_text().into_expr::<String>());
                crate::host::deployment::module(&source, &airlock_build::Workspace::new(apps))
            }),
            "dom0": NixValue::function(|apps| {
                let apps = NixPath::from_source_text(apps.to_text().into_expr::<String>());
                crate::host::dom0::module(&source, &airlock_build::Workspace::new(apps))
            }),
            "network": network::constructor(),
            "privateStore": private_store::constructor(),
            "configuration": configuration::constructor(),
            "appGui": app_gui::module(),
            "personal": personal::module(),
            "assistant": development::module(),
            "assistantBuild": worker::module(WorkerRole::Development),
            "controllerBuild": worker::module(WorkerRole::Controller),
            "assistantStore": worker::store(WorkerRole::Development),
            "controllerStore": worker::store(WorkerRole::Controller),
            "machineSeed": worker::seed(),
        }
    })
}

/// Export shared module constructors and validation libraries for inspection.
pub(crate) fn modules() -> Config {
    Config::new()
        .set_dynamic("modules", module_constructors())
        .set_dynamic("topology", crate::topology::library())
        .set_dynamic("system", crate::system_plan::library())
}

/// Configure the development role with guidance from the admitted application workspace.
pub(crate) fn development() -> NixValue {
    development::module()
}

/// Install personal applications with the GUI agent used by ordinary application VMs.
pub(crate) fn personal() -> NixValue {
    personal::module()
}

/// Install graphical window forwarding for VMs that supply their own application selection.
pub(crate) fn application_gui() -> NixValue {
    app_gui::module()
}

/// Compose a worker's build services using its declared capability rather than a VM-name lookup.
pub(crate) fn worker_modules(role: WorkerRole) -> Vec<NixValue> {
    vec![worker::seed(), worker::store(role), worker::module(role)]
}

/// Select a small system closure while preserving the role's explicit Nix command capability.
pub(crate) fn minimal(enabled: NixValue, role: NixValue) -> NixValue {
    let nix_cli = NixValue::builtin("elem").call(role).call(NixValue::list(
        [
            "sys-config-vault",
            "sys-config-staging",
            "sys-config-validator",
            "cmd",
            "usr-assistant",
            "sys-ctrl",
        ]
        .map(Into::into),
    ));

    minimal::module(enabled, nix_cli)
}

/// Assemble the Qubes VM lifecycle from explicit machine and native application sources.
pub(crate) fn system(source: &NixPath, workspace: &airlock_build::Workspace) -> NixValue {
    system::module(source, workspace)
}
