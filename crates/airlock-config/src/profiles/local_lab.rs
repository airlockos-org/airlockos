//! A small interactive Airlock machine for development inside QEMU.
//! The virtual display uses the existing Qubes relay; VM services and policy use normal components.

use crate::model::{
    AuthoringError, GiB, HermitApplication, Machine, MachineSnapshot, Memory, MiB, Vm,
};
use rusix::{
    nix_record,
    nixos::{ModuleBody, NixosModule},
};

/// Declare two application VMs, the shared clipboard and normal network and management services.
/// Fixed memory bounds keep this machine within a 16 GiB outer guest without changing role defaults.
pub fn machine() -> Result<MachineSnapshot, AuthoringError> {
    let mut machine = Machine::default();
    let network = Vm::network("sys-net", GiB(2))?;
    network.set_memory(Memory::Fixed(MiB(512)));
    machine.add(&network)?;

    let firewall = Vm::firewall("sys-firewall", &network)?;
    firewall.set_memory(Memory::Fixed(MiB(256)));
    machine.add(&firewall)?;

    let home = Vm::personal("usr-home", &firewall, GiB(4))?;
    home.set_memory(Memory::Fixed(MiB(1536)));
    home.add_module(application_scale());
    machine.add(&home)?;

    let work = Vm::personal("usr-work", &firewall, GiB(4))?;
    work.set_memory(Memory::Fixed(MiB(1536)));
    work.add_module(application_scale());
    machine.add(&work)?;

    let gui = Vm::gui("sys-gui", &home)?;
    gui.set_memory(Memory::Fixed(MiB(1536)));
    machine.add(&gui)?;

    let controller = Vm::controller("sys-ctrl", &firewall, GiB(8))?;
    controller.set_memory(Memory::Fixed(MiB(2048)));
    controller.add_module(application_scale());
    controller.add_module(NixosModule::with_arguments([] as [&str; 0], |_| {
        ModuleBody::new(nix_record! {
            "environment": nix_record! {
                "etc": nix_record! {
                    "airlock/machine-build-profile": nix_record! {
                        "text": "local-lab\n",
                    },
                },
            },
        })
    }));
    machine.add(&controller)?;

    let assistant = Vm::assistant("usr-assistant", &firewall, GiB(8))?;
    assistant.set_memory(Memory::Fixed(MiB(2048)));
    assistant.add_module(application_scale());
    machine.add(&assistant)?;

    let clipboard = Vm::hermit("sys-clipboard", MiB(128), HermitApplication::Clipboard)?;
    clipboard.set_autostart(true);
    machine.add(&clipboard)?;
    crate::components::clipboard::connect(&gui, &clipboard);
    crate::components::diagnostics::enable(&mut machine, &assistant);
    machine.set_host(&gui, &firewall, &controller);
    machine.finish()
}

/// Match application rendering to the virtual display rather than the laptop's HiDPI panel.
fn application_scale() -> NixosModule {
    NixosModule::with_arguments([] as [&str; 0], |_| {
        ModuleBody::new(nix_record! {
            "airlock": nix_record! {
                "appGui": nix_record! {
                    "scale": 1_i64,
                },
            },
        })
    })
}

#[cfg(test)]
mod tests {
    /// Ordinary authoring and export must retain the lab's real service contributions.
    #[test]
    fn local_machine_uses_the_standard_export_boundary() {
        let machine = super::machine().unwrap();
        let directory = tempfile::tempdir().unwrap();
        crate::export_installation(&machine, directory.path()).unwrap();
    }
}
