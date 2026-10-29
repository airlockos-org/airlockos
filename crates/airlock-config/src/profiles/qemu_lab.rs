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
/// Fixed memory bounds keep this machine within a 32 GiB outer guest without changing role defaults.
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
    home.add_module(application_session());
    machine.add(&home)?;

    let work = Vm::personal("usr-work", &firewall, GiB(4))?;
    work.set_memory(Memory::Fixed(MiB(1536)));
    work.add_module(application_session());
    machine.add(&work)?;

    let gui = Vm::gui("sys-gui", &home)?;
    gui.set_memory(Memory::Fixed(MiB(1536)));
    machine.add(&gui)?;

    let controller = Vm::controller("sys-ctrl", &firewall, GiB(16))?;
    // Whole-machine Nix evaluation needs room for every VM system, including background controller startup.
    controller.set_memory(Memory::Fixed(MiB(16384)));
    controller.add_module(application_session());
    controller.add_module(NixosModule::with_arguments([] as [&str; 0], |_| {
        ModuleBody::new(nix_record! {
            "environment": nix_record! {
                "etc": nix_record! {
                    "airlock/machine-build-profile": nix_record! {
                        "text": "qemu-lab\n",
                    },
                },
            },
        })
    }));
    machine.add(&controller)?;

    let assistant = Vm::assistant("usr-assistant", &firewall, GiB(16))?;
    assistant.set_memory(Memory::Fixed(MiB(2048)));
    assistant.add_module(application_session());
    machine.add(&assistant)?;

    let clipboard = Vm::hermit_with_scratch(
        "sys-clipboard",
        MiB(128),
        HermitApplication::Clipboard,
        MiB(128),
    )?;
    clipboard.set_autostart(true);
    machine.add(&clipboard)?;
    crate::components::clipboard::connect(&gui, &clipboard);
    crate::components::diagnostics::enable(&mut machine, &assistant);
    machine.set_host(&gui, &firewall, &controller);
    machine.finish()
}

/// Match the virtual display and include the standard X11 clipboard client for local inspection.
fn application_session() -> NixosModule {
    NixosModule::with_arguments([] as [&str; 0], |context| {
        ModuleBody::new(nix_record! {
            "environment": nix_record! {
                "systemPackages": rusix::interop::raw::NixValue::list([context.pkgs.select("xclip")]),
            },
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
    fn qemu_lab_machine_uses_the_standard_export_boundary() {
        let machine = super::machine().unwrap();
        let directory = tempfile::tempdir().unwrap();
        crate::export_installation(&machine, directory.path()).unwrap();
    }
}
