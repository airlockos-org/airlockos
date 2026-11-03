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
    network.set_feature("ipv6", "1")?;
    network.add_module(network_diagnostics());
    machine.add(&network)?;

    let firewall = Vm::firewall("sys-firewall-old", &network)?;
    firewall.set_memory(Memory::Fixed(MiB(256)));
    firewall.set_feature("ipv6", "1")?;
    firewall.add_module(network_diagnostics());
    machine.add(&firewall)?;

    // Four reviewed clients share the native default. Management and build
    // traffic retain the Linux path, including when the native VM is stopped.
    let native_firewall = Vm::hermit_firewall("sys-firewall", &network)?;
    native_firewall.set_autostart(true);
    native_firewall.set_feature("ipv6", "1")?;
    machine.add(&native_firewall)?;
    for name in ["usr-firewall-a", "usr-firewall-b"] {
        let client = Vm::command(name, &native_firewall, GiB(1))?;
        client.set_memory(Memory::Fixed(MiB(512)));
        client.set_autostart(false);
        client.set_feature("ipv6", "1")?;
        client.add_module(network_diagnostics());
        machine.add(&client)?;
    }

    let home = Vm::personal("usr-home", &native_firewall, GiB(4))?;
    home.set_memory(Memory::Fixed(MiB(1536)));
    home.set_feature("ipv6", "1")?;
    home.add_module(network_diagnostics());
    home.add_module(application_session());
    machine.add(&home)?;

    let work = Vm::personal("usr-work", &native_firewall, GiB(4))?;
    work.set_memory(Memory::Fixed(MiB(1536)));
    work.set_feature("ipv6", "1")?;
    work.add_module(network_diagnostics());
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
    assistant.add_module(network_diagnostics());
    assistant.add_module(application_session());
    machine.add(&assistant)?;

    let clipboard = Vm::hermit_with_scratch(
        "sys-clipboard",
        MiB(24),
        HermitApplication::Clipboard,
        MiB(128),
    )?;
    clipboard.set_autostart(true);
    machine.add(&clipboard)?;
    crate::components::clipboard::connect(&gui, &clipboard);
    crate::components::diagnostics::enable(&mut machine, &assistant);
    machine.set_host(&gui, &native_firewall, &controller);
    machine.set_updates_proxy(&firewall);
    machine.finish()
}

/// Install ordinary network tools and allow dom0-selected shell users only in
/// disposable QEMU guests, so live probes do not require modifying guest images.
fn network_diagnostics() -> NixosModule {
    NixosModule::with_arguments([] as [&str; 0], |context| {
        ModuleBody::new(nix_record! {
            "airlock": nix_record! {
                "qubeGuest": nix_record! {
                    "allowQrexecUserSelection": true,
                },
            },
            "environment": nix_record! {
                "systemPackages": rusix::interop::raw::NixValue::list([
                    context.pkgs.clone().select("dnsmasq"),
                    context.pkgs.clone().select("nmap"),
                    context.pkgs.clone().select("socat"),
                    context.pkgs.clone().select("tcpdump"),
                    context.pkgs.clone().select("thc-ipv6"),
                    context.pkgs.clone().select("python3"),
                    context.pkgs.select("bind").select("dnsutils"),
                ]),
            },
        })
    })
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
