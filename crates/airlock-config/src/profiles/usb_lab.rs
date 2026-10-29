//! Author the VMs selected by the physical USB lab machine.
//! Network, storage and resources follow the machine's Nix definition.

use crate::model::{
    AuthoringError, GiB, HermitApplication, HostPlatform, Machine, MachineSnapshot, MiB, Vm,
};

/// Captures the USB lab VM definitions and their shared host relationships.
/// The optional firewall contribution is an inspection scenario for dependency planning;
/// normal generation leaves the firewall configuration unchanged.
pub fn machine(firewall_diagnostics: bool) -> Result<MachineSnapshot, AuthoringError> {
    let mut machine = Machine::default();
    machine.set_host_platform(HostPlatform::UsbLab);

    let network = Vm::network("sys-net", GiB(2))?;
    machine.add(&network)?;

    let firewall = crate::firewall::branch("sys-firewall", &network, firewall_diagnostics)?;
    machine.add(&firewall)?;

    let home = Vm::personal("usr-home", &firewall, GiB(16))?;
    machine.add(&home)?;

    let gui = Vm::physical_gui("sys-gui", &home)?;
    gui.add_module(crate::components::desktop::gnome());
    crate::components::screen_capture::connect(&gui, &home);
    machine.add(&gui)?;

    let controller = Vm::controller("sys-ctrl", &firewall, GiB(32))?;
    machine.add(&controller)?;

    let assistant = Vm::assistant("usr-assistant", &firewall, GiB(16))?;
    machine.add(&assistant)?;

    let clipboard = Vm::hermit("sys-clipboard", MiB(24), HermitApplication::Clipboard)?;
    clipboard.set_autostart(true);
    machine.add(&clipboard)?;
    crate::components::clipboard::connect(&gui, &clipboard);

    machine.set_host(&gui, &firewall, &controller);
    crate::components::diagnostics::enable(&mut machine, &assistant);
    machine.finish()
}
