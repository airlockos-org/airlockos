//! Define the nested QEMU bootstrap machine used for lifecycle and network validation.
//! The physical USB machine has its own hardware and resource configuration.

use crate::model::{AuthoringError, GiB, HermitApplication, Machine, MachineSnapshot, MiB, Vm};

/// Declare the bootstrap VMs with typed network and host relationships.
pub fn machine() -> Result<MachineSnapshot, AuthoringError> {
    let mut machine = Machine::default();

    let network = Vm::network("sys-net", GiB(2))?;
    machine.add(&network)?;

    let firewall = Vm::firewall("sys-firewall", &network)?;
    machine.add(&firewall)?;

    let home = Vm::personal("usr-home", &firewall, GiB(16))?;
    machine.add(&home)?;

    let gui = Vm::gui("sys-gui", &home)?;
    machine.add(&gui)?;

    let controller = Vm::controller("sys-ctrl", &firewall, GiB(32))?;
    machine.add(&controller)?;

    let assistant = Vm::assistant("usr-assistant", &firewall, GiB(16))?;
    machine.add(&assistant)?;

    let command = Vm::command("usr-cmd", &firewall, GiB(8))?;
    machine.add(&command)?;

    let clipboard = Vm::hermit("sys-clipboard", MiB(32), HermitApplication::Clipboard)?;
    clipboard.set_autostart(true);
    machine.add(&clipboard)?;

    machine.set_host(&gui, &firewall, &controller);
    machine.finish()
}
