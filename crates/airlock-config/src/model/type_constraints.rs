//! Type constraints prevent invalid role wiring and mutation of frozen machines.

//! Memory sizes cannot be assigned private-volume units.
//!
//! ```compile_fail,E0308
//! # use airlock_config::model::{self, GiB, Machine, MiB, Vm};
//! let _: MiB = GiB(2);
//! ```

//! A personal VM cannot provide a firewall's uplink.
//!
//! ```compile_fail,E0277
//! # use airlock_config::model::{self, GiB, Machine, MiB, Vm};
//! # let network = Vm::network("sys-net", GiB(2)).unwrap();
//! # let firewall = Vm::firewall("sys-firewall", &network).unwrap();
//! # let home = Vm::personal("usr-home", &firewall, GiB(16)).unwrap();
//! Vm::firewall("bad-firewall", &home);
//! ```

//! The GUI launch target must be a personal VM.
//!
//! ```compile_fail,E0308
//! # use airlock_config::model::{self, GiB, Machine, MiB, Vm};
//! # let network = Vm::network("sys-net", GiB(2)).unwrap();
//! # let firewall = Vm::firewall("sys-firewall", &network).unwrap();
//! # let home = Vm::personal("usr-home", &firewall, GiB(16)).unwrap();
//! # let gui = Vm::gui("sys-gui", &home).unwrap();
//! Vm::gui("another-gui", &network);
//! ```

//! A handle keeps the role established by its constructor.
//!
//! ```compile_fail,E0308
//! # use airlock_config::model::{self, GiB, Machine, MiB, Vm};
//! # let network = Vm::network("sys-net", GiB(2)).unwrap();
//! let _: model::VmHandle<model::Firewall> = network;
//! ```

//! Only Airlock's sealed network roles can provide uplinks.
//!
//! ```compile_fail,E0277
//! # use airlock_config::model::{self, GiB, Machine, MiB, Vm};
//! # let network = Vm::network("sys-net", GiB(2)).unwrap();
//! struct Other;
//!
//! impl model::ProvidesNetwork for Other {}
//! ```

//! Network drivers have no application display assignment.
//!
//! ```compile_fail,E0599
//! # use airlock_config::model::{self, GiB, Machine, MiB, Vm};
//! # let network = Vm::network("sys-net", GiB(2)).unwrap();
//! # let firewall = Vm::firewall("sys-firewall", &network).unwrap();
//! # let home = Vm::personal("usr-home", &firewall, GiB(16)).unwrap();
//! # let gui = Vm::gui("sys-gui", &home).unwrap();
//! network.set_gui(&gui);
//! ```

//! A display assignment requires a GUI handle.
//!
//! ```compile_fail,E0308
//! # use airlock_config::model::{self, GiB, Machine, MiB, Vm};
//! # let network = Vm::network("sys-net", GiB(2)).unwrap();
//! # let firewall = Vm::firewall("sys-firewall", &network).unwrap();
//! # let home = Vm::personal("usr-home", &firewall, GiB(16)).unwrap();
//! home.set_gui(&firewall);
//! ```

//! The host's controller reference must select a controller.
//!
//! ```compile_fail,E0308
//! # use airlock_config::model::{self, GiB, Machine, MiB, Vm};
//! # let mut machine = Machine::default();
//! # let network = Vm::network("sys-net", GiB(2)).unwrap();
//! # let firewall = Vm::firewall("sys-firewall", &network).unwrap();
//! # let home = Vm::personal("usr-home", &firewall, GiB(16)).unwrap();
//! # let gui = Vm::gui("sys-gui", &home).unwrap();
//! machine.set_host(&gui, &firewall, &home);
//! ```

//! Only Airlock's sealed client roles can request a GUI.
//!
//! ```compile_fail,E0277
//! # use airlock_config::model::{self, GiB, Machine, MiB, Vm};
//! struct Other;
//!
//! impl model::UsesGui for Other {}
//! ```

//! Finalized VM resources remain immutable.
//!
//! ```compile_fail,E0594
//! # use airlock_config::model::{self, GiB, Machine, MiB, Vm};
//! # let mut machine = Machine::default();
//! let frozen = machine.finish().unwrap();
//! frozen.vms().next().unwrap().settings.vcpus = 9;
//! ```

//! Finalized host defaults remain immutable.
//!
//! ```compile_fail,E0594
//! # use airlock_config::model::{self, GiB, Machine, MiB, Vm};
//! # let mut machine = Machine::default();
//! # let network = Vm::network("sys-net", GiB(2)).unwrap();
//! let frozen = machine.finish().unwrap();
//! frozen.host().unwrap().network = "other".parse().unwrap();
//! ```

//! Capture senders must provide the GUI capability.
//!
//! ```compile_fail,E0308
//! # use airlock_config::model::{self, GiB, Machine, MiB, Vm};
//! # let network = Vm::network("sys-net", GiB(2)).unwrap();
//! # let firewall = Vm::firewall("sys-firewall", &network).unwrap();
//! # let home = Vm::personal("usr-home", &firewall, GiB(16)).unwrap();
//! # let gui = Vm::gui("sys-gui", &home).unwrap();
//! use airlock_config::components::screen_capture;
//! screen_capture::connect(&home, &gui);
//! ```

//! Capture destinations must provide personal storage.
//!
//! ```compile_fail,E0308
//! # use airlock_config::model::{self, GiB, Machine, MiB, Vm};
//! # let network = Vm::network("sys-net", GiB(2)).unwrap();
//! # let firewall = Vm::firewall("sys-firewall", &network).unwrap();
//! # let home = Vm::personal("usr-home", &firewall, GiB(16)).unwrap();
//! # let gui = Vm::gui("sys-gui", &home).unwrap();
//! # let controller = Vm::controller("sys-ctrl", &firewall, GiB(32)).unwrap();
//! use airlock_config::components::screen_capture;
//! screen_capture::connect(&gui, &controller);
//! ```

//! Hermit handles cannot request a Linux root filesystem.
//!
//! ```compile_fail,E0599
//! use airlock_config::model::{Vm, MiB, HermitApplication};
//! let vm = Vm::hermit("sys-clipboard", MiB(32), HermitApplication::Clipboard).unwrap();
//! vm.set_root_image(MiB(512));
//! ```

//! Hermit handles cannot acquire NixOS modules.
//!
//! ```compile_fail,E0599
//! use airlock_config::model::{Vm, MiB, HermitApplication};
//! let vm = Vm::hermit("sys-clipboard", MiB(32), HermitApplication::Clipboard).unwrap();
//! vm.add_module(rusix::nixos::NixosModule::empty());
//! ```
