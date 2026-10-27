//! Subscribe before enumerating so devices connected during startup cannot be lost.

use super::{
    forwarder::Forwarder,
    model::{self, Hardware, Node},
};
use crate::state;
use airlock_nix_core::identity::GuestName;
use anyhow::{Result, ensure};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Default, Serialize, Deserialize)]
struct Inventory {
    // On-disk advisory inventory version; never interpreted as input authorization.
    version: u8,
    // Historical hardware descriptions keyed by stable descriptor digest.
    devices: BTreeMap<String, Observed>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Observed {
    // Physical interface metadata independent of its current evdev number.
    #[serde(flatten)]
    hardware: Hardware,
    // Existing accept-all policy marker; this record does not authorize enrollment.
    trusted: bool,
    // First successful publication time for this hardware identity.
    first_seen: f64,
}

impl Inventory {
    fn load(path: &Path) -> Self {
        match state::optional::<Self>(path) {
            Ok(Some(record)) if record.version == 1 => record,
            Ok(None) => Self {
                version: 1,
                ..Self::default()
            },
            result => {
                eprintln!("cannot read input inventory ({result:?}); discovery will continue");
                Self {
                    version: 1,
                    ..Self::default()
                }
            }
        }
    }

    fn remember(&mut self, path: &Path, hardware: Hardware) -> Result<()> {
        let identity = format!("{:x}", Sha256::digest(serde_json::to_vec(&hardware)?));
        if self.devices.contains_key(&identity) {
            return Ok(());
        }
        self.devices.insert(
            identity.clone(),
            Observed {
                hardware,
                trusted: true,
                first_seen: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64(),
            },
        );
        if let Err(error) = state::save(path, self) {
            self.devices.remove(&identity);
            return Err(error);
        }
        Ok(())
    }
}

fn add(device: &udev::Device, forwarder: &mut Forwarder, inventory: &mut Inventory, path: &Path) {
    let Some(descriptor) = describe(device) else {
        return;
    };
    let node = descriptor.node.path().to_owned();
    if let Err(error) = inventory.remember(path, descriptor.hardware) {
        eprintln!("cannot persist input inventory: {error:#}; forwarding will continue");
    }
    if let Err(error) = forwarder.add(descriptor.node) {
        eprintln!(
            "cannot forward {}: {error}; other devices remain connected",
            node.display()
        );
    }
}

/// Describe the same eligible physical interfaces for transport and read-only readiness.
fn describe(device: &udev::Device) -> Option<model::Descriptor> {
    let node = device.devnode()?;
    let properties = device
        .properties()
        .map(|p| {
            (
                p.name().to_string_lossy().into_owned(),
                p.value().to_string_lossy().into_owned(),
            )
        })
        .collect();
    let parent = device.parent();
    let name = parent.as_ref().and_then(|p| p.attribute_value("name"));
    model::describe(node, device.syspath(), name, &properties)
}

/// Enumerate independently of the daemon, so an empty or incomplete initial scan cannot pass readiness.
pub(super) fn physical() -> Result<Vec<airlock_machine_core::input::Device>> {
    if let Some(path) = std::env::var_os("AIRLOCK_INPUT_PHYSICAL") {
        return crate::state::read(std::path::Path::new(&path));
    }
    let mut enumerator = udev::Enumerator::new()?;
    enumerator.match_subsystem("input")?;
    let mut result = Vec::new();
    for device in enumerator.scan_devices()? {
        if let Some(descriptor) = describe(&device) {
            let classes = &descriptor.hardware.classes;
            result.push(airlock_machine_core::input::Device {
                name: descriptor.hardware.name,
                keyboard: classes
                    .iter()
                    .any(|class| matches!(class, model::Class::Keyboard)),
                pointer: classes.iter().any(|class| {
                    matches!(
                        class,
                        model::Class::Mouse
                            | model::Class::PointingStick
                            | model::Class::Touchpad
                            | model::Class::Touchscreen
                            | model::Class::Tablet
                    )
                }),
            });
        }
    }
    Ok(result)
}

pub(super) fn run(
    target: GuestName,
    qrexec: PathBuf,
    sender: PathBuf,
    path: PathBuf,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    ensure!(
        path.is_absolute(),
        "input inventory must be an absolute path"
    );

    let _guard = super::runtime_lock("discovery", &target)?;
    let mut forwarder = Forwarder::new(target, qrexec, sender)?;
    let mut inventory = Inventory::load(&path);

    let socket = udev::MonitorBuilder::new()?
        .match_subsystem("input")?
        .listen()?;
    let mut enumerator = udev::Enumerator::new()?;
    enumerator.match_subsystem("input")?;
    for device in enumerator.scan_devices()? {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        add(&device, &mut forwarder, &mut inventory, &path);
    }

    while !stop.load(Ordering::Relaxed) {
        let mut fds = [PollFd::new(&socket, PollFlags::IN)];
        match poll(
            &mut fds,
            Some(&Timespec::try_from(Duration::from_millis(250))?),
        ) {
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
        ensure!(
            !fds[0]
                .revents()
                .intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL),
            "input device monitor disconnected"
        );
        // Drain a bounded batch before checking shutdown and sender exits again.
        for event in socket.iter().take(256) {
            match event.event_type() {
                udev::EventType::Remove => {
                    if let Some(node) = event.devnode().and_then(Node::parse) {
                        forwarder.remove(&node);
                    }
                }
                udev::EventType::Add | udev::EventType::Change => {
                    add(&event, &mut forwarder, &mut inventory, &path)
                }
                _ => {}
            }
        }
        forwarder.reap();
    }
    Ok(())
}
