//! Device identity describes physical interfaces independently of volatile event numbers.

use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    path::{Path, PathBuf},
};

/// A kernel evdev node; unrelated paths must never enter a sender's local command.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Node {
    // Absolute /dev/input/eventN path validated at discovery, including hotplug removal.
    path: PathBuf,
}

impl Node {
    /// Accept only an absolute evdev event node, excluding paths and shell fragments.
    pub(super) fn parse(path: &Path) -> Option<Self> {
        let text = path.to_str()?;
        let number = text.strip_prefix("/dev/input/event")?;
        (!number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()))
            .then(|| Self { path: path.into() })
    }

    /// Borrow the validated path passed to the upstream sender.
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

/// Supported udev capabilities, including composite keyboard and pointer interfaces.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub(super) enum Class {
    Key,
    Keyboard,
    Mouse,
    PointingStick,
    Touchpad,
    Touchscreen,
    Tablet,
    #[serde(rename = "TABLET_PAD")]
    TabletPad,
    Joystick,
}

impl Class {
    pub(super) const ALL: [Self; 9] = [
        Self::Key,
        Self::Keyboard,
        Self::Mouse,
        Self::PointingStick,
        Self::Touchpad,
        Self::Touchscreen,
        Self::Tablet,
        Self::TabletPad,
        Self::Joystick,
    ];

    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Key => "KEY",
            Self::Keyboard => "KEYBOARD",
            Self::Mouse => "MOUSE",
            Self::PointingStick => "POINTINGSTICK",
            Self::Touchpad => "TOUCHPAD",
            Self::Touchscreen => "TOUCHSCREEN",
            Self::Tablet => "TABLET",
            Self::TabletPad => "TABLET_PAD",
            Self::Joystick => "JOYSTICK",
        }
    }
}

/// Observed physical interface metadata used for advisory inventory and diagnostics.
pub(super) struct Descriptor {
    /// Current device node used for transport, excluded from persistent identity.
    pub(super) node: Node,
    /// Stable hardware attributes without the temporary event-node identity.
    pub(super) hardware: Hardware,
}

/// Physical attributes distinguish interfaces without using their current event number.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Hardware {
    /// Human-readable kernel device name; capability selection does not depend on it.
    pub(super) name: String,
    /// Supported udev capabilities, retaining every class of composite interfaces.
    pub(super) classes: Vec<Class>,
    /// Optional serial metadata supplied by udev; empty if none is available.
    pub(super) serial: String,
    /// Udev's physical connection identifier, if the device exposes one.
    pub(super) path: String,
    /// Sysfs interface path with volatile input/inputN/eventN suffixes removed.
    pub(super) sys_path: PathBuf,
    /// Optional udev vendor identifier retained for observation.
    pub(super) vendor: String,
    /// Optional udev product identifier retained for observation.
    pub(super) product: String,
}

pub(super) fn describe(
    node: &Path,
    sys_path: &Path,
    name: Option<&OsStr>,
    properties: &BTreeMap<String, String>,
) -> Option<Descriptor> {
    let node = Node::parse(node)?;
    if !sys_path.starts_with("/sys/devices") || sys_path.starts_with("/sys/devices/virtual") {
        return None;
    }
    let classes: Vec<_> = Class::ALL
        .into_iter()
        .filter(|c| {
            properties
                .get(&format!("ID_INPUT_{}", c.as_str()))
                .is_some_and(|v| v == "1")
        })
        .collect();
    if classes.is_empty() {
        return None;
    }

    let mut stable = sys_path;
    if Node::parse(&Path::new("/dev/input").join(sys_path.file_name()?)).is_some()
        && let Some(parent) = sys_path.parent()
        && parent.file_name().and_then(OsStr::to_str).is_some_and(|n| {
            n.strip_prefix("input").is_some_and(|suffix| {
                !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit())
            })
        })
        && let Some(input) = parent.parent()
        && input.file_name() == Some(OsStr::new("input"))
    {
        stable = input.parent()?;
    }
    let property = |key: &str| properties.get(key).cloned().unwrap_or_default();
    Some(Descriptor {
        node,
        hardware: Hardware {
            name: name
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            classes,
            serial: property("ID_SERIAL"),
            path: property("ID_PATH"),
            sys_path: stable.into(),
            vendor: property("ID_VENDOR_ID"),
            product: property("ID_MODEL_ID"),
        },
    })
}

#[cfg(test)]
#[path = "model/tests.rs"]
mod tests;
