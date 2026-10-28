//! Input readiness describes existing forwarded devices; it never injects events or authorizes callers.

use serde::{Deserialize, Serialize};

/// A physical keyboard/pointer interface or its registered counterpart in the guest.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    /// Kernel name; guest observations include the receiver's authenticated source-domain prefix.
    pub name: String,
    /// Whether the interface supports ordinary typing, rather than only multimedia keys.
    pub keyboard: bool,
    /// Whether the interface supports relative or absolute pointer movement.
    pub pointer: bool,
}

/// A fresh reply from the argument-free, dom0-only receiver readiness RPC.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Receiver {
    /// Closed wire version; unknown replies cannot satisfy boot readiness.
    pub schema: Schema,
    /// Existing kernel interfaces owned by the upstream dom0 input receivers.
    pub devices: Vec<Device>,
}

/// Supported input observation protocol.
#[derive(Debug, Deserialize, Serialize)]
pub enum Schema {
    /// Device names and keyboard/pointer capability observations.
    #[serde(rename = "airlock.input-receiver.v1")]
    V1,
}

/// Match physical interface names as the upstream receiver prefixes and truncates them.
fn forwarded_name(name: &str) -> String {
    // input-proxy accepts printable ASCII only, then adds "dom0: " within the
    // kernel's 80-byte uinput name (including its terminating zero).
    let name: String = name.chars().take(127).collect();
    let name = if name.is_empty() {
        "Forwarded input device"
    } else {
        &name
    };
    format!("dom0: {name}").chars().take(79).collect()
}

impl Receiver {
    /// Require every attached keyboard/pointer interface to be registered in the guest.
    ///
    /// An empty physical inventory is valid. This verifies transport registration,
    /// not that a human has pressed a key or moved a pointer.
    pub fn covers(&self, physical: &[Device]) -> Result<(), String> {
        let mut available: Vec<_> = self.devices.iter().collect();
        for expected in physical
            .iter()
            .filter(|device| device.keyboard || device.pointer)
        {
            if !expected
                .name
                .chars()
                .all(|ch| ch.is_ascii() && (' '..='~').contains(&ch))
            {
                return Err("physical input name is unsupported by the upstream receiver".into());
            }
            let name = forwarded_name(&expected.name);
            let Some(index) = available.iter().position(|actual| {
                actual.name == name
                    && (!expected.keyboard || actual.keyboard)
                    && (!expected.pointer || actual.pointer)
            }) else {
                return Err(format!(
                    "forwarded input interface is missing or incomplete: {name}"
                ));
            };
            // Equal kernel names are common for two identical physical devices.
            // One live receiver must not satisfy both physical interfaces.
            available.remove(index);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A live daemon, an unrelated virtual device and a partial connection cannot satisfy readiness.
    #[test]
    fn coverage_requires_matching_registered_interfaces() {
        let physical = vec![
            Device {
                name: "Keyboard".into(),
                keyboard: true,
                pointer: false,
            },
            Device {
                name: "Mouse".into(),
                keyboard: false,
                pointer: true,
            },
        ];
        let mut receiver = Receiver {
            schema: Schema::V1,
            devices: vec![],
        };
        assert!(receiver.covers(&physical).is_err());
        receiver.devices.push(Device {
            name: forwarded_name("Keyboard"),
            keyboard: true,
            pointer: false,
        });
        assert!(receiver.covers(&physical).is_err());
        receiver.devices.push(Device {
            name: forwarded_name("Mouse"),
            keyboard: false,
            pointer: true,
        });
        assert!(receiver.covers(&physical).is_ok());
        assert!(receiver.covers(&[]).is_ok());
        assert!(receiver.covers(&physical[1..]).is_ok());
        let mut duplicate = physical.clone();
        duplicate.push(physical[0].clone());
        assert!(receiver.covers(&duplicate).is_err());
        receiver.devices.push(receiver.devices[0].clone());
        assert!(receiver.covers(&duplicate).is_ok());
        receiver.devices.pop();
        receiver.devices[0].name = "unrelated: Keyboard".into();
        assert!(receiver.covers(&physical).is_err());
        assert_eq!(forwarded_name(&"x".repeat(200)).len(), 79);
    }
}
