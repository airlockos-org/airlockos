//! Physical identity and capability selection do not depend on event numbering.

use super::*;
use serde_json::to_value;

/// Describe an inert sysfs observation without contacting udev.
fn observation(
    number: u32,
    classes: &[&str],
    node: Option<&str>,
    sys: Option<&str>,
) -> Option<Descriptor> {
    let node_path = format!("/dev/input/event{number}");
    let sys_path = format!("/sys/devices/pci0000:00/usb1/1-2/input/input{number}/event{number}");
    let properties = classes
        .iter()
        .map(|class| (format!("ID_INPUT_{class}"), "1".into()))
        .collect();

    describe(
        Path::new(node.unwrap_or(&node_path)),
        Path::new(sys.unwrap_or(&sys_path)),
        Some(OsStr::new("Generic input")),
        &properties,
    )
}

/// Every supported capability is selected without a vendor-specific device name.
#[test]
fn capabilities_are_name_independent() {
    for class in Class::ALL {
        let descriptor = observation(37, &[class.as_str()], None, None).unwrap();
        assert_eq!(
            descriptor
                .hardware
                .classes
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>(),
            [class.as_str()]
        );
        assert_eq!(descriptor.node.path(), Path::new("/dev/input/event37"));
    }
}

/// Composite interfaces retain their capabilities and stable identity after replug.
#[test]
fn event_renumbering_preserves_physical_identity() {
    let first = observation(1, &["KEYBOARD", "TOUCHPAD"], None, None).unwrap();
    let second = observation(18, &["KEYBOARD", "TOUCHPAD"], None, None).unwrap();
    assert_eq!(
        to_value(&first.hardware).unwrap(),
        to_value(&second.hardware).unwrap()
    );
    assert_eq!(
        first.hardware.sys_path,
        Path::new("/sys/devices/pci0000:00/usb1/1-2")
    );
    assert_eq!(
        first
            .hardware
            .classes
            .iter()
            .map(|c| c.as_str())
            .collect::<Vec<_>>(),
        ["KEYBOARD", "TOUCHPAD"]
    );
}

/// Sensors, virtual interfaces and unvalidated paths never enter the sender inventory.
#[test]
fn unrelated_or_unsafe_observations_are_ignored() {
    for classes in [["ACCELEROMETER"], ["SWITCH"]] {
        assert!(observation(1, &classes, None, None).is_none());
    }

    for node in [
        "/dev/input/mouse0",
        "/dev/input/event1; command",
        "/dev/input/event",
    ] {
        assert!(
            observation(1, &["KEYBOARD"], Some(node), None).is_none(),
            "{node}"
        );
    }

    for sys in ["/sys/devices/virtual/input/input1/event1", "/tmp/device"] {
        assert!(
            observation(1, &["KEYBOARD"], None, Some(sys)).is_none(),
            "{sys}"
        );
    }
}
