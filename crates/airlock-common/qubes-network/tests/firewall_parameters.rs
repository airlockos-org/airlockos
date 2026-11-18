//! Exercise startup selection through the native QubesDB control state machine.

use airlock_boot_core::Challenge;
use airlock_qubes_network::{
    FIREWALL_PARAMETERS_PATH, READY_PATH,
    control::{Control, Step},
};
use airlock_qubesdb::wire::{ENTRY, HEADER, OK, WRITE};

/// Build a daemon response with the pinned QubesDB header layout.
fn record(opcode: u8, key: &str, value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; HEADER];
    bytes[0] = opcode;
    bytes[1..1 + key.len()].copy_from_slice(key.as_bytes());
    bytes[68..72].copy_from_slice(&(value.len() as u32).to_le_bytes());
    bytes.extend_from_slice(value);
    bytes
}

/// Deliver one whole server frame and process its bytes in stream order.
fn consume(control: &mut Control, frame: Vec<u8>) -> Step {
    assert!(control.deliver(&frame));
    for _ in 1..frame.len() {
        assert!(matches!(control.step(), Step::Progress));
    }
    control.step()
}

/// Acknowledge the complete request sent by the control state machine.
fn publish(control: &mut Control) {
    assert!(!control.outgoing().is_empty());
    assert!(control.published(control.outgoing().len()));
}

/// A partial startup yields no selection. A subsequent write cannot change it.
#[test]
fn startup_freezes_presence_or_absence() {
    for initial in [None, Some(b"initial".as_slice())] {
        let challenge = Challenge::parse(b"01234567-89ab-cdef-0123-456789abcdef").unwrap();
        let mut control = Control::synchronizing_at(0, challenge);
        publish(&mut control);
        assert!(matches!(control.step(), Step::Receive));
        if let Some(value) = initial {
            assert!(matches!(
                consume(&mut control, record(ENTRY, FIREWALL_PARAMETERS_PATH, value)),
                Step::Progress
            ));
            assert!(matches!(control.step(), Step::Receive));
        }
        assert_eq!(control.firewall_parameters(), None);
        assert!(matches!(
            consume(&mut control, record(ENTRY, "", b"")),
            Step::Progress
        ));
        assert_eq!(control.firewall_parameters(), None);
        publish(&mut control);
        assert!(matches!(control.step(), Step::Receive));
        assert!(matches!(
            consume(&mut control, record(OK, READY_PATH, b"")),
            Step::Synchronized
        ));
        assert_eq!(control.firewall_parameters(), Some(initial));

        assert!(matches!(control.step(), Step::Receive));
        assert!(matches!(
            consume(
                &mut control,
                record(WRITE, FIREWALL_PARAMETERS_PATH, b"replacement")
            ),
            Step::Changed { .. }
        ));
        assert_eq!(control.firewall_parameters(), Some(initial));
    }
}
