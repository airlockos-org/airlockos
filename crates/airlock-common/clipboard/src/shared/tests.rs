//! Exercise publication, repeated reads, replacement and participant lifetimes.

use super::*;
use alloc::{string::ToString, vec};

/// An authenticated source and a different admitted destination.
const SOURCE: Participant = Participant::from_binding(1, 10).unwrap();

/// Independent connection allowed to paste normal content.
const TARGET: Participant = Participant::from_binding(2, 20).unwrap();

/// Provision independent source and target capabilities for an isolated clipboard.
pub(crate) fn fixture<S: storage::Storage>(
    (mut clipboard, provisioner): (Clipboard<S>, Provisioner),
) -> (Clipboard<S>, Provisioner, Caller, Caller) {
    let source = clipboard.admit(&provisioner, SOURCE).unwrap();
    let target = clipboard.admit(&provisioner, TARGET).unwrap();
    (clipboard, provisioner, source, target)
}

/// Describe one representation without allocating its payload.
fn format(name: &str, size: usize) -> Format {
    Format {
        name: name.to_string(),
        size,
    }
}

#[test]
fn multiple_formats_publish_together_and_survive_repeated_paste_and_idle() {
    let (mut clipboard, _provisioner, source, target) = fixture(Clipboard::new(1024));
    let generation = clipboard
        .begin(
            0,
            &source,
            vec![
                format("text/plain", 3),
                format("image/png", 4),
                format("text/html", 0),
            ],
        )
        .unwrap();
    clipboard
        .write(1, &source, generation, 0, 0, b"abc")
        .unwrap();
    assert!(clipboard.offer(&target).unwrap().1.is_none());
    clipboard
        .write(2, &source, generation, 1, 0, &[0, 255, 3, 0])
        .unwrap();
    clipboard.complete(3, &source, generation).unwrap();
    clipboard.tick(u64::MAX);
    clipboard.disconnect(&source);
    for _ in 0..3 {
        assert_eq!(
            clipboard.read(&target, generation, 0, 0, 10),
            Ok(b"abc".to_vec())
        );
        assert_eq!(
            clipboard.read(&target, generation, 1, 1, 2),
            Ok(vec![255, 3])
        );
        assert_eq!(clipboard.read(&target, generation, 2, 0, 10), Ok(vec![]));
    }
    assert_eq!(clipboard.offer(&target).unwrap().1.unwrap().source, SOURCE);
}

#[test]
fn replacements_invalidate_reads_and_late_source_chunks() {
    let (mut clipboard, _provisioner, source, target) = fixture(Clipboard::new(1024));
    let old = clipboard.reserve(0, &source).unwrap();
    let new = clipboard
        .begin(1, &target, vec![format("text/plain", 1)])
        .unwrap();
    assert_eq!(
        clipboard.declare(2, &source, old, vec![format("text/plain", 1)]),
        Err(Error::Stale)
    );
    assert_eq!(
        clipboard.write(2, &source, old, 0, 0, b"a"),
        Err(Error::Stale)
    );
    clipboard.write(3, &target, new, 0, 0, b"b").unwrap();
    clipboard.complete(4, &target, new).unwrap();
    assert_eq!(clipboard.read(&source, old, 0, 0, 1), Err(Error::Stale));
    assert_eq!(clipboard.read(&source, new, 0, 0, 1), Ok(b"b".to_vec()));
    let cleared = clipboard.begin(5, &source, vec![]).unwrap();
    assert_eq!(clipboard.offer(&target), Ok((cleared, None)));
    assert_eq!(clipboard.read(&target, new, 0, 0, 1), Err(Error::Stale));
}

#[test]
fn incomplete_or_expired_writes_never_publish_and_reconnect_cannot_finish_them() {
    let (mut clipboard, provisioner, mut source, target) = fixture(Clipboard::new(1024));
    let generation = clipboard
        .begin(0, &source, vec![format("text/plain", 2)])
        .unwrap();
    clipboard.disconnect(&source);
    assert_eq!(
        clipboard.write(1, &source, generation, 0, 0, b"ab"),
        Err(Error::Unauthorized)
    );
    source = clipboard
        .admit(&provisioner, Participant::from_binding(1, 21).unwrap())
        .unwrap();
    assert_eq!(
        clipboard.write(1, &source, generation, 0, 0, b"ab"),
        Err(Error::Stale)
    );
    let generation = clipboard
        .begin(1, &source, vec![format("text/plain", 2)])
        .unwrap();
    assert_eq!(
        clipboard.complete(2, &source, generation),
        Err(Error::Order)
    );
    let generation = clipboard
        .begin(3, &source, vec![format("text/plain", 2)])
        .unwrap();
    assert_eq!(
        clipboard.write(WRITE_TIMEOUT + 3, &source, generation, 0, 0, b"ab"),
        Err(Error::Stale)
    );
    assert!(clipboard.offer(&target).unwrap().1.is_none());
}

#[test]
fn rejects_unauthenticated_callers_file_formats_and_resource_exhaustion() {
    let (mut clipboard, _provisioner, source, _target) = fixture(Clipboard::new(4));
    assert!(Participant::from_binding(0, 1).is_none());
    assert!(Participant::from_binding(1, 0).is_none());
    assert_eq!(
        clipboard.begin(0, &source, vec![format("text/uri-list", 1)]),
        Err(Error::Unsupported)
    );
    assert_eq!(
        clipboard.begin(
            0,
            &source,
            vec![format("text/plain", 3), format("text/html", 2)]
        ),
        Err(Error::Bounds)
    );
    assert_eq!(
        clipboard.begin(
            0,
            &source,
            vec![format("text/plain", 0), format("text/plain", 0)]
        ),
        Err(Error::Order)
    );
    assert_eq!(
        clipboard.begin(0, &source, vec![format("text/plain", 0); MAX_FORMATS + 1]),
        Err(Error::Bounds)
    );
}

#[test]
fn admission_capabilities_bind_object_identity_capacity_and_connection_lifetime() {
    let (mut clipboard, provisioner) = Clipboard::new(1024);
    let (mut other, foreign_provisioner) = Clipboard::new(1024);
    let identity = Participant::from_binding(1, 1).unwrap();
    assert!(clipboard.admit(&foreign_provisioner, identity).is_err());
    let foreign_caller = other.admit(&foreign_provisioner, identity).unwrap();
    assert_eq!(clipboard.offer(&foreign_caller), Err(Error::Unauthorized));

    let mut callers = Vec::new();
    for index in 1..=32 {
        let identity = Participant::from_binding(index, index).unwrap();
        callers.push(clipboard.admit(&provisioner, identity).unwrap());
    }
    assert!(
        clipboard
            .admit(&provisioner, Participant::from_binding(33, 33).unwrap())
            .is_err()
    );
    assert!(callers.iter().all(|caller| clipboard.offer(caller).is_ok()));

    let generation = clipboard
        .begin(0, &callers[0], vec![format("text/plain", 1)])
        .unwrap();
    clipboard
        .write(1, &callers[0], generation, 0, 0, b"x")
        .unwrap();
    clipboard.disconnect(&foreign_caller);
    clipboard.complete(2, &callers[0], generation).unwrap();
    assert_eq!(
        clipboard.read(&callers[1], generation, 0, 0, 1).unwrap(),
        b"x"
    );

    clipboard.disconnect(&callers[0]);
    assert_eq!(clipboard.offer(&callers[0]), Err(Error::Unauthorized));
    assert!(clipboard.admit(&provisioner, identity).is_err());
    let successor = clipboard
        .admit(&provisioner, Participant::from_binding(1, 33).unwrap())
        .unwrap();
    // Late cleanup from an old connection cannot revoke a reused registry slot.
    clipboard.disconnect(&callers[0]);
    assert!(clipboard.offer(&successor).is_ok());
    assert_eq!(clipboard.offer(&callers[0]), Err(Error::Unauthorized));
    assert!(
        callers[1..]
            .iter()
            .all(|caller| clipboard.offer(caller).is_ok())
    );
}
