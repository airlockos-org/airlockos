//! Exercise publication, repeated reads, replacement and participant lifetimes.

use super::*;
use alloc::{string::ToString, vec};

/// An authenticated source and a different admitted destination.
const SOURCE: Participant = Participant {
    principal: 1,
    epoch: 10,
};

/// Independent connection allowed to paste normal content.
const TARGET: Participant = Participant {
    principal: 2,
    epoch: 20,
};

/// Describe one representation without allocating its payload.
fn format(name: &str, size: usize) -> Format {
    Format {
        name: name.to_string(),
        size,
    }
}

#[test]
fn multiple_formats_publish_together_and_survive_repeated_paste_and_idle() {
    let mut clipboard = Clipboard::new(1024);
    let generation = clipboard
        .begin(
            0,
            SOURCE,
            vec![
                format("text/plain", 3),
                format("image/png", 4),
                format("text/html", 0),
            ],
        )
        .unwrap();
    clipboard
        .write(1, SOURCE, generation, 0, 0, b"abc")
        .unwrap();
    assert!(clipboard.offer(TARGET).unwrap().1.is_none());
    clipboard
        .write(2, SOURCE, generation, 1, 0, &[0, 255, 3, 0])
        .unwrap();
    clipboard.complete(3, SOURCE, generation).unwrap();
    clipboard.tick(u64::MAX);
    clipboard.disconnect(SOURCE);
    for _ in 0..3 {
        assert_eq!(
            clipboard.read(TARGET, generation, 0, 0, 10),
            Ok(b"abc".to_vec())
        );
        assert_eq!(
            clipboard.read(TARGET, generation, 1, 1, 2),
            Ok(vec![255, 3])
        );
        assert_eq!(clipboard.read(TARGET, generation, 2, 0, 10), Ok(vec![]));
    }
    assert_eq!(clipboard.offer(TARGET).unwrap().1.unwrap().source, SOURCE);
}

#[test]
fn replacements_invalidate_reads_and_late_source_chunks() {
    let mut clipboard = Clipboard::new(1024);
    let old = clipboard.reserve(0, SOURCE).unwrap();
    let new = clipboard
        .begin(1, TARGET, vec![format("text/plain", 1)])
        .unwrap();
    assert_eq!(
        clipboard.declare(2, SOURCE, old, vec![format("text/plain", 1)]),
        Err(Error::Stale)
    );
    assert_eq!(
        clipboard.write(2, SOURCE, old, 0, 0, b"a"),
        Err(Error::Stale)
    );
    clipboard.write(3, TARGET, new, 0, 0, b"b").unwrap();
    clipboard.complete(4, TARGET, new).unwrap();
    assert_eq!(clipboard.read(SOURCE, old, 0, 0, 1), Err(Error::Stale));
    assert_eq!(clipboard.read(SOURCE, new, 0, 0, 1), Ok(b"b".to_vec()));
    let cleared = clipboard.begin(5, SOURCE, vec![]).unwrap();
    assert_eq!(clipboard.offer(TARGET), Ok((cleared, None)));
    assert_eq!(clipboard.read(TARGET, new, 0, 0, 1), Err(Error::Stale));
}

#[test]
fn incomplete_or_expired_writes_never_publish_and_reconnect_cannot_finish_them() {
    let mut clipboard = Clipboard::new(1024);
    let generation = clipboard
        .begin(0, SOURCE, vec![format("text/plain", 2)])
        .unwrap();
    let reconnected = Participant {
        epoch: 11,
        ..SOURCE
    };
    assert_eq!(
        clipboard.write(1, reconnected, generation, 0, 0, b"ab"),
        Err(Error::Stale)
    );
    assert_eq!(clipboard.complete(2, SOURCE, generation), Err(Error::Order));
    let generation = clipboard
        .begin(3, SOURCE, vec![format("text/plain", 2)])
        .unwrap();
    assert_eq!(
        clipboard.write(WRITE_TIMEOUT + 3, SOURCE, generation, 0, 0, b"ab"),
        Err(Error::Stale)
    );
    assert!(clipboard.offer(TARGET).unwrap().1.is_none());
}

#[test]
fn rejects_unauthenticated_callers_file_formats_and_resource_exhaustion() {
    let mut clipboard = Clipboard::new(4);
    let invalid = Participant {
        principal: 0,
        epoch: 1,
    };
    assert_eq!(clipboard.offer(invalid), Err(Error::Unauthorized));
    assert_eq!(
        clipboard.begin(0, invalid, vec![]),
        Err(Error::Unauthorized)
    );
    assert_eq!(
        clipboard.begin(0, SOURCE, vec![format("text/uri-list", 1)]),
        Err(Error::Unsupported)
    );
    assert_eq!(
        clipboard.begin(
            0,
            SOURCE,
            vec![format("text/plain", 3), format("text/html", 2)]
        ),
        Err(Error::Bounds)
    );
    assert_eq!(
        clipboard.begin(
            0,
            SOURCE,
            vec![format("text/plain", 0), format("text/plain", 0)]
        ),
        Err(Error::Order)
    );
    assert_eq!(
        clipboard.begin(0, SOURCE, vec![format("text/plain", 0); MAX_FORMATS + 1]),
        Err(Error::Bounds)
    );
}
