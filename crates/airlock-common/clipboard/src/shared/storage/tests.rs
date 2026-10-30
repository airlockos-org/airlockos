//! Exercise the spool against a sparse host file through the same sector interface.
//! Fixed chunks verify large offers without constructing a payload-sized test buffer.

extern crate std;

use super::*;
use crate::shared::tests::fixture;
use crate::shared::{Caller, Clipboard, Format, Participant, WRITE_TIMEOUT};
use alloc::{rc::Rc, string::ToString, vec};
use core::cell::Cell;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
};

/// Fault injected into the next operation of a particular kind.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    /// No failure requested.
    None,
    /// Fail a write before publication.
    Write,
    /// Fail the commit barrier.
    Flush,
    /// Fail a read of published content.
    Read,
}

/// Disposable sparse disk; file bytes are never logged.
struct Disk {
    /// Private file holding raw sectors.
    file: File,
    /// Path removed on drop, even after an assertion unwinds.
    path: PathBuf,
    /// Fixed test device size.
    sectors: u64,
    /// Shared control for deterministic I/O failure injection.
    fault: Rc<Cell<Fault>>,
}

impl Disk {
    /// Create an exclusive disposable sparse file with bounded capacity.
    fn new(bytes: usize, fault: Rc<Cell<Fault>>) -> Self {
        static NEXT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(alloc::format!(
            "airlock-spool-{pid}-{id}",
            pid = std::process::id()
        ));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.set_len(bytes as u64).unwrap();
        Self {
            file,
            path,
            sectors: bytes as u64 / 512,
            fault,
        }
    }

    /// Reject oversized or unaligned requests before reaching the file.
    fn position(&mut self, sector: u64, bytes: usize, fault: Fault) -> Result<(), Error> {
        assert!(bytes <= CHUNK && bytes.is_multiple_of(SECTOR));
        assert!(sector + bytes as u64 / 512 <= self.sectors);
        if self.fault.get() == fault {
            return Err(Error::Io);
        }
        self.file
            .seek(SeekFrom::Start(sector * 512))
            .map_err(|_| Error::Io)?;
        Ok(())
    }
}

impl BlockDevice for Disk {
    fn sectors(&self) -> u64 {
        self.sectors
    }

    fn read(&mut self, sector: u64, bytes: &mut [u8]) -> Result<(), Error> {
        self.position(sector, bytes.len(), Fault::Read)?;
        self.file.read_exact(bytes).map_err(|_| Error::Io)
    }

    fn write(&mut self, sector: u64, bytes: &[u8]) -> Result<(), Error> {
        self.position(sector, bytes.len(), Fault::Write)?;
        self.file.write_all(bytes).map_err(|_| Error::Io)
    }

    fn flush(&mut self) -> Result<(), Error> {
        if self.fault.get() == Fault::Flush {
            return Err(Error::Io);
        }
        self.file.sync_data().map_err(|_| Error::Io)
    }
}

impl Drop for Disk {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Describe an exact representation without constructing its private contents.
fn format(name: &str, size: usize) -> Format {
    Format {
        name: name.to_string(),
        size,
    }
}

/// Stream deterministic chunks through the clipboard's ordinary write interface.
fn fill(
    clipboard: &mut Clipboard<Spool<Disk>>,
    caller: &Caller,
    generation: u64,
    format: usize,
    size: usize,
    byte: u8,
) {
    let chunk = [byte; CHUNK];
    let now = clipboard.last_time;
    for offset in (0..size).step_by(CHUNK) {
        clipboard
            .write(
                now,
                caller,
                generation,
                format,
                offset,
                &chunk[..CHUNK.min(size - offset)],
            )
            .unwrap();
    }
}

#[test]
fn aggregate_threshold_maximum_and_repeated_paste_use_bounded_ram() {
    let fault = Rc::new(Cell::new(Fault::None));
    let (mut clipboard, _provisioner, source, target) = fixture(Clipboard::with_storage(
        crate::shared::DEFAULT_CAPACITY,
        Spool::new(Disk::new(crate::shared::DEFAULT_CAPACITY, fault), RAM_LIMIT),
    ));
    let ram = clipboard
        .begin(0, &source, vec![format("text/plain", RAM_LIMIT)])
        .unwrap();
    assert_eq!(
        clipboard.storage().usage(),
        Usage {
            ram_bytes: RAM_LIMIT,
            disk_bytes: 0
        }
    );
    fill(&mut clipboard, &source, ram, 0, RAM_LIMIT, 7);
    clipboard.complete(2, &source, ram).unwrap();
    assert_eq!(
        clipboard
            .read(&target, ram, 0, RAM_LIMIT - 1, usize::MAX)
            .unwrap(),
        vec![7]
    );

    // Each representation fits RAM on its own. Their aggregate must use disk.
    let disk = clipboard
        .begin(
            3,
            &source,
            vec![format("text/plain", RAM_LIMIT), format("image/png", 1)],
        )
        .unwrap();
    assert_eq!(
        clipboard.storage().usage(),
        Usage {
            ram_bytes: 0,
            disk_bytes: RAM_LIMIT + 1
        }
    );
    fill(&mut clipboard, &source, disk, 0, RAM_LIMIT, 8);
    fill(&mut clipboard, &source, disk, 1, 1, 9);
    clipboard.complete(4, &source, disk).unwrap();
    assert_eq!(clipboard.read(&target, disk, 1, 0, CHUNK).unwrap(), vec![9]);

    let maximum = crate::shared::DEFAULT_CAPACITY;
    let full = clipboard
        .begin(
            5,
            &source,
            vec![format("application/octet-stream", maximum)],
        )
        .unwrap();
    fill(&mut clipboard, &source, full, 0, maximum, 42);
    clipboard.complete(6, &source, full).unwrap();
    clipboard.disconnect(&source);
    for _ in 0..2 {
        for offset in (0..maximum).step_by(CHUNK) {
            assert_eq!(
                clipboard
                    .read(&target, full, 0, offset, usize::MAX)
                    .unwrap(),
                [42; CHUNK]
            );
        }
    }
    assert_eq!(
        clipboard.storage().usage(),
        Usage {
            ram_bytes: 0,
            disk_bytes: maximum
        }
    );
    assert_eq!(
        clipboard.begin(7, &target, vec![format("text/plain", maximum + 1)]),
        Err(Error::Bounds)
    );
    clipboard.begin(8, &target, vec![]).unwrap();
    assert_eq!(clipboard.storage().usage(), Usage::default());
    assert_eq!(clipboard.read(&target, full, 0, 0, 1), Err(Error::Stale));
}

#[test]
fn unaligned_interleaved_formats_and_all_terminal_paths_retire_the_extent() {
    let fault = Rc::new(Cell::new(Fault::None));
    let disk = Disk::new(4096, fault);
    let (mut clipboard, provisioner, mut source, target) =
        fixture(Clipboard::with_storage(4096, Spool::new(disk, 4)));
    let generation = clipboard
        .begin(
            0,
            &source,
            vec![format("text/plain", 513), format("text/html", 513)],
        )
        .unwrap();
    // Both formats share a sector. Interleaved writes must preserve its other half.
    fill(&mut clipboard, &source, generation, 1, 513, 2);
    fill(&mut clipboard, &source, generation, 0, 513, 1);
    clipboard.complete(2, &source, generation).unwrap();
    assert_eq!(
        clipboard.read(&target, generation, 0, 0, CHUNK).unwrap(),
        vec![1; 513]
    );
    assert_eq!(
        clipboard.read(&target, generation, 1, 0, CHUNK).unwrap(),
        vec![2; 513]
    );

    for reason in 0..4 {
        let generation = clipboard
            .begin(3, &source, vec![format("text/plain", 1024)])
            .unwrap();
        match reason {
            0 => {
                clipboard.disconnect(&source);
                source = clipboard
                    .admit(&provisioner, Participant::from_binding(1, 21).unwrap())
                    .unwrap();
            }
            1 => clipboard.tick(WRITE_TIMEOUT + 3),
            2 => assert_eq!(
                clipboard.write(4, &source, generation, 0, 1, b"a"),
                Err(Error::Order)
            ),
            _ => assert_eq!(
                clipboard.complete(4, &source, generation),
                Err(Error::Order)
            ),
        }
        assert!(clipboard.offer(&target).unwrap().1.is_none());
        assert_eq!(clipboard.storage().usage(), Usage::default());
    }
    let generation = clipboard
        .begin(0, &source, vec![format("text/plain", 8)])
        .unwrap();
    fill(&mut clipboard, &source, generation, 0, 8, 3);
    assert_eq!(
        clipboard.complete_with_clock(2, &source, generation, || WRITE_TIMEOUT),
        Err(Error::Timeout)
    );
    assert_eq!(clipboard.storage().usage(), Usage::default());
    let (mut restarted, _provisioner, _source, target) = fixture(Clipboard::with_storage(
        4096,
        Spool::new(Disk::new(4096, Rc::new(Cell::new(Fault::None))), 4),
    ));
    assert!(restarted.offer(&target).unwrap().1.is_none());
    assert_eq!(
        restarted.read(&target, generation, 0, 0, 1),
        Err(Error::Stale)
    );
}

#[test]
fn storage_failures_invalidate_content_and_never_fall_back_to_large_ram() {
    for failure in [Fault::Write, Fault::Flush, Fault::Read] {
        let fault = Rc::new(Cell::new(Fault::None));
        let (mut clipboard, _provisioner, source, target) = fixture(Clipboard::with_storage(
            8192,
            Spool::new(Disk::new(4096, fault.clone()), 4),
        ));
        assert_eq!(
            clipboard.begin(0, &source, vec![format("text/plain", 4097)]),
            Err(Error::Capacity)
        );
        let generation = clipboard
            .begin(1, &source, vec![format("text/plain", 1024)])
            .unwrap();
        if failure == Fault::Write {
            fault.set(failure);
        }
        let result = clipboard.write(2, &source, generation, 0, 0, &[3; 1024]);
        if failure == Fault::Write {
            assert_eq!(result, Err(Error::Io));
        } else {
            result.unwrap();
            if failure == Fault::Flush {
                fault.set(failure);
            }
            let result = clipboard.complete(3, &source, generation);
            if failure == Fault::Flush {
                assert_eq!(result, Err(Error::Io));
            } else {
                result.unwrap();
                fault.set(failure);
                assert_eq!(
                    clipboard.read(&target, generation, 0, 0, 1024),
                    Err(Error::Io)
                );
                assert!(clipboard.offer(&target).unwrap().0 > generation);
            }
        }
        assert!(clipboard.offer(&target).unwrap().1.is_none());
        assert_eq!(clipboard.storage().usage(), Usage::default());
        assert_eq!(
            clipboard.begin(4, &source, vec![format("text/plain", 1024)]),
            Err(Error::Io)
        );
        // A poisoned disk cannot cause a payload-sized RAM fallback.
        clipboard
            .begin(5, &source, vec![format("text/plain", 4)])
            .unwrap();
        assert_eq!(clipboard.storage().usage().ram_bytes, 4);
    }
}
