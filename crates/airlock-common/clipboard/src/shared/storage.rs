//! One private extent per offer, backed by bounded RAM or an ephemeral block disk.
//! No on-disk metadata survives a service boot. The runtime must supply encrypted
//! temporary storage with a fresh key on restart; this module provides no history.
//!
//! Publication is atomic within one single-threaded service lifetime: readers see
//! either the complete flushed offer or no offer. Chunk writes are not commit
//! points. Success acknowledges this volatile publication, not survival of process
//! failure, guest restart, machine crash or power loss. All content may be lost in
//! any of those events, including after a successful reply; recovery starts empty
//! with a fresh Qubes encryption key and never replays old disk bytes. There is no
//! persistent authoritative metadata requiring a file or multi-file transaction.
//! A flush error can leave device bytes changed; poisoning and logical invalidation
//! preserve that uncertainty without publishing or retrying the failed operation.

use super::Error;
use alloc::vec::Vec;
use vstd::prelude::*;

verus! {

/// Replace one checked byte range while preserving every byte outside it.
pub open spec fn replaced(original: Seq<u8>, offset: int, bytes: Seq<u8>) -> Seq<u8> {
    original.subrange(0, offset) + bytes + original.subrange(offset + bytes.len(), original.len() as int)
}

/// Consecutive writes extend the same contiguous prefix without changing other bytes.
proof fn patch_append(original: Seq<u8>, base: int, prefix: Seq<u8>, next: Seq<u8>)
    requires 0 <= base, base + prefix.len() + next.len() <= original.len(),
    ensures replaced(replaced(original, base, prefix), base + prefix.len(), next)
        == replaced(original, base, prefix + next),
{
    let left = replaced(replaced(original, base, prefix), base + prefix.len(), next);
    let right = replaced(original, base, prefix + next);
    assert(left.len() == right.len());
    assert forall|i: int| 0 <= i < left.len() implies left[i] == right[i] by {
        if i < base {} else if i < base + prefix.len() {}
        else if i < base + prefix.len() + next.len() {} else {}
    }
    assert(left =~= right);
}

/// A sector read/modify/write changes exactly its selected logical subrange.
proof fn patch_window(original: Seq<u8>, start: int, end: int, within: int, bytes: Seq<u8>)
    requires 0 <= start <= end <= original.len(), 0 <= within,
        within + bytes.len() <= end - start,
    ensures replaced(original, start, replaced(original.subrange(start, end), within, bytes))
        == replaced(original, start + within, bytes),
{
    let left = replaced(original, start, replaced(original.subrange(start, end), within, bytes));
    let right = replaced(original, start + within, bytes);
    assert(left.len() == right.len());
    assert forall|i: int| 0 <= i < left.len() implies left[i] == right[i] by {
        if i < start {} else if i < start + within {} else if i < start + within + bytes.len() {}
        else if i < end {} else {}
    }
    assert(left =~= right);
}

/// A physical write contained in the logical extent has the same checked logical projection.
proof fn patch_take(original: Seq<u8>, length: int, offset: int, bytes: Seq<u8>)
    requires 0 <= offset, offset + bytes.len() <= length <= original.len(),
    ensures replaced(original, offset, bytes).take(length)
        == replaced(original.take(length), offset, bytes),
{
    let left = replaced(original, offset, bytes).take(length);
    let right = replaced(original.take(length), offset, bytes);
    assert(left.len() == right.len());
    assert forall|i: int| 0 <= i < left.len() implies left[i] == right[i] by {
        if i < offset {} else if i < offset + bytes.len() {} else {}
    }
    assert(left =~= right);
}

/// Aggregate payload threshold, across all representations of one offer.
pub const RAM_LIMIT: usize = 5 * 1024 * 1024;

/// Largest copied read result or block request held by this layer.
pub const CHUNK: usize = 4096;

/// Xen block devices address fixed 512-byte sectors.
pub const SECTOR: usize = 512;

/// Storage information suitable for diagnostics; contains no clipboard contents.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    /// Payload bytes currently allocated in RAM.
    pub ram_bytes: usize,
    /// Logical bytes in the current disk extent; retired disk bytes are unreachable.
    pub disk_bytes: usize,
}

/// Private storage for the state machine's single pending or published offer.
/// Failed operations must never expose partial data. `clear` invalidates all
/// logical bytes even if a failed device cannot accept further requests.
pub trait Storage {
    /// Logical extent visible to the clipboard, never retired physical disk bytes.
    spec fn view(&self) -> Seq<u8>;

    /// Owned state and resource bounds maintained by this implementation.
    spec fn valid(&self) -> bool;

    /// Replace an empty extent with exactly this many logical bytes.
    fn allocate(&mut self, bytes: usize) -> (out: Result<(), Error>)
        requires old(self).valid(),
        ensures final(self).valid(), out.is_ok() ==> final(self).view().len() == bytes,
            out.is_err() ==> final(self).view().len() == 0,
    ;

    /// Write a checked range within the allocated extent.
    fn write(&mut self, offset: usize, bytes: &[u8]) -> (out: Result<(), Error>)
        requires old(self).valid(),
        ensures final(self).valid(),
            out.is_ok() ==> offset + bytes.len() <= old(self).view().len()
                && final(self).view() == replaced(old(self).view(), offset as int, bytes@),
            out == Err(Error::Io) ==> final(self).view().len() == 0,
            out.is_err() && out != Err(Error::Io) ==> final(self).view() == old(self).view(),
    ;

    /// Copy a checked range into a bounded caller-owned buffer.
    fn read(&mut self, offset: usize, bytes: &mut [u8]) -> (out: Result<(), Error>)
        requires old(self).valid(),
        ensures final(self).valid(), final(bytes)@.len() == old(bytes)@.len(),
            out.is_ok() ==> final(self).view() == old(self).view()
                && offset + old(bytes)@.len() <= old(self).view().len()
                && final(bytes)@ == old(self).view().subrange(offset as int, offset + old(bytes)@.len()),
            out == Err(Error::Io) ==> final(self).view().len() == 0
                && (forall|i: int| 0 <= i < final(bytes)@.len() ==> final(bytes)[i] == 0),
            out.is_err() && out != Err(Error::Io) ==> final(self).view() == old(self).view()
                && final(bytes)@ == old(bytes)@,
    ;

    /// Finish all writes before atomic publication.
    fn flush(&mut self) -> (out: Result<(), Error>)
        requires old(self).valid(),
        ensures final(self).valid(), out.is_ok() ==> final(self).view() == old(self).view(),
            out.is_err() ==> out == Err(Error::Io) && final(self).view().len() == 0,
    ;

    /// Invalidate the extent and erase its owned RAM, without requiring disk I/O.
    fn clear(&mut self)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).view().len() == 0,
    ;

    /// Report only storage sizes, never format names or private bytes.
    fn usage(&self) -> (usage: Usage)
        requires self.valid(),
        ensures usage.ram_bytes <= RAM_LIMIT,
            usage.ram_bytes + usage.disk_bytes == self.view().len(),
    ;
}

/// Minimal synchronous sector device, independent of Xen and operating systems.
/// Implementations check capacity and accept only whole sectors, at most `CHUNK`
/// bytes per request. An ambiguous failure must poison further device access.
pub trait BlockDevice {
    /// Captured device geometry, immutable for this handle's lifetime.
    spec fn geometry(&self) -> u64;

    /// Abstract decrypted device contents; I/O errors may leave their values uncertain.
    spec fn contents(&self) -> Seq<u8>;

    /// Addressable capacity in 512-byte sectors.
    fn sectors(&self) -> (sectors: u64)
        ensures sectors == self.geometry(),
    ;

    /// Read whole sectors into a bounded private buffer.
    fn read(&mut self, sector: u64, bytes: &mut [u8]) -> (out: Result<(), Error>)
        requires old(self).contents().len() == old(self).geometry() * SECTOR, old(bytes).len() <= CHUNK,
            old(bytes).len() % SECTOR == 0, sector * SECTOR + old(bytes).len() <= old(self).contents().len(),
        ensures final(self).contents().len() == final(self).geometry() * SECTOR, final(self).geometry() == old(self).geometry(),
            final(bytes)@.len() == old(bytes)@.len(),
            out.is_ok() ==> final(self).contents() == old(self).contents()
                && final(bytes)@ == old(self).contents().subrange(sector * SECTOR, sector * SECTOR + old(bytes).len()),
    ;

    /// Write whole sectors from a bounded private buffer.
    fn write(&mut self, sector: u64, bytes: &[u8]) -> (out: Result<(), Error>)
        requires old(self).contents().len() == old(self).geometry() * SECTOR, bytes.len() <= CHUNK,
            bytes.len() % SECTOR == 0, sector * SECTOR + bytes.len() <= old(self).contents().len(),
        ensures final(self).contents().len() == final(self).geometry() * SECTOR, final(self).geometry() == old(self).geometry(),
            out.is_ok() ==> final(self).contents() == old(self).contents().subrange(0, sector * SECTOR)
                + bytes@ + old(self).contents().subrange(sector * SECTOR + bytes.len(), old(self).contents().len() as int),
    ;

    /// Confirm writes before an offer becomes visible.
    fn flush(&mut self) -> (out: Result<(), Error>)
        requires old(self).contents().len() == old(self).geometry() * SECTOR,
        ensures final(self).contents().len() == final(self).geometry() * SECTOR, final(self).geometry() == old(self).geometry(),
            out.is_ok() ==> final(self).contents() == old(self).contents(),
    ;
}

/// Geometry describes the same fixed-size private device throughout its handle lifetime.
pub open spec fn device_valid<D: BlockDevice + ?Sized>(device: &D) -> bool {
    device.contents().len() == device.geometry() * SECTOR
}

/// Explicitly diskless storage for host-native policy tests and small offers.
pub struct NoDisk;

impl BlockDevice for NoDisk {
    open spec fn geometry(&self) -> u64 { 0 }

    open spec fn contents(&self) -> Seq<u8> { Seq::empty() }

    fn sectors(&self) -> u64 {
        0
    }

    fn read(&mut self, _sector: u64, _bytes: &mut [u8]) -> Result<(), Error> {
        Err(Error::Io)
    }

    fn write(&mut self, _sector: u64, _bytes: &[u8]) -> Result<(), Error> {
        Err(Error::Io)
    }

    fn flush(&mut self) -> Result<(), Error> {
        Err(Error::Io)
    }
}

/// Exclusive backing for one aggregate offer; replacement releases its predecessor.
enum Backing {
    /// No bytes may be read or published.
    Empty,
    /// Small offers use one bounded allocation, including all representations.
    Ram(
        /// Exclusive payload extent, erased before retirement.
        Vec<u8>,
    ),
    /// Large offers use only a logical extent on the supplied disk.
    Disk {
        /// Exact aggregate extent size, excluding sector padding.
        length: usize,
    },
}

/// RAM/disk spool with fixed-size sector buffering and no payload-sized disk cache.
pub struct Spool<D> {
    /// The runtime's sole private ephemeral block device.
    disk: D,
    /// Maximum aggregate RAM payload; fixed at `RAM_LIMIT` in the service.
    ram_limit: usize,
    /// Current extent; no second old/new extent is retained during replacement.
    backing: Backing,
    /// One private sector for unaligned format boundaries.
    sector: [u8; SECTOR],
    /// Failed I/O disables this disk until a fresh service boot.
    poisoned: bool,
}

impl<D: BlockDevice> Spool<D> {
    /// Use RAM for offers up to the threshold and direct block storage above it.
    pub fn new(disk: D, ram_limit: usize) -> (spool: Self)
        requires device_valid(&disk),
        ensures spool.valid(), spool.view().len() == 0,
    {
        Self {
            disk,
            ram_limit: ram_limit.min(RAM_LIMIT),
            backing: Backing::Empty,
            sector: [0; SECTOR],
            poisoned: false,
        }
    }

    /// Clearing retires logical bytes while preserving the device and sticky health state.
    pub closed spec fn cleared_from(&self, previous: &Self) -> bool {
        self.backing is Empty && self.ram_limit == previous.ram_limit
            && self.poisoned == previous.poisoned && self.disk == previous.disk
    }

    /// Validate logical ranges before any buffer or device access.
    fn range(&self, offset: usize, count: usize) -> (out: Result<(), Error>)
        requires self.valid(),
        ensures out.is_ok() == (!(self.backing is Empty) && offset + count <= self.view().len()),
            out.is_err() ==> out == Err(Error::Stale) || out == Err(Error::Bounds),
    {
        let length = match &self.backing {
            Backing::Empty => return Err(Error::Stale),
            Backing::Ram(bytes) => bytes.len(),
            Backing::Disk { length } => *length,
        };
        if offset > length || count > length - offset {
            return Err(Error::Bounds);
        }
        Ok(())
    }

    /// Prevent any reuse after a failed or ambiguous backend operation.
    fn finish_io(&mut self, result: Result<(), Error>) -> (out: Result<(), Error>)
        requires old(self).valid(),
        ensures final(self).valid(), out.is_ok() == result.is_ok(),
            out.is_err() ==> out == Err(Error::Io),
            result.is_err() ==> final(self).poisoned && final(self).view().len() == 0,
            result.is_ok() ==> final(self).view() == old(self).view(),
    {
        if result.is_err() {
            self.clear();
            self.poisoned = true;
            return Err(Error::Io);
        }
        erase(&mut self.sector);
        Ok(())
    }

    /// Transfer disk bytes using at most one private sector for boundary fragments.
    #[verifier::rlimit(20)]
    fn transfer(
        &mut self,
        base: usize,
        bytes: &mut [u8],
        write: bool,
    ) -> (out: Result<(), Error>)
        requires old(self).valid(), old(self).backing is Disk,
            base + old(bytes)@.len() <= old(self).view().len(), old(bytes)@.len() <= CHUNK,
        ensures final(self).valid(), final(self).backing == old(self).backing,
            final(self).ram_limit == old(self).ram_limit, final(self).poisoned == old(self).poisoned,
            final(self).view().len() == old(self).view().len(),
            final(self).disk.geometry() == old(self).disk.geometry(),
            final(bytes)@.len() == old(bytes)@.len(),
            out.is_ok() && write ==> final(self).disk.contents() == replaced(old(self).disk.contents(), base as int, old(bytes)@)
                && final(bytes)@ == old(bytes)@,
            out.is_ok() && !write ==> final(self).disk.contents() == old(self).disk.contents()
                && final(bytes)@ == old(self).disk.contents().subrange(base as int, base + old(bytes)@.len()),
    {
        let mut copied = 0;
        while copied < bytes.len()
            invariant copied <= bytes.len(), bytes@.len() == old(bytes)@.len(),
                self.valid(), self.backing is Disk,
                self.backing == old(self).backing, self.ram_limit == old(self).ram_limit,
                self.poisoned == old(self).poisoned,
                self.disk.geometry() == old(self).disk.geometry(),
                base + bytes.len() <= self.view().len(), bytes.len() <= CHUNK,
                base + old(bytes)@.len() <= old(self).disk.contents().len(),
                self.view().len() == old(self).view().len(),
                write ==> bytes@ == old(bytes)@ && self.disk.contents()
                    == replaced(old(self).disk.contents(), base as int, old(bytes)@.take(copied as int)),
                !write ==> self.disk.contents() == old(self).disk.contents()
                    && bytes@.take(copied as int) == old(self).disk.contents().subrange(base as int, base + copied),
            decreases bytes.len() - copied,
        {
            let ghost previous_disk = self.disk.contents();
            let ghost previous_bytes = bytes@;
            let offset = base + copied;
            let remaining = bytes.len() - copied;
            let sector = (offset / SECTOR) as u64;
            let within = offset % SECTOR;
            let count = if within == 0 && remaining >= SECTOR {
                remaining.min(CHUNK) / SECTOR * SECTOR
            } else {
                remaining.min(SECTOR - within)
            };
            let part = &mut bytes[copied..copied + count];
            if within == 0 && count.is_multiple_of(SECTOR) {
                if write {
                    self.disk.write(sector, part)?;
                } else {
                    self.disk.read(sector, part)?;
                }
            } else {
                self.disk.read(sector, &mut self.sector)?;
                if write {
                    self.sector[within..within + count].copy_from_slice(part);
                    assert(self.sector@ == replaced(previous_disk.subrange(sector * SECTOR, sector * SECTOR + SECTOR), within as int,
                        previous_bytes.subrange(copied as int, copied + count)));
                    self.disk.write(sector, &self.sector)?;
                    proof { patch_window(previous_disk, sector * SECTOR, sector * SECTOR + SECTOR, within as int,
                        previous_bytes.subrange(copied as int, copied + count)); }
                } else {
                    part.copy_from_slice(&self.sector[within..within + count]);
                }
            }
            if write {
                assert(bytes@ == previous_bytes);
                assert(self.disk.contents() == replaced(previous_disk, offset as int,
                    previous_bytes.subrange(copied as int, copied + count)));
                proof {
                    patch_append(old(self).disk.contents(), base as int, old(bytes)@.take(copied as int),
                        old(bytes)@.subrange(copied as int, copied + count));
                    assert(old(bytes)@.take(copied as int) + old(bytes)@.subrange(copied as int, copied + count)
                        == old(bytes)@.take((copied + count) as int));
                }
            }
            copied += count;
        }
        Ok(())
    }
}

impl<D: BlockDevice> Storage for Spool<D> {
    closed spec fn view(&self) -> Seq<u8> {
        match &self.backing {
            Backing::Empty => Seq::empty(),
            Backing::Ram(bytes) => bytes@,
            Backing::Disk { length } => self.disk.contents().take(*length as int),
        }
    }

    closed spec fn valid(&self) -> bool {
        device_valid(&self.disk) && self.ram_limit <= RAM_LIMIT && match &self.backing {
            Backing::Empty => true,
            Backing::Ram(bytes) => bytes@.len() <= self.ram_limit,
            Backing::Disk { length } => !self.poisoned && *length <= self.disk.contents().len(),
        }
    }

    fn allocate(&mut self, bytes: usize) -> Result<(), Error> {
        self.clear();
        if bytes <= self.ram_limit {
            let mut ram = Vec::new();
            ram.try_reserve_exact(bytes).map_err(|_| Error::Capacity)?;
            ram.resize(bytes, 0);
            self.backing = Backing::Ram(ram);
        } else {
            if self.poisoned {
                return Err(Error::Io);
            }
            let sectors = (bytes / SECTOR + if bytes.is_multiple_of(SECTOR) { 0 } else { 1 }) as u64;
            if sectors > self.disk.sectors() {
                return Err(Error::Capacity);
            }
            self.backing = Backing::Disk { length: bytes };
        }
        Ok(())
    }

    fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        self.range(offset, bytes.len())?;
        if let Backing::Ram(ram) = &mut self.backing {
            let destination = &mut ram.as_mut_slice()[offset..offset + bytes.len()];
            assert(destination.len() == bytes.len());
            destination.copy_from_slice(bytes);
            return Ok(());
        }
        // The immutable caller buffer is copied in bounded chunks, never as a
        // full offer. Device implementations must also use private grant buffers.
        let mut chunk = [0; CHUNK];
        let mut copied = 0;
        while copied < bytes.len()
            invariant copied <= bytes.len(), self.valid(), self.backing is Disk,
                offset + bytes.len() <= self.view().len(),
                offset + bytes.len() <= old(self).view().len(),
                self.view() == replaced(old(self).view(), offset as int, bytes@.take(copied as int)),
            decreases bytes.len() - copied,
        {
            let count = CHUNK.min(bytes.len() - copied);
            chunk[..count].copy_from_slice(&bytes[copied..copied + count]);
            let ghost previous_disk = self.disk.contents();
            let ghost previous_logical = self.view();
            if let Err(error) = self.transfer(offset + copied, &mut chunk[..count], true) {
                erase(&mut chunk);
                return self.finish_io(Err(error));
            }
            proof {
                patch_take(previous_disk, previous_logical.len() as int, (offset + copied) as int,
                    bytes@.subrange(copied as int, copied + count));
                patch_append(old(self).view(), offset as int, bytes@.take(copied as int),
                    bytes@.subrange(copied as int, copied + count));
                assert(bytes@.take(copied as int) + bytes@.subrange(copied as int, copied + count)
                    == bytes@.take((copied + count) as int));
            }
            copied += count;
        }
        erase(&mut chunk);
        self.finish_io(Ok(()))
    }

    fn read(&mut self, offset: usize, bytes: &mut [u8]) -> Result<(), Error> {
        self.range(offset, bytes.len())?;
        if bytes.len() > CHUNK {
            return Err(Error::Bounds);
        }
        if let Backing::Ram(ram) = &self.backing {
            bytes.copy_from_slice(&ram[offset..offset + bytes.len()]);
            return Ok(());
        }
        let result = self.transfer(offset, bytes, false);
        if result.is_err() {
            erase(bytes);
        }
        self.finish_io(result)
    }

    fn flush(&mut self) -> Result<(), Error> {
        if matches!(self.backing, Backing::Disk { .. }) {
            let result = self.disk.flush();
            self.finish_io(result)?;
        }
        Ok(())
    }

    fn clear(&mut self)
        ensures final(self).cleared_from(old(self)),
    {
        if let Backing::Ram(bytes) = &mut self.backing {
            erase(bytes.as_mut_slice());
        }
        erase(&mut self.sector);
        self.backing = Backing::Empty;
    }

    fn usage(&self) -> Usage {
        match &self.backing {
            Backing::Empty => Usage { ram_bytes: 0, disk_bytes: 0 },
            Backing::Ram(bytes) => Usage {
                ram_bytes: bytes.len(),
                disk_bytes: 0,
            },
            Backing::Disk { length } => Usage {
                ram_bytes: 0,
                disk_bytes: *length,
            },
        }
    }
}

impl<D> Drop for Spool<D> {
    fn drop(&mut self)
        opens_invariants none
        no_unwind
    {
        if let Backing::Ram(bytes) = &mut self.backing {
            erase(bytes.as_mut_slice());
        }
        erase(&mut self.sector);
    }
}

/// Erase owned buffers without claiming to erase copies held by a peer or disk.
/// Requirement: unsafe/effect correspondence. Scope: volatile stores to this
/// exclusively borrowed slice only. The pinned vstd does not model volatile
/// pointer stores or compiler elision, so this is a trusted primitive contract.
/// It assumes Rust's valid exclusive slice and write_volatile semantics; no
/// alias, allocation, I/O or fallible cleanup is introduced. Other copies,
/// registers and retired disk sectors are outside this erasure claim.
#[verifier::external_body]
fn erase(bytes: &mut [u8])
    ensures final(bytes)@.len() == old(bytes)@.len(), forall|i: int| 0 <= i < final(bytes)@.len() ==> final(bytes)[i] == 0,
    opens_invariants none
    no_unwind
{
    for byte in bytes {
        // SAFETY: the iterator gives exclusive access to each live byte.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
}

}

#[cfg(test)]
mod tests;
