//! One private extent per offer, backed by bounded RAM or an ephemeral block disk.
//! No on-disk metadata survives a service boot. The runtime must supply encrypted
//! temporary storage with a fresh key on restart; this module provides no history.

use super::Error;
use alloc::vec::Vec;

/// Aggregate payload threshold, across all representations of one offer.
pub const RAM_LIMIT: usize = 5 * 1024 * 1024;

/// Largest copied read result or block request held by this layer.
pub const CHUNK: usize = 4096;

/// Xen block devices address fixed 512-byte sectors.
const SECTOR: usize = 512;

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
    /// Replace an empty extent with exactly this many logical bytes.
    fn allocate(&mut self, bytes: usize) -> Result<(), Error>;

    /// Write a checked range within the allocated extent.
    fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error>;

    /// Copy a checked range into a bounded caller-owned buffer.
    fn read(&mut self, offset: usize, bytes: &mut [u8]) -> Result<(), Error>;

    /// Finish all writes before atomic publication.
    fn flush(&mut self) -> Result<(), Error>;

    /// Invalidate the extent and erase its owned RAM, without requiring disk I/O.
    fn clear(&mut self);

    /// Report only storage sizes, never format names or private bytes.
    fn usage(&self) -> Usage;
}

/// Minimal synchronous sector device, independent of Xen and operating systems.
/// Implementations check capacity and accept only whole sectors, at most `CHUNK`
/// bytes per request. An ambiguous failure must poison further device access.
pub trait BlockDevice {
    /// Addressable capacity in 512-byte sectors.
    fn sectors(&self) -> u64;

    /// Read whole sectors into a bounded private buffer.
    fn read(&mut self, sector: u64, bytes: &mut [u8]) -> Result<(), Error>;

    /// Write whole sectors from a bounded private buffer.
    fn write(&mut self, sector: u64, bytes: &[u8]) -> Result<(), Error>;

    /// Confirm writes before an offer becomes visible.
    fn flush(&mut self) -> Result<(), Error>;
}

/// Explicitly diskless storage for host-native policy tests and small offers.
pub struct NoDisk;

impl BlockDevice for NoDisk {
    fn sectors(&self) -> u64 {
        0
    }

    fn read(&mut self, _: u64, _: &mut [u8]) -> Result<(), Error> {
        Err(Error::Io)
    }

    fn write(&mut self, _: u64, _: &[u8]) -> Result<(), Error> {
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
    Ram(Vec<u8>),
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
    pub fn new(disk: D, ram_limit: usize) -> Self {
        Self {
            disk,
            ram_limit: ram_limit.min(RAM_LIMIT),
            backing: Backing::Empty,
            sector: [0; SECTOR],
            poisoned: false,
        }
    }

    /// Validate logical ranges before any buffer or device access.
    fn range(&self, offset: usize, count: usize) -> Result<(), Error> {
        let length = match &self.backing {
            Backing::Empty => return Err(Error::Stale),
            Backing::Ram(bytes) => bytes.len(),
            Backing::Disk { length } => *length,
        };
        if offset.checked_add(count).is_none_or(|end| end > length) {
            return Err(Error::Bounds);
        }
        Ok(())
    }

    /// Prevent any reuse after a failed or ambiguous backend operation.
    fn finish_io(&mut self, result: Result<(), Error>) -> Result<(), Error> {
        if result.is_err() {
            self.poisoned = true;
            self.clear();
            return Err(Error::Io);
        }
        erase(&mut self.sector);
        Ok(())
    }

    /// Transfer disk bytes using at most one private sector for boundary fragments.
    fn transfer(
        &mut self,
        mut offset: usize,
        mut bytes: &mut [u8],
        write: bool,
    ) -> Result<(), Error> {
        while !bytes.is_empty() {
            let sector = (offset / SECTOR) as u64;
            let within = offset % SECTOR;
            let count = if within == 0 && bytes.len() >= SECTOR {
                bytes.len().min(CHUNK) / SECTOR * SECTOR
            } else {
                bytes.len().min(SECTOR - within)
            };
            let (part, remaining) = bytes.split_at_mut(count);
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
                    self.disk.write(sector, &self.sector)?;
                } else {
                    part.copy_from_slice(&self.sector[within..within + count]);
                }
            }
            offset += count;
            bytes = remaining;
        }
        Ok(())
    }
}

impl<D: BlockDevice> Storage for Spool<D> {
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
            let sectors = bytes.div_ceil(SECTOR) as u64;
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
            ram[offset..offset + bytes.len()].copy_from_slice(bytes);
            return Ok(());
        }
        // The immutable caller buffer is copied in bounded chunks, never as a
        // full offer. Device implementations must also use private grant buffers.
        let mut chunk = [0; CHUNK];
        let result = (|| {
            for (index, part) in bytes.chunks(CHUNK).enumerate() {
                chunk[..part.len()].copy_from_slice(part);
                self.transfer(offset + index * CHUNK, &mut chunk[..part.len()], true)?;
            }
            Ok(())
        })();
        erase(&mut chunk);
        self.finish_io(result)
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

    fn clear(&mut self) {
        if let Backing::Ram(bytes) = &mut self.backing {
            erase(bytes);
        }
        erase(&mut self.sector);
        self.backing = Backing::Empty;
    }

    fn usage(&self) -> Usage {
        match &self.backing {
            Backing::Empty => Usage::default(),
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
    fn drop(&mut self) {
        if let Backing::Ram(bytes) = &mut self.backing {
            erase(bytes);
        }
        erase(&mut self.sector);
    }
}

/// Erase owned buffers without claiming to erase copies held by a peer or disk.
fn erase(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: the iterator gives exclusive access to each live byte.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
}

#[cfg(test)]
mod tests;
