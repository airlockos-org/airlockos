//! A shared desktop clipboard with atomic, multi-format replacement.
//!
//! The transport authenticates participants before calling this module. Content
//! has no expiry and reads never consume it. Only incomplete writes expire.
//! Access decisions are centralized here so future policies need not change
//! desktop format transfer or trust identities supplied by a requesting VM.

use alloc::{string::String, vec::Vec};

pub mod storage;

use storage::{CHUNK, NoDisk, RAM_LIMIT, Spool, Storage};

/// Maximum total payload retained in the default clipboard service.
pub const DEFAULT_CAPACITY: usize = 64 * 1024 * 1024;

/// Deadline for completing an in-flight replacement, in monotonic nanoseconds.
pub const WRITE_TIMEOUT: u64 = 120_000_000_000;

use crate::authority::Admissions;
pub use crate::authority::{Caller, Participant, Provisioner};
use crate::values::Deadline;
pub use crate::values::{Generation, Time};

use crate::formats::CheckedOffer;
pub use crate::formats::{
    Error, Format, MAX_FORMAT_NAME, MAX_FORMATS, is_data_format, is_file_format, validate_formats,
};

/// Public identity of a complete clipboard offer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    /// Monotonically increasing replacement identity within this service boot.
    pub generation: Generation,
    /// Authenticated source of the content, retained independently of its connection.
    pub source: Participant,
    /// Available representations in their original preference order.
    pub formats: Vec<Format>,
}

/// One representation under construction or retained for repeated paste.
struct Representation {
    /// Format name and promised byte length.
    format: Format,
    /// Start in the single aggregate storage extent.
    offset: usize,
    /// Contiguous bytes received; only complete representations can be published.
    written: usize,
}

/// Private offer state before or after publication.
struct Content {
    /// Globally ordered identity issued before reading any source bytes.
    generation: Generation,
    /// Authenticated owner of this replacement.
    source: Participant,
    /// Representation buffers bounded by the service's total capacity.
    formats: Vec<Representation>,
}

/// Mutually exclusive lifecycle stages; partial content cannot be a published offer.
enum State {
    /// No private extent or readable content remains.
    Empty,
    /// A replacement owns ordering but has not declared any representations.
    Reserved {
        /// Latest issued replacement identity, retained across failures.
        generation: Generation,
        /// Exact admitted incarnation allowed to declare this reservation.
        source: Participant,
        /// Fixed monotonic completion deadline, including format conversion time.
        deadline: Deadline,
    },
    /// Declared representations are being filled into their single private extent.
    Receiving {
        /// Exact metadata and contiguous progress for this unfinished offer.
        content: Content,
        /// Original reservation deadline, never extended by incoming chunks.
        deadline: Deadline,
    },
    /// Every byte arrived and flush completed before the transfer deadline.
    Published(
        /// Complete metadata whose private extent is available for repeated reads.
        Content,
    ),
}

/// One shared clipboard with exactly one private storage extent.
/// A replacement invalidates and releases the old offer before allocating new bytes.
/// Only the authenticated owner may advance its pending transfer, and publication
/// requires complete contiguous data and a successful storage flush before deadline.
pub struct Clipboard<S = Spool<NoDisk>> {
    /// Exclusive storage shared by pending and published state, never both.
    storage: S,
    /// Object-bound, revocable authority independent of descriptive identity.
    admissions: Admissions,
    /// Maximum combined length of the representations in an offer.
    capacity: usize,
    /// Latest issued identity; preserved even when a replacement fails.
    generation: Generation,
    /// Exclusive lifecycle stage; callers cannot mutate related fields independently.
    state: State,
    /// Last monotonic observation; regressions invalidate unfinished transfers.
    last_time: Time,
}

impl Clipboard {
    /// Create a diskless clipboard, retaining at most `RAM_LIMIT` payload bytes.
    pub fn new(capacity: usize) -> (Self, Provisioner) {
        Self::with_storage(capacity, Spool::new(NoDisk, RAM_LIMIT))
    }
}

impl<S: Storage> Clipboard<S> {
    /// Create a clipboard with explicit policy capacity and private storage.
    pub fn with_storage(capacity: usize, storage: S) -> (Self, Provisioner) {
        let (admissions, provisioner) = Admissions::new();
        (
            Self {
                admissions,
                storage,
                capacity,
                generation: Generation::from_wire(0),
                state: State::Empty,
                last_time: Time::observe(0),
            },
            provisioner,
        )
    }

    /// Inspect storage metadata without granting mutation of private bytes.
    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// Invalidate unfinished bytes on every terminal transfer path.
    fn abort(&mut self) {
        self.state = State::Empty;
        self.storage.clear();
    }

    /// Admit GUI-authenticated identity metadata using this clipboard's sole provisioner.
    /// A fresh incarnation is mandatory; metadata from a request cannot authorize access.
    pub fn admit(
        &mut self,
        provisioner: &Provisioner,
        identity: Participant,
    ) -> Result<Caller, Error> {
        self.admissions
            .admit(provisioner, identity)
            .ok_or(Error::Unauthorized)
    }

    /// Revalidate object ownership and live membership at each policy operation.
    fn access(&self, caller: &Caller) -> Result<(), Error> {
        if !self.admissions.allows(caller) {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    /// Forget an expired unfinished write; published content never expires.
    pub fn tick(&mut self, now: Time) {
        let expired = match &self.state {
            State::Reserved { deadline, .. } | State::Receiving { deadline, .. } => {
                now.before(self.last_time) || deadline.expired_at(now)
            }
            State::Empty | State::Published(_) => false,
        };
        if expired {
            self.abort();
        }
        self.last_time = now;
    }

    /// Begin replacing the clipboard, invalidating every older offer immediately.
    /// An empty format list clears shared availability, including when a source
    /// copies local files that must remain usable only inside its own VM.
    pub fn begin(
        &mut self,
        now: Time,
        caller: &Caller,
        formats: Vec<Format>,
    ) -> Result<Generation, Error> {
        self.access(caller)?;
        self.tick(now);
        validate_formats(&formats, self.capacity)?;
        let generation = self.reserve(now, caller)?;
        self.declare(now, caller, generation, formats)?;
        Ok(generation)
    }

    /// Reserve replacement order as soon as the local clipboard owner changes.
    /// Slow format conversion cannot later replace a newer copy from another VM.
    pub fn reserve(&mut self, now: Time, caller: &Caller) -> Result<Generation, Error> {
        self.access(caller)?;
        self.tick(now);
        let generation = self.generation.next().ok_or(Error::Bounds)?;
        let deadline = now.deadline_after(WRITE_TIMEOUT).ok_or(Error::Bounds)?;
        self.generation = generation;
        self.abort();
        self.state = State::Reserved {
            generation,
            source: caller.identity(),
            deadline,
        };
        Ok(generation)
    }

    /// Describe representations for an already reserved replacement.
    /// Empty offers clear shared availability while leaving source-local file offers alone.
    pub fn declare(
        &mut self,
        now: Time,
        caller: &Caller,
        generation: Generation,
        formats: Vec<Format>,
    ) -> Result<(), Error> {
        self.access(caller)?;
        self.tick(now);
        let layout = CheckedOffer::new(formats, self.capacity)?;
        let deadline = match &self.state {
            State::Reserved {
                generation: reserved,
                source,
                deadline,
            } if *reserved == generation && *source == caller.identity() => *deadline,
            _ => return Err(Error::Stale),
        };
        self.abort();
        let (formats, total) = layout.into_parts();
        if formats.is_empty() {
            return Ok(());
        }
        let mut representations = Vec::new();
        representations
            .try_reserve_exact(formats.len())
            .map_err(|_| Error::Capacity)?;
        self.storage.allocate(total)?;
        let mut offset = 0;
        for format in formats {
            let next = offset + format.size; // Aggregate overflow was checked before allocation.
            representations.push(Representation {
                format,
                offset,
                written: 0,
            });
            offset = next;
        }
        self.state = State::Receiving {
            content: Content {
                generation,
                source: caller.identity(),
                formats: representations,
            },
            deadline,
        };
        Ok(())
    }

    /// Append one contiguous chunk to an unfinished representation.
    pub fn write(
        &mut self,
        now: Time,
        caller: &Caller,
        generation: Generation,
        format: usize,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), Error> {
        self.access(caller)?;
        self.tick(now);
        let content = match &mut self.state {
            State::Receiving { content, .. } => content,
            _ => return Err(Error::Stale),
        };
        if content.generation != generation || content.source != caller.identity() {
            return Err(Error::Stale);
        }
        let representation = content.formats.get_mut(format).ok_or(Error::Bounds)?;
        let end = offset.checked_add(bytes.len()).ok_or(Error::Bounds)?;
        if offset != representation.written || end > representation.format.size || bytes.is_empty()
        {
            self.abort();
            return Err(Error::Order);
        }
        if let Err(error) = self.storage.write(representation.offset + offset, bytes) {
            self.abort();
            return Err(error);
        }
        representation.written = end;
        Ok(())
    }

    /// Publish all representations together after every promised byte arrived.
    pub fn complete(
        &mut self,
        now: Time,
        caller: &Caller,
        generation: Generation,
    ) -> Result<(), Error> {
        self.complete_with_clock(now, caller, generation, || now)
    }

    /// Flush complete bytes and recheck the injected monotonic clock before publication.
    /// Blocking storage must not publish a transfer whose deadline passed during I/O.
    pub fn complete_with_clock(
        &mut self,
        now: Time,
        caller: &Caller,
        generation: Generation,
        finished_at: impl FnOnce() -> Time,
    ) -> Result<(), Error> {
        self.access(caller)?;
        self.tick(now);
        let content = match &self.state {
            State::Receiving { content, .. } => content,
            State::Reserved {
                generation: reserved,
                source,
                ..
            } if *reserved == generation && *source == caller.identity() => {
                self.abort();
                return Err(Error::Order);
            }
            _ => return Err(Error::Stale),
        };
        if content.generation != generation || content.source != caller.identity() {
            return Err(Error::Stale);
        }
        if content.formats.is_empty() || content.formats.iter().any(|r| r.written != r.format.size)
        {
            self.abort();
            return Err(Error::Order);
        }
        if let Err(error) = self.storage.flush() {
            self.abort();
            return Err(error);
        }
        self.tick(finished_at());
        let state = core::mem::replace(&mut self.state, State::Empty);
        match state {
            State::Receiving { content, .. } => self.state = State::Published(content),
            _ => return Err(Error::Timeout),
        }
        Ok(())
    }

    /// Return the latest issued generation and any completely published offer.
    /// The generation also changes on clear, allowing endpoints to discard stale data.
    pub fn offer(&self, caller: &Caller) -> Result<(Generation, Option<Offer>), Error> {
        self.access(caller)?;
        let offer = if let State::Published(content) = &self.state {
            let mut formats = Vec::new();
            formats
                .try_reserve_exact(content.formats.len())
                .map_err(|_| Error::Capacity)?;
            for representation in &content.formats {
                let mut name = String::new();
                name.try_reserve_exact(representation.format.name.len())
                    .map_err(|_| Error::Capacity)?;
                name.push_str(&representation.format.name);
                formats.push(Format {
                    name,
                    size: representation.format.size,
                });
            }
            Some(Offer {
                generation: content.generation,
                source: content.source,
                formats,
            })
        } else {
            None
        };
        Ok((self.generation, offer))
    }

    /// Read a bounded range from exactly the requested generation, without consuming it.
    pub fn read(
        &mut self,
        caller: &Caller,
        generation: Generation,
        format: usize,
        offset: usize,
        maximum: usize,
    ) -> Result<Vec<u8>, Error> {
        self.access(caller)?;
        let content = match &self.state {
            State::Published(content) if content.generation == generation => content,
            _ => return Err(Error::Stale),
        };
        let representation = content.formats.get(format).ok_or(Error::Bounds)?;
        if offset > representation.format.size || maximum == 0 {
            return Err(Error::Bounds);
        }
        let count = maximum.min(CHUNK).min(representation.format.size - offset);
        let start = representation.offset + offset;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(count)
            .map_err(|_| Error::Capacity)?;
        bytes.resize(count, 0);
        if let Err(error) = self.storage.read(start, &mut bytes) {
            self.state = State::Empty;
            self.storage.clear();
            // Exhaustion cannot wrap a stale generation back into validity.
            self.generation = self.generation.invalidated();
            return Err(error);
        }
        Ok(bytes)
    }

    /// Revoke this live connection and abort its unfinished write; completed copies remain readable.
    pub fn disconnect(&mut self, caller: &Caller) {
        if self.access(caller).is_err() {
            return;
        }
        self.admissions.revoke(caller);
        let owns_pending = match &self.state {
            State::Reserved { source, .. } => *source == caller.identity(),
            State::Receiving { content, .. } => content.source == caller.identity(),
            _ => false,
        };
        if owns_pending {
            self.abort();
        }
    }
}

#[cfg(test)]
mod tests;
