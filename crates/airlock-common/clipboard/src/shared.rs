//! A shared desktop clipboard with atomic, multi-format replacement.
//!
//! The transport authenticates participants before calling this module. Content
//! has no expiry and reads never consume it. Only incomplete writes expire.
//! Access decisions are centralized here so future policies need not change
//! desktop format transfer or trust identities supplied by a requesting VM.

use alloc::{string::String, vec::Vec};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::std_specs::iter::IteratorSpec;

pub mod storage;

use storage::{CHUNK, NoDisk, RAM_LIMIT, Spool, Storage};

use crate::authority::Admissions;
pub use crate::authority::{Caller, Participant, Provisioner};
use crate::values::Deadline;
pub use crate::values::{Generation, Time};

use crate::formats::CheckedOffer;
pub use crate::formats::{
    Error, Format, MAX_FORMAT_NAME, MAX_FORMATS, is_data_format, is_file_format, validate_formats,
};

verus! {

/// Maximum total payload retained in the default clipboard service.
pub const DEFAULT_CAPACITY: usize = 64 * 1024 * 1024;

/// Deadline for completing an in-flight replacement, in monotonic nanoseconds.
pub const WRITE_TIMEOUT: u64 = 120_000_000_000;

/// Public identity of a complete clipboard offer.
#[derive(Debug, PartialEq, Eq)]
pub struct Offer {
    /// Monotonically increasing replacement identity within this service boot.
    pub generation: Generation,
    /// Authenticated source of the content, retained independently of its connection.
    pub source: Participant,
    /// Available representations in their original preference order.
    pub formats: Vec<Format>,
}

impl Clone for Offer {
    fn clone(&self) -> (out: Self)
        ensures out.generation == self.generation, out.source == self.source,
            out.formats@.len() == self.formats@.len(),
            forall|i: int| 0 <= i < self.formats@.len() ==> out.formats[i].name@ == self.formats[i].name@
                && out.formats[i].size == self.formats[i].size,
    {
        let mut formats: Vec<Format> = Vec::new();
        let mut i = 0;
        while i < self.formats.len()
            invariant i <= self.formats.len(), formats@.len() == i,
                forall|j: int| 0 <= j < i ==> formats[j].name@ == self.formats[j].name@
                    && formats[j].size == self.formats[j].size,
            decreases self.formats.len() - i,
        {
            formats.push(self.formats[i].clone());
            i += 1;
        }
        Self { generation: self.generation, source: self.source, formats }
    }
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

spec fn content_valid(content: &Content, generation: Generation, length: nat, capacity: usize, published: bool) -> bool {
        content.generation == generation && 0 < content.formats@.len() <= MAX_FORMATS
            && content.formats[0].offset == 0
            && content.formats@.last().offset + content.formats@.last().format.size == length
            && length <= capacity
            && (forall|i: int| 0 <= i < content.formats@.len() ==>
                (#[trigger] content.formats[i]).offset + content.formats[i].format.size <= length
                && (i > 0 ==> content.formats[i].offset == content.formats[i - 1].offset + content.formats[i - 1].format.size)
                && content.formats[i].written <= content.formats[i].format.size
                && (published ==> content.formats[i].written == content.formats[i].format.size))
    }

/// Decide completion over bounded metadata without changing bytes or ownership.
fn all_complete(formats: &[Representation]) -> (complete: bool)
    ensures complete == (forall|i: int| 0 <= i < formats@.len() ==> formats[i].written == formats[i].format.size),
{
    let mut checked = 0;
    while checked < formats.len()
        invariant checked <= formats.len(),
            forall|i: int| 0 <= i < checked ==> formats[i].written == formats[i].format.size,
        decreases formats.len() - checked,
    {
        if formats[checked].written != formats[checked].format.size { return false; }
        checked += 1;
    }
    true
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
    pub fn new(capacity: usize) -> (out: (Self, Provisioner))
        ensures out.0.valid(),
    {
        Self::with_storage(capacity, Spool::new(NoDisk, RAM_LIMIT))
    }
}

impl<S: Storage> Clipboard<S> {
    /// Current replacement identity, including cleared and unfinished reservations.
    pub closed spec fn current(&self) -> Generation { self.generation }

    /// Exact live object-bound authorization, independent of request metadata.
    pub closed spec fn authorized(&self, caller: &Caller) -> bool { self.admissions.permits(caller) }

    /// Observation most recently processed by the lifecycle.
    pub closed spec fn clock(&self) -> Time { self.last_time }

    /// Immutable configuration and membership are unchanged by clipboard operations.
    pub closed spec fn stable_owner(&self, previous: &Self) -> bool {
        self.capacity == previous.capacity && self.admissions == previous.admissions
    }

    /// Ticking time never expires or rewrites already published normal-mode content.
    pub closed spec fn retained_publication(&self, previous: &Self) -> bool {
        match &previous.state {
            State::Published(_) => self.state == previous.state && self.storage.view() == previous.storage.view(),
            _ => true,
        }
    }

    /// Time processing either preserves the exact lifecycle or discards its pending state.
    pub closed spec fn time_transition(&self, previous: &Self) -> bool {
        let expired = match &previous.state {
            State::Reserved { deadline, .. } | State::Receiving { deadline, .. } =>
                self.last_time.observation() < previous.last_time.observation()
                    || self.last_time.observation() >= deadline.end(),
            _ => false,
        };
        if expired { self.state is Empty && self.storage.view().len() == 0 }
        else { self.state == previous.state && self.storage.view() == previous.storage.view() }
    }

    /// Rejected authority cannot mutate membership, ordering, time, lifecycle or bytes.
    pub closed spec fn unchanged(&self, previous: &Self) -> bool {
        self.stable_owner(previous) && self.generation == previous.generation
            && self.last_time == previous.last_time && self.state == previous.state
            && self.storage.view() == previous.storage.view()
    }

    /// Reservation binds a newly issued generation and deadline to the exact admitted source.
    pub closed spec fn reserved_for(&self, caller: &Caller, generation: Generation, now: Time) -> bool {
        self.generation == generation && self.storage.view().len() == 0 && match &self.state {
            State::Reserved { generation: issued, source, deadline } => *issued == generation
                && *source == caller.subject() && deadline.end() == now.observation() + WRITE_TIMEOUT,
            _ => false,
        }
    }

    /// Successful publication retains the flushed extent, exact owner and complete metadata.
    pub closed spec fn committed(&self, previous: &Self, caller: &Caller, generation: Generation) -> bool {
        self.authorized(caller) && self.storage.view() == previous.storage.view()
            && match (&previous.state, &self.state) {
                (State::Receiving { content: before, deadline }, State::Published(after)) =>
                    *before == *after && after.generation == generation && after.source == caller.subject()
                    && self.last_time.observation() < deadline.end()
                    && self.last_time.observation() >= previous.last_time.observation(),
                _ => false,
            }
    }

    /// A successful write changes exactly the owner's next contiguous range and progress.
    pub closed spec fn written_from(&self, previous: &Self, caller: &Caller, generation: Generation,
        format: usize, offset: usize, bytes: Seq<u8>) -> bool {
        match (&previous.state, &self.state) {
            (State::Receiving { content: before, deadline: old_deadline }, State::Receiving { content: after, deadline }) =>
                before.generation == generation && before.source == caller.subject()
                && after.generation == generation && after.source == caller.subject() && deadline == old_deadline
                && format < before.formats@.len() && before.formats[format as int].written == offset
                && bytes.len() > 0 && offset + bytes.len() <= before.formats[format as int].format.size
                && self.storage.view() == storage::replaced(previous.storage.view(), before.formats[format as int].offset + offset, bytes)
                && before.formats@.len() == after.formats@.len()
                && (forall|i: int| 0 <= i < before.formats@.len() ==> after.formats[i].format == before.formats[i].format
                    && after.formats[i].offset == before.formats[i].offset
                    && after.formats[i].written == if i == format { offset + bytes.len() } else { before.formats[i].written as int }),
            _ => false,
        }
    }

    /// A read returns only the requested published generation's exact bounded byte window.
    pub closed spec fn read_window(&self, generation: Generation, format: usize, offset: usize,
        maximum: usize, bytes: Seq<u8>) -> bool {
        match &self.state {
            State::Published(content) => content.generation == generation && format < content.formats@.len()
                && offset <= content.formats[format as int].format.size && maximum > 0
                && bytes.len() == vstd::math::min(vstd::math::min(maximum as int, CHUNK as int), content.formats[format as int].format.size - offset)
                && bytes == self.storage.view().subrange(content.formats[format as int].offset + offset,
                    content.formats[format as int].offset + offset + bytes.len()),
            _ => false,
        }
    }

    /// Encapsulated metadata bounds, authority and private storage ownership.
    pub closed spec fn valid(&self) -> bool {
        self.admissions.valid() && self.storage.valid() && match &self.state {
            State::Empty => self.storage.view().len() == 0,
            State::Reserved { generation, .. } => self.storage.view().len() == 0 && *generation == self.generation,
            State::Receiving { content, .. } => content_valid(content, self.generation, self.storage.view().len(), self.capacity, false),
            State::Published(content) => content_valid(content, self.generation, self.storage.view().len(), self.capacity, true),
        }
    }

    /// Create a clipboard with explicit policy capacity and private storage.
    pub fn with_storage(capacity: usize, mut storage: S) -> (out: (Self, Provisioner))
        requires storage.valid(),
        ensures out.0.valid(),
    {
        storage.clear();
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
    fn abort(&mut self)
        requires old(self).storage.valid(), old(self).admissions.valid(),
        ensures final(self).valid(), final(self).state is Empty,
            final(self).stable_owner(old(self)), final(self).current() == old(self).current(),
            final(self).clock() == old(self).clock(),
    {
        self.state = State::Empty;
        self.storage.clear();
    }

    /// Admit GUI-authenticated identity metadata using this clipboard's sole provisioner.
    /// A fresh incarnation is mandatory; metadata from a request cannot authorize access.
    pub fn admit(
        &mut self,
        provisioner: &Provisioner,
        identity: Participant,
    ) -> Result<Caller, Error>
        requires old(self).valid(),
        ensures final(self).valid(),
    {
        let out = self.admissions.admit(provisioner, identity).ok_or(Error::Unauthorized);
        assert(self.admissions.valid());
        assert(self.storage.valid());
        proof {
            match &self.state {
                State::Receiving { content, .. } => { assert(content_valid(content, self.generation, self.storage.view().len(), self.capacity, false)); },
                State::Published(content) => { assert(content_valid(content, self.generation, self.storage.view().len(), self.capacity, true)); },
                _ => {},
            }
        }
        assert(self.valid());
        out
    }

    /// Revalidate object ownership and live membership at each policy operation.
    fn access(&self, caller: &Caller) -> (out: Result<(), Error>)
        ensures out.is_ok() == self.authorized(caller), out.is_err() ==> out == Err(Error::Unauthorized),
    {
        if !self.admissions.allows(caller) {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    /// Forget an expired unfinished write; published content never expires.
    pub fn tick(&mut self, now: Time)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).stable_owner(old(self)), final(self).current() == old(self).current(), final(self).clock() == now, final(self).retained_publication(old(self)),
            final(self).time_transition(old(self)),
    {
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
        proof { reveal(Clipboard::valid); }
        assert(self.valid());
    }

    /// Begin replacing the clipboard, invalidating every older offer immediately.
    /// An empty format list clears shared availability, including when a source
    /// copies local files that must remain usable only inside its own VM.
    pub fn begin(
        &mut self,
        now: Time,
        caller: &Caller,
        formats: Vec<Format>,
    ) -> (out: Result<Generation, Error>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).stable_owner(old(self)),
            !old(self).authorized(caller) ==> out == Err(Error::Unauthorized) && final(self).unchanged(old(self)),
    {
        self.access(caller)?;
        self.tick(now);
        validate_formats(&formats, self.capacity)?;
        let generation = self.reserve(now, caller)?;
        self.declare(now, caller, generation, formats)?;
        Ok(generation)
    }

    /// Reserve replacement order as soon as the local clipboard owner changes.
    /// Slow format conversion cannot later replace a newer copy from another VM.
    pub fn reserve(&mut self, now: Time, caller: &Caller) -> (out: Result<Generation, Error>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).stable_owner(old(self)),
            !old(self).authorized(caller) ==> out == Err(Error::Unauthorized) && final(self).unchanged(old(self)),
            out.is_ok() ==> final(self).reserved_for(caller, out.unwrap(), now)
                && out.unwrap().number() > old(self).current().number(),
    {
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
    ) -> (out: Result<(), Error>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).stable_owner(old(self)),
            !old(self).authorized(caller) ==> out == Err(Error::Unauthorized) && final(self).unchanged(old(self)),
    {
        self.access(caller)?;
        self.tick(now);
        let layout = CheckedOffer::new(formats, self.capacity)?;
        assert(self.valid());
        let deadline = match &self.state {
            State::Reserved {
                generation: reserved,
                source,
                deadline,
            } => {
                assert(*reserved == self.generation);
                if *reserved != generation || *source != caller.identity() { return Err(Error::Stale); }
                assert(*reserved == generation);
                *deadline
            },
            _ => return Err(Error::Stale),
        };
        assert(self.generation == generation);
        self.abort();
        let (formats, total) = layout.into_parts();
        if formats.is_empty() {
            return Ok(());
        }
        let mut representations: Vec<Representation> = Vec::new();
        representations
            .try_reserve_exact(formats.len())
            .map_err(|_| Error::Capacity)?;
        self.storage.allocate(total)?;
        let mut offset = 0;
        let count = formats.len();
        let ghost metadata = formats@;
        let mut remaining = formats.into_iter();
        let mut index = 0;
        while index < count
            invariant self.admissions == old(self).admissions, self.capacity == old(self).capacity,
                self.storage.valid(), self.admissions.valid(), self.storage.view().len() == total,
                generation == self.generation, total <= self.capacity,
                metadata.len() <= MAX_FORMATS, crate::formats::payload_bytes(metadata) == total,
                0 < count, count == metadata.len(), index <= metadata.len(), remaining.remaining() == metadata.skip(index as int),
                offset == crate::formats::payload_bytes(metadata.take(index as int)), offset <= total,
                representations@.len() == index,
                index > 0 ==> representations[0].offset == 0
                    && representations[index - 1].offset + representations[index - 1].format.size == offset,
                forall|i: int| 0 <= i < index ==> (#[trigger] representations[i]).format == metadata[i]
                    && representations[i].written == 0
                    && representations[i].offset + representations[i].format.size <= total
                    && (i > 0 ==> representations[i].offset == representations[i - 1].offset + representations[i - 1].format.size),
            decreases metadata.len() - index,
        {
            let format = remaining.next().unwrap();
            proof {
                crate::formats::prefix_bound(metadata, index as int + 1);
                assert(metadata.take(index as int + 1).drop_last() == metadata.take(index as int));
            }
            let next = offset + format.size;
            assert(next <= total);
            let ghost previous = representations@;
            let ghost position = index;
            representations.push(Representation {
                format,
                offset,
                written: 0,
            });
            assert(representations[index as int].format == metadata[index as int]);
            offset = next;
            index += 1;
            assert forall|i: int| 0 <= i < index implies (#[trigger] representations[i]).format == metadata[i]
                && representations[i].written == 0
                && representations[i].offset + representations[i].format.size <= total
                && (i > 0 ==> representations[i].offset == representations[i - 1].offset + representations[i - 1].format.size) by {
                if i < position {
                    assert(representations[i] == previous[i]);
                    assert(previous[i].format == metadata[i]);
                    assert(previous[i].written == 0);
                    assert(previous[i].offset + previous[i].format.size <= total);
                    if i > 0 { assert(previous[i].offset == previous[i - 1].offset + previous[i - 1].format.size); }
                }
                else {
                    assert(representations[i].offset == (next - representations[i].format.size));
                    if i > 0 { assert(representations[i - 1] == previous[i - 1]); }
                }
            }
        }
        assert(metadata.take(index as int) == metadata);
        assert(offset == total);
        assert(representations@.len() > 0);
        assert(representations[0].offset == 0);
        assert(representations@.last().offset + representations@.last().format.size == total);
        assert forall|i: int| 0 <= i < representations@.len() implies (#[trigger] representations[i]).offset + representations[i].format.size <= total
            && (i > 0 ==> representations[i].offset == representations[i - 1].offset + representations[i - 1].format.size)
            && representations[i].written <= representations[i].format.size by {}
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
    ) -> (out: Result<(), Error>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).stable_owner(old(self)),
            !old(self).authorized(caller) ==> out == Err(Error::Unauthorized) && final(self).unchanged(old(self)),
            out.is_ok() ==> final(self).written_from(old(self), caller, generation, format, offset, bytes@),
    {
        self.access(caller)?;
        self.tick(now);
        let content = match &self.state {
            State::Receiving { content, .. } => content,
            _ => return Err(Error::Stale),
        };
        if content.generation != generation || content.source != caller.identity() {
            return Err(Error::Stale);
        }
        assert(content_valid(content, self.generation, self.storage.view().len(), self.capacity, matches!(self.state, State::Published(_))));
        if format >= content.formats.len() { return Err(Error::Bounds); }
        let representation = &content.formats[format];
        assert(content.formats[format as int].offset + content.formats[format as int].format.size <= self.storage.view().len());
        assert(representation.offset + representation.format.size <= self.storage.view().len());
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
        if let State::Receiving { content, .. } = &mut self.state {
            let ghost previous = content.formats@;
            content.formats[format].written = end;
            assert forall|i: int| 0 <= i < content.formats@.len() implies
                content.formats[i].format == previous[i].format && content.formats[i].offset == previous[i].offset
                && content.formats[i].written <= content.formats[i].format.size by {}
        }
        assert(self.valid());
        Ok(())
    }

    /// Publish all representations together after every promised byte arrived.
    pub fn complete(
        &mut self,
        now: Time,
        caller: &Caller,
        generation: Generation,
    ) -> (out: Result<(), Error>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).stable_owner(old(self)),
            !old(self).authorized(caller) ==> out == Err(Error::Unauthorized) && final(self).unchanged(old(self)),
            out.is_ok() ==> final(self).committed(old(self), caller, generation),
    {
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
    ) -> (out: Result<(), Error>)
        requires old(self).valid(), finished_at.requires(()),
        ensures final(self).valid(), final(self).stable_owner(old(self)),
            !old(self).authorized(caller) ==> out == Err(Error::Unauthorized) && final(self).unchanged(old(self)),
            out.is_ok() ==> final(self).committed(old(self), caller, generation),
    {
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
        if !all_complete(&content.formats) {
            self.abort();
            return Err(Error::Order);
        }
        assert(content_valid(content, self.generation, self.storage.view().len(), self.capacity, true));
        assert(self.valid());
        if let Err(error) = self.storage.flush() {
            self.abort();
            return Err(error);
        }
        assert(self.valid());
        let ghost ready = self.state;
        self.tick(finished_at());
        let state = core::mem::replace(&mut self.state, State::Empty);
        match state {
            State::Receiving { content, .. } => self.state = State::Published(content),
            _ => {
                self.abort();
                return Err(Error::Timeout);
            }
        }
        Ok(())
    }

    /// Return the latest issued generation and any completely published offer.
    /// The generation also changes on clear, allowing endpoints to discard stale data.
    pub fn offer(&self, caller: &Caller) -> Result<(Generation, Option<Offer>), Error>
        requires self.valid(),
        ensures self.valid(),
    {
        self.access(caller)?;
        let offer = if let State::Published(content) = &self.state {
            let mut formats = Vec::new();
            formats
                .try_reserve_exact(content.formats.len())
                .map_err(|_| Error::Capacity)?;
            for representation in &content.formats
                invariant self.valid(),
            {
                let mut name = String::new();
                name.try_reserve_exact(representation.format.name.as_str().len())
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
    ) -> (out: Result<Vec<u8>, Error>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).stable_owner(old(self)),
            !old(self).authorized(caller) ==> out == Err(Error::Unauthorized) && final(self).unchanged(old(self)),
            out.is_ok() ==> old(self).read_window(generation, format, offset, maximum, out.unwrap()@)
                && final(self).unchanged(old(self)),
    {
        self.access(caller)?;
        let content = match &self.state {
            State::Published(content) if content.generation == generation => content,
            _ => return Err(Error::Stale),
        };
        assert(content_valid(content, self.generation, self.storage.view().len(), self.capacity, matches!(self.state, State::Published(_))));
        if format >= content.formats.len() { return Err(Error::Bounds); }
        let representation = &content.formats[format];
        if offset > representation.format.size || maximum == 0 {
            return Err(Error::Bounds);
        }
        let count = maximum.min(CHUNK).min(representation.format.size - offset);
        assert(content.formats[format as int].offset + content.formats[format as int].format.size <= self.storage.view().len());
        assert(representation.offset + representation.format.size <= self.storage.view().len());
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
    pub fn disconnect(&mut self, caller: &Caller)
        requires old(self).valid(),
        ensures final(self).valid(), !final(self).authorized(caller),
    {
        if self.access(caller).is_err() {
            return;
        }
        self.admissions.revoke(caller);
        assert(self.valid());
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

}

#[cfg(test)]
mod tests;
