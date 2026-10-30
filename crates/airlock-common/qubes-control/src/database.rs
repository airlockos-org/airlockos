//! Private bounded replica of the native QubesDB stream. The initial terminator
//! is the only full-database synchronization barrier. Later writes/removals are
//! applied in stream order; their paths become local watch hints, not requests
//! to send the local-only QDB_CMD_WATCH operation across libvchan.

use alloc::vec::Vec;
use vstd::prelude::*;

use crate::address::Ip;
use crate::bytes::{copy, equal, prefix};
use crate::policy::Path;
use crate::wire::{self, Message};

verus! {

/// All database keys count, including unrelated and currently unconsumed keys.
pub const MAX_ENTRIES: usize = 4096;

/// Aggregate retained key/value bytes, independently of native per-value limits.
pub const MAX_BYTES: usize = 524_288;

/// Root marker, required default and at most 256 ordered rule records.
pub const MAX_SOURCE_ENTRIES: usize = 258;

/// One source's encoded keys/values may retain at most 32 KiB. Oversize sources
/// are explicitly blocked, with their data discarded to protect other clients.
pub const MAX_SOURCE_BYTES: usize = 32_768;

/// At most four clients in both families may retain over-quota rejection state.
pub const MAX_REJECTIONS: usize = 8;

/// One owned native key/value observation, not authenticated interface authority.
pub struct Entry {
    /// Exact nonempty native key preceding its NUL terminator.
    key: Vec<u8>,
    /// Exact complete non-NUL body retained after native frame validation.
    value: Vec<u8>,
}

impl Entry {
    /// Exact private key used for replacement, deletion and local watch matching.
    pub closed spec fn key(&self) -> Seq<u8> { self.key@ }

    /// Exact native value, with no trimming, decoding or silent truncation.
    pub closed spec fn value(&self) -> Seq<u8> { self.value@ }

    /// Allocation payload charged by this record, excluding bounded Vec metadata.
    pub closed spec fn weight(&self) -> int { self.key@.len() + self.value@.len() }

    /// Every entry fits the native path/value grammar supplied by the decoder.
    pub closed spec fn valid(&self) -> bool {
        0 < self.key@.len() < 64 && self.value@.len() <= wire::MAX_VALUE
    }

    /// Borrow exact private key bytes without exposing mutable representation.
    pub fn name(&self) -> (key: &[u8])
        ensures key@ == self.key(),
    { self.key.as_slice() }

    /// Borrow the current complete private value; this is an observation only.
    pub fn bytes(&self) -> (value: &[u8])
        ensures value@ == self.value(),
    { self.value.as_slice() }
}

/// Logical byte accounting independently sums each retained record.
pub open spec fn weight(entries: Seq<Entry>, count: int) -> int
    decreases count,
{
    if count <= 0 { 0 } else { weight(entries, count-1) + entries[count-1].weight() }
}

/// Replacing one entry changes only that record's exact byte charge.
proof fn replaced_weight(entries: Seq<Entry>, index: int, entry: Entry, count: int)
    requires 0 <= index < entries.len(), 0 <= count <= entries.len(),
    ensures weight(entries.update(index, entry), count) == weight(entries, count)
        + if index < count { entry.weight() - entries[index].weight() } else { 0 },
    decreases count,
{
    if count > 0 { replaced_weight(entries, index, entry, count-1); }
}

/// Removing a record returns exactly its charge while preserving other bytes.
proof fn removed_weight(entries: Seq<Entry>, index: int)
    requires 0 <= index < entries.len(),
    ensures weight(entries.remove(index), entries.len() as int-1)
        == weight(entries, entries.len() as int) - entries[index].weight(),
    decreases entries.len(),
{
    if index < entries.len()-1 {
        removed_weight(entries.drop_last(), index);
        assert(entries.remove(index).drop_last() =~= entries.drop_last().remove(index));
        assert(entries.remove(index).last() == entries.last());
    } else {
        assert(entries.remove(index) =~= entries.drop_last());
    }
}

/// Exact native removal semantics: only a trailing slash selects a subtree.
pub open spec fn erased(existing: Seq<u8>, key: Seq<u8>) -> bool {
    if key.len() > 0 && key.last() == b'/' {
        existing.len() >= key.len() && existing.subrange(0, key.len() as int) == key
    } else { existing == key }
}

/// A native root or child belongs to this normalized source, including aliases.
pub open spec fn belongs(key: Seq<u8>, source: Ip) -> bool {
    exists|end: int| crate::policy::source_path(key, source, end)
}

/// Exact normalized-source record count, independently of enumeration order.
pub open spec fn source_count(entries: Seq<Entry>, source: Ip, count: int) -> int
    decreases count,
{
    if count <= 0 { 0 } else { source_count(entries, source, count-1)
        + if belongs(entries[count-1].key(), source) { 1 } else { 0 } }
}

/// Exact normalized-source payload charge, including native key bytes.
pub open spec fn source_bytes(entries: Seq<Entry>, source: Ip, count: int) -> int
    decreases count,
{
    if count <= 0 { 0 } else { source_bytes(entries, source, count-1)
        + if belongs(entries[count-1].key(), source) { entries[count-1].weight() } else { 0 } }
}

/// Exact bounded key/value ownership. Replacement/deletion never leave a charge
/// detached from retained storage; unsuccessful admission preserves all entries.
pub struct Cache {
    /// Current complete native observations; no public mutable slice escapes.
    entries: Vec<Entry>,
    /// Exact payload charge, maintained before accepting another native mutation.
    used: usize,
    /// At most eight over-quota normalized sources; all their records are
    /// discarded until a real subtree removal begins a fresh replacement.
    suppressed: Vec<Ip>,
}

impl Cache {
    /// Exact retained observations, independent of their internal ordering.
    pub closed spec fn entries(&self) -> Seq<Entry> { self.entries@ }

    /// Current live payload charge, rather than a monotonic lifetime allocation count.
    pub closed spec fn used(&self) -> usize { self.used }

    /// Bounded storage, unique native keys and truthful byte accounting.
    pub closed spec fn valid(&self) -> bool {
        self.entries@.len() <= MAX_ENTRIES && self.used <= MAX_BYTES
            && self.suppressed@.len() <= MAX_REJECTIONS
            && (forall|i: int| 0 <= i < self.suppressed@.len() ==> self.suppressed@[i].valid())
            && (forall|i: int, j: int| 0 <= i < j < self.suppressed@.len() ==> self.suppressed@[i] != self.suppressed@[j])
            && (forall|i: int, j: int| 0 <= i < self.entries@.len() && 0 <= j < self.suppressed@.len()
                ==> !belongs(self.entries@[i].key(), self.suppressed@[j]))
            && self.used == weight(self.entries@, self.entries@.len() as int)
            && (forall|i: int| 0 <= i < self.entries@.len() ==> self.entries@[i].valid())
            && (forall|i: int, j: int| 0 <= i < j < self.entries@.len()
                ==> self.entries@[i].key() != self.entries@[j].key())
    }

    /// Start a wholly empty private replica before receiving a synchronization dump.
    pub fn empty() -> (cache: Self)
        ensures cache.valid() && cache.used() == 0 && cache.entries().len() == 0,
    { Self { entries: Vec::new(), used: 0, suppressed: Vec::new() } }

    /// Resolve one exact native key. Prefix matching is used only for an explicit
    /// trailing-slash deletion and never for an ordinary lookup or replacement.
    fn index(&self, key: &[u8]) -> (index: Option<usize>)
        requires self.valid(), key@.len() < 64,
        ensures match index {
            Some(value) => value < self.entries().len() && self.entries()[value as int].key() == key@,
            None => forall|i: int| 0 <= i < self.entries().len() ==> self.entries()[i].key() != key@,
        },
    {
        let mut i = 0;
        while i < self.entries.len()
            invariant self.valid(), i <= self.entries@.len(), key@.len() < 64,
                forall|j: int| 0 <= j < i ==> self.entries@[j].key() != key@,
            decreases self.entries.len()-i,
        {
            if equal(self.entries[i].name(), key) { return Some(i); }
            i += 1;
        }
        None
    }

    /// Atomically replace/insert a complete record after both count and byte
    /// admission. Failed admission retains the previous exact cache and charge.
    pub fn put(&mut self, key: Vec<u8>, value: Vec<u8>, replacing: bool) -> (accepted: bool)
        requires old(self).valid(), 0 < key@.len() < 64, value@.len() <= wire::MAX_VALUE,
        ensures final(self).valid(),
            !accepted ==> final(self).entries() == old(self).entries() && final(self).used() == old(self).used(),
            accepted ==> (exists|i: int| 0 <= i < final(self).entries().len()
                && final(self).entries()[i].key() == key@ && final(self).entries()[i].value() == value@)
                || final(self).suppressed_key(key@),
            forall|i: int| 0 <= i < old(self).entries().len() && old(self).entries()[i].key() != key@
                && !final(self).suppressed_key(old(self).entries()[i].key())
                ==> final(self).entries().contains(old(self).entries()[i]),
    {
        let old = self.index(key.as_slice());
        if old.is_some() && !replacing { return false; }
        let previous = match old { Some(index) => self.entries[index].key.len()+self.entries[index].value.len(), None => 0 };
        let cost = key.len()+value.len();
        if let Some(source) = Path::parse(key.as_slice()) {
            if self.source_suppressed(source.ip()) { return true; }
            let (count, charge) = self.source_charge(source.ip());
            if count+if old.is_some() { 0 } else { 1 } > MAX_SOURCE_ENTRIES || charge-previous+cost > MAX_SOURCE_BYTES {
                return self.suppress(source.ip());
            }
        }
        if cost > MAX_BYTES - (self.used-previous) { return false; }
        if old.is_none() && self.entries.len() >= MAX_ENTRIES { return false; }
        let entry = Entry { key, value };
        let ghost before = self.entries@;
        let ghost after = entry;
        match old {
            Some(index) => {
                proof { replaced_weight(before, index as int, after, before.len() as int); }
                self.entries.set(index, entry);
            }
            None => { self.entries.push(entry); }
        }
        self.used = self.used-previous+cost;
        true
    }

    /// Determine whether a native successful removal may refer to staged data
    /// intentionally discarded for a rejected source. Whole database/firewall
    /// subtree deletion also covers those records; it must not desynchronize
    /// the replica merely because this bounded consumer already reclaimed them.
    pub fn discarded_remove(&self, key: &[u8]) -> (discarded: bool)
        requires self.valid(), 0 < key@.len() < 64,
        ensures discarded == (self.suppressed@.len() > 0
            && (key@ == b"/"@ || key@ == b"/qubes-firewall/"@ || self.suppressed_key(key@))),
    {
        if self.suppressed.is_empty() { return false; }
        if equal(key, b"/") || equal(key, b"/qubes-firewall/") { return true; }
        match Path::parse(key) { Some(path) => self.source_suppressed(path.ip()), None => false }
    }

    /// Remove exactly a key or all descendants of an explicit trailing-slash
    /// prefix. A zero result is an observation; the native replica treats it
    /// as desynchronization because upstream mirrors only successful removals.
    /// The entire operation is finite and leaves unrelated entries unchanged.
    pub fn remove(&mut self, key: &[u8]) -> (removed: usize)
        requires old(self).valid(), 0 < key@.len() < 64,
        ensures final(self).valid(), removed <= old(self).entries().len(),
            final(self).entries().len()+removed == old(self).entries().len(),
            forall|i: int| 0 <= i < old(self).entries().len() ==>
                final(self).entries().contains(old(self).entries()[i]) == !erased(old(self).entries()[i].key(), key@),
            forall|i: int| 0 <= i < final(self).entries().len() ==> old(self).entries().contains(final(self).entries()[i]),
    {
        if equal(key, b"/") || equal(key, b"/qubes-firewall/") {
            self.suppressed.clear();
        }
        if let Some(path) = Path::parse(key)
            && key.len() == path.boundary()+1 && key[key.len()-1] == b'/' {
                let mut i = 0;
                while i < self.suppressed.len()
                    invariant self.valid(), i <= self.suppressed.len() <= MAX_REJECTIONS,
                    decreases self.suppressed.len()-i,
                {
                    if self.suppressed[i].same(path.ip()) { self.suppressed.remove(i); break; }
                    i += 1;
                }
            }
        let tree = key[key.len()-1] == b'/';
        let mut i = self.entries.len();
        let mut removed = 0;
        while i > 0
            invariant self.valid(), i <= self.entries.len(),
                removed + self.entries.len() == old(self).entries().len(),
                0 < key@.len() < 64,
            decreases i,
        {
            i -= 1;
            let matches = if tree { prefix(self.entries[i].name(), key) } else { equal(self.entries[i].name(), key) };
            if matches {
                let cost = self.entries[i].key.len()+self.entries[i].value.len();
                proof { removed_weight(self.entries@, i as int); }
                self.entries.remove(i);
                self.used -= cost;
                removed += 1;
            }
        }
        removed
    }

    /// Logical over-quota rejection for one normalized source.
    pub closed spec fn is_suppressed(&self, source: Ip) -> bool { self.suppressed@.contains(source) }

    /// A native key belongs to a source whose full staged data was discarded.
    pub closed spec fn suppressed_key(&self, key: Seq<u8>) -> bool {
        exists|i: int| 0 <= i < self.suppressed@.len() && belongs(key, self.suppressed@[i])
    }

    /// Observe the exact bounded per-source rejection, separate from absence.
    pub fn source_suppressed(&self, source: &Ip) -> (suppressed: bool)
        requires self.valid(), source.valid(),
        ensures suppressed == self.is_suppressed(*source),
    {
        let mut i = 0;
        while i < self.suppressed.len()
            invariant self.valid(), source.valid(), i <= self.suppressed.len() <= MAX_REJECTIONS,
                forall|j: int| 0 <= j < i ==> self.suppressed@[j] != *source,
            decreases self.suppressed.len()-i,
        {
            if self.suppressed[i].same(source) { return true; }
            i += 1;
        }
        false
    }

    /// Exact retained count/byte charge of one normalized source's roots/children.
    fn source_charge(&self, source: &Ip) -> (charge: (usize, usize))
        requires self.valid(), source.valid(),
        ensures charge.0 <= self.entries().len(), charge.1 <= self.used(),
            charge.0 == source_count(self.entries(), *source, self.entries().len() as int),
            charge.1 == source_bytes(self.entries(), *source, self.entries().len() as int),
    {
        let mut count = 0;
        let mut charge = 0;
        let mut i = 0;
        while i < self.entries.len()
            invariant self.valid(), source.valid(), i <= self.entries.len() <= MAX_ENTRIES,
                count == source_count(self.entries@, *source, i as int),
                charge == source_bytes(self.entries@, *source, i as int),
                charge <= self.used,
            decreases self.entries.len()-i,
        {
            if let Some(path) = Path::parse(self.entries[i].name())
                && path.ip().same(source) {
                    count += 1;
                    charge += self.entries[i].key.len()+self.entries[i].value.len();
                }
            i += 1;
        }
        (count, charge)
    }

    /// Reject the whole over-quota source and return its retained record charge.
    /// Unrelated entries are preserved exactly; no silently truncated prefix can
    /// become an installable policy. Failed tombstone admission changes nothing.
    fn suppress(&mut self, source: &Ip) -> (accepted: bool)
        requires old(self).valid(), source.valid(), !old(self).is_suppressed(*source),
        ensures final(self).valid(),
            accepted ==> final(self).is_suppressed(*source),
            !accepted ==> final(self).entries() == old(self).entries() && final(self).used() == old(self).used(),
            forall|i: int| 0 <= i < old(self).entries().len() && !belongs(old(self).entries()[i].key(), *source)
                ==> final(self).entries().contains(old(self).entries()[i]),
    {
        if self.suppressed.len() == MAX_REJECTIONS { return false; }
        let mut i = self.entries.len();
        while i > 0
            invariant self.valid(), source.valid(), i <= self.entries.len(),
                self.suppressed@.len() < MAX_REJECTIONS,
                forall|j: int| i <= j < self.entries@.len() ==> !belongs(self.entries@[j].key(), *source),
            decreases i,
        {
            i -= 1;
            if let Some(path) = Path::parse(self.entries[i].name())
                && path.ip().same(source) {
                    let cost = self.entries[i].key.len()+self.entries[i].value.len();
                    proof { removed_weight(self.entries@, i as int); }
                    self.entries.remove(i);
                    self.used -= cost;
                }
        }
        self.suppressed.push(*source);
        true
    }

    /// Borrow one complete value without permitting a caller to mutate storage.
    pub fn read(&self, key: &[u8]) -> (value: Option<&[u8]>)
        requires self.valid(), key@.len() < 64,
        ensures match value {
            Some(bytes) => bytes@.len() <= wire::MAX_VALUE && (exists|i: int| 0 <= i < self.entries().len()
                && self.entries()[i].key() == key@ && self.entries()[i].value() == bytes@),
            None => forall|i: int| 0 <= i < self.entries().len() ==> self.entries()[i].key() != key@,
        },
    {
        match self.index(key) { Some(index) => Some(self.entries[index].bytes()), None => None }
    }

    /// Inspect immutable observations while building a complete configuration
    /// projection. These records alone do not authenticate a network interface.
    pub fn all(&self) -> (entries: &[Entry])
        requires self.valid(),
        ensures entries@ == self.entries(), entries@.len() <= MAX_ENTRIES,
            forall|i: int| 0 <= i < entries@.len() ==> entries@[i].valid(),
    { self.entries.as_slice() }
}

/// Ordered control-stream state. A lost/invalid stream cannot be revived by an
/// entry or completion marker; a new transport requires a new replica owner.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Whole database dump is private until its exact native terminator arrives.
    Synchronizing,
    /// Complete initial snapshot; replicated live mutations may now be consumed.
    Ready,
    /// Terminal loss, malformed sequence or resource exhaustion.
    Failed,
}

/// One local observation after applying the exact native operation. The caller
/// sends acknowledgements before consuming another frame, bounding output state.
pub enum Update {
    /// Initial snapshot became readable at the native completion barrier.
    Initial,
    /// Exact key or subtree changed; policy publication still needs its own
    /// per-source marker, which is distinct from a transport acknowledgement.
    Changed {
        /// Original exact native path, not an untrusted packet's source address.
        key: Vec<u8>,
        /// True only for a native deletion, including explicit subtree removal.
        removed: bool,
        /// Native positive response to this same write/delete record.
        acknowledgement: [u8; wire::HEADER],
    },
    /// Initial entry or harmless acknowledgement produced no application event.
    None,
    /// The one guest boot-notice/handled-counter WRITE received its matching ACK.
    Barrier,
}

/// Exactly one guest-originated boot notice or handled-counter write may await
/// its native positive response. Neither transports policy. Replica owns the
/// pending bytes until a matching reply or terminal loss.
enum Barrier {
    /// No guest write is awaiting acknowledgement.
    Idle,
    /// One request was selected; publication completion is owned by Control.
    Pending {
        /// Exact internally constructed notice/handled path echoed by the ACK.
        path: Vec<u8>,
        /// Exact bounded notice/counter text committed locally only after the ACK.
        value: Vec<u8>,
    },
}

/// Bounded private replica with explicit initial-sync and terminal-loss gates.
/// This object stores observations; the runtime separately authenticates dom0
/// transport ownership before any configuration projection grants authority.
pub struct Replica {
    /// Exact observed native entries, independent of projection/publication state.
    cache: Cache,
    /// Governs whether any complete initial configuration is visible.
    phase: Phase,
    /// One exclusive native write/ACK barrier; no automatic replay after loss.
    barrier: Barrier,
}

impl Replica {
    /// Cache and phase remain internally consistent on every transition.
    pub closed spec fn valid(&self) -> bool {
        self.cache.valid() && match &self.barrier {
            Barrier::Idle => true,
            Barrier::Pending { path, value } => 0 < path@.len() < 64 && 0 < value@.len() <= 36
                && (self.phase == Phase::Ready || self.phase == Phase::Failed),
        }
    }

    /// Current initial-sync/loss observation.
    pub closed spec fn phase(&self) -> Phase { self.phase }

    /// Observe native synchronization/loss state without exposing mutation.
    pub fn state(&self) -> (phase: Phase)
        requires self.valid(), ensures phase == self.phase(),
    { self.phase }

    /// Exact native observed cache, including staged live policy entries.
    pub closed spec fn cache(&self) -> Cache { self.cache }

    /// Begin only at the start of a freshly connected native stream.
    pub fn synchronizing() -> (replica: Self)
        ensures replica.valid() && replica.phase() == Phase::Synchronizing
            && replica.cache().entries().len() == 0,
    { Self { cache: Cache::empty(), phase: Phase::Synchronizing, barrier: Barrier::Idle } }

    /// Terminal control loss blocks all observation consumers. Old bytes remain
    /// available only to diagnostics through internal state, never new admissions.
    pub fn disconnect(&mut self)
        requires old(self).valid(),
        ensures final(self).valid() && final(self).phase() == Phase::Failed
            && final(self).cache() == old(self).cache() && !final(self).pending(),
    { self.phase = Phase::Failed; self.barrier = Barrier::Idle; }

    /// Observe whether a guest write is awaiting its one native ACK.
    pub closed spec fn pending(&self) -> bool { self.barrier is Pending }

    /// Register the internally selected notice/handled write before publication.
    /// Only a fresh idle live replica may own another such request.
    pub(crate) fn barrier(&mut self, path: Vec<u8>, value: Vec<u8>) -> (accepted: bool)
        requires old(self).valid(), 0 < path@.len() < 64, 0 < value@.len() <= 36,
        ensures final(self).valid(), accepted ==> final(self).pending(),
            accepted == (old(self).phase() == Phase::Ready && !old(self).pending()),
    {
        if self.phase != Phase::Ready || !matches!(self.barrier, Barrier::Idle) { return false; }
        self.barrier = Barrier::Pending { path, value };
        true
    }

    /// Consume one already-complete record in native order. Duplicate initial
    /// keys, a second terminator, an early live mutation or a capacity failure
    /// terminates the stream instead of exposing a partial synchronization.
    pub fn apply(&mut self, message: Message) -> (update: Result<Update, wire::Failure>)
        requires old(self).valid(), message.valid(),
        ensures final(self).valid(),
            update.is_err() ==> final(self).phase() == Phase::Failed,
            old(self).phase() == Phase::Failed ==> update.is_err(),
            matches!(update, Ok(Update::Initial)) ==> old(self).phase() == Phase::Synchronizing
                && final(self).phase() == Phase::Ready,
            matches!(update, Ok(Update::Changed { .. })) ==> old(self).phase() == Phase::Ready
                && final(self).phase() == Phase::Ready,
    {
        if self.phase == Phase::Failed { return Err(wire::Failure::Replication); }
        let (header, value) = message.into_parts();
        let operation = header.operation();
        let key = header.key();
        if operation == wire::ENTRY && self.phase == Phase::Synchronizing {
            if key.is_empty() {
                self.phase = Phase::Ready;
                return Ok(Update::Initial);
            }
            if !self.cache.put(copy(key), value, false) { self.phase = Phase::Failed; return Err(wire::Failure::Replication); }
            return Ok(Update::None);
        }
        if self.phase == Phase::Ready && (operation == wire::WRITE || operation == wire::REMOVE) {
            let acknowledgement = header.acknowledge();
            let key = copy(key);
            let removed = operation == wire::REMOVE;
            if removed {
                let discarded = self.cache.discarded_remove(key.as_slice());
                if self.cache.remove(key.as_slice()) == 0 && !discarded { self.phase = Phase::Failed; return Err(wire::Failure::Replication); }
            }
            else if !self.cache.put(copy(key.as_slice()), value, true) { self.phase = Phase::Failed; return Err(wire::Failure::Replication); }
            return Ok(Update::Changed { key, removed, acknowledgement });
        }
        if self.phase == Phase::Ready && operation == wire::OK {
            let barrier = core::mem::replace(&mut self.barrier, Barrier::Idle);
            match barrier {
                Barrier::Pending { path, value } if equal(key, path.as_slice()) => {
                    if !self.cache.put(path, value, true) { self.phase = Phase::Failed; return Err(wire::Failure::Replication); }
                    return Ok(Update::Barrier);
                }
                _ => { self.phase = Phase::Failed; return Err(wire::Failure::Replication); }
            }
        }
        self.phase = Phase::Failed;
        Err(wire::Failure::Replication)
    }

    /// Expose only a complete live replica. This is never a firewall policy
    /// snapshot: per-source completion and semantic validation are still required.
    pub fn current(&self) -> (cache: Option<&Cache>)
        requires self.valid(),
        ensures match cache {
            Some(value) => self.phase() == Phase::Ready && *value == self.cache() && value.valid(),
            None => self.phase() != Phase::Ready,
        },
    {
        if self.phase == Phase::Ready { Some(&self.cache) } else { None }
    }
}

}
