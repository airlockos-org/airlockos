//! Network consumer's retained QubesDB values. Whole-cache and per-source quotas
//! belong here because interpreting firewall paths requires network semantics.
//! Over-quota sources retain bounded rejection state while unrelated clients
//! keep their complete records. Native framing and sequencing live in qubesdb.

use alloc::vec::Vec;
use vstd::prelude::*;

use crate::address::Ip;
use crate::policy::Path;
#[cfg(verus_keep_ghost)]
use crate::wire;

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
            if self.entries[i].name() == key { return Some(i); }
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
        if key == b"/" || key == b"/qubes-firewall/" { return true; }
        match Path::parse(key) { Some(path) => self.source_suppressed(path.ip()), None => false }
    }

    /// Remove exactly a key or all descendants of an explicit trailing-slash
    /// prefix. A zero result is an observation; the network control owner treats it
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
        if key == b"/" || key == b"/qubes-firewall/" {
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
            let matches = if tree { self.entries[i].name().starts_with(key) } else { self.entries[i].name() == key };
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

}
