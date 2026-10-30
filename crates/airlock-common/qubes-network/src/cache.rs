//! Network consumer's retained QubesDB values. BTreeMap owns unique-key storage;
//! this layer owns payload accounting, source quotas and bounded rejection state.
//! A rejected source is discarded as a whole while unrelated records survive.

use alloc::collections::{BTreeMap, btree_map};
use alloc::vec::Vec;
use vstd::prelude::*;

use crate::address::Ip;
use crate::policy::Path;
use airlock_qubesdb::wire::MAX_VALUE;

verus! {

/// All retained keys count, including unrelated configuration records.
pub const MAX_ENTRIES: usize = 4096;

/// Aggregate retained key/value payload, excluding container metadata.
pub const MAX_BYTES: usize = 524_288;

/// Root, required default and at most 256 native rule records per source.
pub const MAX_SOURCE_ENTRIES: usize = 258;

/// Maximum retained native key/value payload for one normalized source.
pub const MAX_SOURCE_BYTES: usize = 32_768;

/// Four clients in both families may retain over-quota rejection state.
pub const MAX_REJECTIONS: usize = 8;

/// Logical record used only in contracts; production stores each key once.
#[cfg(verus_keep_ghost)]
pub struct Entry {
    /// Exact native key preceding its NUL terminator.
    key: Seq<u8>,
    /// Complete native body bytes.
    value: Seq<u8>,
}

#[cfg(verus_keep_ghost)]
impl Entry {
    /// Exact key, independent of map iteration order.
    pub closed spec fn key(&self) -> Seq<u8> { self.key }

    /// Exact retained body.
    pub closed spec fn value(&self) -> Seq<u8> { self.value }

    /// Payload charged once for this key/value record.
    pub closed spec fn weight(&self) -> int { self.key.len()+self.value.len() }

    /// Native key/value bounds.
    pub closed spec fn valid(&self) -> bool { 0 < self.key.len() < 64 && self.value.len() <= MAX_VALUE }
}

/// Independent sum of retained native payload charges.
pub open spec fn weight(entries: Seq<Entry>, count: int) -> int
    decreases count,
{
    if count <= 0 { 0 } else { weight(entries, count-1)+entries[count-1].weight() }
}

/// Native removal semantics: only a trailing slash selects a subtree.
pub open spec fn erased(existing: Seq<u8>, key: Seq<u8>) -> bool {
    if key.len() > 0 && key.last() == b'/' {
        existing.len() >= key.len() && existing.subrange(0, key.len() as int) == key
    } else { existing == key }
}

/// A root or child belongs to this normalized source, including address aliases.
pub open spec fn belongs(key: Seq<u8>, source: Ip) -> bool {
    exists|end: int| crate::policy::source_path(key, source, end)
}

/// Exact normalized-source record count.
pub open spec fn source_count(entries: Seq<Entry>, source: Ip, count: int) -> int
    decreases count,
{
    if count <= 0 { 0 } else { source_count(entries, source, count-1)
        + if belongs(entries[count-1].key(), source) { 1 } else { 0 } }
}

/// Exact normalized-source payload charge.
pub open spec fn source_bytes(entries: Seq<Entry>, source: Ip, count: int) -> int
    decreases count,
{
    if count <= 0 { 0 } else { source_bytes(entries, source, count-1)
        + if belongs(entries[count-1].key(), source) { entries[count-1].weight() } else { 0 } }
}

/// Unique-key storage with explicit global and per-source admission limits.
pub struct Cache {
    /// One owned key and body per record; standard map operations manage storage.
    records: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Exact current key/value payload charge.
    used: usize,
    /// Rejected normalized sources until an authoritative subtree removal.
    suppressed: Vec<Ip>,
}

impl Cache {
    /// All retained records as a logical sequence; consumers never rely on order.
    pub closed spec fn entries(&self) -> Seq<Entry> {
        let records = self.records.deep_view();
        let keys = records.dom().to_seq();
        Seq::new(keys.len(), |i: int| Entry { key: keys[i], value: records[keys[i]] })
    }

    /// Current payload charge, including keys and values exactly once.
    pub closed spec fn used(&self) -> usize { self.used }

    /// Bounded storage, truthful accounting and no retained rejected-source data.
    pub closed spec fn valid(&self) -> bool {
        self.entries().len() <= MAX_ENTRIES && self.used <= MAX_BYTES
            && self.used == weight(self.entries(), self.entries().len() as int)
            && self.suppressed@.len() <= MAX_REJECTIONS
            && (forall|i: int| 0 <= i < self.suppressed@.len() ==> self.suppressed@[i].valid())
            && (forall|i: int, j: int| 0 <= i < j < self.suppressed@.len() ==> self.suppressed@[i] != self.suppressed@[j])
            && (forall|i: int| 0 <= i < self.entries().len() ==> self.entries()[i].valid())
            && (forall|i: int, j: int| 0 <= i < j < self.entries().len() ==> self.entries()[i].key() != self.entries()[j].key())
            && (forall|i: int, j: int| 0 <= i < self.entries().len() && 0 <= j < self.suppressed@.len()
                ==> !belongs(self.entries()[i].key(), self.suppressed@[j]))
    }

    /// Start without retained records or quota rejections.
    pub fn empty() -> (cache: Self)
        ensures cache.valid(), cache.used() == 0, cache.entries().len() == 0,
    { Self { records: BTreeMap::new(), used: 0, suppressed: Vec::new() } }

    /// Admit a whole record before inserting/replacing it. Failed admission
    /// preserves prior storage and accounting. Over-quota sources are discarded
    /// together and blocked; their records are never partially installed.
    pub fn put(&mut self, key: Vec<u8>, value: Vec<u8>, replacing: bool) -> (accepted: bool)
        requires old(self).valid(), 0 < key@.len() < 64, value@.len() <= MAX_VALUE,
        ensures final(self).valid(),
            !accepted ==> final(self).entries() == old(self).entries() && final(self).used() == old(self).used(),
            accepted ==> (exists|i: int| 0 <= i < final(self).entries().len()
                && final(self).entries()[i].key() == key@ && final(self).entries()[i].value() == value@)
                || final(self).suppressed_key(key@),
            forall|i: int| 0 <= i < old(self).entries().len() && old(self).entries()[i].key() != key@
                && !final(self).suppressed_key(old(self).entries()[i].key())
                ==> final(self).entries().contains(old(self).entries()[i]),
    {
        if key.is_empty() || key.len() >= 64 || value.len() > MAX_VALUE { return false; }

        let old = self.records.get(key.as_slice());
        if old.is_some() && !replacing { return false; }
        let previous = old.map_or(0, |value| key.len()+value.len());
        let cost = key.len()+value.len();

        if let Some(source) = Path::parse(key.as_slice()) {
            if self.source_suppressed(source.ip()) { return true; }
            let (count, charge) = self.source_charge(source.ip());
            if count+if old.is_some() { 0 } else { 1 } > MAX_SOURCE_ENTRIES || charge-previous+cost > MAX_SOURCE_BYTES {
                return self.suppress(source.ip());
            }
        }

        if cost > MAX_BYTES-(self.used-previous) || old.is_none() && self.records.len() == MAX_ENTRIES { return false; }

        let _ = self.records.insert(key, value);
        self.used = self.used-previous+cost;
        true
    }

    /// Whether a successful native removal may name intentionally discarded data.
    pub fn discarded_remove(&self, key: &[u8]) -> (discarded: bool)
        requires self.valid(), 0 < key@.len() < 64,
        ensures discarded == (self.suppressed@.len() > 0
            && (key@ == b"/"@ || key@ == b"/qubes-firewall/"@ || self.suppressed_key(key@))),
    {
        if self.suppressed.is_empty() { return false; }
        if key == b"/" || key == b"/qubes-firewall/" { return true; }
        match Path::parse(key) { Some(path) => self.source_suppressed(path.ip()), None => false }
    }

    /// Remove exactly one key or an explicit trailing-slash subtree, returning
    /// the removed count and payload charge. Unrelated records remain unchanged.
    pub fn remove(&mut self, key: &[u8]) -> (removed: usize)
        requires old(self).valid(), 0 < key@.len() < 64,
        ensures final(self).valid(), removed <= old(self).entries().len(),
            final(self).entries().len()+removed == old(self).entries().len(),
            forall|i: int| 0 <= i < old(self).entries().len() ==>
                final(self).entries().contains(old(self).entries()[i]) == !erased(old(self).entries()[i].key(), key@),
            forall|i: int| 0 <= i < final(self).entries().len() ==> old(self).entries().contains(final(self).entries()[i]),
    {
        if key == b"/" || key == b"/qubes-firewall/" { self.suppressed.clear(); }
        if let Some(path) = Path::parse(key)
            && key.len() == path.boundary()+1 && key[key.len()-1] == b'/' {
            self.suppressed.retain(|source| !source.same(path.ip()));
        }

        if !key.ends_with(b"/") {
            return match self.records.remove_entry(key) {
                Some((name, value)) => { self.used -= name.len()+value.len(); 1 }
                None => 0,
            };
        }

        let before = self.records.len();
        let mut reclaimed = 0;
        self.records.retain(|name, value| {
            if name.starts_with(key) { reclaimed += name.len()+value.len(); false } else { true }
        });
        self.used -= reclaimed;
        before-self.records.len()
    }

    /// Logical over-quota rejection for one normalized source.
    pub closed spec fn is_suppressed(&self, source: Ip) -> bool { self.suppressed@.contains(source) }

    /// A native key belongs to a source whose entire staged data was discarded.
    pub closed spec fn suppressed_key(&self, key: Seq<u8>) -> bool {
        exists|i: int| 0 <= i < self.suppressed@.len() && belongs(key, self.suppressed@[i])
    }

    /// Observe source rejection separately from a missing key.
    pub fn source_suppressed(&self, source: &Ip) -> (suppressed: bool)
        requires self.valid(), source.valid(),
        ensures suppressed == self.is_suppressed(*source),
    { self.suppressed.iter().any(|candidate| candidate.same(source)) }

    /// Count and charge every record of one normalized source, including aliases.
    fn source_charge(&self, source: &Ip) -> (charge: (usize, usize))
        requires self.valid(), source.valid(),
        ensures charge.0 == source_count(self.entries(), *source, self.entries().len() as int),
            charge.1 == source_bytes(self.entries(), *source, self.entries().len() as int),
            charge.0 <= self.entries().len(), charge.1 <= self.used(),
    {
        let mut count = 0;
        let mut charge = 0;

        for (key, value) in &self.records {
            if let Some(path) = Path::parse(key.as_slice())
                && path.ip().same(source) { count += 1; charge += key.len()+value.len(); }
        }

        (count, charge)
    }

    /// Reject the whole source after admitting its bounded tombstone. Standard
    /// map retention removes its records; accounting follows the exact removals.
    fn suppress(&mut self, source: &Ip) -> (accepted: bool)
        requires old(self).valid(), source.valid(), !old(self).is_suppressed(*source),
        ensures final(self).valid(), accepted ==> final(self).is_suppressed(*source),
            !accepted ==> final(self).entries() == old(self).entries() && final(self).used() == old(self).used(),
            forall|i: int| 0 <= i < old(self).entries().len() && !belongs(old(self).entries()[i].key(), *source)
                ==> final(self).entries().contains(old(self).entries()[i]),
    {
        if self.suppressed.len() == MAX_REJECTIONS { return false; }

        let mut reclaimed = 0;
        self.records.retain(|key, value| {
            let remove = Path::parse(key.as_slice()).is_some_and(|path| path.ip().same(source));
            if remove { reclaimed += key.len()+value.len(); }
            !remove
        });
        self.used -= reclaimed;
        self.suppressed.push(*source);
        true
    }

    /// Borrow one exact complete value through the map's borrowed-key lookup.
    pub fn read(&self, key: &[u8]) -> (value: Option<&[u8]>)
        requires self.valid(), key@.len() < 64,
        ensures match value {
            Some(bytes) => bytes@.len() <= MAX_VALUE && (exists|i: int| 0 <= i < self.entries().len()
                && self.entries()[i].key() == key@ && self.entries()[i].value() == bytes@),
            None => forall|i: int| 0 <= i < self.entries().len() ==> self.entries()[i].key() != key@,
        },
    { self.records.get(key).map(Vec::as_slice) }

    /// Iterate borrowed keys and bodies without allocating another collection.
    /// Map order is storage detail; policy rules retain their native numeric order.
    pub fn all(&self) -> (entries: btree_map::Iter<'_, Vec<u8>, Vec<u8>>)
        requires self.valid(),
        ensures vstd::std_specs::btree::into_iter(entries).len() == self.entries().len(),
            forall|key: Vec<u8>, value: Vec<u8>|
                vstd::std_specs::btree::into_iter(entries).contains((key, value))
                    == (exists|i: int| 0 <= i < self.entries().len()
                        && self.entries()[i].key() == key@ && self.entries()[i].value() == value@),
    { self.records.iter() }
}

}
