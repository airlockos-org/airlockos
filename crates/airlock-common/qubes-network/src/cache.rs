//! Network consumer's retained QubesDB values. BTreeMap owns unique-key storage;
//! this layer owns payload accounting, source quotas and bounded rejection state.
//! A rejected source is discarded as a whole while unrelated records survive.

use alloc::collections::btree_map;

#[cfg(verus_keep_ghost)]
pub(crate) mod accounting;
mod records;
#[cfg(verus_keep_ghost)]
use vstd::std_specs::iter::IteratorSpec;

use alloc::vec::Vec;
use records::Records;
use vstd::prelude::*;

use crate::address::Ip;
use crate::policy::Path;
use airlock_qubesdb::wire::MAX_VALUE;

verus! {

broadcast use { vstd::seq::group_seq_lemmas, vstd::seq_lib::group_seq_properties, vstd::seq::Seq::lemma_filter_contains_rev, vstd::seq::Seq::lemma_as_ref_index, crate::address::cut_unique };

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
    pub(super) key: Vec<u8>,
    /// Complete native body bytes.
    pub(super) value: Vec<u8>,
}

#[cfg(verus_keep_ghost)]
impl Entry {
    /// Exact key, independent of map iteration order.
    pub closed spec fn key(&self) -> Seq<u8> { self.key@ }

    /// Exact retained body.
    pub closed spec fn value(&self) -> Seq<u8> { self.value@ }

    /// Payload charged once for this key/value record.
    pub closed spec fn weight(&self) -> int { (self.key@.len()+self.value@.len()) as int }

    /// Native key/value bounds.
    pub closed spec fn valid(&self) -> bool { 0 < self.key@.len() < 64 && self.value@.len() <= MAX_VALUE }
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

/// Exact count of records satisfying a logical selection predicate.
pub open spec fn selected_count(entries: Seq<Entry>, selected: spec_fn(Entry) -> bool, count: int) -> int
    decreases count,
{
    if count <= 0 { 0 } else { selected_count(entries, selected, count-1)
        + if selected(entries[count-1]) { 1int } else { 0int } }
}

/// Exact payload charge of records satisfying a logical selection predicate.
pub open spec fn selected_bytes(entries: Seq<Entry>, selected: spec_fn(Entry) -> bool, count: int) -> int
    decreases count,
{
    if count <= 0 { 0 } else { selected_bytes(entries, selected, count-1)
        + if selected(entries[count-1]) { entries[count-1].weight() } else { 0 } }
}

/// Exact normalized-source record count.
pub open spec fn source_count(entries: Seq<Entry>, source: Ip, count: int) -> int {
    selected_count(entries, |entry: Entry| belongs(entry.key(), source), count)
}

/// Exact normalized-source payload charge.
pub open spec fn source_bytes(entries: Seq<Entry>, source: Ip, count: int) -> int {
    selected_bytes(entries, |entry: Entry| belongs(entry.key(), source), count)
}

/// Unique-key storage with explicit global and per-source admission limits.
pub struct Cache {
    /// One owned key and body per record; standard map operations manage storage.
    records: Records,
    /// Exact current key/value payload charge.
    used: usize,
    /// Rejected normalized sources until an authoritative subtree removal.
    suppressed: Vec<Ip>,
}

impl Cache {
    /// At least one source has intentionally discarded over-quota data.
    pub closed spec fn has_suppressed(&self) -> bool { self.suppressed@.len() > 0 }

    /// All retained records as a logical sequence; consumers never rely on order.
    pub closed spec fn entries(&self) -> Seq<Entry> {
        self.records.entries()
    }

    /// Current payload charge, including keys and values exactly once.
    pub closed spec fn used(&self) -> usize { self.used }

    /// Bounded storage, truthful accounting and no retained rejected-source data.
    pub closed spec fn valid(&self) -> bool {
        self.records.valid() && self.entries().len() <= MAX_ENTRIES && self.used <= MAX_BYTES
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
    { Self { records: Records::new(), used: 0, suppressed: Vec::new() } }

    /// Sufficient headroom to retain the exact bytes without source suppression.
    /// This deliberately reserves the whole new charge, even for a replacement;
    /// callers need not rely on reclaiming the previous record to make progress.
    pub closed spec fn can_retain(&self, key: Seq<u8>, value: Seq<u8>, replacing: bool) -> bool {
        0 < key.len() < 64 && value.len() <= MAX_VALUE
            && (replacing || forall|i: int| 0 <= i < self.entries().len() ==> self.entries()[i].key() != key)
            && self.entries().len() < MAX_ENTRIES && self.used+key.len()+value.len() <= MAX_BYTES
            && (forall|source: Ip, end: int| crate::policy::source_path(key, source, end) ==>
                !self.is_suppressed(source)
                    && source_count(self.entries(), source, self.entries().len() as int)+1 <= MAX_SOURCE_ENTRIES
                    && source_bytes(self.entries(), source, self.entries().len() as int)+key.len()+value.len() <= MAX_SOURCE_BYTES)
    }

    /// Admit a whole record before inserting/replacing it. Failed admission
    /// preserves prior storage and accounting. Over-quota sources are discarded
    /// together and blocked; their records are never partially installed.
    #[verifier::rlimit(60)]
    pub fn put(&mut self, key: Vec<u8>, value: Vec<u8>, replacing: bool) -> (accepted: bool)
        requires old(self).valid(), 0 < key@.len() < 64, value@.len() <= MAX_VALUE,
        ensures final(self).valid(),
            old(self).can_retain(key@, value@, replacing) ==> accepted && !final(self).suppressed_key(key@),
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
        let previous = match old { Some(value) => key.len()+value.len(), None => 0 };
        let cost = key.len()+value.len();
        proof {
            if let Some(bytes) = old {
                let index = choose|i: int| 0 <= i < self.entries().len()
                    && self.entries()[i].key() == key@ && self.entries()[i].value() == bytes@;
                accounting::global_entry_bound(self.entries(), index);
            }
        }

        if let Some(source) = Path::parse(key.as_slice()) {
            if self.source_suppressed(source.ip()) { return true; }
            let (count, charge) = self.source_charge(source.ip());
            proof {
                if let Some(bytes) = old {
                    let index = choose|i: int| 0 <= i < self.entries().len()
                        && self.entries()[i].key() == key@ && self.entries()[i].value() == bytes@;
                    assert(belongs(key@, source.source()));
                    accounting::entry_bound(self.entries(), source.source(), index);
                }
            }
            if count+if old.is_some() { 0 } else { 1 } > MAX_SOURCE_ENTRIES || charge-previous+cost > MAX_SOURCE_BYTES {
                return self.suppress(source.ip());
            }
        }

        if cost > MAX_BYTES-(self.used-previous) || old.is_none() && self.records.len() == MAX_ENTRIES { return false; }

        let ghost replacing_existing = old.is_some();
        let ghost before = self.entries();
        self.records.insert(key, value);
        proof {
            if replacing_existing {
                let index = choose|i: int| 0 <= i < before.len() && before[i].key() == key@
                    && self.entries() == before.update(i, Entry { key: before[i].key, value });
                accounting::replaced(before, Entry { key: before[index].key, value }, index);
                assert(self.entries()[index].key() == key@ && self.entries()[index].value() == value@);
                assert forall|i: int| 0 <= i < before.len() && before[i].key() != key@
                    implies self.entries().contains(before[i]) by {
                    assert(i != index);
                    assert(self.entries()[i] == before[i]);
                }
            } else {
                let index = choose|i: int| 0 <= i <= before.len()
                    && self.entries() == before.insert(i, Entry { key, value });
                accounting::inserted(before, Entry { key, value }, index);
                before.insert_ensures(index, Entry { key, value });
                assert(self.entries()[index].key() == key@ && self.entries()[index].value() == value@);
                assert forall|i: int| 0 <= i < before.len() implies self.entries().contains(before[i]) by {
                    if i < index { assert(self.entries()[i] == before[i]); }
                    else { assert(self.entries()[i+1] == before[i]); }
                }
            }
        }
        self.used = self.used-previous+cost;
        true
    }

    /// Whether a successful native removal may name intentionally discarded data.
    pub fn discarded_remove(&self, key: &[u8]) -> (discarded: bool)
        requires self.valid(), 0 < key@.len() < 64,
        ensures discarded == (self.has_suppressed()
            && (key@ == b"/"@ || key@ == b"/qubes-firewall/"@ || self.suppressed_key(key@))),
    {
        if self.suppressed.is_empty() { return false; }
        if *key == *b"/".as_slice() { proof { assert(key@ =~= b"/"@); } return true; }
        if *key == *b"/qubes-firewall/".as_slice() { proof { assert(key@ =~= b"/qubes-firewall/"@); } return true; }
        match Path::parse(key) { Some(path) => self.source_suppressed(path.ip()), None => false }
    }

    /// Remove exactly one key or an explicit trailing-slash subtree, returning
    /// the removed count and payload charge. Unrelated records remain unchanged.
    #[verifier::rlimit(20)]
    pub fn remove(&mut self, key: &[u8]) -> (removed: usize)
        requires old(self).valid(), 0 < key@.len() < 64,
        ensures final(self).valid(), removed <= old(self).entries().len(),
            final(self).entries().len()+removed == old(self).entries().len(),
            forall|i: int| 0 <= i < old(self).entries().len() ==>
                final(self).entries().contains(old(self).entries()[i]) == !erased(old(self).entries()[i].key(), key@),
            forall|i: int| 0 <= i < final(self).entries().len() ==> old(self).entries().contains(final(self).entries()[i]),
    {
        if *key == *b"/".as_slice() || *key == *b"/qubes-firewall/".as_slice() { self.suppressed.clear(); }
        match Path::parse(key) {
            Some(path) if key.len() == path.boundary()+1 && key[key.len()-1] == b'/' => {
                records::retain(&mut self.suppressed, |source: &Ip| -> (keep: bool)
                    requires source.valid(), ensures keep == (*source != path.source()),
                    { !source.same(path.ip()) });
            }
            _ => (),
        }

        if key[key.len()-1] != b'/' {
            let ghost before = self.entries();
            return match self.records.remove(key) {
                Some(value) => {
                    proof {
                        let index = choose|i: int| 0 <= i < before.len() && before[i].key() == key@
                            && before[i].value() == value@ && self.entries() == before.remove(i);
                        accounting::global_entry_bound(before, index);
                        accounting::removed(before, index);
                        before.remove_ensures(index);
                    }
                    self.used -= key.len()+value.len();
                    1
                }
                None => 0,
            };
        }

        proof { assert(key@[key@.len() as int-1] == b'/'); }
        let ghost before = self.entries();
        let mut reclaimed = 0;
        for (name, value) in cursor: self.records.iter()
            invariant self.valid(), self.entries() == before,
                0 < key@.len() < 64, key@.last() == b'/',
                cursor.seq().len() == before.len(),
                forall|j: int| 0 <= j < cursor.seq().len() ==>
                    *cursor.seq()[j].0 == before[j].key && *cursor.seq()[j].1 == before[j].value,
                reclaimed == selected_bytes(before, |entry: Entry| erased(entry.key(), key@), cursor.index()),
                reclaimed <= self.used(),
        {
            proof {
                accounting::selected_bounds(before, |entry: Entry| erased(entry.key(), key@), cursor.index()+1);
                accounting::monotone(before, cursor.index()+1, before.len() as int);
            }
            let selected = name.starts_with(key);
            proof {
                if selected { assert(name@.subrange(0, key@.len() as int) =~= key@); }
                assert(selected == erased(name@, key@));
            }
            if selected { reclaimed += name.len()+value.len(); }
        }
        let count = self.records.len();
        self.records.retain(|name: &Vec<u8>, _value: &Vec<u8>| -> (keep: bool)
            requires key@.len() > 0, key@.last() == b'/',
            ensures keep == !erased(name@, key@),
            {
                let selected = name.starts_with(key);
                proof { if selected { assert(name@.subrange(0, key@.len() as int) =~= key@); } }
                !selected
            });
        proof {
            accounting::retained(before, self.entries(), |entry: Entry| !erased(entry.key(), key@));
            let selected = |entry: Entry| erased(entry.key(), key@);
            accounting::filtered(before, selected);
            assert((|entry: Entry| !selected(entry)) =~= (|entry: Entry| !erased(entry.key(), key@)));
            before.filter_lemma(|entry: Entry| !erased(entry.key(), key@));
        }
        self.used -= reclaimed;
        count-self.records.len()
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
    { self.suppressed.iter().any(|candidate: &Ip| -> (same: bool)
        requires candidate.valid(), ensures same == (*candidate == *source),
        { candidate.same(source) }) }

    /// Count and charge every record of one normalized source, including aliases.
    fn source_charge(&self, source: &Ip) -> (charge: (usize, usize))
        requires self.valid(), source.valid(),
        ensures charge.0 == source_count(self.entries(), *source, self.entries().len() as int),
            charge.1 == source_bytes(self.entries(), *source, self.entries().len() as int),
            charge.0 <= self.entries().len(), charge.1 <= self.used(),
    {
        let mut count = 0;
        let mut charge = 0;

        for (key, value) in cursor: self.records.iter()
            invariant self.valid(), source.valid(),
                cursor.seq().len() == self.entries().len(),
                forall|j: int| 0 <= j < cursor.seq().len() ==>
                    *cursor.seq()[j].0 == self.entries()[j].key && *cursor.seq()[j].1 == self.entries()[j].value,
                count == source_count(self.entries(), *source, cursor.index()),
                charge == source_bytes(self.entries(), *source, cursor.index()),
                count <= self.entries().len(), charge <= self.used(),
        {
            let selected = match Path::parse(key.as_slice()) {
                Some(path) => path.ip().same(source),
                None => false,
            };
            proof {
                assert(selected == belongs(key@, *source));
                accounting::bounds(self.entries(), *source, cursor.index()+1);
                accounting::monotone(self.entries(), cursor.index()+1, self.entries().len() as int);
            }
            if selected { count += 1; charge += key.len()+value.len(); }
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

        let (_, reclaimed) = self.source_charge(source);
        let ghost before = self.entries();
        let ghost previous = *self;
        proof {
            assert(previous.valid());
            assert(previous.entries() == before);
            assert(previous.used == weight(before, before.len() as int));
            assert(reclaimed == source_bytes(before, *source, before.len() as int));
        }
        self.records.retain(|key: &Vec<u8>, _value: &Vec<u8>| -> (keep: bool)
            requires key@.len() < 64,
            ensures keep == !belongs(key@, *source),
        {
            match Path::parse(key.as_slice()) {
                Some(path) => !path.ip().same(source),
                None => true,
            }
        });
        proof {
            accounting::retained(before, self.entries(), |entry: Entry| !belongs(entry.key(), *source));
            let selected = |entry: Entry| belongs(entry.key(), *source);
            accounting::filtered(before, selected);
            assert((|entry: Entry| !selected(entry)) =~= (|entry: Entry| !belongs(entry.key(), *source)));
            before.filter_lemma(|entry: Entry| !belongs(entry.key(), *source));
            assert(self.entries() == before.filter(|entry: Entry| !belongs(entry.key(), *source)));
            assert(weight(self.entries(), self.entries().len() as int)+reclaimed == previous.used);
        }
        let ghost kept = self.entries();
        self.used -= reclaimed;
        let ghost last = self.suppressed@.len();
        self.suppressed.push(*source);
        proof {
            assert(self.entries() == kept);
            assert(self.suppressed@[last as int] == *source);
            assert(self.entries().len() <= MAX_ENTRIES);
            assert(self.used == weight(self.entries(), self.entries().len() as int));
            assert forall|i: int| 0 <= i < self.entries().len() implies self.entries()[i].valid() by {
                assert(before.contains(self.entries()[i]));
                let old_index = choose|j: int| 0 <= j < before.len() && before[j] == self.entries()[i];
            }
            assert forall|i: int, j: int| 0 <= i < self.entries().len() && 0 <= j < self.suppressed@.len()
                implies !belongs(self.entries()[i].key(), self.suppressed@[j]) by {
                assert(before.contains(self.entries()[i]));
                let old_index = choose|k: int| 0 <= k < before.len() && before[k] == self.entries()[i];
                if j < last { assert(self.suppressed@[j] == previous.suppressed@[j]); }
            }
        }
        true
    }

    /// Borrow one exact complete value through the map's borrowed-key lookup.
    pub fn read(&self, key: &[u8]) -> (value: Option<&[u8]>)
        requires self.valid(), key@.len() < 64,
        ensures match value {
            Some(bytes) => bytes@.len() <= MAX_VALUE && (exists|i: int| 0 <= i < self.entries().len()
                && self.entries()[i].key() == key@ && self.entries()[i].value() == bytes@)
                && (forall|i: int| 0 <= i < self.entries().len() && self.entries()[i].key() == key@
                    ==> self.entries()[i].value() == bytes@),
            None => forall|i: int| 0 <= i < self.entries().len() ==> self.entries()[i].key() != key@,
        },
    { self.records.get(key) }

    /// Iterate borrowed keys and bodies without allocating another collection.
    /// Map order is storage detail; policy rules retain their native numeric order.
    pub fn all(&self) -> (entries: btree_map::Iter<'_, Vec<u8>, Vec<u8>>)
        requires self.valid(),
        ensures IteratorSpec::remaining(&entries).len() == self.entries().len() <= MAX_ENTRIES,
            forall|i: int, j: int| 0 <= i < j < self.entries().len() ==> self.entries()[i].key() != self.entries()[j].key(),
            forall|i: int| 0 <= i < self.entries().len() ==>
                0 < IteratorSpec::remaining(&entries)[i].0@.len() < 64
                    && IteratorSpec::remaining(&entries)[i].1@.len() <= MAX_VALUE,
            forall|i: int| 0 <= i < self.entries().len() ==>
                IteratorSpec::remaining(&entries)[i].0@ == self.entries()[i].key()
                    && IteratorSpec::remaining(&entries)[i].1@ == self.entries()[i].value(),
            IteratorSpec::decrease(&entries).is_some(),
    { self.records.iter() }
}

}
