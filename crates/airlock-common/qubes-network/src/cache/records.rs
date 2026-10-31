//! Contracts for standard BTreeMap storage, without network or quota decisions.
//! The pinned vstd lacks Vec's lexical ordering and Vec-to-slice borrowed-key
//! correspondence; Vec::retain also lacks a contract. These adapters trust those
//! operations and iteration order. Their model describes stored records only;
//! callers verify admission, charges, deletion selection and policy isolation.

use alloc::collections::{BTreeMap, btree_map};
use alloc::vec::Vec;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::std_specs::iter::IteratorSpec;

#[cfg(verus_keep_ghost)]
use super::Entry;

verus! {

/// Apply standard Vec retention to a sequence with no duplicate values.
#[verifier::external_body]
pub(super) fn retain<T, F: Fn(&T) -> bool>(values: &mut Vec<T>, keep: F)
    requires old(values)@.no_duplicates(),
        forall|value: T| old(values)@.contains(value) ==> call_requires(keep, (&value,)),
    ensures final(values)@ == old(values)@.filter(|value: T| final(values)@.contains(value)),
        final(values)@.no_duplicates(), final(values)@.len() <= old(values)@.len(),
        forall|i: int| 0 <= i < final(values)@.len() ==> old(values)@.contains(final(values)@[i]),
        forall|value: T| old(values)@.contains(value)
            ==> call_ensures(keep, (&value,), final(values)@.contains(value)),
{
    values.retain(keep);
}

/// Standard-library storage; its private representation grants no network authority.
pub(super) struct Records {
    /// Native keys and complete bodies, each owned exactly once.
    map: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl Records {
    /// Stored key/value pairs in the standard map's iteration order.
    pub(super) uninterp spec fn entries(&self) -> Seq<Entry>;

    /// Standard maps retain at most one value for each byte-equal key.
    pub(super) open spec fn valid(&self) -> bool {
        forall|i: int, j: int| 0 <= i < j < self.entries().len()
            ==> self.entries()[i].key() != self.entries()[j].key()
    }

    /// Construct the standard empty map.
    #[verifier::external_body]
    pub(super) fn new() -> (records: Self)
        ensures records.valid(), records.entries().len() == 0,
    { Self { map: BTreeMap::new() } }

    /// Observe the standard map's exact stored-record count.
    #[verifier::external_body]
    pub(super) fn len(&self) -> (count: usize)
        ensures count == self.entries().len(),
    { self.map.len() }

    /// Borrow the complete value for exactly this byte key.
    #[verifier::external_body]
    pub(super) fn get(&self, key: &[u8]) -> (value: Option<&[u8]>)
        ensures match value {
            Some(value) => exists|i: int| 0 <= i < self.entries().len()
                && self.entries()[i].key() == key@ && self.entries()[i].value() == value@,
            None => forall|i: int| 0 <= i < self.entries().len() ==> self.entries()[i].key() != key@,
        },
    { self.map.get(key).map(Vec::as_slice) }

    /// Replace one value or insert one key, preserving all other records and order.
    #[verifier::external_body]
    pub(super) fn insert(&mut self, key: Vec<u8>, value: Vec<u8>)
        requires old(self).valid(),
        ensures final(self).valid(),
            (exists|i: int| 0 <= i < old(self).entries().len()
                && old(self).entries()[i].key() == key@
                && final(self).entries() == old(self).entries().update(i,
                    Entry { key: old(self).entries()[i].key, value }))
            || ((forall|i: int| 0 <= i < old(self).entries().len() ==> old(self).entries()[i].key() != key@)
                && exists|i: int| 0 <= i <= old(self).entries().len()
                    && final(self).entries() == old(self).entries().insert(i, Entry { key, value })),
    { self.map.insert(key, value); }

    /// Remove exactly this key, returning its original complete body.
    #[verifier::external_body]
    pub(super) fn remove(&mut self, key: &[u8]) -> (value: Option<Vec<u8>>)
        requires old(self).valid(),
        ensures final(self).valid(), match value {
            Some(value) => exists|i: int| 0 <= i < old(self).entries().len()
                && old(self).entries()[i].key() == key@ && old(self).entries()[i].value() == value@
                && final(self).entries() == old(self).entries().remove(i),
            None => final(self).entries() == old(self).entries()
                && (forall|i: int| 0 <= i < old(self).entries().len() ==> old(self).entries()[i].key() != key@),
        },
    { self.map.remove(key) }

    /// Retain the records selected by the caller's checked predicate, in order.
    #[verifier::external_body]
    pub(super) fn retain<F: Fn(&Vec<u8>, &Vec<u8>) -> bool>(&mut self, keep: F)
        requires old(self).valid(),
            forall|entry: Entry| old(self).entries().contains(entry)
                ==> call_requires(keep, (&entry.key, &entry.value)),
        ensures final(self).valid(),
            final(self).entries() == old(self).entries().filter(|entry: Entry| final(self).entries().contains(entry)),
            forall|entry: Entry| old(self).entries().contains(entry) ==>
                call_ensures(keep, (&entry.key, &entry.value), final(self).entries().contains(entry)),
    { self.map.retain(|key, value| keep(key, value)); }

    /// Borrow the standard iterator in exactly the model's record order.
    #[verifier::external_body]
    pub(super) fn iter(&self) -> (iter: btree_map::Iter<'_, Vec<u8>, Vec<u8>>)
        ensures IteratorSpec::remaining(&iter).len() == self.entries().len(),
            forall|i: int| 0 <= i < self.entries().len() ==>
                *IteratorSpec::remaining(&iter)[i].0 == self.entries()[i].key
                    && *IteratorSpec::remaining(&iter)[i].1 == self.entries()[i].value,
            vstd::std_specs::btree::into_iter(iter) == IteratorSpec::remaining(&iter).unref(),
            IteratorSpec::decrease(&iter).is_some(),
    { self.map.iter() }
}

}
