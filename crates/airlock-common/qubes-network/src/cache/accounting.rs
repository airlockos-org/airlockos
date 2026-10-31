//! Checked arithmetic facts for retained payloads and normalized-source charges.
//! This module contains proofs only; production storage remains in BTreeMap.

use super::{Entry, selected_bytes, selected_count, source_bytes, source_count, weight};
use crate::address::Ip;
use vstd::prelude::*;

verus! {

broadcast use { vstd::seq::group_seq_lemmas, vstd::seq_lib::group_seq_properties };

/// Charges depend on the selected prefix, independently of later records.
proof fn same_prefix(left: Seq<Entry>, right: Seq<Entry>, selected: spec_fn(Entry) -> bool, count: int)
    requires 0 <= count <= left.len(), count <= right.len(),
        left.subrange(0, count) == right.subrange(0, count),
    ensures weight(left, count) == weight(right, count),
        selected_bytes(left, selected, count) == selected_bytes(right, selected, count),
        selected_count(left, selected, count) == selected_count(right, selected, count),
    decreases count,
{
    if count > 0 {
        assert(left.subrange(0, count-1) =~= right.subrange(0, count-1));
        same_prefix(left, right, selected, count-1);
        assert(left.subrange(0, count)[count-1] == left[count-1]);
        assert(right.subrange(0, count)[count-1] == right[count-1]);
    }
}

/// Equal decisions on the retained records produce equal standard filters.
proof fn filters_agree(entries: Seq<Entry>, left: spec_fn(Entry) -> bool, right: spec_fn(Entry) -> bool)
    requires forall|i: int| 0 <= i < entries.len() ==> left(entries[i]) == right(entries[i]),
    ensures entries.filter(left) == entries.filter(right),
    decreases entries.len(),
{
    reveal(Seq::filter);
    if entries.len() > 0 {
        assert forall|i: int| 0 <= i < entries.drop_last().len()
            implies left(entries.drop_last()[i]) == right(entries.drop_last()[i]) by {
            assert(entries.drop_last()[i] == entries[i]);
        }
        filters_agree(entries.drop_last(), left, right);
        assert(left(entries.last()) == right(entries.last()));
    }
}

/// Standard retention preserves exactly the predicate-selected record sequence.
pub(super) proof fn retained(before: Seq<Entry>, after: Seq<Entry>, keep: spec_fn(Entry) -> bool)
    requires after == before.filter(|entry: Entry| after.contains(entry)),
        forall|entry: Entry| before.contains(entry) ==> after.contains(entry) == keep(entry),
    ensures after == before.filter(keep),
{
    assert forall|i: int| 0 <= i < before.len() implies after.contains(before[i]) == keep(before[i]) by {
        assert(before.contains(before[i]));
    }
    filters_agree(before, |entry: Entry| after.contains(entry), keep);
}

/// Filtering removes exactly the selected record count and payload charge.
pub(super) proof fn filtered(entries: Seq<Entry>, selected: spec_fn(Entry) -> bool)
    ensures entries.filter(|entry: Entry| !selected(entry)).len()
                + selected_count(entries, selected, entries.len() as int) == entries.len(),
        weight(entries.filter(|entry: Entry| !selected(entry)), entries.filter(|entry: Entry| !selected(entry)).len() as int)
                + selected_bytes(entries, selected, entries.len() as int) == weight(entries, entries.len() as int),
    decreases entries.len(),
{
    reveal(Seq::filter);
    if entries.len() > 0 {
        filtered(entries.drop_last(), selected);
        assert(entries.subrange(0, entries.len() as int-1) =~= entries.drop_last());
        assert(entries.drop_last().subrange(0, entries.len() as int-1) =~= entries.drop_last());
        same_prefix(entries, entries.drop_last(), selected, entries.len() as int-1);
        let prefix = entries.drop_last().filter(|entry: Entry| !selected(entry));
        if !selected(entries.last()) {
            assert(prefix.push(entries.last()).subrange(0, prefix.len() as int) =~= prefix);
            assert(prefix.subrange(0, prefix.len() as int) =~= prefix);
            same_prefix(prefix.push(entries.last()), prefix, selected, prefix.len() as int);
        }
    }
}

/// Every prefix has nonnegative charges; one source cannot exceed that prefix.
pub(super) proof fn bounds(entries: Seq<Entry>, source: Ip, count: int)
    requires 0 <= count <= entries.len(),
    ensures 0 <= weight(entries, count), 0 <= source_count(entries, source, count) <= count,
        0 <= source_bytes(entries, source, count) <= weight(entries, count),
    decreases count,
{
    selected_bounds(entries, |entry: Entry| super::belongs(entry.key(), source), count);
}

/// Any selection charges at most the payload of the prefix being inspected.
pub(super) proof fn selected_bounds(entries: Seq<Entry>, selected: spec_fn(Entry) -> bool, count: int)
    requires 0 <= count <= entries.len(),
    ensures 0 <= weight(entries, count), 0 <= selected_count(entries, selected, count) <= count,
        0 <= selected_bytes(entries, selected, count) <= weight(entries, count),
    decreases count,
{
    if count > 0 { selected_bounds(entries, selected, count-1); }
}

/// Extending a prefix cannot reduce the number of selected records.
pub(crate) proof fn count_monotone(entries: Seq<Entry>, selected: spec_fn(Entry) -> bool, prefix: int, count: int)
    requires 0 <= prefix <= count <= entries.len(),
    ensures selected_count(entries, selected, prefix) <= selected_count(entries, selected, count),
    decreases count-prefix,
{
    if prefix < count { count_monotone(entries, selected, prefix, count-1); }
}

/// Extending a prefix cannot reduce its retained payload charge.
pub(super) proof fn monotone(entries: Seq<Entry>, prefix: int, count: int)
    requires 0 <= prefix <= count <= entries.len(),
    ensures weight(entries, prefix) <= weight(entries, count),
    decreases count-prefix,
{
    if prefix < count { monotone(entries, prefix, count-1); }
}

/// A stored record's charge is included in the whole cache and its source sum.
pub(super) proof fn entry_bound(entries: Seq<Entry>, source: Ip, index: int)
    requires 0 <= index < entries.len(),
    ensures entries[index].weight() <= weight(entries, entries.len() as int),
        super::belongs(entries[index].key(), source) ==>
            entries[index].weight() <= source_bytes(entries, source, entries.len() as int),
{
    bounds(entries, source, index);
    monotone(entries, index+1, entries.len() as int);
    selected_monotone(entries, source, index+1, entries.len() as int);
}

/// The whole payload sum includes the complete charge of each retained record.
pub(super) proof fn global_entry_bound(entries: Seq<Entry>, index: int)
    requires 0 <= index < entries.len(),
    ensures entries[index].weight() <= weight(entries, entries.len() as int),
{
    monotone(entries, 0, index);
    monotone(entries, index+1, entries.len() as int);
}

/// Concatenating retained records adds exactly their two payload charges.
proof fn appended(left: Seq<Entry>, right: Seq<Entry>)
    ensures weight(left+right, (left+right).len() as int)
        == weight(left, left.len() as int)+weight(right, right.len() as int),
    decreases right.len(),
{
    if right.len() == 0 {
        assert(left+right =~= left);
    } else {
        appended(left, right.drop_last());
        let prefix = left+right.drop_last();
        assert((left+right).last() == right.last());
        assert((left+right).subrange(0, prefix.len() as int) =~= prefix);
        assert(prefix.subrange(0, prefix.len() as int) =~= prefix);
        same_prefix(left+right, prefix, |_: Entry| false, prefix.len() as int);
        assert(right.subrange(0, right.len() as int-1) =~= right.drop_last());
        assert(right.drop_last().subrange(0, right.len() as int-1) =~= right.drop_last());
        same_prefix(right, right.drop_last(), |_: Entry| false, right.len() as int-1);
    }
}

/// Inserting one stored record charges exactly that record's complete payload.
pub(super) proof fn inserted(entries: Seq<Entry>, entry: Entry, index: int)
    requires 0 <= index <= entries.len(),
    ensures weight(entries.insert(index, entry), entries.len() as int+1)
        == weight(entries, entries.len() as int)+entry.weight(),
{
    let left = entries.subrange(0, index);
    let right = entries.subrange(index, entries.len() as int);
    assert(left+right =~= entries);
    assert(left.push(entry) =~= left+seq![entry]);
    appended(left, right);
    appended(left, seq![entry]);
    appended(left.push(entry), right);
    assert(weight(seq![entry], 0) == 0);
    assert(weight(seq![entry], 1) == entry.weight());
    assert(entries.insert(index, entry) == left.push(entry)+right);
}

/// Removing one stored record releases exactly that record's complete payload.
pub(super) proof fn removed(entries: Seq<Entry>, index: int)
    requires 0 <= index < entries.len(),
    ensures weight(entries.remove(index), entries.len() as int-1)+entries[index].weight()
        == weight(entries, entries.len() as int),
{
    let left = entries.subrange(0, index);
    let right = entries.subrange(index+1, entries.len() as int);
    assert(left+seq![entries[index]]+right =~= entries);
    appended(left, right);
    appended(left, seq![entries[index]]);
    appended(left+seq![entries[index]], right);
    assert(weight(seq![entries[index]], 0) == 0);
    assert(weight(seq![entries[index]], 1) == entries[index].weight());
    assert(entries.remove(index) == left+right);
}

/// Replacing one value releases its old charge before charging the replacement.
pub(super) proof fn replaced(entries: Seq<Entry>, entry: Entry, index: int)
    requires 0 <= index < entries.len(),
    ensures weight(entries.update(index, entry), entries.len() as int)+entries[index].weight()
        == weight(entries, entries.len() as int)+entry.weight(),
{
    removed(entries, index);
    inserted(entries.remove(index), entry, index);
    vstd::seq_lib::lemma_update_is_remove_insert(entries, index, entry);
}

/// Extending a prefix cannot reduce one source's payload charge.
proof fn selected_monotone(entries: Seq<Entry>, source: Ip, prefix: int, count: int)
    requires 0 <= prefix <= count <= entries.len(),
    ensures source_bytes(entries, source, prefix) <= source_bytes(entries, source, count),
    decreases count-prefix,
{
    if prefix < count { selected_monotone(entries, source, prefix, count-1); }
}

}
