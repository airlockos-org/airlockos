//! Bounded private byte operations shared by configuration and rule decoders.

use alloc::vec::Vec;
use vstd::prelude::*;

verus! {

/// Test a byte interval using the pinned vstd-modeled RangeInclusive contract.
/// This keeps ASCII predicates exact without an unchecked is_ascii_* contract.
pub(crate) fn in_range(byte: u8, first: u8, last: u8) -> (inside: bool)
    ensures inside == (first <= byte <= last),
{ (first..=last).contains(&byte) }

/// Compare exact private bytes; a mismatch never authorizes a prefix match.
pub(crate) fn equal(left: &[u8], right: &[u8]) -> (same: bool)
    requires left@.len() <= 4096,
    ensures same == (left@ == right@),
{
    if left.len() != right.len() { return false; }
    let mut i = 0;
    while i < left.len()
        invariant i <= left.len() == right.len(), left@.len() <= 4096,
            forall|j: int| 0 <= j < i ==> left@[j] == right@[j],
        decreases left.len()-i,
    {
        if left[i] != right[i] { return false; }
        i += 1;
    }
    assert(left@ =~= right@);
    true
}

/// Copy at most one already bounded native value into exclusive owned storage.
pub(crate) fn copy(bytes: &[u8]) -> (out: Vec<u8>)
    requires bytes@.len() <= 4096,
    ensures out@ == bytes@,
{
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len()
        invariant i <= bytes.len() <= 4096, out@ == bytes@.subrange(0, i as int),
        decreases bytes.len()-i,
    {
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// Compare only a complete bounded path prefix, preserving subtree boundaries
/// selected by the caller rather than guessing from packet or watch contents.
pub(crate) fn prefix(bytes: &[u8], start: &[u8]) -> (matched: bool)
    requires start@.len() <= 4096,
    ensures matched == (bytes@.len() >= start@.len()
        && bytes@.subrange(0, start@.len() as int) == start@),
{
    if bytes.len() < start.len() { return false; }
    equal(start, &bytes[..start.len()])
}

/// Find the first exact delimiter in one bounded native value.
pub(crate) fn find(bytes: &[u8], delimiter: u8) -> (index: usize)
    requires bytes@.len() <= 4096,
    ensures index <= bytes@.len()
        && (forall|i: int| 0 <= i < index ==> bytes@[i] != delimiter)
        && (index == bytes@.len() || bytes@[index as int] == delimiter),
{
    let mut i = 0;
    while i < bytes.len()
        invariant i <= bytes.len() <= 4096,
            forall|j: int| 0 <= j < i ==> bytes@[j] != delimiter,
        decreases bytes.len()-i,
    {
        if bytes[i] == delimiter { return i; }
        i += 1;
    }
    i
}

/// Append a bounded fragment while preserving its exact private bytes.
pub(crate) fn append(bytes: &mut Vec<u8>, part: &[u8])
    requires old(bytes)@.len()+part@.len() <= 4096,
    ensures final(bytes)@ == old(bytes)@+part@,
{
    let ghost before = bytes@;
    let mut i = 0;
    while i < part.len()
        invariant i <= part.len(), bytes@ == before+part@.subrange(0, i as int),
            before.len()+part@.len() <= 4096,
        decreases part.len()-i,
    { bytes.push(part[i]); i += 1; }
}

}
