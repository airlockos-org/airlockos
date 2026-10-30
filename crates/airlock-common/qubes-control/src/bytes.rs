//! Bounded private byte operations shared by configuration and rule decoders.
//! Safe Rust slice/Vec primitives are explicitly trusted at these thin library
//! boundaries. Their contracts state the correspondence assumed by callers;
//! library internals are not proved here. Reusing exact byte operations avoids
//! handwritten copy/search loops while leaving Qubes decisions in their callers.
//! Caller bounds limit allocation and work; safe borrows preserve ownership.

use alloc::vec::Vec;
use vstd::prelude::*;

verus! {

/// Test a byte interval using the pinned vstd-modeled RangeInclusive contract.
/// This keeps ASCII predicates exact without an unchecked is_ascii_* contract.
pub(crate) fn in_range(byte: u8, first: u8, last: u8) -> (inside: bool)
    ensures inside == (first <= byte <= last),
{ (first..=last).contains(&byte) }

/// Compare exact private bytes; a mismatch never authorizes a prefix match.
/// Trust scope: Rust slice equality on u8 values.
#[verifier::external_body]
pub(crate) fn equal(left: &[u8], right: &[u8]) -> (same: bool)
    requires left@.len() <= 4096,
    ensures same == (left@ == right@),
{
    left == right
}

/// Copy at most one already bounded native value into exclusive owned storage.
/// Trust scope: slice::to_vec, including Rust's existing allocator behavior.
#[verifier::external_body]
pub(crate) fn copy(bytes: &[u8]) -> (out: Vec<u8>)
    requires bytes@.len() <= 4096,
    ensures out@ == bytes@,
{
    bytes.to_vec()
}

/// Compare only a complete bounded path prefix, preserving subtree boundaries
/// selected by the caller rather than guessing from packet or watch contents.
/// Trust scope: slice::starts_with, with no decoding or normalization.
#[verifier::external_body]
pub(crate) fn prefix(bytes: &[u8], start: &[u8]) -> (matched: bool)
    requires start@.len() <= 4096,
    ensures matched == (bytes@.len() >= start@.len()
        && bytes@.subrange(0, start@.len() as int) == start@),
{
    bytes.starts_with(start)
}

/// Find the first exact delimiter in one bounded native value.
/// Trust scope: the slice iterator's first-match position and absent fallback.
#[verifier::external_body]
pub(crate) fn find(bytes: &[u8], delimiter: u8) -> (index: usize)
    requires bytes@.len() <= 4096,
    ensures index <= bytes@.len()
        && (forall|i: int| 0 <= i < index ==> bytes@[i] != delimiter)
        && (index == bytes@.len() || bytes@[index as int] == delimiter),
{
    bytes.iter().position(|byte| *byte == delimiter).unwrap_or(bytes.len())
}

/// Append a bounded fragment while preserving its exact private bytes.
/// Trust scope: Vec::extend_from_slice on u8 values, under the caller's bound.
#[verifier::external_body]
pub(crate) fn append(bytes: &mut Vec<u8>, part: &[u8])
    requires old(bytes)@.len()+part@.len() <= 4096,
    ensures final(bytes)@ == old(bytes)@+part@,
{
    bytes.extend_from_slice(part)
}

}
