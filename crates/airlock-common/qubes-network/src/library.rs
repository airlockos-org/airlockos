//! Contracts for standard-library operations absent from pinned vstd. These
//! declarations add no runtime implementations. Their correspondence is trusted
//! to Rust's documented library behavior; policy, validation and transitions
//! remain executable verified-body obligations at their callers.

use vstd::prelude::*;

verus! {

/// Delegate exact network-order decoding to the standard library. The pinned
/// verifier compares the anonymous array-length constant in u16's signature
/// structurally and cannot attach an external specification to `[u8; 2]`.
/// This bridge trusts only the unchanged standard-library call, not validation.
#[verifier::external_body]
pub fn network_word(bytes: [u8; 2]) -> (word: u16)
    ensures word as int == bytes[0] as int * 256 + bytes[1] as int,
{ u16::from_be_bytes(bytes) }

/// Delegate exact network-order encoding under the same array-signature gap.
#[verifier::external_body]
pub fn network_bytes(word: u16) -> (bytes: [u8; 2])
    ensures bytes[0] as int == word as int / 256, bytes[1] as int == word as int % 256,
{ word.to_be_bytes() }

/// Replacement moves the new value in and returns the sole original value.
pub assume_specification<T>[ core::mem::replace ](destination: &mut T, source: T) -> (previous: T)
    ensures previous == *old(destination), *final(destination) == source,
    no_unwind
;

/// Evaluate the callback exactly for Some; absence returns false.
pub assume_specification<T, F: FnOnce(T) -> bool>[ Option::<T>::is_some_and ](option: Option<T>, predicate: F) -> (yes: bool)
    requires option.is_some() ==> predicate.requires((option.unwrap(),)),
    ensures match option { Some(value) => predicate.ensures((value,), yes), None => !yes },
;

/// Evaluate the callback exactly for Some; absence returns true.
pub assume_specification<T, F: FnOnce(T) -> bool>[ Option::<T>::is_none_or ](option: Option<T>, predicate: F) -> (yes: bool)
    requires option.is_some() ==> predicate.requires((option.unwrap(),)),
    ensures match option { Some(value) => predicate.ensures((value,), yes), None => yes },
;

}
