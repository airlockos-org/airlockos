//! Narrow contracts for Rust library primitives missing from the pinned vstd.
//! These are trusted external specifications, not proofs of library internals.
//! Business decisions and transitions must remain in verified executable bodies.

use vstd::prelude::*;

verus! {

/// Move the previous value out and install the replacement without cloning either.
/// Requirement: ownership correspondence at adapters. Exact scope: core::mem::replace.
/// Technical reason: pinned vstd has no specification for this core primitive,
/// whose implementation uses compiler-backed pointer reads/writes. Assumption:
/// Rust's exclusive-reference and move semantics hold; no value is duplicated,
/// lost or fabricated. Compensation: safe Rust aliasing, this exact two-value
/// contract, and retained ownership on fallible cleanup paths.
pub assume_specification<T>[ core::mem::replace ](destination: &mut T, replacement: T) -> (previous: T)
    ensures previous == *old(destination), *final(destination) == replacement,
;

/// Reserve fallibly without changing text. Scope: the Rust allocation primitive
/// missing from pinned vstd, matching its existing Vec reservation specifications.
/// Allocation success/failure remains an external outcome; this grants no policy
/// authority and assumes only Rust String/allocator semantics and valid borrows.
pub assume_specification[ alloc::string::String::try_reserve_exact ](
    text: &mut alloc::string::String, additional: usize,
) -> (out: Result<(), alloc::collections::TryReserveError>)
    ensures final(text)@ == old(text)@,
;

/// Rust's checked UTF-8 conversion validates bytes without changing their lifetime or identity.
/// Pinned vstd specifies the unchecked primitive only; use the safe standard routine
/// and trust its documented validation, with no first-party parser excluded here.
#[cfg(verus_keep_ghost)]
#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExUtf8Error(
    /// Opaque standard-library rejection metadata, never inspected by clipboard policy.
    core::str::Utf8Error,
);

/// Preserve exact validated bytes while retaining the input borrow lifetime.
pub assume_specification<'a>[core::str::from_utf8](bytes: &'a [u8]) -> (out: Result<&'a str, core::str::Utf8Error>)
    ensures out.is_ok() == vstd::utf8::valid_utf8(bytes@),
        out.is_ok() ==> vstd::string::StringSliceAdditionalSpecFns::spec_bytes(out.unwrap()) == bytes@,
;

}
