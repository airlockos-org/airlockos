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

}
