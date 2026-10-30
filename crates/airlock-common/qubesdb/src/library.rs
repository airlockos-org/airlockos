//! Contracts for Rust's ASCII predicates, which the pinned vstd does not model.
//! These specify existing library calls, without runtime wrappers. They trust
//! Rust's byte classification; protocol validation remains in its callers.

use vstd::prelude::*;

verus! {

/// Rust classifies exactly the ASCII letters and decimal digits.
pub assume_specification[ u8::is_ascii_alphanumeric ](byte: &u8) -> (yes: bool)
    ensures yes == ((b'a' <= *byte <= b'z') || (b'A' <= *byte <= b'Z') || (b'0' <= *byte <= b'9')),
;

/// Rust classifies exactly the lowercase ASCII letters.
pub assume_specification[ u8::is_ascii_lowercase ](byte: &u8) -> (yes: bool)
    ensures yes == (b'a' <= *byte <= b'z'),
;

/// Rust classifies exactly the ASCII decimal digits.
pub assume_specification[ u8::is_ascii_digit ](byte: &u8) -> (yes: bool)
    ensures yes == (b'0' <= *byte <= b'9'),
;

}
