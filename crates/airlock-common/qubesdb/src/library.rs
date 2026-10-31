//! Contracts for Rust primitives which the pinned vstd does not model.
//! These specify existing library calls, without runtime wrappers. They trust
//! Rust's byte classification and numeric operations; validation stays in callers.

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

/// Number of set bits among the lowest count positions, independently of order.
pub open spec fn population(value: u32, count: int) -> int
    recommends 0 <= count <= 32,
    decreases count,
{
    if count <= 0 { 0 } else { population(value, count-1)
        + if value & (1u32 << (count-1) as u32) != 0 { 1int } else { 0int } }
}

/// Rust counts all set bits, including zero and all-ones inputs.
pub assume_specification[ u32::count_ones ](value: u32) -> (count: u32)
    ensures count <= 32, count as int == population(value, 32),
;

}
