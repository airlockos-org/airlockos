//! Numeric tokens decoded and formatted by Rust's standard library. These thin
//! boundaries trust library conversions rather than duplicate them for proofs.
//! Length, sign, range and caller-selected leading-zero restrictions preserve
//! the Qubes token language. The contracts state assumed library correspondence;
//! they do not claim that Rust's parsing or formatting implementations are proved.

use alloc::string::ToString;
use vstd::prelude::*;

verus! {

/// Exact decimal value of a digit sequence; syntax is specified separately.
pub open spec fn decimal(bytes: Seq<u8>) -> int
    decreases bytes.len(),
{
    if bytes.len() == 0 { 0 } else {
        decimal(bytes.drop_last())*10 + bytes.last() as int - b'0' as int
    }
}

/// A bounded nonempty decimal token, optionally requiring canonical zero spelling.
pub open spec fn digits(bytes: Seq<u8>, canonical: bool) -> bool {
    0 < bytes.len() <= 10
        && (forall|i: int| 0 <= i < bytes.len() ==> b'0' <= bytes[i] <= b'9')
        && (!canonical || bytes.len() == 1 || bytes[0] != b'0')
}

/// Decode the exact bounded value. Overflow, signs, whitespace and incomplete
/// tokens reject rather than truncating, wrapping or consuming a numeric prefix.
/// Trust scope: checked UTF-8, u32 parsing and this bounded lexical adapter.
/// Rust permits a leading plus; explicitly exclude it to retain Qubes syntax.
#[verifier::external_body]
pub fn parse(bytes: &[u8], maximum: u32, canonical: bool) -> (number: Option<u32>)
    ensures match number {
        Some(value) => digits(bytes@, canonical) && value == decimal(bytes@) && value <= maximum,
        None => !digits(bytes@, canonical) || decimal(bytes@) > maximum,
    },
{
    if bytes.is_empty() || bytes.len() > 10 || bytes[0] == b'+' { return None; }
    if canonical && bytes.len() > 1 && bytes[0] == b'0' { return None; }
    let value = core::str::from_utf8(bytes).ok()?.parse::<u32>().ok()?;
    (value <= maximum).then_some(value)
}

/// Mathematical value of one native hexadecimal digit, or -1 for a non-digit.
pub open spec fn hex_digit(byte: u8) -> int {
    if b'0' <= byte <= b'9' { byte as int-b'0' as int }
    else if b'a' <= byte <= b'f' { byte as int-b'a' as int+10 }
    else if b'A' <= byte <= b'F' { byte as int-b'A' as int+10 }
    else { -1 }
}

/// Exact hexadecimal token value, independent of case and leading zero spelling.
pub open spec fn hexadecimal(bytes: Seq<u8>) -> int
    decreases bytes.len(),
{
    if bytes.len() == 0 { 0 }
    else { hexadecimal(bytes.drop_last())*16 + hex_digit(bytes.last()) }
}

/// The one-to-four digit grammar of a single IPv6 word.
pub open spec fn hex_word(bytes: Seq<u8>, value: int) -> bool {
    0 < bytes.len() <= 4
        && (forall|i: int| 0 <= i < bytes.len() ==> 0 <= hex_digit(bytes[i]) <= 15)
        && value == hexadecimal(bytes)
}

/// Decode a bounded hexadecimal token through u16::from_str_radix. Trust scope:
/// checked UTF-8, radix conversion and the explicit length/sign restrictions.
#[verifier::external_body]
pub fn parse_hex(bytes: &[u8]) -> (word: Option<u16>)
    ensures match word {
        Some(value) => hex_word(bytes@, value as int),
        None => !(exists|value: int| hex_word(bytes@, value)),
    },
{
    if bytes.is_empty() || bytes.len() > 4 || bytes[0] == b'+' { return None; }
    u16::from_str_radix(core::str::from_utf8(bytes).ok()?, 16).ok()
}

}

verus! {

/// Canonical decimal counter spelling through Rust's Display implementation.
/// Trust scope: ToString and String::into_bytes; a u32 needs at most ten bytes.
#[verifier::external_body]
pub(crate) fn encode(value: u32) -> (bytes: alloc::vec::Vec<u8>)
    ensures 0 < bytes@.len() <= 10, digits(bytes@, true), decimal(bytes@) == value,
{
    value.to_string().into_bytes()
}

}
