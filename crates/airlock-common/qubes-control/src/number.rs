//! Finite numeric tokens used by native rule names, ports and address parts.
//! Leading zeros are a caller-selected grammar rule, never an implicit integer
//! conversion that could give two textual identities different interpretations.

use crate::bytes::in_range;
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

/// Every decimal prefix is nonnegative and no larger than the complete token.
proof fn decimal_prefix(bytes: Seq<u8>, count: int)
    requires 0 <= count <= bytes.len(),
        forall|i: int| 0 <= i < bytes.len() ==> b'0' <= bytes[i] <= b'9',
    ensures 0 <= decimal(bytes.subrange(0, count)) <= decimal(bytes),
    decreases bytes.len(),
{
    if bytes.len() > 0 {
        if count < bytes.len() { decimal_prefix(bytes.drop_last(), count); }
        decimal_prefix(bytes.drop_last(), bytes.len() as int-1);
    }
}

/// Decode the exact bounded value. Overflow, signs, whitespace and incomplete
/// tokens reject rather than truncating, wrapping or consuming a numeric prefix.
pub fn parse(bytes: &[u8], maximum: u32, canonical: bool) -> (number: Option<u32>)
    ensures match number {
        Some(value) => digits(bytes@, canonical) && value == decimal(bytes@) && value <= maximum,
        None => !digits(bytes@, canonical) || decimal(bytes@) > maximum,
    },
{
    if bytes.is_empty() || bytes.len() > 10 { return None; }
    if canonical && bytes.len() > 1 && bytes[0] == b'0' { return None; }
    let mut i = 0;
    while i < bytes.len()
        invariant i <= bytes.len() <= 10, bytes.len() > 0,
            forall|j: int| 0 <= j < i ==> b'0' <= bytes@[j] <= b'9',
        decreases bytes.len()-i,
    {
        if !in_range(bytes[i], b'0', b'9') { return None; }
        i += 1;
    }
    let mut value: u64 = 0;
    let mut i = 0;
    while i < bytes.len()
        invariant i <= bytes.len() <= 10, value <= maximum,
            value == decimal(bytes@.subrange(0, i as int)), digits(bytes@, canonical),
        decreases bytes.len()-i,
    {
        let next = value*10 + u64::from(bytes[i]-b'0');
        if next > maximum as u64 {
            proof { decimal_prefix(bytes@, i as int+1); }
            return None;
        }
        value = next;
        i += 1;
    }
    Some(value as u32)
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

/// Decode exactly one IPv6 word; no unchecked numeric library contract is used.
pub fn parse_hex(bytes: &[u8]) -> (word: Option<u16>)
    ensures match word {
        Some(value) => hex_word(bytes@, value as int),
        None => !(exists|value: int| hex_word(bytes@, value)),
    },
{
    if bytes.is_empty() || bytes.len() > 4 { return None; }
    let mut value: u32 = 0;
    let mut i = 0;
    while i < bytes.len()
        invariant i <= bytes.len() <= 4,
            value == hexadecimal(bytes@.subrange(0, i as int)), value < 0x1_0000,
            value < if i == 0 { 1int } else if i == 1 { 16int } else if i == 2 { 256int } else if i == 3 { 4096int } else { 65536int },
            forall|j: int| 0 <= j < i ==> 0 <= hex_digit(bytes@[j]) <= 15,
        decreases bytes.len()-i,
    {
        let byte = bytes[i];
        let digit = if in_range(byte, b'0', b'9') { byte-b'0' }
            else if in_range(byte, b'a', b'f') { byte-b'a'+10 }
            else if in_range(byte, b'A', b'F') { byte-b'A'+10 }
            else { return None; };
        value = value*16 + u32::from(digit);
        i += 1;
    }
    Some(value as u16)
}

}

verus! {

/// Canonical decimal counter spelling, including zero, with no formatter trust.
/// Recursion is bounded by the ten decimal digits of a u32.
pub(crate) fn encode(value: u32) -> (bytes: alloc::vec::Vec<u8>)
    ensures 0 < bytes@.len() <= 10, digits(bytes@, true), decimal(bytes@) == value,
    decreases value,
{
    let mut bytes = if value < 10 { alloc::vec::Vec::new() } else { encode(value/10) };
    bytes.push(b'0'+(value%10) as u8);
    bytes
}

}
