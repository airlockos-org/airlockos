//! Numeric tokens decoded and formatted by Rust's standard library. These thin
//! boundaries trust library conversions rather than duplicate them for proofs.
//! Length, sign, range and caller-selected leading-zero restrictions preserve
//! the Qubes token language. The contracts state assumed library correspondence;
//! they do not claim that Rust's parsing or formatting implementations are proved.

use alloc::string::ToString;
use vstd::prelude::*;

verus! {

broadcast use { vstd::seq::Seq::lemma_as_ref_index, crate::address::cut_unique };

/// Number of set bits among the first count network-order positions.
pub open spec fn population(value: u32, count: int) -> int
    recommends 0 <= count <= 32,
    decreases count,
{
    if count <= 0 { 0 } else { population(value, count-1)
        + if (value >> (32-count) as u32) & 1u32 != 0 { 1int } else { 0int } }
}

/// Rust counts all set bits, including zero and all-ones inputs.
pub assume_specification[ u32::count_ones ](value: u32) -> (count: u32)
    ensures count <= 32, count as int == population(value, 32),
;


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
        && (forall|i: int| 0 <= i < bytes.len() ==> b'0' <= #[trigger] bytes[i] <= b'9')
        && (!canonical || bytes.len() == 1 || bytes[0] != b'0')
}

/// Fixed-width decimal spelling is unique, including zero-padded native IDs.
pub(crate) proof fn decimal_unique(left: Seq<u8>, right: Seq<u8>)
    requires left.len() == right.len(), digits(left, false), digits(right, false), decimal(left) == decimal(right),
    ensures left == right,
    decreases left.len(),
{
    vstd::arithmetic::div_mod::lemma_fundamental_div_mod_converse(decimal(left), 10,
        decimal(left.drop_last()), left.last() as int-b'0' as int);
    vstd::arithmetic::div_mod::lemma_fundamental_div_mod_converse(decimal(right), 10,
        decimal(right.drop_last()), right.last() as int-b'0' as int);
    if left.len() > 1 {
        decimal_unique(left.drop_last(), right.drop_last());
    }
    assert forall|i: int| 0 <= i < left.len() implies left[i] == right[i] by {
        if i == left.len()-1 { assert(left[i] == left.last()); assert(right[i] == right.last()); }
        else { assert(left[i] == left.drop_last()[i]); assert(right[i] == right.drop_last()[i]); }
    }
    assert(left =~= right);
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

/// Bounded hexadecimal token used for native MAC octets.
pub open spec fn hex_word(bytes: Seq<u8>, value: int) -> bool {
    0 < bytes.len() <= 4
        && (forall|i: int| 0 <= i < bytes.len() ==> 0 <= #[trigger] hex_digit(bytes[i]) <= 15)
        && value == hexadecimal(bytes)
}

/// Two hexadecimal digits fit exactly in one native octet.
pub(crate) proof fn byte_bound(bytes: Seq<u8>, value: int)
    requires bytes.len() == 2, hex_word(bytes, value),
    ensures 0 <= value <= 255,
{
    reveal_with_fuel(hexadecimal, 3);
    assert(bytes.drop_last().last() == bytes[0]);
    assert(bytes.last() == bytes[1]);
    assert(0 <= hex_digit(bytes[0]) <= 15);
    assert(0 <= hex_digit(bytes[1]) <= 15);
}

/// A nonzero leading decimal digit gives the usual place-value lower bound.
proof fn decimal_floor(bytes: Seq<u8>)
    requires digits(bytes, true), bytes[0] != b'0',
    ensures decimal(bytes) >= vstd::arithmetic::power::pow(10, (bytes.len()-1) as nat),
    decreases bytes.len(),
{
    reveal(vstd::arithmetic::power::pow);
    if bytes.len() == 1 { assert(bytes.last() == bytes[0]); }
    else {
        assert(bytes.drop_last()[0] == bytes[0]);
        assert(digits(bytes.drop_last(), true));
        decimal_floor(bytes.drop_last());
        assert(b'0' <= bytes.last() <= b'9');
    }
}

/// Canonical native domain IDs use at most five decimal bytes before their NUL.
pub(crate) proof fn peer_width(bytes: Seq<u8>)
    requires digits(bytes, true), decimal(bytes) < 100_000,
    ensures bytes.len() <= 5,
{
    if bytes.len() > 5 {
        decimal_floor(bytes);
        vstd::arithmetic::power::lemma_pow_increases(10, 5, (bytes.len()-1) as nat);
        reveal_with_fuel(vstd::arithmetic::power::pow, 6);
        assert(vstd::arithmetic::power::pow(10, 5) == 100_000);
    }
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
