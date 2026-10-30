//! IP observations decoded by Rust's standard address parser. The parser is an
//! explicitly trusted dependency; the grammar below specifies the correspondence
//! expected at that boundary, not a proof of the library. Qubes membership and
//! interface authorization remain separate from a successfully parsed address.

use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
use crate::number;

verus! {

/// First delimiter, or the exact end of a token without that delimiter.
pub open spec fn cut(bytes: Seq<u8>, index: int, delimiter: u8) -> bool {
    0 <= index <= bytes.len()
        && (forall|i: int| 0 <= i < index ==> bytes[i] != delimiter)
        && (index == bytes.len() || bytes[index] == delimiter)
}

/// Exact dotted sequence of canonical decimal octets. The caller fixes its
/// length to four; this smaller recursive language also specifies suffixes.
pub open spec fn octets(bytes: Seq<u8>, values: Seq<u8>) -> bool
    decreases values.len(),
{
    values.len() > 0 && exists|index: int| cut(bytes, index, b'.')
        && number::digits(bytes.subrange(0, index), true)
        && number::decimal(bytes.subrange(0, index)) == values[0]
        && if values.len() == 1 { index == bytes.len() }
            else { index < bytes.len() && octets(bytes.subrange(index+1, bytes.len() as int), values.drop_first()) }
}

/// IPv4 tail occupies exactly two network-order words in an IPv6 spelling.
pub open spec fn dotted_tail(bytes: Seq<u8>, words: Seq<u16>) -> bool {
    bytes.len() <= 15 && words.len() == 2
        && (exists|i: int| 0 <= i < bytes.len() && bytes[i] == b'.')
        && exists|values: Seq<u8>| values.len() == 4 && octets(bytes, values)
            && words[0] == values[0] as int*256+values[1] as int
            && words[1] == values[2] as int*256+values[3] as int
}

/// Colon-separated words with an optional final dotted IPv4 tail. Empty sides
/// are admitted only by the separate double-colon expansion rule.
pub open spec fn groups(bytes: Seq<u8>, words: Seq<u16>, allow_tail: bool) -> bool
    decreases bytes.len(),
{
    if bytes.len() == 0 { words.len() == 0 }
    else {
        exists|index: int| cut(bytes, index, b':') && (
            if exists|j: int| 0 <= j < index && bytes[j] == b'.' {
                allow_tail && index == bytes.len() && dotted_tail(bytes, words)
            } else {
                words.len() > 0 && number::hex_word(bytes.subrange(0, index), words[0] as int)
                    && if index == bytes.len() { words.len() == 1 }
                        else { index+1 < bytes.len() && groups(bytes.subrange(index+1, bytes.len() as int), words.drop_first(), allow_tail) }
            }
        )
    }
}

/// A possible double-colon marker, including overlapping malformed triples.
pub open spec fn double_at(bytes: Seq<u8>, index: int) -> bool {
    0 <= index && index+1 < bytes.len() && bytes[index] == b':' && bytes[index+1] == b':'
}

/// Normative IPv6 expansion: eight words directly, or one marker replacing
/// at least one all-zero word between two independently parsed sides.
pub open spec fn ipv6(bytes: Seq<u8>, words: Seq<u16>) -> bool {
    0 < bytes.len() <= 45 && words.len() == 8 && (
        ((forall|i: int| !double_at(bytes, i)) && groups(bytes, words, true))
        || (exists|index: int, left: Seq<u16>, right: Seq<u16>|
            double_at(bytes, index)
                && (forall|j: int| double_at(bytes, j) ==> j == index)
                && groups(bytes.subrange(0, index), left, false)
                && groups(bytes.subrange(index+2, bytes.len() as int), right, true)
                && left.len()+right.len() < 8
                && words == left + Seq::new((8-left.len()-right.len()) as nat, |_: int| 0u16) + right)
    )
}

/// Normative IPv4 expansion: four octets followed by six unused zero words.
pub open spec fn ipv4(bytes: Seq<u8>, words: Seq<u16>) -> bool {
    0 < bytes.len() <= 15 && words.len() == 8
        && (forall|i: int| 2 <= i < 8 ==> words[i] == 0)
        && exists|values: Seq<u8>| values.len() == 4 && octets(bytes, values)
            && words[0] == values[0] as int*256+values[1] as int
            && words[1] == values[2] as int*256+values[3] as int
}

/// A complete parsed IP observation with no mutable or unchecked constructor.
/// IPv4 occupies its first two words; IPv6 uses all eight, in network order.
#[derive(Clone, Copy)]
pub struct Ip {
    /// Wire address family, exactly 4 or 6 after successful construction.
    family: u8,
    /// Expanded network-order words; IPv4 padding is always zero.
    words: [u16; 8],
}

impl Ip {
    /// Parsed family, still an observation rather than source authority.
    pub closed spec fn family(&self) -> u8 { self.family }

    /// Mathematical expanded network-order address words.
    pub closed spec fn words(&self) -> Seq<u16> { self.words@ }

    /// Meaningful address family and a fixed, unambiguous representation.
    pub closed spec fn valid(&self) -> bool {
        (self.family == 4 || self.family == 6) && self.words@.len() == 8
            && (self.family == 4 ==> forall|i: int| 2 <= i < 8 ==> self.words@[i] == 0)
    }

    /// Native token meaning of this normalized address, independent of spelling.
    pub closed spec fn describes(&self, bytes: Seq<u8>) -> bool {
        self.valid() && if self.family == 4 { ipv4(bytes, self.words()) }
            else { ipv6(bytes, self.words()) }
    }

    /// Decode a complete IPv4/IPv6 token, including a compressed or dotted-tail
    /// IPv6 spelling. Signs, zones, whitespace, brackets and trailing bytes reject.
    /// Trust boundary: safe UTF-8 conversion, core::net::IpAddr parsing and its
    /// octet/segment accessors. Reuse avoids maintaining a second IP parser;
    /// correctness of their correspondence to describes remains assumed. The
    /// 45-byte cap, private normalized representation and later Qubes checks
    /// bound this dependency and prevent parsed syntax becoming authority.
    #[verifier::external_body]
    pub fn parse(bytes: &[u8]) -> (address: Option<Self>)
        ensures match address {
            Some(value) => value.valid() && value.describes(bytes@),
            None => !(exists|words: Seq<u16>| ipv4(bytes@, words) || ipv6(bytes@, words)),
        },
    {
        if bytes.is_empty() || bytes.len() > 45 { return None; }
        let parsed = core::str::from_utf8(bytes).ok()?.parse::<core::net::IpAddr>().ok()?;
        let (family, words) = match parsed {
            core::net::IpAddr::V4(ip) => {
                let [a, b, c, d] = ip.octets();
                (4, [u16::from_be_bytes([a, b]), u16::from_be_bytes([c, d]), 0, 0, 0, 0, 0, 0])
            }
            core::net::IpAddr::V6(ip) => (6, ip.segments()),
        };
        Some(Self { family, words })
    }

    /// Return the parsed family without exposing mutable representation.
    pub fn version(&self) -> (family: u8)
        requires self.valid(), ensures family == self.family(), family == 4 || family == 6,
    { self.family }

    /// Read one expanded word for the packet-policy consumer's mask operations.
    pub fn word(&self, index: usize) -> (word: Option<u16>)
        ensures match word {
            Some(value) => index < 8 && value == self.words()[index as int],
            None => index >= 8,
        },
    {
        if index < 8 { Some(self.words[index]) } else { None }
    }

    /// Compare semantic addresses, so compression/case do not create distinct
    /// source identities. This still does not authenticate a packet sender.
    pub fn same(&self, other: &Self) -> (same: bool)
        ensures same == (self.family() == other.family() && self.words() == other.words()), same == (*self == *other),
    {
        if self.family != other.family { return false; }
        let mut i = 0;
        while i < 8
            invariant i <= 8, self.family == other.family,
                forall|j: int| 0 <= j < i ==> self.words@[j] == other.words@[j],
            decreases 8-i,
        {
            if self.words[i] != other.words[i] { return false; }
            i += 1;
        }
        assert(self.words@ =~= other.words@);
        true
    }
}

}
