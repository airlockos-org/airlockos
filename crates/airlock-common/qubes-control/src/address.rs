//! Finite IPv4/IPv6 syntax and expansion used by trusted configuration and rule
//! observations. An address value is a parsed claim, never an interface owner.
//! No unchecked standard-library IP parser contract supplies these decisions.

use alloc::vec::Vec;
use vstd::prelude::*;

use crate::number;

verus! {

/// First delimiter, or the exact end of a token without that delimiter.
pub open spec fn cut(bytes: Seq<u8>, index: int, delimiter: u8) -> bool {
    0 <= index <= bytes.len()
        && (forall|i: int| 0 <= i < index ==> bytes[i] != delimiter)
        && (index == bytes.len() || bytes[index] == delimiter)
}

/// Two positions cannot both be the first occurrence of one delimiter.
proof fn unique_cut(bytes: Seq<u8>, left: int, right: int, delimiter: u8)
    requires cut(bytes, left, delimiter), cut(bytes, right, delimiter),
    ensures left == right,
{}

/// Find a delimiter in at most one bounded address token.
fn split(bytes: &[u8], delimiter: u8) -> (index: usize)
    requires bytes@.len() <= 45,
    ensures cut(bytes@, index as int, delimiter),
{
    let mut i = 0;
    while i < bytes.len()
        invariant i <= bytes.len() <= 45,
            forall|j: int| 0 <= j < i ==> bytes@[j] != delimiter,
        decreases bytes.len()-i,
    {
        if bytes[i] == delimiter { return i; }
        i += 1;
    }
    i
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

/// Decode a bounded dotted suffix with an exact remaining component count.
fn parse_octets(bytes: &[u8], count: usize) -> (values: Option<Vec<u8>>)
    requires bytes@.len() <= 45, 1 <= count <= 4,
    ensures match values {
        Some(value) => value@.len() == count && octets(bytes@, value@),
        None => !(exists|value: Seq<u8>| value.len() == count && octets(bytes@, value)),
    },
    decreases count,
{
    let index = split(bytes, b'.');
    let value = {
        let value = number::parse(&bytes[..index], 255, true)?;
        value as u8
    };
    let mut out = Vec::new();
    out.push(value);
    if count == 1 {
        if index != bytes.len() { return None; }
        return Some(out);
    }
    if index == bytes.len() { return None; }
    let tail = parse_octets(&bytes[index+1..], count-1)?;
    let mut i = 0;
    while i < tail.len()
        invariant i <= tail.len() == count-1, 1 < count <= 4,
            out@ == seq![value] + tail@.subrange(0, i as int),
            octets(bytes@.subrange(index as int+1, bytes@.len() as int), tail@),
            cut(bytes@, index as int, b'.'),
            number::digits(bytes@.subrange(0, index as int), true),
            number::decimal(bytes@.subrange(0, index as int)) == value,
        decreases tail.len()-i,
    {
        out.push(tail[i]);
        i += 1;
    }
    Some(out)
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

/// Decode at most eight native words, with bounded recursion and no truncation.
fn parse_groups(bytes: &[u8], available: usize, allow_tail: bool) -> (words: Option<Vec<u16>>)
    requires bytes@.len() <= 45, available <= 8,
    ensures match words {
        Some(value) => value@.len() <= available && groups(bytes@, value@, allow_tail),
        None => !(exists|value: Seq<u16>| value.len() <= available && groups(bytes@, value, allow_tail)),
    },
    decreases available,
{
    if bytes.is_empty() { return Some(Vec::new()); }
    if available == 0 { return None; }
    let index = split(bytes, b':');
    let dotted = split(&bytes[..index], b'.') < index;
    if dotted {
        if !allow_tail || index != bytes.len() || bytes.len() > 15 || available < 2 { return None; }
        let values = parse_octets(bytes, 4)?;
        let out = alloc::vec![values[0] as u16*256 + values[1] as u16,
            values[2] as u16*256 + values[3] as u16];
        return Some(out);
    }
    let first = number::parse_hex(&bytes[..index])?;
    let mut out = Vec::new();
    out.push(first);
    if index == bytes.len() { return Some(out); }
    if index+1 == bytes.len() { return None; }
    let tail = parse_groups(&bytes[index+1..], available-1, allow_tail)?;
    let mut i = 0;
    while i < tail.len()
        invariant i <= tail.len() < available <= 8,
            out@ == seq![first] + tail@.subrange(0, i as int),
            cut(bytes@, index as int, b':'), index+1 < bytes.len(),
            number::hex_word(bytes@.subrange(0, index as int), first as int),
            groups(bytes@.subrange(index as int+1, bytes@.len() as int), tail@, allow_tail),
            !(exists|j: int| 0 <= j < index && bytes@[j] == b'.'),
        decreases tail.len()-i,
    {
        out.push(tail[i]);
        i += 1;
    }
    Some(out)
}

/// A possible double-colon marker, including overlapping malformed triples.
pub open spec fn double_at(bytes: Seq<u8>, index: int) -> bool {
    0 <= index && index+1 < bytes.len() && bytes[index] == b':' && bytes[index+1] == b':'
}

/// Locate exactly one compression marker, rejecting multiple or overlapping ones.
fn compression(bytes: &[u8]) -> (position: Result<Option<usize>, ()>)
    requires bytes@.len() <= 45,
    ensures match position {
        Ok(Some(index)) => double_at(bytes@, index as int)
            && forall|j: int| double_at(bytes@, j) ==> j == index,
        Ok(None) => forall|j: int| !double_at(bytes@, j),
        Err(_) => exists|i: int, j: int| double_at(bytes@, i) && double_at(bytes@, j) && i != j,
    },
{
    let mut found: Option<usize> = None;
    let mut i = 0;
    while i+1 < bytes.len()
        invariant i <= 45, bytes@.len() <= 45,
            match found {
                Some(index) => double_at(bytes@, index as int) && index < i
                    && forall|j: int| 0 <= j < i && double_at(bytes@, j) ==> j == index,
                None => forall|j: int| 0 <= j < i ==> !double_at(bytes@, j),
            },
        decreases bytes.len()+1-i,
    {
        if bytes[i] == b':' && bytes[i+1] == b':' {
            if found.is_some() { return Err(()); }
            found = Some(i);
        }
        i += 1;
    }
    Ok(found)
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
    pub fn parse(bytes: &[u8]) -> (address: Option<Self>)
        ensures match address {
            Some(value) => value.valid() && value.describes(bytes@),
            None => !(exists|words: Seq<u16>| ipv4(bytes@, words) || ipv6(bytes@, words)),
        },
    {
        if bytes.is_empty() || bytes.len() > 45 { return None; }
        let colon = split(bytes, b':');
        if colon == bytes.len() {
            if bytes.len() > 15 { return None; }
            let values = parse_octets(bytes, 4)?;
            let mut words = [0; 8];
            words[0] = values[0] as u16*256+values[1] as u16;
            words[1] = values[2] as u16*256+values[3] as u16;
            return Some(Self { family: 4, words });
        }
        let gap = match compression(bytes) { Ok(value) => value, Err(()) => return None };
        let mut words = [0; 8];
        match gap {
            None => {
                let parsed = parse_groups(bytes, 8, true)?;
                if parsed.len() != 8 { return None; }
                let mut i = 0;
                while i < 8
                    invariant i <= 8, parsed@.len() == 8,
                        words@.subrange(0, i as int) == parsed@.subrange(0, i as int),
                        groups(bytes@, parsed@, true),
                        forall|j: int| !double_at(bytes@, j),
                    decreases 8-i,
                { words[i] = parsed[i]; i += 1; }
            }
            Some(index) => {
                let left = parse_groups(&bytes[..index], 8, false)?;
                let right = parse_groups(&bytes[index+2..], 8, true)?;
                if left.len()+right.len() >= 8 { return None; }
                let mut i = 0;
                while i < left.len()
                    invariant i <= left.len(), left.len()+right.len() < 8,
                        words@.subrange(0, i as int) == left@.subrange(0, i as int),
                        forall|j: int| i <= j < 8 ==> words@[j] == 0,
                    decreases left.len()-i,
                { words[i] = left[i]; i += 1; }
                let base = 8-right.len();
                let mut i = 0;
                while i < right.len()
                    invariant i <= right.len(), left.len()+right.len() < 8, base == 8-right.len(),
                        words@.subrange(0, left@.len() as int) == left@,
                        forall|j: int| left@.len() <= j < base ==> words@[j] == 0,
                        words@.subrange(base as int, base as int+i as int) == right@.subrange(0, i as int),
                    decreases right.len()-i,
                { words[base+i] = right[i]; i += 1; }
                proof {
                    assert(words@ =~= left@ + Seq::new((8-left@.len()-right@.len()) as nat, |_: int| 0u16) + right@);
                }
            }
        }
        Some(Self { family: 6, words })
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
