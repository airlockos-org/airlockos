//! IP observations decoded by Rust's standard address parser. The parser is an
//! explicitly trusted dependency; the model specifies its normalized output and
//! bounded ASCII token guarantees, not a proof of the library. Qubes membership and
//! interface authorization remain separate from a successfully parsed address.

use vstd::prelude::*;

verus! {

broadcast use vstd::seq::Seq::lemma_as_ref_index;

/// First delimiter, or the exact end of a token without that delimiter.
pub open spec fn cut(bytes: Seq<u8>, index: int, delimiter: u8) -> bool {
    0 <= index <= bytes.len()
        && (forall|i: int| 0 <= i < index ==> bytes[i] != delimiter)
        && (index == bytes.len() || bytes[index] == delimiter)
}

/// Two observations of the first delimiter in the same bytes must agree.
pub broadcast proof fn cut_unique(bytes: Seq<u8>, left: int, right: int, delimiter: u8)
    requires #[trigger] cut(bytes, left, delimiter), #[trigger] cut(bytes, right, delimiter),
    ensures left == right,
{
    if left < right { assert(bytes[left] != delimiter); }
    if right < left { assert(bytes[right] != delimiter); }
}

/// Rust's pure `core::net::IpAddr` interpretation, normalized to family and
/// network-order words. The standard library defines this grammar; this crate
/// assumes its result rather than maintaining a second parser or grammar.
pub uninterp spec fn standard_address(bytes: Seq<u8>) -> Option<(u8, Seq<u16>)>;

/// Accepted Rust IP spellings fit one bounded ASCII token, without separators
/// used by the surrounding native Qubes formats, zones or socket brackets.
pub open spec fn token(bytes: Seq<u8>) -> bool {
    0 < bytes.len() <= 45 && forall|i: int| 0 <= i < bytes.len() ==>
        (b'0' <= bytes[i] <= b'9') || (b'a' <= bytes[i] <= b'f')
            || (b'A' <= bytes[i] <= b'F') || bytes[i] == b':' || bytes[i] == b'.'
}

/// A surrounding format's separator cannot occur inside a parsed IP token.
pub broadcast proof fn token_cut(address: Ip, bytes: Seq<u8>, index: int, delimiter: u8)
    requires #[trigger] address.describes(bytes), #[trigger] cut(bytes, index, delimiter),
        !((b'0' <= delimiter <= b'9') || (b'a' <= delimiter <= b'f')
            || (b'A' <= delimiter <= b'F') || delimiter == b':' || delimiter == b'.'),
    ensures index == bytes.len(),
{
    reveal(Ip::describes);
    if index < bytes.len() { assert(bytes[index] != delimiter); }
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
    #[verifier::opaque]
    pub open spec fn describes(&self, bytes: Seq<u8>) -> bool {
        self.valid() && token(bytes) && standard_address(bytes) == Some((self.family(), self.words()))
    }

    /// A pure standard-library parse gives one normalized address per token.
    pub broadcast proof fn unique(left: Self, right: Self, bytes: Seq<u8>)
        requires #[trigger] left.describes(bytes), #[trigger] right.describes(bytes),
        ensures left == right,
    {
        reveal(Ip::describes);
        assert(left.words@ == right.words@);
        assert(left.words =~= right.words);
    }

    /// Decode a complete IPv4/IPv6 token, including a compressed or dotted-tail
    /// IPv6 spelling. Signs, zones, whitespace, brackets and trailing bytes reject.
    /// Trust boundary: safe UTF-8 conversion, core::net::IpAddr parsing and its
    /// octet/segment accessors. Reuse avoids maintaining a second IP parser;
    /// correspondence to the standard-library model and token bounds remains
    /// assumed. The 45-byte cap, private normalized representation and later Qubes checks
    /// bound this dependency and prevent parsed syntax becoming authority.
    #[verifier::external_body]
    pub fn parse(bytes: &[u8]) -> (address: Option<Self>)
        ensures match address {
            Some(value) => value.valid() && value.describes(bytes@) && 0 < bytes@.len() <= 45,
            None => standard_address(bytes@).is_none()
                && !(exists|other: Self| other.describes(bytes@)),
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

    /// Mathematical normalized IPv4 representation used by packet contracts.
    pub closed spec fn v4_value(bytes: [u8; 4]) -> Self {
        Self { family: 4, words: [(bytes[0] as u16 * 256 + bytes[1] as u16) as u16,
            (bytes[2] as u16 * 256 + bytes[3] as u16) as u16, 0, 0, 0, 0, 0, 0] }
    }

    /// Normalized IPv4 data cannot identify two different four-byte addresses.
    pub proof fn v4_injective(left: [u8; 4], right: [u8; 4])
        requires Self::v4_value(left) == Self::v4_value(right),
        ensures left == right,
    {
        assert(left[0] == right[0]); assert(left[1] == right[1]);
        assert(left[2] == right[2]); assert(left[3] == right[3]);
        assert(left@ =~= right@);
    }

    /// Construct normalized IPv4 data from an already decoded packet/DNS address.
    /// This produces address data; interface ownership remains a separate check.
    pub fn from_ipv4(bytes: [u8; 4]) -> (address: Self)
        ensures address.valid(), address == Self::v4_value(bytes), address.family() == 4,
            address.words()[0] == bytes@[0] as int * 256 + bytes@[1] as int,
            address.words()[1] == bytes@[2] as int * 256 + bytes@[3] as int,
    {
        Self { family: 4, words: [crate::library::network_word([bytes[0], bytes[1]]),
            crate::library::network_word([bytes[2], bytes[3]]), 0, 0, 0, 0, 0, 0] }
    }

    /// Construct normalized IPv6 data from standard-library network-order words.
    pub fn from_ipv6(words: [u16; 8]) -> (address: Self)
        ensures address.valid(), address.family() == 6, address.words() == words@,
    { Self { family: 6, words } }

    /// Return IPv4 octets without formatting and reparsing the address.
    pub fn ipv4(&self) -> (bytes: Option<[u8; 4]>)
        requires self.valid(),
        ensures bytes.is_some() == (self.family() == 4),
            bytes.is_some() ==> *self == Self::v4_value(bytes.unwrap()),
            bytes.is_some() ==> self.words()[0] == bytes.unwrap()@[0] as int * 256 + bytes.unwrap()@[1] as int
                && self.words()[1] == bytes.unwrap()@[2] as int * 256 + bytes.unwrap()@[3] as int,
    {
        if self.family != 4 { return None; }
        let high = crate::library::network_bytes(self.words[0]);
        let low = crate::library::network_bytes(self.words[1]);
        let bytes = [high[0], high[1], low[0], low[1]];
        proof {
            let rebuilt = Self::v4_value(bytes);
            assert(self.words@ =~= rebuilt.words@);
            assert(self.words =~= rebuilt.words);
        }
        Some(bytes)
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
        let same = self.family == other.family && self.words == other.words;
        proof {
            if same {
                assert(self.words@ =~= other.words@);
                assert(self.words =~= other.words);
            }
        }
        same
    }
}

}
