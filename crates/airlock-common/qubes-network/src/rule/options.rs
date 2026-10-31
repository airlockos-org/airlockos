//! Decode the native space-separated option map with Serde. This boundary owns
//! syntax and unique field binding only; Rule validates the resulting byte claims.

use alloc::vec::Vec;
use vstd::prelude::*;

verus! {

/// Exact native token map, with nonempty keys/values and unique field names.
pub(super) open spec fn tokens(bytes: Seq<u8>, fields: Map<Seq<u8>, Seq<u8>>) -> bool
    decreases bytes.len(),
{
    if fields.dom().is_empty() { bytes.len() == 0 } else {
        exists|end: int, equals: int| crate::address::cut(bytes, end, b' ') && end > 0
            && crate::address::cut(bytes.subrange(0, end), equals, b'=') && 0 < equals < end-1
            && fields.contains_key(bytes.subrange(0, equals))
            && fields[bytes.subrange(0, equals)] == bytes.subrange(equals+1, end)
            && (forall|i: int| equals+1 <= i < end ==> bytes[i] != b'=')
            && if end == bytes.len() { fields.dom() == set![bytes.subrange(0, equals)] }
                else { end+1 < bytes.len() && tokens(bytes.subrange(end+1, bytes.len() as int),
                    fields.remove(bytes.subrange(0, equals))) }
    }
}

/// The first separators fix one field; removing it leaves the same unique map.
proof fn unique_tokens(bytes: Seq<u8>, left: Map<Seq<u8>, Seq<u8>>, right: Map<Seq<u8>, Seq<u8>>)
    requires tokens(bytes, left), tokens(bytes, right),
    ensures left == right,
    decreases bytes.len(),
{
    if left.dom().is_empty() || right.dom().is_empty() { }
    else {
        let (end, equals) = choose|end: int, equals: int| crate::address::cut(bytes, end, b' ') && end > 0
            && crate::address::cut(bytes.subrange(0, end), equals, b'=') && 0 < equals < end-1
            && left.contains_key(bytes.subrange(0, equals))
            && left[bytes.subrange(0, equals)] == bytes.subrange(equals+1, end)
            && (forall|i: int| equals+1 <= i < end ==> bytes[i] != b'=')
            && if end == bytes.len() { left.dom() == set![bytes.subrange(0, equals)] }
                else { end+1 < bytes.len() && tokens(bytes.subrange(end+1, bytes.len() as int), left.remove(bytes.subrange(0, equals))) };
        let (other_end, other_equals) = choose|other_end: int, other_equals: int| crate::address::cut(bytes, other_end, b' ') && other_end > 0
            && crate::address::cut(bytes.subrange(0, other_end), other_equals, b'=') && 0 < other_equals < other_end-1
            && right.contains_key(bytes.subrange(0, other_equals))
            && right[bytes.subrange(0, other_equals)] == bytes.subrange(other_equals+1, other_end)
            && (forall|i: int| other_equals+1 <= i < other_end ==> bytes[i] != b'=')
            && if other_end == bytes.len() { right.dom() == set![bytes.subrange(0, other_equals)] }
                else { other_end+1 < bytes.len() && tokens(bytes.subrange(other_end+1, bytes.len() as int), right.remove(bytes.subrange(0, other_equals))) };
        crate::address::cut_unique(bytes, end, other_end, b' ');
        crate::address::cut_unique(bytes.subrange(0, end), equals, other_equals, b'=');
        if end < bytes.len() {
            unique_tokens(bytes.subrange(end+1, bytes.len() as int), left.remove(bytes.subrange(0, equals)), right.remove(bytes.subrange(0, equals)));
        }
        assert forall|key: Seq<u8>| #[trigger] left.contains_key(key) == right.contains_key(key)
            && (left.contains_key(key) ==> left[key] == right[key]) by {
            if key == bytes.subrange(0, equals) {
                assert(left[key] == bytes.subrange(equals+1, end));
                assert(right[key] == bytes.subrange(equals+1, end));
            }
            else if end < bytes.len() {
                assert(left.remove(bytes.subrange(0, equals)) == right.remove(bytes.subrange(0, equals)));
                assert(left.remove(bytes.subrange(0, equals)).contains_key(key) == left.contains_key(key));
                assert(right.remove(bytes.subrange(0, equals)).contains_key(key) == right.contains_key(key));
                if left.contains_key(key) {
                    assert(left[key] == left.remove(bytes.subrange(0, equals))[key]);
                    assert(right[key] == right.remove(bytes.subrange(0, equals))[key]);
                }
            } else {
                assert(!left.contains_key(key));
                assert(!right.contains_key(key));
            }
        }
        assert(left =~= right);
    }
}

/// Raw byte claims from one complete schema decode; none grant policy authority.
pub(super) struct Options {
    /// Required action spelling, still awaiting semantic validation.
    pub(super) action: Vec<u8>,
    /// Optional protocol spelling; absence has separate network semantics.
    pub(super) proto: Option<Vec<u8>>,
    /// Optional native IPv4 destination spelling.
    pub(super) dst4: Option<Vec<u8>>,
    /// Optional native IPv6 destination spelling.
    pub(super) dst6: Option<Vec<u8>>,
    /// Optional hostname spelling, not a resolution result.
    pub(super) dsthost: Option<Vec<u8>>,
    /// Optional destination port spelling.
    pub(super) dstports: Option<Vec<u8>>,
    /// Optional ICMP type spelling.
    pub(super) icmptype: Option<Vec<u8>>,
    /// Optional special-target spelling.
    pub(super) specialtarget: Option<Vec<u8>>,
}

impl Options {
    /// Equal complete text gives equal presence of the hostname field, before
    /// any DNS result or source-activation decision is considered.
    pub(super) proof fn hostname_agrees(&self, other: Self, bytes: Seq<u8>)
        requires self.describes(bytes), other.describes(bytes),
        ensures self.dsthost.is_some() == other.dsthost.is_some(),
    {
        reveal_byteslit(b"action"); reveal_byteslit(b"proto"); reveal_byteslit(b"dst4"); reveal_byteslit(b"dst6");
        reveal_byteslit(b"dsthost"); reveal_byteslit(b"dstports"); reveal_byteslit(b"icmptype"); reveal_byteslit(b"specialtarget");
        unique_tokens(bytes, self.fields(), other.fields());
        assert(self.fields().contains_key(b"dsthost"@) == self.dsthost.is_some());
        assert(other.fields().contains_key(b"dsthost"@) == other.dsthost.is_some());
    }

    /// Syntax decoding assigns one exact byte claim to each present field.
    pub(super) open spec fn same_claims(&self, other: Self) -> bool {
        self.action@ == other.action@
            && match (self.proto, other.proto) { (None, None) => true, (Some(a), Some(b)) => a@ == b@, _ => false }
            && match (self.dst4, other.dst4) { (None, None) => true, (Some(a), Some(b)) => a@ == b@, _ => false }
            && match (self.dst6, other.dst6) { (None, None) => true, (Some(a), Some(b)) => a@ == b@, _ => false }
            && match (self.dsthost, other.dsthost) { (None, None) => true, (Some(a), Some(b)) => a@ == b@, _ => false }
            && match (self.dstports, other.dstports) { (None, None) => true, (Some(a), Some(b)) => a@ == b@, _ => false }
            && match (self.icmptype, other.icmptype) { (None, None) => true, (Some(a), Some(b)) => a@ == b@, _ => false }
            && match (self.specialtarget, other.specialtarget) { (None, None) => true, (Some(a), Some(b)) => a@ == b@, _ => false }
    }

    /// Exact schema map, independent of its encoded option order.
    pub(super) open spec fn fields(&self) -> Map<Seq<u8>, Seq<u8>> {
        let out = Map::empty().insert(b"action"@, self.action@);
        let out = match self.proto { Some(v) => out.insert(b"proto"@, v@), None => out };
        let out = match self.dst4 { Some(v) => out.insert(b"dst4"@, v@), None => out };
        let out = match self.dst6 { Some(v) => out.insert(b"dst6"@, v@), None => out };
        let out = match self.dsthost { Some(v) => out.insert(b"dsthost"@, v@), None => out };
        let out = match self.dstports { Some(v) => out.insert(b"dstports"@, v@), None => out };
        let out = match self.icmptype { Some(v) => out.insert(b"icmptype"@, v@), None => out };
        match self.specialtarget { Some(v) => out.insert(b"specialtarget"@, v@), None => out }
    }

    /// Every retained claim fits the already bounded native rule value.
    pub(super) open spec fn valid(&self) -> bool {
        0 < self.action@.len() <= 3071
            && (self.proto.is_some() ==> 0 < self.proto.unwrap()@.len() <= 3071)
            && (self.dst4.is_some() ==> 0 < self.dst4.unwrap()@.len() <= 3071)
            && (self.dst6.is_some() ==> 0 < self.dst6.unwrap()@.len() <= 3071)
            && (self.dsthost.is_some() ==> 0 < self.dsthost.unwrap()@.len() <= 3071)
            && (self.dstports.is_some() ==> 0 < self.dstports.unwrap()@.len() <= 3071)
            && (self.icmptype.is_some() ==> 0 < self.icmptype.unwrap()@.len() <= 3071)
            && (self.specialtarget.is_some() ==> 0 < self.specialtarget.unwrap()@.len() <= 3071)
            && (forall|key: Seq<u8>| self.fields().contains_key(key) ==> 0 < self.fields()[key].len() <= 3071)
    }

    /// Whole-input schema meaning, including strict whitespace and key uniqueness.
    pub(super) open spec fn describes(&self, bytes: Seq<u8>) -> bool {
        self.valid() && bytes.len() <= 3071 && vstd::utf8::valid_utf8(bytes) && tokens(bytes, self.fields())
    }

    /// Trust Serde's derived field/duplicate/unknown-name handling and Rust's
    /// string splitting. Input is capped before allocation and at most eight
    /// token pairs are retained. These are syntax claims; Rule owns all network
    /// validation. The contract states assumed library correspondence, not proof.
    #[verifier::external_body]
    pub(super) fn parse(bytes: &[u8]) -> (options: Option<Self>)
        ensures match options {
            Some(value) => value.valid() && value.describes(bytes@)
                && (forall|other: Self| #[trigger] other.describes(bytes@) ==> value.same_claims(other)),
            None => !(exists|value: Options| value.describes(bytes@)),
        },
    {
        use serde::Deserialize;
        use serde::de::value::{BorrowedStrDeserializer, Error, MapDeserializer};

        /// Empty defaults represent absence; supplied empty values are rejected.
        /// Keep the derived decoder inside this explicit library boundary.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawOptions<'a> {
            /// Required disposition token, awaiting semantic validation.
            action: &'a str,
            /// Optional explicit transport protocol.
            #[serde(default)]
            proto: &'a str,
            /// Optional destination in the IPv4 namespace.
            #[serde(default)]
            dst4: &'a str,
            /// Optional destination in the IPv6 namespace.
            #[serde(default)]
            dst6: &'a str,
            /// Optional unresolved hostname condition.
            #[serde(default)]
            dsthost: &'a str,
            /// Optional inclusive destination port range.
            #[serde(default)]
            dstports: &'a str,
            /// Optional native ICMP type condition.
            #[serde(default)]
            icmptype: &'a str,
            /// Optional special destination condition.
            #[serde(default)]
            specialtarget: &'a str,
        }

        if bytes.len() > 3071 { return None; }

        let text = core::str::from_utf8(bytes).ok()?;
        let mut pairs = Vec::new();
        for token in text.split(' ') {
            if pairs.len() == 8 { return None; }
            let (key, value) = token.split_once('=')?;
            if key.is_empty() || value.is_empty() || value.contains('=') { return None; }
            pairs.push((BorrowedStrDeserializer::<Error>::new(key), BorrowedStrDeserializer::<Error>::new(value)));
        }

        let raw = RawOptions::deserialize(MapDeserializer::<_, Error>::new(pairs.into_iter())).ok()?;

        Some(Self {
            action: vstd::slice::slice_to_vec(raw.action.as_bytes()),
            proto: (!raw.proto.is_empty()).then(|| vstd::slice::slice_to_vec(raw.proto.as_bytes())),
            dst4: (!raw.dst4.is_empty()).then(|| vstd::slice::slice_to_vec(raw.dst4.as_bytes())),
            dst6: (!raw.dst6.is_empty()).then(|| vstd::slice::slice_to_vec(raw.dst6.as_bytes())),
            dsthost: (!raw.dsthost.is_empty()).then(|| vstd::slice::slice_to_vec(raw.dsthost.as_bytes())),
            dstports: (!raw.dstports.is_empty()).then(|| vstd::slice::slice_to_vec(raw.dstports.as_bytes())),
            icmptype: (!raw.icmptype.is_empty()).then(|| vstd::slice::slice_to_vec(raw.icmptype.as_bytes())),
            specialtarget: (!raw.specialtarget.is_empty()).then(|| vstd::slice::slice_to_vec(raw.specialtarget.as_bytes())),
        })
    }
}

}
