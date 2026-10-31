//! Domain's DNS codec boundary. These adapters copy library-decoded fields;
//! outstanding-query checks, answer selection, ambiguity rejection, TTL and
//! publication remain in the verified caller. No DNS grammar is duplicated.

use alloc::vec::Vec;
use domain::base::{Message, MessageBuilder, Name, ParsedName, Rtype, ToName};
use domain::rdata::{A, Aaaa, Cname};
use vstd::prelude::*;

verus! {

broadcast use { vstd::seq::group_seq_lemmas, vstd::seq_lib::group_seq_properties,
    vstd::seq::Seq::lemma_as_ref_index, vstd::slice::group_slice_axioms,
    vstd::std_specs::btree::group_btree_axioms };

/// Library-decoded fixed header, without an admission decision.
pub(crate) struct Header {
    /// DNS transaction identifier.
    pub id: u16,
    /// Native opcode value, zero for a normal query/reply.
    pub opcode: u8,
    /// QR bit; the caller requires a response.
    pub response: bool,
    /// TC bit; the caller rejects truncated UDP answers.
    pub truncated: bool,
    /// Native response code, zero for success.
    pub rcode: u8,
    /// Advertised question records.
    pub questions: u16,
    /// Advertised answer records.
    pub answers: u16,
    /// Advertised authority records.
    pub authority: u16,
    /// Advertised additional records.
    pub additional: u16,
}

/// The address/alias record kinds consumed by Airlock's hostname policy.
pub(crate) enum Data {
    /// Native A record bytes.
    V4(/// Exact decoded IPv4 address.
        [u8; 4]),
    /// Native AAAA record words.
    V6(/// Exact decoded IPv6 address.
        [u16; 8]),
    /// Native CNAME target, normalized by domain's canonical-name codec.
    Alias(/// Complete encoded canonical name, including root label.
        Vec<u8>),
    /// Other native type; it cannot populate an address set.
    Other,
}

/// One complete native answer record, retaining class and TTL for validation.
pub(crate) struct Record {
    /// Canonical encoded record owner from domain's name implementation.
    pub owner: Vec<u8>,
    /// Native class, checked against IN by the caller.
    pub class: u16,
    /// Native TTL seconds, before Airlock's cap and monotonic conversion.
    pub ttl: u32,
    /// Library-decoded address, alias or other record kind.
    pub data: Data,
}

/// The library's complete sections and canonical-name traversal result.
pub(crate) struct MessageData {
    /// Exact canonical encoded question name.
    pub name: Vec<u8>,
    /// Native question class.
    pub class: u16,
    /// Native question type.
    pub kind: u16,
    /// Answer section only; other sections cannot supply policy addresses.
    pub records: Vec<Record>,
    /// Domain's bounded CNAME result; None includes invalid/cyclic chains.
    pub canonical: Option<Vec<u8>>,
    /// End of the last additional record, for exact trailing-byte validation.
    pub consumed: usize,
}

impl MessageData {
    /// Only bounded canonical names and a bounded copied answer section exist.
    pub(crate) open spec fn valid(&self) -> bool {
        0 < self.name@.len() <= 255 && self.records@.len() <= super::RECORDS
            && (self.canonical.is_some() ==> 0 < self.canonical.unwrap()@.len() <= 255)
            && (forall|i: int| 0 <= i < self.records@.len() ==> 0 < (#[trigger] self.records@[i]).owner@.len() <= 255
                && match self.records@[i].data { Data::Alias(name) => 0 < name@.len() <= 255, _ => true })
    }
}

/// Domain's fixed-header interpretation. Its correspondence is trusted to the
/// pinned library, including native opcode/count/flag field positions.
pub(crate) uninterp spec fn header_value(bytes: Seq<u8>) -> Option<Header>;

/// Domain's parsed sections/name semantics, not an independent DNS grammar.
pub(crate) uninterp spec fn message_value(bytes: Seq<u8>) -> Option<MessageData>;

/// Copy the fixed native header without applying Airlock acceptance rules.
#[verifier::external_body]
pub(crate) fn header(bytes: &[u8]) -> (header: Option<Header>)
    ensures header == header_value(bytes@),
{
    let message = Message::from_octets(bytes).ok()?;
    let h = message.header();
    let c = message.header_counts();
    Some(Header { id: h.id(), opcode: h.opcode().to_int(), response: h.qr(), truncated: h.tc(), rcode: h.rcode().to_int(),
        questions: c.qdcount(), answers: c.ancount(), authority: c.nscount(), additional: c.arcount() })
}

/// Decode bounded native sections, preserving all fields the caller validates.
/// Trust scope is domain parsing, name canonicalization, record conversion and
/// copying its bounded iterator results. This function makes no policy decision.
#[verifier::external_body]
pub(crate) fn message(bytes: &[u8]) -> (decoded: Option<MessageData>)
    requires header_value(bytes@).is_some(), header_value(bytes@).unwrap().questions == 1,
        header_value(bytes@).unwrap().answers as int + header_value(bytes@).unwrap().authority as int
            + header_value(bytes@).unwrap().additional as int <= super::RECORDS,
    ensures decoded == message_value(bytes@), decoded.is_some() ==> decoded.unwrap().valid()
        && decoded.unwrap().consumed <= bytes@.len()
        && decoded.unwrap().records@.len() == header_value(bytes@).unwrap().answers,
{
    let message = Message::from_octets(bytes).ok()?;
    let question = message.sole_question().ok()?;
    let counts = message.header_counts();
    let mut section = message.answer().ok()?;
    let mut records = Vec::new();
    for _ in 0..counts.ancount() {
        let raw = section.next()?.ok()?;
        let kind = raw.rtype();
        let data = if kind == Rtype::A {
            Data::V4(raw.to_record::<A>().ok()??.data().addr().octets())
        } else if kind == Rtype::AAAA {
            Data::V6(raw.to_record::<Aaaa>().ok()??.data().addr().segments())
        } else if kind == Rtype::CNAME {
            let record = raw.to_record::<Cname<ParsedName<&[u8]>>>().ok()??;
            Data::Alias(record.data().cname().to_canonical_name::<Vec<u8>>().into_octets())
        } else { Data::Other };
        records.push(Record { owner: raw.owner().to_canonical_name::<Vec<u8>>().into_octets(), class: raw.class().to_int(), ttl: raw.ttl().as_secs(), data });
    }
    let mut authority = section.next_section().ok()??;
    for _ in 0..counts.nscount() { authority.next()?.ok()?; }
    let mut additional = authority.next_section().ok()??;
    for _ in 0..counts.arcount() { additional.next()?.ok()?; }
    Some(MessageData { name: question.qname().to_canonical_name::<Vec<u8>>().into_octets(), class: question.qclass().to_int(), kind: question.qtype().to_int(),
        records, canonical: message.canonical_name().map(|name| name.to_canonical_name::<Vec<u8>>().into_octets()), consumed: additional.pos() })
}

/// Library canonicalization of one original validated native hostname.
pub(crate) uninterp spec fn encoded_value(name: Seq<u8>) -> Option<Seq<u8>>;

/// Preserve domain's accepted name language and exact canonical bytes.
#[verifier::external_body]
pub(crate) fn encode(bytes: &[u8]) -> (encoded: Option<Vec<u8>>)
    ensures match encoded {
        Some(name) => encoded_value(bytes@) == Some(name@) && 0 < name@.len() <= 255,
        None => encoded_value(bytes@).is_none(),
    },
{
    let text = core::str::from_utf8(bytes).ok()?;
    let mut name = Name::<Vec<u8>>::vec_from_str(text).ok()?;
    name.make_canonical();
    Some(name.into_octets())
}

/// Delegate complete query emission to domain with the caller's exact ID/type.
#[verifier::external_body]
pub(crate) fn query(name: &[u8], family: u8, transaction: u16) -> (query: Option<Vec<u8>>)
    requires name@.len() <= 255, family == 4 || family == 6,
    ensures query.is_some() ==> query.unwrap()@.len() <= 271,
{
    let name = Name::from_octets(name).ok()?;
    let mut message = MessageBuilder::new_vec();
    message.header_mut().set_id(transaction);
    message.header_mut().set_rd(true);
    let mut question = message.question();
    question.push((name, if family == 4 { Rtype::A } else { Rtype::AAAA })).ok()?;
    Some(question.finish())
}

}
