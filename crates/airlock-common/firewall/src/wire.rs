//! Family-neutral datagrams interpreted by maintained packet libraries. Native
//! interface ownership and policy remain separate from every packet claim.
//!
//! smoltcp supplies field access and checksums; etherparse supplies bounded IPv6
//! extension decoding. Their interpretations and standard encoding effects are
//! explicit dependency contracts in codec. Airlock verifies acceptance, length,
//! family/protocol compatibility, hop handling and the inputs to those effects.

use airlock_qubes_network::address::Ip;
use alloc::{vec, vec::Vec};
use vstd::prelude::*;
use vstd::slice::slice_to_vec;

pub(crate) mod codec;

verus! {

broadcast use { vstd::seq_lib::group_seq_properties, vstd::seq::Seq::lemma_as_ref_index };

/// Maximum native Ethernet frame, fitting the existing single-grant transport.
pub const FRAME_BYTES: usize = 4096;

/// Largest ordinary IP datagram; IPv6 jumbograms are outside the bounded profile.
pub(crate) const DATAGRAM_BYTES: usize = 65_575;

/// An address-family-preserving transport tuple, without interface authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Tuple {
    /// Observed sender, or the exact configured address after translation.
    pub src: Ip,
    /// Observed or deliberately redirected recipient in the same family.
    pub dst: Ip,
    /// TCP/UDP source port or ICMP echo identifier.
    pub sport: u16,
    /// TCP/UDP destination port; zero for ICMP.
    pub dport: u16,
    /// IANA protocol: TCP 6, UDP 17, ICMPv4 1 or ICMPv6 58.
    pub proto: u8,
}

#[cfg(verus_keep_ghost)]
impl vstd::std_specs::cmp::PartialEqSpecImpl for Tuple {
    open spec fn obeys_eq_spec() -> bool { true }

    open spec fn eq_spec(&self, other: &Self) -> bool { *self == *other }
}

/// Transport control observations used by the shared connection state machine.
#[derive(Clone, Copy, Default)]
pub(crate) struct Tcp {
    /// Initial SYN or retransmission.
    pub syn: bool,
    /// Acknowledgement flag.
    pub ack: bool,
    /// Half-close marker.
    pub fin: bool,
    /// Reset marker.
    pub rst: bool,
    /// Wrapping sequence number.
    pub seq: u32,
    /// Wrapping acknowledgement number.
    pub acknowledge: u32,
    /// Application bytes after the complete TCP header.
    pub payload: usize,
}

impl Tcp {
    /// No TCP metadata belongs to UDP or ICMP.
    pub(crate) open spec fn vacant() -> Self {
        Self { syn: false, ack: false, fin: false, rst: false, seq: 0, acknowledge: 0, payload: 0 }
    }


}

impl Tuple {
    /// Same-family supported transport, with nonzero TCP/UDP ports.
    pub(crate) open spec fn valid(&self) -> bool {
        self.src.valid() && self.dst.valid() && self.src.family() == self.dst.family()
            && ((self.proto == 6 || self.proto == 17) && self.sport > 0 && self.dport > 0
                || self.dport == 0 && ((self.proto == 1 && self.src.family() == 4)
                    || (self.proto == 58 && self.src.family() == 6)))
    }

    /// Protocol identity independent of an echo message's request/reply number.
    pub(crate) open spec fn is_icmp(&self) -> bool { self.proto == 1 || self.proto == 58 }

    /// Request type belonging to this tuple's address family.
    pub(crate) open spec fn request_kind(&self) -> u8 { if self.proto == 58 { 128 } else { 8 } }

    /// Reply type belonging to this tuple's address family.
    pub(crate) open spec fn reply_kind(&self) -> u8 { if self.proto == 58 { 129 } else { 0 } }

    /// Both ICMP families use the shared echo/related-flow rules.
    #[verifier::when_used_as_spec(is_icmp)]
    pub(crate) fn icmp(&self) -> (icmp: bool)
        ensures icmp == (self.proto == 1 || self.proto == 58),
    { self.proto == 1 || self.proto == 58 }

    /// Echo request number belonging to this tuple's family.
    #[verifier::when_used_as_spec(request_kind)]
    pub(crate) fn request(&self) -> (kind: u8)
        ensures kind == if self.proto == 58 { 128u8 } else { 8u8 },
    { if self.proto == 58 { 128 } else { 8 } }

    /// Echo reply number belonging to this tuple's family.
    #[verifier::when_used_as_spec(reply_kind)]
    pub(crate) fn reply(&self) -> (kind: u8)
        ensures kind == if self.proto == 58 { 129u8 } else { 0u8 },
    { if self.proto == 58 { 129 } else { 0 } }
}

/// Complete private datagram after any bounded fragment reassembly.
pub(crate) struct Packet<'a> {
    /// Exact IP-length prefix, without Ethernet padding.
    pub bytes: &'a [u8],
    /// Checked transport observation; never an interface selector.
    pub tuple: Tuple,
    /// Remaining TTL/hop limit before forwarding.
    pub ttl: u8,
    /// ICMP type, zero for TCP/UDP.
    pub icmp: u8,
    /// Checked TCP control fields, neutral for other protocols.
    pub tcp: Tcp,
    /// Start of the transport header after library-decoded extension headers.
    pub transport: usize,
}

/// Explicit acceptance conditions around the library's private packet snapshot.
pub(crate) open spec fn acceptable(data: codec::Datagram) -> bool {
    data.tuple.valid() && data.header_checksum && data.checksum && !data.fragmented
        && data.fragment_headers <= 1 && data.extensions <= 8 && !data.routing && !data.authenticated
        && (forall|i: int| 0 <= i < data.options@.len() ==> data.options@[i] < 64)
        && ((data.tuple.src.family() == 4 && data.header == 20)
            || (data.tuple.src.family() == 6 && 40 <= data.header <= 256))
        && data.header + 8 <= data.total <= DATAGRAM_BYTES
        && (data.tuple.proto == 17 ==> data.udp_length == data.total - data.header && (data.tuple.src.family() == 6 ==> data.udp_checksum != 0))
        && (data.tuple.proto == 6 ==> data.header + 20 <= data.total
            && !(data.tcp.syn && (data.tcp.fin || data.tcp.rst)))
        && ((data.tuple.proto == 1 || data.tuple.proto == 58) ==>
            match data.tuple.proto {
                1 => (data.kind == 0 || data.kind == 8) && data.code == 0
                    || data.kind == 3 || data.kind == 11 || data.kind == 12,
                _ => (data.kind == 128 || data.kind == 129 || data.kind == 135 || data.kind == 136) && data.code == 0
                    || 1 <= data.kind <= 4,
            })
}

/// Meaning of a supported complete datagram, parameterized by the library snapshot.
pub(crate) open spec fn decoded(bytes: Seq<u8>) -> Option<codec::Datagram> {
    if bytes.len() > DATAGRAM_BYTES { None } else {
        match codec::datagram_value(bytes) {
            Some(data) if acceptable(data) => Some(data),
            _ => None,
        }
    }
}

impl<'a> Packet<'a> {
    /// The exact retained bytes and fields describe one accepted library snapshot.
    pub(crate) open spec fn valid(&self) -> bool {
        self.tuple.valid() && 20 <= self.transport <= 256 && self.transport + 8 <= self.bytes@.len() <= DATAGRAM_BYTES
            && decoded(self.bytes@).is_some() && decoded(self.bytes@).unwrap().tuple == self.tuple
            && decoded(self.bytes@).unwrap().total == self.bytes@.len()
            && decoded(self.bytes@).unwrap().hop == self.ttl
            && decoded(self.bytes@).unwrap().kind == self.icmp
            && decoded(self.bytes@).unwrap().tcp == self.tcp
            && decoded(self.bytes@).unwrap().header == self.transport
    }

    /// Validate supported protocol/family, extension bounds and checksums.
    pub(crate) fn parse(bytes: &'a [u8]) -> (packet: Option<Self>)
        ensures packet.is_some() == decoded(bytes@).is_some(),
            packet.is_some() ==> packet.unwrap().valid(),
    {
        if bytes.len() > DATAGRAM_BYTES { return None; }
        let data = codec::datagram(bytes)?;
        if data.tuple.src.version() != data.tuple.dst.version() { return None; }
        if !data.header_checksum || !data.checksum || data.fragmented || data.fragment_headers > 1 || data.extensions > 8 || data.routing || data.authenticated { return None; }
        if data.options.iter().any(|kind: &u8| -> (reject: bool) ensures reject == (*kind >= 64), { *kind >= 64 }) { return None; }
        let family = data.tuple.src.version();
        if (family == 4 && data.header != 20) || (family == 6 && (data.header < 40 || data.header > 256)) { return None; }
        if data.header + 8 > data.total { return None; }
        if data.tuple.proto == 17 && (data.udp_length != data.total - data.header || family == 6 && data.udp_checksum == 0) { return None; }
        match data.tuple.proto {
            6 | 17 => { if data.tuple.sport == 0 || data.tuple.dport == 0 { return None; } }
            1 if family == 4 => {
                if !(((data.kind == 0 || data.kind == 8) && data.code == 0) || matches!(data.kind, 3 | 11 | 12)) { return None; }
            }
            58 if family == 6 => {
                if !((matches!(data.kind, 128 | 129 | 135 | 136) && data.code == 0) || (1..=4).contains(&data.kind)) { return None; }
            }
            _ => return None,
        }
        if data.tuple.proto == 6 && (data.header + 20 > data.total || data.tcp.syn && (data.tcp.fin || data.tcp.rst)) { return None; }
        proof { assert(acceptable(data)); }
        let bytes = &bytes[..data.total];
        Some(Self { bytes, tuple: data.tuple, ttl: data.hop, icmp: data.kind, tcp: data.tcp, transport: data.header })
    }

    /// Rewrite one accepted same-family packet and decrement its hop count once.
    pub(crate) fn translate(&self, tuple: Tuple) -> (bytes: Option<Vec<u8>>)
        requires self.valid(), tuple.valid(), tuple.proto == self.tuple.proto,
            tuple.src.family() == self.tuple.src.family(),
            tuple.proto == 1 || tuple.proto == 58 ==> self.icmp == if tuple.proto == 1 { 0u8 } else { 129u8 }
                || self.icmp == if tuple.proto == 1 { 8u8 } else { 128u8 },
        ensures bytes.is_some() == (self.ttl > 1),
            bytes.is_some() ==> decoded(bytes.unwrap()@).is_some()
                && decoded(bytes.unwrap()@).unwrap().tuple == tuple
                && decoded(bytes.unwrap()@).unwrap().hop == self.ttl - 1
                && bytes.unwrap()@.len() == self.bytes@.len(),
    {
        if self.ttl <= 1 { return None; }
        let mut bytes = slice_to_vec(self.bytes);
        codec::rewrite(bytes.as_mut_slice(), self.tuple, tuple, self.ttl - 1);
        Some(bytes)
    }
}

/// Ethernet interpretation stays in smoltcp and never supplies client authority.
pub(crate) fn ethernet(bytes: &[u8]) -> (frame: Option<codec::Ethernet>)
    ensures frame.is_some() ==> 14 <= bytes@.len() <= FRAME_BYTES,
{
    if !(14..=FRAME_BYTES).contains(&bytes.len()) { return None; }
    codec::ethernet(bytes)
}

/// Emit only frames that fit the configured link MTU.
pub(crate) fn frame(src: [u8; 6], dst: [u8; 6], protocol: u16, payload: &[u8]) -> (frame: Option<Vec<u8>>)
    ensures frame.is_some() == (payload@.len() <= crate::MTU),
        frame.is_some() ==> frame.unwrap()@.len() == 14 + payload@.len() <= crate::MTU + 14,
{
    if payload.len() > crate::MTU { return None; }
    let mut bytes = vec![0; 14 + payload.len()];
    codec::emit_ethernet(bytes.as_mut_slice(), src, dst, protocol, payload);
    Some(bytes)
}

/// Existing IPv4 resolver/ARP traffic retains the same library encoding path.
pub(crate) fn ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, payload: &[u8], ttl: u8) -> (packet: Option<Vec<u8>>)
    ensures packet.is_some() == (payload@.len() <= crate::MTU - 20 && ttl > 0),
        packet.is_some() ==> packet.unwrap()@.len() == 20 + payload@.len() <= crate::MTU,
{
    if payload.len() > crate::MTU - 20 || ttl == 0 { return None; }
    let mut bytes = vec![0; 20 + payload.len()];
    codec::emit_ipv4(bytes.as_mut_slice(), src, dst, proto, ttl, payload);
    Some(bytes)
}

/// Emit a same-family native IP envelope, excluding IPv6 jumbograms.
pub(crate) fn ip(src: Ip, dst: Ip, proto: u8, payload: &[u8], hop: u8) -> (packet: Option<Vec<u8>>)
    requires src.valid(), dst.valid(), src.family() == dst.family(),
    ensures packet.is_some() ==> packet.unwrap()@.len() <= crate::MTU,
{ envelope(src, dst, proto, payload, hop, crate::MTU) }

/// Build an owned IP envelope within the caller's explicit ordinary-IP budget.
/// Large envelopes are used only for replies to already reassembled IPv6 input.
fn envelope(src: Ip, dst: Ip, proto: u8, payload: &[u8], hop: u8, limit: usize) -> (packet: Option<Vec<u8>>)
    requires src.valid(), dst.valid(), src.family() == dst.family(), limit <= DATAGRAM_BYTES,
    ensures packet.is_some() ==> packet.unwrap()@.len() <= limit,
{
    let header = if src.version() == 4 { 20usize } else { 40usize };
    let maximum = if src.version() == 4 { 65_515usize } else { 65_535usize };
    if hop == 0 || limit < header || payload.len() > maximum || payload.len() > limit - header { return None; }
    let mut bytes = vec![0; header + payload.len()];
    codec::emit_ip(bytes.as_mut_slice(), src, dst, proto, payload, hop);
    Some(bytes)
}

/// Answer an admitted local echo request, retaining its identifier and payload.
/// The caller can reserve a larger response only for originally fragmented IPv6.
pub(crate) fn echo_reply(packet: &Packet<'_>, limit: usize) -> (reply: Option<Vec<u8>>)
    requires packet.valid(), packet.tuple.is_icmp(), packet.icmp == packet.tuple.request_kind(), limit <= DATAGRAM_BYTES,
    ensures reply.is_some() ==> reply.unwrap()@.len() <= limit,
{
    let mut payload = slice_to_vec(&packet.bytes[packet.transport..]);
    if !codec::emit_icmp(payload.as_mut_slice(), packet.tuple.dst, packet.tuple.src, packet.tuple.reply(), 0, None) { return None; }
    envelope(packet.tuple.dst, packet.tuple.src, packet.tuple.proto, &payload, 64, limit)
}

/// Scoped address eligibility comes from the standard library, without another address parser.
pub(crate) fn unicast(ip: Ip) -> bool
    requires ip.valid(),
{ codec::unicast(ip) }

/// Validate a link sender; MAC data still cannot authorize an IP source.
pub(crate) fn mac_unicast(mac: [u8; 6]) -> bool { mac != [0; 6] && mac[0] & 1 == 0 }

/// Generate only bounded, checksum-complete same-family router errors.
pub(crate) fn error(packet: &Packet<'_>, router: Ip, kind: u8, code: u8) -> Option<Vec<u8>>
    requires packet.valid(), router.valid(), router.family() == packet.tuple.src.family(),
{
    if !unicast(packet.tuple.src) || !unicast(packet.tuple.dst)
        || (packet.tuple.icmp() && packet.icmp != packet.tuple.request()) { return None; }
    let length = if router.version() == 6 { packet.bytes.len().min(1232) }
        else { packet.transport + 8 };
    let size = 8 + length;
    let mut payload: Vec<u8> = Vec::with_capacity(size);
    payload.extend_from_slice(&[0u8; 8]);
    payload.extend_from_slice(&packet.bytes[..length]);
    let too_big = router.version() == 6 && kind == 2 || router.version() == 4 && kind == 3 && code == 4;
    let mtu = if too_big { Some(crate::MTU as u32) } else { None };
    if !codec::emit_icmp(payload.as_mut_slice(), router, packet.tuple.src, kind, code, mtu) { return None; }
    let protocol = if router.version() == 6 { 58u8 } else { 1u8 };
    ip(router, packet.tuple.src, protocol, &payload, 64)
}

/// Decode a truncated ICMP quote using the libraries' header-only views.
pub(crate) fn quote(bytes: &[u8]) -> (quote: Option<(Tuple, Vec<u8>)>)
    ensures quote.is_some() ==> quote.unwrap().0.valid() && quote.unwrap().1@.len() <= crate::MTU,
{
    if bytes.len() > crate::MTU { return None; }
    let header = codec::quote_header(bytes)?;
    if (header.fragmented && header.fragment_offset != 0) || header.fragment_headers > 1 || header.routing || header.authenticated || header.extensions > 8
        || !header.header_checksum || header.header + 8 > bytes.len()
        || header.total < header.header + 8
        || header.tuple.src.version() != header.tuple.dst.version()
        || header.options.iter().any(|kind: &u8| -> (reject: bool) ensures reject == (*kind >= 64), { *kind >= 64 }) { return None; }
    let tuple = header.tuple;
    match tuple.proto {
        6 | 17 => if tuple.sport == 0 || tuple.dport == 0 || tuple.proto == 17 && tuple.src.version() == 6 && header.udp_checksum == 0 { return None; },
        1 if tuple.src.version() == 4 => if header.code != 0 || !matches!(header.kind, 0 | 8) { return None; },
        58 if tuple.src.version() == 6 => if header.code != 0 || !matches!(header.kind, 128 | 129) { return None; },
        _ => return None,
    }
    Some((tuple, slice_to_vec(bytes)))
}

/// Incrementally repair only actually quoted checksums and fields.
pub(crate) fn untranslate_quote(bytes: Vec<u8>, original: Tuple, new: Tuple) -> (quote: Option<Vec<u8>>)
    requires original.valid(), new.valid(), original.proto == new.proto, original.src.family() == new.src.family(),
    ensures quote.is_some() ==> quote.unwrap()@.len() == bytes@.len(),
{
    let mut bytes = bytes;
    let header = codec::quote_header(&bytes)?;
    let start = header.header;
    if header.tuple != original || start + 8 > bytes.len() { return None; }
    let offset = match original.proto {
        17 => Some(start + 6),
        6 if bytes.len() >= start + 18 => Some(start + 16),
        1 | 58 => Some(start + 2),
        _ => None,
    };
    if let Some(offset) = offset {
        // An omitted IPv4 UDP checksum stays omitted. IPv6 zero checksums were
        // rejected before flow admission and cannot identify an emitted packet.
        if original.proto != 17 || bytes[offset] != 0 || bytes[offset + 1] != 0 {
            if original.proto != 1 {
                codec::quote_address_checksum(bytes.as_mut_slice(), offset, original.src, new.src);
                codec::quote_address_checksum(bytes.as_mut_slice(), offset, original.dst, new.dst);
                if original.proto != 58 { codec::quote_word_checksum(bytes.as_mut_slice(), offset, original.dport, new.dport); }
            }
            codec::quote_word_checksum(bytes.as_mut_slice(), offset, original.sport, new.sport);
            if original.proto == 17 && bytes[offset] == 0 && bytes[offset + 1] == 0 {
                bytes[offset] = 255; bytes[offset + 1] = 255;
            }
        }
    }
    codec::quote_ports(bytes.as_mut_slice(), start, new);
    if !codec::quote_addresses(bytes.as_mut_slice(), new.src, new.dst) { return None; }
    Some(bytes)
}

/// Only protocol-defined error messages can consult existing related flows.
pub(crate) fn is_error(protocol: u8, kind: u8) -> bool {
    protocol == 1 && matches!(kind, 3 | 11 | 12) || protocol == 58 && (1..=4).contains(&kind)
}

/// Family-correct Time Exceeded or Packet Too Big/fragmentation-needed response.
pub(crate) fn failure(family: u8, expired: bool) -> (u8, u8) {
    if family == 6 { if expired { (3, 0) } else { (2, 0) } }
    else if expired { (11, 0) } else { (3, 4) }
}

/// Match the actual quoted echo type without inventing a complete transport header.
pub(crate) fn quoted_echo(bytes: &[u8], kind: u8) -> bool {
    let Some(header) = codec::quote_header(bytes) else { return false; };
    if header.header + 8 > bytes.len() { return false; }
    codec::echo_kind(&bytes[header.header..], header.tuple.src.version()) == Some(kind)
}

/// Emit a router-owned neighbor solicitation to only the target's multicast group.
pub(crate) fn solicit(mac: [u8; 6], source: Ip, target: Ip) -> (output: Option<Vec<u8>>)
    requires source.valid(), target.valid(), source.family() == 6, target.family() == 6,
    ensures output.is_some() ==> 14 <= output.unwrap()@.len() <= crate::MTU + 14,
{
    let (destination, hardware) = solicited_node(target);
    let payload = codec::emit_ndp(mac, source, destination, target, false, false)?;
    let bytes = ip(source, destination, 58, &payload, 255)?;
    frame(mac, hardware, 0x86dd, &bytes)
}

/// RFC 4291's fixed solicited-node mapping. smoltcp's corresponding address
/// helper is crate-private; this transformation supplies only the missing API.
fn solicited_node(target: Ip) -> (group: (Ip, [u8; 6]))
    requires target.valid(), target.family() == 6,
    ensures group.0.valid(), group.0.family() == 6,
{
    let words = target.ipv6().unwrap();
    let low = words[6] & 255;
    let destination = Ip::from_ipv6([0xff02, 0, 0, 0, 0, 1, 0xff00 | low, words[7]]);
    (destination, [0x33, 0x33, 0xff, low as u8, (words[7] >> 8) as u8, words[7] as u8])
}

/// Compare the complete solicited-node destination, never only a suffix.
pub(crate) fn solicited_for(destination: Ip, target: Ip) -> bool
    requires destination.valid(), target.valid(), target.family() == 6,
{ destination == solicited_node(target).0 }

/// Check the corresponding multicast Ethernet destination on this link.
pub(crate) fn solicited_mac(destination: [u8; 6], target: Ip) -> bool
    requires target.valid(), target.family() == 6,
{ destination == solicited_node(target).1 }

/// Emit a solicited unicast advertisement for the caller's own configured address.
pub(crate) fn advertise(mac: [u8; 6], recipient: [u8; 6], source: Ip, destination: Ip, router: bool) -> (output: Option<Vec<u8>>)
    requires source.valid(), destination.valid(), source.family() == 6, destination.family() == 6,
    ensures output.is_some() ==> 14 <= output.unwrap()@.len() <= crate::MTU + 14,
{
    let payload = codec::emit_ndp(mac, source, destination, source, true, router)?;
    let bytes = ip(source, destination, 58, &payload, 255)?;
    frame(mac, recipient, 0x86dd, &bytes)
}

}
