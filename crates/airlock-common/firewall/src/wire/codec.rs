//! smoltcp field/checksum adapters. Only library parsing and encoding are trusted
//! here. Airlock selects protocols, rejects fragments/options, checks assignments,
//! chooses NAT tuples, decrements TTL and authorizes effects in verified callers.

use super::Tcp;
use alloc::vec;
use smoltcp::wire::{
    ArpOperation, ArpPacket, ArpRepr, EthernetAddress, EthernetFrame, Icmpv4Message, Icmpv4Packet,
    IpAddress, Ipv4Cidr, Ipv4Packet, TcpPacket, UdpPacket,
};
use vstd::prelude::*;

verus! {

broadcast use { vstd::seq::group_seq_lemmas, vstd::seq_lib::group_seq_properties,
    vstd::seq::Seq::lemma_as_ref_index, vstd::slice::group_slice_axioms,
    vstd::std_specs::btree::group_btree_axioms };

/// Fixed library Ethernet fields; payload begins at the standard 14-byte header.
pub(crate) struct Ethernet {
    /// Native source MAC.
    pub source: [u8; 6],
    /// Native destination MAC.
    pub destination: [u8; 6],
    /// Native EtherType number.
    pub protocol: u16,
}

/// Library-decoded IPv4 fields, including checks the caller must enforce.
pub(crate) struct Ipv4 {
    /// Native version field.
    pub version: u8,
    /// Checked header size, including any native options.
    pub header: u8,
    /// Checked total length, excluding Ethernet padding.
    pub total: u16,
    /// Native hop limit before routing.
    pub ttl: u8,
    /// Native IANA transport number.
    pub protocol: u8,
    /// Native sender address.
    pub source: [u8; 4],
    /// Native recipient address.
    pub destination: [u8; 4],
    /// Native more-fragments flag.
    pub fragments: bool,
    /// Native fragment offset.
    pub offset: u16,
    /// Library checksum result over the private IPv4 header.
    pub checksum: bool,
}

/// Complete checked TCP view with its exact control fields and pseudo-checksum.
pub(crate) struct TcpData {
    /// Native source port.
    pub source: u16,
    /// Native destination port.
    pub destination: u16,
    /// Checked TCP header length, including options.
    pub header: u8,
    /// Library pseudo-header checksum result.
    pub checksum: bool,
    /// Native flags, sequence numbers and payload length.
    pub control: Tcp,
}

/// Complete checked UDP view, without an Airlock acceptance decision.
pub(crate) struct Udp {
    /// Native source port.
    pub source: u16,
    /// Native destination port.
    pub destination: u16,
    /// Native UDP length, including its eight-byte header.
    pub length: u16,
    /// Library IPv4 pseudo-header checksum result, including valid zero checksum.
    pub checksum: bool,
}

/// Complete checked ICMP view; non-echo messages have no echo identifier.
pub(crate) struct Icmp {
    /// Native ICMP type number.
    pub kind: u8,
    /// Native type-specific code.
    pub code: u8,
    /// Native echo identifier, zero for a non-echo message.
    pub identifier: u16,
    /// Library ICMP checksum result.
    pub checksum: bool,
}

/// Native Ethernet/IPv4 ARP fields, decoded through smoltcp's representation.
pub(crate) struct Arp {
    /// Native request/reply operation number.
    pub operation: u16,
    /// Native sender MAC.
    pub source_mac: [u8; 6],
    /// Native sender protocol address.
    pub source: [u8; 4],
    /// Native target MAC.
    pub target_mac: [u8; 6],
    /// Native target protocol address.
    pub target: [u8; 4],
}

/// Fixed-header interpretations supplied by the pinned packet library.
pub(crate) uninterp spec fn ethernet_value(bytes: Seq<u8>) -> Option<Ethernet>;

/// IPv4 interpretation includes library length validation and checksum result.
pub(crate) uninterp spec fn ipv4_value(bytes: Seq<u8>) -> Option<Ipv4>;

/// TCP interpretation is parameterized by the exact supplied pseudo-header.
pub(crate) uninterp spec fn tcp_value(bytes: Seq<u8>, source: [u8; 4], destination: [u8; 4]) -> Option<TcpData>;

/// UDP interpretation is parameterized by the exact supplied pseudo-header.
pub(crate) uninterp spec fn udp_value(bytes: Seq<u8>, source: [u8; 4], destination: [u8; 4]) -> Option<Udp>;

/// Native ICMP interpretation, independent of an interface identity.
pub(crate) uninterp spec fn icmp_value(bytes: Seq<u8>) -> Option<Icmp>;

/// Native ARP interpretation, never an address-authority credential.
pub(crate) uninterp spec fn arp_value(bytes: Seq<u8>) -> Option<Arp>;

/// Decode exact Ethernet fields; no source/destination eligibility is inferred.
#[verifier::external_body]
pub(crate) fn ethernet(bytes: &[u8]) -> (decoded: Option<Ethernet>)
    ensures decoded == ethernet_value(bytes@), decoded.is_some() ==> bytes@.len() >= 14,
{
    let frame = EthernetFrame::new_checked(bytes).ok()?;
    Some(Ethernet { source: frame.src_addr().0, destination: frame.dst_addr().0, protocol: frame.ethertype().into() })
}

/// Decode IPv4 metadata and its checksum without applying Airlock restrictions.
#[verifier::external_body]
pub(crate) fn ipv4(bytes: &[u8]) -> (decoded: Option<Ipv4>)
    ensures decoded == ipv4_value(bytes@), decoded.is_some() ==> 20 <= decoded.unwrap().header
        && decoded.unwrap().header <= decoded.unwrap().total && decoded.unwrap().total <= bytes@.len(),
        decoded.is_some() ==> ipv4_value(bytes@.take(decoded.unwrap().total as int)) == decoded,
{
    let p = Ipv4Packet::new_checked(bytes).ok()?;
    Some(Ipv4 { version: p.version(), header: p.header_len(), total: p.total_len(), ttl: p.hop_limit(), protocol: p.next_header().into(),
        source: p.src_addr().octets(), destination: p.dst_addr().octets(), fragments: p.more_frags(), offset: p.frag_offset(), checksum: p.verify_checksum() })
}

/// Decode TCP ports/control and let smoltcp validate its pseudo-checksum.
#[verifier::external_body]
pub(crate) fn tcp(bytes: &[u8], source: [u8; 4], destination: [u8; 4]) -> (decoded: Option<TcpData>)
    ensures decoded == tcp_value(bytes@, source, destination), decoded.is_some() ==>
        20 <= decoded.unwrap().header <= bytes@.len() && decoded.unwrap().control.payload == bytes@.len() - decoded.unwrap().header,
{
    let p = TcpPacket::new_checked(bytes).ok()?;
    Some(TcpData { source: p.src_port(), destination: p.dst_port(), header: p.header_len(),
        checksum: p.verify_checksum(&IpAddress::Ipv4(source.into()), &IpAddress::Ipv4(destination.into())),
        control: Tcp { syn: p.syn(), ack: p.ack(), fin: p.fin(), rst: p.rst(), seq: p.seq_number().0 as u32,
            acknowledge: p.ack_number().0 as u32, payload: p.payload().len() } })
}

/// Decode UDP metadata and its IPv4 pseudo-checksum through the library.
#[verifier::external_body]
pub(crate) fn udp(bytes: &[u8], source: [u8; 4], destination: [u8; 4]) -> (decoded: Option<Udp>)
    ensures decoded == udp_value(bytes@, source, destination), decoded.is_some() ==> 8 <= decoded.unwrap().length <= bytes@.len(),
{
    let p = UdpPacket::new_checked(bytes).ok()?;
    Some(Udp { source: p.src_port(), destination: p.dst_port(), length: p.len(),
        checksum: p.verify_checksum(&IpAddress::Ipv4(source.into()), &IpAddress::Ipv4(destination.into())) })
}

/// Decode ICMP metadata and its checksum, preserving the exact native type.
#[verifier::external_body]
pub(crate) fn icmp(bytes: &[u8]) -> (decoded: Option<Icmp>)
    ensures decoded == icmp_value(bytes@), decoded.is_some() ==> bytes@.len() >= 8,
{
    let p = Icmpv4Packet::new_checked(bytes).ok()?;
    let identifier = if matches!(p.msg_type(), Icmpv4Message::EchoRequest | Icmpv4Message::EchoReply) { p.echo_ident() } else { 0 };
    Some(Icmp { kind: p.msg_type().into(), code: p.msg_code(), identifier, checksum: p.verify_checksum() })
}

/// Decode only the native library's Ethernet/IPv4 ARP representation.
#[verifier::external_body]
pub(crate) fn arp(bytes: &[u8]) -> (decoded: Option<Arp>)
    ensures decoded == arp_value(bytes@), decoded.is_some() ==> bytes@.len() >= 28,
{
    let packet = ArpPacket::new_checked(bytes).ok()?;
    match ArpRepr::parse(&packet).ok()? {
        ArpRepr::EthernetIpv4 { operation: op, source_hardware_addr: sha, source_protocol_addr: spa, target_hardware_addr: tha, target_protocol_addr: tpa } =>
            Some(Arp { operation: op.into(), source_mac: sha.0, source: spa.octets(), target_mac: tha.0, target: tpa.octets() }),
        _ => None,
    }
}

/// Emit Ethernet fields and copy exactly one supplied payload using smoltcp.
#[verifier::external_body]
pub(crate) fn emit_ethernet(bytes: &mut [u8], source: [u8; 6], destination: [u8; 6], protocol: u16, payload: &[u8])
    requires old(bytes)@.len() == 14 + payload@.len(),
    ensures final(bytes)@.len() == old(bytes)@.len(), ethernet_value(final(bytes)@).is_some()
        && ethernet_value(final(bytes)@).unwrap() == (Ethernet { source, destination, protocol })
        && final(bytes)@.skip(14) == payload@,
{
    let mut frame = EthernetFrame::new_unchecked(bytes);
    frame.set_src_addr(EthernetAddress(source)); frame.set_dst_addr(EthernetAddress(destination));
    frame.set_ethertype(protocol.into()); frame.payload_mut().copy_from_slice(payload);
}

/// Emit a fresh IPv4 header and checksum around the unchanged supplied payload.
#[verifier::external_body]
pub(crate) fn emit_ipv4(bytes: &mut [u8], source: [u8; 4], destination: [u8; 4], protocol: u8, ttl: u8, payload: &[u8])
    requires old(bytes)@.len() == 20 + payload@.len(), old(bytes)@.len() <= super::super::MTU,
    ensures final(bytes)@.len() == old(bytes)@.len(), ipv4_value(final(bytes)@) == Some(Ipv4 { version: 4, header: 20,
        total: final(bytes)@.len() as u16, ttl, protocol, source, destination, fragments: false, offset: 0, checksum: true }),
        final(bytes)@.skip(20) == payload@,
{
    let mut ip = Ipv4Packet::new_unchecked(bytes);
    ip.set_version(4); ip.set_header_len(20); ip.set_total_len((20 + payload.len()) as u16);
    ip.clear_flags(); ip.set_dont_frag(true); ip.set_hop_limit(ttl); ip.set_next_header(protocol.into());
    ip.set_src_addr(source.into()); ip.set_dst_addr(destination.into()); ip.payload_mut().copy_from_slice(payload); ip.fill_checksum();
}

/// Library CIDR meaning, including the all-address /0 prefix.
pub(crate) open spec fn prefix_matches(address: [u8; 4], bits: u8, destination: [u8; 4]) -> bool {
    bits == 0 || (bits <= 32 && {
        let a = ((address[0] as u32) << 24) | ((address[1] as u32) << 16) | ((address[2] as u32) << 8) | address[3] as u32;
        let b = ((destination[0] as u32) << 24) | ((destination[1] as u32) << 16) | ((destination[2] as u32) << 8) | destination[3] as u32;
        (a >> (32 - bits)) == (b >> (32 - bits))
    })
}

/// Delegate prefix comparison to smoltcp; no parallel CIDR algorithm.
#[verifier::external_body]
pub(crate) fn contains(address: [u8; 4], bits: u8, destination: [u8; 4]) -> (contains: bool)
    requires bits <= 32, ensures contains == prefix_matches(address, bits, destination),
{ Ipv4Cidr::new(address.into(), bits).contains_addr(&destination.into()) }

/// Delegate broadcast-address computation to the library's CIDR representation.
#[verifier::external_body]
pub(crate) fn broadcast(address: [u8; 4], bits: u8) -> Option<[u8; 4]>
    requires bits <= 32,
{ Ipv4Cidr::new(address.into(), bits).broadcast().map(|address| address.octets()) }

/// Delegate network-block computation to the library's CIDR representation.
#[verifier::external_body]
pub(crate) fn network(address: [u8; 4], bits: u8) -> [u8; 4]
    requires bits <= 32,
{ Ipv4Cidr::new(address.into(), bits).network().address().octets() }

/// Replace TCP port fields and checksum through the library's mutable view.
#[verifier::external_body]
pub(crate) fn tcp_ports(bytes: &mut [u8], _original: super::Tuple, new: super::Tuple)
    requires tcp_value(old(bytes)@, _original.src, _original.dst).is_some(), old(bytes)@.len() >= 20,
    ensures final(bytes)@.len() == old(bytes)@.len(),
        tcp_value(final(bytes)@, new.src, new.dst) == Some(TcpData { source: new.sport, destination: new.dport,
            header: tcp_value(old(bytes)@, _original.src, _original.dst).unwrap().header, checksum: true,
            control: tcp_value(old(bytes)@, _original.src, _original.dst).unwrap().control }),
        final(bytes)@.skip(tcp_value(old(bytes)@, _original.src, _original.dst).unwrap().header as int)
            == old(bytes)@.skip(tcp_value(old(bytes)@, _original.src, _original.dst).unwrap().header as int),
{
    let mut p = TcpPacket::new_unchecked(bytes);
    p.set_src_port(new.sport); p.set_dst_port(new.dport);
    p.fill_checksum(&IpAddress::Ipv4(new.src.into()), &IpAddress::Ipv4(new.dst.into()));
}

/// Replace UDP port fields and checksum, preserving the exact datagram payload.
#[verifier::external_body]
pub(crate) fn udp_ports(bytes: &mut [u8], _original: super::Tuple, new: super::Tuple)
    requires udp_value(old(bytes)@, _original.src, _original.dst).is_some(), old(bytes)@.len() >= 8,
    ensures final(bytes)@.len() == old(bytes)@.len(),
        udp_value(final(bytes)@, new.src, new.dst) == Some(Udp { source: new.sport, destination: new.dport,
            length: udp_value(old(bytes)@, _original.src, _original.dst).unwrap().length, checksum: true }),
        final(bytes)@.skip(8) == old(bytes)@.skip(8),
{
    let mut p = UdpPacket::new_unchecked(bytes);
    p.set_src_port(new.sport); p.set_dst_port(new.dport);
    p.fill_checksum(&IpAddress::Ipv4(new.src.into()), &IpAddress::Ipv4(new.dst.into()));
}

/// Replace an ICMP echo identifier and checksum, preserving its other fields.
#[verifier::external_body]
pub(crate) fn echo_identifier(bytes: &mut [u8], identifier: u16)
    requires icmp_value(old(bytes)@).is_some(), old(bytes)@.len() >= 8,
        icmp_value(old(bytes)@).unwrap().kind == 0 || icmp_value(old(bytes)@).unwrap().kind == 8,
    ensures final(bytes)@.len() == old(bytes)@.len(),
        icmp_value(final(bytes)@) == Some(Icmp { identifier, checksum: true,
            kind: icmp_value(old(bytes)@).unwrap().kind, code: icmp_value(old(bytes)@).unwrap().code }),
        final(bytes)@.skip(8) == old(bytes)@.skip(8),
{
    let mut p = Icmpv4Packet::new_unchecked(bytes);
    p.set_echo_ident(identifier); p.fill_checksum();
}

/// Replace only IPv4 addresses, TTL and checksum, retaining its full payload.
#[verifier::external_body]
pub(crate) fn route_header(bytes: &mut [u8], source: [u8; 4], destination: [u8; 4], ttl: u8)
    requires ipv4_value(old(bytes)@).is_some(), ipv4_value(old(bytes)@).unwrap().header == 20,
        20 <= old(bytes)@.len(), ipv4_value(old(bytes)@).unwrap().total == old(bytes)@.len(),
    ensures final(bytes)@.len() == old(bytes)@.len(),
        ipv4_value(final(bytes)@) == Some(Ipv4 { source, destination, ttl, checksum: true,
            ..ipv4_value(old(bytes)@).unwrap() }), final(bytes)@.skip(20) == old(bytes)@.skip(20),
{
    let mut p = Ipv4Packet::new_unchecked(bytes);
    p.set_src_addr(source.into()); p.set_dst_addr(destination.into()); p.set_hop_limit(ttl); p.fill_checksum();
}

/// Emit a standard UDP message for the caller's exact endpoints and payload.
#[verifier::external_body]
pub(crate) fn emit_udp(bytes: &mut [u8], source: [u8; 4], destination: [u8; 4], sport: u16, dport: u16, payload: &[u8])
    requires old(bytes)@.len() == 8 + payload@.len(), old(bytes)@.len() <= super::super::MTU - 20,
    ensures final(bytes)@.len() == old(bytes)@.len(), final(bytes)@.skip(8) == payload@,
        udp_value(final(bytes)@, source, destination) == Some(Udp { source: sport, destination: dport, length: final(bytes)@.len() as u16, checksum: true }),
{
    let length = bytes.len();
    let mut p = UdpPacket::new_unchecked(bytes);
    p.set_src_port(sport); p.set_dst_port(dport); p.set_len(length as u16);
    p.payload_mut().copy_from_slice(payload);
    p.fill_checksum(&IpAddress::Ipv4(source.into()), &IpAddress::Ipv4(destination.into()));
}

/// Set the native ICMP type/code and checksum after the caller fills its payload.
#[verifier::external_body]
pub(crate) fn emit_icmp(bytes: &mut [u8], kind: u8, code: u8)
    requires old(bytes)@.len() >= 8,
    ensures final(bytes)@.len() == old(bytes)@.len(), icmp_value(final(bytes)@).is_some()
        && icmp_value(final(bytes)@).unwrap().kind == kind && icmp_value(final(bytes)@).unwrap().code == code
        && icmp_value(final(bytes)@).unwrap().checksum, final(bytes)@.skip(4) == old(bytes)@.skip(4),
{
    let mut p = Icmpv4Packet::new_unchecked(bytes);
    p.set_msg_type(kind.into()); p.set_msg_code(code); p.fill_checksum();
}

/// Refresh a native ICMP checksum after a caller-owned quote transformation.
#[verifier::external_body]
pub(crate) fn icmp_checksum(bytes: &mut [u8])
    requires old(bytes)@.len() >= 8,
    ensures final(bytes)@.len() == old(bytes)@.len(), icmp_value(final(bytes)@).is_some()
        && icmp_value(final(bytes)@).unwrap().checksum, final(bytes)@.skip(4) == old(bytes)@.skip(4),
{ Icmpv4Packet::new_unchecked(bytes).fill_checksum(); }

/// Convert only an echo request into a checksum-complete native reply.
#[verifier::external_body]
pub(crate) fn echo_reply(bytes: &mut [u8])
    requires icmp_value(old(bytes)@).is_some(), old(bytes)@.len() >= 8,
        icmp_value(old(bytes)@).unwrap().kind == 8, icmp_value(old(bytes)@).unwrap().code == 0,
    ensures final(bytes)@.len() == old(bytes)@.len(), icmp_value(final(bytes)@) == Some(Icmp { kind: 0, code: 0,
        checksum: true, identifier: icmp_value(old(bytes)@).unwrap().identifier }), final(bytes)@.skip(4) == old(bytes)@.skip(4),
{
    let mut p = Icmpv4Packet::new_unchecked(bytes);
    p.set_msg_type(Icmpv4Message::EchoReply); p.fill_checksum();
}

/// Emit the supplied native ARP representation; no neighbor learning occurs.
#[verifier::external_body]
pub(crate) fn emit_arp(bytes: &mut [u8], fields: Arp)
    requires old(bytes)@.len() == 28,
    ensures final(bytes)@.len() == 28, arp_value(final(bytes)@) == Some(fields),
{
    let repr = ArpRepr::EthernetIpv4 { operation: ArpOperation::from(fields.operation), source_hardware_addr: EthernetAddress(fields.source_mac),
        source_protocol_addr: fields.source.into(), target_hardware_addr: EthernetAddress(fields.target_mac), target_protocol_addr: fields.target.into() };
    repr.emit(&mut ArpPacket::new_unchecked(bytes));
}

/// A fixed IPv4 header's fields/checksum depend only on its first twenty bytes;
/// copied transport mutations cannot alter that library interpretation.
#[verifier::external_body]
pub(crate) proof fn fixed_header(before: Seq<u8>, after: Seq<u8>)
    requires ipv4_value(before).is_some(), ipv4_value(before).unwrap().header == 20,
        before.len() >= 20, after.len() >= ipv4_value(before).unwrap().total,
        before.take(20) == after.take(20),
    ensures ipv4_value(after) == ipv4_value(before),
{}

/// A truncated quote retains a complete native IPv4 header.
pub(crate) uninterp spec fn quoted_header_value(bytes: Seq<u8>) -> Option<Ipv4>;

/// Decode only quoted native header fields using a private zero-extended view.
/// This is a library-view adapter, not evidence that unreceived payload existed.
#[verifier::external_body]
pub(crate) fn quoted_header(bytes: &[u8]) -> (header: Option<Ipv4>)
    requires 20 <= bytes@.len() <= super::super::MTU,
    ensures header == quoted_header_value(bytes@), header.is_some() ==> 20 <= header.unwrap().header
        && header.unwrap().header <= header.unwrap().total <= super::super::MTU,
{
    let mut extended = vec![0; super::super::MTU];
    extended[..bytes.len()].copy_from_slice(bytes);
    ipv4(extended.as_slice())
}

/// Port-field interpretation of the received eight-byte transport quote.
pub(crate) uninterp spec fn quote_ports_value(bytes: Seq<u8>, protocol: u8) -> (u16, u16);

/// Read only the shared port fields using the protocol's library view. No getter
/// for an unreceived TCP header field or payload is called.
#[verifier::external_body]
pub(crate) fn quote_ports(bytes: &[u8], protocol: u8) -> (ports: (u16, u16))
    requires bytes@.len() >= 8, protocol == 6 || protocol == 17,
    ensures ports == quote_ports_value(bytes@, protocol),
{
    if protocol == 6 { let p = TcpPacket::new_unchecked(bytes); (p.src_port(), p.dst_port()) }
    else { let p = UdpPacket::new_unchecked(bytes); (p.src_port(), p.dst_port()) }
}

/// The library's quoted IPv4 fields depend only on the complete fixed header.
/// Modifying transport bytes cannot alter that header's interpretation.
#[verifier::external_body]
pub(crate) proof fn fixed_quote_header(before: Seq<u8>, after: Seq<u8>)
    requires quoted_header_value(before).is_some(), quoted_header_value(before).unwrap().header == 20,
        28 <= before.len() == after.len() <= super::super::MTU, before.take(20) == after.take(20),
    ensures quoted_header_value(after) == quoted_header_value(before),
{ }

/// Update only addresses and the native checksum in a complete quoted header.
/// smoltcp's field/checksum operations require its header bytes, not the missing
/// transport payload; no new_unchecked payload accessor is used here.
#[verifier::external_body]
pub(crate) fn quoted_addresses(bytes: &mut [u8], source: [u8; 4], destination: [u8; 4])
    requires 28 <= old(bytes)@.len() <= super::super::MTU, quoted_header_value(old(bytes)@).is_some(),
        quoted_header_value(old(bytes)@).unwrap().header == 20,
    ensures final(bytes)@.len() == old(bytes)@.len(),
        quoted_header_value(final(bytes)@) == Some(Ipv4 { source, destination, checksum: true,
            ..quoted_header_value(old(bytes)@).unwrap() }), final(bytes)@.skip(20) == old(bytes)@.skip(20),
{
    let mut p = Ipv4Packet::new_unchecked(bytes);
    p.set_src_addr(source.into()); p.set_dst_addr(destination.into()); p.fill_checksum();
}

/// Standard network-order emission; no first-party integer codec is introduced.
#[verifier::external_body]
pub(crate) fn word_bytes(word: u16) -> (bytes: [u8; 2])
    ensures bytes[0] as int == word as int / 256, bytes[1] as int == word as int % 256,
{ word.to_be_bytes() }

/// The maintained checksum library's RFC 1624 replacement interpretation.
pub uninterp spec fn checksum_value(checksum: [u8; 2], old: Seq<u8>, new: Seq<u8>) -> [u8; 2];

/// Trust only the library's equal-length aligned checksum replacement primitive.
pub assume_specification[ internet_checksum::update ](checksum: [u8; 2], old: &[u8], new: &[u8]) -> (updated: [u8; 2])
    requires old@.len() == new@.len(), old@.len() % 2 == 0,
    ensures updated == checksum_value(checksum, old@, new@),
;

}
