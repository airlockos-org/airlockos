//! Maintained packet-codec boundary. smoltcp owns packet fields, checksums and
//! NDP encoding; etherparse owns extension traversal and truncated-header views.
//! These functions interpret private bytes and perform specified field updates.
//! They do not select interfaces, authorize addresses, admit flows or choose rules.
//!
//! Dependency assumptions: checked library views bound all getters; interpretation
//! is stable on unchanged private bytes and on their exact IP-length prefix.
//! Mutable views preserve unrelated fields and fill complete pseudo-checksums.
//! Incremental quote repairs use internet-checksum's RFC 1624 implementation.

use super::{Tcp, Tuple};
use airlock_qubes_network::address::Ip;
use alloc::{vec, vec::Vec};
use smoltcp::wire::{
    ArpPacket, ArpRepr, EthernetAddress, EthernetFrame, Icmpv4Packet, Icmpv6Packet, IpAddress,
    IpVersion, Ipv4Cidr, Ipv4Packet, Ipv6Cidr, Ipv6OptionRepr, Ipv6OptionsIterator, Ipv6Packet,
    NdiscNeighborFlags, NdiscRepr, TcpPacket, UdpPacket,
};
use vstd::prelude::*;

verus! {

/// Ethernet fields copied from smoltcp's checked frame view.
pub(crate) struct Ethernet {
    /// Native sender MAC.
    pub source: [u8; 6],
    /// Native recipient MAC.
    pub destination: [u8; 6],
    /// Native EtherType number.
    pub protocol: u16,
}

/// Private library observations; Airlock's wire module decides acceptance.
pub(crate) struct Datagram {
    /// Address and transport fields, still without native interface authority.
    pub tuple: Tuple,
    /// Complete IP length, excluding Ethernet padding.
    pub total: usize,
    /// Transport start after the decoded IP/extension headers.
    pub header: usize,
    /// TTL/hop limit before routing.
    pub hop: u8,
    /// Complete header checksum for IPv4; IPv6 has no header checksum.
    pub header_checksum: bool,
    /// Library transport checksum result with the exact IP pseudo-header.
    pub checksum: bool,
    /// UDP's own declared length, zero for other transports.
    pub udp_length: usize,
    /// Transmitted UDP checksum, retained to reject the IPv6 zero-checksum case.
    pub udp_checksum: u16,
    /// ICMP type, zero for TCP/UDP.
    pub kind: u8,
    /// ICMP code, zero for TCP/UDP.
    pub code: u8,
    /// TCP flags and sequence fields, neutral for other transports.
    pub tcp: Tcp,
    /// Fragment header/flags indicate a non-atomic fragment.
    pub fragmented: bool,
    /// Fragment payload offset; zero for unfragmented and first-fragment packets.
    pub fragment_offset: usize,
    /// Number of fragment headers, including atomic ones.
    pub fragment_headers: usize,
    /// Number of decoded IPv6 extension headers.
    pub extensions: usize,
    /// Native IPv6 option type bytes, preserving their action bits.
    pub options: Vec<u8>,
    /// A routing header is present, including obsolete source-routing forms.
    pub routing: bool,
    /// AH is present; address translation cannot preserve its authentication.
    pub authenticated: bool,
}

/// Native Ethernet/IPv4 ARP observation.
pub(crate) struct Arp {
    /// Request/reply operation.
    pub operation: u16,
    /// Sender's link address.
    pub source_mac: [u8; 6],
    /// Sender's IPv4 address.
    pub source: [u8; 4],
    /// Target's link address.
    pub target_mac: [u8; 6],
    /// Target's IPv4 address.
    pub target: [u8; 4],
}

/// Standard-library address interpretation used by the checksum implementation.
pub(crate) uninterp spec fn datagram_value(bytes: Seq<u8>) -> Option<Datagram>;

/// Decode one complete datagram; all application acceptance remains in wire.
#[verifier::external_body]
pub(crate) fn datagram(bytes: &[u8]) -> (data: Option<Datagram>)
    ensures data == datagram_value(bytes@), data.is_some() ==>
        data.unwrap().tuple.src.valid() && data.unwrap().tuple.dst.valid()
        && 20 <= data.unwrap().header <= 256
        && data.unwrap().header <= data.unwrap().total <= bytes@.len()
        && data.unwrap().total <= super::DATAGRAM_BYTES
        && data.unwrap().options@.len() <= 256
        && (data.unwrap().tuple.proto != 6 && data.unwrap().tuple.proto != 17 ==> data.unwrap().tuple.dport == 0)
        && datagram_value(bytes@.take(data.unwrap().total as int)) == data,
{
    let header = native_header(bytes, false)?;
    let payload = &bytes[header.offset..header.total];
    let mut data = Datagram {
        tuple: Tuple { src: header.source, dst: header.destination, sport: 0, dport: 0, proto: header.protocol },
        total: header.total, header: header.offset, hop: header.hop,
        header_checksum: header.checksum, checksum: false, udp_length: 0, udp_checksum: 0,
        kind: 0, code: 0, tcp: Tcp::default(), fragmented: header.fragmented, fragment_offset: header.fragment_offset, fragment_headers: header.fragment_headers,
        extensions: header.extensions, options: header.options,
        routing: header.routing, authenticated: header.authenticated,
    };
    if header.fragmented { return Some(data); }
    let source = native_address(header.source)?;
    let destination = native_address(header.destination)?;
    match header.protocol {
        6 => {
            let packet = TcpPacket::new_checked(payload).ok()?;
            data.tuple.sport = packet.src_port(); data.tuple.dport = packet.dst_port();
            data.checksum = packet.verify_checksum(&source, &destination);
            data.tcp = Tcp { syn: packet.syn(), ack: packet.ack(), fin: packet.fin(), rst: packet.rst(),
                seq: packet.seq_number().0 as u32, acknowledge: packet.ack_number().0 as u32,
                payload: packet.payload().len() };
        }
        17 => {
            let packet = UdpPacket::new_checked(payload).ok()?;
            data.tuple.sport = packet.src_port(); data.tuple.dport = packet.dst_port();
            data.udp_length = usize::from(packet.len());
            data.udp_checksum = packet.checksum();
            data.checksum = packet.verify_checksum(&source, &destination);
        }
        1 if header.source.version() == 4 => {
            let packet = Icmpv4Packet::new_checked(payload).ok()?;
            data.kind = packet.msg_type().into(); data.code = packet.msg_code();
            data.checksum = packet.verify_checksum();
            if matches!(data.kind, 0 | 8) { data.tuple.sport = packet.echo_ident(); }
        }
        58 if header.source.version() == 6 => {
            let packet = Icmpv6Packet::new_checked(payload).ok()?;
            let (IpAddress::Ipv6(source), IpAddress::Ipv6(destination)) = (source, destination) else { return None; };
            data.kind = packet.msg_type().into(); data.code = packet.msg_code();
            data.checksum = packet.verify_checksum(&source, &destination);
            if matches!(data.kind, 128 | 129) { data.tuple.sport = packet.echo_ident(); }
        }
        _ => (),
    }
    Some(data)
}

/// Decode exact Ethernet fields, never source eligibility.
#[verifier::external_body]
pub(crate) fn ethernet(bytes: &[u8]) -> (frame: Option<Ethernet>)
    ensures frame.is_some() ==> bytes@.len() >= 14,
{
    let frame = EthernetFrame::new_checked(bytes).ok()?;
    Some(Ethernet { source: frame.src_addr().0, destination: frame.dst_addr().0, protocol: frame.ethertype().into() })
}

/// Update only addresses, ports/identifier, hop count and their library checksums.
#[verifier::external_body]
pub(crate) fn rewrite(bytes: &mut [u8], _original: Tuple, new: Tuple, hop: u8)
    requires super::decoded(old(bytes)@).is_some(), _original.valid(), new.valid(), _original.proto == new.proto,
        _original.src.family() == new.src.family(), super::decoded(old(bytes)@).unwrap().tuple == _original,
    ensures final(bytes)@.len() == old(bytes)@.len(), super::decoded(final(bytes)@).is_some(),
        super::decoded(final(bytes)@).unwrap().tuple == new,
        super::decoded(final(bytes)@).unwrap().hop == hop,
{
    let header = native_header(bytes, false).expect("validated IP header");
    let source = native_address(new.src).expect("normalized source");
    let destination = native_address(new.dst).expect("normalized destination");
    match new.proto {
        6 => {
            let mut packet = TcpPacket::new_checked(&mut bytes[header.offset..header.total]).expect("validated TCP");
            packet.set_src_port(new.sport); packet.set_dst_port(new.dport);
            packet.fill_checksum(&source, &destination);
        }
        17 => {
            let mut packet = UdpPacket::new_checked(&mut bytes[header.offset..header.total]).expect("validated UDP");
            packet.set_src_port(new.sport); packet.set_dst_port(new.dport);
            packet.fill_checksum(&source, &destination);
        }
        1 => {
            let mut packet = Icmpv4Packet::new_checked(&mut bytes[header.offset..header.total]).expect("validated ICMPv4");
            packet.set_echo_ident(new.sport); packet.fill_checksum();
        }
        58 => {
            let mut packet = Icmpv6Packet::new_checked(&mut bytes[header.offset..header.total]).expect("validated ICMPv6");
            let (IpAddress::Ipv6(source), IpAddress::Ipv6(destination)) = (source, destination) else { unreachable!("same-family tuple"); };
            packet.set_echo_ident(new.sport); packet.fill_checksum(&source, &destination);
        }
        _ => unreachable!("validated transport"),
    }
    write_addresses(bytes, new.src, new.dst, Some(hop)).expect("validated mutable IP header");
}

/// Emit Ethernet fields and payload through the maintained representation.
#[verifier::external_body]
pub(crate) fn emit_ethernet(bytes: &mut [u8], source: [u8; 6], destination: [u8; 6], protocol: u16, payload: &[u8])
    requires old(bytes)@.len() == 14 + payload@.len(),
    ensures final(bytes)@.len() == old(bytes)@.len(),
{
    let mut frame = EthernetFrame::new_unchecked(bytes);
    frame.set_src_addr(EthernetAddress(source)); frame.set_dst_addr(EthernetAddress(destination));
    frame.set_ethertype(protocol.into()); frame.payload_mut().copy_from_slice(payload);
}

/// Preserve the existing fixed-header IPv4 emission boundary for resolver traffic.
#[verifier::external_body]
pub(crate) fn emit_ipv4(bytes: &mut [u8], source: [u8; 4], destination: [u8; 4], protocol: u8, hop: u8, payload: &[u8])
    requires old(bytes)@.len() == payload@.len() + 20, payload@.len() <= 65_515,
    ensures final(bytes)@.len() == old(bytes)@.len(),
{
    let mut packet = Ipv4Packet::new_unchecked(bytes);
    packet.set_version(4); packet.set_header_len(20); packet.set_total_len((20 + payload.len()) as u16);
    packet.set_dont_frag(true); packet.set_more_frags(false); packet.set_frag_offset(0);
    packet.set_hop_limit(hop); packet.set_next_header(protocol.into());
    packet.set_src_addr(source.into()); packet.set_dst_addr(destination.into());
    packet.payload_mut().copy_from_slice(payload); packet.fill_checksum();
}

/// Encode the same-family envelope into the caller's exactly sized buffer.
#[verifier::external_body]
pub(crate) fn emit_ip(bytes: &mut [u8], source: Ip, destination: Ip, protocol: u8, payload: &[u8], hop: u8)
    requires source.valid(), destination.valid(), source.family() == destination.family(),
        payload@.len() <= if source.family() == 4 { 65_515usize } else { 65_535usize },
        old(bytes)@.len() == payload@.len() + if source.family() == 4 { 20usize } else { 40usize },
    ensures final(bytes)@.len() == old(bytes)@.len(),
{
    match (native_address(source), native_address(destination)) {
        (Some(IpAddress::Ipv4(source)), Some(IpAddress::Ipv4(destination))) => {
            emit_ipv4(bytes, source.octets(), destination.octets(), protocol, hop, payload);
        }
        (Some(IpAddress::Ipv6(source)), Some(IpAddress::Ipv6(destination))) => {
            let mut packet = Ipv6Packet::new_unchecked(bytes);
            packet.set_version(6); packet.set_payload_len(payload.len() as u16); packet.set_next_header(protocol.into());
            packet.set_hop_limit(hop); packet.set_src_addr(source); packet.set_dst_addr(destination);
            packet.payload_mut().copy_from_slice(payload);
        }
        _ => unreachable!("normalized same-family addresses"),
    }
}

/// Copy the packet library's family tag into its Ethernet protocol number.
#[verifier::external_body]
pub(crate) fn ethertype(bytes: &[u8]) -> (protocol: Option<u16>)
    ensures protocol.is_some() ==> protocol.unwrap() == 0x0800 || protocol.unwrap() == 0x86dd,
{
    match IpVersion::of_packet(bytes).ok()? {
        IpVersion::Ipv4 => Some(0x0800), IpVersion::Ipv6 => Some(0x86dd),
    }
}

/// Standard-library unicast classification; link-local scope is handled separately.
#[verifier::external_body]
pub(crate) fn unicast(address: Ip) -> bool
    requires address.valid(),
{
    match native_address(address) {
        Some(IpAddress::Ipv4(ip)) => !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !ip.is_broadcast() && ip.octets()[0] != 0 && ip.octets()[0] < 224,
        Some(IpAddress::Ipv6(ip)) => !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && ip.to_ipv4_mapped().is_none(),
        _ => false,
    }
}

/// Standard-library link-local scope observation.
#[verifier::external_body]
pub(crate) fn link_local(address: Ip) -> bool
    requires address.valid(),
{ matches!(native_address(address), Some(IpAddress::Ipv6(ip)) if ip.is_unicast_link_local()) }

/// CIDR interpretation supplied by smoltcp for either address family.
pub(crate) uninterp spec fn prefix_matches(address: Ip, bits: u8, destination: Ip) -> bool;

/// Use the same maintained CIDR implementation for IPv4 and IPv6 policy.
#[verifier::external_body]
pub(crate) fn contains(address: Ip, bits: u8, destination: Ip) -> (inside: bool)
    requires address.valid(), destination.valid(), bits <= if address.family() == 4 { 32u8 } else { 128u8 },
    ensures inside == prefix_matches(address, bits, destination),
{
    match (native_address(address), native_address(destination)) {
        (Some(IpAddress::Ipv4(a)), Some(IpAddress::Ipv4(b))) => Ipv4Cidr::new(a, bits).contains_addr(&b),
        (Some(IpAddress::Ipv6(a)), Some(IpAddress::Ipv6(b))) => Ipv6Cidr::new(a, bits).contains_addr(&b),
        _ => false,
    }
}

/// IPv4 broadcast computation remains a library operation, with no IPv6 analogue.
#[verifier::external_body]
pub(crate) fn broadcast(address: [u8; 4], bits: u8) -> Option<[u8; 4]>
    requires bits <= 32,
{ Ipv4Cidr::new(address.into(), bits).broadcast().map(|address| address.octets()) }

/// IPv4 network-block computation remains in the maintained CIDR implementation.
#[verifier::external_body]
pub(crate) fn network(address: [u8; 4], bits: u8) -> [u8; 4]
    requires bits <= 32,
{ Ipv4Cidr::new(address.into(), bits).network().address().octets() }

/// Build the existing IPv4 resolver's UDP datagram, including pseudo-checksum.
#[verifier::external_body]
pub(crate) fn emit_udp(bytes: &mut [u8], source: [u8; 4], destination: [u8; 4], sport: u16, dport: u16, payload: &[u8])
    requires old(bytes)@.len() == 8 + payload@.len(), old(bytes)@.len() <= 65_535,
    ensures final(bytes)@.len() == old(bytes)@.len(),
{
    let mut packet = UdpPacket::new_unchecked(bytes);
    packet.set_src_port(sport); packet.set_dst_port(dport); packet.set_len((8 + payload.len()) as u16);
    packet.payload_mut().copy_from_slice(payload);
    packet.fill_checksum(&IpAddress::Ipv4(source.into()), &IpAddress::Ipv4(destination.into()));
}

/// Interpret an ARP packet using smoltcp's checked representation.
#[verifier::external_body]
pub(crate) fn arp(bytes: &[u8]) -> Option<Arp> {
    let packet = ArpPacket::new_checked(bytes).ok()?;
    match ArpRepr::parse(&packet).ok()? {
        ArpRepr::EthernetIpv4 { operation: op, source_hardware_addr: sha, source_protocol_addr: spa, target_hardware_addr: tha, target_protocol_addr: tpa } =>
            Some(Arp { operation: op.into(), source_mac: sha.0, source: spa.octets(), target_mac: tha.0, target: tpa.octets() }),
        _ => None,
    }
}

/// Encode exactly the caller-supplied ARP fields; the caller owns neighbor policy.
#[verifier::external_body]
pub(crate) fn emit_arp(bytes: &mut [u8], fields: Arp)
    requires old(bytes)@.len() == 28,
    ensures final(bytes)@.len() == 28,
{
    let repr = ArpRepr::EthernetIpv4 { operation: fields.operation.into(), source_hardware_addr: EthernetAddress(fields.source_mac),
        source_protocol_addr: fields.source.into(), target_hardware_addr: EthernetAddress(fields.target_mac), target_protocol_addr: fields.target.into() };
    repr.emit(&mut ArpPacket::new_unchecked(bytes));
}

/// Set a caller-selected ICMP type, code and MTU, refreshing its checksum.
/// Eligibility, quote length and message selection belong to the verified caller.
#[verifier::external_body]
pub(crate) fn emit_icmp(bytes: &mut [u8], source: Ip, destination: Ip, kind: u8, code: u8, mtu: Option<u32>) -> bool
    requires old(bytes)@.len() >= 8, source.valid(), destination.valid(), source.family() == destination.family(),
    ensures final(bytes)@.len() == old(bytes)@.len(),
{
    match (native_address(source), native_address(destination)) {
        (Some(IpAddress::Ipv4(_)), Some(IpAddress::Ipv4(_))) => {
            if let Some(mtu) = mtu { bytes[4..8].copy_from_slice(&mtu.to_be_bytes()); }
            let mut packet = Icmpv4Packet::new_unchecked(bytes);
            packet.set_msg_type(kind.into()); packet.set_msg_code(code);
            packet.fill_checksum(); true
        }
        (Some(IpAddress::Ipv6(source)), Some(IpAddress::Ipv6(destination))) => {
            let mut packet = Icmpv6Packet::new_unchecked(bytes);
            packet.set_msg_type(kind.into()); packet.set_msg_code(code);
            if let Some(mtu) = mtu { packet.set_pkt_too_big_mtu(mtu); }
            packet.fill_checksum(&source, &destination); true
        }
        _ => false,
    }
}

/// Read only transport bytes actually supplied inside an ICMP quote.
#[verifier::external_body]
pub(crate) fn quote_header(bytes: &[u8]) -> (data: Option<Datagram>)
    ensures data.is_some() ==> data.unwrap().tuple.src.valid() && data.unwrap().tuple.dst.valid()
        && 20 <= data.unwrap().header <= 256 && data.unwrap().header <= bytes@.len()
        && data.unwrap().total <= super::DATAGRAM_BYTES && data.unwrap().options@.len() <= 256
        && (data.unwrap().tuple.proto != 6 && data.unwrap().tuple.proto != 17 ==> data.unwrap().tuple.dport == 0),
{
    let header = native_header(bytes, true)?;
    let payload = bytes.get(header.offset..)?;
    if payload.len() < 8 { return None; }
    let mut tuple = Tuple { src: header.source, dst: header.destination, sport: 0, dport: 0, proto: header.protocol };
    let mut kind = 0; let mut code = 0; let mut udp_checksum = 0;
    match header.protocol {
        6 => { let p = TcpPacket::new_unchecked(payload); tuple.sport = p.src_port(); tuple.dport = p.dst_port(); }
        17 => { let p = etherparse::UdpHeaderSlice::from_slice(payload).ok()?; tuple.sport = p.source_port(); tuple.dport = p.destination_port(); udp_checksum = p.checksum(); }
        1 => { let p = Icmpv4Packet::new_unchecked(payload); kind = p.msg_type().into(); code = p.msg_code(); tuple.sport = p.echo_ident(); }
        58 => { let p = Icmpv6Packet::new_unchecked(payload); kind = p.msg_type().into(); code = p.msg_code(); tuple.sport = p.echo_ident(); }
        _ => (),
    }
    Some(Datagram { tuple, total: header.total, header: header.offset, hop: header.hop,
        header_checksum: header.checksum, checksum: false, udp_length: 0, udp_checksum, kind, code,
        tcp: Tcp::default(), fragmented: header.fragmented, fragment_offset: header.fragment_offset, fragment_headers: header.fragment_headers, extensions: header.extensions,
        options: header.options, routing: header.routing, authenticated: header.authenticated })
}

/// Apply internet-checksum's RFC 1624 address substitution to one selected
/// quoted checksum field. Offset/protocol selection belongs to verified wire.
#[verifier::external_body]
pub(crate) fn quote_address_checksum(bytes: &mut [u8], offset: usize, original: Ip, new: Ip)
    requires offset <= old(bytes)@.len(), 2 <= old(bytes)@.len() - offset,
        original.valid(), new.valid(), original.family() == new.family(),
    ensures final(bytes)@.len() == old(bytes)@.len(),
{
    let checksum = [bytes[offset], bytes[offset + 1]];
    let updated = replace_address_checksum(checksum, original, new).expect("same-family normalized checksum endpoints");
    bytes[offset..offset + 2].copy_from_slice(&updated);
}

/// Apply one selected port/identifier checksum substitution through the library.
#[verifier::external_body]
pub(crate) fn quote_word_checksum(bytes: &mut [u8], offset: usize, original: u16, new: u16)
    requires offset <= old(bytes)@.len(), 2 <= old(bytes)@.len() - offset,
    ensures final(bytes)@.len() == old(bytes)@.len(),
{
    let checksum = [bytes[offset], bytes[offset + 1]];
    let updated = internet_checksum::update(checksum, &original.to_be_bytes(), &new.to_be_bytes());
    bytes[offset..offset + 2].copy_from_slice(&updated);
}

/// Set native quoted transport fields without requiring unreceived TCP bytes.
#[verifier::external_body]
pub(crate) fn quote_ports(bytes: &mut [u8], offset: usize, tuple: Tuple)
    requires offset <= old(bytes)@.len(), 8 <= old(bytes)@.len() - offset, tuple.valid(),
    ensures final(bytes)@.len() == old(bytes)@.len(),
{
    let payload = &mut bytes[offset..];
    match tuple.proto {
        6 => { let mut packet = TcpPacket::new_unchecked(payload); packet.set_src_port(tuple.sport); packet.set_dst_port(tuple.dport); }
        17 => { let mut packet = UdpPacket::new_unchecked(payload); packet.set_src_port(tuple.sport); packet.set_dst_port(tuple.dport); }
        1 => Icmpv4Packet::new_unchecked(payload).set_echo_ident(tuple.sport),
        58 => Icmpv6Packet::new_unchecked(payload).set_echo_ident(tuple.sport),
        _ => unreachable!("validated transport tuple"),
    }
}

/// Set only a checked quoted IP header's endpoints and native header checksum.
#[verifier::external_body]
pub(crate) fn quote_addresses(bytes: &mut [u8], source: Ip, destination: Ip) -> (updated: bool)
    requires source.valid(), destination.valid(), source.family() == destination.family(),
    ensures final(bytes)@.len() == old(bytes)@.len(),
{ write_addresses(bytes, source, destination, None).is_some() }

/// Refresh an outer ICMP checksum using its final family and endpoints.
#[verifier::external_body]
pub(crate) fn icmp_checksum(bytes: &mut [u8], source: Ip, destination: Ip) -> bool {
    match (native_address(source), native_address(destination)) {
        (Some(IpAddress::Ipv4(_)), Some(IpAddress::Ipv4(_))) => match Icmpv4Packet::new_checked(bytes) { Ok(mut p) => { p.fill_checksum(); true }, _ => false },
        (Some(IpAddress::Ipv6(src)), Some(IpAddress::Ipv6(dst))) => match Icmpv6Packet::new_checked(bytes) { Ok(mut p) => { p.fill_checksum(&src, &dst); true }, _ => false },
        _ => false,
    }
}

/// Native ICMP echo type in a quoted prefix.
#[verifier::external_body]
pub(crate) fn echo_kind(bytes: &[u8], family: u8) -> Option<u8> {
    match family {
        4 => Icmpv4Packet::new_checked(bytes).ok().map(|p| p.msg_type().into()),
        6 => Icmpv6Packet::new_checked(bytes).ok().map(|p| p.msg_type().into()),
        _ => None,
    }
}

/// Native fragment identity in a possibly truncated ICMP quotation.
pub(crate) struct FragmentQuote {
    /// Original quoted source address.
    pub source: Ip,
    /// Original quoted destination address.
    pub destination: Ip,
    /// Native fragment header identifier.
    pub id: u32,
    /// Native fragmentable-payload protocol number.
    pub protocol: u8,
    /// Byte offset, identifying whether a transport header may be quoted.
    pub offset: usize,
    /// Decoded extension count before the fragment payload.
    pub extensions: usize,
    /// Fragment-header count, including atomic headers.
    pub fragment_headers: usize,
    /// Pre-fragment native option type bytes.
    pub options: Vec<u8>,
    /// Native routing header presence, rejected by the core profile.
    pub routing: bool,
    /// Native authentication header presence, rejected by the core profile.
    pub authenticated: bool,
}

/// Copy only the original fragment identity from maintained header views.
#[verifier::external_body]
pub(crate) fn fragment_quote(bytes: &[u8]) -> (quote: Option<FragmentQuote>)
    ensures quote.is_some() ==> quote.unwrap().source.valid() && quote.unwrap().source.family() == 6
        && quote.unwrap().destination.valid() && quote.unwrap().destination.family() == 6,
{
    let header = native_header(bytes, true)?;
    let fragment = header.fragment?;
    if !header.fragmented { return None; }
    Some(FragmentQuote { source: header.source, destination: header.destination,
        id: fragment.id, protocol: fragment.protocol, offset: fragment.offset,
        extensions: header.extensions, fragment_headers: header.fragment_headers, options: header.options,
        routing: header.routing, authenticated: header.authenticated })
}

/// Rewrite only quoted IPv6 endpoints and fragment identifier, leaving any
/// quoted transport bytes and payload unchanged. The caller repairs a quoted
/// first fragment's transport fields separately before using this effect.
#[verifier::external_body]
pub(crate) fn rewrite_fragment_quote(bytes: &mut [u8], source: Ip, destination: Ip, id: u32) -> bool
    requires source.valid(), destination.valid(), source.family() == 6, destination.family() == 6,
    ensures final(bytes)@.len() == old(bytes)@.len(),
{
    let Some(header) = native_header(bytes, true) else { return false; };
    let Some(fragment) = header.fragment else { return false; };
    let Some(raw) = bytes.get_mut(fragment.start..fragment.start + 8) else { return false; };
    let Ok((mut native, _)) = etherparse::Ipv6FragmentHeader::from_slice(raw) else { return false; };
    native.identification = id; raw.copy_from_slice(&native.to_bytes());
    write_addresses(bytes, source, destination, None).is_some()
}

/// Copy an actual non-atomic IPv6 fragment from checked maintained views.
/// Prefix consistency, scope, interval admission and expiry remain in Reassembly.
#[verifier::external_body]
pub(crate) fn fragment(bytes: &[u8]) -> (part: Option<crate::fragment::Part>)
    requires bytes@.len() <= super::FRAME_BYTES,
    ensures part.is_some() ==> part.unwrap().source.valid() && part.unwrap().source.family() == 6
        && part.unwrap().destination.valid() && part.unwrap().destination.family() == 6
        && part.unwrap().layout.valid() && part.unwrap().prefix@.len() == part.unwrap().layout.prefix
        && part.unwrap().payload@.len() <= super::FRAME_BYTES,
{
    let header = native_header(bytes, false)?;
    let fragment = header.fragment?;
    if !header.fragmented || fragment.start > 248 || fragment.start < 40
        || header.fragment_headers != 1 || fragment.previous >= fragment.start { return None; }
    let payload = bytes.get(fragment.start + 8..header.total)?;
    let mut extensions_after = 0; let mut fragment_headers_after = 0;
    let first_complete = if fragment.offset == 0 {
        let (extensions, protocol, _) = etherparse::Ipv6ExtensionsSlice::from_slice(etherparse::IpNumber(fragment.protocol), &payload[..payload.len().min(216 - (fragment.start - 40))]).ok()?;
        extensions_after = extensions.clone().into_iter().count();
        fragment_headers_after = extensions.clone().into_iter().filter(|extension|
            matches!(extension, etherparse::Ipv6ExtensionSlice::Fragment(_))).count();
        if extensions.is_fragmenting_payload() { false }
        else {
            let transport = &payload[extensions.slice().len()..];
            match protocol.0 {
                6 => TcpPacket::new_checked(transport).is_ok(),
                17 => etherparse::UdpHeaderSlice::from_slice(transport).is_ok(),
                58 => Icmpv6Packet::new_checked(transport).is_ok(),
                _ => false,
            }
        }
    } else { false };
    Some(crate::fragment::Part { source: header.source, destination: header.destination,
        prefix: bytes[..fragment.start].to_vec(),
        layout: crate::fragment::Layout { prefix: fragment.start, previous: fragment.previous, protocol: fragment.protocol,
            chunk: (payload.len().min(crate::MTU - fragment.start - 8) / 8) * 8, id: fragment.id },
        offset: fragment.offset, more: fragment.more, payload: payload.to_vec(), extensions: header.extensions,
        options: header.options, routing: header.routing, authenticated: header.authenticated, extensions_after, fragment_headers_after, first_complete })
}

/// Set only the native IPv6 payload-length field of an already bounded buffer.
#[verifier::external_body]
pub(crate) fn set_ipv6_length(bytes: &mut [u8], length: u16)
    requires old(bytes)@.len() >= 40,
    ensures final(bytes)@.len() == old(bytes)@.len(),
{
    Ipv6Packet::new_unchecked(bytes).set_payload_len(length);
}

/// Emit exactly the caller-selected IPv6 fragment header using etherparse.
#[verifier::external_body]
pub(crate) fn fragment_header(protocol: u8, offset: usize, more: bool, id: u32) -> (bytes: [u8; 8])
    requires offset % 8 == 0, offset <= 65_528,
{
    let offset = etherparse::IpFragOffset::try_from((offset / 8) as u16).expect("bounded aligned fragment offset");
    etherparse::Ipv6FragmentHeader::new(etherparse::IpNumber(protocol), offset, more, id).to_bytes()
}

/// Native neighbor message fields, with no neighbor-cache authority.
pub(crate) struct Ndp {
    /// Original IPv6 source.
    pub source: Ip,
    /// Original IPv6 destination, possibly solicited-node multicast.
    pub destination: Ip,
    /// Requested or advertised target address.
    pub target: Ip,
    /// Source/target link-layer option copied from the native representation.
    pub mac: Option<[u8; 6]>,
    /// Native ICMPv6 type.
    pub kind: u8,
    /// Native ICMPv6 code.
    pub code: u8,
    /// Original IPv6 hop limit.
    pub hop: u8,
    /// Complete ICMPv6 pseudo-checksum result.
    pub checksum: bool,
    /// Native advertisement solicited bit; false for a request.
    pub solicited: bool,
    /// Fragmentation indication, which must never be accepted for NDP.
    pub fragmented: bool,
    /// Number of extension headers, including an atomic fragment header.
    pub extensions: usize,
}

/// Decode neighbor solicitations/advertisements through smoltcp, retaining the
/// observations needed for the caller's independent link and solicitation checks.
#[verifier::external_body]
pub(crate) fn ndp(bytes: &[u8]) -> (message: Option<Ndp>)
    ensures message.is_some() ==> message.unwrap().source.valid() && message.unwrap().source.family() == 6
        && message.unwrap().destination.valid() && message.unwrap().destination.family() == 6
        && message.unwrap().target.valid() && message.unwrap().target.family() == 6,
{
    let header = native_header(bytes, false)?;
    if header.protocol != 58 { return None; }
    let (Some(IpAddress::Ipv6(source)), Some(IpAddress::Ipv6(destination))) = (native_address(header.source), native_address(header.destination)) else { return None; };
    let packet = Icmpv6Packet::new_checked(&bytes[header.offset..header.total]).ok()?;
    let (target, link, solicited) = match NdiscRepr::parse(&packet).ok()? {
        NdiscRepr::NeighborSolicit { target_addr, lladdr } => (target_addr, lladdr, false),
        NdiscRepr::NeighborAdvert { flags, target_addr, lladdr } => (target_addr, lladdr, flags.contains(NdiscNeighborFlags::SOLICITED)),
        _ => return None,
    };
    let mac = match link {
        Some(raw) => Some(raw.as_bytes().try_into().ok()?),
        None => None,
    };
    Some(Ndp { source: header.source, destination: header.destination,
        target: Ip::from_ipv6(target.segments()), mac, kind: packet.msg_type().into(), code: packet.msg_code(),
        hop: header.hop, checksum: packet.verify_checksum(&source, &destination), solicited,
        fragmented: header.fragmented, extensions: header.extensions })
}

/// Encode the selected NDP representation; all address/message admission is in wire/engine.
#[verifier::external_body]
pub(crate) fn emit_ndp(mac: [u8; 6], source: Ip, destination: Ip, target: Ip, advert: bool, router: bool) -> (payload: Option<Vec<u8>>)
    requires source.valid(), destination.valid(), target.valid(),
        source.family() == 6, destination.family() == 6, target.family() == 6,
    ensures payload.is_some() ==> payload.unwrap()@.len() == 32,
{
    let (Some(IpAddress::Ipv6(source)), Some(IpAddress::Ipv6(destination)), Some(IpAddress::Ipv6(target_addr))) =
        (native_address(source), native_address(destination), native_address(target)) else { return None; };
    let repr = if advert {
        let mut flags = NdiscNeighborFlags::SOLICITED | NdiscNeighborFlags::OVERRIDE;
        if router { flags |= NdiscNeighborFlags::ROUTER; }
        NdiscRepr::NeighborAdvert { flags, target_addr, lladdr: Some(EthernetAddress(mac).into()) }
    } else { NdiscRepr::NeighborSolicit { target_addr, lladdr: Some(EthernetAddress(mac).into()) } };
    let mut bytes = vec![0; repr.buffer_len()];
    let mut packet = Icmpv6Packet::new_unchecked(bytes.as_mut_slice());
    repr.emit(&mut packet); packet.fill_checksum(&source, &destination);
    Some(bytes)
}

}

/// Library-decoded first fragment header and its position in the native chain.
struct NativeFragment {
    /// Offset of the fragment header in the original datagram.
    start: usize,
    /// Offset of the preceding next-header field, or six in the base header.
    previous: usize,
    /// Native fragmentable payload protocol.
    protocol: u8,
    /// Byte offset in the original fragmentable payload.
    offset: usize,
    /// Native more-fragments flag.
    more: bool,
    /// Native reassembly identifier.
    id: u32,
}

/// Private native header snapshot used only inside this library adapter.
struct Header {
    /// Normalized sender.
    source: Ip,
    /// Normalized recipient.
    destination: Ip,
    /// Complete declared length, even for a truncated quote.
    total: usize,
    /// Transport or fragment-payload start in the supplied bytes.
    offset: usize,
    /// Last decoded next-header number.
    protocol: u8,
    /// Original TTL/hop limit.
    hop: u8,
    /// IPv4 header checksum; true for IPv6.
    checksum: bool,
    /// A non-atomic fragment is present.
    fragmented: bool,
    /// Byte offset of the first native fragment.
    fragment_offset: usize,
    /// Total decoded fragment headers, counting atomic headers too.
    fragment_headers: usize,
    /// First fragment header, when present.
    fragment: Option<NativeFragment>,
    /// Decoded extension count.
    extensions: usize,
    /// Raw option types with their original action bits.
    options: Vec<u8>,
    /// Routing-header presence.
    routing: bool,
    /// Authentication-header presence.
    authenticated: bool,
}

/// Convert existing normalized observations to the packet library's standard IP type.
fn native_address(address: Ip) -> Option<IpAddress> {
    if let Some(bytes) = address.ipv4() {
        Some(IpAddress::Ipv4(bytes.into()))
    } else {
        address.ipv6().map(|words| IpAddress::Ipv6(words.into()))
    }
}

/// Decode a bounded extension prefix through etherparse, retaining raw option types.
/// A truncated quote can omit payload, never a header field consumed here.
fn native_header(bytes: &[u8], quoted: bool) -> Option<Header> {
    match IpVersion::of_packet(bytes).ok()? {
        IpVersion::Ipv4 => {
            let p = etherparse::Ipv4HeaderSlice::from_slice(bytes).ok()?;
            let total = usize::from(p.total_len());
            if total < p.slice().len() || (!quoted && total > bytes.len()) {
                return None;
            }
            Some(Header {
                source: Ip::from_ipv4(p.source()),
                destination: Ip::from_ipv4(p.destination()),
                total,
                offset: p.slice().len(),
                protocol: p.protocol().0,
                hop: p.ttl(),
                checksum: Ipv4Packet::new_unchecked(p.slice()).verify_checksum(),
                fragmented: p.more_fragments() || p.fragments_offset().value() != 0,
                fragment_offset: usize::from(p.fragments_offset().byte_offset()),
                fragment_headers: 0,
                fragment: None,
                extensions: 0,
                options: Vec::new(),
                routing: false,
                authenticated: false,
            })
        }
        IpVersion::Ipv6 => {
            let p = etherparse::Ipv6HeaderSlice::from_slice(bytes).ok()?;
            let total = 40 + usize::from(p.payload_length());
            if (!quoted && total > bytes.len()) || total < 40 {
                return None;
            }
            let body = bytes.get(40..total.min(bytes.len()))?;
            // The lax iterator retains validated headers preceding an error.
            // Stop at a non-atomic fragment: bytes after it need not begin with
            // the next header until reassembly. This avoids treating an arbitrary
            // non-first payload as another extension chain.
            let (extensions, final_protocol, _, error) =
                etherparse::Ipv6ExtensionsSlice::from_slice_lax(
                    p.next_header(),
                    &body[..body.len().min(216)],
                );
            let mut options = Vec::new();
            let mut count = 0;
            let mut routing = false;
            let mut authenticated = false;
            let mut offset = 40;
            let mut previous = 6;
            let mut fragment = None;
            let mut fragment_headers = 0;
            let mut protocol = final_protocol;
            let mut fragmented = false;
            let mut fragment_offset = 0;
            for extension in extensions {
                count += 1;
                let length = match extension {
                    etherparse::Ipv6ExtensionSlice::HopByHop(p)
                    | etherparse::Ipv6ExtensionSlice::DestinationOptions(p) => {
                        for option in Ipv6OptionsIterator::new(p.payload()) {
                            options.push(match option.ok()? {
                                Ipv6OptionRepr::Pad1 => 0,
                                Ipv6OptionRepr::PadN(_) => 1,
                                Ipv6OptionRepr::RouterAlert(_) => 5,
                                Ipv6OptionRepr::Unknown { type_, .. } => type_.into(),
                                _ => return None,
                            });
                        }
                        p.slice().len()
                    }
                    etherparse::Ipv6ExtensionSlice::Routing(p) => {
                        routing = true;
                        p.slice().len()
                    }
                    etherparse::Ipv6ExtensionSlice::Authentication(p) => {
                        authenticated = true;
                        p.slice().len()
                    }
                    etherparse::Ipv6ExtensionSlice::Fragment(p) => {
                        fragment_headers += 1;
                        if fragment.is_none() {
                            fragment = Some(NativeFragment {
                                start: offset,
                                previous,
                                protocol: p.next_header().0,
                                offset: usize::from(p.fragment_offset().byte_offset()),
                                more: p.more_fragments(),
                                id: p.identification(),
                            });
                        }
                        if p.is_fragmenting_payload() {
                            fragmented = true;
                            fragment_offset = usize::from(p.fragment_offset().byte_offset());
                            if !quoted || fragment_offset != 0 {
                                protocol = p.next_header();
                                offset += 8;
                                break;
                            }
                        }
                        8
                    }
                };
                previous = offset;
                offset += length;
            }
            if !fragmented && error.is_some() {
                return None;
            }
            Some(Header {
                source: Ip::from_ipv6(core::net::Ipv6Addr::from(p.source()).segments()),
                destination: Ip::from_ipv6(core::net::Ipv6Addr::from(p.destination()).segments()),
                total,
                offset,
                protocol: protocol.0,
                hop: p.hop_limit(),
                checksum: true,
                fragmented,
                fragment_offset,
                fragment_headers,
                fragment,
                extensions: count,
                options,
                routing,
                authenticated,
            })
        }
    }
}

/// Mutate only an already checked IP header, including truncated ICMP quotes.
fn write_addresses(bytes: &mut [u8], source: Ip, destination: Ip, hop: Option<u8>) -> Option<()> {
    match (native_address(source)?, native_address(destination)?) {
        (IpAddress::Ipv4(src), IpAddress::Ipv4(dst)) => {
            etherparse::Ipv4HeaderSlice::from_slice(bytes).ok()?;
            let mut p = Ipv4Packet::new_unchecked(bytes);
            p.set_src_addr(src);
            p.set_dst_addr(dst);
            if let Some(hop) = hop {
                p.set_hop_limit(hop);
            }
            p.fill_checksum();
        }
        (IpAddress::Ipv6(src), IpAddress::Ipv6(dst)) => {
            etherparse::Ipv6HeaderSlice::from_slice(bytes).ok()?;
            let mut p = Ipv6Packet::new_unchecked(bytes);
            p.set_src_addr(src);
            p.set_dst_addr(dst);
            if let Some(hop) = hop {
                p.set_hop_limit(hop);
            }
        }
        _ => return None,
    }
    Some(())
}

/// Apply the maintained incremental checksum implementation to standard IP octets.
fn replace_address_checksum(checksum: [u8; 2], old: Ip, new: Ip) -> Option<[u8; 2]> {
    match (native_address(old)?, native_address(new)?) {
        (IpAddress::Ipv4(old), IpAddress::Ipv4(new)) => Some(internet_checksum::update(
            checksum,
            &old.octets(),
            &new.octets(),
        )),
        (IpAddress::Ipv6(old), IpAddress::Ipv6(new)) => Some(internet_checksum::update(
            checksum,
            &old.octets(),
            &new.octets(),
        )),
        _ => None,
    }
}
