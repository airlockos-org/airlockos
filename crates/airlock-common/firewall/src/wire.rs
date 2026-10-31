//! Packet library adapter. All offsets used for mutation come from a checked
//! fixed IPv4 header and a checked library transport view. Never decode identity.
//!
//! Dependency contracts: smoltcp new_checked rejects buffers too short for its
//! getters; IPv4 total_len bounds payload; TCP data offset and UDP length bound
//! their payload; checksum verification/fill covers the complete private bytes
//! and supplied pseudo-header. We require software-complete checksums rather
//! than trusting peer checksum-offload metadata. internet-checksum::update is
//! RFC 1624 one's-complement replacement of equal-length network-order words.
//! These codecs do not supply Airlock policy, identity or connection authority.

use alloc::{vec, vec::Vec};

use vstd::prelude::*;
use vstd::slice::slice_to_vec;

pub(crate) mod codec;

verus! {

broadcast use { vstd::std_specs::iter::group_iter_axioms, crate::library::byte_array_equality,
    vstd::std_specs::vec::group_vec_axioms,
    vstd::std_specs::vecdeque::group_vec_dequeue_axioms,
    vstd::set::group_set_lemmas, vstd::seq_lib::group_filter_ensures, vstd::seq::group_seq_lemmas, vstd::seq_lib::group_seq_properties,
    vstd::seq::Seq::lemma_as_ref_index, vstd::slice::group_slice_axioms,
    vstd::std_specs::btree::group_btree_axioms };

/// Largest private input frame accepted, including Ethernet overhead.
pub const FRAME_BYTES: usize = 4096;

/// Accepted transport tuple; ICMP uses the identifier as its source port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Tuple {
    /// Original or translated IPv4 sender.
    pub src: [u8; 4],
    /// Original or translated IPv4 receiver.
    pub dst: [u8; 4],
    /// TCP/UDP source port or echo identifier.
    pub sport: u16,
    /// TCP/UDP destination port; zero for echo.
    pub dport: u16,
    /// IANA transport number: TCP 6, UDP 17, ICMP 1.
    pub proto: u8,
}

/// Exact structural meaning of Rust's compiler-derived tuple equality.
#[cfg(verus_keep_ghost)]
impl vstd::std_specs::cmp::PartialEqSpecImpl for Tuple {
    open spec fn obeys_eq_spec() -> bool { true }

    open spec fn eq_spec(&self, other: &Self) -> bool { *self == *other }
}

/// Validated transport control fields needed by connection tracking.
#[derive(Clone, Copy, Default)]
pub(crate) struct Tcp {
    /// Initial SYN or SYN retransmission.
    pub syn: bool,
    /// ACK flag, not merely a nonzero acknowledgement field.
    pub ack: bool,
    /// Stream half-close marker.
    pub fin: bool,
    /// Connection reset marker.
    pub rst: bool,
    /// Native wrapping TCP sequence number.
    pub seq: u32,
    /// Native wrapping acknowledgement number.
    pub acknowledge: u32,
    /// Application payload bytes, excluding header/options.
    pub payload: usize,
}

/// One complete unfragmented checked IPv4 datagram with verified checksums.
pub(crate) struct Packet<'a> {
    /// Exact IP total-length prefix; Ethernet padding is never forwarded.
    pub bytes: &'a [u8],
    /// Checked transport tuple, never an interface selector.
    pub tuple: Tuple,
    /// Remaining IPv4 hop limit before this router.
    pub ttl: u8,
    /// ICMP type, zero for TCP/UDP.
    pub icmp: u8,
    /// Checked TCP flags/sequence fields, default for other transports.
    pub tcp: Tcp,
}

/// Abstract meaning of a complete supported/checksummed wire datagram. This is
/// the packet library's interpretation, not a second grammar or executable
/// parser. Dependency specifications must connect field/checksum API results to
/// this meaning before the surrounding production bodies can be called proved.
/// Components are tuple, TTL, ICMP type, TCP control fields and application data.
pub(crate) open spec fn decoded(bytes: Seq<u8>) -> Option<(Tuple, u8, u8, Tcp, Seq<u8>)> {
    if !codec::ipv4_value(bytes).is_some() { None }
    else {
        let ip = codec::ipv4_value(bytes).unwrap();
        if ip.version != 4 || ip.header != 20 || ip.fragments || ip.offset != 0 || !ip.checksum
            || ip.total < 28 || ip.total > bytes.len() { None }
        else {
            let data = bytes.subrange(20, ip.total as int);
            if ip.protocol == 6 && codec::tcp_value(data, ip.source, ip.destination).is_some() {
                let tcp = codec::tcp_value(data, ip.source, ip.destination).unwrap();
                if !tcp.checksum || tcp.source == 0 || tcp.destination == 0 || tcp.header < 20
                    || tcp.header > data.len() || (tcp.control.syn && (tcp.control.fin || tcp.control.rst)) { None }
                else { Some((Tuple { src: ip.source, dst: ip.destination, sport: tcp.source, dport: tcp.destination, proto: 6 },
                    ip.ttl, 0, tcp.control, data.skip(tcp.header as int))) }
            } else if ip.protocol == 17 && codec::udp_value(data, ip.source, ip.destination).is_some() {
                let udp = codec::udp_value(data, ip.source, ip.destination).unwrap();
                if !udp.checksum || udp.source == 0 || udp.destination == 0 || udp.length != data.len() { None }
                else { Some((Tuple { src: ip.source, dst: ip.destination, sport: udp.source, dport: udp.destination, proto: 17 },
                    ip.ttl, 0, Tcp::vacant(), data.skip(8))) }
            } else if ip.protocol == 1 && codec::icmp_value(data).is_some() {
                let icmp = codec::icmp_value(data).unwrap();
                if !icmp.checksum || !(((icmp.kind == 0 || icmp.kind == 8) && icmp.code == 0)
                    || icmp.kind == 3 || icmp.kind == 11 || icmp.kind == 12) { None }
                else { Some((Tuple { src: ip.source, dst: ip.destination, sport: if icmp.kind == 0 || icmp.kind == 8 { icmp.identifier } else { 0 }, dport: 0, proto: 1 },
                    ip.ttl, icmp.kind, Tcp::vacant(), data.skip(8))) }
            } else { None }
        }
    }
}

impl Tcp {
    /// No TCP control metadata accompanies another transport.
    pub(crate) open spec fn vacant() -> Self {
        Self { syn: false, ack: false, fin: false, rst: false, seq: 0, acknowledge: 0, payload: 0 }
    }

    /// Construct the empty metadata used for UDP and ICMP observations.
    pub(crate) fn empty() -> (tcp: Self)
        ensures tcp == Self::vacant(),
    { Self { syn: false, ack: false, fin: false, rst: false, seq: 0, acknowledge: 0, payload: 0 } }
}

impl Tuple {
    /// The experiment implements only port-bearing TCP/UDP and echo tuples.
    pub(crate) open spec fn valid(&self) -> bool {
        (self.proto == 6 || self.proto == 17) && self.sport > 0 && self.dport > 0
            || self.proto == 1 && self.dport == 0
    }
}

impl<'a> Packet<'a> {
    /// Checked datagram shape retained across normalized policy decisions.
    pub(crate) open spec fn valid(&self) -> bool {
        28 <= self.bytes@.len() <= FRAME_BYTES - 14 && self.tuple.valid()
            && codec::ipv4_value(self.bytes@).is_some() && codec::ipv4_value(self.bytes@).unwrap().total == self.bytes@.len()
            && (self.tuple.proto == 6 ==> self.bytes@.len() >= 40)
            && decoded(self.bytes@).is_some()
            && decoded(self.bytes@).unwrap().0 == self.tuple
            && decoded(self.bytes@).unwrap().1 == self.ttl
            && decoded(self.bytes@).unwrap().2 == self.icmp
            && decoded(self.bytes@).unwrap().3 == self.tcp
    }

    /// Decode complete datagrams; unsupported headers/fragments never reach policy.
    pub(crate) fn parse(bytes: &'a [u8]) -> (packet: Option<Self>)
        ensures packet.is_some() == (bytes@.len() <= FRAME_BYTES - 14 && decoded(bytes@).is_some()),
            packet.is_some() ==> packet.unwrap().valid()
            && packet.unwrap().bytes@ == bytes@.take(packet.unwrap().bytes@.len() as int),
    {
        if bytes.len() > FRAME_BYTES - 14 { return None; }
        let ghost original = bytes@;
        let ip = codec::ipv4(bytes)?;
        if ip.version != 4 || ip.header != 20 || ip.fragments || ip.offset != 0 || !ip.checksum { return None; }
        let bytes = &bytes[..usize::from(ip.total)];
        let data = &bytes[20..];
        proof {
            assert(bytes@.subrange(20, ip.total as int) =~= original.subrange(20, ip.total as int));
            assert(decoded(bytes@) == decoded(original));
        }
        let mut tuple = Tuple { src: ip.source, dst: ip.destination, sport: 0, dport: 0, proto: ip.protocol };
        let mut tcp = Tcp::empty();
        let mut icmp = 0;
        match ip.protocol {
            6 => {
                let p = codec::tcp(data, ip.source, ip.destination)?;
                if p.header < 20 || !p.checksum || p.source == 0 || p.destination == 0 || (p.control.syn && (p.control.fin || p.control.rst)) { return None; }
                tuple.sport = p.source; tuple.dport = p.destination; tcp = p.control;
            }
            17 => {
                let p = codec::udp(data, ip.source, ip.destination)?;
                if usize::from(p.length) != data.len() || !p.checksum || p.source == 0 || p.destination == 0 { return None; }
                tuple.sport = p.source; tuple.dport = p.destination;
            }
            1 => {
                let p = codec::icmp(data)?;
                if !p.checksum { return None; }
                icmp = p.kind;
                match p.kind {
                    0 | 8 => { if p.code != 0 { return None; } tuple.sport = p.identifier; },
                    3 | 11 | 12 => (),
                    _ => return None,
                }
            }
            _ => return None,
        }
        Some(Self { bytes, tuple, ttl: ip.ttl, icmp, tcp })
    }

    /// NAT a validated datagram and decrement its TTL exactly once.
    pub(crate) fn translate(&self, tuple: Tuple) -> (bytes: Option<Vec<u8>>)
        requires self.valid(), tuple.valid(), tuple.proto == self.tuple.proto,
            tuple.proto == 1 ==> self.icmp == 0 || self.icmp == 8,
        ensures bytes.is_some() == (self.ttl > 1),
            bytes.is_some() ==> bytes.unwrap()@.len() == self.bytes@.len()
                && decoded(bytes.unwrap()@).is_some()
                && decoded(bytes.unwrap()@).unwrap().0 == tuple
                && decoded(bytes.unwrap()@).unwrap().1 == self.ttl - 1
                && decoded(bytes.unwrap()@).unwrap().2 == self.icmp
                && decoded(bytes.unwrap()@).unwrap().3 == self.tcp
                && decoded(bytes.unwrap()@).unwrap().4 == decoded(self.bytes@).unwrap().4,
    {
        if self.ttl <= 1 { return None; }
        let mut bytes = slice_to_vec(self.bytes);
        let ghost initial = bytes@;
        proof {
            assert(self.bytes@.subrange(20, self.bytes@.len() as int) == self.bytes@.skip(20));
        }
        match tuple.proto {
            6 => codec::tcp_ports(&mut bytes.as_mut_slice()[20..], self.tuple, tuple),
            17 => codec::udp_ports(&mut bytes.as_mut_slice()[20..], self.tuple, tuple),
            1 => codec::echo_identifier(&mut bytes.as_mut_slice()[20..], tuple.sport),
            _ => return None,
        }
        proof { codec::fixed_header(initial, bytes@); }
        codec::route_header(bytes.as_mut_slice(), tuple.src, tuple.dst, self.ttl - 1);
        Some(bytes)
    }
}

/// Return a checked Ethernet envelope; multicast/broadcast eligibility is
/// decided by ARP handling rather than accepted as an IPv4 routing shortcut.
pub(crate) fn ethernet(bytes: &[u8]) -> (frame: Option<codec::Ethernet>)
    ensures frame.is_some() ==> 14 <= bytes@.len() <= FRAME_BYTES,
{
    if !(14..=FRAME_BYTES).contains(&bytes.len()) { return None; }
    codec::ethernet(bytes)
}

/// Wrap one bounded datagram in exactly the supplied native Ethernet fields.
pub(crate) fn frame(src: [u8; 6], dst: [u8; 6], protocol: u16, payload: &[u8]) -> (frame: Option<Vec<u8>>)
    ensures frame.is_some() == (payload@.len() <= crate::MTU),
        frame.is_some() ==> frame.unwrap()@.len() == 14 + payload@.len() <= crate::MTU + 14,
{
    if payload.len() > crate::MTU { return None; }
    let mut bytes = vec![0; 14 + payload.len()];
    codec::emit_ethernet(bytes.as_mut_slice(), src, dst, protocol, payload);
    Some(bytes)
}

/// Emit one bounded native IPv4 envelope around an already emitted transport.
pub(crate) fn ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, payload: &[u8], ttl: u8) -> (packet: Option<Vec<u8>>)
    ensures packet.is_some() == (payload@.len() <= crate::MTU - 20 && ttl > 0),
        packet.is_some() ==> packet.unwrap()@.len() == 20 + payload@.len() <= crate::MTU,
{
    if payload.len() > crate::MTU - 20 || ttl == 0 { return None; }
    let mut bytes = vec![0; 20 + payload.len()];
    codec::emit_ipv4(bytes.as_mut_slice(), src, dst, proto, ttl, payload);
    Some(bytes)
}

/// Emit a bounded router error, quoting only IPv4 plus eight transport bytes.
pub(crate) fn error(packet: &Packet<'_>, router: [u8; 4], kind: u8, code: u8) -> (error: Option<Vec<u8>>)
    requires packet.valid(),
    ensures error.is_some() ==> error.unwrap()@.len() <= 56,
{
    if !unicast(packet.tuple.src) || !unicast(packet.tuple.dst)
        || (packet.tuple.proto == 1 && packet.icmp != 8) { return None; }
    let quote = &packet.bytes[..packet.bytes.len().min(28)];
    let mut payload = vec![0; 8 + quote.len()];
    payload.as_mut_slice()[8..].copy_from_slice(quote);
    if kind == 3 && code == 4 {
        payload.as_mut_slice()[6..8].copy_from_slice(&codec::word_bytes(crate::MTU as u16));
    }
    codec::emit_icmp(payload.as_mut_slice(), kind, code);
    ipv4(router, packet.tuple.src, 1, &payload, 64)
}

/// Public IPv4 unicast shape; local/client/address-subnet exclusions are policy.
pub(crate) fn unicast(ip: [u8; 4]) -> bool {
    ip[0] != 0 && ip[0] != 127 && ip[0] < 224 && ip != [255; 4]
}

/// Validate a link sender; an Ethernet address never authorizes an IP source.
pub(crate) fn mac_unicast(mac: [u8; 6]) -> bool { mac != [0; 6] && mac[0] & 1 == 0 }

/// Read an error's truncated original header without requiring the missing
/// payload. The library header validator is supplied a private zero-extended
/// buffer; only the received 28-byte prefix may be used as related evidence.
pub(crate) fn quote(bytes: &[u8]) -> (quote: Option<(Tuple, Vec<u8>)>)
    ensures quote.is_some() ==> 28 <= quote.unwrap().1@.len() <= crate::MTU
        && quote.unwrap().1@ == bytes@ && codec::quoted_header_value(bytes@).is_some()
        && codec::quoted_header_value(bytes@).unwrap().header == 20
        && (quote.unwrap().0.proto == 1 || quote.unwrap().0.proto == 6 || quote.unwrap().0.proto == 17),
{
    if bytes.len() < 28 || bytes.len() > crate::MTU { return None; }
    let ip = codec::quoted_header(bytes)?;
    if ip.version != 4 || ip.header != 20 || ip.total < 28 || usize::from(ip.total) < bytes.len()
        || ip.fragments || ip.offset != 0 || !ip.checksum { return None; }
    let proto = ip.protocol;
    let mut tuple = Tuple { src: ip.source, dst: ip.destination, sport: 0, dport: 0, proto };
    match proto {
        6 | 17 => { let ports = codec::quote_ports(&bytes[20..], proto); tuple.sport = ports.0; tuple.dport = ports.1; }
        1 => {
            let icmp = codec::icmp(&bytes[20..])?;
            if !matches!(icmp.kind, 0 | 8) || icmp.code != 0 { return None; }
            tuple.sport = icmp.identifier;
        }
        _ => return None,
    }
    Some((tuple, slice_to_vec(bytes)))
}

/// Undo NAT inside an ICMP quote. RFC 1624 updates come from the checksum crate;
/// truncated TCP checksums are touched only when their field is actually quoted.
pub(crate) fn untranslate_quote(mut bytes: Vec<u8>, old: Tuple, new: Tuple) -> (quote: Option<Vec<u8>>)
    requires 28 <= bytes@.len() <= crate::MTU, codec::quoted_header_value(bytes@).is_some(),
        codec::quoted_header_value(bytes@).unwrap().header == 20,
        old.proto == 1 || old.proto == 6 || old.proto == 17, new.proto == old.proto,
    ensures quote.is_some() ==> quote.unwrap()@.len() == bytes@.len(),
{
    if bytes.len() < 28 { return None; }
    let ghost initial = bytes@;
    let checksum_offset = match old.proto { 17 => Some(26), 6 if bytes.len() >= 38 => Some(36), 1 => Some(22), _ => None };
    if let Some(offset) = checksum_offset {
        let mut current = [0; 2];
        current.copy_from_slice(&bytes[offset..offset+2]);
        if old.proto != 17 || current != [0; 2] {
            let mut checksum = current;
            if old.proto != 1 {
                checksum = internet_checksum::update(checksum, &old.src, &new.src);
                checksum = internet_checksum::update(checksum, &old.dst, &new.dst);
                checksum = internet_checksum::update(checksum, &codec::word_bytes(old.dport), &codec::word_bytes(new.dport));
            }
            checksum = internet_checksum::update(checksum, &codec::word_bytes(old.sport), &codec::word_bytes(new.sport));
            if old.proto == 17 && checksum == [0; 2] { checksum = [255; 2]; }
            bytes.as_mut_slice()[offset..offset+2].copy_from_slice(&checksum);
        }
    }
    proof { assert(bytes@.take(20) =~= initial.take(20)); }
    if old.proto == 1 { bytes.as_mut_slice()[24..26].copy_from_slice(&codec::word_bytes(new.sport)); }
    else { bytes.as_mut_slice()[20..22].copy_from_slice(&codec::word_bytes(new.sport)); bytes.as_mut_slice()[22..24].copy_from_slice(&codec::word_bytes(new.dport)); }
    proof { assert(bytes@.take(20) =~= initial.take(20)); codec::fixed_quote_header(initial, bytes@); }
    codec::quoted_addresses(bytes.as_mut_slice(), new.src, new.dst);
    Some(bytes)
}

}
