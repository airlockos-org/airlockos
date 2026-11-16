//! Bounded outbound-created peer leases, separate from UDP port allocation.
//! A UDP socket keeps one translated port across destinations, but each peer
//! needs its own policy-approved outbound packet before replies are admitted.
//! Expired, revoked and reset entries retain the port during hold-down; a new
//! flow cannot immediately inherit the old flow's reply authorization.
//!
//! smoltcp supplies socket endpoints and wire codecs, not routed conntrack/NAT.
//! Linux conntrack/nftables depend on a Linux kernel and cannot execute in this
//! Hermit application. This module adds only the required outbound mapping and
//! transport lifecycle; BTreeMap, ChaCha and checksum updates remain library code.

use crate::{
    CLIENT_FLOWS, MAX_FLOWS, SECOND,
    engine::Owner,
    wire::{Packet, Tcp, Tuple},
};
use airlock_qubes_network::address::Ip;
use alloc::collections::BTreeMap;
use rand_core::RngCore;

use vstd::prelude::*;

verus! {

broadcast use { vstd::laws_cmp::group_laws_cmp, vstd::std_specs::iter::group_iter_axioms, crate::library::byte_array_equality,
    vstd::std_specs::vec::group_vec_axioms,
    vstd::std_specs::vecdeque::group_vec_dequeue_axioms,
    vstd::set::group_set_lemmas, vstd::seq_lib::group_filter_ensures, vstd::seq::group_seq_lemmas, vstd::seq_lib::group_seq_properties,
    vstd::seq::Seq::lemma_as_ref_index, vstd::slice::group_slice_axioms,
    vstd::std_specs::btree::group_btree_axioms };

/// Inclusive dynamic port range, disjoint from resolver ports.
pub(crate) const FIRST: u16 = 49152;
/// Hold-down after expiry/revocation; UDP late datagrams cannot create a flow.
const HOLD: u64 = 120 * SECOND;

/// RFC 4787 default UDP inactivity interval, independent of TCP/ICMP timers.
const UDP_IDLE: u64 = 300 * SECOND;

/// TCP states distinguished by the completed handshake and independent FINs.
#[derive(Clone, Copy)]
pub(crate) enum State {
    /// Only the initiating SYN has been accepted.
    Syn { /// Exact initial sequence, also required for SYN retries.
        client: u32 },
    /// Server SYN/ACK accepted, final client ACK still required.
    SynAck { /// Initial client sequence.
        client: u32, /// Initial server sequence.
        server: u32 },
    /// Handshake completed; both directions require ACK for stream traffic.
    Established { /// Client has sent FIN.
        client_fin: bool, /// Remote has sent FIN.
        server_fin: bool },
    /// UDP request/reply or ICMP echo request/reply state.
    Datagram,
    /// No packet can extend or revive this NAT lease.
    Retired,
}

/// SYN admission is independent of arbitrary stream payload and ACK claims.
pub(crate) open spec fn initiating(tcp: Tcp) -> bool { tcp.syn && !tcp.ack && !tcp.fin && !tcp.rst && tcp.payload == 0 }

/// Permitted handshake/control events. This is a router's connection-tracking
/// contract, not an endpoint's sequence-window or stream-reassembly contract.
pub(crate) open spec fn tcp_admissible(state: State, tcp: Tcp, outbound: bool) -> bool {
    match state {
        State::Syn { client } =>
            (outbound && initiating(tcp) && tcp.seq == client)
            || (!outbound && tcp.ack && tcp.acknowledge == client.wrapping_add(1)
                && (tcp.rst || (tcp.syn && !tcp.fin && tcp.payload == 0))),
        State::SynAck { client, server } =>
            (!outbound && tcp.syn && tcp.ack && !tcp.fin && !tcp.rst && tcp.payload == 0
                && tcp.seq == server && tcp.acknowledge == client.wrapping_add(1))
            || (outbound && initiating(tcp) && tcp.seq == client)
            || (outbound && tcp.ack && !tcp.syn && tcp.seq == client.wrapping_add(1) && tcp.acknowledge == server.wrapping_add(1)),
        State::Established { .. } => !tcp.syn && tcp.ack,
        _ => false,
    }
}

/// One peer authorization, including the pre-DNAT tuple for client replies.
/// UDP peers from one socket share a translated port, never reply authority.
pub(crate) struct Flow {
    /// Actual native lifetime copied from the admitted binding.
    pub(crate) owner: Owner,
    /// Exact tuple as received on the client interface.
    pub(crate) original: Tuple,
    /// Stable primary assigned address shared by this interface's IPv4/IPv6 quotas.
    pub(crate) quota: Ip,
    /// Outbound tuple after destination redirection, before source NAT.
    pub(crate) policy: Tuple,
    /// Assigned application IP used for source masquerade.
    pub(crate) external: Ip,
    /// Wire port shared only by UDP peers of the same owned source socket.
    pub(crate) translated_port: u16,
    /// Client sender MAC on this owner only; not an identity credential.
    pub(crate) mac: [u8; 6],
    /// Absolute inactivity deadline; queries never refresh on rejected packets.
    pub(crate) deadline: u64,
    /// Absolute port release deadline, including retirement hold-down.
    pub(crate) release: u64,
    /// Monotonic policy generation last checked for this flow.
    pub(crate) revision: u64,
    /// Guarded transport transition state.
    pub(crate) state: State,
}

impl Flow {
    /// One bounded same-family mapping retains the original source identity and
    /// a release deadline no earlier than its inactivity deadline.
    pub(crate) open spec fn valid(&self) -> bool {
        self.owner.valid() && self.quota.valid() && self.external.valid() && self.translated_port >= FIRST
            && self.external.family() == self.original.src.family() && self.original.valid() && self.policy.valid()
            && self.original.src == self.policy.src && self.original.proto == self.policy.proto
            && self.original.sport == self.policy.sport && self.original.dport == self.policy.dport
            && self.deadline <= self.release && self.revision > 0
            && (self.original.proto != 6 ==> self.state is Datagram || self.state is Retired)
    }

    /// The UDP source socket within one interface lifetime and external address.
    /// Destination identity remains in the separate peer authorization.
    pub(crate) open spec fn same_socket(&self, other: &Self) -> bool {
        self.original.proto == 17 && other.original.proto == 17
            && self.owner == other.owner && self.original.src == other.original.src
            && self.original.sport == other.original.sport && self.external == other.external
    }

    /// Exact outbound wire tuple; reversing a received reply selects this peer.
    pub(crate) open spec fn wire_tuple(&self) -> Tuple {
        Tuple { src: self.external, sport: self.translated_port, ..self.policy }
    }

    /// Materialize the wire key without granting permission to receive a packet.
    pub(crate) fn translated(&self) -> (tuple: Tuple)
        ensures tuple == self.wire_tuple(),
    { Tuple { src: self.external, sport: self.translated_port, ..self.policy } }

    /// Exact expiration reservation used by outside-module contracts.
    pub(crate) open spec fn release_deadline(&self) -> u64 { self.release }

    /// Retired mappings cannot re-enter a transport handshake.
    pub(crate) open spec fn retired(&self) -> bool { self.state is Retired }

    /// Exact admission for live UDP/echo traffic and guarded TCP control events.
    pub(crate) open spec fn accepts(&self, packet: Packet<'_>, outbound: bool, now: u64) -> bool {
        (self.usable(now) || (outbound && self.original.proto == 17 && self.state is Datagram && now < u64::MAX))
            && (!packet.tuple.icmp() || packet.icmp == if outbound { packet.tuple.request() } else { packet.tuple.reply() })
            && (packet.tuple.proto != 6 || tcp_admissible(self.state, packet.tcp, outbound))
    }

    /// Existing transport state may authorize a packet only before inactivity.
    pub(crate) open spec fn usable(&self, now: u64) -> bool { now < self.deadline && !(self.state is Retired) }

    /// Existing mappings are usable only before inactivity expiry and retirement.
    pub(crate) fn live(&self, now: u64) -> (live: bool)
        requires self.valid(), ensures live == self.usable(now),
    { now < self.deadline && !matches!(self.state, State::Retired) }

    /// Revoke without releasing its reply tuple to a replacement connection.
    pub(crate) fn retire(&mut self, now: u64)
        requires old(self).valid(),
        ensures final(self).valid(), !final(self).usable(now), final(self).retired(),
            final(self).revision == old(self).revision,
            final(self).external == old(self).external, final(self).mac == old(self).mac,
            final(self).quota == old(self).quota, final(self).translated_port == old(self).translated_port,
            final(self).owner == old(self).owner && final(self).original == old(self).original
                && final(self).policy == old(self).policy && final(self).release_deadline() >= old(self).release_deadline(),
    {
        if !matches!(self.state, State::Retired) {
            self.state = State::Retired; self.release = self.release.max(now.saturating_add(HOLD));
        }
    }

    /// Match inbound transport fields only after looking up a retained NAT port.
    pub(crate) fn reply(&self, tuple: Tuple, port: u16) -> (reply: bool)
        requires self.valid(), tuple.valid(),
        ensures reply == (tuple.src == self.policy.dst && tuple.dst == self.external && tuple.proto == self.policy.proto
            && (if tuple.icmp() { tuple.sport == port }
                else { tuple.sport == self.policy.dport && tuple.dport == port })),
    {
        tuple.src == self.policy.dst && tuple.dst == self.external && tuple.proto == self.policy.proto
            && if tuple.icmp() { tuple.sport == port }
                else { tuple.sport == self.policy.dport && tuple.dport == port }
    }

    /// Validate the TCP handshake and advance only on an accepted direction.
    /// This is connection tracking, not TCP endpoint reassembly/window validation.
    pub(crate) fn accept(&mut self, packet: &Packet<'_>, outbound: bool, now: u64) -> (accepted: bool)
        requires old(self).valid(), packet.valid(), packet.tuple.proto == old(self).original.proto,
        ensures final(self).valid(), accepted == old(self).accepts(*packet, outbound, now),
            !accepted && old(self).usable(now) ==> *final(self) == *old(self),
            accepted && !final(self).retired() ==> final(self).deadline > now,
            accepted && old(self).state is Established && !packet.tcp.rst ==> final(self).state is Established,
            final(self).external == old(self).external, final(self).mac == old(self).mac,
            final(self).quota == old(self).quota, final(self).translated_port == old(self).translated_port,
            final(self).owner == old(self).owner && final(self).original == old(self).original
                && final(self).policy == old(self).policy && final(self).revision == old(self).revision,
            old(self).retired() ==> !accepted && final(self).retired(),
            accepted && packet.tuple.icmp() ==> packet.icmp == if outbound { packet.tuple.request() } else { packet.tuple.reply() },
    {
        // Idle UDP may be renewed by a newly policy-checked outbound packet.
        // Incoming traffic never revives it, and explicit revocation is final.
        if !self.live(now) && !(outbound && packet.tuple.proto == 17
            && matches!(self.state, State::Datagram) && now < u64::MAX) { return false; }
        if packet.tuple.icmp() && packet.icmp != if outbound { packet.tuple.request() } else { packet.tuple.reply() } { return false; }
        let mut timeout = if packet.tuple.icmp() { 10 * SECOND } else { UDP_IDLE };
        if packet.tuple.proto == 6 {
            let tcp = packet.tcp;
            let next = match self.state {
                State::Syn { client } => {
                    if outbound && initial(tcp) && tcp.seq == client { self.state }
                    else if !outbound && tcp.syn && tcp.ack && !tcp.rst && !tcp.fin
                        && tcp.payload == 0 && tcp.acknowledge == client.wrapping_add(1) {
                        State::SynAck { client, server: tcp.seq }
                    } else if !outbound && tcp.rst && tcp.ack && tcp.acknowledge == client.wrapping_add(1) { State::Retired }
                    else { return false; }
                }
                State::SynAck { client, server } => {
                    if (!outbound && tcp.syn && tcp.ack && !tcp.fin && !tcp.rst && tcp.payload == 0
                        && tcp.seq == server && tcp.acknowledge == client.wrapping_add(1))
                        || (outbound && initial(tcp) && tcp.seq == client) { self.state }
                    else if outbound && tcp.ack && !tcp.syn && tcp.seq == client.wrapping_add(1)
                        && tcp.acknowledge == server.wrapping_add(1) {
                        if tcp.rst { State::Retired } else { State::Established { client_fin: tcp.fin, server_fin: false } }
                    } else { return false; }
                }
                State::Established { client_fin, server_fin } => {
                    if tcp.syn || !tcp.ack { return false; }
                    if tcp.rst { State::Retired }
                    else { State::Established { client_fin: client_fin || (outbound && tcp.fin),
                        server_fin: server_fin || (!outbound && tcp.fin) } }
                }
                _ => return false,
            };
            timeout = match next {
                State::Established { client_fin: false, server_fin: false } => 300 * SECOND,
                State::Established { .. } => 30 * SECOND,
                _ => 30 * SECOND,
            };
            if matches!(next, State::Retired) { self.retire(now); }
            else { self.state = next; }
        }
        if !matches!(self.state, State::Retired) {
            self.deadline = now.saturating_add(timeout); self.release = self.deadline.saturating_add(HOLD);
        }
        true
    }
}

/// First outbound TCP segment cannot carry data or acknowledge another stream.
fn initial(tcp: Tcp) -> (initial: bool)
    ensures initial == initiating(tcp),
{ tcp.syn && !tcp.ack && !tcp.fin && !tcp.rst && tcp.payload == 0 }

/// Initialization data for one already permitted outbound mapping, without any
/// resource authority. Kept together to preserve the original route decision.
pub(crate) struct NewMapping {
    /// Exact native lifetime copied from a completed binding.
    pub owner: Owner,
    /// Authorized tuple after provider-DNS redirection.
    pub policy: Tuple,
    /// Primary assigned address; both address families spend the same quota.
    pub quota: Ip,
    /// Current source-NAT address in the packet's address family.
    pub external: Ip,
    /// Original sender's MAC, scoped only to this native lifetime.
    pub mac: [u8; 6],
    /// Observation revision under which the route was permitted.
    pub revision: u64,
}

/// Bounded peer leases with independent internal IDs and translated ports.
/// Both directions use exact tuple indexes. Allocation may inspect the bounded
/// table; established traffic performs logarithmic lookups, not a table scan.
pub(crate) struct Table {
    /// Internal IDs retain at most MAX_FLOWS active plus retired peer leases.
    pub(crate) entries: BTreeMap<u16, Flow>,
    /// Exact original tuple and lifetime select an internal peer lease ID.
    pub(crate) outbound: BTreeMap<(Owner, Tuple), u16>,
    /// Translated outbound tuple selects exactly one peer for replies/errors.
    pub(crate) replies: BTreeMap<Tuple, u16>,
    /// Cursor bounds maintenance to at most 64 leases per scheduler turn.
    pub(crate) cursor: u16,
}

impl Table {
    /// Peer reservations charged to one original source, including retired entries.
    pub(crate) open spec fn source_peers(&self, source: Ip) -> Set<u16> {
        self.entries@.dom().filter(|id: u16| self.entries@[id].quota == source)
    }

    /// Bijections between peer IDs and both directional tuple indexes. Port
    /// sharing is restricted to one UDP socket, independent of its destination.
    /// Retired reservations count against the same global and client limits.
    pub(crate) open spec fn valid(&self) -> bool {
        vstd::std_specs::btree::key_obeys_cmp_spec::<(Owner, Tuple)>()
            && vstd::std_specs::btree::key_obeys_cmp_spec::<Tuple>()
            && self.entries@.len() <= MAX_FLOWS && self.outbound@.len() == self.entries@.len()
            && self.replies@.len() == self.entries@.len()
            && (forall|id: u16| self.entries@.dom().contains(id) ==>
                self.replies@.dom().contains(self.entries@[id].wire_tuple())
                && self.replies@[self.entries@[id].wire_tuple()] == id)
            && (forall|tuple: Tuple| self.replies@.dom().contains(tuple) ==>
                self.entries@.dom().contains(self.replies@[tuple])
                && self.entries@[self.replies@[tuple]].wire_tuple() == tuple)
            && (forall|a: u16, b: u16| self.entries@.dom().contains(a) && self.entries@.dom().contains(b) && a != b ==>
                (self.entries@[a].translated_port == self.entries@[b].translated_port
                    <==> self.entries@[a].same_socket(&self.entries@[b])))
            && (forall|id: u16| self.entries@.dom().contains(id) ==> id >= FIRST
                && self.entries@[id].valid()
                && self.outbound@.dom().contains((self.entries@[id].owner, self.entries@[id].original))
                && self.outbound@[(self.entries@[id].owner, self.entries@[id].original)] == id)
            && (forall|key: (Owner, Tuple)| self.outbound@.dom().contains(key) ==>
                self.entries@.dom().contains(self.outbound@[key])
                && self.entries@[self.outbound@[key]].owner == key.0 && self.entries@[self.outbound@[key]].original == key.1)
            && (forall|source: Ip| (#[trigger] self.source_peers(source)).len() <= CLIENT_FLOWS)
    }

    /// Stored leases, observed without exposing the native map representation.
    pub(crate) open spec fn value(&self) -> Map<u16, Flow> { self.entries@ }

    /// Exact private tuple index corresponding to the retained peer map.
    pub(crate) open spec fn index_value(&self) -> Map<(Owner, Tuple), u16> { self.outbound@ }

    /// Cursor changes and unsuccessful lookups preserve all reservation records.
    pub(crate) proof fn same_records(&self, before: Self)
        requires before.valid(), self.entries@ == before.entries@, self.outbound@ == before.outbound@, self.replies@ == before.replies@,
        ensures self.valid(),
    {
        assert forall|source: Ip| self.source_peers(source).len() <= CLIENT_FLOWS by {
            assert(before.source_peers(source).len() <= CLIENT_FLOWS);
            assert(self.source_peers(source) == before.source_peers(source));
        }
    }

    /// A value-only transition preserving the mapping key cannot change either
    /// index or any source's reservation count. All transport transitions use it.
    pub(crate) proof fn mapping_update(&self, before: Self, id: u16)
        requires before.valid(), before.entries@.dom().contains(id),
            self.outbound@ == before.outbound@, self.replies@ == before.replies@,
            self.entries@ == before.entries@.insert(id, self.entries@[id]),
            self.entries@[id].valid(), self.entries@[id].owner == before.entries@[id].owner,
            self.entries@[id].original == before.entries@[id].original,
            self.entries@[id].quota == before.entries@[id].quota,
            self.entries@[id].external == before.entries@[id].external,
            self.entries@[id].policy == before.entries@[id].policy,
            self.entries@[id].translated_port == before.entries@[id].translated_port,
        ensures self.valid(),
    {
        assert(self.entries@[id].wire_tuple() == before.entries@[id].wire_tuple());
        assert forall|a: u16, b: u16| self.entries@.dom().contains(a) && self.entries@.dom().contains(b) && a != b implies
            (self.entries@[a].translated_port == self.entries@[b].translated_port
                <==> self.entries@[a].same_socket(&self.entries@[b])) by {
            assert(self.entries@[a].same_socket(&self.entries@[b]) == before.entries@[a].same_socket(&before.entries@[b]));
        }
        assert forall|source: Ip| self.source_peers(source).len() <= CLIENT_FLOWS by {
            assert(self.source_peers(source) =~= before.source_peers(source));
        }
    }

    /// Start with no outbound-created authority or reserved ports.
    pub(crate) fn new() -> (table: Self)
        ensures table.valid(), table.value().len() == 0, table.index_value().len() == 0,
    {
        proof { crate::library::derived_key_order(); }
        let table = Self { entries: BTreeMap::new(), outbound: BTreeMap::new(), replies: BTreeMap::new(), cursor: 0 };
        proof {
            assert forall|source: Ip| table.source_peers(source).len() <= CLIENT_FLOWS by {
                assert(table.source_peers(source) =~= Set::empty());
            }
        }
        table
    }

    /// Find a tuple only in the exact native interface incarnation.
    pub(crate) fn find(&self, owner: Owner, tuple: Tuple) -> (id: Option<u16>)
        requires self.valid(),
        ensures id.is_some() == self.index_value().dom().contains((owner, tuple)),
            id.is_some() ==> self.value().dom().contains(id.unwrap())
                && self.value()[id.unwrap()].owner == owner && self.value()[id.unwrap()].original == tuple,
    { self.outbound.get(&(owner, tuple)).copied() }

    /// Look up an exact outbound wire tuple, including its remote endpoint.
    /// Used for replies and ICMP quotes; a shared port alone grants no access.
    pub(crate) fn translated_id(&self, tuple: Tuple) -> (id: Option<u16>)
        requires self.valid(),
        ensures id.is_some() == self.replies@.dom().contains(tuple),
            id.is_some() ==> self.value().dom().contains(id.unwrap())
                && self.value()[id.unwrap()].wire_tuple() == tuple,
    { self.replies.get(&tuple).copied() }

    /// Quotas include previous incarnations with the same assigned source, so a
    /// client's repeated disconnects cannot consume every retired reservation.
    /// Source is accounting data only; owner still selects actual flow identity.
    /// Admit a new mapping only for supported initiating packets and bounded
    /// available global/per-client capacity. Failed admission changes no state.
    pub(crate) fn create(&mut self, mapping: NewMapping, packet: &Packet<'_>, now: u64, random: &mut impl RngCore) -> (id: Option<u16>)
        requires old(self).valid(), mapping.owner.valid(), mapping.quota.valid(), mapping.external.valid(), packet.valid(),
            mapping.external.family() == packet.tuple.src.family(), mapping.policy.valid(), mapping.revision > 0,
            packet.tuple.src == mapping.policy.src && packet.tuple.sport == mapping.policy.sport
                && packet.tuple.dport == mapping.policy.dport && packet.tuple.proto == mapping.policy.proto,
            !old(self).index_value().dom().contains((mapping.owner, packet.tuple)),
        ensures final(self).valid(),
            id.is_some() ==> !old(self).value().dom().contains(id.unwrap())
                && final(self).value().dom().contains(id.unwrap())
                && final(self).value()[id.unwrap()].owner == mapping.owner
                && final(self).value()[id.unwrap()].original == packet.tuple
                && final(self).value()[id.unwrap()].policy == mapping.policy
                && final(self).value()[id.unwrap()].usable(now),
            id.is_none() ==> *final(self) == *old(self),
    {
        let owner = mapping.owner;
        let policy = mapping.policy;
        let quota = mapping.quota;
        let external = mapping.external;
        let mac = mapping.mac;
        let revision = mapping.revision;
        let predicate = |flow: &Flow| -> (matches: bool)
            ensures matches == (flow.quota == quota),
        { flow.quota == quota };
        let count = crate::library::count_values(&self.entries, predicate);
        proof {
            assert(crate::library::selected_keys(self.entries@, predicate) =~= self.source_peers(quota));
            assert(count == self.source_peers(quota).len());
        }
        if now == u64::MAX || self.entries.len() >= MAX_FLOWS
            || count >= CLIENT_FLOWS
            || (packet.tuple.proto == 6 && !initial(packet.tcp))
            || (packet.tuple.icmp() && packet.icmp != packet.tuple.request()) { return None; }
        let start = (random.next_u32() % 16384) as u16;
        let entries = &self.entries;
        let id = (0..=MAX_FLOWS).find_map(|offset: usize| -> (candidate: Option<u16>)
            ensures candidate.is_some() ==> candidate.unwrap() >= FIRST && !entries@.dom().contains(candidate.unwrap()),
        {
            let id = FIRST + (usize::from(start).wrapping_add(offset) % 16384) as u16;
            if entries.contains_key(&id) { None } else { Some(id) }
        })?;
        let socket = |flow: &Flow| -> (same: bool)
            ensures same == (flow.original.proto == 17 && packet.tuple.proto == 17
                && flow.owner == owner && flow.original.src == packet.tuple.src
                && flow.original.sport == packet.tuple.sport && flow.external == external),
        {
            flow.original.proto == 17 && packet.tuple.proto == 17 && flow.owner == owner
                && flow.original.src == packet.tuple.src && flow.original.sport == packet.tuple.sport
                && flow.external == external
        };
        let shared = crate::library::find_key(&self.entries, socket);
        let translated_port = if let Some(id) = shared {
            self.entries.get(&id)?.translated_port
        } else {
            (0..=MAX_FLOWS).find_map(|offset: usize| -> (candidate: Option<u16>)
                ensures candidate.is_some() ==> candidate.unwrap() >= FIRST
                    && (forall|id: u16| entries@.dom().contains(id) ==> entries@[id].translated_port != candidate.unwrap()),
            {
                let candidate = FIRST + (usize::from(start).wrapping_add(offset) % 16384) as u16;
                let occupied = crate::library::find_key(entries, |flow: &Flow| -> (same: bool)
                    ensures same == (flow.translated_port == candidate),
                { flow.translated_port == candidate });
                if occupied.is_some() { None } else { Some(candidate) }
            })?
        };
        let translated = Tuple { src: external, sport: translated_port, ..policy };
        // Different provider-DNS aliases may redirect to one wire tuple. They
        // cannot share reply identity; keep the first authorization unambiguous.
        if self.replies.contains_key(&translated) { return None; }
        let deadline = now.saturating_add(if packet.tuple.proto == 17 { UDP_IDLE } else { 30 * SECOND });
        let ghost before = *self;
        let flow = Flow { owner, original: packet.tuple, quota, policy, external, translated_port, mac,
            deadline, release: deadline.saturating_add(HOLD), revision,
            state: if packet.tuple.proto == 6 { State::Syn { client: packet.tcp.seq } } else { State::Datagram } };
        proof {
            assert forall|id: u16| self.entries@.dom().contains(id) implies
                (flow.translated_port == self.entries@[id].translated_port <==> flow.same_socket(&self.entries@[id])) by {
                if let Some(shared_id) = shared {
                    assert(self.entries@[shared_id].same_socket(&flow));
                    if id != shared_id {
                        assert(self.entries@[id].translated_port == self.entries@[shared_id].translated_port
                            <==> self.entries@[id].same_socket(&self.entries@[shared_id]));
                    }
                }
            }
        }
        self.outbound.insert((owner, packet.tuple), id); self.replies.insert(translated, id); self.entries.insert(id, flow);
        proof {
            assert(self.entries@[id].valid());
            assert(self.entries@.len() <= MAX_FLOWS);
            assert(self.outbound@.len() == self.entries@.len());
            assert forall|a: u16, b: u16| self.entries@.dom().contains(a) && self.entries@.dom().contains(b) && a != b implies
                (self.entries@[a].translated_port == self.entries@[b].translated_port
                    <==> self.entries@[a].same_socket(&self.entries@[b])) by {
                if a != id && b != id {
                    assert(before.entries@[a].translated_port == before.entries@[b].translated_port
                        <==> before.entries@[a].same_socket(&before.entries@[b]));
                }
            }
            assert forall|p: u16| self.entries@.dom().contains(p) implies p >= FIRST
                && self.entries@[p].valid()
                && self.outbound@.dom().contains((self.entries@[p].owner, self.entries@[p].original))
                && self.outbound@[(self.entries@[p].owner, self.entries@[p].original)] == p by { }
            assert forall|key: (Owner, Tuple)| self.outbound@.dom().contains(key) implies
                self.entries@.dom().contains(self.outbound@[key])
                && self.entries@[self.outbound@[key]].owner == key.0 && self.entries@[self.outbound@[key]].original == key.1 by { }
            assert forall|source: Ip| self.source_peers(source).len() <= CLIENT_FLOWS by {
                if source == quota {
                    assert(self.source_peers(source) =~= before.source_peers(source).insert(id));
                } else { assert(self.source_peers(source) =~= before.source_peers(source)); }
            }
        }
        Some(id)
    }

    /// Apply a checked transport transition without exposing a mutable map value.
    pub(crate) fn accept(&mut self, id: u16, packet: &Packet<'_>, outbound: bool, mac: Option<[u8; 6]>, now: u64) -> (accepted: bool)
        requires old(self).valid(), packet.valid(), old(self).entries@.dom().contains(id),
            packet.tuple.proto == old(self).entries@[id].original.proto,
        ensures final(self).valid(), final(self).entries@.dom() == old(self).entries@.dom(),
            final(self).outbound@ == old(self).outbound@,
            accepted == old(self).entries@[id].accepts(*packet, outbound, now),
    {
        let ghost before = *self;
        let Some(flow) = self.entries.get_mut(&id) else { return false; };
        let accepted = flow.accept(packet, outbound, now);
        if let (true, Some(mac)) = (accepted, mac) { flow.mac = mac; }
        proof { self.mapping_update(before, id); }
        accepted
    }

    /// Recheck retained mappings against the current source, redirect and ordered
    /// policy before another packet can use their observation revision.
    pub(crate) fn observe(&mut self, view: &airlock_qubes_network::projection::View, now: u64)
        requires old(self).valid(), view.valid(),
        ensures final(self).valid(), final(self).entries@.dom() == old(self).entries@.dom(),
    {
        let ports = crate::library::port_window(&self.entries, 0, MAX_FLOWS);
        for id in ports
            invariant self.valid(), view.valid(), self.entries@.dom() == old(self).entries@.dom(),
        {
            let ghost before = *self;
            if let Some(flow) = self.entries.get_mut(&id) {
                let address_ok = match view.config() {
                    Some(config) => crate::policy::external(config, flow.original.src.version()) == Some(flow.external)
                        && config.contains(&flow.original.src),
                    None => false,
                };
                let redirect_ok = crate::policy::redirect(view, flow.original) == Some(flow.policy);
                if !address_ok || !redirect_ok || !crate::policy::allows(view, flow.policy, if flow.policy.icmp() { flow.policy.request() } else { 0 }, now) {
                    flow.retire(now);
                } else { flow.revision = view.generation(); }
            }
            proof {
                if before.entries@.dom().contains(id) { self.mapping_update(before, id); }
                else { self.same_records(before); }
            }
        }
    }

    /// Retire all state on an interface lifetime's withdrawal.
    pub(crate) fn retire(&mut self, owner: Owner, now: u64)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).value().dom() == old(self).value().dom(),
            forall|id: u16| final(self).value().dom().contains(id)
                && final(self).value()[id].owner == owner ==> !final(self).value()[id].usable(now),
    {
        let keys = crate::library::port_window(&self.entries, 0, MAX_FLOWS);
        let mut index = 0;
        while index < keys.len()
            invariant self.valid(), self.outbound@ == old(self).outbound@, self.entries@.dom() == old(self).entries@.dom(),
                keys@.len() <= MAX_FLOWS, index <= keys@.len(),
                forall|i: int| 0 <= i < keys@.len() ==> self.entries@.dom().contains(keys@[i]),
                forall|id: u16| old(self).entries@.dom().contains(id) ==> keys@.contains(id),
                forall|i: int| 0 <= i < index && self.entries@[keys@[i]].owner == owner ==> !self.entries@[keys@[i]].usable(now),
            decreases keys.len() - index,
        {
            let id = keys[index];
            let ghost before = *self;
            match self.entries.get_mut(&id) {
                Some(flow) if flow.owner == owner => flow.retire(now),
                _ => (),
            }
            proof { self.mapping_update(before, id); }
            index += 1;
        }
        proof {
            assert forall|id: u16| self.entries@.dom().contains(id) && self.entries@[id].owner == owner
                implies !self.entries@[id].usable(now) by {
                let i = choose|i: int| 0 <= i < keys@.len() && keys@[i] == id;
            }
        }
    }

    /// Release only an expired peer reservation, removing both tuple indexes.
    fn release(&mut self, id: u16, _now: u64)
        requires old(self).valid(), old(self).entries@.dom().contains(id), old(self).entries@[id].release <= _now,
        ensures final(self).valid(), final(self).entries@ == old(self).entries@.remove(id),
    {
        let ghost before = *self;
        let Some(flow) = self.entries.get(&id) else { return; };
        let key = (flow.owner, flow.original);
        let translated = flow.translated();
        self.entries.remove(&id); self.outbound.remove(&key); self.replies.remove(&translated);
        proof {
            assert forall|source: Ip| self.source_peers(source).len() <= CLIENT_FLOWS by {
                assert(self.source_peers(source).subset_of(before.source_peers(source)));
                vstd::set_lib::lemma_len_subset(self.source_peers(source), before.source_peers(source));
            }
        }
    }

    /// Visit at most 64 entries; stale ports remain unavailable until reclaimed.
    pub(crate) fn maintain(&mut self, now: u64)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).value().dom().subset_of(old(self).value().dom()),
            forall|id: u16| old(self).value().dom().contains(id) && !final(self).value().dom().contains(id)
                ==> old(self).value()[id].release <= now,
    {
        let ghost before_cursor = *self;
        let keys: alloc::vec::Vec<u16> = crate::library::port_window(&self.entries, self.cursor, 64);
        if keys.len() < 64 { self.cursor = 0; }
        else { self.cursor = keys.last().copied().unwrap_or(0).saturating_add(1); }
        proof { self.same_records(before_cursor); }
        for id in keys
            invariant self.valid(), self.entries@.dom().subset_of(old(self).entries@.dom()),
                forall|p: u16| self.entries@.dom().contains(p) ==> self.entries@[p].release >= old(self).entries@[p].release,
                forall|p: u16| old(self).entries@.dom().contains(p) && !self.entries@.dom().contains(p)
                    ==> old(self).entries@[p].release <= now,
        {
            let ghost before = *self;
            let release = if let Some(flow) = self.entries.get_mut(&id) {
                if !flow.live(now) && flow.original.proto != 17 { flow.retire(now); }
                now >= flow.release
            } else { false };
            proof {
                if before.entries@.dom().contains(id) { self.mapping_update(before, id); }
                else { self.same_records(before); }
            }
            if release { self.release(id, now); }
        }
    }
}

}
