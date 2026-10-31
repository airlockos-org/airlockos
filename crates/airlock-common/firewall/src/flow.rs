//! Bounded outbound-created NAT leases. Tuple and owner are independent keys.
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

/// One NAT mapping, including the original pre-DNAT tuple for client replies.
pub(crate) struct Flow {
    /// Actual native lifetime copied from the admitted binding.
    pub(crate) owner: Owner,
    /// Exact tuple as received on the client interface.
    pub(crate) original: Tuple,
    /// Outbound tuple after destination redirection, before source NAT.
    pub(crate) policy: Tuple,
    /// Assigned application IP used for source masquerade.
    pub(crate) external: [u8; 4],
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
        self.owner.valid() && self.original.valid() && self.policy.valid()
            && self.original.src == self.policy.src && self.original.proto == self.policy.proto
            && self.original.sport == self.policy.sport && self.original.dport == self.policy.dport
            && self.deadline <= self.release && self.revision > 0
            && (self.original.proto != 6 ==> self.state is Datagram || self.state is Retired)
    }

    /// Exact expiration reservation used by outside-module contracts.
    pub(crate) open spec fn release_deadline(&self) -> u64 { self.release }

    /// Retired mappings cannot re-enter a transport handshake.
    pub(crate) open spec fn retired(&self) -> bool { self.state is Retired }

    /// Exact admission for live UDP/echo traffic and guarded TCP control events.
    pub(crate) open spec fn accepts(&self, packet: Packet<'_>, outbound: bool, now: u64) -> bool {
        self.usable(now)
            && (packet.tuple.proto != 1 || packet.icmp == if outbound { 8u8 } else { 0u8 })
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
            && (if tuple.proto == 1 { tuple.sport == port }
                else { tuple.sport == self.policy.dport && tuple.dport == port })),
    {
        tuple.src == self.policy.dst && tuple.dst == self.external && tuple.proto == self.policy.proto
            && if tuple.proto == 1 { tuple.sport == port }
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
            final(self).owner == old(self).owner && final(self).original == old(self).original
                && final(self).policy == old(self).policy && final(self).revision == old(self).revision,
            old(self).retired() ==> !accepted && final(self).retired(),
            accepted && packet.tuple.proto == 1 ==> packet.icmp == if outbound { 8u8 } else { 0u8 },
    {
        if !self.live(now) { self.retire(now); return false; }
        if packet.tuple.proto == 1 && packet.icmp != if outbound { 8 } else { 0 } { return false; }
        let mut timeout = if packet.tuple.proto == 1 { 10 * SECOND } else { 30 * SECOND };
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
    /// Current source-NAT IPv4 address.
    pub external: [u8; 4],
    /// Original sender's MAC, scoped only to this native lifetime.
    pub mac: [u8; 6],
    /// Observation revision under which the route was permitted.
    pub revision: u64,
}

/// Port-keyed bounded retained leases with an exact outbound tuple index.
pub(crate) struct Table {
    /// At most MAX_FLOWS active plus retired leases, not separate allowances.
    pub(crate) entries: BTreeMap<u16, Flow>,
    /// Exact original tuple and lifetime select an outbound mapping.
    pub(crate) outbound: BTreeMap<(Owner, Tuple), u16>,
    /// Cursor bounds maintenance to at most 64 leases per scheduler turn.
    pub(crate) cursor: u16,
}

impl Table {
    /// Reservations charged to one original source, including retired entries.
    pub(crate) open spec fn source_ports(&self, source: [u8; 4]) -> Set<u16> {
        self.entries@.dom().filter(|port: u16| self.entries@[port].original.src == source)
    }

    /// Finite bijection between reserved NAT ports and exact owner/tuple keys.
    /// Retired reservations count against the same global and client limits.
    pub(crate) open spec fn valid(&self) -> bool {
        vstd::std_specs::btree::key_obeys_cmp_spec::<(Owner, Tuple)>()
            && self.entries@.len() <= MAX_FLOWS && self.outbound@.len() == self.entries@.len()
            && (forall|port: u16| self.entries@.dom().contains(port) ==> port >= FIRST
                && self.entries@[port].valid()
                && self.outbound@.dom().contains((self.entries@[port].owner, self.entries@[port].original))
                && self.outbound@[(self.entries@[port].owner, self.entries@[port].original)] == port)
            && (forall|key: (Owner, Tuple)| self.outbound@.dom().contains(key) ==>
                self.entries@.dom().contains(self.outbound@[key])
                && self.entries@[self.outbound@[key]].owner == key.0 && self.entries@[self.outbound@[key]].original == key.1)
            && (forall|source: [u8; 4]| (#[trigger] self.source_ports(source)).len() <= CLIENT_FLOWS)
    }

    /// Stored leases, observed without exposing the native map representation.
    pub(crate) open spec fn value(&self) -> Map<u16, Flow> { self.entries@ }

    /// Exact private tuple index corresponding to the retained port map.
    pub(crate) open spec fn index_value(&self) -> Map<(Owner, Tuple), u16> { self.outbound@ }

    /// Cursor changes and unsuccessful lookups preserve all reservation records.
    pub(crate) proof fn same_records(&self, before: Self)
        requires before.valid(), self.entries@ == before.entries@, self.outbound@ == before.outbound@,
        ensures self.valid(),
    {
        assert forall|source: [u8; 4]| self.source_ports(source).len() <= CLIENT_FLOWS by {
            assert(before.source_ports(source).len() <= CLIENT_FLOWS);
            assert(self.source_ports(source) == before.source_ports(source));
        }
    }

    /// A value-only transition preserving the mapping key cannot change either
    /// index or any source's reservation count. All transport transitions use it.
    pub(crate) proof fn mapping_update(&self, before: Self, port: u16)
        requires before.valid(), before.entries@.dom().contains(port),
            self.outbound@ == before.outbound@,
            self.entries@ == before.entries@.insert(port, self.entries@[port]),
            self.entries@[port].valid(), self.entries@[port].owner == before.entries@[port].owner,
            self.entries@[port].original == before.entries@[port].original,
        ensures self.valid(),
    {
        assert forall|source: [u8; 4]| self.source_ports(source).len() <= CLIENT_FLOWS by {
            assert(self.source_ports(source) =~= before.source_ports(source));
        }
    }

    /// Start with no outbound-created authority or reserved ports.
    pub(crate) fn new() -> (table: Self)
        ensures table.valid(), table.value().len() == 0, table.index_value().len() == 0,
    {
        proof { crate::library::derived_key_order(); }
        let table = Self { entries: BTreeMap::new(), outbound: BTreeMap::new(), cursor: 0 };
        proof {
            assert forall|source: [u8; 4]| table.source_ports(source).len() <= CLIENT_FLOWS by {
                assert(table.source_ports(source) =~= Set::empty());
            }
        }
        table
    }

    /// Find a tuple only in the exact native interface incarnation.
    pub(crate) fn find(&self, owner: Owner, tuple: Tuple) -> (port: Option<u16>)
        requires self.valid(),
        ensures port.is_some() == self.index_value().dom().contains((owner, tuple)),
            port.is_some() ==> self.value().dom().contains(port.unwrap())
                && self.value()[port.unwrap()].owner == owner && self.value()[port.unwrap()].original == tuple,
    { self.outbound.get(&(owner, tuple)).copied() }

    /// Quotas include previous incarnations with the same assigned source, so a
    /// client's repeated disconnects cannot consume every retired reservation.
    /// Source is accounting data only; owner still selects actual flow identity.
    /// Admit a new mapping only for supported initiating packets and bounded
    /// available global/per-client capacity. Failed admission changes no state.
    pub(crate) fn create(&mut self, mapping: NewMapping, packet: &Packet<'_>, now: u64, random: &mut impl RngCore) -> (port: Option<u16>)
        requires old(self).valid(), mapping.owner.valid(), packet.valid(), mapping.policy.valid(), mapping.revision > 0,
            packet.tuple.src == mapping.policy.src && packet.tuple.sport == mapping.policy.sport
                && packet.tuple.dport == mapping.policy.dport && packet.tuple.proto == mapping.policy.proto,
            !old(self).index_value().dom().contains((mapping.owner, packet.tuple)),
        ensures final(self).valid(),
            port.is_some() ==> !old(self).value().dom().contains(port.unwrap())
                && final(self).value().dom().contains(port.unwrap())
                && final(self).value()[port.unwrap()].owner == mapping.owner
                && final(self).value()[port.unwrap()].original == packet.tuple
                && final(self).value()[port.unwrap()].policy == mapping.policy
                && final(self).value()[port.unwrap()].usable(now),
            port.is_none() ==> *final(self) == *old(self),
    {
        let owner = mapping.owner;
        let policy = mapping.policy;
        let external = mapping.external;
        let mac = mapping.mac;
        let revision = mapping.revision;
        let predicate = |flow: &Flow| -> (matches: bool)
            ensures matches == (flow.original.src == packet.tuple.src),
        { flow.original.src == packet.tuple.src };
        let count = crate::library::count_values(&self.entries, predicate);
        proof {
            assert(crate::library::selected_keys(self.entries@, predicate) =~= self.source_ports(packet.tuple.src));
            assert(count == self.source_ports(packet.tuple.src).len());
        }
        if now == u64::MAX || self.entries.len() >= MAX_FLOWS
            || count >= CLIENT_FLOWS
            || (packet.tuple.proto == 6 && !initial(packet.tcp))
            || (packet.tuple.proto == 1 && packet.icmp != 8) { return None; }
        let start = (random.next_u32() % 16384) as u16;
        let entries = &self.entries;
        let port = (0..=MAX_FLOWS).find_map(|offset: usize| -> (candidate: Option<u16>)
            ensures candidate.is_some() ==> candidate.unwrap() >= FIRST && !entries@.dom().contains(candidate.unwrap()),
        {
            let port = FIRST + (usize::from(start).wrapping_add(offset) % 16384) as u16;
            if entries.contains_key(&port) { None } else { Some(port) }
        })?;
        let deadline = now.saturating_add(30 * SECOND);
        let ghost before = *self;
        let flow = Flow { owner, original: packet.tuple, policy, external, mac,
            deadline, release: deadline.saturating_add(HOLD), revision,
            state: if packet.tuple.proto == 6 { State::Syn { client: packet.tcp.seq } } else { State::Datagram } };
        self.outbound.insert((owner, packet.tuple), port); self.entries.insert(port, flow);
        proof {
            assert(self.entries@[port].valid());
            assert(self.entries@.len() <= MAX_FLOWS);
            assert(self.outbound@.len() == self.entries@.len());
            assert forall|p: u16| self.entries@.dom().contains(p) implies p >= FIRST
                && self.entries@[p].valid()
                && self.outbound@.dom().contains((self.entries@[p].owner, self.entries@[p].original))
                && self.outbound@[(self.entries@[p].owner, self.entries@[p].original)] == p by { }
            assert forall|key: (Owner, Tuple)| self.outbound@.dom().contains(key) implies
                self.entries@.dom().contains(self.outbound@[key])
                && self.entries@[self.outbound@[key]].owner == key.0 && self.entries@[self.outbound@[key]].original == key.1 by { }
            assert forall|source: [u8; 4]| self.source_ports(source).len() <= CLIENT_FLOWS by {
                if source == packet.tuple.src {
                    assert(self.source_ports(source) =~= before.source_ports(source).insert(port));
                } else { assert(self.source_ports(source) =~= before.source_ports(source)); }
            }
        }
        Some(port)
    }

    /// Apply a checked transport transition without exposing a mutable map value.
    pub(crate) fn accept(&mut self, port: u16, packet: &Packet<'_>, outbound: bool, mac: Option<[u8; 6]>, now: u64) -> (accepted: bool)
        requires old(self).valid(), packet.valid(), old(self).entries@.dom().contains(port),
            packet.tuple.proto == old(self).entries@[port].original.proto,
        ensures final(self).valid(), final(self).entries@.dom() == old(self).entries@.dom(),
            final(self).outbound@ == old(self).outbound@,
            accepted == old(self).entries@[port].accepts(*packet, outbound, now),
    {
        let ghost before = *self;
        let Some(flow) = self.entries.get_mut(&port) else { return false; };
        let accepted = flow.accept(packet, outbound, now);
        if let (true, Some(mac)) = (accepted, mac) { flow.mac = mac; }
        proof { self.mapping_update(before, port); }
        accepted
    }

    /// Recheck retained mappings against the current source, redirect and ordered
    /// policy before another packet can use their observation revision.
    pub(crate) fn observe(&mut self, view: &airlock_qubes_network::projection::View, now: u64)
        requires old(self).valid(), view.valid(),
        ensures final(self).valid(), final(self).entries@.dom() == old(self).entries@.dom(),
    {
        let ports = crate::library::port_window(&self.entries, 0, MAX_FLOWS);
        for port in ports
            invariant self.valid(), view.valid(), self.entries@.dom() == old(self).entries@.dom(),
        {
            let ghost before = *self;
            if let Some(flow) = self.entries.get_mut(&port) {
                let address_ok = match view.config() {
                    Some(config) => config.address().ipv4() == Some(flow.external)
                        && config.contains(&airlock_qubes_network::address::Ip::from_ipv4(flow.original.src)),
                    None => false,
                };
                let redirect_ok = crate::policy::redirect(view, flow.original) == Some(flow.policy);
                if !address_ok || !redirect_ok || !crate::policy::allows(view, flow.policy, if flow.policy.proto == 1 { 8 } else { 0 }, now) {
                    flow.retire(now);
                } else { flow.revision = view.generation(); }
            }
            proof {
                if before.entries@.dom().contains(port) { self.mapping_update(before, port); }
                else { self.same_records(before); }
            }
        }
    }

    /// Retire all state on an interface lifetime's withdrawal.
    pub(crate) fn retire(&mut self, owner: Owner, now: u64)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).value().dom() == old(self).value().dom(),
            forall|port: u16| final(self).value().dom().contains(port)
                && final(self).value()[port].owner == owner ==> !final(self).value()[port].usable(now),
    {
        let keys = crate::library::port_window(&self.entries, 0, MAX_FLOWS);
        let mut index = 0;
        while index < keys.len()
            invariant self.valid(), self.outbound@ == old(self).outbound@, self.entries@.dom() == old(self).entries@.dom(),
                keys@.len() <= MAX_FLOWS, index <= keys@.len(),
                forall|i: int| 0 <= i < keys@.len() ==> self.entries@.dom().contains(keys@[i]),
                forall|port: u16| old(self).entries@.dom().contains(port) ==> keys@.contains(port),
                forall|i: int| 0 <= i < index && self.entries@[keys@[i]].owner == owner ==> !self.entries@[keys@[i]].usable(now),
            decreases keys.len() - index,
        {
            let port = keys[index];
            let ghost before = *self;
            match self.entries.get_mut(&port) {
                Some(flow) if flow.owner == owner => flow.retire(now),
                _ => (),
            }
            proof { self.mapping_update(before, port); }
            index += 1;
        }
        proof {
            assert forall|port: u16| self.entries@.dom().contains(port) && self.entries@[port].owner == owner
                implies !self.entries@[port].usable(now) by {
                let i = choose|i: int| 0 <= i < keys@.len() && keys@[i] == port;
            }
        }
    }

    /// Release only an expired reservation, removing both native-map indexes.
    fn release(&mut self, port: u16, _now: u64)
        requires old(self).valid(), old(self).entries@.dom().contains(port), old(self).entries@[port].release <= _now,
        ensures final(self).valid(), final(self).entries@ == old(self).entries@.remove(port),
    {
        let ghost before = *self;
        let Some(flow) = self.entries.get(&port) else { return; };
        let key = (flow.owner, flow.original);
        self.entries.remove(&port); self.outbound.remove(&key);
        proof {
            assert forall|source: [u8; 4]| self.source_ports(source).len() <= CLIENT_FLOWS by {
                assert(self.source_ports(source).subset_of(before.source_ports(source)));
                vstd::set_lib::lemma_len_subset(self.source_ports(source), before.source_ports(source));
            }
        }
    }

    /// Visit at most 64 entries; stale ports remain unavailable until reclaimed.
    pub(crate) fn maintain(&mut self, now: u64)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).value().dom().subset_of(old(self).value().dom()),
            forall|port: u16| old(self).value().dom().contains(port) && !final(self).value().dom().contains(port)
                ==> old(self).value()[port].release <= now,
    {
        let ghost before_cursor = *self;
        let keys: alloc::vec::Vec<u16> = crate::library::port_window(&self.entries, self.cursor, 64);
        if keys.len() < 64 { self.cursor = 0; }
        else { self.cursor = keys.last().copied().unwrap_or(0).saturating_add(1); }
        proof { self.same_records(before_cursor); }
        for port in keys
            invariant self.valid(), self.entries@.dom().subset_of(old(self).entries@.dom()),
                forall|p: u16| self.entries@.dom().contains(p) ==> self.entries@[p].release >= old(self).entries@[p].release,
                forall|p: u16| old(self).entries@.dom().contains(p) && !self.entries@.dom().contains(p)
                    ==> old(self).entries@[p].release <= now,
        {
            let ghost before = *self;
            let release = if let Some(flow) = self.entries.get_mut(&port) {
                if !flow.live(now) { flow.retire(now); }
                now >= flow.release
            } else { false };
            proof {
                if before.entries@.dom().contains(port) { self.mapping_update(before, port); }
                else { self.same_records(before); }
            }
            if release { self.release(port, now); }
        }
    }
}

}
