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

use crate::diagnostics::{Meters, Occupancy, Peaks, Ports, Reclamation};
use crate::{
    MAX_FLOWS, SECOND,
    engine::Owner,
    wire::{Packet, Tcp, Tuple},
};
use airlock_qubes_network::address::Ip;
use alloc::collections::{BTreeMap, BTreeSet};
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
#[derive(Clone, Copy)]
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
    /// Active quota credit, returned on retirement or a maintenance-observed expiry.
    /// Expired entries may conservatively keep this credit until their bounded turn.
    pub(crate) charged_active: bool,
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
            && (self.state is Retired ==> !self.charged_active)
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
        ensures final(self).valid(), !final(self).usable(now), final(self).retired(), !final(self).charged_active,
            final(self).revision == old(self).revision,
            final(self).external == old(self).external, final(self).mac == old(self).mac,
            final(self).quota == old(self).quota, final(self).translated_port == old(self).translated_port,
            final(self).owner == old(self).owner && final(self).original == old(self).original
                && final(self).policy == old(self).policy && final(self).release_deadline() >= old(self).release_deadline(),
    {
        if !matches!(self.state, State::Retired) {
            self.state = State::Retired; self.charged_active = false; self.release = self.release.max(now.saturating_add(HOLD));
        }
    }

    /// Return the active credit on expiry without shortening the reservation.
    fn expire(&mut self, now: u64)
        requires old(self).valid(),
        ensures final(self).valid(),
            final(self).charged_active ==> old(self).charged_active,
            final(self).release >= old(self).release,
            final(self).quota == old(self).quota,
            final(self).owner == old(self).owner && final(self).original == old(self).original,
            final(self).external == old(self).external && final(self).translated_port == old(self).translated_port,
            final(self).wire_tuple() == old(self).wire_tuple(),
    {
        if !self.live(now) {
            self.charged_active = false;
            if self.original.proto != 17 {
                self.retire(now);
            }
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
            !accepted ==> *final(self) == *old(self),
            accepted && !final(self).retired() ==> final(self).deadline > now && final(self).charged_active,
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
            self.charged_active = true;
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
/// One source socket, independent of UDP destination identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Socket {
    /// Exact admitted native lifetime; old incarnations cannot inherit a port.
    pub(crate) owner: Owner,
    /// Assigned source address, keeping IPv4 and IPv6 translations distinct.
    pub(crate) source: Ip,
    /// Original UDP source port.
    pub(crate) port: u16,
    /// Current masquerade address, preventing reuse across upstream changes.
    pub(crate) external: Ip,
}

#[cfg(verus_keep_ghost)]
impl vstd::std_specs::cmp::PartialEqSpecImpl for Socket {
    open spec fn obeys_eq_spec() -> bool { true }

    open spec fn eq_spec(&self, other: &Self) -> bool { *self == *other }
}

/// Maintained credits for one stable client, including prior incarnations.
#[derive(Clone, Copy)]
pub(crate) struct Usage {
    /// Active credits; expired flows retain theirs until maintenance observes them.
    pub(crate) active: usize,
    /// Stored records, each already owning its eventual retirement storage.
    pub(crate) records: usize,
}

/// Admission failure without packet data or a replacement authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    /// One client has used its active allowance.
    ActiveClient,
    /// The active global allowance is exhausted.
    ActiveGlobal,
    /// This client's stored reservations leave no retirement-safe record.
    RetainedClient,
    /// The stored global reservation budget is exhausted.
    RetainedGlobal,
    /// No unused internal identifier remains.
    IdentifierExhausted,
    /// No unused translation port remains for a new socket.
    PortExhausted,
    /// An existing peer already owns this exact translated reply identity.
    TupleCollision,
    /// A transport packet cannot initiate, renew or advance this flow.
    Transport,
    /// Monotonic time is exhausted; no finite new lease can be admitted.
    Clock,
    /// A required index/record was unavailable; no replacement is fabricated.
    State,
}

impl Flow {
    /// Exact index key for a peer's source socket.
    pub(crate) open spec fn socket_key(&self) -> Socket {
        Socket { owner: self.owner, source: self.original.src, port: self.original.sport, external: self.external }
    }

    /// UDP socket identity whose sharing never changes exact-peer reply lookup.
    pub(crate) fn socket(&self) -> (socket: Socket)
        ensures socket == self.socket_key(),
    { Socket { owner: self.owner, source: self.original.src, port: self.original.sport, external: self.external } }
}

/// Standard indexes keep new admission logarithmic, including near capacity.
/// Each record owns retention storage before admission, so retiring any or all
/// active peers needs no additional peer record and cannot steal another client's slot.
pub(crate) struct Table {
    /// Exact private peer record, kept through its complete release deadline.
    pub(crate) entries: BTreeMap<u16, Flow>,
    /// Original lifetime/tuple to internal identifier.
    pub(crate) outbound: BTreeMap<(Owner, Tuple), u16>,
    /// Exact translated tuple to internal identifier; a port alone grants nothing.
    pub(crate) replies: BTreeMap<Tuple, u16>,
    /// One entry per shared UDP source socket, independent of destination count.
    pub(crate) sockets: BTreeMap<Socket, u16>,
    /// References from all retained peer records, including retired UDP peers.
    pub(crate) ports: BTreeMap<u16, usize>,
    /// Available translation ports; std ordered lookup replaces candidate scans.
    pub(crate) free_ports: BTreeSet<u16>,
    /// Available internal IDs, independent of shared translated ports.
    pub(crate) free_ids: BTreeSet<u16>,
    /// Per-client credits; zero-record entries are removed during reclamation.
    pub(crate) usage: BTreeMap<Ip, Usage>,
    /// Sum of active credits; not inferred by rescanning peer records.
    pub(crate) active: usize,
    /// Immutable settings chosen before this table admits its first peer.
    pub(crate) limits: crate::parameters::Limits,
    /// Boot-wide high-water flow occupancy, retained through reclamation.
    pub(crate) peaks: Peaks,
    /// Saturating counters describe actual scheduler and release progress.
    pub(crate) reclamation: Reclamation,
    /// Cursor bounds maintenance to at most 64 retained records per turn.
    pub(crate) cursor: u16,
}

impl Table {
    /// Stored peer records for one stable client, across native incarnations.
    pub(crate) open spec fn source_peers(&self, source: Ip) -> Set<u16> {
        self.entries@.dom().filter(|id: u16| self.entries@[id].quota == source)
    }

    /// Every active credit has one charged record in the global view.
    pub(crate) open spec fn all_active(&self) -> Set<u16> {
        self.entries@.dom().filter(|id: u16| self.entries@[id].charged_active)
    }

    /// Charged active records; conservative until the expiry maintenance turn.
    pub(crate) open spec fn active_peers(&self, source: Ip) -> Set<u16> {
        self.source_peers(source).filter(|id: u16| self.entries@[id].charged_active)
    }

    /// Exact tuple identity, bounded storage, and source/socket port isolation.
    pub(crate) open spec fn mappings_valid(&self) -> bool {
        vstd::std_specs::btree::key_obeys_cmp_spec::<(Owner, Tuple)>()
            && vstd::std_specs::btree::key_obeys_cmp_spec::<Tuple>()
            && vstd::std_specs::btree::key_obeys_cmp_spec::<Socket>()
            && vstd::std_specs::btree::key_obeys_cmp_spec::<Ip>()
            && self.limits.valid() && self.entries@.len() <= self.limits.value().retained_global <= MAX_FLOWS
            && self.outbound@.len() == self.entries@.len() && self.replies@.len() == self.entries@.len()
            && (forall|id: u16| self.entries@.dom().contains(id) ==> id >= FIRST && self.entries@[id].valid()
                && self.outbound@.dom().contains((self.entries@[id].owner, self.entries@[id].original))
                && self.outbound@[(self.entries@[id].owner, self.entries@[id].original)] == id
                && self.replies@.dom().contains(self.entries@[id].wire_tuple())
                && self.replies@[self.entries@[id].wire_tuple()] == id)
            && (forall|key: (Owner, Tuple)| self.outbound@.dom().contains(key) ==>
                self.entries@.dom().contains(self.outbound@[key])
                && self.entries@[self.outbound@[key]].owner == key.0 && self.entries@[self.outbound@[key]].original == key.1)
            && (forall|tuple: Tuple| self.replies@.dom().contains(tuple) ==>
                self.entries@.dom().contains(self.replies@[tuple]) && self.entries@[self.replies@[tuple]].wire_tuple() == tuple)
            && (forall|a: u16, b: u16| self.entries@.dom().contains(a) && self.entries@.dom().contains(b) && a != b ==>
                (self.entries@[a].translated_port == self.entries@[b].translated_port <==> self.entries@[a].same_socket(&self.entries@[b])))
    }

    /// Actual index/count correspondence, independent of individual packet claims.
    pub(crate) open spec fn accounting_valid(&self) -> bool {
        self.active == self.all_active().len()
            && self.active <= self.entries@.len()
            && self.active <= self.limits.value().active_global
            && (forall|id: u16| self.entries@.dom().contains(id) ==>
                self.usage@.dom().contains(self.entries@[id].quota))
            && (forall|source: Ip| self.usage@.dom().contains(source) ==> self.source_peers(source).len() > 0)
            && (forall|source: Ip| self.usage@.dom().contains(source) ==>
                self.usage@[source].records == self.source_peers(source).len()
                && self.usage@[source].active == self.active_peers(source).len()
                && self.usage@[source].active <= self.usage@[source].records
                && self.usage@[source].active <= self.limits.value().active_per_client
                && self.usage@[source].records <= self.limits.value().retained_per_client <= crate::CLIENT_FLOWS)
    }

    /// Records reserving the translated port, including hold-down records.
    pub(crate) open spec fn port_peers(&self, port: u16) -> Set<u16> {
        self.value().dom().filter(|id: u16| self.value()[id].translated_port == port)
    }

    /// Exact forward and reverse correspondence for one UDP socket binding.
    pub(crate) open spec fn socket_index_valid(&self) -> bool {
        (forall|socket: Socket| self.sockets@.dom().contains(socket) ==>
            exists|id: u16| self.value().dom().contains(id) && self.value()[id].original.proto == 17
                && self.value()[id].socket_key() == socket
                && self.value()[id].translated_port == self.sockets@[socket])
        && (forall|id: u16| self.value().dom().contains(id) && self.value()[id].original.proto == 17 ==>
            self.sockets@.dom().contains(self.value()[id].socket_key())
                && self.sockets@[self.value()[id].socket_key()] == self.value()[id].translated_port)
    }

    /// Free pools complement owned records; shared-port references stay exact.
    pub(crate) open spec fn allocation_valid(&self) -> bool {
        (forall|id: u16| #[trigger] self.free_ids@.contains(id)
            <==> id >= FIRST && !self.entries@.dom().contains(id))
            && (forall|port: u16| #[trigger] self.free_ports@.contains(port)
                <==> port >= FIRST && !self.ports@.dom().contains(port))
            && (forall|id: u16| self.entries@.dom().contains(id) ==>
                self.ports@.dom().contains(self.entries@[id].translated_port))
            && (forall|port: u16| self.ports@.dom().contains(port) ==> self.ports@[port] > 0
                && self.ports@[port] <= self.entries@.len()
                && self.ports@[port] == self.port_peers(port).len())
            && self.socket_index_valid()
    }

    /// Both admission and reclamation preserve these production index invariants.
    pub(crate) closed spec fn valid(&self) -> bool {
        self.mappings_valid() && self.accounting_valid() && self.allocation_valid()
    }

    /// Stored records used by the routing/related-error contracts.
    pub(crate) open spec fn value(&self) -> Map<u16, Flow> { self.entries@ }

    /// Look up a stored flow through the table invariant.
    pub(crate) fn get(&self, id: u16) -> (flow: Option<&Flow>)
        requires self.valid(),
        ensures flow.is_some() == self.value().dom().contains(id),
            flow.is_some() ==> id >= FIRST && *flow.unwrap() == self.value()[id] && flow.unwrap().valid(),
    { self.entries.get(&id) }

    /// Original tuple index, without exposing mutable lookup authority.
    pub(crate) open spec fn index_value(&self) -> Map<(Owner, Tuple), u16> { self.outbound@ }

    /// Frozen startup limits carried unchanged through every table operation.
    pub(crate) closed spec fn limits_value(&self) -> crate::parameters::Document { self.limits.value() }

    /// Constant-time global or stable-client credit and stored-record usage.
    pub(crate) fn occupancy(&self, source: Option<Ip>) -> (usage: Occupancy)
        requires self.valid(),
        ensures usage.active_credits <= usage.stored_records <= MAX_FLOWS,
            usage.inactive_records == usage.stored_records - usage.active_credits,
            source.is_none() ==> usage.active_credits == self.active && usage.stored_records == self.entries@.len(),
            source.is_some() ==> usage.stored_records == self.source_peers(source.unwrap()).len()
                && usage.active_credits == self.active_peers(source.unwrap()).len(),
    {
        let (active, stored) = match source {
            None => (self.active, self.entries.len()),
            Some(source) => match self.usage.get(&source) {
                Some(usage) => (usage.active, usage.records),
                None => {
                    proof {
                        assert(self.source_peers(source) =~= Set::empty());
                        assert(self.active_peers(source) =~= Set::empty());
                    }
                    (0, 0)
                },
            },
        };
        Occupancy { active_credits: active, stored_records: stored, inactive_records: stored - active }
    }

    /// Distinct ports held by the selected records.
    pub(crate) open spec fn ports_of(&self, ids: Set<u16>) -> Set<u16> {
        ids.map(|id: u16| self.value()[id].translated_port)
    }

    /// Distinct UDP sockets held by the selected records.
    pub(crate) open spec fn sockets_of(&self, ids: Set<u16>) -> Set<Socket> {
        ids.filter(|id: u16| self.value()[id].original.proto == 17)
            .map(|id: u16| self.value()[id].socket_key())
    }

    /// The image of any record subset holds no more ports or sockets than records.
    proof fn port_counts_bounded(&self, ids: Set<u16>)
        ensures self.ports_of(ids).len() <= ids.len(), self.sockets_of(ids).len() <= ids.len(),
    {
        vstd::set_lib::lemma_map_size_bound(ids, self.ports_of(ids), |id: u16| self.value()[id].translated_port);
        let udp = ids.filter(|id: u16| self.value()[id].original.proto == 17);
        ids.lemma_len_filter(|id: u16| self.value()[id].original.proto == 17);
        vstd::set_lib::lemma_map_size_bound(udp, self.sockets_of(ids), |id: u16| self.value()[id].socket_key());
    }

    /// Scheduled report-only port counts; packet paths never call this scan.
    /// At most MAX_FLOWS records are inspected for one of CLIENT_HISTORY sources.
    pub(crate) fn port_usage(&self, source: Option<Ip>) -> (usage: Ports)
        requires self.valid(),
        ensures usage.translation_ports <= self.entries@.len() && usage.udp_sockets <= self.entries@.len(),
            source.is_none() ==> usage.translation_ports == self.ports@.len() && usage.udp_sockets == self.sockets@.len(),
            source.is_some() ==> usage.translation_ports == self.ports_of(self.source_peers(source.unwrap())).len()
                && usage.udp_sockets == self.sockets_of(self.source_peers(source.unwrap())).len(),
    {
        broadcast use Set::lemma_map_contains;
        let Some(source) = source else {
            proof {
                let ids = self.value().dom();
                assert(self.ports@.dom() =~= self.ports_of(ids)) by {
                    assert forall|port: u16| self.ports@.dom().contains(port) implies self.ports_of(ids).contains(port) by {
                        assert(self.ports@[port] > 0 && self.port_peers(port).len() == self.ports@[port]);
                        assert(!self.port_peers(port).is_empty());
                        let id = self.port_peers(port).choose();
                        assert(ids.contains(id) && self.value()[id].translated_port == port);
                    }
                }
                assert(self.sockets@.dom() =~= self.sockets_of(ids)) by {
                    assert forall|socket: Socket| self.sockets@.dom().contains(socket) implies self.sockets_of(ids).contains(socket) by {
                        let id = choose|id: u16| ids.contains(id) && self.value()[id].original.proto == 17
                            && self.value()[id].socket_key() == socket && self.value()[id].translated_port == self.sockets@[socket];
                        assert(ids.filter(|id: u16| self.value()[id].original.proto == 17).contains(id));
                    }
                }
                self.port_counts_bounded(ids);
            }
            return Ports { translation_ports: self.ports.len(), udp_sockets: self.sockets.len() };
        };
        if !self.usage.contains_key(&source) {
            proof {
                assert(self.source_peers(source) =~= Set::empty());
                self.port_counts_bounded(self.source_peers(source));
            }
            return Ports { translation_ports: 0, udp_sockets: 0 };
        }
        let keys = crate::library::port_window(&self.entries, 0, MAX_FLOWS);
        let mut ports = BTreeSet::new();
        let mut sockets = BTreeSet::new();
        let mut index = 0;
        let ghost mut selected = Set::<u16>::empty();
        proof {
            assert(self.ports_of(selected) =~= Set::empty());
            assert(self.sockets_of(selected) =~= Set::empty());
        }
        while index < keys.len()
            invariant
                self.valid(), index <= keys@.len(), keys@.to_set() == self.value().dom(),
                forall|i: int| 0 <= i < keys@.len() ==> self.value().dom().contains(keys@[i]),
                selected == keys@.take(index as int).to_set().filter(|id: u16| self.value()[id].quota == source),
                ports@ == self.ports_of(selected), sockets@ == self.sockets_of(selected),
            decreases keys@.len() - index,
        {
            let id = keys[index];
            let ghost prior = selected;
            let ghost prior_ports = ports@;
            let ghost prior_sockets = sockets@;
            match self.entries.get(&id) {
                Some(flow) if flow.quota == source => {
                    ports.insert(flow.translated_port);
                    if flow.original.proto == 17 { sockets.insert(flow.socket()); }
                    proof { selected = selected.insert(id); }
                }
                _ => {}
            }
            proof {
                assert(keys@.take(index as int + 1) =~= keys@.take(index as int).push(id));
                assert(selected =~= keys@.take(index as int + 1).to_set().filter(|key: u16| self.value()[key].quota == source));
                if self.value()[id].quota == source {
                    assert(selected =~= prior.insert(id));
                    prior.lemma_set_map_insert_commute(id, |key: u16| self.value()[key].translated_port);
                    assert(ports@ =~= prior_ports.insert(self.value()[id].translated_port));
                    let udp = prior.filter(|key: u16| self.value()[key].original.proto == 17);
                    let next_udp = selected.filter(|key: u16| self.value()[key].original.proto == 17);
                    if self.value()[id].original.proto == 17 {
                        assert(next_udp =~= udp.insert(id));
                        udp.lemma_set_map_insert_commute(id, |key: u16| self.value()[key].socket_key());
                        assert(sockets@ =~= prior_sockets.insert(self.value()[id].socket_key()));
                    } else {
                        assert(next_udp =~= udp);
                    }
                }
                assert(ports@ =~= self.ports_of(selected));
                assert(sockets@ =~= self.sockets_of(selected));
            }
            index += 1;
        }
        proof {
            assert(keys@.take(index as int) =~= keys@);
            vstd::set_lib::lemma_len_subset(selected, self.value().dom());
            self.port_counts_bounded(selected);
        }
        Ports { translation_ports: ports.len(), udp_sockets: sockets.len() }
    }

    /// Default table used by callers without machine-specific tuning.
    #[cfg(test)]
    pub(crate) fn new() -> (table: Self)
        ensures table.valid(), table.value().len() == 0, table.index_value().len() == 0,
    { Self::with_parameters(crate::parameters::Limits::defaults()) }

    /// Construct independent fixed namespace pools and empty operating ledgers.
    pub(crate) fn with_parameters(limits: crate::parameters::Limits) -> (table: Self)
        requires limits.valid(),
        ensures table.valid(), table.value().len() == 0, table.index_value().len() == 0,
            table.limits_value() == limits.value(),
    {
        let _ = limits.document();
        proof { crate::library::derived_key_order(); }
        let table = Self { entries: BTreeMap::new(), outbound: BTreeMap::new(), replies: BTreeMap::new(),
            sockets: BTreeMap::new(), ports: BTreeMap::new(), usage: BTreeMap::new(), active: 0,
            free_ports: crate::library::port_pool(), free_ids: crate::library::port_pool(), limits, cursor: 0,
            peaks: Peaks::empty(), reclamation: Reclamation::empty() };
        proof {
            assert(table.all_active() =~= Set::empty());
            assert(table.mappings_valid());
            assert(table.accounting_valid());
            assert(table.allocation_valid());
        }
        table
    }

    /// Exact original tuple within one admitted native lifetime.
    pub(crate) fn find(&self, owner: Owner, tuple: Tuple) -> (id: Option<u16>)
        requires self.valid(),
        ensures id.is_some() == self.index_value().dom().contains((owner, tuple)),
            id.is_some() ==> self.value().dom().contains(id.unwrap())
                && self.value()[id.unwrap()].owner == owner && self.value()[id.unwrap()].original == tuple,
    { self.outbound.get(&(owner, tuple)).copied() }

    /// Exact wire tuple: sharing a source port never admits an unrelated peer.
    pub(crate) fn translated_id(&self, tuple: Tuple) -> (id: Option<u16>)
        requires self.valid(),
        ensures id.is_some() == self.replies@.dom().contains(tuple),
            id.is_some() ==> self.value().dom().contains(id.unwrap()) && self.value()[id.unwrap()].wire_tuple() == tuple,
    { self.replies.get(&tuple).copied() }

    /// Check both active work and pre-reserved retirement capacity without a scan.
    /// Stored records stay charged across address families and native reconnects.
    fn capacity(&self, source: Ip, new_record: bool) -> (failure: Option<AdmissionError>)
        requires self.valid(),
        ensures self.limits.value().supported(),
            failure.is_none() == (self.active < self.limits.value().active_global
            && (!self.usage@.dom().contains(source) || self.usage@[source].active < self.limits.value().active_per_client)
            && (new_record ==> self.entries@.len() < self.limits.value().retained_global
                && (!self.usage@.dom().contains(source) || self.usage@[source].records < self.limits.value().retained_per_client))),
            match failure {
                Some(AdmissionError::ActiveClient) => self.usage@.dom().contains(source)
                    && self.usage@[source].active >= self.limits.value().active_per_client,
                Some(AdmissionError::ActiveGlobal) => self.active >= self.limits.value().active_global,
                Some(AdmissionError::RetainedClient) => new_record && self.usage@.dom().contains(source)
                    && self.usage@[source].records >= self.limits.value().retained_per_client,
                Some(AdmissionError::RetainedGlobal) => new_record && self.entries@.len() >= self.limits.value().retained_global,
                None => true,
                _ => false,
            },
    {
        let limits = self.limits.document();
        let usage = self.usage.get(&source).copied().unwrap_or(Usage { active: 0, records: 0 });
        if usage.active >= limits.active_per_client { return Some(AdmissionError::ActiveClient); }
        if self.active >= limits.active_global { return Some(AdmissionError::ActiveGlobal); }
        if new_record && usage.records >= limits.retained_per_client { return Some(AdmissionError::RetainedClient); }
        if new_record && self.entries.len() >= limits.retained_global { return Some(AdmissionError::RetainedGlobal); }
        None
    }

    /// Create only a supported initiating peer, after reserving both credits.
    /// Every rejection leaves records, indices, pools and credits unchanged.
    #[verifier::spinoff_prover]
    pub(crate) fn create(&mut self, mapping: NewMapping, packet: &Packet<'_>, now: u64, random: &mut impl RngCore, meters: &mut Meters) -> (result: Result<u16, AdmissionError>)
        requires old(meters).valid(), old(self).valid(), mapping.owner.valid(), mapping.quota.valid(), mapping.external.valid(), packet.valid(),
            mapping.external.family() == packet.tuple.src.family(), mapping.policy.valid(), mapping.revision > 0,
            packet.tuple.src == mapping.policy.src && packet.tuple.sport == mapping.policy.sport
                && packet.tuple.dport == mapping.policy.dport && packet.tuple.proto == mapping.policy.proto,
            !old(self).index_value().dom().contains((mapping.owner, packet.tuple)),
        ensures final(meters).valid(), final(self).limits == old(self).limits, final(self).limits_value() == old(self).limits_value(),
            final(self).valid(), result.is_err() ==> *final(self) == *old(self),
            result.is_ok() ==> !old(self).value().dom().contains(result.unwrap())
                && final(self).value().dom().contains(result.unwrap())
                && final(self).value()[result.unwrap()].owner == mapping.owner
                && final(self).value()[result.unwrap()].original == packet.tuple
                && final(self).value()[result.unwrap()].policy == mapping.policy
                && final(self).value()[result.unwrap()].usable(now),
            match result {
                Err(AdmissionError::ActiveClient) => old(self).usage@.dom().contains(mapping.quota)
                    && old(self).usage@[mapping.quota].active >= old(self).limits.value().active_per_client,
                Err(AdmissionError::ActiveGlobal) => old(self).active >= old(self).limits.value().active_global,
                Err(AdmissionError::RetainedClient) => old(self).usage@.dom().contains(mapping.quota)
                    && old(self).usage@[mapping.quota].records >= old(self).limits.value().retained_per_client,
                Err(AdmissionError::RetainedGlobal) => old(self).entries@.len() >= old(self).limits.value().retained_global,
                Err(AdmissionError::IdentifierExhausted) => old(self).free_ids@.is_empty(),
                Err(AdmissionError::PortExhausted) => old(self).free_ports@.is_empty(),
                Err(AdmissionError::Clock) => now == u64::MAX,
                Err(AdmissionError::Transport) => (packet.tuple.proto == 6 && !initiating(packet.tcp))
                    || (packet.tuple.icmp() && packet.icmp != packet.tuple.request()),
                Err(AdmissionError::State) => false,
                _ => true,
            },
    {
        if now == u64::MAX { return Err(AdmissionError::Clock); }
        if (packet.tuple.proto == 6 && !initial(packet.tcp))
            || (packet.tuple.icmp() && packet.icmp != packet.tuple.request()) { return Err(AdmissionError::Transport); }
        if let Some(failure) = self.capacity(mapping.quota, true) { return Err(failure); }
        let start = FIRST + (random.next_u32() % 16384) as u16;
        let Some(id) = crate::library::pool_candidate(&self.free_ids, start) else { return Err(AdmissionError::IdentifierExhausted); };
        let socket = Socket { owner: mapping.owner, source: packet.tuple.src, port: packet.tuple.sport, external: mapping.external };
        let shared = if packet.tuple.proto == 17 { self.sockets.get(&socket).copied() } else { None };
        let port = match shared {
            Some(port) => port,
            None => match crate::library::pool_candidate(&self.free_ports, start) {
                Some(port) => port,
                None => return Err(AdmissionError::PortExhausted),
            },
        };
        let translated = Tuple { src: mapping.external, sport: port, ..mapping.policy };
        if self.replies.contains_key(&translated) { return Err(AdmissionError::TupleCollision); }
        let references = self.ports.get(&port).copied().unwrap_or(0);
        let usage = self.usage.get(&mapping.quota).copied().unwrap_or(Usage { active: 0, records: 0 });
        let deadline = now.saturating_add(if packet.tuple.proto == 17 { UDP_IDLE } else { 30 * SECOND });
        let flow = Flow { owner: mapping.owner, original: packet.tuple, quota: mapping.quota,
            policy: mapping.policy, external: mapping.external, translated_port: port, mac: mapping.mac,
            deadline, release: deadline.saturating_add(HOLD), revision: mapping.revision, charged_active: true,
            state: if packet.tuple.proto == 6 { State::Syn { client: packet.tcp.seq } } else { State::Datagram } };
        let ghost before = *self;
        self.free_ids.remove(&id);
        self.free_ports.remove(&port);
        self.ports.insert(port, references + 1);
        if packet.tuple.proto == 17 { self.sockets.insert(socket, port); }
        self.usage.insert(mapping.quota, Usage { active: usage.active + 1, records: usage.records + 1 });
        self.active += 1;
        self.outbound.insert((mapping.owner, packet.tuple), id);
        self.replies.insert(translated, id);
        self.entries.insert(id, flow);
        proof { self.inserted_peer(before, flow, id, shared); }
        self.peaks.observe(self.active, self.entries.len());
        meters.observe(mapping.quota, now, Occupancy { active_credits: usage.active + 1,
            stored_records: usage.records + 1, inactive_records: usage.records - usage.active });
        Ok(id)
    }

    /// Check the exact index insertions together with the newly charged credits.
    #[verifier::spinoff_prover]
    proof fn inserted_peer(&self, before: Self, flow: Flow, id: u16, shared: Option<u16>)
        requires before.valid(), before.limits.value().supported(), self.limits == before.limits,
            flow.valid(), flow.charged_active, id >= FIRST, !before.value().dom().contains(id),
            !before.outbound@.dom().contains((flow.owner, flow.original)),
            !before.replies@.dom().contains(flow.wire_tuple()),
            shared == if flow.original.proto == 17 && before.sockets@.dom().contains(flow.socket_key())
                { Some(before.sockets@[flow.socket_key()]) } else { None },
            match shared {
                Some(port) => flow.translated_port == port,
                None => !before.ports@.dom().contains(flow.translated_port),
            },
            self.entries@ == before.entries@.insert(id, flow),
            self.outbound@ == before.outbound@.insert((flow.owner, flow.original), id),
            self.replies@ == before.replies@.insert(flow.wire_tuple(), id),
            self.free_ids@ == before.free_ids@.remove(id),
            self.free_ports@ == before.free_ports@.remove(flow.translated_port),
            self.ports@ == before.ports@.insert(flow.translated_port,
                (if before.ports@.dom().contains(flow.translated_port) { before.ports@[flow.translated_port] + 1 } else { 1 }) as usize),
            self.sockets@ == if flow.original.proto == 17 {
                before.sockets@.insert(flow.socket_key(), flow.translated_port)
            } else { before.sockets@ },
            before.active < before.limits.value().active_global,
            before.entries@.len() < before.limits.value().retained_global,
            self.active == before.active + 1,
            !before.usage@.dom().contains(flow.quota) ||
                (before.usage@[flow.quota].active < before.limits.value().active_per_client
                    && before.usage@[flow.quota].records < before.limits.value().retained_per_client),
            self.usage@ == before.usage@.insert(flow.quota, if before.usage@.dom().contains(flow.quota) {
                Usage { active: (before.usage@[flow.quota].active + 1) as usize,
                    records: (before.usage@[flow.quota].records + 1) as usize }
            } else { Usage { active: 1, records: 1 } }),
        ensures self.valid(),
    {
        let port = flow.translated_port;
        let socket = flow.socket_key();
        assert(self.all_active() =~= before.all_active().insert(id));
        assert forall|source: Ip| self.source_peers(source) ==
            (if source == flow.quota { before.source_peers(source).insert(id) } else { before.source_peers(source) }) by {
            assert(self.source_peers(source) =~=
                if source == flow.quota { before.source_peers(source).insert(id) } else { before.source_peers(source) });
        }
        assert forall|source: Ip| self.active_peers(source) ==
            (if source == flow.quota { before.active_peers(source).insert(id) } else { before.active_peers(source) }) by {
            assert(self.active_peers(source) =~=
                if source == flow.quota { before.active_peers(source).insert(id) } else { before.active_peers(source) });
        }
        assert forall|other: u16| before.value().dom().contains(other) implies
            (self.value()[other].translated_port == port <==> self.value()[other].same_socket(&flow)) by {
            if let Some(existing_port) = shared {
                let member = choose|member: u16| before.value().dom().contains(member)
                    && before.value()[member].original.proto == 17
                    && socket == (Socket { owner: before.value()[member].owner, source: before.value()[member].original.src,
                        port: before.value()[member].original.sport, external: before.value()[member].external })
                    && before.value()[member].translated_port == existing_port;
                assert(before.value()[member].same_socket(&flow));
                if other != member {
                    assert((before.value()[other].translated_port == existing_port)
                        == before.value()[other].same_socket(&before.value()[member]));
                }
            }
        }
        assert(self.value().dom().filter(|key: u16| self.value()[key].translated_port == port)
            =~= before.value().dom().filter(|key: u16| before.value()[key].translated_port == port).insert(id));
        assert(self.mappings_valid());
        assert forall|client: Ip| self.usage@.dom().contains(client) implies
            self.usage@[client].records == self.source_peers(client).len()
                && self.usage@[client].active == self.active_peers(client).len() by {
            if client == flow.quota && !before.usage@.dom().contains(client) {
                assert(before.source_peers(client) =~= Set::empty());
                assert(before.active_peers(client) =~= Set::empty());
            }
        }
        vstd::set_lib::lemma_len_subset(self.all_active(), self.value().dom());
        assert forall|client: Ip| self.usage@.dom().contains(client) implies
            self.usage@[client].active <= self.usage@[client].records
                && self.usage@[client].active <= self.limits.value().active_per_client
                && self.usage@[client].records <= self.limits.value().retained_per_client by {
            vstd::set_lib::lemma_len_subset(self.active_peers(client), self.source_peers(client));
            if client != flow.quota {
                assert(before.usage@.dom().contains(client));
            }
        }
        assert forall|client: Ip| self.usage@.dom().contains(client) implies self.source_peers(client).len() > 0 by {
            if client == flow.quota { assert(self.source_peers(client).contains(id)); }
            else { assert(before.usage@.dom().contains(client)); }
        }
        assert forall|key: u16| self.value().dom().contains(key) implies
            self.usage@.dom().contains(self.value()[key].quota) by {
            if key != id { assert(before.value().dom().contains(key)); }
        }
        assert(self.accounting_valid());
        assert forall|p: u16| self.ports@.dom().contains(p) implies
            self.ports@[p] == self.port_peers(p).len() && 0 < self.ports@[p] <= self.value().len() by {
            if p != port {
                assert(self.port_peers(p) =~= before.port_peers(p));
             } else {
                assert(self.port_peers(p) =~= before.port_peers(p).insert(id));
                if !before.ports@.dom().contains(p) { assert(before.port_peers(p) =~= Set::empty()); }
            }
            vstd::set_lib::lemma_len_subset(self.port_peers(p), self.value().dom());
        }
        assert forall|key: u16| self.value().dom().contains(key) implies
            self.ports@.dom().contains(self.value()[key].translated_port) by {
            if key != id { assert(before.value().dom().contains(key)); }
        }
        assert forall|key: u16| self.value().dom().contains(key) && self.value()[key].original.proto == 17 implies
            self.sockets@.dom().contains(self.value()[key].socket_key())
                && self.sockets@[self.value()[key].socket_key()] == self.value()[key].translated_port by {
            if key == id { assert(flow.socket_key() == socket); }
            else {
                assert(before.value().dom().contains(key));
                if self.value()[key].socket_key() == socket && flow.original.proto == 17 {
                    assert(before.sockets@.dom().contains(socket));
                    assert(shared == Some(port));
                }
            }
        }
        assert forall|key: Socket| self.sockets@.dom().contains(key) implies
            exists|member: u16| self.value().dom().contains(member) && self.value()[member].original.proto == 17
                && self.value()[member].socket_key() == key && self.value()[member].translated_port == self.sockets@[key] by {
            if key == socket && flow.original.proto == 17 {
                assert(flow.socket_key() == key);
                assert(self.value().dom().contains(id) && self.value()[id].socket_key() == key);
            } else {
                assert(before.sockets@.dom().contains(key));
                let member = choose|member: u16| before.value().dom().contains(member) && before.value()[member].original.proto == 17
                    && before.value()[member].socket_key() == key && before.value()[member].translated_port == before.sockets@[key];
                assert(self.value().dom().contains(member) && self.value()[member] == before.value()[member]);
            }
        }
        assert(self.socket_index_valid());
        assert(self.allocation_valid());
    }

    /// Link a record with the credits it owns before changing its active charge.
    proof fn record_holds_credit(&self, id: u16)
        requires self.valid(), self.entries@.dom().contains(id),
        ensures self.usage@.dom().contains(self.entries@[id].quota),
            self.entries@[id].charged_active ==> self.active > 0 && self.usage@[self.entries@[id].quota].active > 0,
            !self.entries@[id].charged_active ==> self.active < self.entries@.len()
                && self.usage@[self.entries@[id].quota].active < self.usage@[self.entries@[id].quota].records,
    {
        let source = self.entries@[id].quota;
        assert(self.source_peers(source).contains(id));
        if self.entries@[id].charged_active {
            assert(self.all_active().contains(id));
            assert(self.active_peers(source).contains(id));
        } else {
            self.all_active().lemma_subset_not_in_lt(self.entries@.dom(), id);
            self.active_peers(source).lemma_subset_not_in_lt(self.source_peers(source), id);
        }
    }

    /// In-place lifecycle changes preserve tuple and socket keys. Only the active
    /// subsets can change, by the same single record as their ledger charges.
    proof fn preserved_flow_change(&self, before: Self, id: u16)
        requires before.valid(), before.value().dom().contains(id), self.value().dom().contains(id),
            self.value() == before.value().insert(id, self.value()[id]),
            self.value()[id].valid(),
            self.value()[id].quota == before.value()[id].quota,
            self.value()[id].owner == before.value()[id].owner,
            self.value()[id].original == before.value()[id].original,
            self.value()[id].external == before.value()[id].external,
            self.value()[id].translated_port == before.value()[id].translated_port,
            self.value()[id].wire_tuple() == before.value()[id].wire_tuple(),
            self.outbound@ == before.outbound@, self.replies@ == before.replies@,
            self.free_ids@ == before.free_ids@, self.free_ports@ == before.free_ports@,
            self.ports@ == before.ports@, self.sockets@ == before.sockets@,
            self.limits == before.limits,
        ensures self.mappings_valid(), self.allocation_valid(),
            self.value().dom() == before.value().dom(),
            forall|key: u16| self.value().dom().contains(key) ==> self.value()[key].quota == before.value()[key].quota,
            self.all_active() == if self.value()[id].charged_active { before.all_active().insert(id) } else { before.all_active().remove(id) },
            forall|source: Ip| self.source_peers(source) == before.source_peers(source),
            forall|source: Ip| self.active_peers(source) ==
                if source == self.value()[id].quota {
                    if self.value()[id].charged_active { before.active_peers(source).insert(id) } else { before.active_peers(source).remove(id) }
                } else { before.active_peers(source) },
    {
        assert(self.value().dom() =~= before.value().dom());
        assert forall|a: u16, b: u16| self.value().dom().contains(a) && self.value().dom().contains(b) && a != b implies
            (self.value()[a].translated_port == self.value()[b].translated_port <==> self.value()[a].same_socket(&self.value()[b])) by {
            assert(before.value().dom().contains(a) && before.value().dom().contains(b));
            assert(self.value()[a].same_socket(&self.value()[b]) == before.value()[a].same_socket(&before.value()[b]));
        }
        assert forall|port: u16| self.ports@.dom().contains(port) implies
            self.ports@[port] == self.value().dom().filter(|key: u16| self.value()[key].translated_port == port).len() by {
            assert(self.value().dom().filter(|key: u16| self.value()[key].translated_port == port)
                =~= before.value().dom().filter(|key: u16| before.value()[key].translated_port == port));
        }

        assert(self.all_active() =~= if self.value()[id].charged_active {
            before.all_active().insert(id)
        } else { before.all_active().remove(id) });
        assert forall|source: Ip| self.source_peers(source) == before.source_peers(source) by {
            assert(self.source_peers(source) =~= before.source_peers(source));
        }
        assert forall|source: Ip| self.active_peers(source) ==
            (if source == self.value()[id].quota {
                if self.value()[id].charged_active { before.active_peers(source).insert(id) }
                else { before.active_peers(source).remove(id) }
            } else { before.active_peers(source) }) by {
            assert(self.active_peers(source) =~= if source == self.value()[id].quota {
                if self.value()[id].charged_active { before.active_peers(source).insert(id) }
                else { before.active_peers(source).remove(id) }
            } else { before.active_peers(source) });
        }
    }

    /// Reconcile the active ledger with the one-record transition.
    proof fn preserved_active_accounting(&self, before: Self, id: u16)
        requires before.valid(), before.value().dom().contains(id), self.value().dom() == before.value().dom(),
            self.value()[id].quota == before.value()[id].quota, self.limits == before.limits,
            self.usage@.dom() == before.usage@.dom(),
            forall|source: Ip| self.source_peers(source) == before.source_peers(source),
            self.all_active() == if self.value()[id].charged_active { before.all_active().insert(id) } else { before.all_active().remove(id) },
            forall|source: Ip| self.active_peers(source) ==
                (if source == self.value()[id].quota {
                    if self.value()[id].charged_active { before.active_peers(source).insert(id) }
                    else { before.active_peers(source).remove(id) }
                } else { before.active_peers(source) }),
            self.active == before.active + (if self.value()[id].charged_active { 1int } else { 0int })
                - (if before.value()[id].charged_active { 1int } else { 0int }),
            self.active <= self.limits.value().active_global,
            forall|source: Ip| self.usage@.dom().contains(source) ==>
                self.usage@[source].records == before.usage@[source].records
                && self.usage@[source].active <= self.limits.value().active_per_client
                && self.usage@[source].active == before.usage@[source].active
                    + (if source == self.value()[id].quota && self.value()[id].charged_active { 1int } else { 0int })
                    - (if source == self.value()[id].quota && before.value()[id].charged_active { 1int } else { 0int }),
            forall|key: u16| self.value().dom().contains(key) ==> self.value()[key].quota == before.value()[key].quota,
        ensures self.accounting_valid(),
    {
        let source = self.value()[id].quota;
        assert(before.all_active().contains(id) == before.value()[id].charged_active);
        assert(before.active_peers(source).contains(id) == before.value()[id].charged_active);
        vstd::set_lib::lemma_len_subset(self.all_active(), self.value().dom());
        assert forall|client: Ip| self.usage@.dom().contains(client) implies
            self.usage@[client].active == self.active_peers(client).len()
                && self.usage@[client].active <= self.usage@[client].records by {
            vstd::set_lib::lemma_len_subset(self.active_peers(client), self.source_peers(client));
        }
    }

    /// Apply an already checked flow transition's change in active credits.
    /// The caller keeps the same quota/record and permits activation only after
    /// capacity validation. This helper neither changes records nor allocates.
    fn active_transition(&mut self, source: Ip, was_active: bool, is_active: bool, now: u64, meters: &mut Meters)
        requires old(meters).valid(), self.usage@.dom().contains(source), source.valid(),
            vstd::std_specs::btree::key_obeys_cmp_spec::<Ip>(),
            self.active <= self.entries@.len(), self.usage@[source].active <= self.usage@[source].records,
            !was_active && is_active ==> self.active < self.entries@.len() && self.usage@[source].active < self.usage@[source].records,
            was_active && !is_active ==> self.active > 0 && self.usage@[source].active > 0,
            !was_active && is_active ==> self.active < MAX_FLOWS && self.usage@[source].active < crate::CLIENT_FLOWS,
        ensures final(meters).valid(), final(self).active == old(self).active + (if is_active { 1int } else { 0int }) - (if was_active { 1int } else { 0int }),
            final(self).usage@.dom() == old(self).usage@.dom(),
            final(self).usage@[source].active == old(self).usage@[source].active + (if is_active { 1int } else { 0int }) - (if was_active { 1int } else { 0int }),
            final(self).usage@[source].records == old(self).usage@[source].records,
            forall|other: Ip| old(self).usage@.dom().contains(other) && other != source ==> final(self).usage@[other] == old(self).usage@[other],
            final(self).entries@ == old(self).entries@ && final(self).outbound@ == old(self).outbound@
                && final(self).replies@ == old(self).replies@ && final(self).ports@ == old(self).ports@
                && final(self).sockets@ == old(self).sockets@ && final(self).free_ids@ == old(self).free_ids@
                && final(self).free_ports@ == old(self).free_ports@ && final(self).limits == old(self).limits,
    {
        if was_active == is_active { return; }
        let Some(usage) = self.usage.get_mut(&source) else { return; };
        if is_active { usage.active += 1; self.active += 1; }
        else { usage.active -= 1; self.active -= 1; self.reclamation.active_returns = self.reclamation.active_returns.saturating_add(1); }
        let active = usage.active;
        let stored = usage.records;
        self.peaks.observe(self.active, self.entries.len());
        meters.observe(source, now, Occupancy { active_credits: active, stored_records: stored, inactive_records: stored - active });
    }

    /// Commit a validated peer update without changing its reservations.
    fn replace_peer(&mut self, id: u16, flow: Flow, now: u64, meters: &mut Meters)
        requires old(self).valid(), old(meters).valid(), old(self).value().dom().contains(id),
            flow.valid(),
            flow.quota == old(self).value()[id].quota,
            flow.owner == old(self).value()[id].owner,
            flow.original == old(self).value()[id].original,
            flow.external == old(self).value()[id].external,
            flow.translated_port == old(self).value()[id].translated_port,
            flow.wire_tuple() == old(self).value()[id].wire_tuple(),
            !old(self).value()[id].charged_active && flow.charged_active ==>
                old(self).active < old(self).limits.value().active_global
                    && old(self).usage@[flow.quota].active < old(self).limits.value().active_per_client,
        ensures final(self).valid(), final(meters).valid(), final(self).limits == old(self).limits,
            final(self).outbound@ == old(self).outbound@,
            final(self).value() == old(self).value().insert(id, flow),
    {
        proof { self.record_holds_credit(id); }
        let ghost before = *self;
        let Some(previous) = self.entries.insert(id, flow) else { return; };
        self.active_transition(flow.quota, previous.charged_active, flow.charged_active, now, meters);
        proof {
            self.preserved_flow_change(before, id);
            self.preserved_active_accounting(before, id);
        }
    }

    /// Existing UDP may regain an active credit after idle expiry, but only on
    /// a policy-checked outbound packet. Explicit retirement is never revived.
    #[verifier::spinoff_prover]
    pub(crate) fn accept(&mut self, id: u16, packet: &Packet<'_>, outbound: bool, mac: Option<[u8; 6]>, now: u64, meters: &mut Meters) -> (result: Result<(), AdmissionError>)
        requires old(meters).valid(), old(self).valid(), packet.valid(), old(self).entries@.dom().contains(id),
            packet.tuple.proto == old(self).entries@[id].original.proto,
        ensures final(meters).valid(), final(self).limits == old(self).limits, final(self).limits_value() == old(self).limits_value(),
            final(self).valid(), final(self).entries@.dom() == old(self).entries@.dom(),
            final(self).outbound@ == old(self).outbound@,
            result.is_err() ==> final(self).value() == old(self).value()
                && final(self).replies@ == old(self).replies@
                && final(self).active == old(self).active && final(self).usage@ == old(self).usage@
                && final(self).free_ids@ == old(self).free_ids@ && final(self).free_ports@ == old(self).free_ports@
                && final(self).sockets@ == old(self).sockets@ && final(self).ports@ == old(self).ports@
                && final(self).peaks == old(self).peaks && final(self).reclamation == old(self).reclamation
                && final(self).cursor == old(self).cursor,
            result.is_ok() ==> old(self).entries@[id].accepts(*packet, outbound, now),
    {
        hide(Table::mappings_valid);
        hide(Table::allocation_valid);
        proof { self.record_holds_credit(id); }
        let Some(flow) = self.get(id) else { return Err(AdmissionError::State); };
        let mut flow = *flow;
        let source = flow.quota;
        let was_active = flow.charged_active;
        if !was_active {
            if !outbound || matches!(flow.state, State::Retired) || packet.tuple.proto != 17 { return Err(AdmissionError::Transport); }
            if let Some(failure) = self.capacity(source, false) { return Err(failure); }
        }
        if !flow.accept(packet, outbound, now) { return Err(AdmissionError::Transport); }
        if let Some(mac) = mac { flow.mac = mac; }
        self.replace_peer(id, flow, now, meters);
        Ok(())
    }

    /// Recheck all retained peers on policy replacement. Expired/revoked records
    /// keep their indices/ports while losing active credits; no new peer record is needed.
    pub(crate) fn observe(&mut self, view: &airlock_qubes_network::projection::View, now: u64, meters: &mut Meters)
        requires old(meters).valid(), old(self).valid(), view.valid(),
        ensures final(meters).valid(), final(self).limits == old(self).limits, final(self).limits_value() == old(self).limits_value(),
            final(self).valid(), final(self).entries@.dom() == old(self).entries@.dom(),
    {
        let keys = crate::library::port_window(&self.entries, 0, MAX_FLOWS);
        for id in keys
            invariant self.valid(), meters.valid(), self.limits == old(self).limits, view.valid(), self.entries@.dom() == old(self).entries@.dom(),
        {
            proof {
                if self.entries@.dom().contains(id) { self.record_holds_credit(id); }
            }
            let ghost before = *self;
            let ghost before = *self;
            if let Some(flow) = self.entries.get_mut(&id) {
                let source = flow.quota;
                let was_active = flow.charged_active;
                let address_ok = match view.config() {
                    Some(config) => crate::policy::external(config, flow.original.src.version()) == Some(flow.external)
                        && config.contains(&flow.original.src),
                    None => false,
                };
                if !address_ok || crate::policy::redirect(view, flow.original) != Some(flow.policy)
                    || !crate::policy::allows(view, flow.policy, if flow.policy.icmp() { flow.policy.request() } else { 0 }, now) {
                    flow.retire(now);
                } else { flow.revision = view.generation(); }
                let is_active = flow.charged_active;
                self.active_transition(source, was_active, is_active, now, meters);
                proof {
                    self.preserved_flow_change(before, id);
                    self.preserved_active_accounting(before, id);
                }
            }
        }
    }

    /// Withdraw one exact native lifetime, preserving other clients' active work.
    pub(crate) fn retire(&mut self, owner: Owner, now: u64, meters: &mut Meters)
        requires old(meters).valid(), old(self).valid(),
        ensures final(meters).valid(), final(self).limits == old(self).limits, final(self).limits_value() == old(self).limits_value(),
            final(self).valid(), final(self).value().dom() == old(self).value().dom(),
            forall|id: u16| final(self).value().dom().contains(id) && final(self).value()[id].owner == owner
                ==> !final(self).value()[id].usable(now),
    {
        let keys = crate::library::port_window(&self.entries, 0, MAX_FLOWS);
        let mut index = 0;
        while index < keys.len()
            invariant self.valid(), meters.valid(), self.limits == old(self).limits, self.entries@.dom() == old(self).entries@.dom(),
                keys@.len() <= MAX_FLOWS, index <= keys@.len(),
                forall|i: int| 0 <= i < keys@.len() ==> self.entries@.dom().contains(keys@[i]),
                forall|id: u16| old(self).entries@.dom().contains(id) ==> keys@.contains(id),
                forall|i: int| 0 <= i < index && self.entries@[keys@[i]].owner == owner
                    ==> !self.entries@[keys@[i]].usable(now),
            decreases keys.len() - index,
        {
            let id = keys[index];
            index += 1;

            let ghost before = *self;
            proof {
                if self.entries@.dom().contains(id) { self.record_holds_credit(id); }
            }
            if !self.entries.get(&id).is_some_and(|flow: &Flow| -> (matches: bool)
                ensures matches == (flow.owner == owner), { flow.owner == owner })
            {
                continue;
            }

            if let Some(flow) = self.entries.get_mut(&id) {
                let source = flow.quota;
                let was_active = flow.charged_active;
                flow.retire(now);
                self.active_transition(source, was_active, false, now, meters);
                proof {
                    self.preserved_flow_change(before, id);
                    self.preserved_active_accounting(before, id);
                }
            }
        }
        proof {
            assert forall|id: u16| self.entries@.dom().contains(id) && self.entries@[id].owner == owner
                implies !self.entries@[id].usable(now) by {
                let i = choose|i: int| 0 <= i < keys@.len() && keys@[i] == id;
            }
        }
    }

    /// Release only after the complete hold-down. Shared UDP ports return to the
    /// free pool only with their last retained peer, never when one peer expires.
    fn release(&mut self, id: u16, now: u64, meters: &mut Meters)
        requires old(meters).valid(), old(self).valid(), old(self).entries@.dom().contains(id), old(self).entries@[id].release <= now,
        ensures final(meters).valid(), final(self).limits == old(self).limits, final(self).limits_value() == old(self).limits_value(),
            final(self).valid(), final(self).entries@ == old(self).entries@.remove(id),
    {
        let ghost before = *self;
        proof { self.record_holds_credit(id); }
        let Some(flow) = self.entries.get(&id) else { return; };
        let source = flow.quota;
        let owner = flow.owner;
        let original = flow.original;
        let translated = flow.translated();
        let port = flow.translated_port;
        let socket = flow.socket();
        let was_active = flow.charged_active;
        let Some(references) = self.ports.get(&port).copied() else { return; };
        let Some(usage) = self.usage.get(&source).copied() else { return; };
        if let Some(flow) = self.entries.get_mut(&id) { flow.charged_active = false; }
        self.active_transition(source, was_active, false, now, meters);
        self.entries.remove(&id);
        self.outbound.remove(&(owner, original));
        self.replies.remove(&translated);
        self.free_ids.insert(id);
        if references == 1 {
            self.ports.remove(&port);
            self.free_ports.insert(port);
            self.reclamation.ports_released = self.reclamation.ports_released.saturating_add(1);
            if original.proto == 17 { self.sockets.remove(&socket); }
        } else { self.ports.insert(port, references - 1); }
        self.reclamation.records_released = self.reclamation.records_released.saturating_add(1);
        self.reclamation.last_release_ns = Some(now);
        if usage.records == 1 { self.usage.remove(&source); }
        else { self.usage.insert(source, Usage { active: usage.active - if was_active { 1 } else { 0 }, records: usage.records - 1 }); }
        proof {
            assert(self.all_active() =~= before.all_active().remove(id));
            assert forall|client: Ip| self.source_peers(client) == before.source_peers(client).remove(id) by {
                assert(self.source_peers(client) =~= before.source_peers(client).remove(id));
            }
            assert forall|client: Ip| self.active_peers(client) == before.active_peers(client).remove(id) by {
                assert(self.active_peers(client) =~= before.active_peers(client).remove(id));
            }
            assert(self.mappings_valid());
            assert(before.source_peers(source).contains(id));
            assert(self.source_peers(source).len() + 1 == before.source_peers(source).len());
            assert(self.value().dom().filter(|key: u16| self.value()[key].translated_port == port)
                =~= before.value().dom().filter(|key: u16| before.value()[key].translated_port == port).remove(id));
            assert forall|client: Ip| self.usage@.dom().contains(client) implies
                self.usage@[client].records == self.source_peers(client).len()
                    && self.usage@[client].active == self.active_peers(client).len() by {
                if client == source {
                    assert(before.active_peers(client).contains(id) == was_active);
                } else {
                    assert(!before.source_peers(client).contains(id));
                    assert(!before.active_peers(client).contains(id));
                }
            }
            assert forall|key: u16| self.value().dom().contains(key) implies
                self.usage@.dom().contains(self.value()[key].quota) by {
                if self.value()[key].quota == source {
                    assert(self.source_peers(source).contains(key));
                    assert(self.source_peers(source).len() > 0);
                }
            }
            assert(self.accounting_valid());
            if references == 1 {
                let owners = before.value().dom().filter(|key: u16| before.value()[key].translated_port == port);
                assert(owners.contains(id));
                assert(owners.len() == 1);
                assert(owners.remove(id) =~= Set::empty());
                assert forall|key: u16| self.value().dom().contains(key) implies self.value()[key].translated_port != port by {
                    if self.value()[key].translated_port == port { assert(owners.remove(id).contains(key)); }
                }
            }
            assert forall|key: u16| self.value().dom().contains(key) implies
                self.ports@.dom().contains(self.value()[key].translated_port) by {
                assert(before.value().dom().contains(key));
                if references == 1 { assert(self.value()[key].translated_port != port); }
            }
            assert forall|key: u16| self.value().dom().contains(key) && self.value()[key].original.proto == 17 implies
                self.sockets@.dom().contains(self.value()[key].socket_key())
                    && self.sockets@[self.value()[key].socket_key()] == self.value()[key].translated_port by {
                if references == 1 && original.proto == 17 {
                    assert(self.value()[key].translated_port != port);
                    assert(!before.value()[key].same_socket(&before.value()[id]));
                }
            }
            assert forall|key: Socket| self.sockets@.dom().contains(key) implies
                exists|member: u16| self.value().dom().contains(member) && self.value()[member].original.proto == 17
                    && self.value()[member].socket_key() == key && self.value()[member].translated_port == self.sockets@[key] by {
                let member = choose|member: u16| before.value().dom().contains(member) && before.value()[member].original.proto == 17
                    && before.value()[member].socket_key() == key && before.value()[member].translated_port == before.sockets@[key];
                if member != id {
                    assert(self.value().dom().contains(member) && self.value()[member] == before.value()[member]);
                } else {
                    assert(key == socket && references > 1);
                    assert(before.port_peers(port).contains(id));
                    assert(self.port_peers(port) =~= before.port_peers(port).remove(id));
                    assert(self.port_peers(port).len() == references - 1 && !self.port_peers(port).is_empty());
                    let peer = self.port_peers(port).choose();
                    assert(self.value().dom().contains(peer) && peer != id && self.value()[peer].translated_port == port);
                    assert(before.value()[peer].same_socket(&before.value()[id]));
                    assert(self.value()[peer].original.proto == 17 && self.value()[peer].socket_key() == key);
                }
            }
            assert(self.socket_index_valid());
            assert forall|p: u16| self.ports@.dom().contains(p) implies
                self.ports@[p] == self.port_peers(p).len() && 0 < self.ports@[p] <= self.value().len() by {
                if p != port {
                    assert(self.port_peers(p) =~= before.port_peers(p));
                } else {
                    assert(self.port_peers(p) =~= before.port_peers(p).remove(id));
                    assert(before.port_peers(p).contains(id));
                }
                vstd::set_lib::lemma_len_subset(self.port_peers(p), self.value().dom());
            }
            assert(self.allocation_valid());
        }
    }

    /// At most 64 records per turn. Inactive credit reclamation and eventual
    /// port release progress independently; neither path steals another's state.
    pub(crate) fn maintain(&mut self, now: u64, meters: &mut Meters)
        requires old(meters).valid(), old(self).valid(),
        ensures final(meters).valid(), final(self).limits == old(self).limits, final(self).limits_value() == old(self).limits_value(),
            final(self).valid(), final(self).value().dom().subset_of(old(self).value().dom()),
            forall|id: u16| old(self).value().dom().contains(id) && !final(self).value().dom().contains(id)
                ==> old(self).value()[id].release <= now,
    {
        let keys = crate::library::port_window(&self.entries, self.cursor, 64);
        self.reclamation.turns = self.reclamation.turns.saturating_add(1);
        self.reclamation.examined = self.reclamation.examined.saturating_add(keys.len() as u64);
        if keys.len() < 64 { self.cursor = 0; }
        else { self.cursor = keys.last().copied().unwrap_or(0).saturating_add(1); }
        for id in keys
            invariant self.valid(), meters.valid(), self.limits == old(self).limits, self.entries@.dom().subset_of(old(self).entries@.dom()),
                forall|key: u16| self.entries@.dom().contains(key) ==>
                    self.entries@[key].release >= old(self).entries@[key].release,
                forall|id: u16| old(self).entries@.dom().contains(id) && !self.entries@.dom().contains(id)
                    ==> old(self).entries@[id].release <= now,
        {
            self.maintain_record(id, now, meters);
        }
    }

    /// Release one due reservation or update its active charge in place.
    #[verifier::spinoff_prover]
    fn maintain_record(&mut self, id: u16, now: u64, meters: &mut Meters)
        requires old(meters).valid(), old(self).valid(),
        ensures final(meters).valid(), final(self).valid(), final(self).limits == old(self).limits,
            final(self).entries@.dom() == old(self).entries@.dom()
                || final(self).entries@.dom() == old(self).entries@.dom().remove(id)
                    && old(self).entries@[id].release <= now,
            forall|key: u16| final(self).entries@.dom().contains(key) ==>
                final(self).entries@[key].release >= old(self).entries@[key].release,
    {
        proof {
            if self.entries@.dom().contains(id) { self.record_holds_credit(id); }
        }
        let ghost before = *self;
        if let Some(flow) = self.entries.get_mut(&id) {
            let source = flow.quota;
            let was_active = flow.charged_active;
            flow.expire(now);
            let is_active = flow.charged_active;
            let release = now >= flow.release;
            self.active_transition(source, was_active, is_active, now, meters);
            proof {
                assert(self.value() == before.value().insert(id, self.value()[id]));
                self.preserved_flow_change(before, id);
                self.preserved_active_accounting(before, id);
                assert(self.value()[id].release >= before.value()[id].release);
            }
            if release {
                proof { assert(before.value()[id].release <= now); }
                self.release(id, now, meters);
            }
        }
    }
}

}
