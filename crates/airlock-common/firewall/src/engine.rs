//! Routing, fair queues and native-lifetime correlation. Scheduling and Xen
//! calls remain outside this module. Every queued effect is revision stamped.

use crate::{
    MAX_CLIENTS, MTU, QUEUE_FRAMES, SECOND,
    dns::Resolver,
    flow::{NewMapping, Table},
    fragment::{self, Emission, History, Layout, Reassembly},
    policy,
    wire::{self, Packet, Tuple},
};
use airlock_qubes_network::{address::Ip, binding::Bound, projection::View, resolution::Resolved};
use alloc::{collections::VecDeque, vec, vec::Vec};
use rand_chacha::ChaCha20Rng;
use rand_core::RngCore;

use crate::wire::codec;
use vstd::prelude::*;
use vstd::slice::slice_to_vec;
#[cfg(verus_keep_ghost)]
use vstd::view::View as ValueView;

verus! {

broadcast use { vstd::laws_cmp::group_laws_cmp, vstd::std_specs::iter::group_iter_axioms, crate::library::byte_array_equality,
    vstd::std_specs::vec::group_vec_axioms,
    vstd::std_specs::vecdeque::group_vec_dequeue_axioms,
    vstd::set::group_set_lemmas, vstd::seq_lib::group_filter_ensures, vstd::seq::group_seq_lemmas, vstd::seq_lib::group_seq_properties,
    vstd::seq::Seq::lemma_as_ref_index, vstd::seq::Seq::filter_distributes_over_add,
    vstd::seq::Seq::lemma_filter_len_push, vstd::slice::group_slice_axioms,
    vstd::std_specs::btree::group_btree_axioms };

/// Native lifetime labels copied from an admitted binding. These labels carry
/// no ability to perform a native operation; the application must obtain permit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Owner {
    /// Connection incarnation, never a packet or peer-supplied identifier.
    connection: u32,
    /// Nonreused backend lease for the original interface.
    lease: u32,
    /// Original Xen peer, correlated with both incarnations above.
    peer: u16,
}

/// The compiler-derived equality compares every field. This specification uses
/// that standard derive, rather than introducing a runtime comparison wrapper.
#[cfg(verus_keep_ghost)]
impl vstd::std_specs::cmp::PartialEqSpecImpl for Owner {
    open spec fn obeys_eq_spec() -> bool { true }

    open spec fn eq_spec(&self, other: &Self) -> bool { *self == *other }
}

impl Owner {
    /// Labels are only meaningful within one nonzero admitted native lifetime.
    pub closed spec fn valid(&self) -> bool {
        self.connection > 0 && self.lease > 0 && 0 < self.peer < 0x7ff0
    }

    /// Exact control, native lease and peer labels; no resource handle is exposed.
    pub closed spec fn labels(&self) -> (u32, u32, u16) { (self.connection, self.lease, self.peer) }

    /// Copy labels from a validated completed barrier, never from packet bytes.
    pub fn from_binding(binding: &Bound) -> (owner: Self)
        requires binding.valid(),
        ensures owner.valid(), owner.labels() == binding.labels(),
    {
        let (connection, lease, peer) = binding.identity(); Self { connection, lease, peer }
    }
}

/// Destination of one already filtered packet, independent of its claimed IPs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// Existing native upstream frontend, never a dynamically packet-selected peer.
    Upstream,
    /// Exact original client owner; no domid-only queue lookup is sufficient.
    Client(/// Native lifetime copied from the original validated binding.
        Owner),
}

/// The compiler-generated enum comparison retains its exact variant and owner.
#[cfg(verus_keep_ghost)]
impl vstd::std_specs::cmp::PartialEqSpecImpl for Target {
    open spec fn obeys_eq_spec() -> bool { true }

    open spec fn eq_spec(&self, other: &Self) -> bool { *self == *other }
}

/// Private queued output. Construction is confined to this core; native effects
/// still require checking this value with the current projection and owner.
pub struct Output {
    /// Native destination, independent of all IP/Ethernet claims.
    target: Target,
    /// Client lifetime required for either direction of a client-created flow.
    owner: Option<Owner>,
    /// Exact view observation revision used for the packet decision.
    revision: u64,
    /// Bounded complete Ethernet frame after next-hop resolution.
    bytes: Vec<u8>,
    /// Absolute queue deadline, preventing indefinite delayed authorized effects.
    deadline: u64,
}

impl Output {
    /// Finite output for one exact native target and one volatile observation.
    pub closed spec fn valid(&self) -> bool {
        14 <= self.bytes@.len() <= MTU + 14 && self.revision > 0 && self.deadline > 0
            && match self.owner { Some(owner) => owner.valid(), None => self.target == Target::Upstream }
            && match self.target { Target::Client(owner) => self.owner == Some(owner), _ => true }
    }

    /// Exact queued destination, owner, observation, bytes and expiry.
    pub closed spec fn value(&self) -> (Target, Option<Owner>, u64, Seq<u8>, u64) {
        (self.target, self.owner, self.revision, self.bytes@, self.deadline)
    }

    /// Current authorization condition, including every assigned family's DNS TTL.
    pub closed spec fn sendable(&self, view: View, binding: Option<Bound>, now: u64) -> bool {
        now < self.deadline && self.revision == view.revision() && view.configuration_value().is_some()
            && match (self.owner, binding) {
                (None, None) => self.target == Target::Upstream,
                (Some(owner), Some(binding)) => binding.labels() == owner.labels()
                    && (forall|i: int| 0 <= i < binding.assigned_value().addresses().len() ==>
                        view.member_ready(binding.assigned_value().addresses()[i])
                        && forall|answers: Resolved| view.resolved_for(binding.assigned_value().addresses()[i], answers)
                            ==> answers.unexpired(now)),
                _ => false,
            }
    }

    /// Native destination for selecting an existing owned driver handle.
    pub fn target(&self) -> (target: Target)
        requires self.valid(), ensures target == self.value().0,
    { self.target }

    /// Source/destination owner whose current native permit must be held.
    pub fn owner(&self) -> (owner: Option<Owner>)
        requires self.valid(), ensures owner == self.value().1,
    { self.owner }

    /// Borrow one complete private Ethernet frame after checking authorization.
    pub fn bytes(&self) -> (bytes: &[u8])
        requires self.valid(), ensures bytes@ == self.value().3,
    { &self.bytes }

    /// Check exact revision, queue lifetime and original binding immediately
    /// before send. A copied Owner alone cannot authorize an interface effect.
    pub fn authorized(&self, view: &View, binding: Option<&Bound>, now: u64) -> (authorized: bool)
        requires self.valid(), view.valid(), binding.is_some() ==> binding.unwrap().valid(),
        ensures authorized == self.sendable(*view, match binding { Some(value) => Some(*value), None => None }, now),
    {
        if now >= self.deadline || self.revision != view.generation() || view.config().is_none() { return false; }
        match (self.owner, binding) {
            (None, None) => self.target == Target::Upstream,
            (Some(owner), Some(binding)) if owner == Owner::from_binding(binding) => {
                binding.assigned().all().iter().all(|ip: &Ip| -> (ready: bool)
                    requires ip.valid(),
                    ensures ready == (view.member_ready(*ip)
                        && forall|answers: Resolved| view.resolved_for(*ip, answers) ==> answers.unexpired(now)),
                { view.policy(ip).is_some() && view.resolution(ip).is_none_or(|answers: &Resolved| -> (fresh: bool)
                    requires answers.valid(), ensures fresh == answers.unexpired(now),
                { answers.fresh(now) }) })
            }
            _ => false,
        }
    }
}

/// A private IP datagram waiting at most two seconds for link resolution/send.
struct Routed {
    /// Exact originating interface, or resolver/router internal traffic.
    owner: Option<Owner>,
    /// View revision used for all checks and source-NAT fields.
    revision: u64,
    /// Private translated datagram; large IPv6 data retains its input layout.
    bytes: Vec<u8>,
    /// Original fragmentation layout; absent for ordinary MTU-sized input.
    layout: Option<Layout>,
    /// Next fragmentable-payload byte to emit; zero before the first output.
    cursor: usize,
    /// Destination copied from this immutable datagram's checked library header.
    /// Dequeue need not parse transport headers or recompute checksums again.
    destination: Ip,
    /// Absolute queue deadline; failed ARP cannot retain packets indefinitely.
    deadline: u64,
}

impl Routed {
    /// Bounded private datagram with one optional original-owner requirement.
    closed spec fn valid(&self) -> bool {
        28 <= self.bytes@.len() <= wire::DATAGRAM_BYTES && self.revision > 0 && self.deadline > 0
            && match self.layout {
                Some(layout) => layout.valid() && layout.prefix < self.bytes@.len()
                    && self.cursor < self.bytes@.len() - layout.prefix && self.cursor % 8 == 0,
                None => self.bytes@.len() <= MTU && self.cursor == 0,
            }
            && self.destination.valid() && match self.owner { Some(owner) => owner.valid(), None => true }
    }
}

/// Per-client queues prevent a single client from taking all output buffers.
struct Link {
    /// Actual validated native incarnation associated with both queues.
    owner: Owner,
    /// Complete frames waiting for the original client.
    incoming: VecDeque<Output>,
    /// Bounded datagrams waiting for upstream neighbor resolution.
    outgoing: VecDeque<Routed>,
    /// One reassembled client-bound datagram emitted lazily as MTU-sized frames.
    /// It cannot consume the normal queue or another client's reservation.
    fragmented: Option<Delivery>,
    /// Alternate available normal and fragmented output to preserve progress.
    fragment_turn: bool,
    /// Last generated local ICMP/ARP response time for this client.
    response_at: u64,
}

impl Link {
    /// Both directions retain the same exact original-owner reservation.
    closed spec fn valid(&self) -> bool {
        self.owner.valid() && (self.fragmented.is_some() ==> self.fragmented.unwrap().packet.valid()
            && self.fragmented.unwrap().packet.layout.is_some() && self.fragmented.unwrap().packet.owner == Some(self.owner))
            && self.incoming@.len() <= QUEUE_FRAMES && self.outgoing@.len() <= QUEUE_FRAMES
            && (forall|i: int| 0 <= i < self.incoming@.len() ==> self.incoming@[i].valid()
                && self.incoming@[i].value().0 == Target::Client(self.owner)
                && self.incoming@[i].value().1 == Some(self.owner))
            && self.outgoing@.filter(|packet: Routed| packet.layout.is_some()).len() <= 1
            && (forall|i: int| 0 <= i < self.outgoing@.len() ==> self.outgoing@[i].valid()
                && self.outgoing@[i].owner == Some(self.owner))
    }
}

/// One private translated datagram waiting to emit client-bound fragments.
struct Delivery {
    /// Original owner/revision/deadline and bounded fragment cursor.
    packet: Routed,
    /// Original client's observed Ethernet recipient on that exact link.
    mac: [u8; 6],
}

/// One solicited upstream ARP/NDP entry. The cache never learns client interfaces.
struct Neighbor {
    /// Cache reservation only, never interface authority. One entry per client;
    /// router/resolver entries have three separate slots including the gateway.
    owner: Option<Owner>,
    /// On-link IP target selected by the configured route.
    ip: Ip,
    /// Configured gateway reservations survive unrelated internal cache churn.
    gateway: bool,
    /// Positive unicast answer, absent while resolution is pending.
    mac: Option<[u8; 6]>,
    /// Positive cache expiry or request retry time.
    expires: u64,
    /// One-second retry bound independent of packet arrival rate.
    requested: u64,
}

/// Complete bounded firewall state, without VM resources or ambient clocks.
pub struct Engine {
    /// Exact native-owner queues, no more than four at once.
    links: Vec<Link>,
    /// Outbound-created NAT mappings with bounded per-client reservations.
    flows: Table,
    /// Shared bounded reassembly reservations, retired with their native owner.
    fragments: Reassembly,
    /// Recent translated fragment identities used only for related ICMP errors.
    history: History,
    /// Number of translated outbound fragmented datagrams since this boot.
    fragment_counter: u64,
    /// Entropy-derived permutation offset; identifiers never repeat this boot.
    fragment_salt: u32,
    /// Resolver uses its own small dynamic port namespace and admission gate.
    dns: Resolver,
    /// At most eight upstream on-link observations or pending requests.
    neighbors: VecDeque<Neighbor>,
    /// Resolver/router datagrams cannot consume client queue reservations.
    internal: VecDeque<Routed>,
    /// Native-shaped internal frames, such as an ARP reply to the gateway.
    control: VecDeque<Output>,
    /// Fair upstream queue cursor, including one internal queue.
    cursor: usize,
    /// Last accepted monotonic time; a regression stops processing permanently.
    time: u64,
    /// Clock/control loss is terminal for this engine instance.
    lost: bool,
    /// Observation revision last used to sweep connection authorization.
    revision: u64,
    /// Independent cryptographically seeded port/transaction allocation.
    random: ChaCha20Rng,
}

impl Engine {
    /// Global and reserved queue/connection bounds, independent of input traffic.
    pub closed spec fn valid(&self) -> bool {
        self.links@.len() <= MAX_CLIENTS && self.flows.valid() && self.fragments.valid() && self.history.valid() && self.fragment_counter <= 4_294_967_296 && self.dns.valid()
            && self.neighbors@.len() <= 8 && self.internal@.filter(|packet: Routed| packet.layout.is_some()).len() <= 1
            && self.internal@.len() <= QUEUE_FRAMES && self.control@.len() <= QUEUE_FRAMES
            && (forall|i: int| 0 <= i < self.links@.len() ==> self.links@[i].valid())
            && (forall|i: int| 0 <= i < self.control@.len() ==> self.control@[i].valid()
                && self.control@[i].value().0 == Target::Upstream)
            && (forall|i: int| 0 <= i < self.internal@.len() ==> self.internal@[i].valid() && self.internal@[i].owner.is_none())
            && (forall|i: int, j: int| 0 <= i < j < self.links@.len() ==> self.links@[i].owner != self.links@[j].owner)
            && (forall|i: int, j: int| 0 <= i < j < self.neighbors@.len() ==> self.neighbors@[i].ip != self.neighbors@[j].ip)
            && (forall|i: int, j: int| 0 <= i < j < self.neighbors@.len() && self.neighbors@[i].owner.is_some()
                ==> self.neighbors@[i].owner != self.neighbors@[j].owner)
    }

    /// Number of reserved original-owner queues, independent of packet claims.
    pub closed spec fn interface_count(&self) -> nat { self.links@.len() }

    /// Reserved NAT leases, including retired ports awaiting hold-down.
    pub closed spec fn connection_count(&self) -> nat { self.flows.value().len() }

    /// Last accepted monotonic observation, never an ambient clock read.
    pub closed spec fn clock(&self) -> u64 { self.time }

    /// A terminal clock/control failure cannot be revived.
    pub closed spec fn stopped(&self) -> bool { self.lost }

    /// Last control revision applied to mappings and queued decisions.
    pub closed spec fn revision_value(&self) -> u64 { self.revision }

    /// Every configured family has a fresh solicited ARP/NDP gateway observation.
    pub closed spec fn gateway_known(&self, view: View, now: u64) -> bool {
        match view.configuration_value() {
            Some(config) => exists|i: int| 0 <= i < self.neighbors@.len()
                && self.neighbors@[i].ip == config.gateway_value()
                && self.neighbors@[i].mac.is_some() && self.neighbors@[i].expires > now
                && match config.ipv6_value() {
                    Some(ipv6) => exists|j: int| 0 <= j < self.neighbors@.len()
                        && self.neighbors@[j].ip == ipv6.gateway_value()
                        && self.neighbors@[j].mac.is_some() && self.neighbors@[j].expires > now,
                    None => true,
                },
            None => false,
        }
    }

    /// Report a still-fresh solicited gateway answer without treating it as
    /// permission or proof of internet reachability. An unknown gateway does
    /// not imply that the client's isolation boundary has failed.
    pub fn gateway_reachable(&self, view: &View, now: u64) -> (reachable: bool)
        requires self.valid(), view.valid(),
        ensures reachable == self.gateway_known(*view, now),
    {
        let Some(config) = view.config() else { return false; };
        let gateway = *config.gateway();
        let ipv4 = self.neighbors.iter().any(|entry: &Neighbor| -> (known: bool)
            ensures known == (entry.ip == config.gateway_value() && entry.mac.is_some() && entry.expires > now),
        { entry.ip == gateway && entry.mac.is_some() && entry.expires > now });
        if !ipv4 { return false; }
        let Some(ipv6) = config.ipv6() else { return true; };
        let gateway6 = *ipv6.gateway();
        self.neighbors.iter().any(|entry: &Neighbor| -> (known: bool)
            ensures known == (entry.ip == ipv6.gateway_value() && entry.mac.is_some() && entry.expires > now),
        { entry.ip == gateway6 && entry.mac.is_some() && entry.expires > now })
    }

    /// Whether queue reservations belong to these exact native lifetime labels.
    pub closed spec fn owns(&self, labels: (u32, u32, u16)) -> bool {
        exists|i: int| 0 <= i < self.links@.len() && self.links@[i].owner.labels() == labels
    }

    /// Start closed, with no interfaces/flows. Seed must come from the platform
    /// entropy API; the boot challenge and clock are not entropy sources.
    pub fn new(seed: [u8; 32]) -> (engine: Self)
        ensures engine.valid(), !engine.stopped(), engine.interface_count() == 0,
            engine.connection_count() == 0, engine.clock() == 0,
    {
        let mut random = crate::library::generator(seed);
        let fragment_salt = random.next_u32();
        Self { links: Vec::new(), flows: Table::new(), fragments: Reassembly::new(), history: History::new(),
            fragment_counter: 0, fragment_salt, dns: Resolver::new(), neighbors: VecDeque::new(),
            internal: VecDeque::new(), control: VecDeque::new(), cursor: 0, time: 0, lost: false,
            revision: 0, random }
    }

    /// Allocate a boot-unique fragment ID before source NAT merges clients into
    /// one upstream address. Exhaustion stops fragmented output rather than reuse.
    fn fragment_id(&mut self) -> (id: Option<u32>)
        requires old(self).valid(),
        ensures final(self).valid(), id.is_some() == (old(self).fragment_counter < 4_294_967_296),
            final(self).fragment_counter == old(self).fragment_counter + if id.is_some() { 1int } else { 0int },
            id.is_some() ==> id.unwrap() == (old(self).fragment_counter as u32).wrapping_add(old(self).fragment_salt),
            final(self).flows == old(self).flows, final(self).links == old(self).links,
            final(self).history == old(self).history, final(self).fragment_salt == old(self).fragment_salt,
            final(self).revision == old(self).revision, final(self).time == old(self).time,
            final(self).lost == old(self).lost,
    {
        if self.fragment_counter == 4_294_967_296 { return None; }
        let id = (self.fragment_counter as u32).wrapping_add(self.fragment_salt);
        self.fragment_counter += 1;
        Some(id)
    }

    /// Locate an existing queue by exact native lifetime with std's slice search.
    fn link_index(&self, owner: Owner) -> (index: Option<usize>)
        requires self.valid(),
        ensures match index {
            Some(i) => i < self.links@.len() && self.links@[i as int].owner == owner,
            None => forall|i: int| 0 <= i < self.links@.len() ==> self.links@[i].owner != owner,
        },
    { self.links.iter().position(|link: &Link| -> (same: bool)
        ensures same == (link.owner == owner),
    { link.owner == owner }) }

    /// Locate a solicited neighbor without creating another iterator abstraction.
    fn neighbor_index(&self, ip: Ip) -> (index: Option<usize>)
        requires self.valid(),
        ensures match index {
            Some(i) => i < self.neighbors@.len() && self.neighbors@[i as int].ip == ip,
            None => forall|i: int| 0 <= i < self.neighbors@.len() ==> self.neighbors@[i].ip != ip,
        },
    { self.neighbors.iter().position(|entry: &Neighbor| -> (same: bool)
        ensures same == (entry.ip == ip),
    { entry.ip == ip }) }

    /// Install bounded queue reservations for a completed native binding.
    /// Merely attaching has no effect on policy or the actual driver resource.
    pub fn attach(&mut self, binding: &Bound) -> (attached: bool)
        requires old(self).valid(), binding.valid(),
        ensures final(self).valid(), final(self).connection_count() == old(self).connection_count(),
            attached ==> final(self).owns(binding.labels()),
            !attached ==> *final(self) == *old(self),
    {
        let owner = Owner::from_binding(binding);
        if self.link_index(owner).is_some() { return true; }
        if self.links.len() == MAX_CLIENTS { return false; }
        let ghost index = self.links@.len();
        self.links.push(Link { owner, incoming: VecDeque::new(), outgoing: VecDeque::new(), fragmented: None, fragment_turn: false, response_at: 0 });
        proof { assert(self.links@[index as int].owner.labels() == binding.labels()); }
        true
    }

    /// Withdraw exact-owner queues and revoke its mappings without reusing ports.
    pub fn retire(&mut self, owner: Owner, now: u64)
        requires old(self).valid(), owner.valid(),
        ensures final(self).valid(), !final(self).owns(owner.labels()),
            final(self).connection_count() == old(self).connection_count(),
    {
        if now < self.time { self.lost = true; }
        crate::library::retain_vec(&mut self.links, |link: &Link| -> (keep: bool)
            ensures keep == (link.owner != owner),
        { link.owner != owner });
        crate::library::retain_deque(&mut self.neighbors, |entry: &Neighbor| -> (keep: bool)
            ensures keep == (entry.owner != Some(owner)),
        { entry.owner != Some(owner) });
        self.flows.retire(owner, now);
        self.fragments.expire(Some(owner), now);
    }

    /// Observe every control event before polling another one or sending data.
    /// Tightening deletes newly denied flows as upstream does; unfinished policy
    /// updates also revoke flows. Later relaxation cannot revive retired state.
    pub fn observe(&mut self, view: &View, now: u64) -> (live: bool)
        requires old(self).valid(), view.valid(),
        ensures final(self).valid(),
            live == (!old(self).stopped() && now >= old(self).clock() && now < u64::MAX && view.phase() != airlock_qubes_network::projection::Phase::Lost),
            live ==> !final(self).stopped() && final(self).clock() == now && final(self).revision_value() == view.revision(),
            !live ==> final(self).stopped(),
    {
        if self.lost || now < self.time || now == u64::MAX { self.lost = true; return false; }
        self.time = now;
        if matches!(view.state(), airlock_qubes_network::projection::Phase::Lost) { self.lost = true; return false; }
        if self.revision != view.generation() {
            self.flows.observe(view, now);
            self.internal.clear(); self.control.clear(); self.neighbors.clear(); self.fragments.clear(); self.history.clear();
            let mut index = 0;
            while index < self.links.len()
                invariant self.valid(), view.valid(), self.time == now, !self.lost, index <= self.links@.len() <= MAX_CLIENTS,
                decreases self.links.len() - index,
            {
                self.links[index].incoming.clear(); self.links[index].outgoing.clear(); self.links[index].fragmented = None;
                index += 1;
            }
            self.revision = view.generation();
        }
        true
    }

    /// One scheduler maintenance turn: at most 64 retained leases and one DNS
    /// work item. A completed answer collection is handed back to control.
    pub fn tick(&mut self, view: &View, now: u64) -> (answers: Option<Resolved>)
        requires old(self).valid(), view.valid(),
        ensures final(self).valid(), answers.is_some() ==> answers.unwrap().valid()
            && answers.unwrap().revision_value() == view.revision() && answers.unwrap().unexpired(now),
    {
        if !self.observe(view, now) { return None; }
        self.flows.maintain(now);
        self.fragments.expire(None, now);
        let (packet, answer) = self.dns.tick(view, now, &mut self.random);
        if let Some(bytes) = packet { self.route(None, view.generation(), bytes, now); }
        answer
    }

    /// Process exactly one frame from a currently permitted native client.
    /// Every drop is silent except bounded router ICMP errors/local echo/ARP.
    pub fn client(&mut self, binding: &Bound, view: &View, bytes: &[u8], now: u64)
        requires old(self).valid(), binding.valid(), view.valid(),
        ensures final(self).valid(), old(self).stopped() ==> final(self).stopped(),
    {
        if !self.observe(view, now) || !self.attach(binding) { return; }
        let owner = Owner::from_binding(binding);
        let Some(frame) = wire::ethernet(bytes) else { return; };
        let mac = frame.source;
        if !wire::mac_unicast(mac) { return; }
        if frame.protocol == 0x0806 {
            self.client_arp(owner, binding, view, &frame, &bytes[14..], now); return;
        }
        // Neighbor discovery is local to this exact authorized client link.
        if frame.protocol == 0x86dd && self.client_ndp(owner, binding, view, &frame, &bytes[14..], now) { return; }
        if !matches!(frame.protocol, 0x0800 | 0x86dd) || frame.destination != router_mac()
            || codec::ethertype(&bytes[14..]) != Some(frame.protocol) { return; }
        let joined = if let Some(part) = codec::fragment(&bytes[14..]) {
            if !wire::unicast(part.source) || view.policy(&part.source).is_none()
                || !binding.assigned().all().contains(&part.source) { return; }
            let Some(joined) = self.fragments.receive(Some(owner), mac, part, now) else { return; };
            Some(joined)
        } else { None };
        let input = match &joined { Some((bytes, _)) => bytes.as_slice(), None => &bytes[14..] };
        let mut layout = joined.as_ref().map(|joined: &(Vec<u8>, Layout)| -> (layout: Layout)
            requires joined.1.valid(), ensures layout == joined.1 && layout.valid(),
        { joined.1 });
        let Some(packet) = Packet::parse(input) else { return; };
        if layout.is_some() && packet.tuple.src.version() != 6 { return; }
        if !wire::unicast(packet.tuple.src) || !binding.assigned().all().iter().any(|ip: &Ip| -> (same: bool) requires ip.valid(), { *ip == packet.tuple.src }) { return; }
        let Some(config) = view.config() else { return; };
        if view.policy(&packet.tuple.src).is_none() { return; }
        if policy::router(config, packet.tuple.src.version()) == Some(packet.tuple.dst) && packet.tuple.icmp() && packet.icmp == packet.tuple.request() {
            if self.response(owner, now) {
                let (limit, reply_layout) = if let Some(layout) = layout {
                    let Some(id) = self.fragment_id() else { return; };
                    (wire::DATAGRAM_BYTES, Some(Layout { prefix: 40, previous: 6, protocol: 58,
                        chunk: (layout.prefix + layout.chunk - 40) / 8 * 8, id }))
                } else { (MTU, None) };
                let Some(bytes) = wire::echo_reply(&packet, limit) else { return; };
                self.deliver_datagram(owner, mac, view.generation(), bytes, reply_layout, now);
            }
            return;
        }
        if wire::is_error(packet.tuple.proto, packet.icmp) {
            self.client_related(owner, view, &packet, now); return;
        }
        if packet.tuple.src.version() == 6 && codec::link_local(packet.tuple.src) { return; }
        let Some(policy_tuple) = policy::redirect(view, packet.tuple) else { return; };
        if !policy::allows(view, policy_tuple, packet.icmp, now) { return; }
        if packet.tuple.icmp() && packet.icmp != packet.tuple.request() { return; }
        if packet.ttl <= 1 || (packet.bytes.len() > MTU && layout.is_none()) {
            if self.response(owner, now) {
                let Some(router) = policy::router(config, packet.tuple.src.version()) else { return; };
                let (kind, code) = wire::failure(packet.tuple.src.version(), packet.ttl <= 1);
                if let Some(bytes) = wire::error(&packet, router, kind, code) { self.deliver(owner, mac, view.generation(), bytes, now); }
            }
            return;
        }
        let Some(external) = policy::external(config, packet.tuple.src.version()) else { return; };
        let quota = binding.assigned().primary();
        let port = match self.flows.find(owner, packet.tuple) {
            Some(port) => Some(port),
            None => self.flows.create(NewMapping { owner, quota, policy: policy_tuple, external, mac, revision: view.generation() }, &packet, now, &mut self.random),
        };
        let Some(port) = port else { return; };
        let Some(flow) = self.flows.entries.get(&port) else { return; };
        if flow.policy != policy_tuple || flow.external != external || flow.revision != view.generation() { return; }
        if !self.flows.accept(port, &packet, true, Some(mac), now) { return; }
        let translated = Tuple { src: external, sport: port, ..policy_tuple };
        if let Some(fragment) = &mut layout {
            let Some(id) = self.fragment_id() else { return; };
            self.history.record(Emission { id, original: fragment.id, port, quota, source: translated.src,
                destination: translated.dst, protocol: fragment.protocol, client: None,
                deadline: now.saturating_add(30 * SECOND) });
            fragment.id = id;
        }
        if let Some(bytes) = packet.translate(translated) { self.route_datagram(Some(owner), view.generation(), bytes, layout, now); }
    }

    /// Process one upstream frame. Only our solicited ARP, resolver replies and
    /// replies/errors related to outbound-created mappings can produce output.
    pub fn upstream(&mut self, view: &View, bytes: &[u8], now: u64)
        requires old(self).valid(), view.valid(),
        ensures final(self).valid(), old(self).stopped() ==> final(self).stopped(),
    {
        if !self.observe(view, now) { return; }
        let Some(config) = view.config() else { return; };
        let Some(frame) = wire::ethernet(bytes) else { return; };
        if frame.protocol == 0x0806 { self.upstream_arp(view, &frame, &bytes[14..], now); return; }
        if frame.protocol == 0x86dd && self.upstream_ndp(view, &frame, &bytes[14..], now) { return; }
        if !matches!(frame.protocol, 0x0800 | 0x86dd) || frame.destination != *config.mac().bytes()
            || codec::ethertype(&bytes[14..]) != Some(frame.protocol) { return; }
        let joined = if let Some(part) = codec::fragment(&bytes[14..]) {
            if !wire::unicast(part.source) || policy::external(config, 6) != Some(part.destination) { return; }
            let Some(joined) = self.fragments.receive(None, frame.source, part, now) else { return; };
            Some(joined)
        } else { None };
        let input = match &joined { Some((bytes, _)) => bytes.as_slice(), None => &bytes[14..] };
        let layout = joined.as_ref().map(|joined: &(Vec<u8>, Layout)| -> (layout: Layout)
            requires joined.1.valid(), ensures layout == joined.1 && layout.valid(),
        { joined.1 });
        let Some(packet) = Packet::parse(input) else { return; };
        if layout.is_some() && packet.tuple.src.version() != 6 { return; }
        if policy::external(config, packet.tuple.dst.version()) != Some(packet.tuple.dst) { return; }
        if self.dns.receive(&packet, view, now) { return; }
        if wire::is_error(packet.tuple.proto, packet.icmp) { self.related(view, &packet, now); return; }
        if packet.tuple.icmp() && packet.icmp != packet.tuple.reply() { return; }
        let port = if packet.tuple.icmp() { packet.tuple.sport } else { packet.tuple.dport };
        let Some(flow) = self.flows.entries.get(&port) else { return; };
        if !flow.live(now) || !flow.reply(packet.tuple, port) || flow.revision != view.generation()
            || !policy::allows(view, flow.policy, if flow.policy.icmp() { flow.policy.request() } else { 0 }, now) { return; }
        if packet.ttl <= 1 || (packet.bytes.len() > MTU && layout.is_none()) {
            let owner = flow.owner; let external = flow.external;
            if self.response(owner, now) {
                let (kind, code) = wire::failure(packet.tuple.src.version(), packet.ttl <= 1);
                if let Some(bytes) = wire::error(&packet, external, kind, code) { self.route(Some(owner), view.generation(), bytes, now); }
            }
            return;
        }
        let owner = flow.owner; let mac = flow.mac; let quota = flow.quota;
        let tuple = if packet.tuple.icmp() {
            Tuple { src: flow.original.dst, dst: flow.original.src, sport: flow.original.sport, dport: 0, proto: flow.original.proto }
        } else { Tuple { src: flow.original.dst, dst: flow.original.src,
            sport: flow.original.dport, dport: flow.original.sport, proto: flow.original.proto } };
        if !self.flows.accept(port, &packet, false, None, now) { return; }
        if let Some(fragment) = layout {
            self.history.record(Emission { id: fragment.id, original: fragment.id, port, quota, source: tuple.src,
                destination: tuple.dst, protocol: fragment.protocol, client: Some(owner),
                deadline: now.saturating_add(30 * SECOND) });
        }
        if let Some(bytes) = packet.translate(tuple) { self.deliver_datagram(owner, mac, view.generation(), bytes, layout, now); }
    }

    /// Take one original client's output; native send must still call authorized.
    pub fn next_client(&mut self, owner: Owner) -> (output: Option<Output>)
        requires old(self).valid(), owner.valid(),
        ensures final(self).valid(), output.is_some() ==> output.unwrap().valid()
            && output.unwrap().value().0 == Target::Client(owner) && output.unwrap().value().1 == Some(owner),
    {
        if self.lost { return None; }
        let index = self.link_index(owner)?;
        if self.links[index].fragmented.as_ref().is_some_and(|delivery| delivery.packet.deadline <= self.time) {
            self.links[index].fragmented = None;
        }
        let ordinary = if !self.links[index].fragment_turn || self.links[index].fragmented.is_none() {
            self.links[index].incoming.pop_front()
        } else { None };
        if let Some(output) = ordinary { self.links[index].fragment_turn = true; return Some(output); }
        self.links[index].fragment_turn = false;
        let delivery = self.links[index].fragmented.as_mut()?;
        let layout = delivery.packet.layout?;
        let (bytes, cursor) = fragment::emit(&delivery.packet.bytes, layout, delivery.packet.cursor)?;
        let bytes = wire::frame(router_mac(), delivery.mac, 0x86dd, &bytes)?;
        let output = Output { target: Target::Client(owner), owner: Some(owner), revision: delivery.packet.revision,
            bytes, deadline: delivery.packet.deadline };
        let complete = cursor == delivery.packet.bytes.len() - layout.prefix;
        if !complete { delivery.packet.cursor = cursor; }
        if complete { self.links[index].fragmented = None; }
        Some(output)
    }

    /// Take one upstream frame fairly across all clients and internal work.
    /// Unresolved heads expire; each call inspects at most six destinations.
    pub fn next_upstream(&mut self, view: &View, now: u64) -> (output: Option<Output>)
        requires old(self).valid(), view.valid(),
        ensures final(self).valid(), output.is_some() ==> output.unwrap().valid()
            && output.unwrap().value().0 == Target::Upstream,
    {
        if !self.observe(view, now) { return None; }
        let queues = self.links.len() + 2;
        let mut remaining = queues;
        while remaining > 0
            invariant self.valid(), view.valid(), queues == self.links@.len() + 2, 2 <= queues <= MAX_CLIENTS + 2,
                remaining <= queues,
            decreases remaining,
        {
            remaining -= 1;
            self.cursor %= queues;
            let selected = self.cursor; self.cursor = (self.cursor + 1) % queues;
            if selected == 0 {
                if let Some(output) = self.control.pop_front() { return Some(output); }
                continue;
            }
            let index = selected - 1;
            let ghost before_queue = if index == self.links.len() { self.internal@ } else { self.links@[index as int].outgoing@ };
            let pending = if index == self.links.len() { self.internal.pop_front() } else { self.links[index].outgoing.pop_front() };
            proof {
                let after_queue = if index == self.links.len() { self.internal@ } else { self.links@[index as int].outgoing@ };
                if pending.is_some() {
                    assert(before_queue =~= seq![pending.unwrap()] + after_queue);
                    Seq::<Routed>::filter_distributes_over_add(seq![pending.unwrap()], after_queue, |packet: Routed| packet.layout.is_some());
                }
                assert(after_queue.filter(|packet: Routed| packet.layout.is_some()).len() <= 1);
            }
            let Some(mut pending) = pending else { continue; };
            if pending.deadline <= now || pending.revision != view.generation() { continue; }
            let config = view.config()?;
            let family = pending.destination.version();
            let local = policy::external(config, family)?;
            let gateway = policy::gateway(config, family)?;
            let prefix = if family == 4 { config.prefix() } else { 128u8 };
            let on_link = codec::contains(local, prefix, pending.destination);
            let next = if on_link { pending.destination } else { gateway };
            if let Some(mac) = self.neighbors.iter().find(|entry| entry.ip == next && entry.expires > now).and_then(|entry| entry.mac) {
                let protocol = if family == 4 { 0x0800 } else { 0x86dd };
                let (datagram, cursor) = match pending.layout {
                    Some(layout) => fragment::emit(&pending.bytes, layout, pending.cursor)?,
                    None => (slice_to_vec(&pending.bytes), pending.bytes.len()),
                };
                let bytes = wire::frame(*config.mac().bytes(), mac, protocol, &datagram)?;
                let output = Output { target: Target::Upstream, owner: pending.owner, revision: pending.revision, bytes, deadline: pending.deadline };
                match pending.layout {
                    Some(layout) if cursor < pending.bytes.len() - layout.prefix => {
                        pending.cursor = cursor;
                        if index == self.links.len() { self.internal.push_back(pending); }
                        else { self.links[index].outgoing.push_back(pending); }
                    }
                    _ => (),
                }
                return Some(output);
            }
            let reservation = if next == gateway { None } else { pending.owner };
            let request = self.neighbor_request(next, reservation, gateway, now);
            if index == self.links.len() { self.internal.push_back(pending); } else { self.links[index].outgoing.push_back(pending); }
            if request {
                let bytes = if family == 4 {
                    let bytes = arp(1, *config.mac().bytes(), local.ipv4()?, [0; 6], next.ipv4()?)?;
                    wire::frame(*config.mac().bytes(), [255; 6], 0x0806, &bytes)?
                } else {
                    wire::solicit(*config.mac().bytes(), local, next)?
                };
                return Some(Output { target: Target::Upstream, owner: None, revision: view.generation(), bytes, deadline: now.saturating_add(SECOND) });
            }
        }
        None
    }

    /// Requeue only a previously taken value after native backpressure. The
    /// bounded queue admission is repeated; a full queue drops the output.
    pub fn retry(&mut self, output: Output)
        requires old(self).valid(), output.valid(),
        ensures final(self).valid(),
    {
        if self.lost { return; }
        let queue = match output.target {
            Target::Client(owner) => match self.link_index(owner) { Some(index) => Some(&mut self.links[index].incoming), None => None },
            Target::Upstream => Some(&mut self.control),
        };
        let Some(queue) = queue else { return; };
        if queue.len() < QUEUE_FRAMES { queue.push_back(output); }
    }

    /// Ordinary internal/client traffic retains the existing MTU-sized path.
    fn route(&mut self, owner: Option<Owner>, revision: u64, bytes: Vec<u8>, now: u64)
        requires old(self).valid(), revision > 0, owner.is_some() ==> owner.unwrap().valid(),
        ensures final(self).valid(),
    { self.route_datagram(owner, revision, bytes, None, now); }

    /// Admit one large datagram per queue, retaining the input fragmentation
    /// layout. Normal traffic shares the same queue and scheduler reservation.
    fn route_datagram(&mut self, owner: Option<Owner>, revision: u64, bytes: Vec<u8>, layout: Option<Layout>, now: u64)
        requires old(self).valid(), revision > 0, owner.is_some() ==> owner.unwrap().valid(),
        ensures final(self).valid(),
    {
        if bytes.len() < 28 || bytes.len() > wire::DATAGRAM_BYTES { return; }
        if let Some(layout) = layout {
            if layout.prefix < 40 || layout.prefix > 248 || layout.previous >= layout.prefix || layout.prefix >= bytes.len()
                || layout.chunk > MTU - layout.prefix - 8 || layout.chunk % 8 != 0 { return; }
        } else if bytes.len() > MTU { return; }
        let Some(header) = codec::datagram(bytes.as_slice()) else { return; };
        let destination = header.tuple.dst;
        let queue = match owner {
            Some(owner) => match self.link_index(owner) { Some(index) => Some(&mut self.links[index].outgoing), None => None },
            None => Some(&mut self.internal),
        };
        let Some(queue) = queue else { return; };
        if queue.len() < QUEUE_FRAMES && (layout.is_none() || !queue.iter().any(|packet: &Routed| -> (fragmented: bool)
            ensures fragmented == packet.layout.is_some(), { packet.layout.is_some() })) {
            proof {
                if layout.is_some() { queue@.lemma_all_neg_filter_empty(|packet: Routed| packet.layout.is_some()); }
            }
            queue.push_back(Routed { owner, revision, bytes, layout, cursor: 0, destination, deadline: now.saturating_add(2 * SECOND) });
        }
    }

    /// Retain at most one large client-bound datagram; normal frames keep their
    /// existing reservation and always have a bounded opportunity to progress.
    fn deliver_datagram(&mut self, owner: Owner, mac: [u8; 6], revision: u64, bytes: Vec<u8>, layout: Option<Layout>, now: u64)
        requires old(self).valid(), owner.valid(), revision > 0,
        ensures final(self).valid(),
    {
        let Some(layout) = layout else { self.deliver(owner, mac, revision, bytes, now); return; };
        if bytes.len() > wire::DATAGRAM_BYTES || layout.prefix < 40 || layout.prefix > 248
            || layout.previous >= layout.prefix || layout.prefix >= bytes.len()
                || layout.chunk > MTU - layout.prefix - 8 || layout.chunk % 8 != 0 { return; }
        let Some(index) = self.link_index(owner) else { return; };
        if self.links[index].fragmented.is_some() { return; }
        let Some(header) = codec::datagram(&bytes) else { return; };
        self.links[index].fragmented = Some(Delivery { mac, packet: Routed { owner: Some(owner), revision,
            destination: header.tuple.dst, bytes, layout: Some(layout), cursor: 0, deadline: now.saturating_add(2 * SECOND) } });
    }

    /// Frame and append output only to the exact original client's own queue.
    fn deliver(&mut self, owner: Owner, mac: [u8; 6], revision: u64, bytes: Vec<u8>, now: u64)
        requires old(self).valid(), owner.valid(), revision > 0,
        ensures final(self).valid(),
    {
        let Some(protocol) = codec::ethertype(&bytes) else { return; };
        let Some(bytes) = wire::frame(router_mac(), mac, protocol, &bytes) else { return; };
        self.deliver_frame(owner, revision, bytes, now);
    }

    /// Reserve one bounded complete client output, never selecting by IP tuple.
    fn deliver_frame(&mut self, owner: Owner, revision: u64, bytes: Vec<u8>, now: u64)
        requires old(self).valid(), owner.valid(), revision > 0, 14 <= bytes@.len() <= MTU + 14,
        ensures final(self).valid(),
    {
        let Some(index) = self.link_index(owner) else { return; };
        let link = &mut self.links[index];
        if link.incoming.len() < QUEUE_FRAMES { link.incoming.push_back(Output { target: Target::Client(owner), owner: Some(owner), revision, bytes, deadline: now.saturating_add(2 * SECOND) }); }
    }

    /// Admit at most ten local router replies per second per original client.
    fn response(&mut self, owner: Owner, now: u64) -> (allowed: bool)
        requires old(self).valid(), owner.valid(),
        ensures final(self).valid(),
    {
        let Some(index) = self.link_index(owner) else { return false; };
        let link = &mut self.links[index];
        if now < link.response_at { return false; }
        link.response_at = now.saturating_add(SECOND / 10); true
    }

    /// Rate-limit ARP/NDP and preserve one reservation per client plus three for
    /// router/resolver traffic. Client churn evicts only that client's entry;
    /// internal churn retains the configured gateway. At capacity the new
    /// request is dropped rather than taking another client's reservation.
    fn neighbor_request(&mut self, ip: Ip, owner: Option<Owner>, gateway: Ip, now: u64) -> (request: bool)
        requires old(self).valid(), owner.is_some() ==> owner.unwrap().valid(),
        ensures final(self).valid(), final(self).links == old(self).links,
            final(self).internal == old(self).internal, final(self).control == old(self).control,
    {
        if let Some(index) = self.neighbor_index(ip) {
            let entry = &mut self.neighbors[index];
            if now < entry.requested.saturating_add(SECOND) { return false; }
            entry.mac = None; entry.requested = now; return true;
        }
        if let Some(owner) = owner { crate::library::retain_deque(&mut self.neighbors, |entry: &Neighbor| -> (keep: bool)
            ensures keep == (entry.owner != Some(owner)),
        { entry.owner != Some(owner) }); }
        else if self.neighbors.iter().filter(|entry| entry.owner.is_none()).count() >= 3 {
            let Some(index) = self.neighbors.iter().position(|entry| entry.owner.is_none() && !entry.gateway) else { return false; };
            self.neighbors.remove(index);
        }
        if self.neighbors.len() == 8 { return false; }
        self.neighbors.push_back(Neighbor { owner, ip, gateway: ip == gateway, mac: None, expires: 0, requested: now }); true
    }

    /// Proxy only the configured client gateway on the already authorized link.
    fn client_arp(&mut self, owner: Owner, binding: &Bound, view: &View, frame: &codec::Ethernet, payload: &[u8], now: u64)
        requires old(self).valid(), owner.valid(), binding.valid(), view.valid(),
        ensures final(self).valid(),
    {
        let Some(config) = view.config() else { return; };
        let Some(fields) = codec::arp(payload) else { return; };
        if fields.operation != 1 || fields.source_mac != frame.source
            || !binding.assigned().all().iter().any(|ip: &Ip| -> (same: bool) requires ip.valid(), { ip.ipv4() == Some(fields.source) })
            || config.provided_gateway().ipv4() != Some(fields.target) || !self.response(owner, now) { return; }
        let Some(bytes) = arp(2, router_mac(), fields.target, fields.source_mac, fields.source) else { return; };
        if let Some(bytes) = wire::frame(router_mac(), fields.source_mac, 0x0806, &bytes) {
            self.deliver_frame(owner, view.generation(), bytes, now);
        }
    }

    /// Learn only an outstanding upstream solicitation addressed to our own MAC
    /// and IP; upstream requests receive only a reply for our configured address.
    fn upstream_arp(&mut self, view: &View, frame: &codec::Ethernet, payload: &[u8], now: u64)
        requires old(self).valid(), view.valid(),
        ensures final(self).valid(),
    {
        let Some(config) = view.config() else { return; };
        let Some(local) = config.address().ipv4() else { return; };
        let Some(fields) = codec::arp(payload) else { return; };
        if fields.source_mac != frame.source || !wire::mac_unicast(fields.source_mac)
            || !wire::unicast(Ip::from_ipv4(fields.source)) || fields.target != local { return; }
        if fields.operation == 2 && fields.target_mac == *config.mac().bytes()
            && frame.destination == *config.mac().bytes() {
            if let Some(index) = self.neighbor_index(Ip::from_ipv4(fields.source)) {
                let entry = &mut self.neighbors[index];
                if now < entry.requested.saturating_add(2 * SECOND) {
                    entry.mac = Some(fields.source_mac); entry.expires = now.saturating_add(30 * SECOND);
                }
            }
        } else if fields.operation == 1 && self.control.len() < QUEUE_FRAMES {
            let Some(bytes) = arp(2, *config.mac().bytes(), local, fields.source_mac, fields.source) else { return; };
            let Some(bytes) = wire::frame(*config.mac().bytes(), fields.source_mac, 0x0806, &bytes) else { return; };
            self.control.push_back(Output { target: Target::Upstream, owner: None, revision: view.generation(), bytes, deadline: now.saturating_add(SECOND) });
        }
    }

    /// Answer only solicitations for the configured router on this exact client
    /// link. Link-local requests produce local replies, never routed authority.
    fn client_ndp(&mut self, owner: Owner, binding: &Bound, view: &View, frame: &codec::Ethernet, bytes: &[u8], now: u64) -> (consumed: bool)
        requires old(self).valid(), owner.valid(), binding.valid(), view.valid(),
        ensures final(self).valid(),
    {
        let Some(message) = codec::ndp(bytes) else { return false; };
        let Some(config) = view.config() else { return true; };
        let Some(router) = policy::router(config, 6) else { return true; };
        if message.kind != 135 || message.code != 0 || message.hop != 255 || !message.checksum
            || message.fragmented || message.extensions != 0 || message.target != router
            || !wire::mac_unicast(frame.source)
            || message.mac.is_some_and(|mac| mac != frame.source)
            || !(message.destination == router || wire::solicited_for(message.destination, router))
            || !(frame.destination == router_mac() || wire::solicited_mac(frame.destination, router))
            || !wire::unicast(message.source) { return true; }
        let assigned = binding.assigned().all().iter().any(|ip: &Ip| -> (assigned: bool)
            requires ip.valid(), { *ip == message.source });
        if !assigned && !codec::link_local(message.source) { return true; }
        let ready = binding.assigned().all().iter().any(|ip: &Ip| -> (ready: bool)
            requires ip.valid(), { ip.version() == 6 && view.policy(ip).is_some() });
        if !ready || !self.response(owner, now) { return true; }
        if let Some(bytes) = wire::advertise(router_mac(), frame.source, router, message.source, true) {
            self.deliver_frame(owner, view.generation(), bytes, now);
        }
        true
    }

    /// NDP cannot install routes or addresses. Learn only a unicast solicited
    /// answer matching our outstanding target and our exact local recipient.
    fn upstream_ndp(&mut self, view: &View, frame: &codec::Ethernet, bytes: &[u8], now: u64) -> (consumed: bool)
        requires old(self).valid(), view.valid(),
        ensures final(self).valid(),
    {
        let Some(message) = codec::ndp(bytes) else { return false; };
        let Some(config) = view.config() else { return true; };
        let Some(local) = policy::external(config, 6) else { return true; };
        if message.code != 0 || message.hop != 255 || !message.checksum || message.fragmented
            || message.extensions != 0 || !wire::mac_unicast(frame.source)
            || message.mac.is_some_and(|mac| mac != frame.source)
            || !wire::unicast(message.source) { return true; }
        if message.kind == 136 && message.solicited && (message.target == message.source || codec::link_local(message.source))
            && message.destination == local && frame.destination == *config.mac().bytes()
            && message.mac == Some(frame.source) {
            if let Some(index) = self.neighbor_index(message.target) {
                let entry = &mut self.neighbors[index];
                if now < entry.requested.saturating_add(2 * SECOND) {
                    entry.mac = Some(frame.source); entry.expires = now.saturating_add(30 * SECOND);
                }
            }
        } else if message.kind == 135 && message.target == local
            && (message.destination == local || wire::solicited_for(message.destination, local))
            && (frame.destination == *config.mac().bytes() || wire::solicited_mac(frame.destination, local))
            && self.control.len() < QUEUE_FRAMES {
            let Some(bytes) = wire::advertise(*config.mac().bytes(), frame.source, local, message.source, false) else { return true; };
            self.control.push_back(Output { target: Target::Upstream, owner: None, revision: view.generation(), bytes, deadline: now.saturating_add(SECOND) });
        }
        true
    }

    /// Related fragment errors use a recent emission and a still-live mapping.
    /// Non-first quotes carry no ports; they can never create a connection or
    /// select a client using their own addresses alone. History eviction drops
    /// old error detail while allowing ordinary data to continue within quotas.
    fn fragment_related(&mut self, client: Option<Owner>, view: &View, packet: &Packet<'_>, now: u64) -> bool
        requires old(self).valid(), view.valid(), packet.valid(), packet.ttl > 1,
        ensures final(self).valid(),
    {
        let quoted = &packet.bytes[packet.transport + 8..];
        let Some(identity) = codec::fragment_quote(quoted) else { return false; };
        if identity.extensions > 8 || identity.fragment_headers != 1 || identity.routing || identity.authenticated
            || identity.options.iter().any(|kind: &u8| -> (reject: bool) ensures reject == (*kind >= 64), { *kind >= 64 }) { return true; }
        let Some(emission) = self.history.find(&identity, client, now) else { return true; };
        let Some(flow) = self.flows.entries.get(&emission.port) else { return true; };
        if packet.tuple.proto != 58 || !flow.live(now) || flow.quota != emission.quota
            || flow.revision != view.generation() || client.is_some_and(|owner| owner != flow.owner)
            || !policy::allows(view, flow.policy, if flow.policy.icmp() { flow.policy.request() } else { 0 }, now) { return true; }
        let port = emission.port;
        let (before, after, source, destination) = if client.is_some() {
            if packet.tuple.src != flow.original.src || packet.tuple.dst != flow.original.dst { return true; }
            let before = if flow.original.icmp() {
                Tuple { src: flow.original.dst, dst: flow.original.src, ..flow.original }
            } else { Tuple { src: flow.original.dst, dst: flow.original.src,
                sport: flow.original.dport, dport: flow.original.sport, proto: flow.original.proto } };
            let after = if flow.policy.icmp() {
                Tuple { src: flow.policy.dst, dst: flow.external, sport: port, ..flow.policy }
            } else { Tuple { src: flow.policy.dst, dst: flow.external,
                sport: flow.policy.dport, dport: port, proto: flow.policy.proto } };
            (before, after, flow.external, flow.policy.dst)
        } else {
            if packet.tuple.dst != flow.external { return true; }
            let before = Tuple { src: flow.external, sport: port, ..flow.policy };
            let remote = if flow.original.dst != flow.policy.dst { flow.original.dst } else { packet.tuple.src };
            let Some(remote) = policy::error_sender(view, remote) else { return true; };
            (before, flow.original, remote, flow.original.src)
        };
        if identity.source != before.src || identity.destination != before.dst || !wire::unicast(source) { return true; }
        let mut quote = if identity.offset == 0 {
            let Some((tuple, bytes)) = wire::quote(quoted) else { return true; };
            if tuple != before { return true; }
            let Some(bytes) = wire::untranslate_quote(bytes, before, after) else { return true; };
            bytes
        } else { slice_to_vec(quoted) };
        if !codec::rewrite_fragment_quote(quote.as_mut_slice(), after.src, after.dst, emission.original) { return true; }
        let owner = flow.owner; let mac = flow.mac;
        let mut payload = slice_to_vec(&packet.bytes[packet.transport..packet.transport + 8]);
        payload.extend_from_slice(&quote);
        if !codec::icmp_checksum(payload.as_mut_slice(), source, destination) { return true; }
        if let Some(bytes) = wire::ip(source, destination, 58, &payload, packet.ttl - 1) {
            if client.is_some() { self.route(Some(owner), view.generation(), bytes, now); }
            else { self.deliver(owner, mac, view.generation(), bytes, now); }
        }
        true
    }

    /// Translate a client's error only when its quote describes a reply on one
    /// of this same owner's existing allowed flows. It creates no new mapping.
    fn client_related(&mut self, owner: Owner, view: &View, packet: &Packet<'_>, now: u64)
        requires old(self).valid(), owner.valid(), view.valid(), packet.valid(),
        ensures final(self).valid(),
    {
        if packet.ttl <= 1 || packet.bytes.len() > MTU { return; }
        if self.fragment_related(Some(owner), view, packet, now) { return; }
        let Some((quote_tuple, quote)) = wire::quote(&packet.bytes[packet.transport + 8..]) else { return; };
        if quote_tuple.src.version() != packet.tuple.src.version() { return; }
        if quote_tuple.icmp() && !wire::quoted_echo(&quote, quote_tuple.reply()) { return; }
        let original = if quote_tuple.icmp() {
            Tuple { src: quote_tuple.dst, dst: quote_tuple.src, ..quote_tuple }
        } else {
            Tuple { src: quote_tuple.dst, dst: quote_tuple.src, sport: quote_tuple.dport,
                dport: quote_tuple.sport, proto: quote_tuple.proto }
        };
        let Some(port) = self.flows.find(owner, original) else { return; };
        let Some(flow) = self.flows.entries.get(&port) else { return; };
        if packet.tuple.src != flow.original.src || packet.tuple.dst != flow.original.dst
            || !flow.live(now) || flow.revision != view.generation()
            || !policy::allows(view, flow.policy, if flow.policy.icmp() { flow.policy.request() } else { 0 }, now) { return; }
        let translated = if quote_tuple.icmp() {
            Tuple { src: flow.policy.dst, dst: flow.external, sport: port, ..quote_tuple }
        } else {
            Tuple { src: flow.policy.dst, dst: flow.external, sport: flow.policy.dport, dport: port, proto: flow.policy.proto }
        };
        let external = flow.external; let destination = flow.policy.dst;
        let Some(quote) = wire::untranslate_quote(quote, quote_tuple, translated) else { return; };
        let mut payload = slice_to_vec(&packet.bytes[packet.transport..packet.transport + 8]); payload.extend_from_slice(&quote);
        codec::icmp_checksum(payload.as_mut_slice(), external, destination);
        if let Some(bytes) = wire::ip(external, destination, packet.tuple.proto, &payload, packet.ttl - 1) {
            self.route(Some(owner), view.generation(), bytes, now);
        }
    }

    /// Translate only a quote matching an existing source-NAT mapping. ICMP
    /// cannot create/extend a lease; redirects and arbitrary inner IPs are dropped.
    fn related(&mut self, view: &View, packet: &Packet<'_>, now: u64)
        requires old(self).valid(), view.valid(), packet.valid(),
        ensures final(self).valid(),
    {
        if packet.ttl <= 1 || packet.bytes.len() > MTU { return; }
        if self.fragment_related(None, view, packet, now) { return; }
        let Some((tuple, quote)) = wire::quote(&packet.bytes[packet.transport + 8..]) else { return; };
        if tuple.src.version() != packet.tuple.src.version() { return; }
        if tuple.icmp() && !wire::quoted_echo(&quote, tuple.request()) { return; }
        let port = tuple.sport;
        let Some(flow) = self.flows.entries.get(&port) else { return; };
        let translated = Tuple { src: flow.external, sport: port, ..flow.policy };
        if tuple != translated || !flow.live(now) || flow.revision != view.generation()
            || !policy::allows(view, flow.policy, if flow.policy.icmp() { flow.policy.request() } else { 0 }, now) { return; }
        // DNS redirection errors are presented from the provider DNS identity.
        let remote = if flow.original.dst != flow.policy.dst { flow.original.dst } else { packet.tuple.src };
        let Some(remote) = policy::error_sender(view, remote) else { return; };
        if !wire::unicast(remote) { return; }
        let owner = flow.owner; let mac = flow.mac; let local = flow.original.src;
        let Some(quote) = wire::untranslate_quote(quote, translated, flow.original) else { return; };
        let mut payload = slice_to_vec(&packet.bytes[packet.transport..packet.transport + 8]); payload.extend_from_slice(&quote);
        codec::icmp_checksum(payload.as_mut_slice(), remote, local);
        if let Some(bytes) = wire::ip(remote, local, packet.tuple.proto, &payload, packet.ttl - 1) { self.deliver(owner, mac, view.generation(), bytes, now); }
    }
}

/// Qubes routed client links use this fixed router MAC; no bridge FDB is needed.
fn router_mac() -> [u8; 6] { [0xfe, 0xff, 0xff, 0xff, 0xff, 0xff] }

/// Emit only standard Ethernet/IPv4 ARP via the upstream library representation.
fn arp(operation: u16, src_mac: [u8; 6], src: [u8; 4], dst_mac: [u8; 6], dst: [u8; 4]) -> Option<Vec<u8>> {
    let mut bytes = vec![0; 28];
    codec::emit_arp(bytes.as_mut_slice(), codec::Arp { operation, source_mac: src_mac, source: src, target_mac: dst_mac, target: dst });
    Some(bytes)
}

}
