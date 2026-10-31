//! Routing, fair queues and native-lifetime correlation. Scheduling and Xen
//! calls remain outside this module. Every queued effect is revision stamped.

use crate::{
    MAX_CLIENTS, MTU, QUEUE_FRAMES, SECOND,
    dns::Resolver,
    flow::{NewMapping, Table},
    policy,
    wire::{self, Packet, Tuple},
};
use airlock_qubes_network::{address::Ip, binding::Bound, projection::View, resolution::Resolved};
use alloc::{collections::VecDeque, vec, vec::Vec};
use rand_chacha::ChaCha20Rng;

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
    vstd::seq::Seq::lemma_as_ref_index, vstd::slice::group_slice_axioms,
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
    /// IPv4 datagram, at most MTU bytes, never a raw client Ethernet frame.
    bytes: Vec<u8>,
    /// Destination copied from this immutable datagram's checked library header.
    /// Dequeue need not parse transport headers or recompute checksums again.
    destination: [u8; 4],
    /// Absolute queue deadline; failed ARP cannot retain packets indefinitely.
    deadline: u64,
}

impl Routed {
    /// Bounded private datagram with one optional original-owner requirement.
    closed spec fn valid(&self) -> bool {
        28 <= self.bytes@.len() <= MTU && self.revision > 0 && self.deadline > 0
            && match self.owner { Some(owner) => owner.valid(), None => true }
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
    /// Last generated local ICMP/ARP response time for this client.
    response_at: u64,
}

impl Link {
    /// Both directions retain the same exact original-owner reservation.
    closed spec fn valid(&self) -> bool {
        self.owner.valid() && self.incoming@.len() <= QUEUE_FRAMES && self.outgoing@.len() <= QUEUE_FRAMES
            && (forall|i: int| 0 <= i < self.incoming@.len() ==> self.incoming@[i].valid()
                && self.incoming@[i].value().0 == Target::Client(self.owner)
                && self.incoming@[i].value().1 == Some(self.owner))
            && (forall|i: int| 0 <= i < self.outgoing@.len() ==> self.outgoing@[i].valid()
                && self.outgoing@[i].owner == Some(self.owner))
    }
}

/// One solicited upstream ARP entry. The cache never learns client interfaces.
struct Neighbor {
    /// Cache reservation only, never interface authority. One entry per client;
    /// router/resolver entries have three separate slots including the gateway.
    owner: Option<Owner>,
    /// On-link IPv4 target selected by the configured route.
    ip: [u8; 4],
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
        self.links@.len() <= MAX_CLIENTS && self.flows.valid() && self.dns.valid()
            && self.neighbors@.len() <= 8 && self.internal@.len() <= QUEUE_FRAMES && self.control@.len() <= QUEUE_FRAMES
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
        Self { links: Vec::new(), flows: Table::new(), dns: Resolver::new(), neighbors: VecDeque::new(),
            internal: VecDeque::new(), control: VecDeque::new(), cursor: 0, time: 0, lost: false,
            revision: 0, random: crate::library::generator(seed) }
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
    fn neighbor_index(&self, ip: [u8; 4]) -> (index: Option<usize>)
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
        self.links.push(Link { owner, incoming: VecDeque::new(), outgoing: VecDeque::new(), response_at: 0 });
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
            self.internal.clear(); self.control.clear(); self.neighbors.clear();
            let mut index = 0;
            while index < self.links.len()
                invariant self.valid(), view.valid(), self.time == now, !self.lost, index <= self.links@.len() <= MAX_CLIENTS,
                decreases self.links.len() - index,
            {
                self.links[index].incoming.clear(); self.links[index].outgoing.clear();
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
        // No IPv6, VLAN, broadcast IP, multicast or Ethernet bridging path.
        if frame.protocol != 0x0800 || frame.destination != router_mac() { return; }
        let Some(packet) = Packet::parse(&bytes[14..]) else { return; };
        if !wire::unicast(packet.tuple.src) || !binding.assigned().all().iter().any(|ip: &Ip| -> (same: bool) requires ip.valid(), { ip.ipv4() == Some(packet.tuple.src) }) { return; }
        let Some(config) = view.config() else { return; };
        if view.policy(&Ip::from_ipv4(packet.tuple.src)).is_none() { return; }
        if config.provided_gateway().ipv4() == Some(packet.tuple.dst) && packet.tuple.proto == 1 && packet.icmp == 8 {
            if self.response(owner, now) {
                let mut payload = slice_to_vec(&packet.bytes[20..]);
                codec::echo_reply(payload.as_mut_slice());
                if let Some(bytes) = wire::ipv4(packet.tuple.dst, packet.tuple.src, 1, &payload, 64) {
                    self.deliver(owner, mac, view.generation(), bytes, now);
                }
            }
            return;
        }
        if packet.tuple.proto == 1 && matches!(packet.icmp, 3 | 11 | 12) {
            self.client_related(owner, view, &packet, now); return;
        }
        let Some(policy_tuple) = policy::redirect(view, packet.tuple) else { return; };
        if !policy::allows(view, policy_tuple, packet.icmp, now) { return; }
        if packet.tuple.proto == 1 && packet.icmp != 8 { return; }
        if packet.ttl <= 1 || packet.bytes.len() > MTU {
            if self.response(owner, now) {
                let Some(router) = config.provided_gateway().ipv4() else { return; };
                let (kind, code) = if packet.ttl <= 1 { (11, 0) } else { (3, 4) };
                if let Some(bytes) = wire::error(&packet, router, kind, code) { self.deliver(owner, mac, view.generation(), bytes, now); }
            }
            return;
        }
        let Some(external) = config.address().ipv4() else { return; };
        let port = match self.flows.find(owner, packet.tuple) {
            Some(port) => Some(port),
            None => self.flows.create(NewMapping { owner, policy: policy_tuple, external, mac, revision: view.generation() }, &packet, now, &mut self.random),
        };
        let Some(port) = port else { return; };
        let Some(flow) = self.flows.entries.get(&port) else { return; };
        if flow.policy != policy_tuple || flow.external != external || flow.revision != view.generation() { return; }
        if !self.flows.accept(port, &packet, true, Some(mac), now) { return; }
        let translated = Tuple { src: external, sport: port, ..policy_tuple };
        if let Some(bytes) = packet.translate(translated) { self.route(Some(owner), view.generation(), bytes, now); }
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
        if frame.protocol != 0x0800 || frame.destination != *config.mac().bytes() { return; }
        let Some(packet) = Packet::parse(&bytes[14..]) else { return; };
        if config.address().ipv4() != Some(packet.tuple.dst) { return; }
        if self.dns.receive(&packet, view, now) { return; }
        if packet.tuple.proto == 1 && matches!(packet.icmp, 3 | 11 | 12) { self.related(view, &packet, now); return; }
        if packet.tuple.proto == 1 && packet.icmp != 0 { return; }
        let port = if packet.tuple.proto == 1 { packet.tuple.sport } else { packet.tuple.dport };
        let Some(flow) = self.flows.entries.get(&port) else { return; };
        if !flow.live(now) || !flow.reply(packet.tuple, port) || flow.revision != view.generation()
            || !policy::allows(view, flow.policy, if flow.policy.proto == 1 { 8 } else { 0 }, now) { return; }
        if packet.ttl <= 1 || packet.bytes.len() > MTU {
            let owner = flow.owner; let external = flow.external;
            if self.response(owner, now) {
                let (kind, code) = if packet.ttl <= 1 { (11, 0) } else { (3, 4) };
                if let Some(bytes) = wire::error(&packet, external, kind, code) { self.route(Some(owner), view.generation(), bytes, now); }
            }
            return;
        }
        let owner = flow.owner; let mac = flow.mac;
        let tuple = if packet.tuple.proto == 1 {
            Tuple { src: flow.original.dst, dst: flow.original.src, sport: flow.original.sport, dport: 0, proto: 1 }
        } else { Tuple { src: flow.original.dst, dst: flow.original.src,
            sport: flow.original.dport, dport: flow.original.sport, proto: flow.original.proto } };
        if !self.flows.accept(port, &packet, false, None, now) { return; }
        if let Some(bytes) = packet.translate(tuple) { self.deliver(owner, mac, view.generation(), bytes, now); }
    }

    /// Take one original client's output; native send must still call authorized.
    pub fn next_client(&mut self, owner: Owner) -> (output: Option<Output>)
        requires old(self).valid(), owner.valid(),
        ensures final(self).valid(), output.is_some() ==> output.unwrap().valid()
            && output.unwrap().value().0 == Target::Client(owner) && output.unwrap().value().1 == Some(owner),
    {
        if self.lost { return None; }
        {
            let index = self.link_index(owner)?;
            self.links[index].incoming.pop_front()
        }
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
            let pending = if index == self.links.len() { self.internal.pop_front() } else { self.links[index].outgoing.pop_front() };
            let Some(pending) = pending else { continue; };
            if pending.deadline <= now || pending.revision != view.generation() { continue; }
            let config = view.config()?;
            let local = config.address().ipv4()?;
            let on_link = codec::contains(local, config.prefix(), pending.destination);
            let next = if on_link { Some(pending.destination) } else { config.gateway().ipv4() }?;
            if let Some(mac) = self.neighbors.iter().find(|entry| entry.ip == next && entry.expires > now).and_then(|entry| entry.mac) {
                let bytes = wire::frame(*config.mac().bytes(), mac, 0x0800, &pending.bytes)?;
                return Some(Output { target: Target::Upstream, owner: pending.owner, revision: pending.revision, bytes, deadline: pending.deadline });
            }
            let gateway = config.gateway().ipv4()?;
            let reservation = if next == gateway { None } else { pending.owner };
            let request = self.neighbor_request(next, reservation, gateway, now);
            if index == self.links.len() { self.internal.push_back(pending); } else { self.links[index].outgoing.push_back(pending); }
            if request {
                let bytes = arp(1, *config.mac().bytes(), local, [0; 6], next)?;
                let bytes = wire::frame(*config.mac().bytes(), [255; 6], 0x0806, &bytes)?;
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

    /// Append an internal/client datagram only within that queue's reservation.
    fn route(&mut self, owner: Option<Owner>, revision: u64, bytes: Vec<u8>, now: u64)
        requires old(self).valid(), revision > 0, owner.is_some() ==> owner.unwrap().valid(),
        ensures final(self).valid(),
    {
        if bytes.len() < 28 || bytes.len() > MTU { return; }
        let Some(header) = codec::ipv4(bytes.as_slice()) else { return; };
        let destination = header.destination;
        let queue = match owner {
            Some(owner) => match self.link_index(owner) { Some(index) => Some(&mut self.links[index].outgoing), None => None },
            None => Some(&mut self.internal),
        };
        let Some(queue) = queue else { return; };
        if queue.len() < QUEUE_FRAMES { queue.push_back(Routed { owner, revision, bytes, destination, deadline: now.saturating_add(2 * SECOND) }); }
    }

    /// Frame and append output only to the exact original client's own queue.
    fn deliver(&mut self, owner: Owner, mac: [u8; 6], revision: u64, bytes: Vec<u8>, now: u64)
        requires old(self).valid(), owner.valid(), revision > 0,
        ensures final(self).valid(),
    {
        let Some(bytes) = wire::frame(router_mac(), mac, 0x0800, &bytes) else { return; };
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

    /// Rate-limit ARP and preserve one reservation per client plus three for
    /// router/resolver traffic. Client churn evicts only that client's entry;
    /// internal churn retains the configured gateway. At capacity the new
    /// request is dropped rather than taking another client's reservation.
    fn neighbor_request(&mut self, ip: [u8; 4], owner: Option<Owner>, gateway: [u8; 4], now: u64) -> (request: bool)
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
            let Some(index) = self.neighbors.iter().position(|entry| entry.owner.is_none() && entry.ip != gateway) else { return false; };
            self.neighbors.remove(index);
        }
        if self.neighbors.len() == 8 { return false; }
        self.neighbors.push_back(Neighbor { owner, ip, mac: None, expires: 0, requested: now }); true
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
            || !wire::unicast(fields.source) || fields.target != local { return; }
        if fields.operation == 2 && fields.target_mac == *config.mac().bytes()
            && frame.destination == *config.mac().bytes() {
            if let Some(index) = self.neighbor_index(fields.source) {
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

    /// Translate a client's error only when its quote describes a reply on one
    /// of this same owner's existing allowed flows. It creates no new mapping.
    fn client_related(&mut self, owner: Owner, view: &View, packet: &Packet<'_>, now: u64)
        requires old(self).valid(), owner.valid(), view.valid(), packet.valid(),
        ensures final(self).valid(),
    {
        if packet.ttl <= 1 || packet.bytes.len() > MTU { return; }
        let Some((quote_tuple, quote)) = wire::quote(&packet.bytes[28..]) else { return; };
        if quote_tuple.proto == 1 && codec::icmp(&quote[20..]).is_none_or(|icmp| icmp.kind != 0) { return; }
        let original = if quote_tuple.proto == 1 {
            Tuple { src: quote_tuple.dst, dst: quote_tuple.src, ..quote_tuple }
        } else {
            Tuple { src: quote_tuple.dst, dst: quote_tuple.src, sport: quote_tuple.dport,
                dport: quote_tuple.sport, proto: quote_tuple.proto }
        };
        let Some(port) = self.flows.find(owner, original) else { return; };
        let Some(flow) = self.flows.entries.get(&port) else { return; };
        if packet.tuple.src != flow.original.src || packet.tuple.dst != flow.original.dst
            || !flow.live(now) || flow.revision != view.generation()
            || !policy::allows(view, flow.policy, if flow.policy.proto == 1 { 8 } else { 0 }, now) { return; }
        let translated = if quote_tuple.proto == 1 {
            Tuple { src: flow.policy.dst, dst: flow.external, sport: port, ..quote_tuple }
        } else {
            Tuple { src: flow.policy.dst, dst: flow.external, sport: flow.policy.dport, dport: port, proto: flow.policy.proto }
        };
        let external = flow.external; let destination = flow.policy.dst;
        let Some(quote) = wire::untranslate_quote(quote, quote_tuple, translated) else { return; };
        let mut payload = slice_to_vec(&packet.bytes[20..28]); payload.extend_from_slice(&quote);
        codec::icmp_checksum(payload.as_mut_slice());
        if let Some(bytes) = wire::ipv4(external, destination, 1, &payload, packet.ttl - 1) {
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
        let Some((tuple, quote)) = wire::quote(&packet.bytes[28..]) else { return; };
        if tuple.proto == 1 && codec::icmp(&quote[20..]).is_none_or(|icmp| icmp.kind != 8) { return; }
        let port = tuple.sport;
        let Some(flow) = self.flows.entries.get(&port) else { return; };
        let translated = Tuple { src: flow.external, sport: port, ..flow.policy };
        if tuple != translated || !flow.live(now) || flow.revision != view.generation()
            || !policy::allows(view, flow.policy, if flow.policy.proto == 1 { 8 } else { 0 }, now) { return; }
        // DNS redirection errors are presented from the provider DNS identity.
        let remote = if flow.original.dst != flow.policy.dst { flow.original.dst } else { packet.tuple.src };
        if !wire::unicast(remote) { return; }
        let owner = flow.owner; let mac = flow.mac; let local = flow.original.src;
        let Some(quote) = wire::untranslate_quote(quote, translated, flow.original) else { return; };
        let mut payload = slice_to_vec(&packet.bytes[20..28]); payload.extend_from_slice(&quote);
        codec::icmp_checksum(payload.as_mut_slice());
        if let Some(bytes) = wire::ipv4(remote, local, 1, &payload, packet.ttl - 1) { self.deliver(owner, mac, view.generation(), bytes, now); }
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
