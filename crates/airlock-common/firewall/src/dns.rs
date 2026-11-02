//! One bounded upstream resolver, independent of client-created NAT mappings.
//! Positive results are tied to the exact complete policy revision. A failed,
//! oversized or incomplete answer leaves the entire source blocked. Truncated
//! UDP answers use the maintained TCP endpoint before publishing any policy.
//!
//! Dependency contracts: domain parses complete DNS sections, rejects invalid
//! name lengths/pointer loops, compares names without case, and emits canonical
//! uncompressed names/messages within DNS wire bounds. Only checked IN-class A,
//! AAAA and CNAME records from the answer section populate policy. DNS server
//! authenticity is the existing configured upstream network's assumption; DNSSEC
//! is not claimed. A matched truncated response starts one bounded smoltcp TCP
//! exchange; addresses remain unpublished until its complete DNS reply validates.
//! Cache/query/alias/TTL and exact pending-policy checks are Airlock decisions.

use crate::wire::codec as packet_codec;
use crate::{SECOND, wire};
use airlock_qubes_network::{
    address::Ip,
    projection::View,
    resolution::{NameAnswers, Resolved},
};
use alloc::{boxed::Box, collections::VecDeque, vec, vec::Vec};
use rand_core::RngCore;

use vstd::prelude::*;
use vstd::slice::slice_to_vec;
#[cfg(verus_keep_ghost)]
use vstd::view::View as ValueView;

mod codec;
mod tcp;

verus! {

broadcast use { vstd::std_specs::iter::group_iter_axioms, crate::library::byte_array_equality,
    vstd::std_specs::vec::group_vec_axioms,
    vstd::std_specs::vecdeque::group_vec_dequeue_axioms,
    vstd::set::group_set_lemmas, vstd::seq_lib::group_filter_ensures, vstd::seq::group_seq_lemmas, vstd::seq_lib::group_seq_properties,
    vstd::seq::Seq::lemma_as_ref_index, vstd::slice::group_slice_axioms,
    vstd::std_specs::btree::group_btree_axioms };

/// Maximum cached distinct names, shared across source policies with fair visits.
pub(crate) const CACHE: usize = 2 * 8 * airlock_qubes_network::rule::MAX_RULES;
/// Bounded records per DNS response, including ignored authority/additional data.
pub(crate) const RECORDS: usize = 32;
/// Match domain::Message::canonical_name's bounded chain traversal.
const ALIASES: usize = 20;

/// Canonicalized positive answer or short negative backoff for one server/name.
pub(crate) struct Entry {
    /// Exact selected native upstream resolver.
    pub(crate) server: [u8; 4],
    /// Validated lowercase encoded absolute query name.
    pub(crate) name: Vec<u8>,
    /// Address family, not inferred from arbitrary returned records.
    pub(crate) family: u8,
    /// Positive answers only; empty is a negative backoff, never an allow set.
    pub(crate) addresses: Vec<Ip>,
    /// Monotonic TTL/backoff deadline, capped at five minutes.
    pub(crate) expires: u64,
}

impl Entry {
    /// Cache records are finite and contain only the selected address family.
    pub(crate) open spec fn valid(&self) -> bool {
        0 < self.name@.len() <= 255 && (self.family == 4 || self.family == 6)
            && self.addresses@.len() <= airlock_qubes_network::resolution::MAX_ANSWERS
            && forall|i: int| 0 <= i < self.addresses@.len() ==>
                self.addresses@[i].valid() && self.addresses@[i].family() == self.family
    }

    /// Exact resolver, canonical name and requested address-family cache key.
    pub(crate) open spec fn key(&self) -> ([u8; 4], Seq<u8>, u8) { (self.server, self.name@, self.family) }
}

/// Largest retained DNS TCP message, excluding its two-byte length prefix.
/// Record/name limits still apply independently after domain decodes the message.
pub(crate) const TCP_BYTES: usize = 16_384;

/// One bounded DNS stream exchange, using smoltcp for transport state.
pub(crate) struct Stream {
    /// Actual maintained TCP endpoint, without native send authority.
    connection: Box<tcp::Connection>,
    /// One complete length-prefixed question.
    query: Vec<u8>,
    /// Question bytes already accepted by the TCP endpoint.
    sent: usize,
    /// Ordered response prefix; never larger than the fixed DNS message budget.
    received: Vec<u8>,
}

/// The single request's legal transport states; fallback occurs at most once.
pub(crate) enum Transport {
    /// Initial UDP query, with no stream resources allocated.
    Datagram,
    /// A matched truncated answer caused one bounded TCP exchange.
    Stream(/// Original endpoint and ordered query/response progress.
        Stream),
}

impl Transport {
    /// Each state retains at most one question and one bounded response.
    pub(crate) closed spec fn valid(&self) -> bool {
        match self {
            Self::Datagram => true,
            Self::Stream(stream) => 2 <= stream.query@.len() <= 273
                && stream.sent <= stream.query@.len() && stream.received@.len() <= TCP_BYTES + 2,
        }
    }
}

/// Exactly one outstanding request, with independent port and transaction ID.
pub(crate) struct Pending {
    /// Captured policy revision; any mutation cancels this completion.
    pub(crate) revision: u64,
    /// Source whose whole policy is being populated.
    pub(crate) source: Ip,
    /// Encoded lowercase absolute name for query and compressed-name comparison.
    pub(crate) name: Vec<u8>,
    /// Actual resolver selected from current config.
    pub(crate) server: [u8; 4],
    /// Masquerade address captured before emitting the request.
    pub(crate) local: [u8; 4],
    /// Dynamic UDP/TCP port disjoint from client NAT leases.
    pub(crate) port: u16,
    /// Independent DNS transaction identifier.
    pub(crate) transaction: u16,
    /// Independent seed for the maintained TCP endpoint's sequence allocator.
    pub(crate) seed: u64,
    /// Explicit UDP or single-fallback TCP state.
    pub(crate) transport: Transport,
    /// Absolute request expiry; TCP fallback gets one separately bounded period.
    pub(crate) deadline: u64,
}

impl Pending {
    /// One original policy and bounded question in the resolver-only namespace.
    pub(crate) open spec fn valid(&self) -> bool {
        self.source.valid() && self.revision > 0 && 0 < self.name@.len() <= 255 && 32768 <= self.port < 49152 && self.transport.valid()
    }
}

/// Resolver cache and one explicit UDP/TCP exchange, without VM effects.
pub(crate) struct Resolver {
    /// FIFO eviction avoids unbounded access timestamps or a custom cache.
    pub(crate) cache: VecDeque<Entry>,
    /// At most one outstanding upstream request at any time.
    pub(crate) pending: Option<Pending>,
    /// Next source index for bounded round-robin progress.
    pub(crate) cursor: usize,
    /// Next admitted query time also rate-limits repeated cache misses.
    pub(crate) next: u64,
}

impl Resolver {
    /// Cached and in-flight observations have finite names and address counts;
    /// their addresses remain data, never native interface credentials.
    pub(crate) open spec fn valid(&self) -> bool {
        self.cache@.len() <= CACHE
            && (forall|i: int| 0 <= i < self.cache@.len() ==> self.cache@[i].valid())
            && (forall|i: int, j: int| 0 <= i < j < self.cache@.len() ==> self.cache@[i].key() != self.cache@[j].key())
            && match self.pending { Some(pending) => pending.valid(), None => true }
    }

    /// Cache capacity and original outstanding-query endpoint, for contracts.
    pub(crate) open spec fn cache_count(&self) -> nat { self.cache@.len() }

    /// Whether a datagram belongs to the original outstanding resolver endpoint.
    pub(crate) open spec fn expecting(&self, tuple: wire::Tuple) -> bool {
        self.pending.is_some()
            && (tuple.proto == 17 && self.pending.unwrap().transport is Datagram
                || tuple.proto == 6 && self.pending.unwrap().transport is Stream)
            && tuple.dst == Ip::v4_value(self.pending.unwrap().local)
            && tuple.src == Ip::v4_value(self.pending.unwrap().server) && tuple.dport == self.pending.unwrap().port && tuple.sport == 53
    }

    /// Begin without cached policy data or query authorization.
    pub(crate) fn new() -> (resolver: Self)
        ensures resolver.valid(), resolver.cache_count() == 0,
    { Self { cache: VecDeque::new(), pending: None, cursor: 0, next: 0 } }

    /// Make at most one query or one whole-source publication per scheduler turn.
    /// Returns a private IP datagram; the engine handles ARP and output queues.
    pub(crate) fn tick(&mut self, view: &View, now: u64, random: &mut impl RngCore) -> (work: (Option<Vec<u8>>, Option<Resolved>))
        requires old(self).valid(), view.valid(),
        ensures final(self).valid(), work.0.is_some() ==> work.0.unwrap()@.len() <= crate::MTU && view.revision() > 0,
            work.1.is_some() ==> work.1.unwrap().valid() && work.1.unwrap().revision_value() == view.revision()
                && work.1.unwrap().unexpired(now)
                && exists|snapshot: airlock_qubes_network::policy::Snapshot|
                    view.awaiting(work.1.unwrap().source_value(), snapshot) && work.1.unwrap().matches(snapshot),
    {
        if let Some(pending) = &self.pending {
            if pending.revision != view.generation() || view.candidate(&pending.source).is_none() { self.pending = None; }
            else if now >= pending.deadline {
                let Some(pending) = self.pending.take() else { return (None, None); };
                self.insert(Entry { server: pending.server, name: pending.name, family: pending.source.version(),
                    addresses: Vec::new(), expires: now.saturating_add(5 * SECOND) });
            } else {
                if matches!(pending.transport, Transport::Stream(_)) { return (self.stream_turn(view, now), None); }
                return (None, None);
            }
        }
        if now < self.next { return (None, None); }
        let Some(config) = view.config() else { return (None, None); };
        let sources = config.all_sources();
        if sources.is_empty() { return (None, None); }
        self.cursor %= sources.len();
        let source = sources[self.cursor]; self.cursor = (self.cursor + 1) % sources.len();
        let Some((revision, snapshot)) = view.candidate(&source) else { return (None, None); };
        let Some(local) = config.address().ipv4() else { return (None, None); };
        let server_index = ((now / (5 * SECOND)) % 2) as usize;
        let Some(server) = config.dns()[server_index].ipv4() else { return (None, None); };
        if !crate::policy::remote(view, Ip::from_ipv4(server)) { return (None, None); }
        let mut names: Vec<Vec<u8>> = Vec::new();
        let mut answers: Vec<NameAnswers> = Vec::new();
        let rules = snapshot.rules();
        let family = source.version();
        let mut index = 0;
        while index < rules.len()
            invariant self.valid(), view.valid(), snapshot.valid(), config.valid(), source.valid(),
                revision == view.revision(), view.awaiting(source, *snapshot),
                source == snapshot.source_value(),
                forall|j: int| 0 <= j < rules@.len() ==> rules@[j].rule().valid(),
                revision > 0, family == source.family(), family == 4 || family == 6,
                rules@ == snapshot.rules_value(), index <= rules@.len() <= airlock_qubes_network::policy::MAX_RULES,
                names@.len() <= index, answers@.len() <= index,
                forall|i: int| 0 <= i < answers@.len() ==> answers@[i].valid(),
            decreases rules.len() - index,
        {
            let rule = &rules[index];
            index += 1;
            let Some(host) = rule.entry().host() else { continue; };
            if names.iter().any(|name: &Vec<u8>| -> (same: bool)
                ensures same == (name@ == host.bytes()),
            {
                let original = host.name();
                let same = name.as_slice().eq(original);
                proof { assert(same ==> name@ =~= original@); assert(!same ==> name@ != original@); }
                same
            }) { continue; }
            names.push(slice_to_vec(host.name()));
            let Some(name) = codec::encode(host.name()) else { return (None, None); };
            if let Some(entry) = self.cache.iter().find(|entry: &&Entry| -> (matches: bool)
                requires entry.valid(),
                ensures matches ==> entry.family == family && entry.expires > now,
            { entry.server == server && entry.name == name && entry.family == family && entry.expires > now }) {
                if entry.addresses.is_empty() { return (None, None); }
                let addresses = slice_to_vec(entry.addresses.as_slice());
                let Some(answer) = NameAnswers::new(host.name(), addresses, entry.expires, now, source.version()) else { return (None, None); };
                answers.push(answer);
            } else {
                let port = 32768 + (random.next_u32() % 16384) as u16;
                let transaction = (random.next_u32() % 65536) as u16;
                let Some(dns) = codec::query(&name, source.version(), transaction) else { return (None, None); };
                let mut udp = vec![0; 8 + dns.len()];
                packet_codec::emit_udp(udp.as_mut_slice(), local, server, port, 53, &dns);
                self.pending = Some(Pending { revision, source, name, server, local,
                    port, transaction, seed: random.next_u64(), transport: Transport::Datagram, deadline: now.saturating_add(2 * SECOND) });
                self.next = now.saturating_add(SECOND / 10);
                return (wire::ipv4(local, server, 17, &udp, 64), None);
            }
        }
        let complete = Resolved::new(snapshot, revision, answers, now);
        proof {
            if complete.is_some() { assert(view.awaiting(complete.unwrap().source_value(), *snapshot)); }
        }
        (None, complete)
    }

    /// A resolver response cannot enter client conntrack. Match both endpoints,
    /// port, ID, exact question and the still-current policy before caching data.
    pub(crate) fn receive(&mut self, packet: &wire::Packet<'_>, view: &View, now: u64) -> (consumed: bool)
        requires old(self).valid(), packet.valid(), view.valid(),
        ensures final(self).valid(), !consumed ==> *final(self) == *old(self),
            consumed ==> old(self).expecting(packet.tuple),
    {
        let Some(pending) = &self.pending else { return false; };
        let protocol = match pending.transport { Transport::Datagram => 17u8, Transport::Stream(_) => 6u8 };
        if packet.tuple.proto != protocol || packet.tuple.dst != Ip::from_ipv4(pending.local) || packet.tuple.dport != pending.port
            || packet.tuple.src != Ip::from_ipv4(pending.server) || packet.tuple.sport != 53 { return false; }
        if now >= pending.deadline || pending.revision != view.generation() { self.pending = None; return true; }
        if protocol == 6 {
            if packet.bytes.len() > crate::MTU { return true; }
            let Some(Pending { transport: Transport::Stream(stream), .. }) = &mut self.pending else { return true; };
            tcp::input(&mut stream.connection, packet.bytes);
            return true;
        }
        let payload = &packet.bytes[packet.transport + 8..];
        if truncated(payload, pending) {
            let Some(query) = codec::query(&pending.name, pending.source.version(), pending.transaction) else { return true; };
            let Some(connection) = tcp::open(pending.local, pending.server, pending.port, pending.seed, now) else { return true; };
            let mut framed = Vec::new();
            framed.extend_from_slice(&airlock_qubes_network::network_bytes(query.len() as u16)); framed.extend_from_slice(&query);
            if let Some(pending) = &mut self.pending {
                pending.transport = Transport::Stream(Stream { connection: Box::new(connection), query: framed, sent: 0, received: Vec::new() });
                pending.deadline = now.saturating_add(10 * SECOND);
            }
            return true;
        }
        let Some((addresses, ttl)) = response(&packet.bytes[packet.transport + 8..], pending) else { return true; };
        let Some(pending) = self.pending.take() else { return true; };
        self.insert(Entry { server: pending.server, name: pending.name, family: pending.source.version(),
            addresses, expires: now.saturating_add(u64::from(ttl.min(300)) * SECOND) });
        true
    }

    /// Drive one finite stream exchange. The library owns TCP sequencing; this
    /// state machine admits only the original framed DNS message and revision.
    fn stream_turn(&mut self, view: &View, now: u64) -> (packet: Option<Vec<u8>>)
        requires old(self).valid(), view.valid(),
        ensures final(self).valid(), packet.is_some() ==> packet.unwrap()@.len() <= crate::MTU && view.revision() > 0,
    {
        let mut pending = self.pending.take()?;
        if pending.revision != view.generation() || pending.deadline <= now { return None; }
        let Transport::Stream(stream) = &mut pending.transport else { self.pending = Some(pending); return None; };
        let sent = tcp::write(&mut stream.connection, &stream.query[stream.sent..]);
        stream.sent += sent;
        let mut output = tcp::poll(&mut stream.connection, now);
        let received = tcp::read(&mut stream.connection, TCP_BYTES + 2 - stream.received.len());
        stream.received.extend_from_slice(&received);
        if stream.received.len() < 2 { self.pending = Some(pending); return output; }
        let length = usize::from(airlock_qubes_network::network_word([stream.received[0], stream.received[1]]));
        if !(12..=TCP_BYTES).contains(&length) {
            pending.deadline = now; self.pending = Some(pending); return output;
        }
        if stream.received.len() < length + 2 { self.pending = Some(pending); return output; }
        if stream.received.len() != length + 2 || stream.sent != stream.query.len() {
            pending.deadline = now; self.pending = Some(pending); return output;
        }
        let message = slice_to_vec(&stream.received[2..]);
        // This one-shot endpoint has consumed its complete response. Emit a
        // library TCP reset so a remote server does not retain an idle socket.
        tcp::abort(&mut stream.connection);
        if let Some(reset) = tcp::poll(&mut stream.connection, now) { output = Some(reset); }
        if let Some((addresses, ttl)) = response(&message, &pending) {
            self.insert(Entry { server: pending.server, name: pending.name, family: pending.source.version(),
                addresses, expires: now.saturating_add(u64::from(ttl.min(300)) * SECOND) });
        } else {
            self.insert(Entry { server: pending.server, name: pending.name, family: pending.source.version(),
                addresses: Vec::new(), expires: now.saturating_add(5 * SECOND) });
        }
        output
    }

    /// Insert only bounded entries, evicting one old observation at capacity.
    fn insert(&mut self, entry: Entry)
        requires old(self).valid(), entry.valid(),
        ensures final(self).valid(), final(self).pending == old(self).pending,
    {
        let ghost before = self.cache@;
        proof { assert(before.no_duplicates()); }
        crate::library::retain_deque(&mut self.cache, |old: &Entry| -> (keep: bool)
            ensures keep == (old.key() != entry.key()),
        {
            let left = old.name.as_slice();
            let right = entry.name.as_slice();
            let same = left.eq(right);
            proof { assert(same ==> left@ =~= right@); assert(!same ==> left@ != right@); }
            !(old.server == entry.server && same && old.family == entry.family)
        });
        proof {
            assert forall|i: int| 0 <= i < self.cache@.len() implies self.cache@[i].key() != entry.key() by {
                assert(before.contains(self.cache@[i]));
            }
        }
        if self.cache.len() == CACHE { self.cache.pop_front(); }
        self.cache.push_back(entry);
    }
}

/// A truncation flag requests fallback only for the exact outstanding question.
fn truncated(bytes: &[u8], pending: &Pending) -> bool
    requires pending.valid(),
{
    let Some(header) = codec::header(bytes) else { return false; };
    if header.id != pending.transaction || header.opcode != 0 || !header.response || !header.truncated
        || header.rcode != 0 || header.questions != 1 { return false; }
    let Some(question) = codec::question(bytes) else { return false; };
    question.name == pending.name && question.class == 1
        && question.kind == if pending.source.version() == 4 { 1u16 } else { 28u16 }
}


/// Accept only complete positive answers for the original outstanding question.
/// Library parsing and CNAME traversal are supplied by codec; every admission,
/// ambiguity, address-family and TTL decision remains in this production body.
fn response(bytes: &[u8], pending: &Pending) -> (answer: Option<(Vec<Ip>, u32)>)
    requires pending.valid(),
    ensures answer.is_some() ==> 0 < answer.unwrap().0@.len() <= airlock_qubes_network::resolution::MAX_ANSWERS
        && answer.unwrap().1 > 0
        && (forall|i: int| 0 <= i < answer.unwrap().0@.len() ==> answer.unwrap().0@[i].valid()
            && answer.unwrap().0@[i].family() == pending.source.family()),
{
    if bytes.len() > TCP_BYTES { return None; }
    let h = codec::header(bytes)?;
    if h.id != pending.transaction || h.opcode != 0 || !h.response || h.truncated || h.rcode != 0 || h.questions != 1 { return None; }
    let count = usize::from(h.answers) + usize::from(h.authority) + usize::from(h.additional);
    if count > RECORDS || h.answers == 0 { return None; }
    let message = codec::message(bytes)?;
    if message.consumed != bytes.len() || message.name != pending.name || message.class != 1
        || message.kind != if pending.source.version() == 4 { 1 } else { 28 } { return None; }
    let mut aliases = 0;
    let mut ttl = u32::MAX;
    let mut index = 0;
    while index < message.records.len()
        invariant message.valid(), pending.valid(), index <= message.records@.len() <= RECORDS,
            aliases <= ALIASES,
        decreases message.records.len() - index,
    {
        let record = &message.records[index];
        index += 1;
        if record.class != 1 { return None; }
        ttl = ttl.min(record.ttl);
        if let codec::Data::Alias(target) = &record.data {
            if aliases == ALIASES { return None; }
            let mut other_index = 0;
            while other_index < message.records.len()
                invariant message.valid(), pending.valid(), index <= message.records@.len() <= RECORDS,
                    other_index <= message.records@.len(), aliases < ALIASES,
                decreases message.records.len() - other_index,
            {
                let other = &message.records[other_index];
                other_index += 1;
                if other.owner != record.owner { continue; }
                match &other.data {
                    codec::Data::V4(_) | codec::Data::V6(_) => return None,
                    codec::Data::Alias(other) => if other != target { return None; },
                    codec::Data::Other => (),
                }
            }
            aliases += 1;
        }
    }
    if ttl == 0 { return None; }
    let canonical = message.canonical.as_ref()?;
    let mut addresses: Vec<Ip> = Vec::new();
    index = 0;
    while index < message.records.len()
        invariant message.valid(), pending.valid(), ttl > 0, index <= message.records@.len() <= RECORDS,
            addresses@.len() <= airlock_qubes_network::resolution::MAX_ANSWERS,
            forall|i: int| 0 <= i < addresses@.len() ==> addresses@[i].valid()
                && addresses@[i].family() == pending.source.family(),
        decreases message.records.len() - index,
    {
        let record = &message.records[index];
        index += 1;
        if record.owner.as_slice() != canonical.as_slice() { continue; }
        let ip = match &record.data {
            codec::Data::V4(ip) if pending.source.version() == 4 => Ip::from_ipv4(*ip),
            codec::Data::V6(ip) if pending.source.version() == 6 => Ip::from_ipv6(*ip),
            _ => continue,
        };
        if !addresses.iter().any(|old: &Ip| -> (same: bool) requires old.valid(), { old.same(&ip) }) {
            if addresses.len() == airlock_qubes_network::resolution::MAX_ANSWERS { return None; }
            addresses.push(ip);
        }
    }
    if addresses.is_empty() { return None; }
    Some((addresses, ttl))
}

}
