//! Bounded resource observations, separate from policy and lifecycle readiness.
//! Packet paths update fixed counters and a small client history; only scheduled
//! reports inspect retained port usage. Nothing in this module grants admission.
//! Global totals span the boot. Per-client totals span each reported tracking
//! start; address churn beyond the history bound increments an eviction counter.

use crate::AdmissionError;
use airlock_qubes_network::address::Ip;
use vstd::prelude::*;

verus! {

broadcast use { vstd::std_specs::iter::group_iter_axioms,
    vstd::seq::Seq::lemma_as_ref_index, vstd::seq_lib::group_seq_properties };

/// Retain up to eight client histories in a fixed insertion cycle.
pub const CLIENT_HISTORY: usize = 2 * crate::MAX_CLIENTS;

/// Counter for each distinct admission outcome, excluding policy/parser drops.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(verus_keep_ghost), derive(serde::Serialize))]
pub struct Rejections {
    /// Client active credits were full.
    pub active_client: u64,
    /// Global active credits were full.
    pub active_global: u64,
    /// Client stored reservations were full.
    pub retained_client: u64,
    /// Global stored reservations were full.
    pub retained_global: u64,
    /// The internal identifier namespace was exhausted.
    pub identifier: u64,
    /// No translation port was available for a new socket.
    pub port: u64,
    /// An existing peer owned the translated reply tuple.
    pub tuple_collision: u64,
    /// Transport state rejected initiation, renewal or advancement.
    pub transport: u64,
    /// No finite lease could be admitted at the exhausted clock.
    pub clock: u64,
    /// A required private record/index was unavailable.
    pub state: u64,
}

impl Rejections {
    /// Start with no observed admission failures.
    pub(crate) fn empty() -> (counts: Self)
        ensures counts.active_client == 0 && counts.active_global == 0
            && counts.retained_client == 0 && counts.retained_global == 0
            && counts.identifier == 0 && counts.port == 0 && counts.tuple_collision == 0
            && counts.transport == 0 && counts.clock == 0 && counts.state == 0,
    {
        Self { active_client: 0, active_global: 0, retained_client: 0, retained_global: 0,
            identifier: 0, port: 0, tuple_collision: 0, transport: 0, clock: 0, state: 0 }
    }

    /// Exactly one selected counter advances, with saturation at the type bound.
    pub(crate) open spec fn recorded(&self, before: Self, failure: AdmissionError) -> bool {
        self.active_client == before.active_client.saturating_add(if failure is ActiveClient { 1 } else { 0 })
            && self.active_global == before.active_global.saturating_add(if failure is ActiveGlobal { 1 } else { 0 })
            && self.retained_client == before.retained_client.saturating_add(if failure is RetainedClient { 1 } else { 0 })
            && self.retained_global == before.retained_global.saturating_add(if failure is RetainedGlobal { 1 } else { 0 })
            && self.identifier == before.identifier.saturating_add(if failure is IdentifierExhausted { 1 } else { 0 })
            && self.port == before.port.saturating_add(if failure is PortExhausted { 1 } else { 0 })
            && self.tuple_collision == before.tuple_collision.saturating_add(if failure is TupleCollision { 1 } else { 0 })
            && self.transport == before.transport.saturating_add(if failure is Transport { 1 } else { 0 })
            && self.clock == before.clock.saturating_add(if failure is Clock { 1 } else { 0 })
            && self.state == before.state.saturating_add(if failure is State { 1 } else { 0 })
    }

    /// Count exactly one failure category, saturating rather than wrapping.
    pub(crate) fn record(&mut self, failure: AdmissionError)
        ensures final(self).recorded(*old(self), failure),
    {
        match failure {
            AdmissionError::ActiveClient => self.active_client = self.active_client.saturating_add(1),
            AdmissionError::ActiveGlobal => self.active_global = self.active_global.saturating_add(1),
            AdmissionError::RetainedClient => self.retained_client = self.retained_client.saturating_add(1),
            AdmissionError::RetainedGlobal => self.retained_global = self.retained_global.saturating_add(1),
            AdmissionError::IdentifierExhausted => self.identifier = self.identifier.saturating_add(1),
            AdmissionError::PortExhausted => self.port = self.port.saturating_add(1),
            AdmissionError::TupleCollision => self.tuple_collision = self.tuple_collision.saturating_add(1),
            AdmissionError::Transport => self.transport = self.transport.saturating_add(1),
            AdmissionError::Clock => self.clock = self.clock.saturating_add(1),
            AdmissionError::State => self.state = self.state.saturating_add(1),
        }
    }
}

/// Queue exhaustion categories; ordinary validation/policy drops are excluded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(verus_keep_ghost), derive(serde::Serialize))]
pub struct QueueDrops {
    /// A client-to-upstream ordinary queue was full.
    pub upstream: u64,
    /// A client-bound ordinary queue was full.
    pub downstream: u64,
    /// The resolver/router queue was full.
    pub internal: u64,
    /// Native backpressure could not requeue a previously selected output.
    pub retry: u64,
    /// A queue already retained its one allowed large datagram.
    pub fragment: u64,
}

/// Exact bounded queue reservation whose exhaustion dropped an output.
#[derive(Clone, Copy)]
pub(crate) enum Queue {
    /// Ordinary client-to-upstream traffic.
    Upstream,
    /// Ordinary upstream-to-client traffic.
    Downstream,
    /// Router/resolver output.
    Internal,
    /// Requeue after native backpressure.
    Retry,
    /// Already occupied large-datagram reservation.
    Fragment,
}

impl QueueDrops {
    /// Start with all queue exhaustion counters clear.
    pub(crate) fn empty() -> (counts: Self)
        ensures counts.upstream == 0 && counts.downstream == 0 && counts.internal == 0
            && counts.retry == 0 && counts.fragment == 0,
    { Self { upstream: 0, downstream: 0, internal: 0, retry: 0, fragment: 0 } }

    /// Exactly one selected counter advances, with saturation at the type bound.
    pub(crate) open spec fn recorded(&self, before: Self, queue: Queue) -> bool {
        self.upstream == before.upstream.saturating_add(if queue is Upstream { 1 } else { 0 })
            && self.downstream == before.downstream.saturating_add(if queue is Downstream { 1 } else { 0 })
            && self.internal == before.internal.saturating_add(if queue is Internal { 1 } else { 0 })
            && self.retry == before.retry.saturating_add(if queue is Retry { 1 } else { 0 })
            && self.fragment == before.fragment.saturating_add(if queue is Fragment { 1 } else { 0 })
    }

    /// Count only the selected exhaustion category, retaining lifetime totals.
    pub(crate) fn record(&mut self, queue: Queue)
        ensures final(self).recorded(*old(self), queue),
    {
        match queue {
            Queue::Upstream => self.upstream = self.upstream.saturating_add(1),
            Queue::Downstream => self.downstream = self.downstream.saturating_add(1),
            Queue::Internal => self.internal = self.internal.saturating_add(1),
            Queue::Retry => self.retry = self.retry.saturating_add(1),
            Queue::Fragment => self.fragment = self.fragment.saturating_add(1),
        }
    }
}

/// Current active credits and all stored reservations, including those credits.
/// Credits conservatively include expiry awaiting the bounded maintenance turn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(verus_keep_ghost), derive(serde::Serialize))]
pub struct Occupancy {
    /// Active admission credits, shared by both address families.
    pub active_credits: usize,
    /// All peer records, each owning its eventual retirement storage.
    pub stored_records: usize,
    /// Stored records without an active credit, retaining delayed-packet protection.
    pub inactive_records: usize,
}

/// High-water marks persist even when the current occupancy returns to zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(verus_keep_ghost), derive(serde::Serialize))]
pub struct Peaks {
    /// Largest charged active occupancy in this tracking scope.
    pub active_credits: usize,
    /// Largest stored occupancy in this tracking scope.
    pub stored_records: usize,
    /// Largest protected occupancy without active credits in this tracking scope.
    pub inactive_records: usize,
}

impl Peaks {
    /// Empty high-water state before any peer has been observed.
    pub(crate) fn empty() -> (peaks: Self)
        ensures peaks.active_credits == 0 && peaks.stored_records == 0 && peaks.inactive_records == 0,
    { Self { active_credits: 0, stored_records: 0, inactive_records: 0 } }

    /// Observe constant-time occupancy without losing earlier bursts.
    pub(crate) fn observe(&mut self, active: usize, stored: usize)
        requires active <= stored,
        ensures final(self).active_credits == if active > old(self).active_credits { active } else { old(self).active_credits },
            final(self).stored_records == if stored > old(self).stored_records { stored } else { old(self).stored_records },
            final(self).inactive_records == if stored - active > old(self).inactive_records { stored - active } else { old(self).inactive_records as int },
    {
        self.active_credits = self.active_credits.max(active);
        self.stored_records = self.stored_records.max(stored);
        self.inactive_records = self.inactive_records.max(stored - active);
    }
}

/// Cumulative progress through active-credit return and protected state release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(verus_keep_ghost), derive(serde::Serialize))]
pub struct Reclamation {
    /// Scheduler maintenance turns, including empty turns.
    pub turns: u64,
    /// Retained records examined by those bounded turns.
    pub examined: u64,
    /// Active credits returned on expiry, revocation or transport retirement.
    pub active_returns: u64,
    /// Peer records actually released after their full hold-down.
    pub records_released: u64,
    /// Translation ports released after the last retained peer.
    pub ports_released: u64,
    /// Monotonic time of the latest peer-record release; absent before the first.
    pub last_release_ns: Option<u64>,
}

impl Reclamation {
    /// Start without claiming any scheduler or release progress.
    pub(crate) fn empty() -> (progress: Self)
        ensures progress.turns == 0 && progress.examined == 0 && progress.active_returns == 0
            && progress.records_released == 0 && progress.ports_released == 0 && progress.last_release_ns is None,
    {
        Self { turns: 0, examined: 0, active_returns: 0, records_released: 0,
            ports_released: 0, last_release_ns: None }
    }
}

/// One source's history, independent of its current native interface lifetime.
#[derive(Clone, Copy)]
pub(crate) struct ClientMeter {
    /// Stable primary assigned address; never a packet-supplied remote endpoint.
    pub(crate) source: Ip,
    /// Start of this bounded history entry, making any reset explicit.
    pub(crate) since_ns: u64,
    /// Flow high-water marks across reconnects of this tracked source.
    pub(crate) peaks: Peaks,
    /// Admission failures attributed to this source, including failed first flows.
    pub(crate) rejections: Rejections,
    /// Output exhaustion attributed through the original native owner.
    pub(crate) queue_drops: QueueDrops,
    /// Native send backpressure, including successful requeues.
    pub(crate) native_retries: u64,
}

/// Fixed observation state; no mutable forwarding state or resource authority.
pub(crate) struct Meters {
    /// Saturating boot-wide failure totals, never cleared by publication.
    pub(crate) rejections: Rejections,
    /// Saturating boot-wide queue totals, including unattributed internal output.
    pub(crate) queue_drops: QueueDrops,
    /// Boot-wide native backpressure attempts, even if every requeue succeeds.
    pub(crate) native_retries: u64,
    /// Small fixed client history; this is independent of flow-table storage.
    pub(crate) clients: [Option<ClientMeter>; CLIENT_HISTORY],
    /// Replaced client histories; global totals remain complete for this boot.
    pub(crate) history_evictions: u64,
    /// Next fixed history slot to replace if every slot is occupied.
    pub(crate) next_slot: usize,
}

impl Meters {
    /// Bound every retained history entry to one valid, distinct source.
    pub(crate) open spec fn valid(&self) -> bool {
        self.next_slot < CLIENT_HISTORY
            && (forall|i: int| 0 <= i < CLIENT_HISTORY && self.clients@[i] is Some ==> self.clients@[i].unwrap().source.valid())
            && (forall|i: int, j: int| 0 <= i < j < CLIENT_HISTORY && self.clients@[i] is Some && self.clients@[j] is Some
                ==> self.clients@[i].unwrap().source != self.clients@[j].unwrap().source)
    }

    /// Clear counters and all fixed history slots without heap allocation.
    pub(crate) fn new() -> (meters: Self)
        ensures meters.valid(), meters.history_evictions == 0,
    { Self { rejections: Rejections::empty(), queue_drops: QueueDrops::empty(), native_retries: 0, clients: [None; CLIENT_HISTORY], history_evictions: 0, next_slot: 0 } }

    /// Reuse an existing source's counters, then an empty slot, then the next
    /// slot in a fixed insertion cycle. Eviction is observation loss only:
    /// boot-wide counters stay intact and report how many histories were replaced.
    pub(crate) fn client(&mut self, source: Ip, now: u64) -> (slot: usize)
        requires old(self).valid(), source.valid(),
        ensures final(self).valid(), slot < CLIENT_HISTORY,
            final(self).clients@[slot as int] is Some && final(self).clients@[slot as int].unwrap().source == source,
            final(self).rejections == old(self).rejections && final(self).queue_drops == old(self).queue_drops,
            final(self).native_retries == old(self).native_retries,
            final(self).history_evictions == old(self).history_evictions.saturating_add(
                if old(self).clients@[slot as int] is Some && old(self).clients@[slot as int].unwrap().source != source { 1 } else { 0 }),
            forall|i: int| 0 <= i < CLIENT_HISTORY && i != slot ==> final(self).clients@[i] == old(self).clients@[i],
            old(self).clients@[slot as int] is Some && old(self).clients@[slot as int].unwrap().source == source
                ==> final(self).clients@[slot as int] == old(self).clients@[slot as int],
    {
        let existing = self.clients.iter().position(|client: &Option<ClientMeter>| -> (same: bool)
            ensures same == (client.is_some() && client.unwrap().source == source),
        { match client { Some(client) => client.source == source, None => false } });
        if let Some(slot) = existing { return slot; }
        let empty = self.clients.iter().position(|client: &Option<ClientMeter>| -> (empty: bool)
            ensures empty == client.is_none(),
        { client.is_none() });
        let chosen = empty.unwrap_or(self.next_slot);
        if empty.is_none() { self.history_evictions = self.history_evictions.saturating_add(1); }
        self.clients[chosen] = Some(ClientMeter { source, since_ns: now,
            peaks: Peaks::empty(), rejections: Rejections::empty(), queue_drops: QueueDrops::empty(), native_retries: 0 });
        self.next_slot = (chosen + 1) % CLIENT_HISTORY;
        chosen
    }

    /// Retain the source's latest active/stored high-water observations.
    pub(crate) fn observe(&mut self, source: Ip, now: u64, occupancy: Occupancy)
        requires old(self).valid(), source.valid(), occupancy.active_credits <= occupancy.stored_records,
        ensures final(self).valid(), final(self).rejections == old(self).rejections,
            final(self).queue_drops == old(self).queue_drops, final(self).native_retries == old(self).native_retries,
    {
        let slot = self.client(source, now);
        if let Some(client) = &mut self.clients[slot] { client.peaks.observe(occupancy.active_credits, occupancy.stored_records); }
    }

    /// Attribute a failed admission without losing global totals on history churn.
    pub(crate) fn rejection(&mut self, source: Ip, now: u64, failure: AdmissionError)
        requires old(self).valid(), source.valid(),
        ensures final(self).valid(), final(self).rejections.recorded(old(self).rejections, failure),
    {
        self.rejections.record(failure);
        let slot = self.client(source, now);
        if let Some(client) = &mut self.clients[slot] { client.rejections.record(failure); }
    }

    /// Count native backpressure separately from full-queue requeue failures.
    pub(crate) fn retry(&mut self, source: Option<Ip>, now: u64)
        requires old(self).valid(), source.is_some() ==> source.unwrap().valid(),
        ensures final(self).valid(), final(self).native_retries == old(self).native_retries.saturating_add(1),
    {
        self.native_retries = self.native_retries.saturating_add(1);
        if let Some(source) = source {
            let slot = self.client(source, now);
            if let Some(client) = &mut self.clients[slot] { client.native_retries = client.native_retries.saturating_add(1); }
        }
    }

    /// Attribute queue pressure where an original client identity is available.
    pub(crate) fn queue_drop(&mut self, source: Option<Ip>, now: u64, queue: Queue)
        requires old(self).valid(), source.is_some() ==> source.unwrap().valid(),
        ensures final(self).valid(), final(self).queue_drops.recorded(old(self).queue_drops, queue),
    {
        self.queue_drops.record(queue);
        if let Some(source) = source {
            let slot = self.client(source, now);
            if let Some(client) = &mut self.clients[slot] { client.queue_drops.record(queue); }
        }
    }
}

/// Current shared translation usage. Multiple UDP peers can share one socket.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(not(verus_keep_ghost), derive(serde::Serialize))]
pub struct Ports {
    /// Distinct translated ports, including reservations held after expiry.
    pub translation_ports: usize,
    /// UDP source sockets with at least one retained peer reservation.
    pub udp_sockets: usize,
}

/// One bounded source report, including its explicit history scope.
#[derive(Clone, Copy)]
#[cfg_attr(not(verus_keep_ghost), derive(serde::Serialize))]
pub struct ClientSample {
    /// Stable client source, formatted by Rust's IP-address implementation.
    #[cfg_attr(not(verus_keep_ghost), serde(serialize_with = "serialize_source"))]
    pub source: Ip,
    /// Monotonic start of the retained per-client history.
    pub since_ns: u64,
    /// Current credits and stored records, including old native incarnations.
    pub current: Occupancy,
    /// High-water flow occupancy in this source's retained history.
    pub peaks: Peaks,
    /// Current distinct ports and shared UDP source sockets.
    pub ports: Ports,
    /// This client's active or stored allowance is currently full.
    pub limit_reached: bool,
    /// Attributed failures in this source's retained history.
    pub rejections: Rejections,
    /// Attributed queue exhaustion in this source's retained history.
    pub queue_drops: QueueDrops,
    /// Native backpressure attempts in this source's retained history.
    pub native_retries: u64,
}

/// Scheduled fixed-schema observations; none of these fields changes readiness.
#[cfg_attr(not(verus_keep_ghost), derive(serde::Serialize))]
pub struct Snapshot {
    /// Current global occupancy, including all sources and old incarnations.
    pub current: Occupancy,
    /// Global high-water marks spanning this boot.
    pub peaks: Peaks,
    /// Current reserved ports and UDP socket mappings.
    pub ports: Ports,
    /// Global active or stored allowance is currently full.
    pub global_limit_reached: bool,
    /// Boot-wide admission totals, retained even after all client history evictions.
    pub rejections: Rejections,
    /// Boot-wide queue exhaustion totals, including internal traffic.
    pub queue_drops: QueueDrops,
    /// Boot-wide native backpressure attempts, including successful requeues.
    pub native_retries: u64,
    /// Actual maintenance and protected-state release progress.
    pub reclamation: Reclamation,
    /// Bounded client histories; empty slots serialize as null.
    pub clients: [Option<ClientSample>; CLIENT_HISTORY],
    /// Number of source histories replaced since this boot.
    pub client_history_evictions: u64,
}

}

/// Console report bound to one firewall boot and the full effective settings.
#[cfg(not(verus_keep_ghost))]
#[derive(serde::Serialize)]
pub struct Report<'a> {
    /// Fixed report schema, separate from the host's lifecycle status schema.
    pub schema: &'a str,
    /// Current protected boot challenge, identifying this admitted incarnation.
    pub boot: &'a str,
    /// Monotonic sample time within the identified boot.
    pub at_ns: u64,
    /// Complete effective versioned parameter identity, without an opaque hash.
    pub settings: &'a crate::parameters::Document,
    /// Compiled global stored-record ceiling; higher settings need another binary.
    pub compiled_record_ceiling: usize,
    /// Compiled stable-client stored-record ceiling.
    pub compiled_client_record_ceiling: usize,
    /// Bounded resource observations captured at the sample time.
    pub resources: Snapshot,
    /// Current live requested allocation bytes; excludes allocator metadata.
    pub heap_requested_bytes: usize,
    /// Peak live requested bytes; not a guarantee about allocatable free space.
    pub heap_peak_requested_bytes: usize,
    /// Entire fixed arena, including metadata and fragmentation overhead.
    pub heap_arena_bytes: usize,
}

/// Format an assigned address with standard-library display; no custom codec.
#[cfg(not(verus_keep_ghost))]
fn serialize_source<S: serde::Serializer>(source: &Ip, serializer: S) -> Result<S::Ok, S::Error> {
    if let Some(bytes) = source.ipv4() {
        serializer.collect_str(&core::net::Ipv4Addr::from(bytes))
    } else if let Some(words) = source.ipv6() {
        serializer.collect_str(&core::net::Ipv6Addr::from(words))
    } else {
        serializer.serialize_str("invalid-source")
    }
}
