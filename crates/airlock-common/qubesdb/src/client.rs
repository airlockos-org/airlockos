//! One native replication lifetime, independent of retained data and key meaning.
//! The consumer handles each owned event before calling step again. No frame is
//! consumed past an unsent acknowledgement. Uncertain I/O, sequencing failure,
//! deadline expiry or identifier exhaustion terminates this owner permanently.

use alloc::vec::Vec;
use vstd::prelude::*;
use vstd::slice::slice_to_vec;

use crate::wire::{self, Decoder};

verus! {

/// Native synchronization state; loss never returns to a usable phase.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// The initial whole-database dump has not reached its terminator.
    Synchronizing,
    /// The dump ended and live replicated mutations may be consumed.
    Ready,
    /// Terminal protocol, clock, I/O or resource failure.
    Failed,
}

/// One bounded protocol action or complete owned replication observation.
pub enum Step {
    /// Supply another private chunk after consuming the previous one.
    Receive,
    /// Publish the exact unpublished request/acknowledgement suffix.
    Send,
    /// One byte was consumed without completing a native record.
    Progress,
    /// One initial key/value; consumers must reject duplicate retained keys.
    Entry {
        /// Exact nonempty native key, without its NUL terminator.
        key: Vec<u8>,
        /// Complete validated native value, including an allowed empty value.
        value: Vec<u8>,
    },
    /// The sole initial dump terminator arrived in stream order.
    Synchronized,
    /// One live mutation; its matching acknowledgement is now queued.
    Changed {
        /// Exact affected key or explicit trailing-slash subtree.
        key: Vec<u8>,
        /// Complete replacement value; empty for removals.
        value: Vec<u8>,
        /// True only for the native removal operation.
        removed: bool,
    },
    /// The outstanding guest WRITE received a matching positive response.
    Written {
        /// Nonreused local write identifier, never proof of durability.
        serial: u32,
        /// Original requested key, matched against the native response.
        key: Vec<u8>,
        /// Original requested value, retained until positive acknowledgement.
        value: Vec<u8>,
    },
    /// Terminal loss; the consumer must invalidate dependent decisions.
    Failed,
}

impl Step {
    /// Every delivered record has complete bounded native bytes; phases and
    /// positive-response correlation are specified by Client::step separately.
    pub closed spec fn valid(&self) -> bool {
        match self {
            Self::Entry { key, value } | Self::Changed { key, value, .. } =>
                0 < key@.len() < 64 && value@.len() <= wire::MAX_VALUE,
            Self::Written { serial, key, value } => *serial > 0 && wire::writable(key@, value@),
            _ => true,
        }
    }
}

/// Exactly one guest WRITE awaiting its native response.
struct Write {
    /// Complete original native path, used to correlate the response.
    key: Vec<u8>,
    /// Complete original body; publication alone cannot commit this value.
    value: Vec<u8>,
    /// Monotonic issue time; partial input/output cannot extend the deadline.
    started: u64,
}

/// Bounded framing, replication sequencing and write-response correlation.
/// Consumers own retained values and key semantics, including any narrower
/// quotas. This owner never resets or replays on the same transport lifetime.
pub struct Client {
    /// Private native record decoder; shared memory is copied before parsing.
    decoder: Decoder,
    /// Initial dump, live replication or terminal failure.
    phase: Phase,
    /// One private ingress chunk; no unconsumed bytes can be overwritten.
    incoming: Vec<u8>,
    /// Next unconsumed byte in the private ingress chunk.
    cursor: usize,
    /// One bounded initial request, mutation ACK or guest WRITE.
    output: Vec<u8>,
    /// Exact prefix actually published by the native transport.
    sent: usize,
    /// Whole initial-dump deadline starts at construction.
    started: u64,
    /// Latest monotonic observation; backwards time is terminal.
    clock: u64,
    /// First byte of an incomplete record, without progress-based extension.
    record_since: Option<u64>,
    /// First publication attempt for the entire current output.
    output_since: u64,
    /// Latest issued guest WRITE; exhaustion fails rather than wrapping.
    serial: u32,
    /// Latest positively acknowledged guest WRITE.
    completed: u32,
    /// Original request bytes retained until their exact native response.
    pending: Option<Write>,
}

impl Client {
    /// Bounded private buffers, truthful publication counts and write ownership.
    pub closed spec fn valid(&self) -> bool {
        self.decoder.valid() && self.cursor <= self.incoming@.len() <= 1024
            && self.sent <= self.output@.len() <= wire::MAX_RECORD
            && self.started <= self.clock && self.output_since <= self.clock
            && self.completed <= self.serial
            && (self.record_since.is_some() ==> self.record_since.unwrap() <= self.clock)
            && (matches!(self.phase, Phase::Failed) ==> self.pending.is_none())
            && match &self.pending {
                None => true,
                Some(write) => matches!(self.phase, Phase::Ready) && self.completed < self.serial
                    && self.serial > 0 && write.started <= self.clock
                    && wire::writable(write.key@, write.value@),
            }
    }

    /// Exact protocol phase, independent of any consumer's publication gates.
    pub closed spec fn phase(&self) -> Phase { self.phase }

    /// Exact unpublished suffix, preserving correspondence through effect adapters.
    pub closed spec fn unpublished(&self) -> Seq<u8> {
        self.output@.subrange(self.sent as int, self.output@.len() as int)
    }

    /// The initial request is selected in full and no byte has been published.
    pub closed spec fn initial_request(&self) -> bool {
        self.output@ == wire::synchronization() && self.sent == 0
    }

    /// Exact most recent monotonic observation, without exposing mutable clocks.
    pub closed spec fn observed_time(&self) -> u64 { self.clock }

    /// All time budgets hold at this exact observation.
    pub closed spec fn within_deadlines(&self, now: u64) -> bool {
        self.clock == now && !matches!(self.phase, Phase::Failed)
            && (matches!(self.phase, Phase::Synchronizing) ==> now-self.started <= 10_000_000_000)
            && (self.record_since.is_some() ==> now-self.record_since.unwrap() <= 2_000_000_000)
            && (self.sent < self.output@.len() ==> now-self.output_since <= 2_000_000_000)
            && (self.pending.is_some() ==> now-self.pending.unwrap().started <= 2_000_000_000)
    }

    /// The exact supplied chunk is retained from its first unconsumed byte.
    pub closed spec fn received(&self, bytes: Seq<u8>) -> bool {
        self.incoming@ == bytes && self.cursor == 0
    }

    /// Native publication advanced by exactly count on the same selected output.
    pub closed spec fn publication(&self, previous: Self, count: usize) -> bool {
        count > 0 && self.sent == previous.sent+count && self.output@ == previous.output@
    }

    /// Every byte of the private ingress chunk has been consumed.
    pub closed spec fn input_drained(&self) -> bool { self.cursor == self.incoming@.len() }

    /// This newer request owns the one response slot, before any publication.
    pub closed spec fn selected(&self, previous: Self, serial: u32) -> bool {
        serial > previous.serial && self.serial == serial && self.pending.is_some() && self.sent == 0
    }

    /// Remaining ability to issue another nonreused local write identifier.
    pub closed spec fn write_available(&self) -> bool {
        matches!(self.phase, Phase::Ready) && self.pending.is_none() && self.serial < u32::MAX
            && self.sent == self.output@.len() && self.decoder.prefix().len() == 0
    }

    /// Complete-record input/output drain; an outstanding WRITE may still await
    /// its response. Consumers separately check write availability when issuing.
    pub closed spec fn drained(&self) -> bool {
        matches!(self.phase, Phase::Ready) && self.cursor == self.incoming@.len()
            && self.sent == self.output@.len() && self.decoder.prefix().len() == 0
    }

    /// Exact latest positive write response, without subsequent issue or failure.
    pub closed spec fn write_completed(&self, serial: u32) -> bool {
        matches!(self.phase, Phase::Ready) && self.pending.is_none()
            && serial > 0 && self.completed == serial && self.serial == serial
    }

    /// Start a fresh connection with exactly the initial empty MULTIREAD.
    pub fn synchronizing_at(now: u64) -> (client: Self)
        ensures client.valid(), client.phase() == Phase::Synchronizing,
            client.initial_request(),
    {
        Self { decoder: Decoder::fresh(), phase: Phase::Synchronizing,
            incoming: Vec::new(), cursor: 0, output: slice_to_vec(&wire::synchronize()), sent: 0,
            started: now, clock: now, record_since: None, output_since: now,
            serial: 0, completed: 0, pending: None }
    }

    /// Observe protocol state without exposing a way to revive the connection.
    pub fn state(&self) -> (phase: Phase)
        requires self.valid(), ensures phase == self.phase(),
    { self.phase }

    /// Terminate the original stream and relinquish pending response ownership.
    pub fn disconnect(&mut self)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).phase() == Phase::Failed,
    { self.phase = Phase::Failed; self.pending = None; }

    /// Enforce whole-sync (10 seconds), partial-record, output and guest-WRITE
    /// deadlines (2 seconds each). The adapter must check before I/O or use of
    /// retained data. Scheduling fairness and the real clock remain assumptions.
    pub fn tick(&mut self, now: u64) -> (live: bool)
        requires old(self).valid(),
        ensures final(self).valid(),
            live ==> final(self).within_deadlines(now) && now >= old(self).observed_time()
                && final(self).phase() == old(self).phase(),
            !live ==> final(self).phase() == Phase::Failed,
    {
        if matches!(self.phase, Phase::Failed) || now < self.clock { self.disconnect(); return false; }
        self.clock = now;
        if matches!(self.phase, Phase::Synchronizing) && now-self.started > 10_000_000_000
            || self.sent < self.output.len() && now-self.output_since > 2_000_000_000 {
            self.disconnect(); return false;
        }
        match self.record_since {
            Some(started) if now-started > 2_000_000_000 => { self.disconnect(); return false; }
            _ => (),
        }
        match &self.pending {
            Some(write) if now-write.started > 2_000_000_000 => { self.disconnect(); return false; }
            _ => (),
        }
        true
    }

    /// Retain the next exact bounded ingress chunk only after the prior one
    /// was consumed. Invalid caller sequencing is terminal, without data loss.
    pub fn deliver(&mut self, bytes: &[u8]) -> (accepted: bool)
        requires old(self).valid(),
        ensures final(self).valid(), accepted ==> final(self).received(bytes@)
            && final(self).phase() == old(self).phase(),
            !accepted ==> final(self).phase() == Phase::Failed,
    {
        if matches!(self.phase, Phase::Failed) || self.cursor != self.incoming.len()
            || bytes.is_empty() || bytes.len() > 1024 { self.disconnect(); return false; }
        self.incoming = slice_to_vec(bytes);
        self.cursor = 0;
        true
    }

    /// Borrow only the unpublished suffix of the exact selected output bytes.
    pub fn outgoing(&self) -> (bytes: &[u8])
        requires self.valid(),
        ensures bytes@ == self.unpublished(),
            bytes@.len() <= wire::MAX_RECORD,
    { &self.output[self.sent..] }

    /// Advance by the native transport's actual positive publication count.
    /// Impossible counts are terminal; zero backpressure should not call this.
    pub fn published(&mut self, count: usize) -> (accepted: bool)
        requires old(self).valid(),
        ensures final(self).valid(),
            accepted ==> final(self).publication(*old(self), count)
                && final(self).phase() == old(self).phase(),
            !accepted ==> final(self).phase() == Phase::Failed,
    {
        if matches!(self.phase, Phase::Failed) || count == 0 || count > self.output.len()-self.sent {
            self.disconnect(); return false;
        }
        self.sent += count;
        true
    }

    /// Process at most one byte and return each complete mutation in order.
    /// The caller must apply an event, or terminate on storage/semantic failure,
    /// before stepping again. ACK backpressure prevents reading ahead past it.
    pub fn step(&mut self) -> (step: Step)
        requires old(self).valid(),
        ensures final(self).valid(), step.valid(), step is Failed ==> final(self).phase() == Phase::Failed,
            old(self).phase() == Phase::Failed ==> step is Failed,
            step is Send ==> final(self).unpublished().len() > 0,
            step is Receive ==> final(self).input_drained(),
            step is Entry ==> old(self).phase() == Phase::Synchronizing,
            step is Synchronized ==> old(self).phase() == Phase::Synchronizing && final(self).phase() == Phase::Ready,
            step is Changed ==> old(self).phase() == Phase::Ready,
            step is Written ==> final(self).write_completed(step->Written_serial),
    {
        if matches!(self.phase, Phase::Failed) { return Step::Failed; }
        if self.sent < self.output.len() { return Step::Send; }
        if self.cursor == self.incoming.len() { return Step::Receive; }
        if self.record_since.is_none() { self.record_since = Some(self.clock); }
        let byte = self.incoming[self.cursor];
        self.cursor += 1;
        let message = match self.decoder.push(byte) {
            Ok(Some(value)) => value,
            Ok(None) => return Step::Progress,
            Err(_) => { self.disconnect(); return Step::Failed; }
        };
        self.record_since = None;
        let (header, value) = message.into_parts();
        let operation = header.operation();
        let key = header.key();
        if operation == wire::ENTRY && matches!(self.phase, Phase::Synchronizing) {
            if key.is_empty() { self.phase = Phase::Ready; return Step::Synchronized; }
            return Step::Entry { key: slice_to_vec(key), value };
        }
        if matches!(self.phase, Phase::Ready) && (operation == wire::WRITE || operation == wire::REMOVE) {
            self.output = slice_to_vec(&header.acknowledge());
            self.sent = 0;
            self.output_since = self.clock;
            return Step::Changed { key: slice_to_vec(key), value, removed: operation == wire::REMOVE };
        }
        if matches!(self.phase, Phase::Ready) && operation == wire::OK {
            let pending = self.pending.take();
            match pending {
                Some(write) if key == write.key.as_slice() => {
                    self.completed = self.serial;
                    return Step::Written { serial: self.serial, key: write.key, value: write.value };
                }
                _ => (),
            }
        }
        self.disconnect();
        Step::Failed
    }

    /// Issue exactly one bounded native WRITE, with no key-specific semantics.
    /// A complete-record boundary is required; unread buffered records may remain
    /// and must precede the eventual matching response. The caller may require
    /// the stronger between_records observation before selecting its request.
    pub fn write(&mut self, key: &[u8], value: &[u8]) -> (serial: Option<u32>)
        requires old(self).valid(),
        ensures final(self).valid(),
            serial.is_some() == (old(self).write_available() && wire::writable(key@, value@)),
            serial.is_some() ==> final(self).selected(*old(self), serial.unwrap())
                && final(self).phase() == old(self).phase(),
    {
        if self.serial == u32::MAX { self.disconnect(); return None; }
        if !matches!(self.phase, Phase::Ready) || self.pending.is_some()
            || self.sent != self.output.len() || self.decoder.buffered() != 0
            || !wire::writeable(key, value) { return None; }
        self.output = wire::guest_write(key, value);
        self.sent = 0;
        self.output_since = self.clock;
        self.serial += 1;
        self.pending = Some(Write { key: slice_to_vec(key), value: slice_to_vec(value), started: self.clock });
        Some(self.serial)
    }

    /// Observe request availability without selecting a key or publishing bytes.
    pub fn available(&self) -> (available: bool)
        requires self.valid(), ensures available == self.write_available(),
    {
        matches!(self.phase, Phase::Ready) && self.pending.is_none() && self.serial < u32::MAX
            && self.sent == self.output.len() && self.decoder.buffered() == 0
    }

    /// Observe a complete-record input/output drain without consuming an event.
    pub fn between_records(&self) -> (idle: bool)
        requires self.valid(), ensures idle == self.drained(),
    {
        matches!(self.phase, Phase::Ready) && self.cursor == self.incoming.len()
            && self.sent == self.output.len() && self.decoder.buffered() == 0
    }

    /// Confirm this exact latest WRITE received its native positive response.
    pub fn completed(&self, serial: u32) -> (completed: bool)
        requires self.valid(), ensures completed == self.write_completed(serial),
    { matches!(self.phase, Phase::Ready) && self.pending.is_none() && serial > 0 && self.completed == serial && self.serial == serial }
}

}
