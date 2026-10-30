//! Bounded native stream pump. Deterministic framing, input retention, ACK
//! backpressure and publication transitions execute here; the platform adapter
//! only copies bytes to/from its actually owned dom0 libvchan. There is exactly
//! one outstanding ACK and one 1024-byte private ingress buffer. Input cannot
//! advance past an unsent ACK, and a lost/invalid stream is terminal.

use alloc::vec::Vec;
use vstd::prelude::*;

use crate::bytes::{append, copy};
use crate::database::{Phase, Replica, Update};
use crate::number;
use crate::policy::Path;
use crate::projection::View;
use crate::wire::{self, Decoder};

verus! {

/// One bounded pump action. Send and Receive refer only to the owner's existing
/// stream; these decisions never select a peer or grant interface authority.
pub enum Step {
    /// The entire private ingress was consumed; copy another bounded chunk.
    Receive,
    /// Publish the remaining prefix of the one exact native request/ACK.
    Send,
    /// One byte was consumed without a completed application event.
    Progress,
    /// Native initial synchronization completed; source roots remain blocked.
    Synchronized,
    /// A live native mutation was applied and acknowledged locally.
    Changed {
        /// Exact changed native key for local diagnostics, not an authority claim.
        key: Vec<u8>,
    },
    /// Terminal control loss; no cached source can be used for a new operation.
    Failed,
    /// Native handled-counter ACK completed this exact local FIFO barrier.
    Barrier {
        /// Nonreused local request label, bound by the adapter to one interface.
        serial: u32,
    },
}

/// Deterministic state belonging to exactly one fresh native transport lifetime.
/// A separate instance is not authority to reconnect or replay an uncertain write.
pub struct Control {
    /// Complete-record framing with private bounded partial bytes.
    decoder: Decoder,
    /// Native initial/live replication lifecycle and exact observed database.
    replica: Replica,
    /// Complete addressing, source completion gates and policy generations.
    view: View,
    /// One private chunk; the platform may supply no more than this capacity.
    incoming: Vec<u8>,
    /// Next unconsumed byte; no bytes after a pending ACK are parsed early.
    cursor: usize,
    /// Exact initial MULTIREAD or the one live mutation ACK being published.
    output: Vec<u8>,
    /// Confirmed published prefix, advanced only by the transport's actual count.
    sent: usize,
    /// Monotonic time at creation; bounds the whole initial dump, not each byte.
    started: u64,
    /// Last monotonic observation; a backwards clock closes the stream.
    clock: u64,
    /// First byte time of the current partial record, never refreshed by dribbling.
    record_since: Option<u64>,
    /// First publication time for this entire request/ACK, not its last byte.
    output_since: u64,
    /// Last issued FIFO barrier label; exhaustion terminates instead of wrapping.
    serial: u32,
    /// Last positively acknowledged barrier, never advanced on publication alone.
    completed: u32,
    /// Exact label awaiting its native handled-counter response.
    awaiting: Option<u32>,
    /// Whole guest-write barrier deadline, independent of incoming progress.
    barrier_since: Option<u64>,
}

impl Control {
    /// Independently valid components, including during a composed transition.
    closed spec fn parts_valid(&self) -> bool {
        self.decoder.valid() && self.replica.valid() && self.view.valid()
            && self.cursor <= self.incoming@.len() <= 1024 && self.sent <= self.output@.len() <= wire::HEADER+10
            && self.output_since <= self.clock && self.started <= self.clock && self.completed <= self.serial
            && (self.record_since.is_some() ==> self.record_since.unwrap() <= self.clock)
            && (self.barrier_since.is_some() ==> self.barrier_since.unwrap() <= self.clock)
    }

    /// Bounded private buffers and valid independently owned protocol machines.
    pub closed spec fn valid(&self) -> bool {
        self.parts_valid()
            && self.awaiting.is_some() == self.replica.pending()
            && self.awaiting.is_some() == self.barrier_since.is_some()
            && (self.awaiting.is_some() ==> 0 < self.awaiting.unwrap() <= self.serial)
            && (self.replica.phase() == Phase::Failed ==> self.view.phase() == crate::projection::Phase::Lost)
    }

    /// Exact retained source/configuration data, never runtime transport authority.
    pub closed spec fn view(&self) -> View { self.view }

    /// Begin a fresh native stream with exactly the initial empty MULTIREAD.
    pub fn synchronizing_at(now: u64) -> (control: Self)
        ensures control.valid(), control.replica.phase() == Phase::Synchronizing,
            control.view().phase() == crate::projection::Phase::Synchronizing,
            control.output@ == wire::synchronization(), control.sent == 0,
    {
        Self { decoder: Decoder::fresh(), replica: Replica::synchronizing(), view: View::synchronizing(),
            incoming: Vec::new(), cursor: 0, output: copy(&wire::synchronize()), sent: 0,
            started: now, clock: now, record_since: None, output_since: now,
            serial: 0, completed: 0, awaiting: None, barrier_since: None }
    }

    /// Terminal stream loss. Clear operational gates before exposing the failure;
    /// retained byte buffers are bounded and cannot be reinterpreted on reconnect.
    pub fn disconnect(&mut self)
        requires old(self).parts_valid(),
        ensures final(self).valid(), final(self).replica.phase() == Phase::Failed,
            final(self).view().phase() == crate::projection::Phase::Lost,
    {
        self.replica.disconnect();
        self.view.disconnect();
        self.awaiting = None;
        self.barrier_since = None;
    }

    /// Enforce whole-sync and per-record deadlines using a runtime monotonic
    /// nanosecond observation. Partial progress cannot extend either deadline.
    /// The adapter must poll this before I/O or interface admission; scheduling
    /// fairness and the clock's correspondence remain environmental obligations.
    pub fn tick(&mut self, now: u64) -> (live: bool)
        requires old(self).valid(),
        ensures final(self).valid(),
            live ==> final(self).clock == now && now >= old(self).clock
                && final(self).replica.phase() != Phase::Failed
                && (final(self).replica.phase() == Phase::Synchronizing ==> now-final(self).started <= 10_000_000_000)
                && (final(self).record_since.is_some() ==> now-final(self).record_since.unwrap() <= 2_000_000_000),
            !live ==> final(self).replica.phase() == Phase::Failed,
    {
        if self.replica.state() == Phase::Failed || now < self.clock {
            self.disconnect(); return false;
        }
        self.clock = now;
        if self.replica.state() == Phase::Synchronizing && now-self.started > 10_000_000_000 {
            self.disconnect(); return false;
        }
        if let Some(started) = self.record_since
            && now-started > 2_000_000_000 { self.disconnect(); return false; }
        if self.sent < self.output.len() && now-self.output_since > 2_000_000_000 {
            self.disconnect(); return false;
        }
        if let Some(started) = self.barrier_since
            && now-started > 2_000_000_000 { self.disconnect(); return false; }
        true
    }

    /// Supply a private bounded chunk only after the prior one was consumed.
    /// Invalid caller sequencing terminates the stream instead of losing bytes.
    pub fn deliver(&mut self, bytes: &[u8]) -> (accepted: bool)
        requires old(self).valid(),
        ensures final(self).valid(),
            accepted ==> final(self).incoming@ == bytes@ && final(self).cursor == 0,
            !accepted ==> final(self).replica.phase() == Phase::Failed,
    {
        if self.replica.state() == Phase::Failed || self.cursor != self.incoming.len()
            || bytes.is_empty() || bytes.len() > 1024 {
            self.disconnect(); return false;
        }
        self.incoming = copy(bytes);
        self.cursor = 0;
        true
    }

    /// Borrow precisely the unpublished suffix. Nothing permits an adapter to
    /// substitute reconstructed bytes or acknowledge publication without I/O.
    pub fn outgoing(&self) -> (bytes: &[u8])
        requires self.valid(),
        ensures bytes@ == self.output@.subrange(self.sent as int, self.output@.len() as int),
            bytes@.len() <= wire::HEADER+10,
    { &self.output[self.sent..] }

    /// Commit the transport's actual positive write count. Zero is backpressure
    /// and should not call this method; impossible counts terminate the stream.
    pub fn published(&mut self, count: usize) -> (accepted: bool)
        requires old(self).valid(),
        ensures final(self).valid(),
            accepted ==> count > 0 && final(self).sent == old(self).sent+count
                && final(self).output@ == old(self).output@,
            !accepted ==> final(self).replica.phase() == Phase::Failed,
    {
        if self.replica.state() == Phase::Failed || count == 0 || count > self.output.len()-self.sent {
            self.disconnect(); return false;
        }
        self.sent += count;
        true
    }

    /// Take at most one byte step. All finite loops are inside bounded parser
    /// operations. The owner schedules at most 1024 steps per turn and must poll
    /// native connection liveness before permitting a new interface operation.
    pub fn step(&mut self) -> (step: Step)
        requires old(self).valid(),
        ensures final(self).valid(),
            step is Failed ==> final(self).replica.phase() == Phase::Failed,
            old(self).replica.phase() == Phase::Failed ==> step is Failed,
            step is Send ==> final(self).sent < final(self).output@.len(),
            step is Receive ==> final(self).cursor == final(self).incoming@.len(),
    {
        if self.replica.state() == Phase::Failed { return Step::Failed; }
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
        match self.replica.apply(message) {
            Ok(Update::None) => Step::Progress,
            Ok(Update::Initial) => {
                let cache = match self.replica.current() { Some(value) => value, None => { self.disconnect(); return Step::Failed; } };
                if !self.view.synchronized(cache) { self.disconnect(); return Step::Failed; }
                Step::Synchronized
            }
            Ok(Update::Changed { key, removed, acknowledgement }) => {
                let cache = match self.replica.current() { Some(value) => value, None => { self.disconnect(); return Step::Failed; } };
                if !self.view.changed(cache, key.as_slice(), removed) { self.disconnect(); return Step::Failed; }
                self.output = copy(&acknowledgement);
                self.sent = 0;
                self.output_since = self.clock;
                Step::Changed { key }
            }
            Ok(Update::Barrier) => {
                let serial = match self.awaiting { Some(value) => value, None => { self.disconnect(); return Step::Failed; } };
                self.awaiting = None;
                self.barrier_since = None;
                self.completed = serial;
                Step::Barrier { serial }
            }
            Err(_) => { self.disconnect(); Step::Failed }
        }
    }

    /// Native handled path preserves the original source spelling and ABI bound.
    pub closed spec fn counter_path(root: Seq<u8>) -> Seq<u8> {
        b"/qubes-firewall-handled/"@ + root.subrange(16, root.len() as int)
    }

    /// Useful request domain: an idle synchronized stream and one valid native
    /// source root whose next handled counter fits both protocol and u32 bounds.
    /// This is an input/output contract; no peer processing is assumed here.
    pub closed spec fn can_barrier(&self, root: Seq<u8>) -> bool {
        self.replica.phase() == Phase::Ready && self.awaiting.is_none()
            && self.cursor == self.incoming@.len() && self.sent == self.output@.len()
            && self.serial < u32::MAX && Self::counter_path(root).len() < 64
            && (exists|ip: crate::address::Ip| crate::policy::source_path(root, ip, root.len() as int))
            && (crate::config::absent(self.replica.cache(), Self::counter_path(root))
                || exists|bytes: Seq<u8>| crate::config::observed(self.replica.cache(), Self::counter_path(root), bytes)
                    && number::digits(bytes, true) && number::decimal(bytes) < u32::MAX)
    }

    /// Queue the existing native handled-counter WRITE as a FIFO read barrier
    /// for an actually observed interface. The pinned daemon permits only one
    /// MULTIREAD, so another dump is not a legal barrier. A matching native OK
    /// arrives after earlier replicated writes in this same vchan stream.
    ///
    /// The adapter captures the connected lease first and waits for this exact
    /// serial before checking current eligibility again. It may not interpret
    /// publication itself or another source's counter as barrier completion.
    pub fn barrier(&mut self, root: &[u8]) -> (serial: Option<u32>)
        requires old(self).valid(), root@.len() < 64,
        ensures final(self).valid(), serial.is_some() == old(self).can_barrier(root@),
            serial.is_some() ==> final(self).awaiting == serial && final(self).serial == serial.unwrap()
                && serial.unwrap() > old(self).serial && final(self).sent == 0,
    {
        if self.replica.state() != Phase::Ready || self.awaiting.is_some()
            || self.cursor != self.incoming.len() || self.sent != self.output.len() { return None; }
        let source = Path::parse(root)?;
        if !source.is_root(root) { return None; }
        let mut path = copy(b"/qubes-firewall-handled/");
        if path.len()+root.len()-16 >= 64 { return None; }
        append(&mut path, &root[16..]);
        let cache = self.replica.current()?;
        let previous = match cache.read(path.as_slice()) {
            None => 0,
            Some(bytes) => match number::parse(bytes, u32::MAX, true) {
                Some(value) => value,
                None => { self.disconnect(); return None; }
            },
        };
        if previous == u32::MAX || self.serial == u32::MAX { self.disconnect(); return None; }
        let value = number::encode(previous+1);
        let output = wire::counter(path.as_slice(), value.as_slice());
        if !self.replica.barrier(path, value) { self.disconnect(); return None; }
        self.serial += 1;
        self.awaiting = Some(self.serial);
        self.barrier_since = Some(self.clock);
        self.output = output;
        self.sent = 0;
        self.output_since = self.clock;
        Some(self.serial)
    }

    /// Exact positive-response predicate, separate from an issued request label.
    pub closed spec fn barrier_completed(&self, serial: u32) -> bool {
        self.replica.phase() == Phase::Ready && self.awaiting.is_none()
            && serial > 0 && self.completed == serial && self.serial == serial
    }

    /// The private ingress and outgoing ACK are drained at a complete-record
    /// boundary. A runtime may check native input without consuming an event;
    /// newly copied bytes must return through the ordinary pump before data I/O.
    pub fn between_records(&self) -> (idle: bool)
        requires self.valid(),
        ensures idle == (self.replica.phase() == Phase::Ready && self.cursor == self.incoming@.len()
            && self.sent == self.output@.len() && self.decoder.prefix().len() == 0),
    {
        self.replica.state() == Phase::Ready && self.cursor == self.incoming.len()
            && self.sent == self.output.len() && self.decoder.buffered() == 0
    }

    /// Confirm this exact latest barrier received its positive native response.
    /// A pending request, old label, failed connection or publication count is
    /// insufficient evidence. The runtime additionally checks connection/lease.
    pub fn completed(&self, serial: u32) -> (completed: bool)
        requires self.valid(),
        ensures completed == self.barrier_completed(serial),
    {
        self.replica.state() == Phase::Ready && self.awaiting.is_none()
            && serial > 0 && self.completed == serial && self.serial == serial
    }

    /// Borrow complete currently usable data. It stays tied to this pump's
    /// immutable borrow, so a later stream event cannot replace it mid-operation.
    pub fn projection(&self) -> (view: &View)
        requires self.valid(), ensures *view == self.view(), view.valid(),
    { &self.view }
}

}
