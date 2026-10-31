//! Compose the native QubesDB client with the network consumer's retained values
//! and publication gates. The database client selects no network paths or quotas.
//! This layer interprets its ordered events, owns the current-boot policy refresh
//! notice and issues handled-counter writes when binding an actual interface.

use airlock_boot_core::Challenge;
#[cfg(verus_keep_ghost)]
use airlock_boot_core::challenge_bytes;
#[cfg(verus_keep_ghost)]
use airlock_qubesdb::client::Phase;
use airlock_qubesdb::client::{Client, Step as DatabaseStep};
use alloc::vec::Vec;
use vstd::prelude::*;
use vstd::slice::slice_to_vec;
#[cfg(verus_keep_ghost)]
use vstd::view::View as ValueView;

use crate::cache::Cache;
use crate::number;
use crate::policy::Path;
use crate::projection::View;
#[cfg(verus_keep_ghost)]
use crate::wire;

verus! {

broadcast use { vstd::seq::Seq::lemma_as_ref_index, crate::address::cut_unique };

/// Network-facing scheduling result. Initial entries are retained internally;
/// native synchronization is exposed only after the current-boot notice ACK.
pub enum Step {
    /// Supply another bounded private native input chunk.
    Receive,
    /// Publish the database client's exact remaining output suffix.
    Send,
    /// One bounded protocol/cache step completed without a network event.
    Progress,
    /// Initial synchronization and the current-boot notice ACK completed.
    /// Source roots remain blocked until fresh policy completion markers arrive.
    Synchronized,
    /// A live mutation reached the retained cache and policy projection.
    Changed {
        /// Exact changed key for diagnostics, never an interface identity claim.
        key: Vec<u8>,
    },
    /// Terminal protocol, storage or publication failure; all sources are blocked.
    Failed,
    /// This exact handled-counter WRITE received its native positive response.
    Barrier {
        /// Nonreused database request label bound to an interface observation.
        serial: u32,
    },
}

/// Current-boot refresh handoff, distinct from native database synchronization.
pub enum Startup {
    /// Initial entries are still arriving; no source root may activate.
    Waiting(/// Original deployment challenge, without network authority.
        Challenge),
    /// The dump ended and this boot's notice awaits its exact native ACK.
    Announcing(/// Nonreused native WRITE identifier for the boot notice.
        u32),
    /// The host was notified; each source still needs fresh completed policy.
    Ready,
    /// Terminal loss; a later event cannot revive this owner.
    Lost,
}

/// One network control lifetime composed around one native replication client.
/// Retained data and policy decisions never escape as transport authority.
pub struct Control {
    /// Generic framing, sequencing, output backpressure and response ownership.
    native: Client,
    /// Network-owned records and bounded per-source quota rejections.
    cache: Cache,
    /// Addressing, per-source completion gates and current policy generations.
    view: View,
    /// Current-boot host policy-refresh handoff or terminal loss.
    startup: Startup,
}

/// An absent counter starts at one; a present canonical counter must not wrap.
closed spec fn counter_available(cache: Cache, key: Seq<u8>) -> bool {
    crate::config::absent(cache, key) || exists|bytes: Seq<u8>| crate::config::observed(cache, key, bytes)
        && number::digits(bytes, true) && number::decimal(bytes) < u32::MAX
}

/// Read and increment the standard handled counter using the shared numeric
/// adapter. The caller owns terminal disconnection if the counter is invalid.
fn next_counter(cache: &Cache, key: &[u8]) -> (next: Option<Vec<u8>>)
    requires cache.valid(), key@.len() < 64,
    ensures next.is_some() == counter_available(*cache, key@),
        match next {
            Some(value) => number::digits(value@, true) && number::decimal(value@) <= u32::MAX
                && (crate::config::absent(*cache, key@) ==> number::decimal(value@) == 1)
                && (forall|bytes: Seq<u8>| crate::config::observed(*cache, key@, bytes)
                    ==> number::decimal(value@) == number::decimal(bytes)+1),
            None => true,
        },
{
    let previous = match cache.read(key) {
        None => 0,
        Some(bytes) => number::parse(bytes, u32::MAX, true)?,
    };
    if previous == u32::MAX { return None; }
    Some(number::encode(previous+1))
}

impl Control {
    /// Exact current-boot synchronization handoff state.
    pub closed spec fn startup(&self) -> Startup { self.startup }

    /// Exact native output suffix selected for the transport.
    pub closed spec fn unpublished(&self) -> Seq<u8> { self.native.unpublished() }

    /// The boot handoff completed and native input/output is drained.
    pub closed spec fn drained(&self) -> bool { self.startup is Ready && self.native.drained() }

    /// Independent invariants remain available during a composed transition.
    pub closed spec fn parts_valid(&self) -> bool {
        self.native.valid() && self.cache.valid() && self.view.valid()
            && match self.startup {
                Startup::Waiting(challenge) => challenge_bytes(challenge.value()),
                Startup::Announcing(serial) => serial > 0,
                _ => true,
            }
    }

    /// Protocol phase and network publication gates agree at API boundaries.
    pub closed spec fn valid(&self) -> bool {
        self.parts_valid() && match self.startup {
            Startup::Waiting(_) => self.native.phase() == Phase::Synchronizing
                && self.view.phase() == crate::projection::Phase::Synchronizing,
            Startup::Announcing(serial) => self.native.phase() == Phase::Ready
                && self.native.request().is_some() && self.native.request().unwrap().0 == serial
                && self.view.phase() == crate::projection::Phase::Synchronized,
            Startup::Ready => self.native.phase() == Phase::Ready
                && self.view.phase() == crate::projection::Phase::Synchronized,
            Startup::Lost => self.native.phase() == Phase::Failed
                && self.view.phase() == crate::projection::Phase::Lost,
        }
    }

    /// Exact network projection, separate from native connection ownership.
    pub closed spec fn view(&self) -> View { self.view }

    /// The next complete input is the initial empty ENTRY terminator, after
    /// output backpressure has been satisfied on this same native connection.
    pub closed spec fn completing_dump(&self) -> bool {
        self.startup is Waiting && self.native.input_available()
            && wire::complete_record(self.native.next_record())
            && self.native.next_record()[0] == wire::ENTRY && wire::path_at(self.native.next_record(), 0)
    }

    /// The next ordered record positively acknowledges this boot's notice and
    /// there is sufficient cache headroom to retain its exact original bytes.
    pub closed spec fn completing_notice(&self) -> bool {
        self.startup is Announcing && self.native.input_available() && self.native.request().is_some()
            && self.native.request().unwrap().0 == self.startup->Announcing_0
            && wire::complete_record(self.native.next_record()) && self.native.next_record()[0] == wire::OK
            && self.native.next_key(self.native.request().unwrap().1)
            && self.cache.can_retain(self.native.request().unwrap().1, self.native.request().unwrap().2, true)
    }

    /// Start a native dump with this boot's challenge retained for its later
    /// synchronization notice. Neither initial roots nor publication alone
    /// authorize an interface; fresh source policies and a binding are required.
    pub fn synchronizing_at(now: u64, challenge: Challenge) -> (control: Self)
        requires challenge_bytes(challenge.value()),
        ensures control.valid(), control.startup() is Waiting,
            control.view().phase() == crate::projection::Phase::Synchronizing,
    {
        Self { native: Client::synchronizing_at(now), cache: Cache::empty(),
            view: View::synchronizing(), startup: Startup::Waiting(challenge) }
    }

    /// Terminate native control and revoke all network publication gates first.
    /// Retained bytes remain bounded diagnostics and cannot be replayed.
    pub fn disconnect(&mut self)
        requires old(self).parts_valid(),
        ensures final(self).valid(), final(self).startup() is Lost,
            final(self).view().phase() == crate::projection::Phase::Lost,
    {
        self.native.disconnect();
        self.view.disconnect();
        self.startup = Startup::Lost;
    }

    /// Check the generic client's monotonic deadlines before I/O or admission.
    /// Any failure revokes the network projection before returning to the owner.
    pub fn tick(&mut self, now: u64) -> (live: bool)
        requires old(self).valid(),
        ensures final(self).valid(), !live ==> final(self).startup() is Lost,
            live ==> final(self).view().phase() == old(self).view().phase()
                && final(self).view().revision() >= old(self).view().revision() && final(self).startup() == old(self).startup(),
    {
        if !self.native.tick(now) || !self.view.expire(now) { self.disconnect(); return false; }
        true
    }

    /// Supply the native client's next exact chunk; invalid sequencing revokes
    /// every network gate rather than overwriting unconsumed control data.
    pub fn deliver(&mut self, bytes: &[u8]) -> (accepted: bool)
        requires old(self).valid(),
        ensures final(self).valid(), !accepted ==> final(self).startup() is Lost,
    {
        if !self.native.deliver(bytes) { self.disconnect(); return false; }
        true
    }

    /// Preserve exact database output bytes through the network effect adapter.
    pub fn outgoing(&self) -> (bytes: &[u8])
        requires self.valid(),
        ensures bytes@ == self.unpublished(), bytes@.len() <= wire::MAX_RECORD,
    { self.native.outgoing() }

    /// Record the actual positive transport count; publication is never a native
    /// response or permission to commit a boot notice/handled counter locally.
    pub fn published(&mut self, count: usize) -> (accepted: bool)
        requires old(self).valid(),
        ensures final(self).valid(), !accepted ==> final(self).startup() is Lost,
    {
        if !self.native.published(count) { self.disconnect(); return false; }
        true
    }

    /// Apply one ordered protocol event before another may be consumed. The
    /// retained cache rejects duplicates and enforces network source quotas;
    /// the projection alone decides when a complete policy can become usable.
    pub fn step(&mut self) -> (step: Step)
        requires old(self).valid(),
        ensures final(self).valid(), step is Failed ==> final(self).startup() is Lost,
            old(self).startup() is Lost ==> step is Failed,
            step is Synchronized ==> final(self).startup() is Ready,
            old(self).completing_dump() ==> final(self).startup() is Announcing,
            old(self).completing_notice() ==> step is Synchronized && final(self).startup() is Ready,
            step is Barrier ==> final(self).barrier_completed(step->Barrier_serial),
    {
        match self.native.step() {
            DatabaseStep::Receive => Step::Receive,
            DatabaseStep::Send => Step::Send,
            DatabaseStep::Progress => Step::Progress,
            DatabaseStep::Entry { key, value } => {
                if !self.cache.put(key, value, false) { self.disconnect(); return Step::Failed; }
                Step::Progress
            }
            DatabaseStep::Synchronized => {
                if !self.view.synchronized(&self.cache) { self.disconnect(); return Step::Failed; }
                // An initial dump may retain an old root during an unfinished
                // rewrite. Ask the existing host writer for fresh completions.
                let challenge = match &self.startup {
                    Startup::Waiting(challenge) => challenge,
                    _ => { self.disconnect(); return Step::Failed; }
                };
                let key = crate::READY_PATH.as_bytes();
                let value = challenge.as_bytes();
                proof {
                    reveal_strlit("/airlock-network-control-ready");
                    assert(vstd::string::is_ascii(crate::READY_PATH));
                    vstd::string::is_ascii_spec_bytes(crate::READY_PATH);
                    assert(wire::writable(key@, value@));
                }
                let serial = match self.native.write(key, value) {
                    Some(serial) => serial,
                    None => { self.disconnect(); return Step::Failed; }
                };
                self.startup = Startup::Announcing(serial);
                Step::Progress
            }
            DatabaseStep::Changed { key, value, removed } => {
                if removed {
                    let discarded = self.cache.discarded_remove(key.as_slice());
                    if self.cache.remove(key.as_slice()) == 0 && !discarded { self.disconnect(); return Step::Failed; }
                } else if !self.cache.put(slice_to_vec(key.as_slice()), value, true) { self.disconnect(); return Step::Failed; }
                if !self.view.changed(&self.cache, key.as_slice(), removed) { self.disconnect(); return Step::Failed; }
                Step::Changed { key }
            }
            DatabaseStep::Written { serial, key, value } => {
                if !self.cache.put(key, value, true) { self.disconnect(); return Step::Failed; }
                match self.startup {
                    Startup::Announcing(expected) if expected == serial => {
                        self.startup = Startup::Ready;
                        Step::Synchronized
                    }
                    Startup::Ready => Step::Barrier { serial },
                    _ => { self.disconnect(); Step::Failed }
                }
            }
            DatabaseStep::Failed => { self.disconnect(); Step::Failed }
        }
    }

    /// Preserve the source's original spelling when constructing its handled key.
    pub closed spec fn counter_path(root: Seq<u8>) -> Seq<u8> {
        b"/qubes-firewall-handled/"@ + root.subrange(16, root.len() as int)
    }

    /// Useful request domain: the boot handoff completed, native input/output
    /// drained, and this exact source's next counter fits the existing ABI.
    pub closed spec fn can_barrier(&self, root: Seq<u8>) -> bool {
        self.startup is Ready && self.native.drained() && self.native.write_available()
            && Self::counter_path(root).len() < 64
            && (exists|ip: crate::address::Ip| crate::policy::source_path(root, ip, root.len() as int))
            && counter_available(self.cache, Self::counter_path(root))
    }

    /// Issue the existing handled-counter WRITE after observing an actual lease.
    /// Its matching native ACK orders earlier dom0 writes; a second MULTIREAD
    /// is forbidden by the upstream daemon and is never used as a barrier.
    pub fn barrier(&mut self, root: &[u8]) -> (serial: Option<u32>)
        requires old(self).valid(), root@.len() < 64,
        ensures final(self).valid(), serial.is_some() == old(self).can_barrier(root@),
            serial.is_some() ==> serial.unwrap() > 0 && final(self).view() == old(self).view(),
    {
        if !matches!(self.startup, Startup::Ready) || !self.native.between_records() || !self.native.available() { return None; }
        let source = Path::parse(root)?;
        if !source.is_root(root) { return None; }
        let mut path = slice_to_vec(b"/qubes-firewall-handled/");
        if path.len()+root.len()-16 >= 64 { return None; }
        path.extend_from_slice(&root[16..]);
        proof { assert(path@ =~= Self::counter_path(root@)); }
        let value = match next_counter(&self.cache, path.as_slice()) {
            Some(value) => value,
            None => { self.disconnect(); return None; }
        };
        proof {
            reveal(crate::address::Ip::describes);
            let prefix = b"/qubes-firewall-handled/"@;
            reveal_byteslit(b"/qubes-firewall-handled/");
            assert(crate::address::token(root@.subrange(16, root@.len() as int)));
            assert forall|i: int| 0 <= i < path@.len() implies wire::path_byte(path@[i], i) by {
                if i < prefix.len() {
                    assert(path@[i] == prefix[i]);
                    assert(wire::path_byte(prefix[i], i));
                } else {
                    let source = root@.subrange(16, root@.len() as int);
                    assert(path@[i] == source[i-prefix.len()]);
                    assert(source[i-prefix.len()] == root@[i-prefix.len()+16]);
                }
            }
            assert(wire::writable(path@, value@));
        }
        let serial = self.native.write(path.as_slice(), value.as_slice());
        if serial.is_none() { self.disconnect(); }
        serial
    }

    /// Install complete DNS data without creating another control channel or
    /// bypassing the source's original ordered native completion observation.
    pub fn resolve(&mut self, answers: crate::resolution::Resolved, now: u64) -> (accepted: bool)
        requires old(self).valid(), answers.valid(),
        ensures final(self).valid(),
            accepted ==> final(self).view().resolved_for(answers.source_value(), answers)
                && final(self).view().revision() == old(self).view().revision() + 1,
            !accepted ==> final(self).view() == old(self).view() || final(self).startup() is Lost,
    {
        if !matches!(self.startup, Startup::Ready) || !self.native.between_records() { return false; }
        let accepted = self.view.resolve(answers, now);
        if matches!(self.view.state(), crate::projection::Phase::Lost) { self.disconnect(); }
        accepted
    }

    /// Exact latest handled-counter ACK after the network boot handoff.
    pub closed spec fn barrier_completed(&self, serial: u32) -> bool {
        self.startup is Ready && self.native.write_completed(serial)
    }

    /// Observe the stronger network-ready, complete-record input/output drain.
    pub fn between_records(&self) -> (idle: bool)
        requires self.valid(),
        ensures idle == self.drained(),
    { matches!(self.startup, Startup::Ready) && self.native.between_records() }

    /// Confirm the exact latest barrier rather than publication or an old ACK.
    pub fn completed(&self, serial: u32) -> (completed: bool)
        requires self.valid(), ensures completed == self.barrier_completed(serial),
    { matches!(self.startup, Startup::Ready) && self.native.completed(serial) }

    /// Borrow the current network projection under the control owner's lifetime.
    pub fn projection(&self) -> (view: &View)
        requires self.valid(), ensures *view == self.view(), view.valid(),
    { &self.view }
}

}
