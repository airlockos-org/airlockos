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

use crate::bytes::{append, copy};
use crate::cache::Cache;
use crate::number;
use crate::policy::Path;
use crate::projection::View;
#[cfg(verus_keep_ghost)]
use crate::wire;

verus! {

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
enum Startup {
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

impl Control {
    /// Independent invariants remain available during a composed transition.
    closed spec fn parts_valid(&self) -> bool {
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
            Startup::Announcing(_) | Startup::Ready => self.native.phase() == Phase::Ready
                && self.view.phase() == crate::projection::Phase::Synchronized,
            Startup::Lost => self.native.phase() == Phase::Failed
                && self.view.phase() == crate::projection::Phase::Lost,
        }
    }

    /// Exact network projection, separate from native connection ownership.
    pub closed spec fn view(&self) -> View { self.view }

    /// Start a native dump with this boot's challenge retained for its later
    /// synchronization notice. Neither initial roots nor publication alone
    /// authorize an interface; fresh source policies and a binding are required.
    pub fn synchronizing_at(now: u64, challenge: Challenge) -> (control: Self)
        requires challenge_bytes(challenge.value()),
        ensures control.valid(), control.startup is Waiting,
            control.view().phase() == crate::projection::Phase::Synchronizing,
    {
        Self { native: Client::synchronizing_at(now), cache: Cache::empty(),
            view: View::synchronizing(), startup: Startup::Waiting(challenge) }
    }

    /// Terminate native control and revoke all network publication gates first.
    /// Retained bytes remain bounded diagnostics and cannot be replayed.
    pub fn disconnect(&mut self)
        requires old(self).parts_valid(),
        ensures final(self).valid(), final(self).startup is Lost,
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
        ensures final(self).valid(), !live ==> final(self).startup is Lost,
            live ==> final(self).view() == old(self).view() && final(self).startup == old(self).startup,
    {
        if !self.native.tick(now) { self.disconnect(); return false; }
        true
    }

    /// Supply the native client's next exact chunk; invalid sequencing revokes
    /// every network gate rather than overwriting unconsumed control data.
    pub fn deliver(&mut self, bytes: &[u8]) -> (accepted: bool)
        requires old(self).valid(),
        ensures final(self).valid(), !accepted ==> final(self).startup is Lost,
    {
        if !self.native.deliver(bytes) { self.disconnect(); return false; }
        true
    }

    /// Preserve exact database output bytes through the network effect adapter.
    pub fn outgoing(&self) -> (bytes: &[u8])
        requires self.valid(),
        ensures bytes@ == self.native.unpublished(), bytes@.len() <= wire::MAX_RECORD,
    { self.native.outgoing() }

    /// Record the actual positive transport count; publication is never a native
    /// response or permission to commit a boot notice/handled counter locally.
    pub fn published(&mut self, count: usize) -> (accepted: bool)
        requires old(self).valid(),
        ensures final(self).valid(), !accepted ==> final(self).startup is Lost,
    {
        if !self.native.published(count) { self.disconnect(); return false; }
        true
    }

    /// Apply one ordered protocol event before another may be consumed. The
    /// retained cache rejects duplicates and enforces network source quotas;
    /// the projection alone decides when a complete policy can become usable.
    pub fn step(&mut self) -> (step: Step)
        requires old(self).valid(),
        ensures final(self).valid(), step is Failed ==> final(self).startup is Lost,
            old(self).startup is Lost ==> step is Failed,
            step is Synchronized ==> final(self).startup is Ready,
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
                let serial = match self.native.write(crate::READY_PATH.as_bytes(), challenge.as_bytes()) {
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
                } else if !self.cache.put(copy(key.as_slice()), value, true) { self.disconnect(); return Step::Failed; }
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
            && (crate::config::absent(self.cache, Self::counter_path(root))
                || exists|bytes: Seq<u8>| crate::config::observed(self.cache, Self::counter_path(root), bytes)
                    && number::digits(bytes, true) && number::decimal(bytes) < u32::MAX)
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
        let mut path = copy(b"/qubes-firewall-handled/");
        if path.len()+root.len()-16 >= 64 { return None; }
        append(&mut path, &root[16..]);
        let previous = match self.cache.read(path.as_slice()) {
            None => 0,
            Some(bytes) => match number::parse(bytes, u32::MAX, true) {
                Some(value) => value,
                None => { self.disconnect(); return None; }
            },
        };
        if previous == u32::MAX { self.disconnect(); return None; }
        let value = number::encode(previous+1);
        let serial = self.native.write(path.as_slice(), value.as_slice());
        if serial.is_none() { self.disconnect(); }
        serial
    }

    /// Exact latest handled-counter ACK after the network boot handoff.
    pub closed spec fn barrier_completed(&self, serial: u32) -> bool {
        self.startup is Ready && self.native.write_completed(serial)
    }

    /// Observe the stronger network-ready, complete-record input/output drain.
    pub fn between_records(&self) -> (idle: bool)
        requires self.valid(),
        ensures idle == (self.startup is Ready && self.native.drained()),
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
