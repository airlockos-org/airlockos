//! Atomic in-memory policy publication from ordered native QubesDB observations.
//! No persistence is claimed: a VM crash discards all state and requires native
//! initial synchronization followed by fresh source completion writes. Native
//! write ACKs acknowledge replication, never policy installation or durability.
//!
//! Control loss blocks both established and newly attached clients. An initial
//! or changed source remains blocked while its complete snapshot is built. A
//! rejected source cannot alter another source's snapshot. Global network/DNS
//! changes invalidate all snapshots; a membership addition/removal preserves
//! unchanged members only when their complete network configuration is equal.
//! Consumers in milestone 03 must re-evaluate existing flows against the current
//! generation; an established-flow shortcut cannot bypass a replacement/drop.

use alloc::vec::Vec;
use vstd::prelude::*;

use crate::address::Ip;
use crate::bytes::{equal, prefix};
use crate::cache::Cache;
use crate::config::Config;
#[cfg(verus_keep_ghost)]
use crate::config::MAX_CLIENTS;
use crate::policy::{self, Path, Rejection, Snapshot};

verus! {

/// Full-stream synchronization and terminal invalidation of the projection.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Native initial-dump completion has not yet arrived.
    Synchronizing,
    /// Native stream is synchronized; individual source gates still apply.
    Synchronized,
    /// Lost stream or exhausted generation; cannot be revived in this boot.
    Lost,
}

/// One source's publication gate; independent booleans cannot represent this.
enum Publication {
    /// No fresh live completion or an update is currently incomplete.
    Waiting,
    /// A complete update was rejected with an observable reason.
    Blocked(/// Exact reason this completed source is blocked.
        Rejection),
    /// Complete validated data; only constructed after a live completion write.
    Complete(/// Complete same-source validated policy, never a partial prefix.
        Snapshot),
}

/// One native source membership and its independently published policy.
struct Slot {
    /// Exact normalized address from the current complete membership projection.
    source: Ip,
    /// Governs whether a complete policy may be borrowed.
    publication: Publication,
}

impl Slot {
    /// Every completed snapshot belongs only to this same native source.
    closed spec fn valid(&self) -> bool {
        self.source.valid() && match self.publication {
            Publication::Complete(snapshot) => snapshot.valid()
                && snapshot.source == self.source && !snapshot.unresolved,
            _ => true,
        }
    }
}

/// A synchronized projection is data, not authority: the runtime must own the
/// actual dom0 vchan and the exact connected Netback before it can authorize an
/// operation. Holding an immutable borrow prevents replacement during that
/// operation. Do not construct a second projection to reset a failed live stream.
pub struct View {
    /// Native stream lifecycle, distinct from per-source completion.
    phase: Phase,
    /// Complete global addressing and current membership, or a closed gate.
    pub(crate) config: Option<Config>,
    /// One bounded source slot for each normalized current member.
    slots: Vec<Slot>,
    /// Monotonic volatile revision used to invalidate cached connection decisions.
    generation: u64,
}

/// Sources' normalized identities, independent of their per-source state.
closed spec fn identities(slots: Seq<Slot>) -> Seq<Ip> {
    slots.map(|i: int, slot: Slot| slot.source)
}

impl View {
    /// Bounded same-source policy ownership and complete membership projection.
    pub closed spec fn valid(&self) -> bool {
        self.slots@.len() <= 2*MAX_CLIENTS
            && (forall|i: int| 0 <= i < self.slots@.len() ==> self.slots@[i].valid())
            && match self.config {
                Some(config) => config.valid() && identities(self.slots@) == config.sources(),
                None => self.slots@.len() == 0,
            }
            && (self.phase == Phase::Synchronizing ==> self.generation == 0 && self.config.is_none())
            && (self.phase == Phase::Synchronized ==> self.generation > 0)
    }

    /// Exact current generation, never reused while this VM remains alive.
    pub closed spec fn revision(&self) -> u64 { self.generation }

    /// Exact full-stream synchronization/loss observation.
    pub closed spec fn phase(&self) -> Phase { self.phase }

    /// Current data eligibility for one normalized authoritative address. A
    /// runtime still needs a live interface owner to turn it into permission.
    pub closed spec fn member_ready(&self, source: Ip) -> bool {
        self.phase == Phase::Synchronized && self.config.is_some()
            && self.config.unwrap().sources().contains(source)
            && exists|i: int, snapshot: Snapshot| 0 <= i < self.slots@.len()
                && self.slots@[i].source == source && self.slots@[i].publication == Publication::Complete(snapshot)
    }

    /// This exact complete typed source snapshot is currently published.
    pub closed spec fn published(&self, snapshot: Snapshot) -> bool {
        self.phase == Phase::Synchronized && self.config.is_some()
            && exists|i: int| 0 <= i < self.slots@.len()
                && self.slots@[i].publication == Publication::Complete(snapshot)
    }

    /// Initial closed projection, with no trusted transport or client implied.
    pub fn synchronizing() -> (view: Self)
        ensures view.valid(), view.phase() == Phase::Synchronizing, view.revision() == 0,
    { Self { phase: Phase::Synchronizing, config: None, slots: Vec::new(), generation: 0 } }

    /// Irreversibly block every source on control loss. Retained cache bytes or
    /// later marker writes cannot revive this projection in the same boot.
    pub fn disconnect(&mut self)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).phase() == Phase::Lost,
            final(self).revision() == old(self).revision(), final(self).config.is_none(),
    {
        self.phase = Phase::Lost;
        self.config = None;
        self.slots.clear();
    }

    /// Advance before changing a generation. Exhaustion closes the whole view,
    /// rather than wrapping a revision into a potentially cached old decision.
    fn advance(&mut self) -> (advanced: bool)
        requires old(self).valid(), old(self).phase() != Phase::Synchronizing,
        ensures final(self).valid(),
            advanced ==> final(self).revision() == old(self).revision()+1 && final(self).phase() == Phase::Synchronized,
            !advanced ==> final(self).phase() == Phase::Lost,
    {
        if self.phase != Phase::Synchronized || self.generation == u64::MAX {
            self.disconnect(); return false;
        }
        self.generation += 1;
        true
    }

    /// Replace complete addressing, preserving existing members only when the
    /// complete network configuration is unchanged. A removed member loses its
    /// slot; adding the same address later cannot recover its old policy.
    fn configuration(&mut self, cache: &Cache)
        requires old(self).valid(), cache.valid(), self.phase() == Phase::Synchronized,
        ensures final(self).valid(), final(self).phase() == old(self).phase(),
            final(self).revision() == old(self).revision(),
            match final(self).config {
                Some(config) => config.describes(*cache),
                None => !(exists|config: Config| config.describes(*cache)),
            },
    {
        let config = match Config::read(cache) {
            Some(value) => value,
            None => { self.config = None; self.slots.clear(); return; }
        };
        let preserve = match &self.config { Some(previous) => previous.same_network(&config), None => false };
        let sources = config.all_sources();
        let mut slots = Vec::new();
        let mut i = 0;
        while i < sources.len()
            invariant i <= sources.len() <= 2*MAX_CLIENTS, config.valid(),
                sources@ == config.sources(), slots@.len() == i,
                identities(slots@) == sources@.subrange(0, i as int),
                forall|j: int| 0 <= j < slots@.len() ==> slots@[j].valid(),
                self.slots@.len() <= 2*MAX_CLIENTS,
                forall|j: int| 0 <= j < self.slots@.len() ==> self.slots@[j].valid(),
            decreases sources.len()-i,
        {
            let source = sources[i];
            let mut selected = None;
            if preserve {
                let mut j = 0;
                while j < self.slots.len()
                    invariant j <= self.slots.len() <= 2*MAX_CLIENTS, source.valid(),
                        forall|k: int| 0 <= k < self.slots@.len() ==> self.slots@[k].valid(),
                    decreases self.slots.len()-j,
                {
                    if self.slots[j].source.same(&source) { selected = Some(j); break; }
                    j += 1;
                }
            }
            let slot = match selected {
                Some(index) => self.slots.remove(index),
                None => Slot { source, publication: Publication::Waiting },
            };
            slots.push(slot);
            i += 1;
        }
        self.config = Some(config);
        self.slots = slots;
    }

    /// Native whole-database barrier. Initial source roots are deliberately
    /// ignored: a dom0 writer may have left an old root during a partial update.
    /// The current-boot QubesDB notice requests the normal upstream firewall
    /// reload after this sync; no alternate policy writer or relay is introduced.
    pub fn synchronized(&mut self, cache: &Cache) -> (accepted: bool)
        requires old(self).valid(), cache.valid(),
        ensures final(self).valid(),
            accepted ==> old(self).phase() == Phase::Synchronizing
                && final(self).phase() == Phase::Synchronized && final(self).revision() == 1
                && (forall|i: int| 0 <= i < final(self).slots@.len()
                    ==> final(self).slots@[i].publication is Waiting),
            !accepted ==> final(self).phase() == Phase::Lost,
    {
        if self.phase != Phase::Synchronizing { self.disconnect(); return false; }
        self.phase = Phase::Synchronized;
        self.generation = 1;
        self.configuration(cache);
        true
    }

    /// Apply one exact local watch observation after its native mutation was
    /// committed to the private replica. A source's first descendant mutation
    /// blocks it before another packet operation; only a live empty root WRITE
    /// can publish a replacement. Resource-bounded construction is atomic under
    /// the exclusive mutable borrow. Native ACK generation belongs to qubesdb.
    pub fn changed(&mut self, cache: &Cache, key: &[u8], removed: bool) -> (accepted: bool)
        requires old(self).valid(), cache.valid(), 0 < key@.len() < 64,
        ensures final(self).valid(),
            !accepted ==> final(self).phase() == Phase::Lost,
            old(self).phase() == Phase::Lost ==> !accepted,
    {
        if self.phase != Phase::Synchronized { self.disconnect(); return false; }
        if !self.advance() { return false; }
        if configuration_key(key) || (removed && equal(key, b"/")) { self.configuration(cache); }
        if removed && (equal(key, b"/") || equal(key, b"/qubes-firewall/")) {
            let mut i = 0;
            while i < self.slots.len()
                invariant self.valid(), i <= self.slots.len() <= 2*MAX_CLIENTS,
                decreases self.slots.len()-i,
            {
                self.slots[i].publication = Publication::Waiting;
                i += 1;
            }
        }
        if prefix(key, b"/mapped-ip/") {
            // Native map changes occur before upstream completion on attachment.
            // Do not retain an old translation decision across those writes.
            let mut i = 0;
            while i < self.slots.len()
                invariant self.valid(), i <= self.slots.len() <= 2*MAX_CLIENTS,
                decreases self.slots.len()-i,
            {
                if let Some(config) = &self.config
                    && !policy::mapping_supported(cache, &self.slots[i].source, config) {
                        self.slots[i].publication = Publication::Blocked(Rejection::Mapping);
                    }
                i += 1;
            }
        }
        let path = match Path::parse(key) { Some(value) => value, None => return true };
        let mut i = 0;
        while i < self.slots.len()
            invariant self.valid(), i <= self.slots.len() <= 2*MAX_CLIENTS,
                source_path_for(path, key@),
            decreases self.slots.len()-i,
        {
            if self.slots[i].source.same(path.ip()) {
                self.slots[i].publication = Publication::Waiting;
                if !removed && path.is_root(key) {
                    let config = match &self.config { Some(value) => value, None => return true };
                    self.slots[i].publication = if !policy::mapping_supported(cache, &self.slots[i].source, config) {
                        Publication::Blocked(Rejection::Mapping)
                    } else {
                        match Snapshot::read(cache, path.root(key)) {
                            Ok(snapshot) if snapshot.unresolved() => Publication::Blocked(Rejection::Dns),
                            Ok(snapshot) => Publication::Complete(snapshot),
                            Err(reason) => Publication::Blocked(reason),
                        }
                    };
                }
                return true;
            }
            i += 1;
        }
        true
    }

    /// Borrow current complete addressing; no cached projection survives loss.
    pub fn config(&self) -> (config: Option<&Config>)
        requires self.valid(),
        ensures match config {
            Some(value) => self.phase() == Phase::Synchronized && value.valid() && self.config == Some(*value),
            None => self.config.is_none(),
        },
    { self.config.as_ref() }

    /// Borrow a currently installable complete source policy. This returns data,
    /// not an authenticated interface or permission to trust packet source claims.
    pub fn policy(&self, source: &Ip) -> (policy: Option<&Snapshot>)
        requires self.valid(), source.valid(),
        ensures match policy {
            Some(value) => self.phase() == Phase::Synchronized && self.config.is_some()
                && value.valid() && value.source == *source && !value.unresolved
                && (exists|i: int| 0 <= i < self.slots@.len()
                    && self.slots@[i].source == *source && self.slots@[i].publication == Publication::Complete(*value)),
            None => !(exists|i: int, snapshot: Snapshot| 0 <= i < self.slots@.len()
                && self.slots@[i].source == *source && self.slots@[i].publication == Publication::Complete(snapshot)),
        },
    {
        let mut i = 0;
        while i < self.slots.len()
            invariant self.valid(), source.valid(), i <= self.slots.len() <= 2*MAX_CLIENTS,
                forall|j: int, snapshot: Snapshot| 0 <= j < i && self.slots@[j].source == *source
                    ==> self.slots@[j].publication != Publication::Complete(snapshot),
            decreases self.slots.len()-i,
        {
            if self.slots[i].source.same(source) {
                return match &self.slots[i].publication { Publication::Complete(value) => Some(value), _ => None };
            }
            i += 1;
        }
        None
    }

    /// Payload-free blocking reason for a native source. No API substitutes a
    /// drop-default snapshot for an error, so operators can observe the rejection.
    pub fn rejection(&self, source: &Ip) -> (reason: Option<Rejection>)
        requires self.valid(), source.valid(),
        ensures reason.is_none() ==> exists|i: int, snapshot: Snapshot| 0 <= i < self.slots@.len()
            && self.slots@[i].source == *source && self.slots@[i].publication == Publication::Complete(snapshot),
    {
        if self.phase != Phase::Synchronized { return Some(Rejection::Disconnected); }
        if self.config.is_none() { return Some(Rejection::Configuration); }
        let mut i = 0;
        while i < self.slots.len()
            invariant self.valid(), source.valid(), i <= self.slots.len() <= 2*MAX_CLIENTS,
            decreases self.slots.len()-i,
        {
            if self.slots[i].source.same(source) {
                return match &self.slots[i].publication {
                    Publication::Complete(_) => None,
                    Publication::Waiting => Some(Rejection::Incomplete),
                    Publication::Blocked(reason) => Some(*reason),
                };
            }
            i += 1;
        }
        Some(Rejection::Configuration)
    }

    /// Current volatile revision for invalidating any cached flow decision.
    pub fn generation(&self) -> (generation: u64)
        requires self.valid(), ensures generation == self.revision(),
    { self.generation }
}

/// Keep the path observation attached to the exact bytes used to parse it.
closed spec fn source_path_for(path: Path, key: Seq<u8>) -> bool {
    policy::source_path(key, path.source(), path.end() as int)
}

/// Complete inventory of global network keys consumed by Config. Native policy
/// acknowledgements and unrelated Qubes features cannot trigger a refresh loop.
pub open spec fn network_key(key: Seq<u8>) -> bool {
    key == b"/qubes-mac"@ || key == b"/qubes-ip"@ || key == b"/qubes-netmask"@
        || key == b"/qubes-gateway"@ || key == b"/qubes-primary-dns"@ || key == b"/qubes-secondary-dns"@
        || key == b"/qubes-ip6"@ || key == b"/qubes-gateway6"@ || key == b"/qubes-netvm-network"@
        || key == b"/qubes-netvm-gateway"@ || key == b"/qubes-netvm-netmask"@
        || key == b"/qubes-netvm-primary-dns"@ || key == b"/qubes-netvm-secondary-dns"@
        || key == b"/qubes-netvm-gateway6"@ || key == b"/connected-ips"@ || key == b"/connected-ips6"@
}

/// Classify only exact native global keys, never arbitrary packet/watch prefixes.
fn configuration_key(key: &[u8]) -> (network: bool)
    requires key@.len() < 64,
    ensures network == network_key(key@),
{
    equal(key, b"/qubes-mac") || equal(key, b"/qubes-ip") || equal(key, b"/qubes-netmask")
        || equal(key, b"/qubes-gateway") || equal(key, b"/qubes-primary-dns") || equal(key, b"/qubes-secondary-dns")
        || equal(key, b"/qubes-ip6") || equal(key, b"/qubes-gateway6") || equal(key, b"/qubes-netvm-network")
        || equal(key, b"/qubes-netvm-gateway") || equal(key, b"/qubes-netvm-netmask")
        || equal(key, b"/qubes-netvm-primary-dns") || equal(key, b"/qubes-netvm-secondary-dns")
        || equal(key, b"/qubes-netvm-gateway6") || equal(key, b"/connected-ips") || equal(key, b"/connected-ips6")
}

}
