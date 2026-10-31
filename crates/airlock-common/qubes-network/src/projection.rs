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
#[cfg(verus_keep_ghost)]
use vstd::view::View as ValueView;

use crate::address::Ip;
use crate::cache::Cache;
use crate::config::Config;
#[cfg(verus_keep_ghost)]
use crate::config::MAX_CLIENTS;
use crate::policy::{self, Path, Rejection, Snapshot};
use crate::resolution::Resolved;

verus! {

broadcast use { vstd::seq::group_seq_lemmas, vstd::seq_lib::group_seq_properties, vstd::seq::Seq::lemma_as_ref_index, crate::address::cut_unique };

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
    /// Fresh complete policy awaiting all hostname obligations.
    Resolving(/// Exact immutable snapshot retained while DNS work is pending.
        Snapshot),
    /// Complete policy with a checked positive answer for every hostname.
    CompleteDns(/// Exact completed policy owning these answers.
        Snapshot, /// Bounded DNS data accepted at this policy's observed revision.
        Resolved),
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
                && snapshot.source_value() == self.source && !snapshot.unresolved_value(),
            Publication::Resolving(snapshot) => snapshot.valid() && snapshot.source_value() == self.source
                && snapshot.unresolved_value(),
            Publication::CompleteDns(snapshot, answers) => snapshot.valid() && snapshot.source_value() == self.source
                && snapshot.unresolved_value() && answers.valid() && answers.source_value() == self.source && answers.matches(snapshot),
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

/// A publication exposes one exact completed policy, with DNS data when needed.
closed spec fn installed(publication: Publication, snapshot: Snapshot) -> bool {
    match publication {
        Publication::Complete(value) | Publication::CompleteDns(value, _) => value == snapshot,
        _ => false,
    }
}

/// Whether a publication has passed its complete-policy and DNS gates.
closed spec fn has_installed(publication: Publication) -> bool {
    publication is Complete || publication is CompleteDns
}

/// Sources' normalized identities, independent of their per-source state.
closed spec fn identities(slots: Seq<Slot>) -> Seq<Ip> {
    slots.map(|i: int, slot: Slot| slot.source)
}

/// Complete supported source bytes have no remaining DNS obligation.
pub open spec fn publishable(cache: Cache, root: Seq<u8>) -> bool {
    exists|snapshot: Snapshot| snapshot.describes(cache) && snapshot.root_value() == root && !snapshot.unresolved_value()
}

/// A native mapped-IP mutation can invalidate translation decisions globally.
pub open spec fn mapping_key(key: Seq<u8>) -> bool {
    key.len() >= 11 && key.subrange(0, 11) == b"/mapped-ip/"@
}

impl View {
    /// Complete global configuration, absent while publication is blocked.
    pub closed spec fn configuration_value(&self) -> Option<Config> { self.config }

    /// Every current source is waiting for a fresh completion marker.
    pub closed spec fn all_waiting(&self) -> bool {
        forall|i: int| 0 <= i < self.slots@.len() ==> self.slots@[i].publication is Waiting
    }

    /// A complete source snapshot occupies its exact source's publication slot.
    pub closed spec fn complete_for(&self, source: Ip, snapshot: Snapshot) -> bool {
        exists|i: int| 0 <= i < self.slots@.len()
            && self.slots@[i].source == source && installed(self.slots@[i].publication, snapshot)
    }

    /// A source has a complete snapshot, independently of its rule contents.
    pub closed spec fn has_complete(&self, source: Ip) -> bool {
        exists|snapshot: Snapshot| self.complete_for(source, snapshot)
    }

    /// Bounded same-source policy ownership and complete membership projection.
    pub closed spec fn valid(&self) -> bool {
        self.slots@.len() <= 2*MAX_CLIENTS
            && (forall|i: int, j: int| 0 <= i < j < self.slots@.len() ==> self.slots@[i].source != self.slots@[j].source)
            && (forall|i: int| 0 <= i < self.slots@.len() ==> self.slots@[i].valid())
            && match self.config {
                Some(config) => config.valid() && identities(self.slots@) == config.sources(),
                None => self.slots@.len() == 0,
            }
            && (matches!(self.phase, Phase::Synchronizing) ==> self.generation == 0 && self.config.is_none())
            && (matches!(self.phase, Phase::Synchronized) ==> self.generation > 0)
            && (matches!(self.phase, Phase::Lost) ==> self.config.is_none() && self.slots@.len() == 0)
    }

    /// Exact current generation, never reused while this VM remains alive.
    pub closed spec fn revision(&self) -> u64 { self.generation }

    /// Exact full-stream synchronization/loss observation.
    pub closed spec fn phase(&self) -> Phase { self.phase }

    /// Current data eligibility for one normalized authoritative address. A
    /// runtime still needs a live interface owner to turn it into permission.
    pub open spec fn member_ready(&self, source: Ip) -> bool {
        self.phase() == Phase::Synchronized && self.configuration_value().is_some()
            && self.configuration_value().unwrap().sources().contains(source)
            && self.has_complete(source)
    }

    /// This exact complete typed source snapshot is currently published.
    pub open spec fn published(&self, snapshot: Snapshot) -> bool {
        self.phase() == Phase::Synchronized && self.configuration_value().is_some()
            && exists|source: Ip| self.complete_for(source, snapshot)
    }

    /// A source's publication slot owns exactly one complete snapshot.
    pub proof fn unique_snapshot(&self, left: Snapshot, right: Snapshot)
        requires self.valid(), self.published(left), self.published(right),
            left.source_value() == right.source_value(),
        ensures left == right,
    {
        let i = choose|i: int| 0 <= i < self.slots@.len()
            && installed(self.slots@[i].publication, left);
        let j = choose|j: int| 0 <= j < self.slots@.len()
            && installed(self.slots@[j].publication, right);
        assert(self.slots@[i].source == left.source_value());
        assert(self.slots@[j].source == right.source_value());
        assert(i == j);
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
            final(self).revision() == old(self).revision(), final(self).configuration_value().is_none(),
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
            advanced == (old(self).phase() == Phase::Synchronized && old(self).revision() < u64::MAX),
            advanced ==> final(self).revision() == old(self).revision()+1 && final(self).phase() == Phase::Synchronized
                && final(self).slots@ == old(self).slots@ && final(self).config == old(self).config,
            !advanced ==> final(self).phase() == Phase::Lost,
    {
        if !matches!(self.phase, Phase::Synchronized) || self.generation == u64::MAX {
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
            old(self).all_waiting() ==> final(self).all_waiting(),
            forall|source: Ip, snapshot: Snapshot| final(self).complete_for(source, snapshot) == (
                old(self).config.is_some() && final(self).config.is_some()
                    && old(self).config.unwrap().same_network_as(final(self).config.unwrap())
                    && final(self).config.unwrap().sources().contains(source) && old(self).complete_for(source, snapshot)),
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
        let ghost initially_waiting = self.all_waiting();
        let ghost previous = self.slots@;
        let mut slots: Vec<Slot> = Vec::new();
        let mut i = 0;
        while i < sources.len()
            invariant i <= sources.len() <= 2*MAX_CLIENTS, config.valid(), config.describes(*cache),
                self.phase == Phase::Synchronized, self.generation == old(self).generation,
                self.config == old(self).config, previous == old(self).slots@,
                preserve == (old(self).config.is_some() && old(self).config.unwrap().same_network_as(config)),
                sources@ == config.sources(), slots@.len() == i,
                forall|j: int| 0 <= j < sources@.len() ==> sources@[j].valid(),
                forall|j: int, k: int| 0 <= j < k < sources@.len() ==> sources@[j] != sources@[k],
                initially_waiting == old(self).all_waiting(),
                initially_waiting ==> (forall|j: int| 0 <= j < slots@.len() ==> slots@[j].publication is Waiting),
                initially_waiting ==> (forall|j: int| 0 <= j < self.slots@.len() ==> self.slots@[j].publication is Waiting),
                identities(slots@) == sources@.subrange(0, i as int),
                forall|j: int| 0 <= j < slots@.len() ==> slots@[j].valid(),
                self.slots@.len() <= 2*MAX_CLIENTS,
                forall|j: int| 0 <= j < self.slots@.len() ==> self.slots@[j].valid(),
                forall|j: int, k: int| 0 <= j < k < self.slots@.len() ==> self.slots@[j].source != self.slots@[k].source,
                forall|slot: Slot| self.slots@.contains(slot) ==> previous.contains(slot),
                forall|slot: Slot| previous.contains(slot) ==> self.slots@.contains(slot) || slots@.contains(slot),
                forall|j: int| 0 <= j < slots@.len() ==> (preserve && previous.contains(slots@[j])) || slots@[j].publication is Waiting,
                preserve ==> (forall|j: int, k: int| 0 <= j < self.slots@.len() && 0 <= k < i
                    ==> self.slots@[j].source != sources@[k]),
            decreases sources.len()-i,
        {
            let source = sources[i];
            let mut selected: Option<usize> = None;
            if preserve {
                let mut j = 0;
                while selected.is_none() && j < self.slots.len()
                    invariant preserve, j <= self.slots.len() <= 2*MAX_CLIENTS, source.valid(),
                        forall|slot: Slot| self.slots@.contains(slot) ==> previous.contains(slot),
                        forall|k: int| 0 <= k < slots@.len() ==> (preserve && previous.contains(slots@[k])) || slots@[k].publication is Waiting,
                        selected.is_some() ==> selected.unwrap() < self.slots@.len()
                            && self.slots@[selected.unwrap() as int].source == source,
                        selected.is_none() ==> (forall|k: int| 0 <= k < j ==> self.slots@[k].source != source),
                        forall|k: int| 0 <= k < self.slots@.len() ==> self.slots@[k].valid(),
                        initially_waiting ==> (forall|k: int| 0 <= k < self.slots@.len() ==> self.slots@[k].publication is Waiting),
                    decreases self.slots.len()-j,
                {
                    if self.slots[j].source.same(&source) { selected = Some(j); }
                    j += 1;
                }
            }
            let slot = match selected {
                Some(index) => {
                    let ghost remaining = self.slots@;
                    let slot = self.slots.remove(index);
                    proof { remaining.remove_ensures(index as int); }
                    slot
                },
                None => Slot { source, publication: Publication::Waiting },
            };
            proof { assert((preserve && previous.contains(slot)) || slot.publication is Waiting); }
            let ghost built = slots@;
            let ghost next = slot;
            slots.push(slot);
            proof {
                assert forall|j: int| 0 <= j < slots@.len()
                    implies (preserve && previous.contains(slots@[j])) || slots@[j].publication is Waiting by {
                    if j < built.len() { assert(slots@[j] == built[j]); }
                    else { assert(slots@[j] == next); }
                }
            }
            i += 1;
        }
        let ghost remaining = self.slots@;
        self.config = Some(config);
        self.slots = slots;
        proof {
            assert forall|j: int, k: int| 0 <= j < k < self.slots@.len()
                implies self.slots@[j].source != self.slots@[k].source by {
                assert(self.slots@[j].source == identities(self.slots@)[j]);
                assert(self.slots@[k].source == identities(self.slots@)[k]);
            }
            assert forall|source: Ip, snapshot: Snapshot| self.complete_for(source, snapshot) == (
                old(self).config.is_some() && old(self).config.unwrap().same_network_as(config)
                    && config.sources().contains(source) && old(self).complete_for(source, snapshot)) by {
                if self.complete_for(source, snapshot) {
                    let j = choose|j: int| 0 <= j < self.slots@.len() && self.slots@[j].source == source
                        && installed(self.slots@[j].publication, snapshot);
                    let slot = self.slots@[j];
                    assert(config.sources()[j] == source);
                    assert(config.sources().contains(source));
                    assert(preserve && previous.contains(slot));
                    let k = choose|k: int| 0 <= k < previous.len() && previous[k] == slot;
                    assert(old(self).complete_for(source, snapshot));
                }
                if preserve && config.sources().contains(source) && old(self).complete_for(source, snapshot) {
                    let k = choose|k: int| 0 <= k < previous.len() && previous[k].source == source
                        && installed(previous[k].publication, snapshot);
                    let slot = previous[k];
                    assert(previous.contains(slot));
                    if remaining.contains(slot) {
                        let j = choose|j: int| 0 <= j < remaining.len() && remaining[j] == slot;
                        let k = choose|k: int| 0 <= k < sources@.len() && sources@[k] == source;
                        assert(remaining[j].source != sources@[k]);
                    }
                    assert(self.slots@.contains(slot));
                    let j = choose|j: int| 0 <= j < self.slots@.len() && self.slots@[j] == slot;
                    assert(self.complete_for(source, snapshot));
                }
            }
        }
    }

    /// Replace one source's gate without changing membership or other sources.
    fn publish(&mut self, index: usize, publication: Publication)
        requires old(self).valid(), index < old(self).slots@.len(),
            (Slot { source: old(self).slots@[index as int].source, publication }).valid(),
        ensures final(self).valid(), final(self).phase() == old(self).phase(),
            final(self).revision() == old(self).revision(), final(self).config == old(self).config,
            final(self).slots@ == old(self).slots@.update(index as int,
                Slot { source: old(self).slots@[index as int].source, publication }),
            forall|source: Ip, snapshot: Snapshot| final(self).complete_for(source, snapshot) ==
                (if source == old(self).slots@[index as int].source { installed(publication, snapshot) }
                    else { old(self).complete_for(source, snapshot) }),
            final(self).has_complete(old(self).slots@[index as int].source) == has_installed(publication),
    {
        let ghost previous = self.slots@;
        let ghost chosen = publication;
        self.slots[index].publication = publication;
        proof {
            assert(identities(self.slots@) =~= identities(previous));
            assert forall|source: Ip, snapshot: Snapshot| self.complete_for(source, snapshot) ==
                (if source == previous[index as int].source { installed(publication, snapshot) }
                    else { old(self).complete_for(source, snapshot) }) by {
                assert forall|j: int| 0 <= j < previous.len() && previous[j].source == previous[index as int].source
                    implies j == index by { }
                if source == previous[index as int].source && installed(publication, snapshot) {
                    assert(installed(self.slots@[index as int].publication, snapshot));
                }
                if self.complete_for(source, snapshot) {
                    let j = choose|j: int| 0 <= j < self.slots@.len() && self.slots@[j].source == source
                        && installed(self.slots@[j].publication, snapshot);
                    assert(previous[j].source == source);
                    if source == previous[index as int].source { assert(j == index); }
                    else { assert(old(self).complete_for(source, snapshot)); }
                }
                if source != previous[index as int].source && old(self).complete_for(source, snapshot) {
                    let j = choose|j: int| 0 <= j < previous.len() && previous[j].source == source
                        && installed(previous[j].publication, snapshot);
                    assert(j != index);
                    assert(installed(self.slots@[j].publication, snapshot));
                    assert(self.complete_for(source, snapshot));
                }
            }
            if let Publication::Complete(snapshot) | Publication::CompleteDns(snapshot, _) = chosen {
                assert(self.complete_for(previous[index as int].source, snapshot));
                assert(self.has_complete(previous[index as int].source));
            }
        }
    }

    /// Move one original publication out while leaving that source's gate shut.
    /// Exclusive mutable access prevents an observer seeing this intermediate
    /// state during replacement; no fallible external effect occurs here.
    fn take_publication(&mut self, index: usize) -> (publication: Publication)
        requires old(self).valid(), index < old(self).slots@.len(),
        ensures final(self).valid(), final(self).phase() == old(self).phase(),
            final(self).revision() == old(self).revision(), final(self).config == old(self).config,
            publication == old(self).slots@[index as int].publication,
            final(self).slots@ == old(self).slots@.update(index as int,
                Slot { source: old(self).slots@[index as int].source, publication: Publication::Waiting }),
    {
        let ghost previous = self.slots@;
        let publication = core::mem::replace(&mut self.slots[index].publication, Publication::Waiting);
        proof { assert(identities(self.slots@) =~= identities(previous)); }
        publication
    }

    /// Native whole-database barrier. Initial source roots are deliberately
    /// ignored: a dom0 writer may have left an old root during a partial update.
    /// The current-boot QubesDB notice requests the normal upstream firewall
    /// reload after this sync; no alternate policy writer or relay is introduced.
    pub fn synchronized(&mut self, cache: &Cache) -> (accepted: bool)
        requires old(self).valid(), cache.valid(),
        ensures final(self).valid(),
            accepted == (old(self).phase() == Phase::Synchronizing),
            accepted ==> old(self).phase() == Phase::Synchronizing
                && final(self).phase() == Phase::Synchronized && final(self).revision() == 1
                && final(self).all_waiting(),
            !accepted ==> final(self).phase() == Phase::Lost,
    {
        if !matches!(self.phase, Phase::Synchronizing) { self.disconnect(); return false; }
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
            accepted == (old(self).phase() == Phase::Synchronized && old(self).revision() < u64::MAX),
            accepted ==> final(self).phase() == Phase::Synchronized && final(self).revision() == old(self).revision()+1,
            accepted ==> (forall|source: Ip, end: int| policy::source_path(key@, source, end) ==>
                ((removed || end < key@.len()) ==> !final(self).has_complete(source))
                    && ((!removed && end == key@.len()) ==> final(self).has_complete(source) == (
                        final(self).configuration_value().is_some() && final(self).configuration_value().unwrap().sources().contains(source)
                            && policy::mapping_valid(*cache, source, final(self).configuration_value().unwrap()) && publishable(*cache, key@)))),
            accepted && !network_key(key@) && !mapping_key(key@) ==>
                (forall|target: Ip, end: int, source: Ip, snapshot: Snapshot|
                    policy::source_path(key@, target, end) && source != target ==>
                        final(self).complete_for(source, snapshot) == old(self).complete_for(source, snapshot)),
    {
        if !matches!(self.phase, Phase::Synchronized) { self.disconnect(); return false; }
        if !self.advance() { return false; }
        let ghost plain = !network_key(key@) && !mapping_key(key@) && key@.len() > 16;
        if configuration_key(key) || (removed && *key == *b"/".as_slice()) { self.configuration(cache); }
        if removed && (*key == *b"/".as_slice() || *key == *b"/qubes-firewall/".as_slice()) {
            proof {
                if key@.len() == 1 { assert(key@ =~= b"/"@); }
                else { assert(key@ =~= b"/qubes-firewall/"@); }
            }
            let mut i = 0;
            while i < self.slots.len()
                invariant self.valid(), cache.valid(), self.phase == Phase::Synchronized,
                    key@ == b"/"@ || key@ == b"/qubes-firewall/"@,
                    old(self).phase() == Phase::Synchronized, self.generation == old(self).revision()+1,
                    plain == (!network_key(key@) && !mapping_key(key@) && key@.len() > 16),
                    plain ==> self.slots@ == old(self).slots@,
                    i <= self.slots.len() <= 2*MAX_CLIENTS,
                decreases self.slots.len()-i,
            {
                self.publish(i, Publication::Waiting);
                i += 1;
            }
        }
        let mapped = key.starts_with(b"/mapped-ip/");
        proof { if mapped { assert(key@.subrange(0, 11) =~= b"/mapped-ip/"@); } assert(mapped == mapping_key(key@)); }
        if mapped {
            // Native map changes occur before upstream completion on attachment.
            // Do not retain an old translation decision across those writes.
            let mut i = 0;
            while i < self.slots.len()
                invariant self.valid(), cache.valid(), self.phase == Phase::Synchronized,
                    mapping_key(key@),
                    old(self).phase() == Phase::Synchronized, self.generation == old(self).revision()+1,
                    plain == (!network_key(key@) && !mapping_key(key@) && key@.len() > 16),
                    plain ==> self.slots@ == old(self).slots@,
                    i <= self.slots.len() <= 2*MAX_CLIENTS,
                decreases self.slots.len()-i,
            {
                match &self.config {
                    Some(config) if !policy::mapping_supported(cache, &self.slots[i].source, config) => {
                        self.publish(i, Publication::Blocked(Rejection::Mapping));
                    }
                    _ => (),
                }
                i += 1;
            }
        }
        let path = match Path::parse(key) { Some(value) => value, None => return true };
        proof {
            assert(key@.len() > 16);
            if !network_key(key@) && !mapping_key(key@) { assert(plain); assert(self.slots@ == old(self).slots@); }
        }
        let ghost target = path.source();
        let ghost end = path.end();
        self.source_changed(cache, key, removed, path);
        proof {
            assert forall|source: Ip, boundary: int, other: Ip, snapshot: Snapshot|
                !network_key(key@) && !mapping_key(key@) && policy::source_path(key@, source, boundary) && other != source
                implies self.complete_for(other, snapshot) == old(self).complete_for(other, snapshot) by {
                policy::source_unique(key@, source, boundary, target, end as int);
            }
        }
        true
    }

    /// Apply one parsed source observation without changing membership, another
    /// source's complete snapshot, the transport phase or this event's revision.
    fn source_changed(&mut self, cache: &Cache, key: &[u8], removed: bool, path: Path)
        requires old(self).valid(), old(self).phase() == Phase::Synchronized,
            cache.valid(), path.valid(), source_path_for(path, key@),
        ensures final(self).valid(), final(self).phase() == old(self).phase(),
            final(self).revision() == old(self).revision(), final(self).config == old(self).config,
            forall|source: Ip, snapshot: Snapshot| source != path.source() ==>
                final(self).complete_for(source, snapshot) == old(self).complete_for(source, snapshot),
            removed || path.end() < key@.len() ==> !final(self).has_complete(path.source()),
            !removed && path.end() == key@.len() ==> final(self).has_complete(path.source()) == (
                old(self).config.is_some() && old(self).config.unwrap().sources().contains(path.source())
                    && policy::mapping_valid(*cache, path.source(), old(self).config.unwrap()) && publishable(*cache, key@)),
            !removed && path.end() == key@.len() && final(self).has_complete(path.source()) ==>
                exists|snapshot: Snapshot| final(self).complete_for(path.source(), snapshot)
                    && snapshot.describes(*cache) && snapshot.root_value() == key@,
    {
        let mut i = 0;
        while i < self.slots.len()
            invariant self.valid(), self.phase == Phase::Synchronized,
                old(self).phase() == Phase::Synchronized,
                self.generation == old(self).generation, self.config == old(self).config,
                self.slots@ == old(self).slots@,
                forall|j: int| 0 <= j < i ==> self.slots@[j].source != path.source(),
                i <= self.slots.len() <= 2*MAX_CLIENTS,
                source_path_for(path, key@), path.valid(), cache.valid(),
            decreases self.slots.len()-i,
        {
            if self.slots[i].source.same(path.ip()) {
                proof {
                    assert(self.config.is_some());
                    assert(identities(self.slots@)[i as int] == path.source());
                    assert(self.config.unwrap().sources().contains(path.source()));
                }
                self.publish(i, Publication::Waiting);
                if !removed && path.is_root(key) {
                    let config = match &self.config { Some(value) => value, None => return };
                    let publication = if !policy::mapping_supported(cache, &self.slots[i].source, config) {
                        Publication::Blocked(Rejection::Mapping)
                    } else {
                        let root = path.root(key);
                        proof { assert(root@ =~= key@); }
                        match Snapshot::read(cache, root) {
                            Ok(snapshot) => {
                                proof {
                                    if publishable(*cache, key@) && path.end() == key@.len() {
                                        let candidate = choose|candidate: Snapshot| candidate.describes(*cache)
                                            && candidate.root_value() == key@ && !candidate.unresolved_value();
                                        snapshot.dns_agrees(candidate, *cache);
                                    }
                                }
                                if snapshot.unresolved() { Publication::Resolving(snapshot) }
                                else { Publication::Complete(snapshot) }
                            },
                            Err(reason) => Publication::Blocked(reason),
                        }
                    };
                    proof {
                        if let Publication::Complete(snapshot) | Publication::Resolving(snapshot) = &publication {
                            if !snapshot.unresolved_value() { assert(publishable(*cache, key@)); }
                            policy::source_unique(key@.subrange(0, path.end() as int), path.source(), path.end() as int,
                                snapshot.source_value(), snapshot.root_value().len() as int);
                        }
                    }
                    self.publish(i, publication);
                }
                return;
            }
            i += 1;
        }
        proof {
            if self.config.is_some() && self.config.unwrap().sources().contains(path.source()) {
                let j = choose|j: int| 0 <= j < self.config.unwrap().sources().len()
                    && self.config.unwrap().sources()[j] == path.source();
                assert(self.slots@[j].source == identities(self.slots@)[j]);
            }
        }
    }

    /// Exact retained whole-source observation awaiting its DNS obligations.
    pub closed spec fn awaiting(&self, source: Ip, snapshot: Snapshot) -> bool {
        self.phase == Phase::Synchronized && exists|i: int| 0 <= i < self.slots@.len()
            && self.slots@[i].source == source && self.slots@[i].publication == Publication::Resolving(snapshot)
    }

    /// Positive DNS data owned by the same exact currently installed source.
    pub closed spec fn resolved_for(&self, source: Ip, answers: Resolved) -> bool {
        exists|i: int, snapshot: Snapshot| 0 <= i < self.slots@.len()
            && self.slots@[i].source == source
            && self.slots@[i].publication == Publication::CompleteDns(snapshot, answers)
    }

    /// Any stale DNS source forces a new volatile revision before forwarding.
    pub closed spec fn needs_expiry(&self, now: u64) -> bool {
        exists|i: int| 0 <= i < self.slots@.len() && match #[trigger] self.slots@[i].publication {
            Publication::CompleteDns(_, answers) => !answers.unexpired(now), _ => false,
        }
    }

    /// Complete answers may activate only their original pending observation.
    pub closed spec fn accepts_resolution(&self, answers: Resolved, now: u64) -> bool {
        answers.valid() && self.phase == Phase::Synchronized && answers.revision_value() == self.revision()
            && answers.unexpired(now) && exists|snapshot: Snapshot|
                self.awaiting(answers.source_value(), snapshot) && answers.matches(snapshot)
    }

    /// Find a source slot without copying or manufacturing its publication.
    fn slot_index(&self, source: &Ip) -> (index: Option<usize>)
        requires self.valid(), source.valid(),
        ensures match index {
            Some(i) => i < self.slots@.len() && self.slots@[i as int].source == *source,
            None => forall|i: int| 0 <= i < self.slots@.len() ==> self.slots@[i].source != *source,
        },
    {
        self.slots.iter().position(|slot: &Slot| -> (same: bool)
            requires slot.valid(), ensures same == (slot.source == *source),
        { slot.source.same(source) })
    }

    /// Borrow a fresh completed snapshot for bounded DNS work. Candidate data
    /// alone does not satisfy member_ready or permit an interface operation.
    pub fn candidate(&self, source: &Ip) -> (candidate: Option<(u64, &Snapshot)>)
        requires self.valid(), source.valid(),
        ensures match candidate {
            Some((revision, snapshot)) => revision == self.revision() && snapshot.valid()
                && snapshot.source_value() == *source && snapshot.unresolved_value() && self.awaiting(*source, *snapshot),
            None => !(exists|snapshot: Snapshot| self.awaiting(*source, snapshot)),
        },
    {
        if !matches!(self.phase, Phase::Synchronized) { return None; }
        let index = self.slot_index(source)?;
        match &self.slots[index].publication {
            Publication::Resolving(snapshot) => Some((self.generation, snapshot)),
            _ => None,
        }
    }

    /// Borrow the current positive DNS data; packet admission checks expiry at
    /// the operation's own monotonic time even while this immutable view is held.
    pub fn resolution(&self, source: &Ip) -> (answers: Option<&Resolved>)
        requires self.valid(), source.valid(),
        ensures match answers {
            Some(value) => value.valid() && value.source_value() == *source && self.resolved_for(*source, *value)
                && (forall|other: Resolved| self.resolved_for(*source, other) ==> other == *value)
                && (exists|snapshot: Snapshot| self.complete_for(*source, snapshot) && value.matches(snapshot)),
            None => !(exists|value: Resolved| self.resolved_for(*source, value)),
        },
    {
        let index = self.slot_index(source)?;
        match &self.slots[index].publication { Publication::CompleteDns(_, answers) => Some(answers), _ => None }
    }

    /// Consume complete answers only for the still-current policy observation.
    /// Any intervening QubesDB mutation forces the resolver to obtain a new view.
    pub fn resolve(&mut self, answers: Resolved, now: u64) -> (accepted: bool)
        requires old(self).valid(), answers.valid(),
        ensures final(self).valid(),
            accepted == (old(self).accepts_resolution(answers, now) && old(self).revision() < u64::MAX),
            accepted ==> final(self).phase() == Phase::Synchronized
                && final(self).revision() == old(self).revision() + 1
                && final(self).configuration_value() == old(self).configuration_value()
                && final(self).resolved_for(answers.source_value(), answers),
            !accepted ==> *final(self) == *old(self) || final(self).phase() == Phase::Lost,
    {
        if !matches!(self.phase, Phase::Synchronized) || answers.revision() != self.generation { return false; }
        let index = match self.slot_index(answers.source()) { Some(index) => index, None => return false };
        match &self.slots[index].publication {
            Publication::Resolving(snapshot) => if !answers.applies(snapshot, now) { return false; },
            _ => return false,
        }
        if !self.advance() { return false; }
        let previous = self.take_publication(index);
        match previous {
            Publication::Resolving(snapshot) => { self.publish(index, Publication::CompleteDns(snapshot, answers)); true }
            _ => false,
        }
    }

    /// Revoke expired DNS publications before new bindings or packet operations.
    /// One revision covers the whole bounded expiry pass; no stale flow survives it.
    pub fn expire(&mut self, now: u64) -> (live: bool)
        requires old(self).valid(),
        ensures final(self).valid(),
            live == (old(self).phase() != Phase::Lost
                && !(old(self).needs_expiry(now) && old(self).revision() == u64::MAX)),
            live ==> final(self).phase() == old(self).phase()
                && final(self).configuration_value() == old(self).configuration_value()
                && final(self).revision() == old(self).revision() + if old(self).needs_expiry(now) { 1u64 } else { 0u64 }
                && !final(self).needs_expiry(now),
            !live ==> final(self).phase() == Phase::Lost,
    {
        if matches!(self.phase, Phase::Lost) { return false; }
        let stale = self.slots.iter().any(|slot: &Slot| -> (stale: bool)
            requires slot.valid(),
            ensures stale == match slot.publication { Publication::CompleteDns(_, answers) => !answers.unexpired(now), _ => false },
        { match &slot.publication { Publication::CompleteDns(_, answers) => !answers.fresh(now), _ => false } });
        proof { assert(stale == self.needs_expiry(now)); }
        if !stale { return true; }
        proof { assert(self.phase() == Phase::Synchronized); }
        if !self.advance() { return false; }
        let mut i = 0;
        while i < self.slots.len()
            invariant self.valid(), self.phase() == Phase::Synchronized, i <= self.slots@.len() <= 2*MAX_CLIENTS,
                self.config == old(self).config, self.generation == old(self).generation + 1,
                old(self).phase() == Phase::Synchronized, old(self).needs_expiry(now),
                forall|j: int| 0 <= j < i ==> match #[trigger] self.slots@[j].publication {
                    Publication::CompleteDns(_, answers) => answers.unexpired(now), _ => true,
                },
            decreases self.slots.len() - i,
        {
            let stale = match &self.slots[i].publication { Publication::CompleteDns(_, answers) => !answers.fresh(now), _ => false };
            if stale {
                let previous = self.take_publication(i);
                if let Publication::CompleteDns(snapshot, _) = previous { self.publish(i, Publication::Resolving(snapshot)); }
            }
            i += 1;
        }
        true
    }

    /// Borrow current complete addressing; no cached projection survives loss.
    pub fn config(&self) -> (config: Option<&Config>)
        requires self.valid(),
        ensures match config {
            Some(value) => self.phase() == Phase::Synchronized && value.valid() && self.configuration_value() == Some(*value) && self.revision() > 0,
            None => self.configuration_value().is_none(),
        },
    { self.config.as_ref() }

    /// Borrow a currently installable complete source policy. This returns data,
    /// not an authenticated interface or permission to trust packet source claims.
    pub fn policy(&self, source: &Ip) -> (policy: Option<&Snapshot>)
        requires self.valid(), source.valid(),
        ensures match policy {
            Some(value) => self.phase() == Phase::Synchronized && self.configuration_value().is_some()
                && value.valid() && value.source_value() == *source
                && self.member_ready(*source) && self.published(*value)
                && self.complete_for(*source, *value)
                && (forall|other: Snapshot| self.complete_for(*source, other) ==> other == *value)
                && (forall|other: Snapshot| self.published(other) && other.source_value() == *source ==> other == *value),
            None => !self.has_complete(*source) && !self.member_ready(*source)
                && (forall|snapshot: Snapshot| !self.complete_for(*source, snapshot)),
        },
    {
        let mut i = 0;
        while i < self.slots.len()
            invariant self.valid(), source.valid(), i <= self.slots.len() <= 2*MAX_CLIENTS,
                forall|j: int, snapshot: Snapshot| 0 <= j < i && self.slots@[j].source == *source
                    ==> !installed(self.slots@[j].publication, snapshot),
            decreases self.slots.len()-i,
        {
            if self.slots[i].source.same(source) {
                proof {
                    assert forall|j: int, snapshot: Snapshot| 0 <= j < self.slots@.len()
                        && self.slots@[j].source == *source
                        && installed(self.slots@[j].publication, snapshot)
                        implies j == i by { }
                    if let Publication::Complete(value) | Publication::CompleteDns(value, _) = self.slots@[i as int].publication {
                        assert(self.complete_for(*source, value));
                        assert(self.has_complete(*source));
                        assert(identities(self.slots@)[i as int] == *source);
                        assert(self.config.unwrap().sources().contains(*source));
                        assert(self.published(value));
                        assert forall|other: Snapshot| self.published(other) && other.source_value() == *source
                            implies other == value by { self.unique_snapshot(other, value); }
                    }
                }
                return match &self.slots[i].publication {
                    Publication::Complete(value) | Publication::CompleteDns(value, _) => Some(value),
                    _ => None,
                };
            }
            i += 1;
        }
        None
    }

    /// Payload-free blocking reason for a native source. No API substitutes a
    /// drop-default snapshot for an error, so operators can observe the rejection.
    pub fn rejection(&self, source: &Ip) -> (reason: Option<Rejection>)
        requires self.valid(), source.valid(),
        ensures reason.is_none() ==> self.has_complete(*source),
    {
        if !matches!(self.phase, Phase::Synchronized) { return Some(Rejection::Disconnected); }
        if self.config.is_none() { return Some(Rejection::Configuration); }
        let mut i = 0;
        while i < self.slots.len()
            invariant self.valid(), source.valid(), i <= self.slots.len() <= 2*MAX_CLIENTS,
            decreases self.slots.len()-i,
        {
            if self.slots[i].source.same(source) {
                proof {
                    if let Publication::Complete(value) | Publication::CompleteDns(value, _) = self.slots@[i as int].publication {
                        assert(self.complete_for(*source, value));
                        assert(self.has_complete(*source));
                    }
                }
                return match &self.slots[i].publication {
                    Publication::Complete(_) | Publication::CompleteDns(_, _) => None,
                    Publication::Resolving(_) => Some(Rejection::Dns),
                    Publication::Waiting => Some(Rejection::Incomplete),
                    Publication::Blocked(reason) => Some(*reason),
                };
            }
            i += 1;
        }
        Some(Rejection::Configuration)
    }

    /// Observe the native projection's lifecycle without exposing mutable state.
    pub fn state(&self) -> (phase: Phase)
        requires self.valid(), ensures phase == self.phase(),
    { self.phase }

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
    proof {
        assert forall|candidate: Seq<u8>| key@.len() == #[trigger] candidate.len()
            && (forall|i: int| 0 <= i < key@.len() ==> key@[i] == candidate[i])
            implies key@ == candidate by { assert(key@ =~= candidate); }
    }
    *key == *b"/qubes-mac".as_slice() || *key == *b"/qubes-ip".as_slice() || *key == *b"/qubes-netmask".as_slice()
        || *key == *b"/qubes-gateway".as_slice() || *key == *b"/qubes-primary-dns".as_slice() || *key == *b"/qubes-secondary-dns".as_slice()
        || *key == *b"/qubes-ip6".as_slice() || *key == *b"/qubes-gateway6".as_slice() || *key == *b"/qubes-netvm-network".as_slice()
        || *key == *b"/qubes-netvm-gateway".as_slice() || *key == *b"/qubes-netvm-netmask".as_slice()
        || *key == *b"/qubes-netvm-primary-dns".as_slice() || *key == *b"/qubes-netvm-secondary-dns".as_slice()
        || *key == *b"/qubes-netvm-gateway6".as_slice() || *key == *b"/connected-ips".as_slice() || *key == *b"/connected-ips6".as_slice()
}

}
