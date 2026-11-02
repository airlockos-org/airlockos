//! Bounded IPv6 fragment admission around etherparse's owned reassembler.
//! Its assembler permits overlapping writes; Airlock rejects overlaps before
//! calling it and binds every assembly to the original native link and MAC.
//! IPv4 retains its existing no-fragment input contract. smoltcp's assembler is
//! crate-private; etherparse provides the maintained public reassembly API.

#[cfg(verus_keep_ghost)]
use crate::wire;
use crate::{MAX_CLIENTS, MTU, SECOND, engine::Owner, wire::codec as packet};
use airlock_qubes_network::address::Ip;
use alloc::{collections::VecDeque, vec::Vec};
use vstd::prelude::*;
use vstd::slice::slice_to_vec;
#[cfg(verus_keep_ghost)]
use vstd::std_specs::iter::{IteratorSpec, filter_keep};

mod codec;

verus! {

broadcast use { vstd::std_specs::iter::group_iter_axioms, vstd::seq_lib::group_seq_properties,
    vstd::seq::group_seq_lemmas, vstd::seq_lib::group_filter_ensures,
    vstd::seq::Seq::filter_distributes_over_add, vstd::seq::Seq::lemma_filter_len_push,
    vstd::seq::Seq::lemma_as_ref_index,
    vstd::slice::group_slice_axioms, crate::library::byte_array_equality };

/// Original position and identity of an IPv6 fragment header.
#[derive(Clone, Copy)]
pub(crate) struct Layout {
    /// Length of the unfragmentable prefix, excluding the fragment header.
    pub prefix: usize,
    /// Position of the preceding header's next-header byte.
    pub previous: usize,
    /// Protocol number immediately following the original fragment header.
    pub protocol: u8,
    /// Largest observed fragment payload, rounded down to eight-byte alignment.
    /// Preserving this cap prevents reassembly from undoing sender PMTU learning.
    pub chunk: usize,
    /// Original identifier, retained while emitting translated fragments.
    pub id: u32,
}

impl Layout {
    /// Every retained native header fits the fixed extension traversal bound.
    pub(crate) open spec fn valid(&self) -> bool {
        40 <= self.prefix <= 248 && self.previous < self.prefix && self.chunk <= MTU - self.prefix - 8 && self.chunk % 8 == 0
    }
}

/// Observations copied from maintained header views; none authorizes forwarding.
pub(crate) struct Part {
    /// Exact native source address.
    pub source: Ip,
    /// Exact native destination address.
    pub destination: Ip,
    /// Original unfragmentable bytes; only payload length varies between parts.
    pub prefix: Vec<u8>,
    /// Fragment's identity and header positions.
    pub layout: Layout,
    /// Byte offset in the fragmentable payload.
    pub offset: usize,
    /// More-fragments bit.
    pub more: bool,
    /// Exact declared payload after the fragment header, without Ethernet padding.
    pub payload: Vec<u8>,
    /// Native pre-fragment extension count.
    pub extensions: usize,
    /// Raw pre-fragment option types, including their action bits.
    pub options: Vec<u8>,
    /// Native routing header observation.
    pub routing: bool,
    /// Native authentication header observation.
    pub authenticated: bool,
    /// Additional extension headers present after the first fragment header.
    pub extensions_after: usize,
    /// Fragment headers after the original one, including atomic repeats.
    pub fragment_headers_after: usize,
    /// First fragment includes the entire extension and transport header chain.
    pub first_complete: bool,
}

/// An incomplete assembly's retained authority and resource reservation.
struct Slot {
    /// Exact native source link; None is the separately bounded upstream pool.
    owner: Option<Owner>,
    /// Original Ethernet source, which cannot change within an assembly.
    mac: [u8; 6],
    /// Source and destination are data correlated with this one native link.
    source: Ip,
    /// Exact original destination.
    destination: Ip,
    /// Immutable fragment header identity and insertion position.
    layout: Layout,
    /// Canonical unfragmentable header with its payload length temporarily zero.
    prefix: Vec<u8>,
    /// Disjoint admitted byte ranges; bounded independently of payload size.
    ranges: Vec<(usize, usize)>,
    /// Native final length, once a last fragment has been accepted.
    end: Option<usize>,
    /// Maintained reassembly implementation; never read before completion.
    buffer: etherparse::defrag::IpDefragBuf,
    /// Fixed lifetime from the first accepted part, never extended by traffic.
    deadline: u64,
}

impl Slot {
    /// One 64 KiB assembly and at most 64 disjoint fragment admissions.
    closed spec fn valid(&self) -> bool {
        self.source.valid() && self.source.family() == 6
            && self.destination.valid() && self.destination.family() == 6
            && self.layout.valid() && self.prefix@.len() == self.layout.prefix
            && self.ranges@.len() <= 64 && self.deadline > 0
            && codec::bounded(self.buffer) && codec::intervals(self.buffer) <= self.ranges@.len()
            && codec::end(self.buffer) == match self.end { Some(length) => Some(length as nat), None => None }
            && (self.end.is_some() ==> forall|i: int| #![trigger self.ranges@[i]] 0 <= i < self.ranges@.len() ==> self.ranges@[i].1 <= self.end.unwrap())
            && codec::image(self.buffer).dom() == ISet::new(|byte: int|
                exists|i: int| 0 <= i < self.ranges@.len() && (#[trigger] self.ranges@[i]).0 <= byte < self.ranges@[i].1)
            && (self.owner.is_some() ==> self.owner.unwrap().valid())
            && (forall|i: int| #![trigger self.ranges@[i]] 0 <= i < self.ranges@.len() ==> 0 <= self.ranges@[i].0 < self.ranges@[i].1 <= 65_535)
            && forall|i: int, j: int| #![trigger self.ranges@[i], self.ranges@[j]] 0 <= i < j < self.ranges@.len() ==>
                self.ranges@[i].1 <= self.ranges@[j].0 || self.ranges@[j].1 <= self.ranges@[i].0
    }
    /// A successful library append initializes exactly the recorded new range.
    /// Keep this correspondence proof separate from pool and owner accounting.
    proof fn received_image(&self, previous: Self, offset: usize, end: usize, payload: Seq<u8>)
        requires previous.valid(), end == offset + payload.len(),
            self.ranges@ == previous.ranges@.push((offset, end)),
            codec::image(self.buffer) == codec::image(previous.buffer).union_prefer_right(IMap::new(
                |byte: int| offset <= byte < end, |byte: int| payload[byte - offset])),
        ensures codec::image(self.buffer).dom() == ISet::new(|byte: int|
            exists|i: int| 0 <= i < self.ranges@.len() && (#[trigger] self.ranges@[i]).0 <= byte < self.ranges@[i].1),
    {
        let initialized = codec::image(self.buffer).dom();
        let received = ISet::new(|byte: int| exists|i: int| 0 <= i < self.ranges@.len()
            && (#[trigger] self.ranges@[i]).0 <= byte < self.ranges@[i].1);
        assert forall|byte: int| #[trigger] initialized.contains(byte) == received.contains(byte) by {
            if initialized.contains(byte) {
                if offset <= byte < end {
                    assert(self.ranges@[previous.ranges@.len() as int] == (offset, end));
                    assert(exists|i: int| 0 <= i < self.ranges@.len()
                        && (#[trigger] self.ranges@[i]).0 <= byte < self.ranges@[i].1);
                } else {
                    assert(codec::image(previous.buffer).dom().contains(byte));
                    let i = choose|i: int| 0 <= i < previous.ranges@.len()
                        && (#[trigger] previous.ranges@[i]).0 <= byte < previous.ranges@[i].1;
                    assert(self.ranges@[i] == previous.ranges@[i]);
                }
            }
            if received.contains(byte) {
                let i = choose|i: int| 0 <= i < self.ranges@.len()
                    && (#[trigger] self.ranges@[i]).0 <= byte < self.ranges@[i].1;
                if i < previous.ranges@.len() {
                    assert(self.ranges@[i] == previous.ranges@[i]);
                    assert(codec::image(previous.buffer).dom().contains(byte));
                } else {
                    assert(i == previous.ranges@.len());
                    assert(offset <= byte < end);
                }
            }
        }
        assert(initialized =~= received);
    }

}

/// One assembly per client across both families, plus two upstream reservations.
pub(crate) struct Reassembly {
    /// Finite active reservations; expiry and link retirement release ownership.
    slots: Vec<Slot>,
}

impl Reassembly {
    /// Untrusted identifiers cannot grow the retained slot table beyond six.
    pub(crate) closed spec fn valid(&self) -> bool {
        self.slots@.len() <= MAX_CLIENTS + 2
            && (forall|i: int| 0 <= i < self.slots@.len() ==> self.slots@[i].valid())
            && self.slots@.filter(|slot: Slot| slot.owner.is_none()).len() <= 2
            && forall|i: int, j: int| #![trigger self.slots@[i], self.slots@[j]] 0 <= i < j < self.slots@.len() && self.slots@[i].owner.is_some()
                ==> self.slots@[i].owner != self.slots@[j].owner
    }

    /// Start without retained fragment data or reserved client slots.
    pub(crate) fn new() -> (table: Self)
        ensures table.valid(),
    { Self { slots: Vec::new() } }

    /// Control replacement discards all old bytes before another native effect.
    pub(crate) fn clear(&mut self)
        requires old(self).valid(), ensures final(self).valid(),
    { self.slots.clear(); }

    /// Removing one actual slot preserves owner separation and both pool limits.
    proof fn removed(&self, before: Self, index: int)
        requires before.valid(), 0 <= index < before.slots@.len(),
            self.slots@ == before.slots@.remove(index),
        ensures self.valid(),
    {
        before.slots@.remove_ensures(index);
        crate::library::filter_remove(before.slots@, index, |slot: Slot| slot.owner.is_none());
        assert forall|i: int, j: int| #![trigger self.slots@[i], self.slots@[j]]
            0 <= i < j < self.slots@.len() && self.slots@[i].owner.is_some()
            implies self.slots@[i].owner != self.slots@[j].owner by {
            let left = if i < index { i } else { i + 1 };
            let right = if j < index { j } else { j + 1 };
            assert(self.slots@[i] == before.slots@[left]);
            assert(self.slots@[j] == before.slots@[right]);
        }
    }

    /// Updating payload progress cannot change which link owns a reservation.
    proof fn updated(&self, before: Self, index: int)
        requires before.valid(), 0 <= index < before.slots@.len(),
            self.slots@ == before.slots@.update(index, self.slots@[index]),
            self.slots@[index].valid(), self.slots@[index].owner == before.slots@[index].owner,
        ensures self.valid(),
    {
        assert forall|i: int| 0 <= i < self.slots@.len()
            implies self.slots@[i].owner == before.slots@[i].owner by { }
        let decisions = |i: int| before.slots@[i].owner.is_none();
        crate::library::filter_count(before.slots@, decisions, self.slots@, |slot: Slot| slot.owner.is_none());
        crate::library::filter_count(before.slots@, decisions, before.slots@, |slot: Slot| slot.owner.is_none());
    }

    /// Reclaim expired or retired link state without extending any other lease.
    pub(crate) fn expire(&mut self, owner: Option<Owner>, now: u64)
        requires old(self).valid(), ensures final(self).valid(),
    {
        let mut index = self.slots.len();
        while index > 0
            invariant self.valid(), index <= self.slots@.len(),
            decreases index,
        {
            index -= 1;
            if self.slots[index].deadline <= now || (owner.is_some() && self.slots[index].owner == owner) {
                let ghost before = *self;
                self.slots.remove(index);
                proof { self.removed(before, index as int); }
            }
        }
    }

    /// Admit only a bounded, non-overlapping fragment for the original endpoint.
    /// Completion returns one private datagram; transport policy still must run.
    pub(crate) fn receive(&mut self, owner: Option<Owner>, mac: [u8; 6], mut part: Part, now: u64) -> (complete: Option<(Vec<u8>, Layout)>)
        requires old(self).valid(), owner.is_some() ==> owner.unwrap().valid(),
            part.source.valid(), part.source.family() == 6, part.destination.valid(), part.destination.family() == 6,
            part.layout.valid(), part.prefix@.len() == part.layout.prefix, part.payload@.len() <= wire::FRAME_BYTES,
        ensures final(self).valid(), complete.is_some() ==> complete.unwrap().1.valid()
            && complete.unwrap().1.prefix < complete.unwrap().0@.len() <= wire::DATAGRAM_BYTES,
    {
        self.expire(None, now);
        if part.payload.is_empty() || part.layout.prefix + 8 + part.payload.len() > MTU || part.offset > 65_535 || part.payload.len() > 65_535 - part.offset
            || part.offset + part.payload.len() > 65_535 - (part.layout.prefix - 40)
            || part.extensions > 8 || part.routing || part.authenticated || matches!(part.layout.protocol, 0 | 44)
            || part.options.iter().any(|kind: &u8| -> (reject: bool) ensures reject == (*kind >= 64), { *kind >= 64 })
            || (part.more && !part.payload.len().is_multiple_of(8)) || !part.offset.is_multiple_of(8)
            || (part.offset == 0 && (!part.first_complete || part.fragment_headers_after != 0 || part.extensions_after > 8 || part.extensions + part.extensions_after > 8)) { return None; }
        let end = part.offset + part.payload.len();
        packet::set_ipv6_length(part.prefix.as_mut_slice(), 0);
        let key = self.slots.iter().position(|slot: &Slot| -> (same: bool)
            requires slot.valid(),
            ensures same == (slot.owner == owner && slot.source == part.source
                && slot.destination == part.destination && slot.layout.id == part.layout.id),
        { slot.owner == owner && slot.source == part.source
            && slot.destination == part.destination && slot.layout.id == part.layout.id });
        let index = match key {
            Some(index) => index,
            None => {
                if self.slots.len() == MAX_CLIENTS + 2
                    || (owner.is_some() && self.slots.iter().any(|slot: &Slot| -> (same: bool) ensures same == (slot.owner == owner), { slot.owner == owner })) { return None; }
                if owner.is_none() {
                    let selected = self.slots.iter().filter(|slot: &&Slot| -> (upstream: bool)
                        ensures upstream == slot.owner.is_none(), { slot.owner.is_none() });
                    let ghost selection = selected;
                    let count = selected.count();
                    proof {
                        let keep = filter_keep(selection);
                        assert(keep.len() == self.slots@.len());
                        crate::library::filter_count(self.slots@.as_ref(), |i: int| keep[i], self.slots@, |slot: Slot| slot.owner.is_none());
                        assert(count == self.slots@.filter(|slot: Slot| slot.owner.is_none()).len());
                    }
                    if count >= 2 { return None; }
                }
                let index = self.slots.len();
                let slot = Slot { owner, mac, source: part.source, destination: part.destination,
                    layout: part.layout, prefix: slice_to_vec(&part.prefix), ranges: Vec::new(), end: None,
                    buffer: codec::new(part.layout.protocol), deadline: now.saturating_add(15 * SECOND) };
                proof {
                    assert(codec::image(slot.buffer).dom() =~= ISet::new(|byte: int|
                        exists|i: int| 0 <= i < slot.ranges@.len() && (#[trigger] slot.ranges@[i]).0 <= byte < slot.ranges@[i].1));
                    assert(slot.valid());
                }
                self.slots.push(slot);
                index
            }
        };
        proof {
            assert(self.slots@.len() <= MAX_CLIENTS + 2);
            assert(forall|i: int| 0 <= i < self.slots@.len() ==> self.slots@[i].valid());
            assert(self.slots@.filter(|slot: Slot| slot.owner.is_none()).len() <= 2);
            assert(self.valid());
        }
        let ghost before_admission = *self;
        let slot = &self.slots[index];
        // etherparse intentionally merges overlaps. Reject the whole assembly
        // first, including identical retransmitted ranges (RFC 5722).
        if slot.mac != mac || slot.layout.prefix != part.layout.prefix || slot.layout.previous != part.layout.previous
            || slot.layout.protocol != part.layout.protocol || slot.ranges.len() == 64
            || (key.is_some() && slot.prefix != part.prefix)
            || slot.ranges.iter().any(|range: &(usize, usize)| -> (overlap: bool) ensures overlap == (part.offset < range.1 && range.0 < end), { part.offset < range.1 && range.0 < end })
            || (!part.more && slot.ranges.iter().any(|range: &(usize, usize)| -> (beyond: bool) ensures beyond == (range.1 > end), { range.1 > end }))
            || slot.end.is_some_and(|length: usize| -> (conflict: bool) ensures conflict == (end > length || (part.more && end >= length) || (!part.more && end != length)), { end > length || (part.more && end >= length) || (!part.more && end != length) }) {
            self.slots.remove(index);
            proof { self.removed(before_admission, index as int); }
            return None;
        }
        let slot = &mut self.slots[index];
        let ghost previous = *slot;
        if !codec::add(&mut slot.buffer, part.offset, part.more, &part.payload) {
            self.slots.remove(index);
            proof { self.removed(before_admission, index as int); }
            return None;
        }
        slot.ranges.push((part.offset, end));
        slot.layout.chunk = slot.layout.chunk.max(part.layout.chunk);
        if !part.more { slot.end = Some(end); }
        proof {
            assert(slot.layout.valid());
            assert(slot.ranges@.len() <= 64);
            assert(codec::bounded(slot.buffer));
            assert(codec::intervals(slot.buffer) <= slot.ranges@.len());
            assert(codec::end(slot.buffer) == match slot.end { Some(length) => Some(length as nat), None => None });
            slot.received_image(previous, part.offset, end, part.payload@);
            assert(slot.valid());
        }
        let complete = codec::complete(&slot.buffer);
        proof { self.updated(before_admission, index as int); }
        if !complete { return None; }
        let ghost before_complete = *self;
        let slot = self.slots.remove(index);
        proof { self.removed(before_complete, index as int); }
        let payload = codec::finish(slot.buffer);
        if payload.is_empty() || payload.len() > 65_535 - (slot.layout.prefix - 40) { return None; }
        let mut bytes = slot.prefix;
        bytes[slot.layout.previous] = slot.layout.protocol;
        bytes.extend_from_slice(&payload);
        let length = bytes.len() - 40;
        packet::set_ipv6_length(bytes.as_mut_slice(), length as u16);
        Some((bytes, slot.layout))
    }
}

/// Recent fragment emission needed to translate even a non-first ICMP quote.
/// These records create no flow and cannot revive a retired NAT port.
pub(crate) struct Emission {
    /// Unique post-NAT identifier observed by the recipient.
    pub id: u32,
    /// Original pre-NAT identifier restored in a related error.
    pub original: u32,
    /// Existing mapped port whose current flow must still authorize the error.
    pub port: u16,
    /// Stable interface quota shared across address families and incarnations.
    pub quota: Ip,
    /// Recipient-side source address used to correlate the native quote.
    pub source: Ip,
    /// Recipient-side destination address used to correlate the native quote.
    pub destination: Ip,
    /// Native protocol immediately after the fragment header.
    pub protocol: u8,
    /// None for upstream emission; client emission retains its exact owner.
    pub client: Option<Owner>,
    /// Absolute short history lifetime, independent of traffic and NAT liveness.
    pub deadline: u64,
}

impl Emission {
    /// Normalized same-family quote endpoints and a stable accounting identity.
    pub(crate) open spec fn valid(&self) -> bool {
        self.quota.valid() && self.source.valid() && self.source.family() == 6
            && self.destination.valid() && self.destination.family() == 6
            && self.port >= crate::flow::FIRST && (self.client.is_some() ==> self.client.unwrap().valid())
    }
}

/// Fixed recent-error correlation budget; eviction loses only old error detail.
/// Data admission and NAT ownership remain in the existing flow table.
pub(crate) struct History {
    /// At most 1024 observations, with at most 256 per stable client key.
    entries: VecDeque<Emission>,
}

impl History {
    /// Both emission directions spend the same stable interface reservation.
    closed spec fn quota_count(&self, quota: Ip) -> nat {
        self.entries@.filter(|entry: Emission| entry.quota == quota).len()
    }

    /// Every record has normalized endpoints and one existing port reference.
    pub(crate) closed spec fn valid(&self) -> bool {
        self.entries@.len() <= crate::MAX_FLOWS
            && (forall|i: int| 0 <= i < self.entries@.len() ==> self.entries@[i].valid())
            && forall|quota: Ip| (#[trigger] self.quota_count(quota)) <= crate::CLIENT_FLOWS
    }

    /// Begin without an accepted fragment quote.
    pub(crate) fn new() -> (history: Self) ensures history.valid(),
    { Self { entries: VecDeque::new() } }

    /// Configuration replacement invalidates all old translated fragment bytes.
    pub(crate) fn clear(&mut self) requires old(self).valid(), ensures final(self).valid(),
    { self.entries.clear(); }

    /// Use exact std deletion correspondence for every stable client's quota.
    proof fn removed(&self, before: Self, index: int)
        requires before.valid(), 0 <= index < before.entries@.len(),
            self.entries@ == before.entries@.remove(index),
        ensures self.valid(), forall|quota: Ip| (#[trigger] self.quota_count(quota))
            + if before.entries@[index].quota == quota { 1int } else { 0int } == before.quota_count(quota),
    {
        before.entries@.remove_ensures(index);
        assert forall|quota: Ip| (#[trigger] self.quota_count(quota))
            + if before.entries@[index].quota == quota { 1int } else { 0int } == before.quota_count(quota) by {
            crate::library::filter_remove(before.entries@, index, |entry: Emission| entry.quota == quota);
        }
    }

    /// Retain a bounded recent observation, evicting only this client's oldest
    /// record at its quota. Global eviction affects error detail, never permission.
    pub(crate) fn record(&mut self, entry: Emission)
        requires old(self).valid(), entry.valid(),
        ensures final(self).valid(),
    {
        let selected = self.entries.iter().filter(|old: &&Emission| -> (same: bool)
            ensures same == (old.quota == entry.quota), { old.quota == entry.quota });
        let ghost selection = selected;
        let count = selected.count();
        proof {
            let keep = filter_keep(selection);
            assert(keep.len() == self.entries@.len());
            crate::library::filter_count(self.entries@.as_ref(), |i: int| keep[i], self.entries@, |old: Emission| old.quota == entry.quota);
            assert(count == self.quota_count(entry.quota));
        }
        if count >= crate::CLIENT_FLOWS {
            let Some(index) = self.entries.iter().position(|old: &Emission| -> (same: bool) ensures same == (old.quota == entry.quota), { old.quota == entry.quota }) else { return; };
            let ghost before = *self;
            self.entries.remove(index);
            proof { self.removed(before, index as int); }
        }
        proof { assert(self.quota_count(entry.quota) < crate::CLIENT_FLOWS); }
        if self.entries.len() == crate::MAX_FLOWS {
            let ghost before = *self;
            self.entries.pop_front();
            proof {
                assert(self.entries@ =~= before.entries@.remove(0));
                self.removed(before, 0);
            }
        }
        let ghost before = *self;
        self.entries.push_back(entry);
        proof {
            assert forall|quota: Ip| (#[trigger] self.quota_count(quota)) <= crate::CLIENT_FLOWS by {
                before.entries@.lemma_filter_len_push(|old: Emission| old.quota == quota, entry);
                if quota == entry.quota { assert(before.quota_count(quota) < crate::CLIENT_FLOWS); }
            }
        }
    }

    /// A recent native quote still needs the referenced flow's live-policy check.
    pub(crate) fn find(&self, quote: &packet::FragmentQuote, client: Option<Owner>, now: u64) -> (found: Option<&Emission>)
        requires self.valid(),
        ensures found.is_some() ==> found.unwrap().valid() && found.unwrap().client == client
            && found.unwrap().id == quote.id && found.unwrap().source == quote.source
            && found.unwrap().destination == quote.destination && found.unwrap().protocol == quote.protocol
            && found.unwrap().deadline > now,
    {
        self.entries.iter().rev().find(|entry: &&Emission| -> (same: bool)
            requires entry.valid(),
            ensures same == (entry.client == client && entry.id == quote.id
                && entry.source == quote.source && entry.destination == quote.destination
                && entry.protocol == quote.protocol && entry.deadline > now),
        { entry.client == client && entry.id == quote.id
            && entry.source == quote.source && entry.destination == quote.destination
            && entry.protocol == quote.protocol && entry.deadline > now })
    }
}

/// Emit one fragment at a time; queues retain at most one large datagram per
/// direction/client. Routers never fragment an initially unfragmented IPv6 input.
pub(crate) fn emit(bytes: &[u8], layout: Layout, cursor: usize) -> (fragment: Option<(Vec<u8>, usize)>)
    requires layout.valid(), layout.prefix < bytes@.len() <= wire::DATAGRAM_BYTES,
    ensures fragment.is_some() ==> fragment.unwrap().0@.len() <= MTU
        && cursor < fragment.unwrap().1 <= bytes@.len() - layout.prefix
        && (fragment.unwrap().1 < bytes@.len() - layout.prefix ==> fragment.unwrap().1 % 8 == 0),
{
    let payload = bytes.len() - layout.prefix;
    if cursor >= payload || !cursor.is_multiple_of(8) || layout.chunk == 0 { return None; }
    let count = layout.chunk;
    let end = cursor + count.min(payload - cursor);
    let mut fragment = slice_to_vec(&bytes[..layout.prefix]);
    let header = packet::fragment_header(layout.protocol, cursor, end < payload, layout.id);
    fragment.extend_from_slice(&header);
    fragment.extend_from_slice(&bytes[layout.prefix + cursor..layout.prefix + end]);
    fragment[layout.previous] = 44;
    let length = fragment.len() - 40;
    packet::set_ipv6_length(fragment.as_mut_slice(), length as u16);
    Some((fragment, end))
}

}
