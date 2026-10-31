//! Assigned address observations are parsed separately from identity authority.
//! Only the runtime's actual Netback owner can supply an authoritative lease.
//! Its private session borrows the owner and current control projection together,
//! so a raw domid, packet address or deserialized claim cannot create that session.

use alloc::vec::Vec;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::view::View as ValueView;

use crate::address::Ip;
use crate::control::Control;
use crate::projection::View;

verus! {

broadcast use { vstd::seq::group_seq_lemmas, vstd::seq_lib::group_seq_properties, vstd::seq::Seq::lemma_as_ref_index, crate::address::cut_unique, Ip::unique, crate::address::token_cut };

/// The native XenStore vif IP list: one or two addresses in either order,
/// with no repeated family. This remains validated data.
pub struct Assigned {
    /// Exactly the complete observed native address tokens, never packet claims.
    addresses: Vec<Ip>,
}

/// Complete native assigned text contains one or two address tokens, with at
/// most one per family. Empty tokens and trailing separators are invalid.
pub open spec fn assigned_text(bytes: Seq<u8>, addresses: Seq<Ip>) -> bool {
    0 < addresses.len() <= 2
        && (forall|i: int| 0 <= i < addresses.len() ==> addresses[i].valid())
        && (forall|i: int, j: int| 0 <= i < j < addresses.len() ==> addresses[i].family() != addresses[j].family())
        && if addresses.len() == 1 { addresses[0].describes(bytes) }
            else { exists|end: int| crate::address::cut(bytes, end, b' ') && end < bytes.len()
                && addresses[0].describes(bytes.subrange(0, end))
                && addresses[1].describes(bytes.subrange(end+1, bytes.len() as int)) }
}

/// One complete native assignment has a unique ordered normalized address set.
pub broadcast proof fn assigned_unique(bytes: Seq<u8>, left: Seq<Ip>, right: Seq<Ip>)
    requires #[trigger] assigned_text(bytes, left), #[trigger] assigned_text(bytes, right),
    ensures left == right,
{
    if left.len() == 1 {
        if right.len() == 2 {
            let end = choose|end: int| crate::address::cut(bytes, end, b' ') && end < bytes.len()
                && right[0].describes(bytes.subrange(0, end)) && right[1].describes(bytes.subrange(end+1, bytes.len() as int));
            crate::address::token_cut(left[0], bytes, end, b' ');
        }
        Ip::unique(left[0], right[0], bytes);
    } else {
        let end = choose|end: int| crate::address::cut(bytes, end, b' ') && end < bytes.len()
            && left[0].describes(bytes.subrange(0, end)) && left[1].describes(bytes.subrange(end+1, bytes.len() as int));
        if right.len() == 1 { crate::address::token_cut(right[0], bytes, end, b' '); }
        let other = choose|other: int| crate::address::cut(bytes, other, b' ') && other < bytes.len()
            && right[0].describes(bytes.subrange(0, other)) && right[1].describes(bytes.subrange(other+1, bytes.len() as int));
        crate::address::cut_unique(bytes, end, other, b' ');
        Ip::unique(left[0], right[0], bytes.subrange(0, end));
        Ip::unique(left[1], right[1], bytes.subrange(end+1, bytes.len() as int));
    }
    assert(left =~= right);
}

impl Assigned {
    /// The assigned set contains at most one address per family.
    pub closed spec fn valid(&self) -> bool {
        0 < self.addresses@.len() <= 2
            && (forall|i: int| 0 <= i < self.addresses@.len() ==> self.addresses@[i].valid())
            && (forall|i: int, j: int| 0 <= i < j < self.addresses@.len() ==> self.addresses@[i].family() != self.addresses@[j].family())
    }

    /// Exact normalized assigned addresses, not an authorization credential.
    pub closed spec fn addresses(&self) -> Seq<Ip> { self.addresses@ }

    /// Parse the complete private observation copied by the native driver.
    /// No caller-controlled address, including a valid one, grants authority.
    pub fn parse(bytes: &[u8]) -> (assigned: Option<Self>)
        ensures match assigned {
            Some(value) => value.valid() && assigned_text(bytes@, value.addresses()),
            None => !(exists|addresses: Seq<Ip>| assigned_text(bytes@, addresses)),
        },
    {
        proof { reveal(Ip::describes); }
        if bytes.is_empty() || bytes.len() > 91 { return None; }
        let split = bytes.iter().position(|byte: &u8| -> (found: bool) ensures found == (*byte == b' ') { *byte == b' ' }).unwrap_or(bytes.len());
        proof { assert(crate::address::cut(bytes@, split as int, b' ')); }
        proof { if split == bytes.len() { assert(bytes@.subrange(0, split as int) =~= bytes@); } }
        let first = Ip::parse(&bytes[..split])?;
        let mut addresses = Vec::new();
        addresses.push(first);
        if split < bytes.len() {
            let second = Ip::parse(&bytes[split+1..])?;
            if first.version() == second.version() { return None; }
            addresses.push(second);
        }
        let assigned = Self { addresses };
        proof {
            assert(assigned.valid());
            assert(assigned_text(bytes@, assigned.addresses()));
        }
        Some(assigned)
    }

    /// Borrow the exact assigned address set for current membership/policy checks.
    pub fn all(&self) -> (addresses: &[Ip])
        requires self.valid(), ensures addresses@ == self.addresses(),
            0 < addresses@.len() <= 2,
            forall|i: int| 0 <= i < addresses@.len() ==> addresses@[i].valid(),
    { self.addresses.as_slice() }

    /// Preserve exact normalized address correspondence across a read barrier.
    pub fn same(&self, other: &Self) -> (same: bool)
        requires self.valid(), other.valid(),
        ensures same == (self.addresses() == other.addresses()),
    {
        if self.addresses.len() != other.addresses.len() { return false; }
        let mut i = 0;
        while i < self.addresses.len()
            invariant self.valid(), other.valid(), i <= self.addresses.len() == other.addresses.len(),
                forall|j: int| 0 <= j < i ==> self.addresses@[j] == other.addresses@[j],
            decreases self.addresses.len()-i,
        {
            if !self.addresses[i].same(&other.addresses[i]) { return false; }
            i += 1;
        }
        proof { assert(self.addresses@ =~= other.addresses@); }
        true
    }

    /// Require current membership and a complete installable snapshot for every
    /// assigned family. This is only a data decision: the adapter additionally
    /// binds it to the same live interface and current control generation.
    pub fn eligible(&self, view: &View) -> (eligible: bool)
        requires self.valid(), view.valid(),
        ensures eligible == (view.configuration_value().is_some()
            && (forall|i: int| 0 <= i < self.addresses().len()
                ==> view.member_ready(self.addresses()[i]))),
    {
        let config = match view.config() { Some(value) => value, None => return false };
        let mut i = 0;
        while i < self.addresses.len()
            invariant self.valid(), view.valid(), i <= self.addresses.len() <= 2,
                config.valid(), view.configuration_value() == Some(*config),
                forall|j: int| 0 <= j < i ==> view.member_ready(self.addresses@[j]),
            decreases self.addresses.len()-i,
        {
            if !config.contains(&self.addresses[i]) || view.policy(&self.addresses[i]).is_none() {
                proof {
                    assert(!view.member_ready(self.addresses@[i as int]));
                    assert(self.addresses()[i as int] == self.addresses@[i as int]);
                    assert(exists|j: int| 0 <= j < self.addresses().len() && !view.member_ready(self.addresses()[j]));
                }
                return false;
            }
            i += 1;
        }
        true
    }
}

/// One pending data decision tied to exact observed connection/interface labels.
/// Only an effect adapter holding those actual owners may turn its accepted
/// result into operation authority. Labels supplied as ordinary data are claims.
pub struct Request {
    /// Nonreused native connection label captured before the barrier request.
    connection: u32,
    /// Nonreused native interface label captured from its actual assignment.
    lease: u32,
    /// Exact selected peer, independent of its self-declared packet source.
    peer: u16,
    /// Native FIFO barrier selected internally by the control owner.
    serial: u32,
    /// Exact private assigned set captured before requesting the read barrier.
    assigned: Assigned,
}

impl Request {
    /// Exact normalized addresses captured for this interface lifetime.
    pub closed spec fn assigned_value(&self) -> Assigned { self.assigned }

    /// Captured request remains bounded and all labels are nonzero real ranges.
    pub closed spec fn valid(&self) -> bool {
        self.connection > 0 && self.lease > 0 && self.serial > 0
            && 0 < self.peer < 0x7ff0 && self.assigned.valid()
    }

    /// Exact captured correlation labels and normalized address observations.
    pub closed spec fn labels(&self) -> (u32, u32, u16, u32) {
        (self.connection, self.lease, self.peer, self.serial)
    }

    /// Native barrier label, useful only with this still-owned request.
    pub fn serial(&self) -> (serial: u32)
        requires self.valid(), ensures serial == self.labels().3,
    { self.serial }

    /// Successful initial binding needs complete assigned data, all current
    /// source snapshots and a legal idle native barrier. Ordinary observations
    /// alone still cannot supply the adapter's actual resource owners.
    pub closed spec fn can_begin(control: Control, connection: u32, lease: u32, peer: u16, bytes: Seq<u8>) -> bool {
        connection > 0 && lease > 0 && 0 < peer < 0x7ff0
            && exists|assigned: Assigned, snapshot: crate::policy::Snapshot|
                assigned.valid() && assigned_text(bytes, assigned.addresses())
                    && control.view().configuration_value().is_some()
                    && (forall|i: int| 0 <= i < assigned.addresses().len() ==> control.view().member_ready(assigned.addresses()[i]))
                    && control.view().published(snapshot) && snapshot.source_value() == assigned.addresses()[0]
                    && control.can_barrier(snapshot.root_value())
    }

    /// Parse the actual interface assignment, require currently usable policy,
    /// and select one native FIFO barrier after the assignment was observed.
    /// No domain/lease is manufactured: their physical correspondence is the
    /// narrow adapter's obligation, independently of this data transition.
    pub fn begin(control: &mut Control, connection: u32, lease: u32, peer: u16, bytes: &[u8]) -> (request: Option<Self>)
        requires old(control).valid(), bytes@.len() <= 128,
        ensures final(control).valid(), request.is_some() == Self::can_begin(*old(control), connection, lease, peer, bytes@),
            request.is_some() ==> request.unwrap().valid()
            && request.unwrap().labels().0 == connection && request.unwrap().labels().1 == lease
            && request.unwrap().labels().2 == peer && assigned_text(bytes@, request.unwrap().assigned_value().addresses()),
    {
        broadcast use assigned_unique;
        if connection == 0 || lease == 0 || peer == 0 || peer >= 0x7ff0 { return None; }
        let assigned = Assigned::parse(bytes)?;
        if !assigned.eligible(control.projection()) { return None; }
        let source = &assigned.all()[0];
        let snapshot = control.projection().policy(source)?;
        let root = vstd::slice::slice_to_vec(snapshot.root());
        let serial = control.barrier(root.as_slice())?;
        Some(Self { connection, lease, peer, serial, assigned })
    }

    /// Complete data acceptance predicate, independent of executable branches.
    pub closed spec fn accepts(&self, control: Control, connection: u32, lease: u32, peer: u16, bytes: Seq<u8>) -> bool {
        self.connection == connection && self.lease == lease && self.peer == peer
            && control.barrier_completed(self.serial) && assigned_text(bytes, self.assigned.addresses())
            && (forall|i: int| 0 <= i < self.assigned.addresses().len()
                ==> control.view().member_ready(self.assigned.addresses()[i]))
    }

    /// Consume the original request only after its native barrier completed.
    /// Exact labels, still-current assigned bytes and every source policy must
    /// agree. No previously completed but superseded barrier can authorize it.
    pub fn finish(self, control: &Control, connection: u32, lease: u32, peer: u16, bytes: &[u8]) -> (bound: Option<Bound>)
        requires self.valid(), control.valid(), bytes@.len() <= 128,
        ensures match bound {
            Some(value) => value.valid() && value.labels() == (connection, lease, peer)
                && assigned_text(bytes@, value.assigned_value().addresses())
                && value.assigned_value().addresses() == self.assigned_value().addresses()
                && self.labels().0 == connection && self.labels().1 == lease && self.labels().2 == peer
                && control.barrier_completed(self.labels().3)
                && (forall|i: int| 0 <= i < value.assigned_value().addresses().len() ==> control.view().member_ready(value.assigned_value().addresses()[i])),
            None => !self.accepts(*control, connection, lease, peer, bytes@),
        },
    {
        broadcast use assigned_unique;
        if self.connection != connection || self.lease != lease || self.peer != peer || !control.completed(self.serial) { return None; }
        let assigned = Assigned::parse(bytes)?;
        if !assigned.same(&self.assigned) || !assigned.eligible(control.projection()) { return None; }
        Some(Bound { connection, lease, peer, assigned })
    }
}

/// A completed binding decision, reusable only with its exact actual owners
/// and current policy. A packet operation still needs runtime borrowing of both
/// owners; this data certificate by itself cannot access any Xen resource.
pub struct Bound {
    /// Exact nonreused native control connection whose barrier completed.
    connection: u32,
    /// Exact nonreused native interface incarnation, never a raw domid alone.
    lease: u32,
    /// Selected peer retained with that actual kernel owner.
    peer: u16,
    /// Complete fixed assigned addresses observed on both sides of the barrier.
    assigned: Assigned,
}

impl Bound {
    /// Exact normalized addresses captured for this interface lifetime.
    pub closed spec fn assigned_value(&self) -> Assigned { self.assigned }

    /// Typed assigned data and nonzero labels from one successful native barrier.
    pub closed spec fn valid(&self) -> bool {
        self.connection > 0 && self.lease > 0 && 0 < self.peer < 0x7ff0 && self.assigned.valid()
    }

    /// Exact control/interface/peer correlation from the completed request.
    pub closed spec fn labels(&self) -> (u32, u32, u16) { (self.connection, self.lease, self.peer) }

    /// Copy lifetime labels for bounded packet state, never native authority.
    pub fn identity(&self) -> (identity: (u32, u32, u16))
        requires self.valid(), ensures identity == self.labels(), identity.0 > 0 && identity.1 > 0
            && 0 < identity.2 < 0x7ff0,
    { (self.connection, self.lease, self.peer) }

    /// Read exact source address data for packet anti-spoofing after permission.
    pub fn assigned(&self) -> (assigned: &Assigned)
        requires self.valid(), ensures assigned.valid(), *assigned == self.assigned_value(),
    { &self.assigned }

    /// Check the original owners and current source policies for each operation.
    /// This needs no new QubesDB barrier: the original interface cannot become a
    /// new incarnation, and native progress rechecks its driver-owned marker on
    /// backend-node change. Cached flows still recheck the current generation.
    pub fn eligible(&self, control: &Control, connection: u32, lease: u32, peer: u16) -> (eligible: bool)
        requires self.valid(), control.valid(),
        ensures eligible == (self.labels() == (connection, lease, peer)
            && control.view().configuration_value().is_some()
            && (forall|i: int| 0 <= i < self.assigned_value().addresses().len()
                ==> control.view().member_ready(self.assigned_value().addresses()[i]))),
    {
        if self.connection != connection || self.lease != lease || self.peer != peer { return false; }
        let view = control.projection();
        let eligible = self.assigned.eligible(view);
        proof {
            assert(*view == control.view());
            assert(self.assigned_value() == self.assigned);
            assert(eligible == (view.configuration_value().is_some()
                && (forall|i: int| 0 <= i < self.assigned.addresses().len()
                    ==> view.member_ready(self.assigned.addresses()[i]))));
            assert(self.labels() == (connection, lease, peer));
            assert(eligible == (control.view().configuration_value().is_some()
                && forall|i: int| 0 <= i < self.assigned_value().addresses().len()
                    ==> control.view().member_ready(self.assigned_value().addresses()[i])));
        }
        eligible
    }
}

}
