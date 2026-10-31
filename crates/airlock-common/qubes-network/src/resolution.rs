//! Bounded DNS data associated with one exact completed policy observation.
//! These values create no transport/interface authority. The firewall resolver
//! checks the native server, outstanding query, name and complete response before
//! supplying them; this layer checks every hostname obligation before activation.

use alloc::vec::Vec;
use vstd::prelude::*;
use vstd::slice::slice_to_vec;

use crate::address::Ip;
use crate::policy::{MAX_RULES, Ordered, Snapshot};
use crate::rule::Hostname;

verus! {

broadcast use { vstd::seq::group_seq_lemmas, vstd::seq_lib::group_seq_properties, vstd::seq::Seq::lemma_as_ref_index, vstd::slice::group_slice_axioms };

/// Maximum retained addresses for one name in a complete source policy.
pub const MAX_ANSWERS: usize = 16;

/// Positive answers for one exact native hostname spelling and one source family.
pub struct NameAnswers {
    /// Validated original spelling; DNS matching itself is case-insensitive.
    name: Hostname,
    /// Nonempty bounded normalized addresses returned by the selected DNS server.
    addresses: Vec<Ip>,
    /// Absolute monotonic expiry, including the shortest followed CNAME TTL.
    expires: u64,
}

impl NameAnswers {
    /// Accept a complete positive bounded answer set; empty/family-mixed results
    /// cannot silently turn an unresolved drop rule into a matches-none rule.
    pub fn new(name: &[u8], addresses: Vec<Ip>, expires: u64, now: u64, family: u8) -> (answer: Option<Self>)
        requires forall|i: int| 0 <= i < addresses@.len() ==> addresses@[i].valid(),
        ensures answer.is_some() ==> answer.unwrap().valid()
            && answer.unwrap().name_value() == name@ && answer.unwrap().address_values() == addresses@
            && answer.unwrap().expiry() == expires && expires > now
            && answer.unwrap().address_values()[0].family() == family,
    {
        let name = Hostname::parse(name)?;
        if addresses.is_empty() || addresses.len() > MAX_ANSWERS || expires <= now { return None; }
        if family != 4 && family != 6 { return None; }
        let mut i = 0;
        while i < addresses.len()
            invariant i <= addresses.len() <= MAX_ANSWERS,
                forall|j: int| 0 <= j < addresses@.len() ==> addresses@[j].valid(),
                forall|j: int| 0 <= j < i ==> addresses@[j].family() == family,
            decreases addresses.len()-i,
        {
            if addresses[i].version() != family { return None; }
            i += 1;
        }
        Some(Self { name, addresses, expires })
    }

    /// Every retained answer has a validated name and finite nonempty address set.
    pub closed spec fn valid(&self) -> bool {
        self.name.valid() && 0 < self.addresses@.len() <= MAX_ANSWERS && self.expires > 0
            && (forall|i: int| 0 <= i < self.addresses@.len() ==> self.addresses@[i].valid()
                && self.addresses@[i].family() == self.addresses@[0].family())
    }

    /// Original validated hostname, independent of presentation case.
    pub closed spec fn name_value(&self) -> Seq<u8> { self.name.bytes() }

    /// Exact positive normalized addresses owned by this answer.
    pub closed spec fn address_values(&self) -> Seq<Ip> { self.addresses@ }

    /// Absolute monotonic expiry, with zero never a valid answer lifetime.
    pub closed spec fn expiry(&self) -> u64 { self.expires }

    /// Exact original hostname bytes to correlate repeated native rules.
    pub fn name(&self) -> (name: &[u8])
        requires self.valid(), ensures name@ == self.name_value(),
    { self.name.name() }

    /// Borrow positive addresses; callers still enforce the owning policy epoch.
    pub fn addresses(&self) -> (addresses: &[Ip])
        requires self.valid(), ensures addresses@ == self.address_values(), 0 < addresses@.len() <= MAX_ANSWERS,
            forall|i: int| 0 <= i < addresses@.len() ==> addresses@[i].valid(),
    { self.addresses.as_slice() }
}

/// Locate one exact original policy name using the standard slice iterator.
fn answer_index(answers: &[NameAnswers], name: &[u8]) -> (index: Option<usize>)
    requires answers@.len() <= MAX_RULES, forall|i: int| 0 <= i < answers@.len() ==> answers@[i].valid(),
    ensures match index {
        Some(i) => i < answers@.len() && answers@[i as int].name_value() == name@,
        None => forall|i: int| 0 <= i < answers@.len() ==> answers@[i].name_value() != name@,
    },
{
    answers.iter().position(|answer: &NameAnswers| -> (same: bool)
        requires answer.valid(), ensures same == (answer.name_value() == name@),
    {
        let bytes = answer.name();
        let same = bytes.eq(name);
        proof {
            assert(<[u8] as vstd::std_specs::cmp::PartialEqSpec<[u8]>>::obeys_eq_spec());
            assert(same == <[u8] as vstd::std_specs::cmp::PartialEqSpec<[u8]>>::eq_spec(bytes, name));
            assert(same ==> bytes@ =~= name@);
            assert(!same ==> bytes@ != name@);
        }
        same
    })
}

/// Whether one native rule name is present in this complete source.
fn mentioned(snapshot: &Snapshot, name: &[u8]) -> (present: bool)
    requires snapshot.valid(),
    ensures present == (exists|i: int| 0 <= i < snapshot.rules_value().len()
        && snapshot.rules_value()[i].rule().host_value().is_some()
        && snapshot.rules_value()[i].rule().host_value().unwrap().bytes() == name@),
{
    snapshot.rules().iter().any(|entry: &Ordered| -> (present: bool)
        requires entry.rule().valid(),
        ensures present == (entry.rule().host_value().is_some()
            && entry.rule().host_value().unwrap().bytes() == name@),
    { match entry.entry().host() {
        Some(host) => {
            let bytes = host.name();
            let same = bytes.eq(name);
            proof { assert(same ==> bytes@ =~= name@); assert(!same ==> bytes@ != name@); }
            same
        },
        None => false,
    } })
}

/// Whole-policy hostname coverage, independent of rule disposition or position.
closed spec fn coverage(snapshot: Snapshot, answers: Seq<NameAnswers>) -> bool {
    forall|i: int| 0 <= i < snapshot.rules_value().len() && snapshot.rules_value()[i].rule().host_value().is_some() ==>
        exists|j: int| 0 <= j < answers.len() && answers[j].name_value() == snapshot.rules_value()[i].rule().host_value().unwrap().bytes()
}

/// Check every hostname obligation using the same bounded standard lookups.
fn covered(snapshot: &Snapshot, answers: &[NameAnswers]) -> (covered: bool)
    requires snapshot.valid(), answers@.len() <= MAX_RULES,
        forall|i: int| 0 <= i < answers@.len() ==> answers@[i].valid(),
    ensures covered == coverage(*snapshot, answers@),
{
    snapshot.rules().iter().all(|entry: &Ordered| -> (covered: bool)
        requires entry.rule().valid(),
        ensures covered == (entry.rule().host_value().is_none() || exists|j: int| 0 <= j < answers@.len()
            && answers@[j].name_value() == entry.rule().host_value().unwrap().bytes()),
    { match entry.entry().host() { Some(host) => answer_index(answers, host.name()).is_some(), None => true } })
}

/// All hostname obligations resolved for one source at one control revision.
/// The view consumes this value only if its original revision is still current.
pub struct Resolved {
    /// Exact normalized source owning the completed native snapshot.
    source: Ip,
    /// Exact root spelling prevents address aliases from sharing completions.
    root: Vec<u8>,
    /// Observation revision captured before scheduling any DNS work.
    revision: u64,
    /// One answer set per distinct original hostname, bounded by rule count.
    answers: Vec<NameAnswers>,
}

impl Resolved {
    /// Finite owned DNS data, with no authority to select a network interface.
    pub closed spec fn valid(&self) -> bool {
        self.source.valid() && self.root@.len() < 64 && self.revision > 0
            && 0 < self.answers@.len() <= MAX_RULES
            && (forall|i: int| 0 <= i < self.answers@.len() ==> self.answers@[i].valid()
                && self.answers@[i].address_values()[0].family() == self.source.family())
            && (forall|i: int, j: int| 0 <= i < j < self.answers@.len() ==>
                self.answers@[i].name_value() != self.answers@[j].name_value())
    }

    /// The answer collection covers every hostname in this exact source policy.
    pub closed spec fn matches(&self, snapshot: Snapshot) -> bool {
        self.valid() && snapshot.valid() && self.source == snapshot.source_value() && self.root@ == snapshot.root_value()
            && coverage(snapshot, self.answers@)
    }

    /// Construct complete resolution data, rejecting missing, duplicate, stale,
    /// extraneous or wrong-family answers before any publication gate can open.
    pub fn new(snapshot: &Snapshot, revision: u64, answers: Vec<NameAnswers>, now: u64) -> (resolved: Option<Self>)
        requires snapshot.valid(), forall|i: int| 0 <= i < answers@.len() ==> answers@[i].valid(),
        ensures resolved.is_some() ==> resolved.unwrap().valid() && resolved.unwrap().matches(*snapshot)
            && resolved.unwrap().revision_value() == revision && resolved.unwrap().unexpired(now)
            && resolved.unwrap().source_value() == snapshot.source_value(),
    {
        if revision == 0 || answers.is_empty() || answers.len() > MAX_RULES { return None; }
        let mut i = 0;
        while i < answers.len()
            invariant snapshot.valid(), 0 < revision, 0 < answers@.len() <= MAX_RULES, i <= answers@.len(),
                forall|j: int| 0 <= j < answers@.len() ==> answers@[j].valid(),
                forall|j: int| 0 <= j < i ==> answers@[j].expiry() > now
                    && answers@[j].address_values()[0].family() == snapshot.source_value().family(),
                forall|j: int, k: int| 0 <= j < k < i ==> answers@[j].name_value() != answers@[k].name_value(),
            decreases answers.len() - i,
        {
            let answer = &answers[i];
            if answer.expires <= now || answer.addresses[0].version() != snapshot.source().version() { return None; }
            let prefix = &answers[..i];
            if answer_index(prefix, answer.name()).is_some() || !mentioned(snapshot, answer.name()) { return None; }
            proof {
                assert forall|j: int, k: int| 0 <= j < k < i + 1
                    implies answers@[j].name_value() != answers@[k].name_value() by {
                    if k == i { assert(prefix@[j] == answers@[j]); }
                }
            }
            i += 1;
        }
        if !covered(snapshot, answers.as_slice()) { return None; }
        Some(Self { source: *snapshot.source(), root: slice_to_vec(snapshot.root()), revision, answers })
    }

    /// Revision captured before scheduling any DNS work for this source.
    pub closed spec fn revision_value(&self) -> u64 { self.revision }

    /// Exact policy source owning all retained names.
    pub closed spec fn source_value(&self) -> Ip { self.source }

    /// Mathematical whole-source TTL condition.
    pub closed spec fn unexpired(&self, now: u64) -> bool {
        0 < self.answers@.len() && forall|i: int| 0 <= i < self.answers@.len() ==> self.answers@[i].expiry() > now
    }

    /// Original control revision; data from a replaced policy cannot activate it.
    pub fn revision(&self) -> (revision: u64)
        requires self.valid(), ensures revision == self.revision_value(),
    { self.revision }

    /// Original exact source, independently of packet source claims.
    pub fn source(&self) -> (source: &Ip)
        requires self.valid(), ensures source.valid(), *source == self.source_value(),
    { &self.source }

    /// Check the complete policy and current monotonic time before publication.
    pub fn applies(&self, snapshot: &Snapshot, now: u64) -> (applies: bool)
        requires self.valid(), snapshot.valid(),
        ensures applies == (self.matches(*snapshot) && self.unexpired(now)),
    {
        if !self.source.same(snapshot.source()) || !self.fresh(now) { return false; }
        let left = self.root.as_slice();
        let right = snapshot.root();
        let same = left.eq(right);
        proof { assert(same ==> left@ =~= right@); assert(!same ==> left@ != right@); }
        same && covered(snapshot, self.answers.as_slice())
    }

    /// Every obligation must remain positive and unexpired for the whole source.
    pub fn fresh(&self, now: u64) -> (fresh: bool)
        requires self.valid(), ensures fresh == self.unexpired(now),
    {
        !self.answers.is_empty() && self.answers.iter().all(|answer: &NameAnswers| -> (fresh: bool)
            ensures fresh == (answer.expiry() > now),
        { answer.expires > now })
    }

    /// A fresh same-name answer contains this exact normalized destination.
    pub closed spec fn contains(&self, name: Seq<u8>, destination: Ip, now: u64) -> bool {
        self.unexpired(now) && exists|i: int| 0 <= i < self.answers@.len()
            && self.answers@[i].name_value() == name && self.answers@[i].address_values().contains(destination)
    }

    /// Exact owned answer collection for caller-visible specification results.
    pub closed spec fn answer_values(&self) -> Seq<NameAnswers> { self.answers@ }

    /// Resolve the exact hostname retained by the native rule; absence is an error
    /// for the whole source rather than permission to skip that rule.
    pub fn addresses(&self, name: &[u8], now: u64) -> (addresses: Option<&[Ip]>)
        requires self.valid(),
        ensures match addresses {
            Some(values) => self.unexpired(now) && 0 < values@.len() <= MAX_ANSWERS
                && (forall|i: int| 0 <= i < values@.len() ==> values@[i].valid())
                && (exists|j: int| 0 <= j < self.answer_values().len() && self.answer_values()[j].name_value() == name@
                    && values@ == self.answer_values()[j].address_values())
                && (forall|destination: Ip| self.contains(name@, destination, now) == values@.contains(destination)),
            None => (!self.unexpired(now) || forall|j: int| 0 <= j < self.answer_values().len() ==> self.answer_values()[j].name_value() != name@)
                && (forall|destination: Ip| !self.contains(name@, destination, now)),
        },
    {
        if !self.fresh(now) { return None; }
        let index = answer_index(self.answers.as_slice(), name)?;
        let values = self.answers[index].addresses();
        proof {
            assert(self.answer_values()[index as int].name_value() == name@);
            assert(exists|j: int| 0 <= j < self.answer_values().len() && self.answer_values()[j].name_value() == name@
                && values@ == self.answer_values()[j].address_values());
        }
        proof {
            assert forall|destination: Ip| self.contains(name@, destination, now) == values@.contains(destination) by {
                if self.contains(name@, destination, now) {
                    let j = choose|j: int| 0 <= j < self.answers@.len() && self.answers@[j].name_value() == name@
                        && self.answers@[j].address_values().contains(destination);
                    assert(j == index);
                }
            }
        }
        Some(values)
    }
}

}
