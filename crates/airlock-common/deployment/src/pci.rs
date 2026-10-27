//! Bound network-device handoff to the checked endpoints and a complete observed snapshot.
//! Qubes supplies assignments and attachments separately; neither is inferred from display text.
//!
//! ## Network PCI handoff
//!
//! The [PCI boundary](crate::pci) retains the specific checked source and destination
//! fields, rather than accepting a pair from the caller at dispatch. Only the existing
//! assistant/network-provider transfer is supported. Snapshot validation checks every
//! physical network function and both persistent assignments and live attachments,
//! including undeclared frontends. Foreign or conflicting owners, broad port wildcards,
//! missing network functions and unsupported endpoints yield no executable handoff.
//! The complete snapshot is checked before the first mutation, so a later conflict
//! cannot follow an earlier unassignment.
//!
//! Selection is proved exact: a request exists precisely for a persistent source-owned
//! row matching a current dom0 network function. Network class is specified numerically;
//! matching preserves backend, port and hardware identity. Future device-specific rules
//! which do not match current hardware, other PCI classes and current attachments never
//! become unassignment requests. Recovery may accept an already unassigned no-op; it
//! cannot relax ownership, change endpoints or bypass the operation/attempt/authority/
//! complete-plan binding and executing publication gate.
//!
//! The [Qubes adapter](../../../runtime/airlock-dom0/service/src/qubes/pci.rs) queries all registered
//! frontends, validates identity consistency and encodes the selected virtual assignment
//! for the upstream [device API](https://github.com/QubesOS/qubes-core-admin-client/blob/v4.3.30/qubesadmin/devices.py).
//! It preserves wildcard device identity rather than resolving it to the current device.
//! Wire decoding, sysfs/Qubes completeness, transport encoding and faithful external
//! execution remain trusted and tested Rust. The snapshot is not atomic with external
//! administrators or hotplug. Unassignment changes persistent policy, not proof of physical
//! detachment; quiescence and subsequent device reconciliation retain their existing
//! coordinator rules. Raw deployment `qvm-device`/`qvm-pci` mutations are blocked by the
//! process adapter; boot/manual setup keeps its separate policy. The separate assignment boundary below checks native deployment configuration; boot/manual setup keeps its compatibility path.

use crate::{
    effects::{self, Targets},
    operation::{DurableOperation, ExecutionContext, PlanBinding},
};
use vstd::prelude::*;

verus! {

/// A dom0 PCI function observed through sysfs and Qubes' Available interface.
pub struct Device {
    /// Exact Qubes port, without a backend prefix.
    pub port: String,
    /// Current hardware identity reported by Qubes, not an assignment wildcard.
    pub identity: String,
    /// Numeric 24-bit PCI class from sysfs.
    pub class: u32,
}

/// Persistent assignment and current attachment are independent observations.
#[derive(Clone, Copy)]
pub enum Kind {
    /// A persistent assignment which may be removed by handoff.
    Assigned,
    /// A current attachment which constrains ownership but grants no unassignment.
    Attached,
}

/// One raw row from a named frontend's structured device interface.
pub struct Usage {
    /// Registered frontend under which this row was queried.
    pub owner: String,
    /// Device backend, normally dom0 for physical PCI functions.
    pub backend: String,
    /// Exact assignment port, or the Qubes wildcard.
    pub port: String,
    /// Exact assignment device identity, or the Qubes wildcard.
    pub identity: String,
    /// Upstream attachment mode as reported by the structured API.
    pub mode: String,
    /// Exact assignment options, independent of human display formatting.
    pub options: Vec<crate::devices::OptionValue>,
    /// Whether the row describes persistent or current use.
    pub kind: Kind,
}

/// Network class is defined numerically, independently of human-readable device descriptions.
pub open spec fn network(d: Device) -> bool { 0x020000 <= d.class && d.class < 0x030000 }

fn is_network(d: &Device) -> (yes: bool)
    ensures yes == network(*d),
{ d.class >= 0x020000 && d.class < 0x030000 }

/// Qubes virtual-device matching, restricted to physical dom0 network functions.
pub open spec fn matches_device(d: Device, u: Usage) -> bool {
    network(d) && u.backend@ == "dom0"@
        && (u.port@ == d.port@ || u.port@ == "*"@)
        && (u.identity@ == d.identity@ || u.identity@ == "*"@)
}

fn matches(d: &Device, u: &Usage) -> (yes: bool)
    ensures yes == matches_device(*d, *u),
{
    is_network(d) && u.backend.as_str() == "dom0" && (u.port.as_str() == d.port.as_str() || u.port.as_str() == "*")
        && (u.identity.as_str() == d.identity.as_str() || u.identity.as_str() == "*")
}

/// No matched assignment can cover other ports, and all current/persistent owners agree.
pub open spec fn safe_device(d: Device, uses: Seq<Usage>, from: Seq<char>, to: Seq<char>) -> bool {
    &&& forall|i: int| 0 <= i < uses.len() && #[trigger] matches_device(d, uses[i]) ==>
        uses[i].port@ != "*"@ && (uses[i].owner@ == from || uses[i].owner@ == to)
    &&& forall|i: int, j: int| 0 <= i < uses.len() && 0 <= j < uses.len()
        && #[trigger] matches_device(d, uses[i]) && #[trigger] matches_device(d, uses[j]) ==>
        uses[i].owner@ == uses[j].owner@
}

/// Validate a full port before any effect; a later conflicting row cannot follow a mutation.
fn check_device(d: &Device, uses: &[Usage], from: &str, to: &str) -> (yes: bool)
    ensures yes ==> safe_device(*d, uses@, from@, to@),
{
    let mut owner: Option<&str> = None;
    let mut i = 0;
    while i < uses.len()
        invariant 0 <= i <= uses.len(),
            forall|j: int| 0 <= j < i && #[trigger] matches_device(*d, uses[j]) ==>
                uses[j].port@ != "*"@ && (uses[j].owner@ == from@ || uses[j].owner@ == to@)
                && owner.is_some() && uses[j].owner@ == owner.unwrap()@,
        decreases uses.len() - i,
    {
        let u = &uses[i];
        if matches(d, u) {
            if u.port.as_str() == "*" || (u.owner.as_str() != from && u.owner.as_str() != to) { return false; }
            if owner.is_some() && owner.unwrap() != u.owner.as_str() { return false; }
            proof {
                assert forall|j: int| 0 <= j < i && #[trigger] matches_device(*d, uses[j]) implies uses[j].owner@ == u.owner@ by {
                    if matches_device(*d, uses[j]) { assert(owner.is_some()); }
                }
            }
            owner = Some(u.owner.as_str());
        }
        i += 1;
    }
    true
}

/// A selected assignment is exactly a persistent row matching a current network function.
pub open spec fn relevant(devices: Seq<Device>, u: Usage) -> bool {
    exists|j: int| 0 <= j < devices.len() && #[trigger] matches_device(devices[j], u)
}

fn relevant_usage(devices: &[Device], u: &Usage) -> (yes: bool)
    ensures yes == relevant(devices@, *u),
{
    let mut i = 0;
    while i < devices.len()
        invariant 0 <= i <= devices.len(),
            forall|j: int| 0 <= j < i ==> !#[trigger] matches_device(devices[j], *u),
        decreases devices.len() - i,
    {
        if matches(&devices[i], u) { return true; }
        i += 1;
    }
    false
}

/// Complete device and frontend snapshots; constructing observations supplies no execution authority.
pub struct Observation {
    /// All physical PCI functions, with network class interpreted by verified Rust.
    pub devices: Vec<Device>,
    /// All assignments and attachments, including undeclared frontends.
    pub uses: Vec<Usage>,
}

/// Exact observed ownership constraints, without assuming that a prior phase completed.
pub open spec fn safe(o: Observation, from: Seq<char>, to: Seq<char>) -> bool {
    &&& exists|j: int| 0 <= j < o.devices.len() && #[trigger] network(o.devices[j])
    &&& forall|j: int| 0 <= j < o.devices.len() ==> #[trigger] safe_device(o.devices[j], o.uses@, from, to)
}

/// Only the existing assistant/network-provider transfer has automatic handoff semantics.
pub open spec fn supported(from: Seq<char>, to: Seq<char>) -> bool {
    (from == "usr-assistant"@ && to == "sys-net"@) || (from == "sys-net"@ && to == "usr-assistant"@)
}

/// Snapshot whose complete ownership constraints passed; still not executable on its own.
pub struct CheckedObservation {
    // Exact snapshot validated before the first unassignment.
    observed: Observation,
    // Supported original source used for ownership checks.
    from: String,
    // Supported destination used for ownership checks.
    to: String,
}

impl View for CheckedObservation {
    type V = (Observation, Seq<char>, Seq<char>);

    closed spec fn view(&self) -> Self::V { (self.observed, self.from@, self.to@) }
}

impl Observation {
    /// Check all devices and both kinds of ownership before allowing any request construction.
    /// Recovery permits an already unassigned no-op; it never relaxes ownership constraints.
    pub fn check(self, from: String, to: String, recovery: bool) -> (out: Option<CheckedObservation>)
        ensures out.is_some() ==> out.unwrap()@ == (self, from@, to@)
            && supported(from@, to@) && safe(self, from@, to@),
        out.is_some() && !recovery ==> exists|i: int| 0 <= i < self.uses.len()
            && self.uses[i].kind is Assigned && #[trigger] relevant(self.devices@, self.uses[i]),
    {
        if !((from.as_str() == "usr-assistant" && to.as_str() == "sys-net") || (from.as_str() == "sys-net" && to.as_str() == "usr-assistant")) { return None; }
        let mut found = false;
        let mut i = 0;
        while i < self.devices.len()
            invariant 0 <= i <= self.devices.len(),
                found == (exists|j: int| 0 <= j < i && #[trigger] network(self.devices[j])),
                forall|j: int| 0 <= j < i ==> #[trigger] safe_device(self.devices[j], self.uses@, from@, to@),
            decreases self.devices.len() - i,
        {
            if !check_device(&self.devices[i], self.uses.as_slice(), from.as_str(), to.as_str()) { return None; }
            found = found || is_network(&self.devices[i]);
            i += 1;
        }
        if !found { return None; }
        assert(safe(self, from@, to@));
        let mut assigned = false;
        let mut k = 0;
        while k < self.uses.len()
            invariant 0 <= k <= self.uses.len(), safe(self, from@, to@), supported(from@, to@),
                assigned == (exists|j: int| 0 <= j < k && self.uses[j].kind is Assigned && #[trigger] relevant(self.devices@, self.uses[j])),
            decreases self.uses.len() - k,
        {
            assigned = assigned || (matches!(self.uses[k].kind, Kind::Assigned) && relevant_usage(self.devices.as_slice(), &self.uses[k]));
            k += 1;
        }
        if !assigned && !recovery { return None; }
        Some(CheckedObservation { observed: self, from, to })
    }
}

/// Handoff endpoints retained from their specific classified plan fields.
pub struct HandoffPlan {
    // Source scope checked by the original approval.
    sources: Targets,
    // Destination scope checked by the same approval.
    targets: Targets,
    // Candidate, baseline, revision and complete-plan identity.
    binding: PlanBinding,
}

impl View for HandoffPlan {
    type V = (effects::Scope, effects::Scope, Seq<char>);

    closed spec fn view(&self) -> Self::V { (self.sources@, self.targets@, self.binding@) }
}

impl HandoffPlan {
    /// Retain both original fields rather than accepting endpoints at dispatch.
    pub(crate) fn new(sources: Targets, targets: Targets, binding: PlanBinding) -> (out: Self)
        ensures out@ == (sources@, targets@, binding@),
    { Self { sources, targets, binding } }

    /// Only one exact approved transfer can consume a validated observed snapshot.
    pub fn execution<'a>(&'a self, durable: &'a DurableOperation, context: &ExecutionContext,
        observed: &'a CheckedObservation) -> (out: Option<Handoff<'a>>)
        ensures out.is_some() ==> crate::operation::executing(durable, context) && self@.2 == context.plan@
            && self@.0.targets.len() == 1 && self@.1.targets.len() == 1
            && self@.0.targets[0]@ == observed@.1 && self@.1.targets[0]@ == observed@.2,
        out.is_some() ==> out.unwrap()@ == observed@,
        out.is_some() && effects::valid(self@.0) && self@.0.reviewed ==> self@.0.allowed.contains(observed@.1),
        out.is_some() && effects::valid(self@.1) && self@.1.reviewed ==> self@.1.allowed.contains(observed@.2),
    {
        if self.binding.as_str() != context.plan.as_str() || !durable.allows_effect(context) { return None; }
        let from = self.sources.names();
        let to = self.targets.names();
        if from.len() != 1 || to.len() != 1 || from[0] != observed.from || to[0] != observed.to { return None; }
        Some(Handoff { observed, _durable: durable })
    }
}

/// A complete checked handoff, borrowing the exact durable execution gate.
pub struct Handoff<'a> {
    // Full snapshot with checked endpoint ownership.
    observed: &'a CheckedObservation,
    // Keep the gate borrowed until every selected request is dispatched.
    _durable: &'a DurableOperation,
}

impl<'a> View for Handoff<'a> {
    type V = (Observation, Seq<char>, Seq<char>);

    closed spec fn view(&self) -> Self::V { self.observed@ }
}

impl<'a> Handoff<'a> {
    /// Enumerate the exact snapshot, without exposing mutable rows.
    pub fn len(&self) -> (n: usize) ensures n == self@.0.uses.len(),
    { self.observed.observed.uses.len() }

    /// Whether the observation contains no device-use rows.
    pub fn is_empty(&self) -> (yes: bool) ensures yes == (self@.0.uses.len() == 0),
    { self.len() == 0 }

    /// Select exactly a source-owned assignment to an observed network function.
    pub fn request(&self, index: usize) -> (out: Option<UnassignRequest<'_>>)
        ensures out.is_some() == (index < self@.0.uses.len()
            && self@.0.uses[index as int].kind is Assigned && self@.0.uses[index as int].owner@ == self@.1
            && relevant(self@.0.devices@, self@.0.uses[index as int])),
        out.is_some() ==> out.unwrap()@ == self@.0.uses[index as int],
        out.is_some() && safe(self@.0, self@.1, self@.2) ==> out.unwrap()@.port@ != "*"@ && out.unwrap()@.owner@ == self@.1,
    {
        if index >= self.observed.observed.uses.len() { return None; }
        let u = &self.observed.observed.uses[index];
        if !matches!(u.kind, Kind::Assigned) || u.owner != self.observed.from || !relevant_usage(self.observed.observed.devices.as_slice(), u) { return None; }
        proof {
            if safe(self@.0, self@.1, self@.2) {
                let j = choose|j: int| 0 <= j < self@.0.devices.len() && #[trigger] matches_device(self@.0.devices[j], *u);
                assert(safe_device(self@.0.devices[j], self@.0.uses@, self@.1, self@.2));
            }
        }
        Some(UnassignRequest { usage: u, _handoff: self })
    }
}

/// The Qubes adapter accepts this exact assignment; no independent owner or port is supplied.
///
/// ```compile_fail
/// use airlock_deployment_core::pci::{Usage, UnassignRequest};
/// fn adapter(_: UnassignRequest<'_>) {}
/// fn bypass(raw: Usage) { adapter(raw); }
/// ```
pub struct UnassignRequest<'a> {
    // Actual matching persistent row, including wildcard device identity.
    usage: &'a Usage,
    // Preserve the validated snapshot and durable gate throughout dispatch.
    _handoff: &'a Handoff<'a>,
}

impl<'a> View for UnassignRequest<'a> {
    type V = Usage;

    closed spec fn view(&self) -> Self::V { *self.usage }
}

impl<'a> UnassignRequest<'a> {
    /// Exact frontend passed to Qubes' unassignment API.
    pub fn owner(&self) -> (owner: &str) ensures owner@ == self@.owner@,
    { self.usage.owner.as_str() }

    /// Exact backend, port and device identity; the adapter only encodes these for transport.
    pub fn device(&self) -> (parts: (&str, &str, &str))
        ensures parts.0@ == self@.backend@ && parts.1@ == self@.port@ && parts.2@ == self@.identity@,
    { (self.usage.backend.as_str(), self.usage.port.as_str(), self.usage.identity.as_str()) }
}

}
