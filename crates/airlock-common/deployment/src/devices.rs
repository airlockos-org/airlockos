//! Select exact declared PCI assignments and constrained automatic network assignments.
//! Topology decoding and truthful hardware observations remain adapters, never permission flags.
//!
//! ## PCI assignment configuration
//!
//! The [device boundary](crate::devices) retains the complete, ordered configuration
//! namespace and each VM's exact assignment declarations before publication. Selection
//! checks the executing operation/attempt/authority/plan binding and the named physical
//! hardware snapshot. Declared backend, port, explicit device restriction, matching mode,
//! attachment mode and complete options cannot be substituted at dispatch. Physical PCI
//! requests require dom0; unknown backends and identities fail closed.
//!
//! Automatic discovery follows the effective root-provider rules: no explicit assignments,
//! `provides_network`, the conventional provider or literal opt-in feature, and no NetVM.
//! Only observed network-class functions outside both exclusion sets are selectable.
//! Assignment and attachment ownership is checked across all relevant frontends. Device-ID
//! wildcards check every matching physical port and refuse incomplete identities. These
//! rules do not grant VM scope: the retained configuration target must independently belong
//! to the original approval.
//!
//! An opaque selection allows checking whether an assignment already matches, including
//! all options. It is not accepted by the privileged adapter. Mutation requires consuming
//! that selection after a named halted-state and complete ownership check. Qubes PCI only
//! supports required assignments; unsupported new modes are refused before replacement.
//! An option/mode replacement may unassign only the exact same frontend and virtual device
//! selected by the approved new request. Interrupted replacement is reconciled from fresh
//! structured observations; matching completed assignments are skipped even on running VMs.
//! No exactly-once or atomic replacement guarantee is claimed.
//!
//! The direct [local API adapter](../../../runtime/airlock-dom0/service/src/qubes/pci.rs) receives the
//! opaque request and serializes its retained identity, mode and options. Topology decoding,
//! legacy option normalization, truthful complete snapshots and faithful Qubes execution
//! remain trusted. All selections for one VM are checked before its first mutation. The
//! machine lock does not exclude independent administrators or hotplug. A declaration
//! without a device ID authorises resolution of the current hardware at its declared port;
//! automatic discovery likewise authorises a rule rather than a fixed hardware inventory.
//! Retries reapply those original rules to fresh observations. They do not promise that
//! hotplug preserves the first attempt's physical device. An explicit device ID restricts
//! resolution on every attempt. Ordinary deployment rejects changed device declarations
//! on an existing VM; those require migration. This boundary reconciles approved declarations
//! and configures new VMs. It does not infer removal of a different virtual resource from
//! an absent declaration. USB/block configuration
//! is not implemented by this PCI boundary. Boot/manual setup and older full-batch admitted
//! helpers retain explicit compatibility policies outside these fine-grained guarantees.

use crate::{
    effects::{self, Targets},
    inventory::PowerState,
    operation::{DurableOperation, ExecutionContext, PlanBinding},
    pci::{Device, Usage},
};
use vstd::prelude::*;

verus! {

/// Upstream persistent device attachment policy.
#[derive(Clone, Copy)]
pub enum Mode {
    /// Attach automatically when the device is available.
    Auto,
    /// Ask before automatic attachment.
    Ask,
    /// Require the device to start this VM.
    Required,
}

/// A declared assignment fixes a port, a device, or both.
#[derive(Clone, Copy)]
pub enum Matching {
    /// Resolve the declared port to its exact current device identity.
    Exact,
    /// Any device at this exact port.
    Port,
    /// This exact device at any port on the same backend.
    Device,
}

/// Exact option supplied to upstream Qubes, with no command-line interpretation.
pub struct OptionValue {
    /// Upstream assignment option name.
    pub name: String,
    /// Scalar value decoded from the approved configuration.
    pub value: String,
}

/// Parsed declared virtual device, retained before durable intent publication.
pub struct Assignment {
    /// Declared backend; reviewed physical PCI currently supports dom0.
    pub backend: String,
    /// Declared Qubes PCI port.
    pub port: String,
    /// Explicit device restriction, or resolve the actual device at this port.
    pub identity: Option<String>,
    /// Original attachment policy.
    pub mode: Mode,
    /// Original port/device matching rule.
    pub matching: Matching,
    /// Complete original option list, including order.
    pub options: Vec<OptionValue>,
}

/// Effective configuration captured from the same admitted topology as the complete plan.
pub struct Definition {
    /// VM whose explicit and automatic assignments are being reconciled.
    pub name: String,
    /// Complete declared PCI assignment list.
    pub assignments: Vec<Assignment>,
    /// Raw effective provides_network property.
    pub provides_network: bool,
    /// Effective opt-in feature; only the literal value 1 enables it.
    pub auto_feature: String,
    /// Effective NetVM spelling, normalized to empty/none for a disabled relationship.
    pub netvm: String,
    /// Deployment-selected exclusion list; exclusions can only reduce automatic selection.
    pub excludes: Vec<String>,
}

/// Automatic assignment follows the existing explicit-empty/root-provider rules.
pub open spec fn automatic(d: Definition) -> bool {
    d.assignments.len() == 0 && (d.name@ == "sys-net"@ || d.auto_feature@ == "1"@)
        && d.provides_network && (d.netvm@ == ""@ || d.netvm@ == "none"@)
}

/// Interpret the automatic-assignment rule without granting mutation authority.
pub fn is_automatic(d: &Definition) -> (yes: bool) ensures yes == automatic(*d),
{
    d.assignments.is_empty() && (d.name.as_str() == "sys-net" || d.auto_feature.as_str() == "1")
        && d.provides_network && (d.netvm.as_str() == "" || d.netvm.as_str() == "none")
}

/// Exclusions are compared by content, independently of collection order.
pub open spec fn member(names: Seq<String>, target: Seq<char>) -> bool {
    exists|i: int| 0 <= i < names.len() && #[trigger] names[i]@ == target
}

fn contains(names: &[String], target: &str) -> (yes: bool)
    ensures yes == member(names@, target@),
{
    let mut i = 0;
    while i < names.len()
        invariant 0 <= i <= names.len(), forall|j: int| 0 <= j < i ==> #[trigger] names[j]@ != target@,
        decreases names.len() - i,
    {
        if names[i].as_str() == target { return true; }
        i += 1;
    }
    false
}

/// An automatic device must be a present network function and avoid both exclusion sets.
pub open spec fn eligible(d: Definition, hardware: Device, routes: Seq<String>) -> bool {
    automatic(d) && crate::pci::network(hardware)
        && !member(d.excludes@, hardware.port@)
        && (d.name@ != "sys-net"@ || !member(routes, hardware.port@))
}

/// Eligibility is a discovery decision only; ownership and durable authority are checked separately.
pub fn is_eligible(d: &Definition, hardware: &Device, routes: &[String]) -> (yes: bool)
    ensures yes == eligible(*d, *hardware, routes@),
{
    is_automatic(d) && hardware.class >= 0x020000 && hardware.class < 0x030000
        && !contains(d.excludes.as_slice(), hardware.port.as_str())
        && (d.name.as_str() != "sys-net" || !contains(routes, hardware.port.as_str()))
}

/// Device/port wildcards determine ownership independently of the display format.
pub open spec fn uses_device(h: Device, u: Usage) -> bool {
    u.backend@ == "dom0"@ && (u.port@ == h.port@ || u.port@ == "*"@)
        && (u.identity@ == h.identity@ || u.identity@ == "*"@)
}

/// No persistent or live use of this physical function belongs to another frontend.
pub open spec fn ownership(h: Device, uses: Seq<Usage>, name: Seq<char>) -> bool {
    forall|i: int| 0 <= i < uses.len() && #[trigger] uses_device(h, uses[i]) ==> uses[i].owner@ == name
}

fn own(h: &Device, uses: &[Usage], name: &str) -> (yes: bool)
    ensures yes == ownership(*h, uses@, name@),
{
    let mut i = 0;
    while i < uses.len()
        invariant 0 <= i <= uses.len(),
            forall|j: int| 0 <= j < i && #[trigger] uses_device(*h, uses[j]) ==> uses[j].owner@ == name@,
        decreases uses.len() - i,
    {
        let u = &uses[i];
        if u.backend.as_str() == "dom0" && (u.port.as_str() == h.port.as_str() || u.port.as_str() == "*")
            && (u.identity.as_str() == h.identity.as_str() || u.identity.as_str() == "*") && u.owner.as_str() != name { assert(uses_device(*h, uses[i as int])); return false; }
        i += 1;
    }
    true
}

/// Named power evidence cannot be substituted for another VM.
pub struct Observation {
    /// Frontend whose raw power state was queried.
    pub name: String,
    /// Verified classification of that observation.
    pub power: PowerState,
    /// Complete physical inventory; wildcard matching checks every applicable port.
    pub hardware: Vec<Device>,
    /// Full persistent/current ownership snapshot, including undeclared frontends.
    pub uses: Vec<Usage>,
    /// Current physical ports backing dom0's recovery route.
    pub recovery_routes: Vec<String>,
}

/// Unknown hardware identities cannot justify matching away a foreign assignment.
pub open spec fn known(h: Device) -> bool {
    h.port@.len() > 0 && h.port@ != "*"@ && h.identity@.len() > 0 && h.identity@ != "*"@
}

fn is_known(h: &Device) -> (yes: bool) ensures yes == known(*h),
{ !h.port.is_empty() && h.port.as_str() != "*" && !h.identity.is_empty() && h.identity.as_str() != "*" }

/// A selected physical function must occur in the supplied complete hardware snapshot.
pub open spec fn present(h: Device, devices: Seq<Device>) -> bool {
    exists|i: int| 0 <= i < devices.len() && #[trigger] devices[i].port@ == h.port@
        && devices[i].identity@ == h.identity@ && devices[i].class == h.class
}

fn is_present(h: &Device, devices: &[Device]) -> (yes: bool)
    ensures yes == present(*h, devices@),
{
    let mut i = 0;
    while i < devices.len()
        invariant 0 <= i <= devices.len(),
            forall|j: int| 0 <= j < i ==> #[trigger] devices[j].port@ != h.port@
                || devices[j].identity@ != h.identity@ || devices[j].class != h.class,
        decreases devices.len() - i,
    {
        if devices[i].port.as_str() == h.port.as_str() && devices[i].identity.as_str() == h.identity.as_str() && devices[i].class == h.class { return true; }
        i += 1;
    }
    false
}

/// A device-ID wildcard applies to every matching physical function, including different ports.
pub open spec fn all_owned(h: Device, o: Observation, name: Seq<char>) -> bool {
    forall|i: int| 0 <= i < o.hardware.len() ==> known(#[trigger] o.hardware[i])
        && (o.hardware[i].identity@ == h.identity@ ==> ownership(o.hardware[i], o.uses@, name))
}

fn own_all(h: &Device, o: &Observation, name: &str) -> (yes: bool)
    ensures yes == all_owned(*h, *o, name@),
{
    let mut i = 0;
    while i < o.hardware.len()
        invariant 0 <= i <= o.hardware.len(),
            forall|j: int| 0 <= j < i ==> known(#[trigger] o.hardware[j])
                && (o.hardware[j].identity@ == h.identity@ ==> ownership(o.hardware[j], o.uses@, name@)),
        decreases o.hardware.len() - i,
    {
        if !is_known(&o.hardware[i]) { return false; }
        if o.hardware[i].identity.as_str() == h.identity.as_str() && !own(&o.hardware[i], o.uses.as_slice(), name) { return false; }
        assert(known(o.hardware[i as int]));
        assert(o.hardware[i as int].identity@ == h.identity@ ==> ownership(o.hardware[i as int], o.uses@, name@));
        proof {
            assert forall|j: int| 0 <= j < i + 1 implies known(#[trigger] o.hardware[j])
                && (o.hardware[j].identity@ == h.identity@ ==> ownership(o.hardware[j], o.uses@, name@)) by {
                if j == i { } else { assert(j < i); }
            }
        }
        i += 1;
    }
    true
}

/// Complete ownership required for the original assignment's matching semantics.
pub open spec fn assignment_owned(a: Assignment, h: Device, o: Observation, name: Seq<char>) -> bool {
    known(h) && present(h, o.hardware@) && ownership(h, o.uses@, name) && (a.matching is Device ==> all_owned(h, o, name))
}

fn own_assignment(a: &Assignment, h: &Device, o: &Observation, name: &str) -> (yes: bool)
    ensures yes == assignment_owned(*a, *h, *o, name@),
{
    is_known(h) && is_present(h, o.hardware.as_slice()) && own(h, o.uses.as_slice(), name)
        && (!matches!(a.matching, Matching::Device) || own_all(h, o, name))
}

/// The exact approved namespace, effective definitions and complete-plan binding.
pub struct DevicePlan {
    // Names already checked against the original review.
    targets: Targets,
    // Immutable per-VM declarations retained before publication.
    definitions: Vec<Definition>,
    // Candidate, baseline, revision and complete plan identity.
    binding: PlanBinding,
}

impl View for DevicePlan {
    type V = (effects::Scope, Seq<Definition>, Seq<char>);

    closed spec fn view(&self) -> Self::V { (self.targets@, self.definitions@, self.binding@) }
}

/// Definitions cannot add a VM outside the checked configuration namespace.
pub open spec fn valid(s: (effects::Scope, Seq<Definition>, Seq<char>)) -> bool {
    effects::valid(s.0) && s.1.len() == s.0.targets.len()
        && forall|i: int| 0 <= i < s.1.len() ==> #[trigger] effects::planned(s.0, s.1[i].name@)
            && s.1[i].name@ == s.0.targets[i]@
}

impl DevicePlan {
    /// Retain only declared configuration targets; duplicate names are rejected by the wire decoder.
    pub(crate) fn new(targets: Targets, definitions: Vec<Definition>, binding: PlanBinding) -> (out: Option<Self>)
        ensures out.is_some() ==> out.unwrap()@ == (targets@, definitions@, binding@),
            out.is_some() && effects::valid(targets@) ==> valid(out.unwrap()@),
    {
        let names = targets.names();
        if definitions.len() != names.len() { return None; }
        let mut i = 0;
        while i < definitions.len()
            invariant 0 <= i <= definitions.len(), definitions.len() == names.len(),
                forall|j: int| 0 <= j < i ==> #[trigger] effects::planned(targets@, definitions[j].name@)
                    && definitions[j].name@ == names[j]@,
            decreases definitions.len() - i,
        {
            if definitions[i].name.as_str() != names[i].as_str() || !targets.contains(definitions[i].name.as_str()) { return None; }
            assert(definitions[i as int].name@ == names[i as int]@);
            proof {
                assert forall|j: int| 0 <= j < i + 1 implies #[trigger] effects::planned(targets@, definitions[j].name@) && definitions[j].name@ == names[j]@ by {
                    if j == i { } else { assert(j < i); }
                }
            }
            i += 1;
        }
        Some(Self { targets, definitions, binding })
    }

    /// Read retained declarations for hardware observation; this confers no mutation authority.
    pub fn definitions(&self) -> (out: &[Definition]) ensures out@ == self@.1,
    { self.definitions.as_slice() }

    /// Select a declared assignment with exact target, physical identity and ownership checks.
    pub fn explicit<'a>(&'a self, durable: &'a DurableOperation, context: &ExecutionContext,
        vm: usize, assignment: usize, h: &'a Device, o: &Observation) -> (out: Option<AssignmentIntent<'a>>)
        ensures out.is_some() ==> crate::operation::executing(durable, context) && self@.2 == context.plan@,
            out.is_some() ==> vm < self@.1.len() && assignment < self@.1[vm as int].assignments.len(),
            out.is_some() ==> out.unwrap()@ == Effect::Declared(self@.1[vm as int], self@.1[vm as int].assignments[assignment as int], *h),
            out.is_some() ==> o.name@ == self@.1[vm as int].name@
                && assignment_owned(self@.1[vm as int].assignments[assignment as int], *h, *o, self@.1[vm as int].name@),
            out.is_some() ==> self@.1[vm as int].assignments[assignment as int].backend@ == "dom0"@
                && self@.1[vm as int].assignments[assignment as int].port@ == h.port@
                && match self@.1[vm as int].assignments[assignment as int].identity { Some(id) => id@ == h.identity@, None => true },
            out.is_some() && valid(self@) && self@.0.reviewed ==> self@.0.allowed.contains(o.name@),
    {
        if self.binding.as_str() != context.plan.as_str() || !durable.allows_effect(context) || vm >= self.definitions.len() { return None; }
        let d = &self.definitions[vm];
        if !self.targets.contains(d.name.as_str()) { return None; }
        if assignment >= d.assignments.len() || o.name.as_str() != d.name.as_str() { return None; }
        let a = &d.assignments[assignment];
        if !own_assignment(a, h, o, d.name.as_str()) { return None; }
        if a.backend.as_str() != "dom0" || a.port.as_str() != h.port.as_str() { return None; }
        if a.identity.is_some() && a.identity.as_ref().unwrap().as_str() != h.identity.as_str() { return None; }
        proof {
            if valid(self@) && self@.0.reviewed {
                assert(effects::planned(self@.0, d.name@));
                let j = choose|j: int| 0 <= j < self@.0.targets.len() && #[trigger] self@.0.targets[j]@ == d.name@;
            }
        }
        Some(AssignmentIntent { definition: d, source: Source::Declared(a), hardware: h, _durable: durable })
    }

    /// Automatic discovery grants no arbitrary device: only eligible observed network functions.
    pub fn automatic<'a>(&'a self, durable: &'a DurableOperation, context: &ExecutionContext,
        vm: usize, h: &'a Device, o: &Observation) -> (out: Option<AssignmentIntent<'a>>)
        ensures out.is_some() ==> crate::operation::executing(durable, context) && self@.2 == context.plan@ && vm < self@.1.len(),
            out.is_some() ==> out.unwrap()@ == Effect::Automatic(self@.1[vm as int], *h),
            out.is_some() ==> eligible(self@.1[vm as int], *h, o.recovery_routes@)
                && o.name@ == self@.1[vm as int].name@
                && ownership(*h, o.uses@, o.name@) && present(*h, o.hardware@) && known(*h),
            out.is_some() && valid(self@) && self@.0.reviewed ==> self@.0.allowed.contains(o.name@),
    {
        if self.binding.as_str() != context.plan.as_str() || !durable.allows_effect(context) || vm >= self.definitions.len() { return None; }
        let d = &self.definitions[vm];
        if !self.targets.contains(d.name.as_str()) { return None; }
        if !is_known(h) || !is_present(h, o.hardware.as_slice()) { return None; }
        if !is_automatic(d) || h.class < 0x020000 || h.class >= 0x030000 || contains(d.excludes.as_slice(), h.port.as_str()) { return None; }
        if d.name.as_str() == "sys-net" && contains(o.recovery_routes.as_slice(), h.port.as_str()) { return None; }
        if o.name.as_str() != d.name.as_str() || !own(h, o.uses.as_slice(), d.name.as_str()) { return None; }
        proof {
            if valid(self@) && self@.0.reviewed {
                assert(effects::planned(self@.0, d.name@));
                let j = choose|j: int| 0 <= j < self@.0.targets.len() && #[trigger] self@.0.targets[j]@ == d.name@;
            }
        }
        Some(AssignmentIntent { definition: d, source: Source::Automatic, hardware: h, _durable: durable })
    }
}

/// Meaning of the complete selected assignment, independent of transport encoding.
pub ghost enum Effect {
    /// Exact original declaration and its resolved physical function.
    Declared(Definition, Assignment, Device),
    /// Constrained network discovery under the original effective VM configuration.
    Automatic(Definition, Device),
}

enum Source<'a> {
    // Borrow the original declaration without copying or substituting its options.
    Declared(&'a Assignment),
    // Only the verified automatic eligibility predicate can select this case.
    Automatic,
}

/// Checked selection for read-only comparison; mutation additionally requires `permit`.
///
/// ```compile_fail
/// use airlock_deployment_core::devices::{AssignmentIntent, AssignmentRequest};
/// fn adapter(_: AssignmentRequest<'_>) {}
/// fn bypass(selection: AssignmentIntent<'_>) { adapter(selection); }
/// ```
pub struct AssignmentIntent<'a> {
    // Exact checked VM whose review scope applies.
    definition: &'a Definition,
    // Original declaration or constrained automatic rule.
    source: Source<'a>,
    // Named physical function whose ownership was checked.
    hardware: &'a Device,
    // Preserve durable gate ownership through dispatch.
    _durable: &'a DurableOperation,
}

impl<'a> View for AssignmentIntent<'a> {
    type V = Effect;

    closed spec fn view(&self) -> Effect {
        match self.source { Source::Declared(a) => Effect::Declared(*self.definition, *a, *self.hardware), Source::Automatic => Effect::Automatic(*self.definition, *self.hardware) }
    }
}

/// Target identity of either kind of approved request.
pub open spec fn owner(e: Effect) -> Seq<char> { match e { Effect::Declared(d, _, _) | Effect::Automatic(d, _) => d.name@ } }

/// Physical function whose ownership was checked before selecting this request.
pub open spec fn hardware(e: Effect) -> Device {
    match e { Effect::Declared(_, _, h) | Effect::Automatic(_, h) => h }
}

/// A new observation must retain complete ownership for the selected effect's actual wildcard semantics.
pub open spec fn effect_owned(e: Effect, observed: Observation) -> bool {
    match e {
        Effect::Declared(d, a, h) => assignment_owned(a, h, observed, d.name@),
        Effect::Automatic(d, h) => known(h) && present(h, observed.hardware@) && ownership(h, observed.uses@, d.name@),
    }
}

/// Exact virtual identity selected by the original matching rule.
pub open spec fn resource(e: Effect) -> (Seq<char>, Seq<char>, Seq<char>) {
    match e {
        Effect::Automatic(_, h) => ("dom0"@, h.port@, "*"@),
        Effect::Declared(_, a, h) => (a.backend@,
            match a.matching { Matching::Device => "*"@, Matching::Exact | Matching::Port => a.port@ },
            match a.matching { Matching::Port => "*"@, Matching::Exact | Matching::Device => h.identity@ }),
    }
}

impl<'a> AssignmentIntent<'a> {
    /// Sole frontend passed to the upstream assignment API.
    pub fn owner(&self) -> (name: &str) ensures name@ == owner(self@),
    { self.definition.name.as_str() }

    /// Exact backend/port/device tuple, including the original wildcard semantics.
    pub fn resource(&self) -> (parts: (&str, &str, &str))
        ensures (parts.0@, parts.1@, parts.2@) == resource(self@),
    {
        match &self.source {
            Source::Automatic => ("dom0", self.hardware.port.as_str(), "*"),
            Source::Declared(a) => (a.backend.as_str(),
                match a.matching { Matching::Device => "*", Matching::Exact | Matching::Port => a.port.as_str() },
                match a.matching { Matching::Port => "*", Matching::Exact | Matching::Device => self.hardware.identity.as_str() }),
        }
    }

    /// Fixed upstream mode name; automatic discovery always requires the network device.
    pub fn mode(&self) -> (value: &str)
        ensures match self@ { Effect::Automatic(_, _) => value@ == "required"@,
            Effect::Declared(_, a, _) => match a.mode { Mode::Auto => value@ == "auto-attach"@, Mode::Ask => value@ == "ask-to-attach"@, Mode::Required => value@ == "required"@ } },
    {
        match &self.source { Source::Automatic => "required", Source::Declared(a) => match a.mode { Mode::Auto => "auto-attach", Mode::Ask => "ask-to-attach", Mode::Required => "required" } }
    }

    /// Complete declared options; automatic discovery supplies none.
    pub fn options(&self) -> (out: &[OptionValue])
        ensures match self@ { Effect::Automatic(_, _) => out.len() == 0, Effect::Declared(_, a, _) => out@ == a.options@ },
    {
        match &self.source { Source::Automatic => &[], Source::Declared(a) => a.options.as_slice() }
    }
}

/// Only a halted, still correctly owned observation turns a selection into mutation authority.
pub struct AssignmentRequest<'a> {
    // Ownership and halted-state checks consumed the immutable selected declaration.
    intent: AssignmentIntent<'a>,
}

impl<'a> View for AssignmentRequest<'a> {
    type V = Effect;

    closed spec fn view(&self) -> Effect { self.intent@ }
}

impl<'a> AssignmentIntent<'a> {
    /// A matching no-op needs no request; changes require explicitly halted named observations.
    pub fn permit(self, observed: &Observation) -> (out: Option<AssignmentRequest<'a>>)
        ensures out.is_some() ==> out.unwrap()@ == self@ && observed.name@ == owner(self@)
            && observed.power@ == crate::inventory::PowerClass::Halted
            && effect_owned(self@, *observed),
            out.is_some() ==> match self@ { Effect::Automatic(_, _) => true, Effect::Declared(_, a, _) => a.mode is Required },
    {
        if self.mode() != "required" { return None; }
        if observed.name.as_str() != self.definition.name.as_str() || !observed.power.is_halted()
            || !is_known(self.hardware) || !is_present(self.hardware, observed.hardware.as_slice()) { return None; }
        let permitted = match &self.source {
            Source::Declared(a) => own_assignment(a, self.hardware, observed, observed.name.as_str()),
            Source::Automatic => own(self.hardware, observed.uses.as_slice(), observed.name.as_str()),
        };
        if !permitted { return None; }
        Some(AssignmentRequest { intent: self })
    }
}

impl<'a> AssignmentRequest<'a> {
    /// Sole frontend passed to the Qubes adapter.
    pub fn owner(&self) -> (name: &str) ensures name@ == owner(self@),
    { self.intent.owner() }

    /// Exact wildcard-aware virtual resource from the checked selection.
    pub fn resource(&self) -> (parts: (&str, &str, &str)) ensures (parts.0@, parts.1@, parts.2@) == resource(self@),
    { self.intent.resource() }

    /// Selected upstream assignment mode.
    pub fn mode(&self) -> (value: &str)
        ensures match self@ { Effect::Automatic(_, _) => value@ == "required"@,
            Effect::Declared(_, a, _) => match a.mode { Mode::Auto => value@ == "auto-attach"@, Mode::Ask => value@ == "ask-to-attach"@, Mode::Required => value@ == "required"@ } },
    { self.intent.mode() }

    /// Full approved options; never supplied independently at dispatch.
    pub fn options(&self) -> (out: &[OptionValue])
        ensures match self@ { Effect::Automatic(_, _) => out.len() == 0, Effect::Declared(_, a, _) => out@ == a.options@ },
    { self.intent.options() }
}

/// A configuration replacement can remove only the exact virtual resource it is about to assign.
pub struct ReplacementRequest<'a> {
    // Actual persistent row matched against the checked replacement resource.
    usage: &'a Usage,
    // Retain the halted, authorized request throughout unassignment.
    _desired: &'a AssignmentRequest<'a>,
}

impl<'a> View for ReplacementRequest<'a> {
    type V = Usage;

    closed spec fn view(&self) -> Usage { *self.usage }
}

impl<'a> AssignmentRequest<'a> {
    /// Permit an option/mode replacement only for the same frontend and exact virtual resource.
    pub fn replacement<'b>(&'b self, existing: &'b Usage) -> (out: Option<ReplacementRequest<'b>>)
        ensures out.is_some() ==> out.unwrap()@ == *existing && existing.kind is Assigned
            && existing.owner@ == owner(self@)
            && (existing.backend@, existing.port@, existing.identity@) == resource(self@),
    {
        let (backend, port, identity) = self.resource();
        if !matches!(existing.kind, crate::pci::Kind::Assigned) || existing.owner.as_str() != self.owner()
            || existing.backend.as_str() != backend || existing.port.as_str() != port || existing.identity.as_str() != identity { return None; }
        Some(ReplacementRequest { usage: existing, _desired: self })
    }
}

impl<'a> ReplacementRequest<'a> {
    /// Sole frontend whose old assignment may be removed.
    pub fn owner(&self) -> (name: &str) ensures name@ == self@.owner@,
    { self.usage.owner.as_str() }

    /// Exact persistent assignment, preserving wildcard device IDs.
    pub fn resource(&self) -> (parts: (&str, &str, &str))
        ensures parts.0@ == self@.backend@ && parts.1@ == self@.port@ && parts.2@ == self@.identity@,
    { (self.usage.backend.as_str(), self.usage.port.as_str(), self.usage.identity.as_str()) }
}

}
