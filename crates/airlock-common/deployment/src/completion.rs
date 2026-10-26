//! Check complete, freshly collected guest observations against journaled selections.
//! This is read-only completion evidence, never permission to execute deployment effects.
//! Adapters authenticate records and observations; sequential probes are not an atomic
//! machine snapshot and do not prove continuing health or faithful external execution.

use crate::{
    boot::{self, Selection},
    operation::ExecutionContext,
    storage::{
        Definition,
        staging::{
            self,
            persistence::{RecordedResolution, Snapshot},
        },
    },
};
use airlock_machine_planning::names::owned_contains;

#[cfg(verus_keep_ghost)]
use airlock_machine_planning::names::owned_member;

use vstd::prelude::*;

verus! {

/// Independently decoded journal and effective topology that define the required observations.
pub struct Inputs {
    /// Original operation/authority and exact current attempt/plan.
    pub context: ExecutionContext,
    /// Canonical release path and fingerprint whose completion is being assessed.
    pub target: String,
    /// Current host boot, preventing evidence reuse after reboot.
    pub boot: String,
    /// Admitted host system whose actual boot distinguishes completion from pending reboot.
    pub host: String,
    /// Complete effective topology in its original storage-definition order.
    pub definitions: Vec<Definition>,
    /// Original planned backend changes, independent of reported successful work.
    pub stage: Vec<String>,
    /// VMs required to have answered the running-system/readiness probes.
    pub running: Vec<String>,
    /// Full target snapshot retained in the authoritative journal.
    pub snapshot: Snapshot,
}

/// Raw named storage and readiness facts, supplied by the Qubes/storage observation adapter.
pub struct NativeObservation {
    /// Full independently inspected committed generation, including its consuming VM.
    pub selection: Selection,
    /// System source reported by the VM's selected-configuration feature.
    pub feature_system: String,
    /// Numeric generation reported by the VM's selected-configuration feature.
    pub feature_generation: u64,
    /// Storage inspection reports this generation selected, rather than merely retained.
    pub pool_selected: bool,
    /// Running guest system after required readiness checks; absent when not probed.
    pub running_system: Option<String>,
}

/// Every topology coordinate must supply its own observation or explicit nonnative classification.
pub enum Observation {
    /// Hermit identity and application execution observed for the selected boot.
    Hermit {
        /// Original VM whose console and domain identity were observed.
        name: String,
        /// Selected immutable system object.
        system: String,
        /// Full selected artifact descriptor, not just a caller-reported hash.
        descriptor: String,
        /// Executing application identity after current-boot readiness evidence.
        running_system: Option<String>,
    },
    /// The named topology entry has no native storage; it supplies no readiness evidence.
    NonNative(
        /// Original VM identity, never an unnamed omission.
        String,
    ),
    /// Native guest facts; none of these fields alone is completion authority.
    Native(
        /// Full storage and runtime observation for this coordinate.
        Box<NativeObservation>,
    ),
}

/// A topology name exists in the independently supplied complete definition set.
pub open spec fn named(definitions: Seq<Definition>, name: Seq<char>) -> bool {
    exists|i: int| 0 <= i < definitions.len() && #[trigger] definitions[i].name@ == name
}

fn contains(definitions: &[Definition], name: &str) -> (yes: bool)
    ensures yes == named(definitions@, name@),
{
    let mut i = 0;
    while i < definitions.len()
        invariant 0 <= i <= definitions.len(),
            forall|j: int| 0 <= j < i ==> #[trigger] definitions[j].name@ != name@,
        decreases definitions.len() - i,
    {
        if definitions[i].name.as_str() == name { return true; }
        i += 1;
    }
    false
}

/// Neither an unknown staged VM nor an unknown readiness requirement may silently disappear.
pub open spec fn covered(definitions: Seq<Definition>, names: Seq<String>) -> bool {
    forall|i: int| 0 <= i < names.len() ==> named(definitions, #[trigger] names[i]@)
}

fn names_covered(definitions: &[Definition], names: &[String]) -> (yes: bool)
    ensures yes == covered(definitions@, names@),
{
    let mut i = 0;
    while i < names.len()
        invariant 0 <= i <= names.len(),
            forall|j: int| 0 <= j < i ==> named(definitions@, #[trigger] names[j]@),
        decreases names.len() - i,
    {
        if !contains(definitions, names[i].as_str()) { return false; }
        i += 1;
    }
    true
}

/// Journal classifications preserve original staging obligations, even without manifest pins.
pub open spec fn recorded(d: Definition, stage: Seq<String>, saved: RecordedResolution) -> bool {
    let needed = d.native.is_some() && (d.native.unwrap().generation.is_some() || owned_member(stage, d.name@));
    match saved {
        RecordedResolution::NonNative(name) => d.native.is_none() && name@ == d.name@,
        RecordedResolution::Existing(name) => d.native.is_some() && !needed && name@ == d.name@,
        RecordedResolution::Retained(s) => needed && staging::agrees(d, *s),
    }
}

fn record_matches(d: &Definition, stage: &[String], saved: &RecordedResolution) -> (yes: bool)
    ensures yes == recorded(*d, stage@, *saved),
{
    let needed = d.native.is_some() && (d.native.as_ref().unwrap().generation.is_some() || owned_contains(stage, d.name.as_str()));
    match saved {
        RecordedResolution::NonNative(name) => d.native.is_none() && name.as_str() == d.name.as_str(),
        RecordedResolution::Existing(name) => d.native.is_some() && !needed && name.as_str() == d.name.as_str(),
        RecordedResolution::Retained(s) => needed && staging::selection_matches(d, s),
    }
}

/// A concrete observed generation matches its original journal number and every boot field.
pub open spec fn observed(d: Definition, saved: RecordedResolution, running: Seq<String>, o: Observation) -> bool {
    match o {
        Observation::Hermit { name, system, descriptor, running_system } => d.native.is_none() && d.executable.is_some()
            && name@ == d.name@ && system@ == d.executable.unwrap().system@
            && descriptor@ == d.executable.unwrap().descriptor@
            && (running_system.is_some() ==> running_system.unwrap()@ == system@)
            && (owned_member(running, d.name@) ==> running_system.is_some()),
        Observation::NonNative(name) => d.native.is_none() && d.executable.is_none() && name@ == d.name@ && !owned_member(running, d.name@),
        Observation::Native(n) => d.executable.is_none() && staging::agrees(d, n.selection)
            && n.feature_system@ == n.selection.system@ && n.feature_generation == n.selection.generation
            && n.pool_selected
            && (n.running_system.is_some() ==> n.running_system.unwrap()@ == n.selection.system@)
            && (owned_member(running, d.name@) ==> n.running_system.is_some())
            && match saved { RecordedResolution::Retained(s) => boot::same(*s, n.selection),
                RecordedResolution::Existing(_) => true, _ => false },
    }
}

fn observation_matches(d: &Definition, saved: &RecordedResolution, running: &[String], o: &Observation) -> (yes: bool)
    ensures yes == observed(*d, *saved, running@, *o),
{
    match o {
        Observation::Hermit { name, system, descriptor, running_system } => {
            if d.native.is_some() || d.executable.is_none() { return false; }
            let expected = d.executable.as_ref().unwrap();
            name.as_str() == d.name.as_str() && system.as_str() == expected.system.as_str() && descriptor.as_str() == expected.descriptor.as_str()
                && (running_system.is_none() || running_system.as_ref().unwrap().as_str() == system.as_str())
                && (!owned_contains(running, d.name.as_str()) || running_system.is_some())
        },
        Observation::NonNative(name) => d.native.is_none() && d.executable.is_none() && name.as_str() == d.name.as_str() && !owned_contains(running, d.name.as_str()),
        Observation::Native(n) => {
            if d.executable.is_some() || !staging::selection_matches(d, &n.selection) || n.feature_system != n.selection.system
                || n.feature_generation != n.selection.generation || !n.pool_selected { return false; }
            if n.running_system.is_some() && n.running_system.as_ref().unwrap().as_str() != n.selection.system.as_str() { return false; }
            if owned_contains(running, d.name.as_str()) && n.running_system.is_none() { return false; }
            match saved { RecordedResolution::Retained(s) => boot::matching(s, &n.selection),
                RecordedResolution::Existing(_) => true, _ => false }
        },
    }
}

/// Complete correspondence, unique identities and exact original generation selections.
pub open spec fn ready(input: Inputs, observations: Seq<Observation>) -> bool {
    input.target@.len() > 0 && input.boot@.len() > 0 && input.host@.len() > 0
        && input.context.attempt@.len() > 0 && input.context.operation@.len() > 0
        && input.context.authority@.len() > 0 && input.context.plan@.len() > 0
        && input.snapshot.operation@ == input.context.operation@ && input.snapshot.authority@ == input.context.authority@
        && input.snapshot.target@ == input.target@
        && input.definitions.len() == input.snapshot.entries.len() && input.definitions.len() == observations.len()
        && covered(input.definitions@, input.stage@) && covered(input.definitions@, input.running@)
        && forall|i: int| 0 <= i < input.definitions.len() ==>
            input.definitions[i].name@.len() > 0
            && recorded(#[trigger] input.definitions[i], input.stage@, input.snapshot.entries[i])
            && observed(input.definitions[i], input.snapshot.entries[i], input.running@, observations[i])
            && forall|j: int| 0 <= j < i ==> input.definitions[i].name@ != #[trigger] input.definitions[j].name@
}

/// Result of comparing the admitted host with the observed currently booted host.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Required guest evidence passed and the admitted host is running.
    Complete,
    /// Required guest evidence passed, but the host must still boot the admitted system.
    RebootRequired,
}

/// Opaque proof-carrying result of the production guest-completion decision.
/// It grants no execution authority and does not promise health after the observations.
///
/// ```compile_fail,E0616
/// use airlock_deployment_core::completion::VerifiedGuests;
/// /// The admitted host cannot be replaced after completion evidence was checked.
/// fn substitute_host(mut checked: VerifiedGuests) {
///     checked.host = "/different-host".into();
/// }
/// ```
pub struct VerifiedGuests {
    // Exact attempt, operation, authority and plan whose observations passed.
    context: ExecutionContext,
    // Exact fingerprinted release target, preventing result substitution.
    target: String,
    // Host boot in which observations were collected.
    boot: String,
    // Original admitted host, never resupplied by the completion publisher.
    host: String,
    // Erased proof witness: no future constructor may create completion without ready evidence.
    _witness: Ghost<(Inputs, Seq<Observation>)>,
}

impl View for VerifiedGuests {
    type V = (ExecutionContext, Seq<char>, Seq<char>, Seq<char>);

    closed spec fn view(&self) -> Self::V { (self.context, self.target@, self.boot@, self.host@) }
}

/// Completion evidence can be consumed only in its unchanged journal and host-boot context.
pub open spec fn bound(v: VerifiedGuests, c: ExecutionContext, target: Seq<char>, boot: Seq<char>) -> bool {
    v@.0.attempt@ == c.attempt@ && v@.0.operation@ == c.operation@ && v@.0.authority@ == c.authority@
        && v@.0.plan@ == c.plan@ && v@.1 == target && v@.2 == boot
}

impl VerifiedGuests {
    /// Every constructible result retains complete original evidence, including future constructors.
    #[verifier::type_invariant]
    closed spec fn valid(&self) -> bool {
        ready(self._witness@.0, self._witness@.1)
            && self@ == (self._witness@.0.context, self._witness@.0.target@, self._witness@.0.boot@, self._witness@.0.host@)
    }

    /// Accept exactly complete matching observations, without trusting a caller's success flag.
    pub fn check(input: Inputs, observations: &[Observation]) -> (out: Option<Self>)
        ensures out.is_some() == ready(input, observations@),
            out.is_some() ==> out.unwrap()@ == (input.context, input.target@, input.boot@, input.host@),
    {
        let ghost original = input;
        let ghost facts = observations@;

        if input.target.is_empty() || input.boot.is_empty() || input.host.is_empty()
            || input.context.attempt.as_str().is_empty() || input.context.operation.as_str().is_empty()
            || input.context.authority.as_str().is_empty() || input.context.plan.as_str().is_empty()
            || input.snapshot.operation.as_str() != input.context.operation.as_str()
            || input.snapshot.authority.as_str() != input.context.authority.as_str() || input.snapshot.target != input.target
            || input.definitions.len() != input.snapshot.entries.len() || input.definitions.len() != observations.len()
            || !names_covered(&input.definitions, &input.stage) || !names_covered(&input.definitions, &input.running) { return None; }

        let mut i = 0;
        while i < input.definitions.len()
            invariant 0 <= i <= input.definitions.len(), input.definitions.len() == input.snapshot.entries.len(),
                input.definitions.len() == observations.len(),
                forall|k: int| 0 <= k < i ==> input.definitions[k].name@.len() > 0
                    && recorded(#[trigger] input.definitions[k], input.stage@, input.snapshot.entries[k])
                    && observed(input.definitions[k], input.snapshot.entries[k], input.running@, observations[k])
                    && forall|j: int| 0 <= j < k ==> input.definitions[k].name@ != #[trigger] input.definitions[j].name@,
            decreases input.definitions.len() - i,
        {
            let d = &input.definitions[i];
            if d.name.is_empty() || !record_matches(d, &input.stage, &input.snapshot.entries[i])
                || !observation_matches(d, &input.snapshot.entries[i], &input.running, &observations[i]) { return None; }
            let mut j = 0;
            while j < i
                invariant 0 <= j <= i < input.definitions.len(),
                    forall|k: int| 0 <= k < j ==> input.definitions[i as int].name@ != #[trigger] input.definitions[k].name@,
                decreases i - j,
            {
                if input.definitions[i].name == input.definitions[j].name { return None; }
                j += 1;
            }
            i += 1;
        }

        Some(Self { context: input.context, target: input.target, boot: input.boot, host: input.host,
            _witness: Ghost((original, facts)) })
    }

    /// Choose completion only for the original context and admitted host; mismatches grant no result.
    pub fn status(&self, c: &ExecutionContext, target: &str, boot: &str, running_host: &str) -> (out: Option<Status>)
        ensures out.is_some() == (bound(*self, *c, target@, boot@) && running_host@.len() > 0),
            out.is_some() ==> (out.unwrap() is Complete <==> running_host@ == self@.3),
    {
        proof { use_type_invariant(self); }

        if self.context.attempt.as_str() != c.attempt.as_str() || self.context.operation.as_str() != c.operation.as_str()
            || self.context.authority.as_str() != c.authority.as_str() || self.context.plan.as_str() != c.plan.as_str()
            || self.target.as_str() != target || self.boot.as_str() != boot || running_host.is_empty() { return None; }

        Some(if self.host.as_str() == running_host { Status::Complete } else { Status::RebootRequired })
    }
}

}
