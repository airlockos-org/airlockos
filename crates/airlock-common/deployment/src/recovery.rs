//! Reconcile durable intent with selected intent without inferring completed effects.
//! The adapter authenticates records and observes Qubes; neither a phase nor a
//! selection authorizes skipping reconciliation of an uncertain external outcome.
//!
//! ## Recovery evidence and decisions
//!
//! The [reconciler](crate::recovery) separates intended state from completion evidence.
//! These records answer different questions:
//!
//! | Fact | Authoritative evidence |
//! | --- | --- |
//! | Current attempt, immutable release pair, plan and operation | `latest.json`; a retained history copy may lag in progress but must agree on immutable intent. |
//! | Original source approval and permitted effect scope | Protected review and candidate binding, rechecked before every new execution attempt. A started-status projection alone grants nothing. |
//! | Intended machine/boot selection | `selection.json` and its referenced journal. Selection is published before VM shutdown/configuration and does not attest that either completed. |
//! | Actual selected and running generations | Fresh Qubes, pool and guest observations plus host inspection; desired selection is not a substitute. |
//! | Guest generations in native journal v3 | Complete target-specific snapshots in the authoritative intent, checked before publication and reauthenticated from committed storage on recovery. Missing originals stop execution; a newer matching generation is not a substitute. |
//! | Private-copy completion | Identity-bound copy receipt, checked by the migration adapter; not inferred from the deployment phase. |
//!
//! `RecoveryDecision::reconcile` executes in production. Its success is proved
//! equivalent to `compatible`, which permits a current selection only when its
//! transaction, release pair, fingerprints, plan and operation agree. A lagging
//! selection must name one of the two fingerprint-bound endpoints and have a
//! matching journal: either another attempt of the same operation with the same
//! authority and pair, or a completed earlier deployment of that endpoint. Missing
//! selection is accepted only for an interrupted pair containing the image baseline.
//! Other missing records, undecodable native identities, collapsed release/predecessor
//! pairs and unsupported legacy journals yield no recovery decision. A collapsed
//! pair cannot identify the possibly applied candidate, so it needs operator repair.
//! For reviewed V2 authority the original approved candidate and fingerprint must
//! also be an endpoint; recovery cannot substitute an unrelated pair.
//! A verified outcome requires selection of
//! the current attempt; `Complete` cannot roll back, while `RebootRequired` can.
//!
//! Every incomplete phase selects reconciliation, regardless of how far its external
//! effects may have progressed. Resume uses the recorded release and predecessor;
//! rollback exchanges them. Selection never supplies the planning baseline. This
//! preserves knowledge of the attempted candidate when selection is absent or lags.
//! `releases` proves this mapping; changing the rollback baseline or dropping a
//! fingerprint comparison violates its executable contracts.
//!
//! The [coordinator adapter](../../../runtime/airlock-dom0/service/src/coordinator/recovery.rs)
//! loads and checks those files, replans from fresh stable power observations and
//! rechecks the complete proposed effects against the original approval. It must
//! consume the accepted decision through `authorize` to create the new
//! `AuthorizedOperation`. That method rejects a substituted prior journal, loaded
//! release, baseline or V2 authority, preserves the stable operation identity and
//! carries the freshly checked scopes and new plan binding into publication. V1
//! adopts its attempt ID after checking the protected approval; it cannot compare an
//! original decision digest that its format did not retain. A prior plan cannot be silently replaced in the evidence;
//! the new plan may differ, but must be independently reauthorized. Verification-only
//! decisions cannot create deployment authority. Neither action restores volatile
//! publication acknowledgments from the previous attempt.
//!
//! `history_preserves` proves by induction that finite endpoint exchanges retain
//! the original pair, operation and recorded authority. This composes with the
//! executable endpoint and operation contracts; it is **not** a model of filesystem
//! crash consistency or every coordinator instruction.
//!
//! Before retirement and again before configuration, the coordinator obtains a
//! fresh stable power snapshot. Verified `quiescent` accepts exactly when no required
//! VM is active. The tested adapter supplies changed, affected, retired and explicit
//! stop targets, including VMs halted when the plan was constructed. Thus an observed
//! restart after shutdown blocks configuration. The check cannot prevent a later
//! independent restart: Qubes observation and mutation are not atomic.
//!
//! Replaying reconciles uncertain external outcomes rather than assuming a failed
//! call had no effects. Host/storage/setup helper replay safety, generation
//! verification, copy receipts and rollback's private-data preservation remain
//! adapter obligations. No exactly-once or eventual-recovery theorem is claimed.
//! Invalid authority, unsupported rollback migrations and ambiguous evidence can
//! require operator intervention. The same separation of durable intent, checked
//! reconciliation and fresh publication can serve retirement, artifact admission
//! and generation publication; each needs its own external reconciliation contract.

use crate::{
    effects::{Shutdowns, Targets},
    operation::{
        AttemptId, AuthorityBinding, AuthorizedOperation, OperationId, PlanBinding,
        PreviousOperation,
    },
};
use airlock_machine_planning::names::owned_contains;
use vstd::prelude::*;

verus! {

/// Immutable release identity, including the fingerprint of its complete inputs.
pub struct Release {
    /// Protected release directory, distinct from a VM's selected/running generation.
    pub path: String,
    /// Digest checked against the release files by the coordinator.
    pub fingerprint: String,
}


/// Relationship between two independently decoded release identities.
pub open spec fn same(a: Release, b: Release) -> bool {
    a.path@ == b.path@ && a.fingerprint@ == b.fingerprint@
}

impl Release {
    /// Compare both location and content; equal paths alone are insufficient.
    pub fn matches(&self, other: &Self) -> (equal: bool)
        ensures equal == same(*self, *other),
    { self.path == other.path && self.fingerprint == other.fingerprint }

    /// Borrow the checked directory for loading the corresponding production release.
    pub fn path(&self) -> (path: &str)
        ensures path@ == self.path@,
    { self.path.as_str() }
}

/// Persisted outcome classification. Incomplete phases never attest external completion.
#[derive(Clone, Copy)]
pub enum Progress {
    /// Any attempted phase, failed operation, or uncertain external outcome.
    Interrupted,
    /// VM verification succeeded; the host may still need its selected reboot.
    RebootRequired,
    /// The recorded whole-machine verification succeeded.
    Complete,
}

/// Native journal evidence; construction grants no execution authority.
pub struct Journal {
    /// Attempt whose current intent this evidence describes.
    pub attempt: String,
    /// V2 stable identity and exact authority, or absent for a native V1 journal.
    pub operation: Option<PreviousOperation>,
    /// Original candidate from reviewed V2 authority; absent for V1 or explicit policy exemptions.
    pub candidate: Option<Release>,
    /// Intended release, not a claim about the live Qubes configuration.
    pub release: Release,
    /// Fingerprint-bound other endpoint of this attempt's recovery pair.
    pub previous: Release,
    /// Canonical immutable plan binding, including both release identities.
    pub plan: String,
    /// Only verified outcomes may select the verification-only action.
    pub progress: Progress,
}

/// Selected intent accompanied by the journal to which its transaction refers.
pub struct Selection {
    /// Transaction identity from selection.json.
    pub attempt: String,
    /// Selected release directory from selection.json.
    pub release: String,
    /// Retained previous release directory from selection.json.
    pub previous: String,
    /// Current authoritative record or the retained history of this selection.
    pub journal: Journal,
}

/// Requested interpretation of the current journal's two immutable endpoints.
#[derive(Clone, Copy)]
pub enum Mode {
    /// Reconcile the intended release against its recorded predecessor.
    Resume,
    /// Restore the predecessor, using the attempted release as the possible live baseline.
    Rollback,
}

/// What recovery may do; neither variant claims an external operation completed.
#[derive(Clone, Copy)]
pub enum Action {
    /// Recheck selected generations through the existing verification path.
    Verify,
    /// Replan and reauthorize before publishing a fresh, initially unready intent.
    Reconcile,
}

/// Fresh attempt inputs kept distinct from the retained journal being reconciled.
/// These values become executable authority only after the decision and scope checks.
pub struct Attempt {
    /// New identity allocated for this recovery attempt.
    pub id: AttemptId,
    /// Rechecked protected decision, which must equal the retained V2 authority.
    pub authority: AuthorityBinding,
    /// Binding of the newly computed and independently authorized plan.
    pub plan: PlanBinding,
}

/// The stable identity of a native V1 journal is adopted by its first V2 recovery.
pub open spec fn operation(j: Journal) -> Seq<char> {
    match j.operation { Some(o) => o.id@, None => j.attempt@ }
}

/// A current selection must describe the exact current immutable intent.
pub open spec fn identical(a: Journal, b: Journal) -> bool {
    &&& a.attempt@ == b.attempt@
    &&& same(a.release, b.release) && same(a.previous, b.previous)
    &&& a.plan@ == b.plan@
    &&& match (a.candidate, b.candidate) {
        (Some(x), Some(y)) => same(x, y),
        (None, None) => true,
        _ => false,
    }
    &&& match (a.operation, b.operation) {
        (Some(x), Some(y)) => x.id@ == y.id@ && x.authority@ == y.authority@,
        (None, None) => true,
        _ => false,
    }
}

/// Both endpoints remain fixed, although rollback may exchange their roles.
pub open spec fn pair(a: Journal, b: Journal) -> bool {
    (same(a.release, b.release) && same(a.previous, b.previous))
        || (same(a.release, b.previous) && same(a.previous, b.release))
}

/// Once recorded, the exact protected authority survives every recovery direction change.
pub open spec fn retains_authority(a: Journal, b: Journal) -> bool {
    match a.operation {
        Some(original) => match b.operation { Some(next) => original.authority@ == next.authority@, None => false },
        None => true,
    }
}

/// Swapping recovery direction cannot add a third release to the immutable pair.
pub proof fn pair_transitive(a: Journal, b: Journal, c: Journal)
    requires pair(a, b), pair(b, c),
    ensures pair(a, c),
{}

/// Repeated accepted endpoint exchanges preserve the original pair for any finite history.
/// This describes endpoint transitions, not durability or successful external execution.
pub proof fn history_preserves(history: Seq<Journal>)
    requires history.len() > 0,
        forall|i: int| 0 <= i < history.len() - 1 ==> pair(#[trigger] history[i], history[i + 1])
            && operation(history[i]) == operation(history[i + 1]) && retains_authority(history[i], history[i + 1]),
    ensures pair(history[0], history.last()), operation(history[0]) == operation(history.last()),
        retains_authority(history[0], history.last()),
    decreases history.len(),
{
    if history.len() > 1 {
        let prefix = history.drop_last();
        history_preserves(prefix);
        pair_transitive(history[0], prefix.last(), history.last());
    }
}

/// Every VM whose mutation requires quiescence is absent from the active observation.
pub open spec fn quiescent_state(required: Seq<String>, active: Seq<String>) -> bool {
    forall|i: int| 0 <= i < required.len() ==> !airlock_machine_planning::names::owned_member(active, #[trigger] required[i]@)
}

/// Check fresh observations after shutdown, including targets halted at planning time.
/// Unknown power states and incomplete inventories must be rejected by the observation adapter.
/// This is a snapshot check; it does not fence independent Qubes administrators.
pub fn quiescent(required: &[String], active: &[String]) -> (safe: bool)
    ensures safe == quiescent_state(required@, active@),
{
    let mut i = 0;
    while i < required.len()
        invariant i <= required.len(),
            forall|j: int| 0 <= j < i ==> !airlock_machine_planning::names::owned_member(active@, #[trigger] required@[j]@),
        decreases required.len() - i,
    {
        if owned_contains(active, required[i].as_str()) { return false; }
        i += 1;
    }
    true
}

/// A retained selection is consistent evidence, never a substitute for current authority.
pub open spec fn selected(j: Journal, s: Selection) -> bool {
    &&& s.attempt@ == s.journal.attempt@
    &&& s.release@ == s.journal.release.path@ && s.previous@ == s.journal.previous.path@
    &&& (same(s.journal.release, j.release) || same(s.journal.release, j.previous))
    &&& if s.attempt@ == j.attempt@ { identical(j, s.journal) }
        else if operation(s.journal) == operation(j) {
            pair(j, s.journal) && match (j.operation, s.journal.operation) {
                (Some(a), Some(b)) => a.authority@ == b.authority@,
                (Some(_), None) => true,
                _ => false,
            }
        } else { s.journal.progress is Complete }
}

/// The pair retains the reviewed candidate and never collapses its two possible endpoints.
pub open spec fn bound(j: Journal) -> bool {
    &&& j.release.path@ != j.previous.path@
    &&& match j.candidate {
        Some(c) => j.operation.is_some() && (same(c, j.release) || same(c, j.previous)),
        None => true,
    }
}

/// Independent acceptance conditions for the two classes of recovery action.
pub open spec fn compatible(j: Journal, selection: Option<Selection>, bootstrap: Seq<char>, mode: Mode) -> bool {
    &&& bound(j)
    &&& match selection {
        Some(s) => selected(j, s),
        None => j.progress is Interrupted && (j.release.path@ == bootstrap || j.previous.path@ == bootstrap),
    }
    &&& (mode is Rollback ==> !(j.progress is Complete))
    &&& (!(j.progress is Interrupted) ==> selection.is_some()
        && selection.unwrap().attempt@ == j.attempt@)
}

/// Accepted recovery context, unavailable through JSON decoding or public fields.
/// It cannot directly execute effects: consuming it still requires freshly checked scopes
/// and publication of the exact new intent through the existing durable gate.
///
/// ```compile_fail
/// use airlock_deployment_core::recovery::{RecoveryDecision, Journal};
/// // A decoded journal cannot stand in for the accepted reconciliation.
/// fn bypass(journal: Journal) -> RecoveryDecision { journal.into() }
/// ```
pub struct RecoveryDecision {
    // Original journal retained so an adapter cannot substitute a different plan or identity.
    journal: Journal,
    // Determines which of the two fingerprint-bound endpoints can become the target.
    mode: Mode,
    // Verification-only outcomes cannot mint a new deployment attempt.
    action: Action,
}

impl View for RecoveryDecision {
    type V = (Journal, Mode, Action);

    closed spec fn view(&self) -> Self::V { (self.journal, self.mode, self.action) }
}

impl Journal {
    /// Check equality of immutable intent; progress and recorded observations may lag.
    fn matches(&self, other: &Self) -> (equal: bool)
        ensures equal == identical(*self, *other),
    {
        if self.attempt != other.attempt || !self.release.matches(&other.release)
            || !self.previous.matches(&other.previous) || self.plan != other.plan { return false; }
        let candidate = match (&self.candidate, &other.candidate) {
            (Some(a), Some(b)) => a.matches(b),
            (None, None) => true,
            _ => false,
        };
        if !candidate { return false; }
        match (&self.operation, &other.operation) {
            (Some(a), Some(b)) => a.id.as_str() == b.id.as_str() && a.authority.as_str() == b.authority.as_str(),
            (None, None) => true,
            _ => false,
        }
    }

    /// Borrow the stable identity without allocating authority.
    fn operation(&self) -> (id: &str)
        ensures id@ == operation(*self),
    { match &self.operation { Some(o) => o.id.as_str(), None => self.attempt.as_str() } }

    /// Validate an independent selection against its journal and the possible recovery pair.
    fn selection(&self, s: &Selection) -> (accepted: bool)
        ensures accepted == selected(*self, *s),
    {
        if s.attempt != s.journal.attempt || s.release != s.journal.release.path
            || s.previous != s.journal.previous.path
            || (!s.journal.release.matches(&self.release) && !s.journal.release.matches(&self.previous)) { return false; }
        if s.attempt == self.attempt { return self.matches(&s.journal); }
        if s.journal.operation() != self.operation() { return matches!(s.journal.progress, Progress::Complete); }
        let endpoints = (self.release.matches(&s.journal.release) && self.previous.matches(&s.journal.previous))
            || (self.release.matches(&s.journal.previous) && self.previous.matches(&s.journal.release));
        endpoints && match (&self.operation, &s.journal.operation) {
            (Some(a), Some(b)) => a.authority.as_str() == b.authority.as_str(),
            (Some(_), None) => true,
            _ => false,
        }
    }
}

impl RecoveryDecision {
    /// Every constructible decision retains the checked pair and approved candidate.
    #[verifier::type_invariant]
    closed spec fn valid(&self) -> bool { bound(self.journal) }

    /// Refuse contradictory evidence; accept lagging selection only within the bound pair.
    /// Absence is supported for interruption of the initial image-baseline deployment.
    pub fn reconcile(journal: Journal, selection: Option<&Selection>, bootstrap: &str, mode: Mode) -> (result: Option<Self>)
        ensures
            result.is_some() == compatible(journal, match selection { Some(s) => Some(*s), None => None }, bootstrap@, mode),
            result.is_some() ==> result.unwrap()@.0 == journal && result.unwrap()@.1 == mode,
            result.is_some() ==> (result.unwrap()@.2 is Verify) == (mode is Resume && !(journal.progress is Interrupted)),
    {
        // Historical rollback could replace the possible live candidate with the restore target.
        // A collapsed pair cannot describe what configuration may still be running.
        if journal.release.path == journal.previous.path { return None; }

        let candidate_bound = match &journal.candidate {
            Some(candidate) => journal.operation.is_some()
                && (candidate.matches(&journal.release) || candidate.matches(&journal.previous)),
            None => true,
        };
        if !candidate_bound { return None; }

        let selected = match selection {
            Some(s) => journal.selection(s),
            None => matches!(journal.progress, Progress::Interrupted)
                && (journal.release.path.as_str() == bootstrap || journal.previous.path.as_str() == bootstrap),
        };
        if !selected || (matches!(mode, Mode::Rollback) && matches!(journal.progress, Progress::Complete)) { return None; }
        if !matches!(journal.progress, Progress::Interrupted)
            && !match selection { Some(s) => s.attempt == journal.attempt, None => false } { return None; }

        let action = if matches!(mode, Mode::Resume) && !matches!(journal.progress, Progress::Interrupted) {
            Action::Verify
        } else { Action::Reconcile };
        Some(Self { journal, mode, action })
    }

    /// Borrow the exact intended target and possible live baseline; selection never chooses them.
    pub fn releases(&self) -> (endpoints: (&Release, &Release))
        ensures
            self@.1 is Resume ==> *endpoints.0 == self@.0.release && *endpoints.1 == self@.0.previous,
            self@.1 is Rollback ==> *endpoints.0 == self@.0.previous && *endpoints.1 == self@.0.release,
    {
        match self.mode {
            Mode::Resume => (&self.journal.release, &self.journal.previous),
            Mode::Rollback => (&self.journal.previous, &self.journal.release),
        }
    }

    /// Expose the permitted action without exposing a way to fabricate the decision.
    pub fn action(&self) -> (action: Action)
        ensures action == self@.2,
    { self.action }

    /// Consume reconciliation evidence and fresh scope checks into the real publication path.
    /// The prior journal, both loaded releases and (for V2) the protected authority must match.
    pub fn authorize(self, prior: &Journal, target: &Release, baseline: &Release,
        starts: Targets, shutdowns: Shutdowns, attempt: Attempt,
    ) -> (result: Option<AuthorizedOperation>)
        ensures
            result.is_some() == (self@.2 is Reconcile && identical(self@.0, *prior)
                && same(*target, if self@.1 is Resume { self@.0.release } else { self@.0.previous })
                && same(*baseline, if self@.1 is Resume { self@.0.previous } else { self@.0.release })
                && match self@.0.operation { Some(o) => attempt.authority@ == o.authority@, None => true }),
            result.is_some() ==> self@.2 is Reconcile && identical(self@.0, *prior),
            result.is_some() ==> same(*target, if self@.1 is Resume { self@.0.release } else { self@.0.previous })
                && same(*baseline, if self@.1 is Resume { self@.0.previous } else { self@.0.release }),
            result.is_some() ==> result.unwrap()@.operation == operation(self@.0)
                && result.unwrap()@.authority == attempt.authority@ && result.unwrap()@.attempt == attempt.id@
                && result.unwrap()@.plan == attempt.plan@ && result.unwrap()@.scope == starts@ && result.unwrap()@.shutdown == shutdowns@,
            result.is_some() && self@.0.operation.is_some() ==> attempt.authority@ == self@.0.operation.unwrap().authority@,
            result.is_some() && self@.0.candidate.is_some() ==>
                same(*target, self@.0.candidate.unwrap()) || same(*baseline, self@.0.candidate.unwrap()),
    {
        proof { use_type_invariant(&self); }

        if !matches!(self.action, Action::Reconcile) || !self.journal.matches(prior) { return None; }
        let (expected, previous) = self.releases();
        if !target.matches(expected) || !baseline.matches(previous) { return None; }

        let legacy = OperationId::new(self.journal.attempt.as_str().to_string());
        AuthorizedOperation::new(starts, shutdowns, attempt.id, attempt.authority, attempt.plan, self.journal.operation.as_ref(), Some(&legacy))
    }
}

}

#[cfg(test)]
mod tests;
