//! A volatile execution gate driven by acknowledged durable writes.
//! A restart constructs a fresh gate after revalidating the retained intent.
//! An I/O error may have committed data, but never counts as an acknowledgment.

use vstd::prelude::*;

verus! {

/// Match a committed journal to the complete request, fresh source authorization
/// and current host boot. This selects a retained-artifact check; it never grants
/// execution or replaces the filesystem checks at the storage boundary.
pub fn completion_matches(
    committed: bool,
    saved_request: &str, request: &str,
    saved_authorization: &str, authorization: &str,
    saved_boot: &str, boot: &str,
) -> (matches: bool)
    ensures matches == (committed && saved_request@ == request@
        && saved_authorization@ == authorization@ && saved_boot@ == boot@),
{
    committed && saved_request == request
        && saved_authorization == authorization && saved_boot == boot
}

/// Position of one attempt in the publication-to-execution handoff.
#[derive(Clone, Copy)]
pub enum Stage {
    /// No durable publication acknowledged in this attempt.
    Unpublished,
    /// Authoritative intent and transaction history writes acknowledged.
    Intent,
    /// Approval projection also acknowledged; execution may begin once.
    Ready,
    /// External effects may have happened, regardless of subsequent errors.
    Executing,
    /// The external adapter verified its outcome.
    Complete,
    /// An interruption, uncertain outcome or invalid event requires fresh recovery.
    Blocked,
}

/// Observations supplied by the coordinator, never inferred from failed I/O.
#[derive(Clone, Copy)]
pub enum Event {
    /// Intent and history publication returned success.
    IntentSaved,
    /// Required approval projection publication returned success.
    ApprovalSaved,
    /// Begin external execution after checking the exact preflight binding.
    Begin,
    /// Adapter reports verified completion of execution.
    Verified,
    /// Crash, I/O failure or uncertain external completion invalidates this gate.
    Interrupted,
}

/// Pure state used to specify the same gate executed in production.
pub ghost struct State {
    /// Attempt identity remains unchanged on every transition.
    pub attempt: Seq<char>,
    /// Digest of the complete preflight intent, including authority and plan.
    pub binding: Seq<char>,
    /// Intent publication has been acknowledged in this attempt.
    pub intent: bool,
    /// Approval projection publication has been acknowledged in this attempt.
    pub approval: bool,
    /// Current position in the handoff.
    pub stage: Stage,
}

/// Owned, non-cloneable execution gate; it carries no authority across a restart.
pub struct Publication {
    // Attempt identity copied from the record being published.
    attempt: String,
    // Complete preflight digest prevents token reuse with altered record contents.
    binding: String,
    // Successful intent/history acknowledgment for this attempt only.
    intent: bool,
    // Successful approval projection acknowledgment for this attempt only.
    approval: bool,
    // Invalid transitions consume readiness and require reauthorization.
    stage: Stage,
}

impl View for Publication {
    type V = State;

    closed spec fn view(&self) -> State {
        State {
            attempt: self.attempt@, binding: self.binding@,
            intent: self.intent, approval: self.approval, stage: self.stage,
        }
    }
}

/// Execution and completion require both acknowledged publication barriers.
pub open spec fn valid(s: State) -> bool {
    &&& (s.approval ==> s.intent)
    &&& (s.stage is Intent ==> s.intent)
    &&& (s.stage is Ready || s.stage is Executing || s.stage is Complete ==>
        s.intent && s.approval)
}

/// Invalid event order fails closed. Interruption discards all volatile acknowledgments.
pub open spec fn next(s: State, e: Event) -> State {
    match (s.stage, e) {
        (Stage::Unpublished, Event::IntentSaved) => State { intent: true, stage: Stage::Intent, ..s },
        (Stage::Intent, Event::ApprovalSaved) => State { approval: true, stage: Stage::Ready, ..s },
        (Stage::Ready, Event::Begin) => State { stage: Stage::Executing, ..s },
        (Stage::Executing, Event::Verified) => State { stage: Stage::Complete, ..s },
        _ => State { intent: false, approval: false, stage: Stage::Blocked, ..s },
    }
}

/// One-step inductiveness, including every invalid ordering and interruption edge.
pub proof fn preserves(s: State, e: Event)
    requires valid(s),
    ensures
        valid(next(s, e)),
        next(s, e).attempt == s.attempt,
        next(s, e).binding == s.binding,
{
}

/// Apply a finite event history; used only in proofs, never as a second executor.
pub open spec fn run(s: State, events: Seq<Event>) -> State
    decreases events.len(),
{
    if events.len() == 0 { s } else { run(next(s, events[0]), events.drop_first()) }
}

/// Induction extends the executable step contract to every finite event history.
pub proof fn history_preserves(s: State, events: Seq<Event>)
    requires valid(s),
    ensures
        valid(run(s, events)),
        run(s, events).attempt == s.attempt,
        run(s, events).binding == s.binding,
    decreases events.len(),
{
    if events.len() > 0 {
        preserves(s, events[0]);
        history_preserves(next(s, events[0]), events.drop_first());
    }
}

impl Publication {
    /// Create an unready gate after authorization; the caller must publish its binding.
    pub fn new(attempt: String, binding: String) -> (p: Self)
        ensures
            valid(p@),
            p@.attempt == attempt@, p@.binding == binding@,
            !p@.intent, !p@.approval, p@.stage is Unpublished,
    {
        Self { attempt, binding, intent: false, approval: false, stage: Stage::Unpublished }
    }

    /// Record an acknowledgment or interruption. This cannot change either identity.
    pub fn advance(&mut self, event: Event)
        ensures
            final(self)@ == next(old(self)@, event),
            valid(old(self)@) ==> valid(final(self)@),
    {
        match (self.stage, event) {
            (Stage::Unpublished, Event::IntentSaved) => {
                self.intent = true;
                self.stage = Stage::Intent;
            },
            (Stage::Intent, Event::ApprovalSaved) => {
                self.approval = true;
                self.stage = Stage::Ready;
            },
            (Stage::Ready, Event::Begin) => self.stage = Stage::Executing,
            (Stage::Executing, Event::Verified) => self.stage = Stage::Complete,
            _ => {
                self.intent = false;
                self.approval = false;
                self.stage = Stage::Blocked;
            },
        }
    }

    /// Check the exact attempt and complete intent, including both acknowledged barriers.
    pub fn permits(&self, attempt: &str, binding: &str) -> (allowed: bool)
        ensures allowed == (
            self@.stage is Ready && self@.intent && self@.approval
            && self@.attempt == attempt@ && self@.binding == binding@
        ),
    {
        matches!(self.stage, Stage::Ready) && self.intent && self.approval
            && self.attempt.as_str() == attempt && self.binding.as_str() == binding
    }

    /// Permit requests only during execution of this exact acknowledged intent.
    pub fn executing(&self, attempt: &str, binding: &str) -> (allowed: bool)
        ensures allowed == (
            self@.stage is Executing && self@.intent && self@.approval
            && self@.attempt == attempt@ && self@.binding == binding@
        ),
    {
        matches!(self.stage, Stage::Executing) && self.intent && self.approval
            && self.attempt.as_str() == attempt && self.binding.as_str() == binding
    }

    /// Consume readiness before effects; a duplicate call or changed binding fails closed.
    pub fn begin(&mut self, attempt: &str, binding: &str) -> (allowed: bool)
        ensures
            allowed == (old(self)@.stage is Ready && old(self)@.intent && old(self)@.approval
                && old(self)@.attempt == attempt@ && old(self)@.binding == binding@),
            allowed ==> final(self)@.stage is Executing && final(self)@.intent && final(self)@.approval,
            !allowed ==> final(self)@.stage is Blocked,
            final(self)@.attempt == old(self)@.attempt, final(self)@.binding == old(self)@.binding,
            valid(old(self)@) ==> valid(final(self)@),
    {
        let allowed = self.permits(attempt, binding);
        self.advance(if allowed { Event::Begin } else { Event::Interrupted });
        allowed
    }
}

}
