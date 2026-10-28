//! Check a complete foreground schedule before either startup phase can execute.
//! Canonical guest indices and resolved hard edges come from the topology adapter.

use vstd::prelude::*;

verus! {

/// Execution phase relative to the guarded GUI handoff.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Headless services whose hard prerequisites can start before the GUI.
    BeforeGui,
    /// The single GUI started by the existing GPU guard.
    Gui,
    /// Services admitted only after the running GUI handoff.
    AfterGui,
}

/// Execution precedence, with canonical index order breaking ties inside a phase.
pub open spec fn rank(phase: Phase) -> int {
    match phase { Phase::BeforeGui => 0, Phase::Gui => 1, Phase::AfterGui => 2 }
}

/// Every canonical guest has exactly one phase and only the selected GUI occupies the handoff.
pub open spec fn partition(stages: Seq<Phase>, gui: int) -> bool {
    0 <= gui < stages.len() && forall|i: int| 0 <= i < stages.len()
        ==> ((#[trigger] stages[i] is Gui) == (i == gui))
}

/// Every hard provider executes earlier, including edges crossing the GUI handoff.
pub open spec fn ordered(parents: Seq<Vec<usize>>, stages: Seq<Phase>) -> bool {
    parents.len() == stages.len() && forall|i: int, j: int|
        0 <= i < parents.len() && 0 <= j < parents[i].len() ==> {
            let p = #[trigger] parents[i][j] as int;
            0 <= p < i && rank(stages[p]) <= rank(stages[i])
        }
}

/// A complete schedule checked against every hard edge; its phase vector cannot be replaced.
/// Canonical indices represent each guest once, so selecting phases partitions the whole input.
///
/// ```compile_fail
/// use airlock_deployment_core::boot::startup::{Phase, Plan};
/// /// An unchecked phase vector cannot authorize startup.
/// fn bypass() -> Plan {
///     Plan { stages: vec![Phase::Gui] }
/// }
/// ```
pub struct Plan {
    // Exactly one phase for every canonical input guest, including the GUI.
    stages: Vec<Phase>,
}

impl View for Plan {
    type V = Seq<Phase>;

    closed spec fn view(&self) -> Self::V { self.stages@ }
}

/// Compare phases without admitting a GUI prerequisite into the earlier phase.
fn precedes(provider: Phase, client: Phase) -> (out: bool)
    ensures out == (rank(provider) <= rank(client)),
{
    matches!((provider, client), (Phase::BeforeGui, _) | (_, Phase::AfterGui) | (Phase::Gui, Phase::Gui))
}

impl Plan {
    /// Reject omitted guests, duplicate GUI slots, backward edges and invalid phase boundaries.
    /// The caller proposes phases for the entire canonical graph, never a selected subset of edges.
    pub fn check(parents: &[Vec<usize>], gui: usize, stages: Vec<Phase>) -> (out: Option<Self>)
        ensures out.is_some() == (partition(stages@, gui as int) && ordered(parents@, stages@)),
            out.is_some() ==> out.unwrap()@ == stages@,
    {
        if stages.len() != parents.len() || gui >= stages.len() { return None; }
        let mut i = 0;
        while i < stages.len()
            invariant stages.len() == parents.len(), gui < stages.len(), 0 <= i <= stages.len(),
                forall|k: int| 0 <= k < i ==> ((#[trigger] stages[k] is Gui) == (k == gui)),
                forall|k: int, j: int| 0 <= k < i && 0 <= j < parents[k].len() ==> {
                    let p = #[trigger] parents[k][j] as int;
                    0 <= p < k && rank(stages[p]) <= rank(stages[k])
                },
            decreases stages.len() - i,
        {
            if matches!(stages[i], Phase::Gui) != (i == gui) { return None; }
            let mut j = 0;
            while j < parents[i].len()
                invariant stages.len() == parents.len(), i < stages.len(),
                    0 <= j <= parents[i as int].len(),
                    forall|k: int| 0 <= k < j ==> {
                        let p = #[trigger] parents[i as int][k] as int;
                        0 <= p < i && rank(stages[p]) <= rank(stages[i as int])
                    },
                decreases parents[i as int].len() - j,
            {
                let p = parents[i][j];
                if p >= i || !precedes(stages[p], stages[i]) { return None; }
                j += 1;
            }
            i += 1;
        }
        Some(Self { stages })
    }

    /// Inspect one canonical guest without exposing mutable scheduling state.
    pub fn phase(&self, index: usize) -> (out: Option<Phase>)
        ensures index < self@.len() ==> out == Some(self@[index as int]),
            index >= self@.len() ==> out.is_none(),
    {
        if index < self.stages.len() { Some(self.stages[index]) } else { None }
    }
}

}
