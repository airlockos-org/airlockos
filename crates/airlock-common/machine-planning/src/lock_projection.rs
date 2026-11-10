//! Check the only permitted lock transformation: unchanged root bindings and removal
//! of unused dependency nodes. Serde's node encoding and Nix's lock validity remain
//! adapter contracts; matching a projection grants no approval or deployment authority.

use vstd::prelude::*;

verus! {

/// Accept exactly matching root identity/bindings and unchanged retained nodes.
/// Node strings encode their names and complete contents, including dependency edges.
/// Standard slice membership owns searching and string equality; only the
/// project-specific projection condition and its finite iteration are verified here.
pub fn matches(
    expected_root: &str,
    observed_root: &str,
    expected_nodes: &[&str],
    observed_nodes: &[&str],
) -> (valid: bool)
    ensures valid == (
        expected_root@ == observed_root@
        && forall|i: int| 0 <= i < observed_nodes.len()
            ==> expected_nodes.contains(&observed_nodes[i])
    ),
{
    if expected_root != observed_root { return false; }
    let mut i = 0;
    while i < observed_nodes.len()
        invariant
            i <= observed_nodes.len(),
            forall|j: int| 0 <= j < i ==> expected_nodes.contains(&observed_nodes[j]),
        decreases observed_nodes.len() - i,
    {
        if !expected_nodes.contains(&observed_nodes[i]) { return false; }
        i += 1;
    }
    true
}

}
