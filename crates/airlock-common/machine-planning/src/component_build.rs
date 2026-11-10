//! A recipe can be replayed only for the same complete evaluation input. A
//! successful child must also return the exact recipe and output requested.
//! The adapters supply the input digest, checked store paths, and Nix's own
//! registration observations. None of this evidence authorizes a deployment.

use vstd::prelude::*;

verus! {

/// Select replay only when the input identity matches and Nix retains the recipe.
/// A collected output can be realized from that recipe without repeating evaluation.
pub fn replay(expected: &str, recorded: &str, recipe_registered: bool) -> (valid: bool)
    ensures valid == (expected@ == recorded@ && recipe_registered),
{
    expected == recorded && recipe_registered
}

/// Require a completed realization to report both the selected recipe and its expected output.
pub fn completed(
    derivation: &str,
    output: &str,
    realized_derivation: &str,
    realized_output: &str,
) -> (valid: bool)
    ensures valid == (derivation@ == realized_derivation@ && output@ == realized_output@),
{
    derivation == realized_derivation && output == realized_output
}

}
