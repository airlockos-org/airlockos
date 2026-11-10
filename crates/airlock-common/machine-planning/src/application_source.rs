//! Bind the authoring library actually selected for a build to the reviewed application pin.
//! Nix verifies recursive tree hashes; serde and filesystem/Nix adapters supply these observations.
//! Matching source inputs does not grant review, build or activation authority.

use vstd::prelude::*;

verus! {

/// Accept source only when the machine's application pin agrees with its lock and
/// the observed source has that exact revision and recursive tree hash.
pub fn matches_pin(
    requested_revision: &str,
    locked_revision: &str,
    locked_hash: &str,
    observed_revision: &str,
    observed_hash: &str,
) -> (matches: bool)
    ensures matches == (
        requested_revision@ == locked_revision@
        && locked_revision@ == observed_revision@
        && locked_hash@ == observed_hash@
    ),
{
    requested_revision == locked_revision
        && locked_revision == observed_revision
        && locked_hash == observed_hash
}

}
