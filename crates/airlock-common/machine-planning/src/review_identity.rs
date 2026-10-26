//! Compare the complete source/target identity and deployed baseline of a review request.
//! Equality can select a matching protected record; it does not grant approval or execution
//! authority. Nominal-type projection, record decoding and retained extension-map equality
//! remain ordinary Rust boundaries. The executable comparisons below are used in production.

use vstd::prelude::*;

verus! {

/// Review scope distinguishes the whole machine from any one guest, including an empty name.
pub enum Target<'a> {
    /// Whole-machine source review, including host effects subject to separate scope checks.
    Machine,
    /// Review restricted to the exact named guest.
    Guest(
        /// Original guest name; nominal validation happens before projection.
        &'a str,
    ),
}

/// Source and target coordinates that must remain together when identifying a review.
pub struct Identity<'a> {
    /// Exact reviewed Git revision.
    pub revision: &'a str,
    /// Exact dependency-lock digest.
    pub lock: &'a str,
    /// Closed interpretation of the request's target family and guest identity.
    pub target: Target<'a>,
}

/// Mathematical target equality preserves family as well as guest spelling.
pub open spec fn same_target(a: Target, b: Target) -> bool {
    match (a, b) {
        (Target::Machine, Target::Machine) => true,
        (Target::Guest(x), Target::Guest(y)) => x@ == y@,
        _ => false,
    }
}

/// Exact equality of every protected source and target coordinate.
pub open spec fn same_identity(a: Identity, b: Identity) -> bool {
    a.revision@ == b.revision@ && a.lock@ == b.lock@ && same_target(a.target, b.target)
}

fn target_equal(a: &Target, b: &Target) -> (equal: bool)
    ensures equal == same_target(*a, *b),
{
    match (a, b) {
        (Target::Machine, Target::Machine) => true,
        (Target::Guest(x), Target::Guest(y)) => *x == *y,
        _ => false,
    }
}

/// Compare source identities without encoding a record or normalizing its fields.
pub fn equal(a: &Identity, b: &Identity) -> (equal: bool)
    ensures equal == same_identity(*a, *b),
{
    a.revision == b.revision && a.lock == b.lock && target_equal(&a.target, &b.target)
}

/// Review reuse also requires the exact original deployed baseline.
pub fn same_context(a: &Identity, a_baseline: &str, b: &Identity, b_baseline: &str) -> (equal: bool)
    ensures equal == (same_identity(*a, *b) && a_baseline@ == b_baseline@),
{
    equal(a, b) && a_baseline == b_baseline
}

}
