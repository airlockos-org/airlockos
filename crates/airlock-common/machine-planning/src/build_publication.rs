//! Publication quotas apply to the exact objects selected by Nix. Wire decoding,
//! iteration over Nix metadata and correspondence to transferred bytes remain adapters.
//! The production charge below rejects oversized requests before arithmetic can overflow.

use vstd::prelude::*;

verus! {

/// Maximum objects in one reviewed compilation-input publication.
pub const MAX_OBJECTS: usize = 100_000;

/// Maximum uncompressed object bytes in one publication, independently of free-space checks.
pub const MAX_BYTES: u64 = 64 * 1024 * 1024 * 1024;

/// Maximum protected preparation records and temporary metadata roots.
pub const MAX_PREPARATIONS: usize = 1024;

/// Maximum preparation retirements in one background pass.
pub const MAX_RETIREMENTS: usize = 64;

/// Keep a bounded preparation namespace while permitting an existing token to retry.
pub fn preparation_fits(count: usize, existing: bool) -> (fits: bool)
    ensures fits == (count <= MAX_PREPARATIONS && (existing || count < MAX_PREPARATIONS)),
{
    count <= MAX_PREPARATIONS && (existing || count < MAX_PREPARATIONS)
}

/// Exclusive permission to end ownership of one original protected preparation.
pub struct Retirement {
    // Original preparation identity; effects cannot substitute another token.
    identity: String,
}

impl View for Retirement {
    type V = Seq<char>;

    closed spec fn view(&self) -> Self::V { self.identity@ }
}

impl Retirement {
    /// Read the exact token accepted by the retirement decision.
    pub fn identity(&self) -> (identity: &str)
        ensures identity@ == self@,
    { self.identity.as_str() }
}

/// Retire completed ownership or expired authority, preserving every live unfinished job.
/// `completed` includes an acknowledged retirement intent during crash recovery.
pub fn retire(identity: String, completed: bool, authority_live: bool) -> (out: Option<Retirement>)
    ensures out.is_some() == (identity@.len() > 0 && (completed || !authority_live)),
        out.is_some() ==> out.unwrap()@ == identity@,
{
    if identity.is_empty() || (!completed && authority_live) { None }
    else { Some(Retirement { identity }) }
}

/// Account for the next actual object under the complete inventory's count and byte ceilings.
/// Failure leaves the caller's previous total available and never produces an admitted total.
pub fn charge(count: usize, current: u64, next: u64) -> (out: Option<u64>)
    ensures
        out.is_some() <==> (0 < count <= MAX_OBJECTS && current as int + next as int <= MAX_BYTES),
        out.is_some() ==> out.unwrap() as int == current as int + next as int,
{
    if count == 0 || count > MAX_OBJECTS || current > MAX_BYTES {
        return None;
    }
    if next > MAX_BYTES - current {
        None
    } else {
        Some(current + next)
    }
}

}
