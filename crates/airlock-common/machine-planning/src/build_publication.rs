//! Publication quotas apply to the exact objects selected by Nix. Wire decoding,
//! iteration over Nix metadata and correspondence to transferred bytes remain adapters.
//! The production charge below rejects oversized requests before arithmetic can overflow.

use vstd::prelude::*;

verus! {

/// Maximum objects in one reviewed compilation-input publication.
pub const MAX_OBJECTS: usize = 100_000;

/// Maximum uncompressed object bytes in one publication, independently of free-space checks.
pub const MAX_BYTES: u64 = 64 * 1024 * 1024 * 1024;

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
