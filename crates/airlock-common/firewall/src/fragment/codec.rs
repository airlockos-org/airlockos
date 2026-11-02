//! Narrow etherparse reassembly boundary. Airlock validates all byte intervals,
//! rejects overlaps, limits slots/ranges and owns expiry before these effects.
//! The dependency supplies contiguous assembly and completion detection; an
//! incomplete buffer is never exposed as bytes, including its unfilled holes.

use alloc::vec::Vec;
use etherparse::{IpFragOffset, IpNumber, defrag::IpDefragBuf};
use vstd::prelude::*;

verus! {

/// Reuse the actual maintained implementation; no model replaces its storage.
#[cfg(verus_keep_ghost)]
#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExIpDefragBuf(/// Owned library assembly, including its initialized intervals.
    IpDefragBuf);

/// Initialized bytes retained by the actual library assembly, excluding holes.
pub(crate) uninterp spec fn image(buffer: IpDefragBuf) -> IMap<int, u8>;

/// Final payload length from a received last fragment, if any.
pub(crate) uninterp spec fn end(buffer: IpDefragBuf) -> Option<nat>;

/// Number of library interval records, which never exceeds admitted fragments.
pub(crate) uninterp spec fn intervals(buffer: IpDefragBuf) -> nat;

/// Fixed dependency resource contract for one admitted ordinary-IP assembly.
pub(crate) open spec fn bounded(buffer: IpDefragBuf) -> bool {
    intervals(buffer) <= 64 && (end(buffer).is_some() ==> end(buffer).unwrap() <= 65_535)
        && forall|i: int| image(buffer).dom().contains(i) ==> 0 <= i < 65_535
}

/// Complete data contains every byte before the declared end, with no holes.
pub(crate) open spec fn assembled(buffer: IpDefragBuf) -> bool {
    end(buffer).is_some() && image(buffer).dom() == ISet::new(|i: int| 0 <= i < end(buffer).unwrap())
}

/// Allocate one fixed-capacity payload buffer only after admission has a slot.
#[verifier::external_body]
pub(crate) fn new(protocol: u8) -> (buffer: IpDefragBuf)
    ensures bounded(buffer), image(buffer) == IMap::<int, u8>::empty(), end(buffer).is_none(), intervals(buffer) == 0,
{
    IpDefragBuf::new(IpNumber(protocol), Vec::with_capacity(65_535), Vec::with_capacity(64))
}

/// Add only a caller-admitted nonempty, disjoint interval. Allocation and writes
/// cannot exceed the preallocated 65535-byte payload or 64-range capacity.
#[verifier::external_body]
pub(crate) fn add(buffer: &mut IpDefragBuf, offset: usize, more: bool, payload: &[u8]) -> (accepted: bool)
    requires bounded(*old(buffer)), intervals(*old(buffer)) < 64,
        offset % 8 == 0, offset <= 65_535, payload@.len() <= 65_535 - offset,
        end(*old(buffer)).is_some() ==> offset + payload@.len() <= end(*old(buffer)).unwrap()
            && (!more ==> offset + payload@.len() == end(*old(buffer)).unwrap()),
        !more ==> forall|byte: int| image(*old(buffer)).dom().contains(byte) ==> byte < offset + payload@.len(),
    ensures bounded(*final(buffer)), accepted ==>
        image(*final(buffer)) == image(*old(buffer)).union_prefer_right(IMap::new(
            |i: int| offset <= i < offset + payload@.len(), |i: int| payload@[i - offset]))
        && intervals(*final(buffer)) <= intervals(*old(buffer)) + 1
        && end(*final(buffer)) == if more { end(*old(buffer)) } else { Some((offset + payload@.len()) as nat) },
{
    let Ok(offset) = IpFragOffset::try_from((offset / 8) as u16) else { return false; };
    buffer.add(offset, more, payload).is_ok()
}

/// Complete means a final length exists and every preceding byte was received.
#[verifier::external_body]
pub(crate) fn complete(buffer: &IpDefragBuf) -> (complete: bool)
    requires bounded(*buffer), ensures complete == assembled(*buffer),
{ buffer.is_complete() }

/// Consume only a complete library assembly. Dependency correspondence promises
/// the exact admitted payload, bounded by the ordinary IP length field.
#[verifier::external_body]
pub(crate) fn finish(buffer: IpDefragBuf) -> (payload: Vec<u8>)
    requires bounded(buffer), assembled(buffer),
    ensures payload@.len() == end(buffer).unwrap() <= 65_535,
        forall|i: int| 0 <= i < payload@.len() ==> payload@[i] == image(buffer)[i],
{ buffer.take_bufs().0 }

}
