//! Driver-domain discovery from its own toolstack-owned XenStore subtree.
//! Directory entries are observations, not identities. The native driver must
//! validate reciprocal vif links, establish mappings and recheck its retained
//! lease marker before any parsed address can be used for admission.

use alloc::vec::Vec;
use vstd::prelude::*;

use crate::number;

verus! {

broadcast use { vstd::seq::group_seq_lemmas, vstd::seq_lib::group_seq_properties, vstd::seq::Seq::lemma_as_ref_index, crate::address::cut_unique };

/// Native NUL-separated canonical peer-domain directory names.
pub open spec fn directory(bytes: Seq<u8>, peers: Seq<u16>) -> bool
    decreases peers.len(),
{
    if peers.len() == 0 { bytes.len() == 0 } else {
        0 < peers[0] < 0x7ff0
            && (forall|i: int| 0 < i < peers.len() ==> #[trigger] peers[i] != peers[0])
            && exists|end: int| crate::address::cut(bytes, end, 0) && end < bytes.len()
                && number::digits(bytes.subrange(0, end), true)
                && number::decimal(bytes.subrange(0, end)) == peers[0]
                && directory(bytes.subrange(end+1, bytes.len() as int), peers.drop_first())
    }
}

/// A canonical native peer name and its NUL consume at most six bytes.
proof fn directory_bound(bytes: Seq<u8>, peers: Seq<u16>)
    requires directory(bytes, peers),
    ensures bytes.len() <= 6*peers.len(),
    decreases peers.len(),
{
    if peers.len() > 0 {
        let end = choose|end: int| crate::address::cut(bytes, end, 0) && end < bytes.len()
            && number::digits(bytes.subrange(0, end), true)
            && number::decimal(bytes.subrange(0, end)) == peers[0]
            && directory(bytes.subrange(end+1, bytes.len() as int), peers.drop_first());
        number::peer_width(bytes.subrange(0, end));
        directory_bound(bytes.subrange(end+1, bytes.len() as int), peers.drop_first());
    }
}

/// The first NUL separates exactly the directory grammar's head and tail.
proof fn directory_head(bytes: Seq<u8>, peers: Seq<u16>, end: int)
    requires directory(bytes, peers), bytes.len() > 0, crate::address::cut(bytes, end, 0),
    ensures peers.len() > 0, end < bytes.len(), 0 < peers[0] < 0x7ff0,
        number::digits(bytes.subrange(0, end), true),
        number::decimal(bytes.subrange(0, end)) == peers[0],
        directory(bytes.subrange(end+1, bytes.len() as int), peers.drop_first()),
        forall|i: int| 0 < i < peers.len() ==> #[trigger] peers[i] != peers[0],
{
    let actual = choose|index: int| crate::address::cut(bytes, index, 0) && index < bytes.len()
        && number::digits(bytes.subrange(0, index), true)
        && number::decimal(bytes.subrange(0, index)) == peers[0]
        && directory(bytes.subrange(index+1, bytes.len() as int), peers.drop_first());
    crate::address::cut_unique(bytes, end, actual, 0);
}

/// Canonical numeric tokens give one ordered peer list for a complete directory.
proof fn directory_unique(bytes: Seq<u8>, left: Seq<u16>, right: Seq<u16>)
    requires directory(bytes, left), directory(bytes, right),
    ensures left == right,
    decreases left.len(),
{
    if left.len() > 0 {
        let end = choose|end: int| crate::address::cut(bytes, end, 0) && end < bytes.len()
            && number::digits(bytes.subrange(0, end), true)
            && number::decimal(bytes.subrange(0, end)) == left[0]
            && directory(bytes.subrange(end+1, bytes.len() as int), left.drop_first());
        directory_head(bytes, right, end);
        directory_unique(bytes.subrange(end+1, bytes.len() as int), left.drop_first(), right.drop_first());
        assert(left =~= right);
    } else { assert(left =~= right); }
}

/// Parse one whole native directory with at most four distinct peers. Empty
/// directories are valid; malformed/truncated names or input beyond capacity
/// cannot be partially admitted. The actual lease still comes from Netback.
pub fn peers(bytes: &[u8]) -> (peers: Option<Vec<u16>>)
    ensures match peers {
        Some(value) => value@.len() <= 4 && directory(bytes@, value@),
        None => !(exists|peers: Seq<u16>| peers.len() <= 4 && directory(bytes@, peers)),
    },
{
    if bytes.len() > 24 {
        proof {
            assert forall|candidate: Seq<u16>| candidate.len() <= 4 implies !directory(bytes@, candidate) by {
                if directory(bytes@, candidate) { directory_bound(bytes@, candidate); }
            }
        }
        return None;
    }
    limited(bytes, 4)
}

/// Consume a bounded directory using standard delimiter search, numeric parsing
/// and duplicate lookup. Recursion consumes one of the four available peer slots.
fn limited(bytes: &[u8], remaining: usize) -> (peers: Option<Vec<u16>>)
    requires bytes@.len() <= 24, remaining <= 4,
    ensures match peers {
        Some(value) => value@.len() <= remaining && directory(bytes@, value@),
        None => !(exists|peers: Seq<u16>| peers.len() <= remaining && directory(bytes@, peers)),
    },
    decreases remaining,
{
    if bytes.is_empty() { return Some(Vec::new()); }
    if remaining == 0 { return None; }
    let end = bytes.iter().position(|byte: &u8| -> (found: bool)
        ensures found == (*byte == 0), { *byte == 0 }).unwrap_or(bytes.len());
    proof {
        assert(crate::address::cut(bytes@, end as int, 0));
        assert forall|candidate: Seq<u16>| directory(bytes@, candidate) implies
            candidate.len() > 0 && end < bytes@.len()
                && number::digits(bytes@.subrange(0, end as int), true)
                && number::decimal(bytes@.subrange(0, end as int)) == candidate[0]
                && 0 < candidate[0] < 0x7ff0
                && directory(bytes@.subrange(end as int+1, bytes@.len() as int), candidate.drop_first())
                && (forall|i: int| 0 < i < candidate.len() ==> #[trigger] candidate[i] != candidate[0]) by {
            directory_head(bytes@, candidate, end as int);
        }
    }
    if end == bytes.len() { return None; }
    let peer = match number::parse(&bytes[..end], 0x7fef, true) {
        Some(value) if value > 0 => value as u16,
        _ => return None,
    };
    let mut peers = limited(&bytes[end+1..], remaining-1)?;
    if peers.contains(&peer) {
        proof {
            assert forall|candidate: Seq<u16>| candidate.len() <= remaining implies !directory(bytes@, candidate) by {
                if directory(bytes@, candidate) {
                    directory_unique(bytes@.subrange(end as int+1, bytes@.len() as int), peers@, candidate.drop_first());
                }
            }
        }
        return None;
    }
    peers.insert(0, peer);
    Some(peers)
}

}
