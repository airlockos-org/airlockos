//! Driver-domain discovery from its own toolstack-owned XenStore subtree.
//! Directory entries are observations, not identities. The native driver must
//! validate reciprocal vif links, establish mappings and recheck its retained
//! lease marker before any parsed address can be used for admission.

use alloc::vec::Vec;
use vstd::prelude::*;

use crate::number;

verus! {

/// Native NUL-separated canonical peer-domain directory names.
pub open spec fn directory(bytes: Seq<u8>, peers: Seq<u16>) -> bool
    decreases peers.len(),
{
    if peers.len() == 0 { bytes.len() == 0 } else {
        0 < peers[0] < 0x7ff0
            && (forall|i: int| 0 < i < peers.len() ==> peers[i] != peers[0])
            && exists|end: int| crate::address::cut(bytes, end, 0) && end < bytes.len()
                && number::digits(bytes.subrange(0, end), true)
                && number::decimal(bytes.subrange(0, end)) == peers[0]
                && directory(bytes.subrange(end+1, bytes.len() as int), peers.drop_first())
    }
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
    if bytes.len() > 24 { return None; }
    let mut peers = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len()
        invariant cursor <= bytes.len() <= 24, peers@.len() <= 4,
            directory(bytes@.subrange(0, cursor as int), peers@),
        decreases bytes.len()-cursor,
    {
        if peers.len() == 4 { return None; }
        let end = cursor+bytes[cursor..].iter().position(|byte| *byte == 0).unwrap_or(bytes.len()-cursor);
        if end == bytes.len() { return None; }
        let peer = match number::parse(&bytes[cursor..end], 0x7fef, true) {
            Some(value) if value > 0 => value as u16,
            _ => return None,
        };
        let mut i = 0;
        while i < peers.len()
            invariant i <= peers.len() <= 4,
                forall|j: int| 0 <= j < i ==> peers@[j] != peer,
            decreases peers.len()-i,
        {
            if peers[i] == peer { return None; }
            i += 1;
        }
        peers.push(peer);
        cursor = end+1;
    }
    Some(peers)
}

}
