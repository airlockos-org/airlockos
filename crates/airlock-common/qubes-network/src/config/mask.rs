//! Proof correspondence for the standard integer netmask operations.
//! No executable bit-counting or mask parser is implemented here.

use crate::number::population;
use vstd::prelude::*;
use vstd::std_specs::bits::{axiom_u32_leading_ones, u32_leading_ones};

verus! {

/// One bit numbered from the most significant native IPv4 position.
pub(super) open spec fn bit(value: u32, index: int) -> bool {
    (value >> (31-index) as u32) & 1u32 != 0
}

/// The complete word has exactly these contiguous leading one bits.
pub(super) open spec fn shape(value: u32, prefix: int) -> bool {
    0 <= prefix <= 32 && forall|i: int| 0 <= i < 32 ==> bit(value, i) == (i < prefix)
}

/// Extending the inspected prefix cannot reduce its set-bit count.
proof fn monotone(value: u32, prefix: int, count: int)
    requires 0 <= prefix <= count <= 32,
    ensures population(value, prefix) <= population(value, count),
    decreases count-prefix,
{
    if prefix < count { monotone(value, prefix, count-1); }
}

/// A contiguous prefix contributes one per leading position and zero thereafter.
proof fn count_shape(value: u32, prefix: int, count: int)
    requires 0 <= prefix <= 32, 0 <= count <= 32,
        forall|i: int| 0 <= i < count ==> bit(value, i) == (i < prefix),
    ensures population(value, count) == if count <= prefix { count } else { prefix },
    decreases count,
{
    if count > 0 {
        count_shape(value, prefix, count-1);
        assert(bit(value, count-1) == (count-1 < prefix));
    }
}

/// An unchanged set-bit count means no later inspected position contains a one.
proof fn empty_suffix(value: u32, prefix: int, count: int)
    requires 0 <= prefix <= count <= 32,
        population(value, prefix) == population(value, count),
    ensures forall|i: int| prefix <= i < count ==> !bit(value, i),
    decreases count-prefix,
{
    if prefix < count {
        monotone(value, prefix, count-1);
        assert(!bit(value, count-1));
        empty_suffix(value, prefix, count-1);
    }
}

/// Standard leading-ones and population counts agree exactly for contiguous masks.
pub(super) proof fn contiguous(value: u32, prefix: u32, total: u32)
    requires prefix == u32_leading_ones(value), total == population(value, 32),
    ensures prefix <= 32,
        total == prefix ==> shape(value, prefix as int),
        total != prefix ==> !(exists|candidate: int| shape(value, candidate)),
{
    axiom_u32_leading_ones(value);
    assert forall|i: int| 0 <= i < prefix implies bit(value, i) by {
        let shift = (31-i) as u32;
        assert(32-prefix <= shift < 32);
        assert((value >> shift) & 1u32 == 1);
    }
    count_shape(value, prefix as int, prefix as int);
    if total == prefix {
        empty_suffix(value, prefix as int, 32);
    } else {
        assert forall|candidate: int| !#[trigger] shape(value, candidate) by {
            if shape(value, candidate) {
                if candidate < prefix {
                    assert(bit(value, candidate));
                    assert(!bit(value, candidate));
                }
                if candidate > prefix {
                    assert(prefix < 32);
                    assert((value >> (31-prefix)) & 1u32 == 0);
                    assert(bit(value, prefix as int));
                }
                count_shape(value, candidate, 32);
            }
        }
    }
}

}
