//! Fixed-capacity application allocation shared by Hermit services. Byte credits
//! are deterministic core computation; the optional Talc adapter owns pointer,
//! layout and lock correspondence. Neither layer grants Xen or service authority.

#![no_std]
#![warn(missing_docs)]

#[cfg(feature = "allocator")]
extern crate std;

use vstd::prelude::*;

#[cfg(feature = "allocator")]
mod allocator;

#[cfg(feature = "allocator")]
pub use allocator::FixedHeap;

verus! {

/// Byte credits consumed by every successful application heap allocation.
/// The allocator adapter ties credits to actual pointer/layout ownership; these
/// checked transitions prove the byte bound under that explicit trusted contract.
pub struct Budget {
    /// Maximum sum of live requested allocation sizes.
    limit: usize,
    /// Requested bytes owned by currently live allocations.
    used: usize,
    /// Largest successfully charged byte count in this budget's lifetime.
    peak: usize,
}

impl Budget {
    /// Start with all byte credits available; no allocation is performed.
    pub const fn new(limit: usize) -> (budget: Self)
        ensures budget.valid(), budget.used_bytes() == 0, budget.limit_bytes() == limit,
    { Self { limit, used: 0, peak: 0 } }

    /// Configured byte limit for this ledger.
    pub closed spec fn limit_bytes(&self) -> usize { self.limit }

    /// Allocation and high-water counters stay within the configured limit.
    pub closed spec fn valid(&self) -> bool {
        self.used <= self.peak && self.peak <= self.limit
    }

    /// Current requested bytes represented by this ledger.
    pub closed spec fn used_bytes(&self) -> usize { self.used }

    /// Charge one successful allocation; rejection preserves the previous state.
    pub fn reserve(&mut self, bytes: usize) -> (accepted: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).limit_bytes() == old(self).limit_bytes(),
            accepted == (bytes <= old(self).limit_bytes() - old(self).used_bytes()),
            accepted ==> final(self).used_bytes() == old(self).used_bytes() + bytes,
            !accepted ==> final(self).used_bytes() == old(self).used_bytes(),
    {
        if bytes > self.limit - self.used { return false; }
        self.used += bytes;
        if self.used > self.peak { self.peak = self.used; }
        true
    }

    /// Return credits only for a corresponding freed allocation's original layout.
    pub fn release(&mut self, bytes: usize) -> (released: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).limit_bytes() == old(self).limit_bytes(),
            released == (bytes <= old(self).used_bytes()),
            released ==> final(self).used_bytes() + bytes == old(self).used_bytes(),
            !released ==> final(self).used_bytes() == old(self).used_bytes(),
    {
        if bytes > self.used { return false; }
        self.used -= bytes;
        true
    }

    /// Return current and peak requested bytes, both bounded by the original limit.
    pub fn usage(&self) -> (usage: (usize, usize))
        requires self.valid(),
        ensures usage.0 == self.used_bytes(), usage.0 <= usage.1, usage.1 <= self.limit_bytes(),
    { (self.used, self.peak) }
}

}
