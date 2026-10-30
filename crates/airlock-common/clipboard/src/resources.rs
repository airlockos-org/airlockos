//! Admission accounting for live and quarantined clipboard connections.
//! Quarantined connections keep their reservation until transport cleanup succeeds.

use vstd::prelude::*;

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

/// Maximum simultaneously admitted data connections.
pub const LIVE_LIMIT: usize = 32;

/// Total live and retiring reservations, including uncooperative peers.
pub const SLOT_LIMIT: usize = 64;

/// Checked reservation ledger used by the actual service loop.
/// Transport handles and their correspondence to these counts remain runtime adapters.
pub struct Slots {
    /// Reservations that may receive and process requests.
    live: usize,
    /// Reservations whose grants have not yet been safely released.
    retiring: usize,
}

impl Slots {
    /// Live reservations represented by this ledger.
    pub closed spec fn live_count(&self) -> usize { self.live }

    /// Quarantined reservations represented by this ledger.
    pub closed spec fn retiring_count(&self) -> usize { self.retiring }

    /// Construct an empty ledger without allocating memory.
    pub fn new() -> (slots: Self)
        ensures slots.valid(), slots.live_count() == 0, slots.retiring_count() == 0,
    { Self { live: 0, retiring: 0 } }

    /// Capacity and arithmetic invariants preserved by every transition.
    pub closed spec fn valid(&self) -> bool {
        self.live <= LIVE_LIMIT && self.retiring <= SLOT_LIMIT
            && self.live + self.retiring <= SLOT_LIMIT
    }

    /// Reserve before creating a transport endpoint; rejection changes no ownership.
    pub fn admit(&mut self) -> (accepted: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).retiring_count() == old(self).retiring_count(),
            accepted == (old(self).live_count() < LIVE_LIMIT && old(self).live_count() + old(self).retiring_count() < SLOT_LIMIT),
            accepted ==> final(self).live_count() == old(self).live_count() + 1,
            !accepted ==> final(self).live_count() == old(self).live_count(),
    {
        if self.live >= LIVE_LIMIT || self.live + self.retiring >= SLOT_LIMIT { return false; }
        self.live += 1;
        true
    }

    /// Move a live reservation to quarantine without making its capacity reusable.
    pub fn retire(&mut self) -> (changed: bool)
        requires old(self).valid(),
        ensures final(self).valid(), changed == (old(self).live_count() > 0),
            changed ==> final(self).live_count() + 1 == old(self).live_count() && final(self).retiring_count() == old(self).retiring_count() + 1,
            !changed ==> final(self).live_count() == old(self).live_count() && final(self).retiring_count() == old(self).retiring_count(),
    {
        if self.live == 0 { return false; }
        self.live -= 1;
        self.retiring += 1;
        true
    }

    /// Undo admission when endpoint construction fails before ownership is installed.
    pub fn release_live(&mut self) -> (changed: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).retiring_count() == old(self).retiring_count(),
            changed == (old(self).live_count() > 0),
            changed ==> final(self).live_count() + 1 == old(self).live_count(),
            !changed ==> final(self).live_count() == old(self).live_count(),
    {
        if self.live == 0 { return false; }
        self.live -= 1;
        true
    }

    /// Return exactly the reservations whose transport cleanup has completed.
    pub fn release_retired(&mut self, count: usize) -> (changed: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).live_count() == old(self).live_count(),
            changed == (count <= old(self).retiring_count()),
            changed ==> final(self).retiring_count() + count == old(self).retiring_count(),
            !changed ==> final(self).retiring_count() == old(self).retiring_count(),
    {
        if count > self.retiring { return false; }
        self.retiring -= count;
        true
    }

    /// Observe counts for adapter correspondence checks and payload-free diagnostics.
    pub fn counts(&self) -> (counts: (usize, usize))
        ensures counts.0 == self.live_count(), counts.1 == self.retiring_count(),
    { (self.live, self.retiring) }
}

}

impl Default for Slots {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_admission_rejects_overflow_and_returns_exact_credits() {
        let mut budget = Budget::new(8 * 1024 * 1024);
        assert!(budget.reserve(5 * 1024 * 1024));
        let before = budget.usage();
        assert!(!budget.reserve(usize::MAX));
        assert!(!budget.release(usize::MAX));
        assert_eq!(budget.usage(), before);
        assert!(budget.reserve(3 * 1024 * 1024));
        assert!(!budget.reserve(1));
        assert!(budget.release(8 * 1024 * 1024));
        assert_eq!(budget.usage(), (0, 8 * 1024 * 1024));
        assert!(!budget.release(1));
    }

    #[test]
    fn failed_cleanup_keeps_capacity_charged_and_success_recovers_it() {
        let mut slots = Slots::new();
        for _ in 0..LIVE_LIMIT {
            assert!(slots.admit());
        }
        assert!(!slots.admit());
        for _ in 0..LIVE_LIMIT {
            assert!(slots.retire());
        }
        for _ in 0..LIVE_LIMIT {
            assert!(slots.admit());
            assert!(slots.retire());
        }
        assert_eq!(slots.counts(), (0, SLOT_LIMIT));
        assert!(!slots.admit());
        assert!(!slots.release_retired(usize::MAX));
        assert!(slots.release_retired(SLOT_LIMIT));
        assert!(!slots.retire());
        assert!(!slots.release_live());
        assert!(slots.admit());
        assert!(slots.release_live());
        assert_eq!(slots.counts(), (0, 0));
    }
}
