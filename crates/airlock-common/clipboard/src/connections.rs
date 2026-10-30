//! Owned live and quarantined transport resources with one checked admission ledger.
//! Construction happens only after admission; failed cleanup keeps both the handle
//! and its credit. The effect adapter supplies truthful construction/close outcomes.

use crate::resources::{LIVE_LIMIT, SLOT_LIMIT, Slots};
use alloc::vec::Vec;
use vstd::prelude::*;

verus! {

/// Startup metadata could not be reserved inside the bounded application arena.
#[derive(Clone, Copy, Debug)]
pub struct Exhausted;

/// Admission rejects capacity before invoking an endpoint constructor.
pub enum InsertError<E> {
    /// All live or total handle credits are already owned.
    Capacity,
    /// Endpoint construction failed without returning a resource owner.
    Build(
        /// Dependency-specific construction failure, without clipboard bytes.
        E,
    ),
}

/// Exclusive transport ownership coupled to the production admission ledger.
pub struct Connections<T> {
    /// Active handles that may process authenticated requests.
    live: Vec<T>,
    /// Revoked handles retained until the transport confirms cleanup.
    retiring: Vec<T>,
    /// Credits correspond exactly to the two owned collections.
    slots: Slots,
}

impl<T> Connections<T> {
    /// Exact correspondence between checked credits and actual owned values.
    pub closed spec fn valid(&self) -> bool {
        self.slots.valid() && self.live@.len() == self.slots.live_count()
            && self.retiring@.len() == self.slots.retiring_count()
    }

    /// Current owners, available to proofs without duplicating mutable counters.
    pub closed spec fn owners(&self) -> (Seq<T>, Seq<T>) { (self.live@, self.retiring@) }

    /// Reserve fixed metadata once, before creating any peer resources.
    pub fn new() -> (out: Result<Self, Exhausted>)
        ensures out.is_ok() ==> out.unwrap().valid() && out.unwrap().owners() == (Seq::<T>::empty(), Seq::<T>::empty()),
    {
        let mut live = Vec::new();
        live.try_reserve_exact(LIVE_LIMIT).map_err(|_| Exhausted)?;
        let mut retiring = Vec::new();
        retiring.try_reserve_exact(SLOT_LIMIT).map_err(|_| Exhausted)?;
        Ok(Self { live, retiring, slots: Slots::new() })
    }

    /// Construct exactly one resource while this exclusive borrow reserves checked capacity.
    /// No other admission can interleave. Publish owner and credit only on success;
    /// failed or unwound construction leaves the collection and ledger unchanged.
    /// The constructor returns acquired resources in T, or releases partial effects
    /// on error; an effect adapter must terminate if that release is uncertain.
    pub fn insert_with<U, E, F: FnOnce() -> Result<(T, U), E>>(&mut self, build: F) -> (out: Result<U, InsertError<E>>)
        requires old(self).valid(), build.requires(()),
        ensures final(self).valid(),
            out.is_ok() ==> final(self).owners().0.len() == old(self).owners().0.len() + 1
                && final(self).owners().1 == old(self).owners().1,
            out.is_err() ==> final(self).owners() == old(self).owners(),
    {
        if !self.slots.can_admit() { return Err(InsertError::Capacity); }
        match build() {
            Ok((owner, result)) => {
                let _admitted = self.slots.admit();
                self.live.push(owner);
                Ok(result)
            },
            Err(error) => Err(InsertError::Build(error)),
        }
    }

    /// Number of active handles; the bound is independent of hostile peer behavior.
    pub fn live_len(&self) -> (count: usize)
        requires self.valid(),
        ensures count == self.owners().0.len(), count <= LIVE_LIMIT,
    { self.slots.counts().0 }

    /// Number of resources whose release remains uncertain.
    pub fn retiring_len(&self) -> (count: usize)
        requires self.valid(),
        ensures count == self.owners().1.len(), count <= SLOT_LIMIT,
    { self.slots.counts().1 }

    /// Borrow an active owner without permitting collection or ledger mutation.
    pub fn live_mut(&mut self, index: usize) -> (owner: Option<&mut T>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).owners().0.len() == old(self).owners().0.len(),
            final(self).owners().1 == old(self).owners().1,
            owner.is_some() == (index < old(self).owners().0.len()),
    { self.live.get_mut(index) }

    /// Move ownership into quarantine; no resource is dropped or credit released.
    pub fn retire(&mut self, index: usize) -> (changed: bool)
        requires old(self).valid(),
        ensures final(self).valid(), changed == (index < old(self).owners().0.len()),
            changed ==> final(self).owners().1 == old(self).owners().1.push(old(self).owners().0[index as int])
                && final(self).owners().0 == old(self).owners().0.remove(index as int),
            !changed ==> final(self).owners() == old(self).owners(),
    {
        if index >= self.live.len() { return false; }
        let owner = self.live.remove(index);
        let _retired = self.slots.retire();
        self.retiring.push(owner);
        true
    }

    /// Release an owner only after its close callback confirms completed cleanup.
    /// A false result may change the resource's cleanup progress but retains its
    /// owner and reservation. The callback cannot mutate this collection.
    pub fn reclaim_with<F: FnOnce(&mut T) -> bool>(&mut self, index: usize, close: F) -> (released: bool)
        requires old(self).valid(), forall|owner: &mut T| close.requires((owner,)),
        ensures final(self).valid(), final(self).owners().0 == old(self).owners().0,
            final(self).owners().1.len() + (if released { 1int } else { 0int }) == old(self).owners().1.len(),
    {
        if index >= self.retiring.len() { return false; }
        if !close(&mut self.retiring[index]) { return false; }
        self.retiring.remove(index);
        let _released = self.slots.release_retired(1);
        true
    }
}

}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn construction_failure_and_quarantine_preserve_exact_capacity() {
        let mut peers = Connections::<usize>::new().unwrap();
        assert!(matches!(
            peers.insert_with(|| Err::<(usize, ()), _>(7)),
            Err(InsertError::Build(7))
        ));
        assert_eq!(peers.live_len(), 0);
        for value in 0..LIVE_LIMIT {
            assert!(peers.insert_with(|| Ok::<_, ()>((value, ()))).is_ok());
        }
        let called = Cell::new(false);
        assert!(matches!(
            peers.insert_with(|| {
                called.set(true);
                Ok::<_, ()>((99, ()))
            }),
            Err(InsertError::Capacity)
        ));
        assert!(!called.get());
        for _ in 0..LIVE_LIMIT {
            assert!(peers.retire(0));
        }
        assert!(!peers.retire(0));
        assert!(!peers.reclaim_with(0, |_| false));
        assert_eq!(peers.retiring_len(), LIVE_LIMIT);
        for value in 0..LIVE_LIMIT {
            assert!(peers.insert_with(|| Ok::<_, ()>((value, ()))).is_ok());
        }
        for _ in 0..LIVE_LIMIT {
            assert!(peers.retire(0));
        }
        assert_eq!(peers.retiring_len(), SLOT_LIMIT);
        assert!(matches!(
            peers.insert_with(|| Ok::<_, ()>((7, ()))),
            Err(InsertError::Capacity)
        ));
        assert!(peers.reclaim_with(0, |_| true));
        assert!(peers.insert_with(|| Ok::<_, ()>((8, ()))).is_ok());
        assert_eq!(peers.live_len(), 1);
        assert_eq!(peers.retiring_len(), SLOT_LIMIT - 1);
    }
}
