//! Distinct identities and time observations used by clipboard policy.
//! A wire generation is a claim that still needs an ownership/lifetime check;
//! constructing one never authorizes an operation. A time observation similarly
//! does not promise clock monotonicity: the lifecycle checks regressions explicitly.

use vstd::prelude::*;

verus! {

/// Replacement identity within one service lifetime; zero denotes no issued offer.
#[derive(Clone, Copy, Debug, Eq)]
pub struct Generation {
    /// Ordered protocol value, kept distinct from principal, epoch and request IDs.
    value: u64,
}

#[cfg(verus_keep_ghost)]
impl vstd::std_specs::cmp::PartialEqSpecImpl for Generation {
    open spec fn obeys_eq_spec() -> bool { true }

    open spec fn eq_spec(&self, other: &Self) -> bool { *self == *other }
}

impl PartialEq for Generation {
    fn eq(&self, other: &Self) -> (equal: bool)
        ensures equal == (*self == *other),
    { self.value == other.value }
}

impl Generation {
    /// Logical replacement identity, independent of its wire representation.
    pub closed spec fn number(&self) -> u64 { self.value }

    /// Decode an observed identity without granting access to that generation.
    pub const fn from_wire(value: u64) -> (generation: Self)
        ensures generation.number() == value,
    { Self { value } }

    /// Encode this identity at the wire boundary.
    pub fn get(&self) -> (value: u64)
        ensures value == self.number(),
    { self.value }

    /// Issue a strictly newer replacement, rejecting exhaustion instead of wrapping.
    pub fn next(&self) -> (out: Option<Self>)
        ensures out.is_some() == (self.number() < u64::MAX),
            out.is_some() ==> out.unwrap().number() == self.number() + 1,
    {
        if self.value == u64::MAX { None } else { Some(Self { value: self.value + 1 }) }
    }

    /// Invalidate a failed offer without ever wrapping a stale identity into validity.
    /// Exhaustion retains the last counter; availability is separately cleared.
    pub fn invalidated(&self) -> (out: Self)
        ensures out.number() >= self.number(),
            out.number() == if self.number() < u64::MAX { self.number() + 1 } else { u64::MAX as int },
    {
        if self.value == u64::MAX { Self { value: self.value } }
        else { Self { value: self.value + 1 } }
    }
}

/// Nanoseconds observed from the injected service clock, never from a VM request.
#[derive(Clone, Copy, Debug, Eq)]
pub struct Time {
    /// Raw observation; monotonic ordering is checked rather than assumed.
    nanos: u64,
}

#[cfg(verus_keep_ghost)]
impl vstd::std_specs::cmp::PartialEqSpecImpl for Time {
    open spec fn obeys_eq_spec() -> bool { true }

    open spec fn eq_spec(&self, other: &Self) -> bool { *self == *other }
}

impl PartialEq for Time {
    fn eq(&self, other: &Self) -> (equal: bool)
        ensures equal == (*self == *other),
    { self.nanos == other.nanos }
}

impl Time {
    /// Logical observation in nanoseconds.
    pub closed spec fn observation(&self) -> u64 { self.nanos }

    /// Wrap an explicit clock observation without asserting that it is trustworthy or monotonic.
    pub const fn observe(nanos: u64) -> (time: Self)
        ensures time.observation() == nanos,
    { Self { nanos } }

    /// Detect a backwards observation at a lifecycle boundary.
    pub fn before(&self, previous: Self) -> (regressed: bool)
        ensures regressed == (self.observation() < previous.observation()),
    { self.nanos < previous.nanos }

    /// Establish a bounded completion deadline, rejecting arithmetic overflow.
    pub fn deadline_after(&self, duration: u64) -> (out: Option<Deadline>)
        ensures out.is_some() == (self.observation() + duration <= u64::MAX),
            out.is_some() ==> out.unwrap().end() == self.observation() + duration,
    {
        if duration > u64::MAX - self.nanos { None }
        else { Some(Deadline { nanos: self.nanos + duration }) }
    }
}

/// Fixed completion boundary, created only by checked timestamp arithmetic.
#[derive(Clone, Copy, Debug, Eq)]
pub struct Deadline {
    /// First clock observation at which the unfinished operation is expired.
    nanos: u64,
}

#[cfg(verus_keep_ghost)]
impl vstd::std_specs::cmp::PartialEqSpecImpl for Deadline {
    open spec fn obeys_eq_spec() -> bool { true }

    open spec fn eq_spec(&self, other: &Self) -> bool { *self == *other }
}

impl PartialEq for Deadline {
    fn eq(&self, other: &Self) -> (equal: bool)
        ensures equal == (*self == *other),
    { self.nanos == other.nanos }
}

impl Deadline {
    /// Logical first-expired instant.
    pub closed spec fn end(&self) -> u64 { self.nanos }

    /// Expire at the boundary, including a forward clock jump beyond it.
    pub fn expired_at(&self, now: Time) -> (expired: bool)
        ensures expired == (now.observation() >= self.end()),
    { now.nanos >= self.nanos }
}

}
