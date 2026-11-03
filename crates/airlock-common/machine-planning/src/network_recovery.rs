//! Bound a native firewall restart to an observed upstream incarnation change.
//! Qubes owns locks, teardown and activation. The adapter binds these domain IDs
//! to one VM object, reviewed generation and protected boot challenge. State is
//! volatile: a toolstack reload can reconstruct a running boot, but cannot infer
//! an absent guest's prior running intent. Explicit stop requests revoke intent.

use vstd::prelude::*;

verus! {

/// Original native boot and its upstream, authenticated by the host adapter.
#[derive(Clone, Copy)]
pub struct Binding {
    /// Native Xen domain belonging to the protected original boot.
    child: u16,
    /// Upstream Xen domain captured before that boot was spawned.
    peer: u16,
}

impl Binding {
    /// Reject reserved or missing Xen identities before retaining a boot observation.
    pub fn new(child: u16, peer: u16) -> (binding: Option<Self>)
        ensures binding.is_some() == (0 < child < 0x7ff0 && 0 < peer < 0x7ff0),
            binding.is_some() ==> binding.unwrap().valid()
                && binding.unwrap().identities() == (child, peer),
    {
        if child == 0 || child >= 0x7ff0 || peer == 0 || peer >= 0x7ff0 { return None; }
        Some(Self { child, peer })
    }

    /// Original child and upstream identities, exposed only to specifications.
    pub closed spec fn identities(self) -> (u16, u16) { (self.child, self.peer) }

    /// Domain IDs remain within the native transport's supported range.
    pub closed spec fn valid(self) -> bool { 0 < self.child < 0x7ff0 && 0 < self.peer < 0x7ff0 }
}

/// Fresh power observation; unknown, paused and transitional states are unavailable.
#[derive(Clone, Copy)]
pub enum Power {
    /// Exact live Xen domain, further bound to its protected challenge by the adapter.
    Running {
        /// Native Xen identity observed through the current Qubes VM object.
        xid: u16,
    },
    /// Qubes reports the domain halted; its own start still drains prior cleanup.
    Halted,
    /// No lifecycle effect is permitted from an ambiguous or paused observation.
    Unavailable,
}

/// Ordered operations within one restart attempt.
#[derive(Clone, Copy, PartialEq, Eq, StructuralEq)]
pub enum Stage {
    /// Acquire Qubes' startup lock before checking and stopping the original boot.
    Lock,
    /// Await Qubes' complete shutdown while retaining the acquired startup lock.
    Stop,
    /// Use Qubes' normal start, whose own startup lock and pre-events guard activation.
    Start,
}

/// A non-cloneable callback identity, consumed at each transition.
pub struct Ticket {
    /// Monotonic attempt number; replacement attempts never reuse it.
    serial: u64,
}

impl Ticket {
    /// Attempt identity for contracts; this cannot create or clone a runtime ticket.
    pub closed spec fn identity(self) -> u64 { self.serial }

    /// Identify an owned callback for error retirement; this does not construct a permission.
    pub fn sequence(&self) -> (serial: u64)
        ensures serial == self.identity(),
    { self.serial }
}

/// Retained intent and the only permitted in-flight transition.
enum State {
    /// No observed running intent, or an explicit stop has revoked it.
    Off,
    /// Running intent survives an unexpected exit; the last attempted peer prevents loops.
    Armed {
        /// Last authenticated native boot, even if it subsequently exited.
        binding: Binding,
        /// Original or most recently attempted upstream incarnation.
        handled: u16,
    },
    /// Exactly one attempt is active for this original native boot and target peer.
    Active {
        /// Original boot whose resources must be torn down before activation.
        binding: Binding,
        /// Upstream incarnation selecting this attempt.
        peer: u16,
        /// Only this operation can consume the current ticket.
        stage: Stage,
    },
}

/// One VM's bounded restart intent; it neither starts VMs nor changes their NetVM.
pub struct Recovery {
    /// Last issued attempt; exhaustion disables new attempts rather than wrapping.
    serial: u64,
    /// Coupled intent, upstream selection and operation sequencing.
    state: State,
}

impl Recovery {
    /// Last issued attempt, exposed only for monotonicity and exhaustion contracts.
    pub closed spec fn issued(self) -> u64 { self.serial }

    /// Start without inferred authority to revive a halted guest.
    pub fn inactive() -> (state: Self)
        ensures state.valid(), forall|s: u64, step: Stage, peer: u16| !state.pending(s, step, peer),
    { Self { serial: 0, state: State::Off } }

    /// All retained identities are valid; active attempts have a positive unique serial.
    pub closed spec fn valid(self) -> bool {
        match self.state {
            State::Off => true,
            State::Armed { binding, handled } => binding.valid() && 0 < handled < 0x7ff0,
            State::Active { binding, peer, .. } => binding.valid() && 0 < peer < 0x7ff0 && self.serial > 0,
        }
    }

    /// Exact active callback and step, rather than a reusable running/ready flag.
    pub closed spec fn pending(self, serial: u64, step: Stage, peer: u16) -> bool {
        match self.state {
            State::Active { peer: expected, stage, .. } => self.serial == serial && stage == step && expected == peer,
            _ => false,
        }
    }

    /// New upstream observations can recover only the original live boot or its halted successor state.
    pub closed spec fn eligible(self, power: Power, peer: u16) -> bool {
        match self.state {
            State::Armed { binding, handled } => 0 < peer < 0x7ff0 && peer != handled
                && match power { Power::Running { xid } => xid == binding.child, Power::Halted => true, _ => false },
            _ => false,
        }
    }

    /// A held startup lock still refers to the original boot, or to an observed halt.
    pub closed spec fn compatible(self, serial: u64, power: Power, peer: u16) -> bool {
        self.pending(serial, Stage::Lock, peer) && match self.state {
            State::Active { binding, .. } => match power {
                Power::Running { xid } => xid == binding.child,
                Power::Halted => true,
                Power::Unavailable => false,
            },
            _ => false,
        }
    }

    /// Retain an authenticated running boot; stale callbacks cannot operate on this replacement.
    pub fn arm(&mut self, binding: Binding)
        requires old(self).valid(), binding.valid(),
        ensures final(self).valid(), final(self).issued() == old(self).issued(),
            forall|s: u64, step: Stage, peer: u16| !final(self).pending(s, step, peer),
    { self.state = State::Armed { binding, handled: binding.peer }; }

    /// Revoke every outstanding callback without pretending a dispatched effect was cancelled.
    pub fn cancel(&mut self)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).issued() == old(self).issued(),
            forall|s: u64, step: Stage, peer: u16| !final(self).pending(s, step, peer),
    { self.state = State::Off; }

    /// Issue one attempt for a changed upstream; failed attempts cannot retry that same peer.
    pub fn begin(&mut self, power: Power, peer: u16) -> (ticket: Option<Ticket>)
        requires old(self).valid(),
        ensures final(self).valid(),
            ticket.is_some() == (old(self).eligible(power, peer) && old(self).issued() < u64::MAX),
            ticket.is_some() ==> ticket.unwrap().identity() == old(self).issued() + 1
                && final(self).pending(ticket.unwrap().identity(), Stage::Lock, peer),
            ticket.is_none() ==> *final(self) == *old(self),
    {
        let State::Armed { binding: boot, handled: previous } = self.state else { return None; };
        if self.serial == u64::MAX || peer == 0 || peer >= 0x7ff0 || peer == previous { return None; }
        match power {
            Power::Running { xid } => if xid != boot.child { return None; },
            Power::Halted => {},
            Power::Unavailable => return None,
        }
        self.serial += 1;
        self.state = State::Active { binding: boot, peer, stage: Stage::Lock };
        Some(Ticket { serial: self.serial })
    }

    /// Check an activation callback at every Qubes pre-event and before each owned effect.
    pub fn permits(&self, ticket: &Ticket, stage: Stage, peer: u16) -> (allowed: bool)
        requires self.valid(),
        ensures allowed == self.pending(ticket.identity(), stage, peer),
    {
        match self.state {
            State::Active { peer: expected, stage: current, .. } => ticket.serial == self.serial && current == stage && expected == peer,
            _ => false,
        }
    }

    /// Consume the acquired-lock ticket after fresh observations, selecting stop or direct start.
    pub fn locked(&mut self, ticket: Ticket, power: Power, peer: u16) -> (next: Option<(Ticket, Stage)>)
        requires old(self).valid(),
        ensures final(self).valid(), next.is_some() == old(self).compatible(ticket.identity(), power, peer),
            next.is_some() ==> old(self).pending(ticket.identity(), Stage::Lock, peer)
            && next.unwrap().0.identity() == ticket.identity()
            && final(self).pending(ticket.identity(), next.unwrap().1, peer)
            && (next.unwrap().1 == Stage::Stop || next.unwrap().1 == Stage::Start)
            && (next.unwrap().1 == Stage::Start ==> power is Halted)
            && (next.unwrap().1 == Stage::Stop ==> power is Running),
    {
        if !self.permits(&ticket, Stage::Lock, peer) { self.fail(ticket); return None; }
        let State::Active { binding: boot, .. } = self.state else { return None; };
        let stage = match power {
            Power::Halted => Stage::Start,
            Power::Running { xid } => {
                if xid != boot.child { self.fail(ticket); return None; }
                Stage::Stop
            },
            Power::Unavailable => { self.fail(ticket); return None; },
        };
        self.state = State::Active { binding: boot, peer, stage };
        Some((ticket, stage))
    }

    /// Permit start only after successful, observed Qubes teardown on the same upstream.
    pub fn stopped(&mut self, ticket: Ticket, halted: bool, peer: u16) -> (next: Option<Ticket>)
        requires old(self).valid(),
        ensures final(self).valid(), next.is_some() == (halted && old(self).pending(ticket.identity(), Stage::Stop, peer)),
            next.is_some() ==> halted
            && old(self).pending(ticket.identity(), Stage::Stop, peer)
            && next.unwrap().identity() == ticket.identity()
            && final(self).pending(ticket.identity(), Stage::Start, peer),
    {
        if !halted || !self.permits(&ticket, Stage::Stop, peer) { self.fail(ticket); return None; }
        let State::Active { binding: boot, .. } = self.state else { return None; };
        self.state = State::Active { binding: boot, peer, stage: Stage::Start };
        Some(ticket)
    }

    /// Consume completion only for an authenticated new boot using the selected upstream.
    pub fn complete(&mut self, ticket: Ticket, binding: Binding) -> (accepted: bool)
        requires old(self).valid(), binding.valid(),
        ensures final(self).valid(), accepted == old(self).pending(ticket.identity(), Stage::Start, binding.identities().1),
    {
        if !self.permits(&ticket, Stage::Start, binding.peer) { self.fail(ticket); return false; }
        self.arm(binding);
        true
    }

    /// Retire a failed owned attempt; replay on the same upstream remains ineligible.
    pub fn fail(&mut self, ticket: Ticket)
        requires old(self).valid(),
        ensures final(self).valid(),
            forall|power: Power, peer: u16| old(self).pending(ticket.identity(), Stage::Lock, peer)
                || old(self).pending(ticket.identity(), Stage::Stop, peer)
                || old(self).pending(ticket.identity(), Stage::Start, peer)
                ==> !final(self).eligible(power, peer),
    {
        self.fail_active(ticket.serial);
    }

    /// Revoke an exact in-flight attempt after an adapter failure; this grants no effect.
    pub fn fail_active(&mut self, serial: u64)
        requires old(self).valid(),
        ensures final(self).valid(),
            forall|power: Power, peer: u16| old(self).pending(serial, Stage::Lock, peer)
                || old(self).pending(serial, Stage::Stop, peer)
                || old(self).pending(serial, Stage::Start, peer)
                ==> !final(self).eligible(power, peer),
    {
        if serial != self.serial { return; }
        if let State::Active { binding, peer, .. } = self.state {
            self.state = State::Armed { binding, handled: peer };
        }
    }
}

}
