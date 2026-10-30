//! Object-bound admission capabilities and reconnect invalidation.
//!
//! A participant is descriptive metadata, never authorization. Each clipboard
//! creates a distinct provisioning capability. Its holder may admit identities
//! authenticated by the GUI adapter; the resulting non-cloneable caller belongs
//! to that clipboard and to exactly one revocable membership incarnation.

use alloc::sync::Arc;
use vstd::prelude::*;

verus! {

/// Observed principal and connection lifetime; constructing metadata grants no access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Participant {
    /// Stable, nonzero identity assigned by the machine's GUI membership policy.
    principal: u64,
    /// Nonzero incarnation assigned by trusted provisioning, never by data requests.
    epoch: u64,
}

impl Participant {
    /// Logical principal observed through this opaque identity.
    pub closed spec fn principal_id(&self) -> u64 { self.principal }

    /// Logical incarnation observed through this opaque identity.
    pub closed spec fn incarnation(&self) -> u64 { self.epoch }

    /// Validate identity metadata without manufacturing an admission capability.
    pub const fn from_binding(principal: u64, epoch: u64) -> (out: Option<Self>)
        ensures out.is_some() == (principal > 0 && epoch > 0),
            out.is_some() ==> out.unwrap().principal_id() == principal && out.unwrap().incarnation() == epoch,
    {
        if principal == 0 || epoch == 0 { None } else { Some(Self { principal, epoch }) }
    }

    /// Return the policy-assigned principal for metadata or trusted provisioning.
    pub fn principal(&self) -> (value: u64)
        ensures value == self.principal_id(),
    { self.principal }

    /// Return the authenticated connection incarnation for metadata.
    pub fn epoch(&self) -> (value: u64)
        ensures value == self.incarnation(),
    { self.epoch }
}

/// One registry entry; zero denotes an unused reservation, never an admitted caller.
#[derive(Clone, Copy)]
struct Binding {
    /// Policy principal, or zero for an unused entry.
    principal: u64,
    /// Issued connection incarnation, or zero for an unused entry.
    epoch: u64,
}

/// Checked admission decision carried unchanged into the caller capability.
struct Ticket {
    /// Exact registry entry checked at every effect boundary.
    slot: usize,
    /// Admitted identity; does not itself establish continuing membership.
    identity: Participant,
}

impl Ticket {
    /// Read descriptive identity without exposing a constructor for the ticket.
    fn identity(&self) -> (identity: Participant)
        ensures identity == self.identity,
    { self.identity }
}

/// Fixed membership registry; retiring transports are accounted separately.
struct Registry {
    /// At most 32 active memberships, with no allocation or input-driven growth.
    entries: [Binding; 32],
    /// Greatest admitted incarnation; exhaustion rejects rather than wrapping.
    latest: u64,
}

impl Registry {
    /// All entries denote empty slots or previously admitted, nonzero incarnations.
    closed spec fn valid(&self) -> bool {
        forall|i: int| 0 <= i < 32 ==> ((self.entries[i].principal == 0) == (self.entries[i].epoch == 0))
            && self.entries[i].epoch <= self.latest
    }

    /// Successful admission requires freshness, unique membership and a free slot.
    closed spec fn eligible(&self, identity: Participant) -> bool {
        identity.principal > 0 && identity.epoch > self.latest
            && (forall|i: int| 0 <= i < 32 ==> self.entries[i].principal != identity.principal)
            && (exists|i: int| 0 <= i < 32 && self.entries[i].principal == 0)
    }

    /// Exact membership, including entry reuse and connection incarnation.
    closed spec fn permits(&self, ticket: &Ticket) -> bool {
        ticket.slot < 32 && ticket.identity.principal > 0 && ticket.identity.epoch > 0
            && self.entries[ticket.slot as int].principal == ticket.identity.principal
            && self.entries[ticket.slot as int].epoch == ticket.identity.epoch
    }

    /// Start empty without allocating; no ticket from another registry grants access.
    fn new() -> (registry: Self)
        ensures registry.valid(), registry.latest == 0,
            forall|i: int| 0 <= i < 32 ==> registry.entries[i].principal == 0,
    {
        Self { entries: [Binding { principal: 0, epoch: 0 }; 32], latest: 0 }
    }

    /// Admit only a fresh incarnation, a new principal and an available fixed slot.
    /// Invalid or exhausted admission leaves every existing membership unchanged.
    fn admit(&mut self, identity: Participant) -> (out: Option<Ticket>)
        requires old(self).valid(),
        ensures final(self).valid(), out.is_some() == old(self).eligible(identity),
            out.is_some() ==> final(self).permits(&out.unwrap()) && out.unwrap().identity == identity
                && final(self).latest == identity.epoch && identity.epoch > old(self).latest,
            out.is_some() ==> forall|j: int| 0 <= j < 32 && j != out.unwrap().slot
                ==> final(self).entries[j] == old(self).entries[j],
            out.is_none() ==> *final(self) == *old(self),
    {
        if identity.principal == 0 || identity.epoch == 0 || identity.epoch <= self.latest { return None; }
        let mut free: Option<usize> = None;
        let mut i = 0;
        while i < 32
            invariant self.valid(), *self == *old(self), i <= 32,
                forall|j: int| 0 <= j < i ==> self.entries[j].principal != identity.principal,
                free.is_some() == (exists|j: int| 0 <= j < i && self.entries[j].principal == 0),
                free.is_some() ==> free.unwrap() < i && self.entries[free.unwrap() as int].principal == 0,
            decreases 32 - i,
        {
            if self.entries[i].principal == identity.principal { return None; }
            if self.entries[i].principal == 0 { free = Some(i); }
            i += 1;
        }
        if let Some(slot) = free {
            self.entries[slot] = Binding { principal: identity.principal, epoch: identity.epoch };
            self.latest = identity.epoch;
            Some(Ticket { slot, identity })
        } else { None }
    }

    /// Revalidate the exact current incarnation; stale tickets never authorize reuse.
    fn allows(&self, ticket: &Ticket) -> (allowed: bool)
        ensures allowed == self.permits(ticket),
    {
        ticket.slot < 32 && ticket.identity.principal > 0 && ticket.identity.epoch > 0
            && self.entries[ticket.slot].principal == ticket.identity.principal
            && self.entries[ticket.slot].epoch == ticket.identity.epoch
    }

    /// Revoke only this exact incarnation; an old ticket cannot revoke its successor.
    fn revoke(&mut self, ticket: &Ticket)
        requires old(self).valid(),
        ensures final(self).valid(), !final(self).permits(ticket), final(self).latest == old(self).latest,
            !old(self).permits(ticket) ==> *final(self) == *old(self),
            forall|j: int| 0 <= j < 32 && j != ticket.slot
                ==> final(self).entries[j] == old(self).entries[j],
    {
        if self.allows(ticket) {
            self.entries[ticket.slot] = Binding { principal: 0, epoch: 0 };
        }
    }
}

}

/// Sole capability authorizing GUI-authenticated admissions for one clipboard.
/// The constructor returns this independently from the service so data connections
/// never receive it. It cannot be serialized, cloned or built from an identity.
pub struct Provisioner {
    /// Unique object identity shared only with this clipboard's admission scope.
    scope: Arc<()>,
}

/// Owned permission for one admitted connection; every use rechecks revocation.
/// Observed participant metadata is deliberately insufficient to construct this type.
///
/// ```compile_fail
/// use airlock_clipboard_core::shared::{Clipboard, Participant};
/// let (mut clipboard, _provisioner) = Clipboard::new(1024);
/// let identity = Participant::from_binding(1, 1).unwrap();
/// clipboard.reserve(0, &identity);
/// ```
pub struct Caller {
    /// Object identity prevents a ticket from another clipboard being replayed.
    scope: Arc<()>,
    /// Checked registry admission, retained unchanged through the effect adapter.
    ticket: Ticket,
}

impl Caller {
    /// Inspect descriptive identity without yielding provisioning authority.
    pub fn identity(&self) -> Participant {
        self.ticket.identity()
    }
}

/// Clipboard-owned admission state; only the associated provisioner can mint callers.
pub(crate) struct Admissions {
    /// Stable object identity, independent of movement of the containing clipboard.
    scope: Arc<()>,
    /// Verified revocable memberships, bounded independently of transport quarantine.
    registry: Registry,
}

impl Admissions {
    /// Create an isolated authority scope during service initialization.
    pub(crate) fn new() -> (Self, Provisioner) {
        // Boundary: alloc::sync::Arc identity/lifetime operations are trusted Rust
        // library effects, not Verus-verified. Pointer equality checks object identity,
        // not an attacker-controlled numeric label. Construction OOM is an explicitly
        // fatal startup condition; subsequent clones of this Arc do not allocate.
        let scope = Arc::new(());
        let provisioner = Provisioner {
            scope: scope.clone(),
        };
        (
            Self {
                scope,
                registry: Registry::new(),
            },
            provisioner,
        )
    }

    /// Mint a caller only with the exact object capability and a fresh admission.
    pub(crate) fn admit(
        &mut self,
        provisioner: &Provisioner,
        identity: Participant,
    ) -> Option<Caller> {
        if !Arc::ptr_eq(&self.scope, &provisioner.scope) {
            return None;
        }
        let ticket = self.registry.admit(identity)?;
        Some(Caller {
            scope: self.scope.clone(),
            ticket,
        })
    }

    /// Require both object ownership and a still-live registry incarnation.
    pub(crate) fn allows(&self, caller: &Caller) -> bool {
        Arc::ptr_eq(&self.scope, &caller.scope) && self.registry.allows(&caller.ticket)
    }

    /// Retire authorization before fallible asynchronous transport cleanup starts.
    pub(crate) fn revoke(&mut self, caller: &Caller) {
        if Arc::ptr_eq(&self.scope, &caller.scope) {
            self.registry.revoke(&caller.ticket);
        }
    }
}
