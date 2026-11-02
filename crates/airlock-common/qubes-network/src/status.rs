//! Bounded diagnostic reports distinguish isolation readiness from upstream
//! reachability. A decoded report is an observation; dom0 must bind it to the
//! selected artifact, protected boot challenge and current Xen incarnation.

#[cfg(not(verus_keep_ghost))]
use alloc::string::String;
use vstd::prelude::*;

verus! {

/// Isolation readiness for the native IPv4 profile, independent of internet access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(verus_keep_ghost), derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(not(verus_keep_ghost), serde(rename_all = "kebab-case"))]
pub enum State {
    /// Configuration synchronization or a complete current view is unavailable.
    Configuration,
    /// An active interface lacks usable devices, complete policy or fresh admission.
    Clients,
    /// Every active interface has a usable device and current policy admission.
    Ready,
    /// Impossible counts require terminating the native application.
    Fault,
}

/// Classify only supplied current observations, never cached readiness. The
/// selected Qubes profile assigns one IPv4 address to each frontend interface,
/// but its configured address list also includes halted VMs. Waiting for those
/// VMs would prevent dependency-ordered startup of their provider.
pub fn classify(configured: bool, expected: usize, interfaces: usize, admitted: usize) -> (state: State)
    ensures (state is Fault) == (expected > 4 || interfaces > 4 || admitted > interfaces),
        (state is Ready) == (expected <= 4 && interfaces <= expected && configured && admitted == interfaces),
{
    if expected > 4 || interfaces > 4 || admitted > interfaces { State::Fault }
    else if !configured { State::Configuration }
    else if interfaces > expected || admitted != interfaces { State::Clients }
    else { State::Ready }
}

}

/// Fixed-size observations compared without allocating on the packet scheduling path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg(not(verus_keep_ghost))]
pub struct Snapshot {
    /// Latest isolation observation after draining native control input.
    pub state: State,
    /// Current control view revision; older policy views cannot authorize forwarding.
    pub revision: u64,
    /// Configured IPv4 clients, including halted VMs; at most four.
    pub expected: usize,
    /// Native interface owners including pending admission, at most four.
    pub interfaces: usize,
    /// Interfaces with a fresh current-view packet permit, at most four.
    pub admitted: usize,
    /// A recent solicited gateway ARP answer; false indicates unknown/degraded connectivity.
    pub gateway_reachable: bool,
}

/// A bounded status record tied to one exact admitted boot.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg(not(verus_keep_ghost))]
pub struct Report {
    /// Exact current admitted boot challenge; not a secret or authorization token.
    pub boot: String,
    /// Latest observations, without packet data or endpoint addresses.
    pub snapshot: Snapshot,
}
