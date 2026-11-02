//! Closed application profiles describe capabilities that reviewed artifacts may
//! request. They are validation inputs, not permission to create a Xen device.

use vstd::prelude::*;

verus! {

/// Maximum downstream interfaces in the current native firewall profile.
pub const NETWORK_CLIENTS: usize = 4;

/// Executable selection independent of clipboard's peer-authority mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(verus_keep_ghost), derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(not(verus_keep_ghost), serde(rename_all = "kebab-case"))]
pub enum Application {
    /// Isolated clipboard service with no network interfaces.
    Clipboard,
    /// IPv4 firewall with one upstream and at most four downstream interfaces.
    Firewall,
}

impl Application {
    /// The profile has native network-provider responsibilities.
    pub open spec fn provider(self) -> bool { self is Firewall }

    /// Identify the explicit network-provider application; never infer it from a VM name.
    pub fn networking(self) -> (yes: bool)
        ensures yes == self.provider(),
    { matches!(self, Self::Firewall) }

    /// Require exactly the profile's network relationships. Clipboard cannot
    /// have an upstream or clients; firewall requires a declared upstream and
    /// provider role and must fit all active/retiring native interface slots.
    pub fn valid_links(self, upstream: bool, provides_network: bool, clients: usize) -> (valid: bool)
        ensures valid == if self.provider() { upstream && provides_network && clients <= 4 }
            else { !upstream && !provides_network && clients == 0 },
    {
        match self {
            Self::Clipboard => !upstream && !provides_network && clients == 0,
            Self::Firewall => upstream && provides_network && clients <= NETWORK_CLIENTS,
        }
    }

    /// Admit only the tested fixed-memory firewall profile, while preserving
    /// clipboard's existing 16–256 MiB range. GUI authority adds its own minimum.
    pub fn valid_memory(self, mib: u64) -> (valid: bool)
        ensures valid == if self.provider() { mib == 256 } else { 16 <= mib <= 256 },
    {
        match self {
            Self::Clipboard => (16..=256).contains(&mib),
            Self::Firewall => mib == 256,
        }
    }
}

}
