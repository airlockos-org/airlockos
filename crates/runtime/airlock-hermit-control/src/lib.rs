//! Own the existing dom0 QubesDB transport and borrow policy with an actual
//! connected Xen interface. Packet routing and machine role construction remain
//! responsibilities of the firewall application and its deployment integration.
//!
//! airlock-qubesdb owns framing and sequencing; airlock-qubes-network owns
//! retained values, source quotas, policy decisions and interface binding.
//! The Xen adapter is an explicit effect boundary: native syscall byte counts,
//! selected peer/port, monotonic-clock correspondence, retained kernel resource
//! ownership and cooperative single-thread scheduling are trusted dependencies.
//! It cannot manufacture policy or turn a packet's source into a lease identity.

#![warn(missing_docs)]

#[cfg(target_os = "hermit")]
pub mod xen;
