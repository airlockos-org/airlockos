//! Typed Xen framing for the Airlock clipboard, separate from its pure policy.
//!
//! The laboratory authority is feature gated and trusts only the provisioned dom0
//! endpoint. A production adapter must obtain decisions from Qubes GUI policy.
#![warn(missing_docs)]

pub mod protocol;

#[cfg(feature = "lab-authority")]
pub mod laboratory;
