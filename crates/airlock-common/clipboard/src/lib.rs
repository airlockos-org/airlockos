//! Shared desktop clipboard ownership and bounded transfer policy without an OS.
//!
//! Trusted adapters authenticate participants; the shared clipboard retains
//! complete multi-format offers for repeated reads until they are replaced.
#![no_std]
#![warn(missing_docs)]

extern crate alloc;

pub mod shared;

/// Verified connection resource admission and cleanup accounting.
pub mod resources;

/// Object-bound authority and revocable clipboard caller capabilities.
pub mod authority;

/// Verified offer-name policy, representation uniqueness and bounded layout.
pub mod formats;

/// Verified bounded parsing over immutable packet snapshots.
pub mod packet;

/// Verified frame ordering, replay rejection and bounded packet ownership.
pub mod framing;

mod library;

/// Opaque replacement identities and checked time/deadline arithmetic.
pub mod values;

/// Bounded clipboard wire claims, encoded independently of Xen or application authority.
pub mod protocol;

/// Owned endpoint admission and quarantine coupled to checked resource accounting.
pub mod connections;

/// Validated deployment boot observations, separate from runtime caller authority.
pub mod boot;
