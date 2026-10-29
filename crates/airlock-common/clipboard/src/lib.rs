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
