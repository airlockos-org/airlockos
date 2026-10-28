//! Typed Xen framing and the Hermit service for the shared Airlock clipboard.
//!
//! The boot-provisioned GUI authority admits participants to direct Xen channels.
//! Clipboard ownership and transfer policy live in `airlock-clipboard-core`.
#![warn(missing_docs)]

pub mod shared;

#[cfg(target_os = "hermit")]
pub mod service;
