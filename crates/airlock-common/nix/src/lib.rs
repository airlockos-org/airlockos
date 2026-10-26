//! Shared Nix types, validation and runtime support for Airlock applications.
//!
//! Airlock separates application and build VMs from dom0, the administrative
//! host. Qubes qrexec supplies policy-controlled calls between these domains.
//! A Nix system closure is an immutable system artifact plus its dependencies.
//! Source review binds a proposed commit and dependency selection to the deployed
//! baseline; a deployment plan describes its VM effects and reboot requirement.
//!
//! Parsed records describe data; they do not authenticate its sender. In
//! particular, the checked workflow in [`review`] is not a replacement for dom0's
//! protected approval state or Qubes qrexec policy. Role-specific runtime
//! executables use those existing services and keep observation read-only.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod command;

/// Failures kept structured until the command or wire boundary.
pub mod error;

/// Validated names and source digests shared across VM boundaries.
pub mod identity;

/// Sparse boot-image identity without transport or filesystem dependencies.
pub mod root_artifact;

/// Immutable Hermit executable identity and Xen PVH loader validation.
pub mod hermit_artifact;

/// Shared guest-admission claims and candidate bindings.
pub mod admission;

/// Content-bound offline configuration validation and administrative apply inputs.
pub mod configuration;

#[cfg(feature = "artifacts")]
pub mod artifact;

pub mod job;

pub mod review;

#[cfg(feature = "runtime")]
pub mod runtime;

pub mod state;

pub mod store_path;

mod wire;

pub use error::{Error, Result};
