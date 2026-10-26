//! Match machine artifacts and relationships before calculating deployment effects.
//! These decisions grant no activation authority. Cargo executes the same Rust bodies that
//! Verus checks; configuration decoding and external observations remain adapters.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub mod names;

pub mod graph;

pub mod topology;

pub mod deployment;

pub mod effects;

/// Guest-admission evidence matched to complete immutable candidate requirements.
pub mod admission;

/// Content correspondence and complete evidence for administrative configuration validation.
pub mod validation;

/// Live private-device and home-mount checks used before guest initialization and readiness.
pub mod private_storage;

/// Typed topology-owned IPC policy, exact ordered encoding and publication/refresh bindings.
pub mod ipc_policy;
