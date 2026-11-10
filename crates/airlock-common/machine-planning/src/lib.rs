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

/// Count and byte admission for reusable compilation-input publication.
pub mod build_publication;

/// Content correspondence and complete evidence for administrative configuration validation.
pub mod validation;

/// Live private-device and home-mount checks used before guest initialization and readiness.
pub mod private_storage;

/// Typed topology-owned IPC policy, exact ordered encoding and publication/refresh bindings.
pub mod ipc_policy;

/// Exact review-source, target-family and baseline comparisons before protected-record reuse.
pub mod review_identity;

/// Exact application pin, dependency lock and observed authoring-source correspondence.
pub mod application_source;

/// Bounded native firewall recovery after an upstream Xen incarnation changes.
pub mod network_recovery;
