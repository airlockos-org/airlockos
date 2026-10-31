//! Interpret Qubes network configuration and firewall policy from native
//! QubesDB events. This crate owns bounded retained values, source quotas,
//! addressing, policy snapshots and interface-binding decisions. The protocol
//! client lives in airlock-qubesdb; packet forwarding belongs to the consumer.
//!
//! Compatibility is pinned to QubesDB 4.3.2, core-admin 4.3.44 and Linux agent
//! 4.4.0 from this repository's nixos-qubes recipes. XenStore negotiates devices;
//! it does not replace QubesDB network configuration. QubesDB watch commands
//! are local-daemon operations, not the inter-domain protocol: this guest
//! consumes replicated writes/removals after the initial full-database barrier.
//!
//! Connection state is volatile. Losing the control stream blocks forwarding
//! and new admissions for that owner permanently. A fresh VM boot must complete
//! synchronization and fresh source publications before rebuilding bindings;
//! acknowledgements promise no crash durability.
//!
//! Continuing-service progress assumes the runtime schedules this owner fairly,
//! supplies private input chunks in native stream order, publishes its exact
//! output suffix and checks monotonic deadlines before admission or I/O. Finite
//! operations have explicit byte, record and source limits. Payload accounting
//! excludes allocator/container metadata; standard allocation failure is fatal
//! to the guest lifetime. Library correspondence and effect assumptions remain
//! explicit at the Serde, standard-library and native transport boundaries.

#![no_std]
#![warn(missing_docs)]

extern crate alloc;

vstd::prelude::verus! {
/// Guest-originated current-boot synchronization notice. The host watches this
/// ordinary QubesDB key and rewrites policy through Qubes' existing NetVM API.
/// Its value correlates a boot; it never carries rules or grants authority.
#[expect(clippy::redundant_static_lifetimes, reason = "Pinned Verus requires an explicit lifetime on reference constants")]
pub const READY_PATH: &'static str = "/airlock-network-control-ready";
}

mod library;

pub mod address;
pub mod backend;
pub mod binding;
pub mod boot;

#[cfg(verus_keep_ghost)]
pub(crate) use airlock_qubesdb::wire;

mod number;

pub mod config;
pub mod control;
pub mod resolution;

pub mod cache;

pub mod policy;
pub mod projection;
pub mod rule;
