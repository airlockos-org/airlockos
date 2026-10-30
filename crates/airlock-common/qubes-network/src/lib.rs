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
//! and new admissions. A fresh, fully synchronized stream is required before
//! rebuilding interface bindings; acknowledgements promise no crash durability.

#![no_std]
#![warn(missing_docs)]

extern crate alloc;

/// Guest-originated current-boot synchronization notice. The host watches this
/// ordinary QubesDB key and rewrites policy through Qubes' existing NetVM API.
/// Its value correlates a boot; it never carries rules or grants authority.
pub const READY_PATH: &str = "/airlock-network-control-ready";

pub mod address;
pub mod backend;
pub mod binding;
pub mod boot;

#[cfg(verus_keep_ghost)]
pub(crate) use airlock_qubesdb::wire;

mod number;

pub mod config;
pub mod control;

pub mod cache;

pub mod policy;
pub mod projection;
pub mod rule;
