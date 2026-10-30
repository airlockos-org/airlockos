//! Consume Qubes' existing configuration stream without creating control authority.
//! Native QubesDB supplies a bounded private replica; complete per-source rule
//! snapshots and toolstack-bound interface lifetimes remain separate objects.
//! Packet policy and forwarding belong to the firewall consumer.
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

mod bytes;

mod number;

pub mod config;
pub mod control;

pub mod database;

pub mod policy;
pub mod projection;
pub mod rule;

pub mod wire;
