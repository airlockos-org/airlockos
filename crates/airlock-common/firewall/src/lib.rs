//! A routed IPv4 experiment with explicit interface, policy and time inputs.
//! Packet bytes never select interface authority. Outputs retain the exact
//! connection/lease labels and observation revision and must be checked again
//! immediately before a native send. This crate performs no Xen operations.
//!
//! Compatibility baseline: qubes-core-agent-linux v4.4.0 firewall.py,
//! network/qubes-ipv4.nft and qubes-setup-dnat-to-ns. Ordered outbound rules,
//! assigned-source checks, masquerading and related replies are retained.
//! Every packet rechecks current policy, including established connections.
//! IPv6, IP options and all fragments are dropped in this initial experiment;
//! this is not full replacement compatibility. The application never bridges.
//!
//! smoltcp owns IP/transport field access and checksums; domain owns DNS
//! message parsing, name handling and encoding. Those libraries, alloc collections and ChaCha are dependency trust
//! boundaries, not first-party packet parsers or a second network socket stack.

#![no_std]
#![warn(missing_docs)]

extern crate alloc;

mod dns;
mod engine;
mod flow;
mod library;
mod policy;
mod wire;

pub use engine::{Engine, Output, Owner, Target};
pub use wire::FRAME_BYTES;

vstd::prelude::verus! {

/// Maximum simultaneously retained NAT leases, including closing hold-downs.
pub const MAX_FLOWS: usize = 1024;

/// One client can consume at most one quarter of the NAT table.
pub const CLIENT_FLOWS: usize = 256;

/// Maximum attached client interfaces, matching the native driver limit.
pub const MAX_CLIENTS: usize = 4;

/// Maximum queued frames per destination; full queues drop the new frame.
pub const QUEUE_FRAMES: usize = 16;

/// Maximum Ethernet payload; forwarding does not create IP fragments.
pub const MTU: usize = 1500;

/// Nanoseconds per second for all absolute monotonic deadlines.
const SECOND: u64 = 1_000_000_000;

}
