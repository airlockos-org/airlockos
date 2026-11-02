//! A bounded dual-stack routed firewall with explicit interface, policy and time
//! inputs. Packet bytes never select interface authority. Every output retains
//! its exact connection/lease labels and observation revision for a fresh check
//! immediately before native send. This crate performs no Xen operations.
//!
//! Compatibility baseline: qubes-core-agent-linux v4.4.0 firewall.py,
//! network/qubes-ipv4.nft, network/qubes-ipv6.nft and qubes-setup-dnat-to-ns;
//! qubes-core-admin v4.3.44 supplies the static client addressing contract.
//! Ordered outbound policy, assigned-source checks, IPv4/IPv6 masquerading,
//! echo and related errors share one flow table and per-client quota. Current
//! policy is rechecked even for established connections. No bridging occurs.
//!
//! IPv6 has scoped solicited neighbor discovery, bounded options/fragment
//! handling and translated Packet Too Big quotes. Pre-existing IPv4 options and
//! fragment exclusions remain. IPv6 routing/AH/ESP, mobility headers and jumbo
//! payloads are unsupported; unknown options requiring non-skip processing are
//! dropped. IPv6 extension chains are limited to eight headers and 256 bytes.
//! Reassembly admits 64 disjoint parts per slot, one slot per client and two
//! upstream slots, with fixed 15-second lifetimes. Output preserves the largest
//! original fragment size so it cannot undo path-MTU learning. Recent fragment
//! error history shares flow-sized quotas; eviction drops old error detail.
//!
//! smoltcp supplies wire access/checksums and the single policy-DNS TCP endpoint;
//! etherparse supplies extension views and owned reassembly; domain supplies DNS
//! parsing and canonical names. DNS retains one question, at most 32 records and
//! a 16 KiB TCP message. Standard collections and ChaCha remain dependencies.
//! Our admission, policy, accounting and lifetime decisions surround these
//! explicit unverified library boundaries; they are not replaced by new codecs.

#![no_std]
#![warn(missing_docs)]

extern crate alloc;

mod dns;
mod engine;
mod flow;
mod fragment;
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

/// Maximum Ethernet payload; originally fragmented IPv6 is emitted lazily.
pub const MTU: usize = 1500;

/// Nanoseconds per second for all absolute monotonic deadlines.
const SECOND: u64 = 1_000_000_000;

}
