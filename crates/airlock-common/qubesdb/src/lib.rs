//! Bounded client for QubesDB's native inter-domain replication protocol.
//! One initial dump is followed by ordered write/removal events. Consumers own
//! retained values and interpret keys; this crate owns framing, sequencing,
//! acknowledgements and deadlines, without network policy or VM authority.
//!
//! The effect adapter supplies bytes from its actual native connection and a
//! monotonic clock. Each returned event must be consumed before another step;
//! storage failure requires disconnecting the client. A positive write response
//! confirms peer processing, not crash durability. Local-daemon watch/read
//! commands are not sent over this protocol. Compatibility follows QubesDB 4.3.2.

#![no_std]
#![warn(missing_docs)]

extern crate alloc;

pub mod bytes;
pub mod client;
pub mod wire;
