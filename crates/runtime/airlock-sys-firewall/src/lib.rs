//! Hermit application adapters for the bounded firewall core. Native leases and
//! the original QubesDB session remain owned for every effect; the core never
//! receives a constructor for those resources. All state is volatile. Crash or
//! terminal I/O uncertainty requires a fresh VM, not reconnecting old handles.

#![warn(missing_docs)]

/// Sole application arena, shared allocator implementation with sys-clipboard.
#[cfg(target_os = "hermit")]
#[global_allocator]
static HEAP: airlock_bounded_heap::FixedHeap<{ 8 * 1024 * 1024 }> =
    airlock_bounded_heap::FixedHeap::new();

#[cfg(target_os = "hermit")]
pub mod service;
