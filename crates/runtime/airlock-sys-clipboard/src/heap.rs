//! Clipboard's allocation cap; the allocator and byte-credit implementation are
//! shared with the firewall. Clipboard ownership and connection limits stay local.

/// Fixed arena allocator with no system-heap fallback.
pub use airlock_bounded_heap::FixedHeap;

/// Backing bytes for clipboard application allocations, including allocator metadata.
pub const APP_HEAP_BYTES: usize = 8 * 1024 * 1024;

/// The clipboard executable's sole application allocator.
#[cfg(target_os = "hermit")]
#[global_allocator]
pub static APPLICATION_HEAP: FixedHeap<APP_HEAP_BYTES> = FixedHeap::new();
