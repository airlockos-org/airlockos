//! Fixed application heap, independent of Hermit's kernel allocator.
//! Talc and this small unsafe adapter are trusted: Verus checks byte-credit and
//! connection ledgers, not allocator internals or Rust/compiler allocation behavior.
//! Exhaustion returns null to fallible allocation APIs; infallible Rust allocations
//! retain Rust's abort-on-exhaustion behavior. There is no system-heap fallback.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};
use talc::{TalcCell, source::Manual};

/// Backing bytes for the application heap, including Talc's in-arena overhead.
pub const APP_HEAP_BYTES: usize = 8 * 1024 * 1024;

/// The executable's sole application allocator; Hermit kernel allocations stay separate.
#[cfg(target_os = "hermit")]
#[global_allocator]
pub static APPLICATION_HEAP: FixedHeap<APP_HEAP_BYTES> = FixedHeap::new();

/// Page-aligned private backing; no clipboard bytes are shared with the kernel allocator.
#[repr(C, align(4096))]
struct Arena<const N: usize> {
    /// Uninitialized bytes become allocator-owned only under the exclusive lock.
    bytes: [MaybeUninit<u8>; N],
}

/// Mutable allocator metadata, exclusively protected by the enclosing spin lock.
struct State {
    /// Allocator with a source that cannot request additional memory.
    allocator: TalcCell<Manual>,
    /// Whether the sole backing extent has been claimed successfully.
    initialized: bool,
    /// Verus-checked byte ledger charged by every successful allocation.
    budget: airlock_clipboard_core::resources::Budget,
}

/// One fixed arena; use as the Hermit executable's global allocator.
/// Its address must remain stable while allocations exist. The application must
/// not allocate recursively or from interrupt handlers while holding this lock;
/// Hermit's separately linked kernel allocator remains independent.
pub struct FixedHeap<const N: usize> {
    /// Serializes all metadata access without allocating or calling the kernel.
    locked: AtomicBool,
    /// Talc state accessed only through an acquired guard.
    state: UnsafeCell<State>,
    /// Sole backing allocation, never grown or replaced.
    arena: UnsafeCell<Arena<N>>,
}

// All mutable access is serialized; the allocator never lends metadata references.
unsafe impl<const N: usize> Sync for FixedHeap<N> {}

/// Lock ownership retained through allocation and released without allocating.
struct Guard<'a, const N: usize> {
    /// Stable allocator whose metadata is exclusively held.
    heap: &'a FixedHeap<N>,
}

impl<const N: usize> Drop for Guard<'_, N> {
    fn drop(&mut self) {
        self.heap.locked.store(false, Ordering::Release);
    }
}

impl<const N: usize> FixedHeap<N> {
    /// Construct empty metadata and uninitialized static backing without allocating.
    pub const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
            state: UnsafeCell::new(State {
                allocator: TalcCell::new(Manual),
                initialized: false,
                // Zero initialization keeps the large static arena in ELF .bss.
                // Its real byte budget is installed when the sole extent is claimed.
                budget: airlock_clipboard_core::resources::Budget::new(0),
            }),
            arena: UnsafeCell::new(Arena {
                bytes: [MaybeUninit::uninit(); N],
            }),
        }
    }

    /// Exclusively inspect or update Talc; initialization also obeys this lock.
    fn with<R>(&self, run: impl FnOnce(&mut State) -> R) -> R {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        let _guard = Guard { heap: self };
        // SAFETY: the acquired lock gives exclusive state and backing ownership.
        let state = unsafe { &mut *self.state.get() };
        if !state.initialized {
            let base = self.arena.get().cast::<u8>();
            // SAFETY: the stable, aligned N-byte arena is private and claimed once.
            state.initialized = unsafe { state.allocator.claim(base, N) }.is_some();
            if state.initialized {
                state.budget = airlock_clipboard_core::resources::Budget::new(N);
            }
        }
        run(state)
    }

    /// Return live and peak requested heap bytes; excludes static metadata and stacks.
    pub fn usage(&self) -> (usize, usize) {
        self.with(|state| state.budget.usage())
    }
}

impl<const N: usize> Default for FixedHeap<N> {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: Talc upholds layout/alignment and allocation lifetime rules. Its only
// source is Manual and the single extent lies inside arena; no fallback exists.
// Delegated pointers/layouts satisfy GlobalAlloc's caller obligations.
unsafe impl<const N: usize> GlobalAlloc for FixedHeap<N> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.with(|state| {
            // SAFETY: exclusive allocator access; the caller supplies a valid layout.
            let pointer = unsafe { state.allocator.alloc(layout) };
            if !pointer.is_null() && !state.budget.reserve(layout.size()) {
                // SAFETY: this allocation has not escaped and retains its exact layout.
                unsafe { state.allocator.dealloc(pointer, layout) };
                return core::ptr::null_mut();
            }
            pointer
        })
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        self.with(|state| {
            // SAFETY: caller supplies a live pointer and its original layout.
            unsafe { state.allocator.dealloc(pointer, layout) };
            let _ = state.budget.release(layout.size());
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_allocations_serialize_metadata_and_preserve_owned_bytes() {
        let heap = FixedHeap::<65536>::new();
        std::thread::scope(|scope| {
            for tag in 1..=4 {
                let heap = &heap;
                scope.spawn(move || {
                    let layout = Layout::from_size_align(256, 16).unwrap();
                    for _ in 0..256 {
                        // SAFETY: valid layout; heap is stable until all scoped threads exit.
                        let pointer = unsafe { heap.alloc(layout) };
                        assert!(!pointer.is_null());
                        // SAFETY: this thread exclusively owns the returned 256-byte block.
                        unsafe { pointer.write_bytes(tag, layout.size()) };
                        std::thread::yield_now();
                        // SAFETY: the live block is initialized and owned by this thread.
                        assert!(
                            unsafe { core::slice::from_raw_parts(pointer, layout.size()) }
                                .iter()
                                .all(|byte| *byte == tag)
                        );
                        // SAFETY: this thread frees its own live allocation exactly once.
                        unsafe { heap.dealloc(pointer, layout) };
                    }
                });
            }
        });
        assert_eq!(heap.usage().0, 0);
    }

    #[test]
    fn exhaustion_has_no_fallback_and_released_capacity_is_reusable() {
        let heap = FixedHeap::<65536>::new();
        let layout = Layout::from_size_align(4096, 4096).unwrap();
        let base = heap.arena.get() as usize;
        let mut blocks = Vec::new();
        loop {
            // SAFETY: valid nonzero layout; heap stays at a stable address throughout.
            let pointer = unsafe { heap.alloc(layout) };
            if pointer.is_null() {
                break;
            }
            assert!((base..base + 65536).contains(&(pointer as usize)));
            assert!((pointer as usize) + layout.size() <= base + 65536);
            assert_eq!((pointer as usize) % layout.align(), 0);
            assert!(!blocks.contains(&pointer));
            blocks.push(pointer);
        }
        assert!(!blocks.is_empty());
        let count = blocks.len();
        for pointer in blocks.drain(..) {
            // SAFETY: each distinct live allocation is freed exactly once.
            unsafe { heap.dealloc(pointer, layout) };
        }
        assert_eq!(heap.usage().0, 0);
        let large = Layout::from_size_align(32768, 4096).unwrap();
        // SAFETY: layout is valid, and the original blocks have all been released.
        let pointer = unsafe { heap.alloc(large) };
        assert!(!pointer.is_null());
        unsafe { heap.dealloc(pointer, large) };
        assert!(count * layout.size() < 65536);
        assert_eq!(heap.usage().0, 0);
    }
}
