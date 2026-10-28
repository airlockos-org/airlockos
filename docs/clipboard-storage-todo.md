# TODO: bounded-memory storage for sys-clipboard

Implement two storage paths in the Hermit clipboard VM: keep small clipboard
contents in RAM and stream larger contents to a disk owned by `sys-clipboard`.
On paste, stream from that storage using bounded buffers. Retain an independent
copy so pasting does not depend on the source application or VM staying alive.

This is an implementation handoff requested by the user. Remove it when the work
is complete; keep lasting design decisions beside the implementation.

## Agreed direction

- Use **5 MiB** as the initial in-memory threshold, measured across all formats
  of one clipboard offer, not separately for each format or connection.
- Stream large offers directly to disk without first allocating their full size.
  Keep the existing 64 MiB total payload limit initially; the storage threshold
  and maximum accepted payload are separate settings.
- Keep completed content available for repeated pastes until replacement or
  clear. Invalidate content when the clipboard service restarts, including a
  restart caused by a new GUI authority lifetime. Disk backing does not imply
  clipboard history or persistence across boots.
- Keep content transfer on the existing authenticated VM channels. Dom0 must
  not become a clipboard-content relay. Preserve current participant permissions;
  this work does not introduce protected clipboard modes or file transfer.

## Memory target

Start by validating **32 MiB** for the complete VM. **16 MiB** is a later stretch
target, not a requirement or an established minimum. Disk drivers, buffers,
allocator overhead, stacks and metadata all count toward the budget.

The live read-only inspection on 2026-10-28 found a fixed 128 MiB allocation and
a 108 MiB heap reported at boot. That heap figure is capacity, not measured use.
No lower allocation has been tested. The configuration currently rejects less
than 128 MiB; change that guard only alongside evidence for the new minimum.

## Implementation work

- [ ] Inspect the pinned Hermit and Hermit–Xen integration for usable block-device
  support. Determine the driver and Qubes lifecycle work required before choosing
  a storage format. A dedicated virtual block device may avoid a filesystem;
  use a filesystem if existing support makes that simpler and reliable.
- [ ] Define bounded disk capacity, allocation, attachment and cleanup through
  the Rust machine configuration and existing Qubes storage/lifecycle mechanisms.
  Keep temporary clipboard storage separate from persistent user data.
- [ ] Add storage behind the shared clipboard state machine. The current
  `declare` path reserves each representation's full length in a `Vec`; replacing
  only the transfer buffers will not reduce payload memory usage.
- [ ] Select memory or disk storage from the validated aggregate offer size.
  Bound queues, outstanding I/O and concurrent reads as well as individual
  chunks; apply backpressure rather than buffering an entire transfer.
- [ ] Preserve reservation order, source identity, epochs, generation checks,
  timeouts and atomic publication of complete multi-format offers. The current
  reservation invalidates the old offer; do not silently change that behavior.
- [ ] Specify disk-full, I/O-error and interrupted-write behavior. Never publish
  a partial offer or allow a stale generation to read replacement content.
- [ ] Define restart invalidation and handling of leftover disk bytes. Logical
  invalidation alone is not erasure; decide whether boot-scoped encryption or
  another disposal mechanism is appropriate without adding history/persistence.
- [ ] Measure peak memory under load, then update the allocation and minimum-memory
  guard. Avoid changing the live VM's allocation as an unrecorded experiment.

## Verification

Extend existing clipboard scenarios rather than duplicating them for every
storage combination. Cover offers below and above the threshold, multiple
formats whose combined size crosses it, and a maximum-size offer. Verify exact
bytes on repeated pastes, replacement during transfer, cancellation, reconnects,
restart invalidation, storage exhaustion and I/O failure.

Demonstrate that memory remains bounded as disk-backed payload size increases,
including overlapping reads and repeated replacements. A successful boot at
32 MiB is insufficient: exercise sustained clipboard traffic and allocation
failure handling. Measure the whole VM, not only payload-buffer sizes.

Follow the root [AGENTS.md](../AGENTS.md) for Rust checks and
[development operations](development-operations.md) for any live work. Recheck
the deployed baseline first; the earlier read-only inspection is not a current
deployment baseline. Keep test and memory evidence under `.airlock-logs/`.

## Starting points

The [shared clipboard state machine](../crates/airlock-common/clipboard/src/shared.rs)
owns offer lifetime and storage. The
[Hermit service](../crates/runtime/airlock-sys-clipboard/src/service.rs) and
[transport protocol](../crates/runtime/airlock-sys-clipboard/src/shared.rs) handle
authenticated requests and chunked transfers. The
[clipboard component](../crates/airlock-config/src/components/clipboard.rs)
enforces the current minimum memory, while the
[Hermit builder](../crates/airlock-config/src/hermit_build.rs) defines the VM backend.
Block support belongs with the [Hermit–Xen integration](https://github.com/airlockos-org/hermit-xen).

Update the website's Experiments page if disk backing is implemented: it
currently describes `sys-clipboard` as needing no persistent filesystem or root
disk. Describe the resulting storage accurately without claiming an untested
RAM minimum or reduced attack surface solely from using Rust.
