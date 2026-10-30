# Hermit clipboard service

The clipboard stores one complete, multi-format offer in its Hermit VM. Linux session adapters copy application selections into it and expose
the latest offer on their own desktops. Reads do not consume content, and completed
content has no expiry. Only unfinished transfers and inactive connections time out.
The total offer is bounded to 64 MiB across at most 64 representations. Up to
5 MiB of aggregate payload uses RAM; larger offers stream directly into one
Qubes-owned encrypted volatile disk using fixed buffers. The whole offer uses
one backing, so multiple representations cannot each claim a separate RAM budget.
Replacement, cancellation and failed I/O invalidate the logical extent; publication
requires every promised byte and a successful flush before the write deadline.
Restart discards all metadata and Qubes creates a fresh encryption key. Retired
disk bytes are not securely overwritten in place and are never offered as history.

The Hermit executable now owns a fixed 8 MiB application heap, including allocator
metadata inside that arena, with no fallback to the kernel heap. Its 5 MiB payload
allowance shares that budget with bounded protocol and connection metadata.
Packet assembly and response framing reserve their checked sizes; service-side
payload, metadata and wire allocations return exhaustion errors. A data connection
that cannot allocate a packet or response is retired. Startup and standard-library
infallible allocation failure still terminates the guest; this is not a proof that
all policy-admitted workloads can always complete. Heap diagnostics record only
capacity, live requested bytes and their allocation-boundary high-water mark.

The core owns non-cloneable admission capabilities scoped to one clipboard object
and one authenticated incarnation. A descriptive participant or decoded message
cannot create authority. Revocation invalidates old capabilities, and reconnects
require strictly newer epochs. Pending and published content are exclusive states;
only the current owner can advance a contiguous transfer. The lifecycle contracts
cover unchanged state on unauthorized calls, exact write/read windows, complete
publication after successful flush, monotonic generations, deadline failure and
source-disconnect behavior. Time and caller authority are injected independently
of wire contents. Completed normal-mode content remains readable after its source
disconnects and does not expire or become one-shot.

The packet codec and ordered sender/receiver live in the OS-independent core.
Their contracts retain opcode, identity, byte order, names, exact consumption and
payload bytes; counts, lengths and allocations are bounded before copying. Wire
claims remain separate from admitted callers. Malformed or replayed frame streams
poison that connection rather than resuming an ambiguous transfer.

The connection owner couples the checked ledger directly to its live and retiring
transport collections: at most 32 live data connections and 64 live/retiring owners
in total. A peer preventing grant revocation keeps both its owner and reservation.
Construction is invoked only after admission. An uncertain endpoint-construction
failure terminates this service lifetime; normal processing never resumes after
releasing that reservation. Shutdown revokes all data capabilities and retries
owned cleanup for at most two seconds or 200 passes before terminating the guest.
Outstanding kernel quarantine is released by Xen/toolstack domain teardown.

The unsafe allocator bridge, Talc, Rust's allocation/provenance contract and the
Hermit/Xen drivers remain explicit trusted boundaries. Every successful alloc/free
updates the checked byte ledger under the allocator lock and compares it with
Talc's independent live-byte counter. Disagreement is a fatal internal contract
violation. A failed initial arena claim is terminal. Source-local notes specify
these assumptions and the narrow standard-library contracts missing from pinned
vstd; successful proofs do not establish allocator, driver or kernel correctness.
Startup consumes a typed boot parser: duplicate, unknown Airlock fields,
noncanonical challenges and inconsistent authority/storage modes reject startup.
Failure consumes the parser; code cannot finish a rejected continuation. Startup
and peer lifecycle diagnostics contain challenge, identity and error categories,
never format names or clipboard bytes.
The actual Hermit adapter supplies owned message snapshots, the boot-bound GUI
connection, its resolved data peers, fresh PV-clock observations and truthful I/O
results to the core. Those FFI and runtime scheduling correspondences remain
unverified. The service makes one bounded pass over all active peers, limits frames
per poll and parks on existing Xen events/timers. Progress assumes the kernel
schedules the service and its bounded I/O and waits return; resource bounds alone
do not prove fairness of Xen or another VM.

The 8 MiB heap cap excludes application static allocator bookkeeping, code, stacks,
kernel allocations and Xen mappings. The configured guest allocation is 24 MiB; those components remain outside the
application proof and require runtime validation at that allocation. The app build
lock includes the pinned external builder's build-std dependencies plus the isolated
application lock; its vendor output is authenticated by the build recipe's hash.
Payload usage events distinguish RAM and disk bytes without recording content.
The disk contract admits only the canonical Qubes encrypted volatile mapping;
NixOS root/private volumes and persistent Hermit storage remain unsupported.

File offers
stay local until a separate cross-VM file-transfer capability exists.

A typed clipboard connection in `airlock-config` derives membership from the GUI
assignments and installs user services, a GUI provisioner and exact Qubes policy.
The provisioner authenticates callers through qrexec and resolves current domain
IDs through Qubes. Hermit grants each admitted participant its own direct IPC
channel. Dom0 retains its trusted toolstack and disk-backend roles: Qubes owns
the encryption keys and can access disk plaintext. Ephemeral encryption protects
retired on-disk data after key disposal.
A new GUI authority lifetime restarts the volatile clipboard service. Individual
participant reconnections preserve completed content and receive fresh epochs.

The shared core keeps source identity, connection epoch and generation separate
from desktop format handling. Every admitted participant can read and replace
the clipboard.

The desktop adapter uses the existing Qubes X servers and sys-gui's Xwayland
selection bridge. It handles binary representations and incremental transfers,
without publishing its own proxy selections back into the service. The ordinary
CLIPBOARD selection is shared; PRIMARY selection and file operations remain local.

Protected clipboard mode is separate work. It will need non-cloneable operation
permissions bound to source, destination, generation and deadline, consumed by a
single authorized paste. The normal shared-membership capability must not silently
become that authority; production GUI policy must explicitly issue it. This change
preserves the existing normal clipboard workflow and keeps file offers local.
