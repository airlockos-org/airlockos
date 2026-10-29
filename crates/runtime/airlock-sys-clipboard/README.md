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

The executable uses the Verus-checked connection ledger in `clipboard::resources`:
at most 32 live data connections and 64 live/retiring reservations in total. A peer
that prevents grant revocation retains its reservation until cleanup succeeds.
The runtime checks correspondence between ledger counts and owned transport handles.
Every successful allocation and free also updates the Verus-checked byte-credit
ledger, which preserves live/peak requested-byte bounds. The allocator adapter ties
those credits to pointer/layout ownership and is part of the trusted boundary.
Verus verifies both ledgers' actual transition bodies; transport-handle correspondence,
Talc, the small unsafe arena adapter, the compiler and Hermit remain trusted or
unverified boundaries. The native arena test combines maximum packet buffers,
queued replies, format metadata and a 5 MiB offer, then exercises exhaustion and reuse.

The 8 MiB heap cap excludes application static allocator bookkeeping, code, stacks,
kernel allocations and Xen mappings. Those still need separate budgets and proof
or measurement before reducing the current 128 MiB guest allocation. The app build
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
