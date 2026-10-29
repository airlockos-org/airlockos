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

The guest remains at 128 MiB pending a separate memory-sizing experiment. Payload
usage events distinguish RAM and disk bytes; they do not measure total live heap
or record content. The optional disk contract admits only the canonical Qubes
encrypted volatile mapping, with bounded capacity and no arbitrary source paths.
NixOS root/private volumes and persistent Hermit storage remain unsupported.

File offers
stay local until a separate cross-VM file-transfer capability exists.

A typed clipboard connection in `airlock-config` derives membership from the GUI
assignments and installs user services, a GUI provisioner and exact Qubes policy.
The provisioner authenticates callers through qrexec and resolves current domain
IDs through Qubes. Hermit grants each admitted participant its own direct channel;
dom0 observes the boot-bound control offer but never relays clipboard content.
A new GUI authority lifetime restarts the volatile clipboard service. Individual
participant reconnections preserve completed content and receive fresh epochs.

The shared core keeps source identity, connection epoch and generation separate
from desktop format handling. Every admitted participant can read and replace
the clipboard.

The desktop adapter uses the existing Qubes X servers and sys-gui's Xwayland
selection bridge. It handles binary representations and incremental transfers,
without publishing its own proxy selections back into the service. The ordinary
CLIPBOARD selection is shared; PRIMARY selection and file operations remain local.
