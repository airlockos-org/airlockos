# Hermit clipboard service

The normal clipboard stores one complete, multi-format offer in the diskless
Hermit VM. Linux session adapters copy application selections into it and expose
the latest offer on their own desktops. Reads do not consume content, and completed
content has no expiry. Only unfinished transfers and inactive connections time out.
The total offer is bounded to 64 MiB across at most 64 representations. File offers
stay local until a separate cross-VM file-transfer capability exists.

A typed clipboard connection in `airlock-config` derives membership from the GUI
assignments and installs user services, a GUI provisioner and exact Qubes policy.
The provisioner authenticates callers through qrexec and resolves current domain
IDs through Qubes. Hermit grants each admitted participant its own direct channel;
dom0 observes the boot-bound control offer but never relays clipboard content.
A new GUI authority lifetime restarts the volatile clipboard service. Individual
participant reconnections preserve completed content and receive fresh epochs.

The shared core keeps source identity, connection epoch and generation separate
from desktop format handling. Its access boundary currently permits every admitted
participant to read and replace the clipboard. This is the extension point for
future modes; no protected mode or user-gesture authorization is implemented.
The older approval-based laboratory fixture is separate from production behavior.

The desktop adapter uses the existing Qubes X servers and sys-gui's Xwayland
selection bridge. It handles binary representations and incremental transfers,
without publishing its own proxy selections back into the service. The ordinary
CLIPBOARD selection is shared; PRIMARY selection and file operations remain local.
