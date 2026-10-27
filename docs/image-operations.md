# Image operations

Run these commands from the parent airlock checkout with its initialized
component at the committed pin. Commit the intended source and align its
application pins. Set `AIRLOCK_DATA_ROOT` to the external development store
location.

## Build and provision

```sh
lsblk -o NAME,TRAN,SIZE,MODEL,SERIAL,MOUNTPOINTS
make usb-dev-install USB_SERIAL=YOUR_USB_SERIAL
```

Provisioning erases the selected USB disk. Verify its serial; the provisioner
unmounts its partitions before writing. `USB_PUBLIC_KEY` optionally selects an SSH
public key; omitting it installs no SSH credentials.
Run the combined command as your normal user; it collects sudo authentication and
the dom0 password before building, then provisions that build's exact result.
The provisioner writes the image, grows its root filesystem, and installs the
committed source and any supplied key. It leaves internal disks alone. If it
reports stale partition information, unplug/replug and restart the combined command; unchanged
build outputs can be reused from cache. Do not
improvise partition changes or resume a partial write.

`make usb-builder-offline-check` explicitly repeats the pinned offline-builder
trials. Image assembly runs its own input and storage checks.

Image builds reserve one physical CPU core, including its online SMT siblings,
for workstation responsiveness. The limit covers preparation, compilers and
image-assembly children, respects inherited CPU restrictions, and keeps release
optimizations unchanged. The selected CPU identities are recorded in
`.airlock-logs/build-cpu-budget.json`. If no core can be reserved while leaving
CPUs for the build, the build stops with an explanation.

The provisioner's partition backups are recovery metadata for the newly written
image, not backups of the USB's previous data. Keep them outside the checkout.
They are written below the configured log directory or `/var/log/airlock`.

## Boot recovery

Keep the machine's screen and keyboard available for hardware changes. If the
normal graphical entry cannot start, select the text recovery entry in the
boot menu. Inspect the failed services and deployment status before attempting
resume or rollback. Preserve diagnostics for an unresolved failure.

Changing boot profiles does not remove persistent Qubes PCI assignments. Do not
start sys-gui with a display GPU still owned by dom0 or delete Qubes state to
force a boot. Inspect the declared hardware configuration and Qubes assignments
from recovery before changing ownership.

For an active display stall, the GUI service keeps the bounded
[display recovery procedure](../crates/runtime/airlock-sys-gui/service/src/gpu/README.md)
beside its tool.
