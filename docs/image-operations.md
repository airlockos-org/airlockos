# Image operations

Run from the airlock repository root with the `airlock-machine` submodule
initialized and checked out at the revision committed in this repository.
Commit the intended changes before building: the installer uses committed source,
not working-tree edits. When application code changes, update
`airlock-machine/application-revision` and the `airlock-apps` pins in both
repositories' `flake.lock` files, then commit the updated submodule revision here.

Set `AIRLOCK_DATA_ROOT` to the development storage directory, on a disk other
than the USB being provisioned. Prepare offline Cargo dependencies before the
first installation and again after dependency changes.

## Build and provision

```sh
make prepare-dependencies
lsblk -o NAME,TRAN,SIZE,MODEL,SERIAL,MOUNTPOINTS
make usb-dev-install USB_SERIAL=YOUR_USB_SERIAL
```

Provisioning erases the selected USB disk. Verify its serial; the provisioner
unmounts its partitions before writing. `USB_PUBLIC_KEY` optionally selects an SSH
public key; omitting it installs no SSH credentials.

Run the combined command as your normal user; it collects sudo authentication and
the dom0 password before building, then provisions that build's exact result.
The provisioner writes the image, grows its root filesystem, and installs the
committed source and any supplied key. It leaves internal disks alone.

If it reports stale partition information, unplug/replug the USB and rerun the
combined command; unchanged build outputs can be reused from cache. Do not
improvise partition changes or resume a partial write.

The provisioner's partition backups are recovery metadata for the newly written
image, not backups of the USB's previous data. Keep them outside the checkout.
They are written below the configured log directory or `/var/log/airlock`.

## Boot recovery

Keep the machine's screen and keyboard available for hardware changes. If the
normal graphical entry cannot start, select `usb-text-recovery` in the boot menu.
This boots an independent recovery system with networking and VMs disabled;
the normal machine's storage pool is not mounted automatically. Its service
status describes the recovery system, not the failed normal boot. Preserve
diagnostics from the failed boot before attempting repairs. The recovery system's
`/etc/airlock/pool-recovery` describes how to select a retained boot entry.

For a deployment failure on a running normal system, inspect deployment status
before resuming or rolling back; see
[Development operations](development-operations.md#deployment).

Changing boot profiles does not remove persistent Qubes PCI assignments. Do not
start sys-gui with a display GPU still owned by dom0 or delete Qubes state to
force a boot. Inspect the declared hardware configuration and Qubes assignments
before changing ownership.

For an active display stall, the GUI service keeps the bounded
[display recovery procedure](../crates/runtime/airlock-sys-gui/service/src/gpu/README.md)
beside its tool.
