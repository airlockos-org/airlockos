# Development operations

Run from the parent airlock checkout. Both repositories must be committed, and
`airlock-machine` must match the parent pin. `DEPLOY_TARGET` is the confirmed
SSH target for the machine's usr-assistant VM. The workstation commands require
stable Rust; their launcher builds the local development tool before running it.
This tool is separate from the applications installed in VMs.

`make usb-dev-install USB_SERIAL=...` collects sudo authentication and the
dom0 password before the image build, then provisions that serial automatically
after success. Run it as the normal user and keep the selected USB connected.
The build stays unprivileged; the waiting provisioning helper retains only a
password hash. sys-gui keeps its existing development password. Both committed
repository revisions and the prepared offline authoring dependencies are copied
into private storage before credentials are collected. The build and installed
source use that checkout, so development and commits can continue in the
original checkout. A failed build or changes to the
isolated source cancel provisioning. This combined operation uses
its own temporary result link, so another build cannot replace its image through
the shared `usb-dev-image` link. A successful build also updates that shared link
and its GC root. To retry provisioning, rerun the combined command; unchanged
build outputs can be reused from cache.

## Deployment

Before editing system configuration, inspect its recorded deployed source and
compare it with the checkout, including committed and uncommitted changes:

```sh
make machine-status DEPLOY_TARGET=user@TARGET
make machine-verify DEPLOY_TARGET=user@TARGET
```

Before the first deployment, a freshly flashed machine reports `image-baseline`
with no deployment selection. Its `baseline` object identifies the image source;
verification checks that snapshot against the host and running VM generations.
An uninitialized baseline requires startup to finish before verification.

Stop for older undeployed work, incomplete or failed deployments, a required
reboot, or an unknown baseline. Resolve that state before preparing another
change. Follow the full baseline and submission rules in the root [AGENTS.md](../AGENTS.md).

After making and committing the intended changes and updating the parent pin:

```sh
make machine-plan DEPLOY_TARGET=user@TARGET
```

Source approval occurs before evaluation and building. An approved or accepted
request is not a completed plan or deployment. Follow its returned request ID
inside usr-assistant with `airlock machine review-status --request-id REQUEST_ID`
and wait for the plan. Review its affected VMs, restarts, and reboot requirement
before applying:

```sh
make machine-apply DEPLOY_TARGET=user@TARGET
make machine-status DEPLOY_TARGET=user@TARGET
make machine-verify DEPLOY_TARGET=user@TARGET
```

Activation uses a detached dom0 worker. Restarting usr-assistant can disconnect
the client while deployment continues. Reconnect and check the worker outcome.
If dom0 requires a reboot, verify again after restarting the machine. A build,
approval, or accepted submission does not establish a verified deployment.

For recovery, inspect status before `make machine-resume` or
`make machine-rollback`, using the same `DEPLOY_TARGET`. Rollback changes system
software and configuration; it does not reverse private application data.

## QEMU lab and nested-VM checks

`make qemu-lab-start` builds and opens the interactive Airlock machine in the QEMU lab.
Commit source changes and align the machine/application pins before building.
The outer guest defaults to 32 GiB so the controller can evaluate whole-machine
updates; the controller VM starts in the background after usr-assistant is ready.
Its Rust definition is in [qemu_lab.rs](../crates/airlock-config/src/profiles/qemu_lab.rs);
it uses the existing X11 display relay and normal VM services. Log in to the
nested desktop as `user` with the development password `airlock`. `make qemu-lab-resume`
keeps the selected image and writable disk without rebuilding. `make qemu-lab-status`
reports QEMU state and source identity; `make qemu-lab-ssh` opens the dom0 development
endpoint. `make qemu-lab-stop` requests a clean shutdown. `make qemu-lab-reset` discards only
a stopped instance's writable disk and EFI variables.

Instances are isolated by worktree and `QEMU_LAB_INSTANCE`; select a distinct
`QEMU_LAB_SSH_PORT` when running several concurrently. Logs live under
`.airlock-logs/qemu-lab/`. The native `airlock-dev qemu-lab` command also exposes
headless startup and explicit forced shutdown. A changed image requires a reset
or a new instance, so rebuilding cannot silently replace a development disk.
Image build output is retained in the instance's log directory. Ordinary updates
use the `qemu-lab` release profile through the existing reviewed deployment path.

The workstation Rust tool owns image selection, writable overlays, baseline reuse,
SSH orchestration and test evidence. Shell entry points pass arguments to that
command. Warm tool sync is an explicit development override inside the disposable
guest; it is separate from the reviewed deployment path.

```sh
make test-warm
make test-slow
```

These explicitly build and run nested-VM checks. They require the external Nix
store and suitable virtualization support; use disposable test state. Test
selection and VM/storage options are defined in the root Makefile. These checks
do not verify physical hardware or establish Qubes OS security equivalence.

The ordinary `make test-quick` loop remains free of Nix builds and automatic
tool provisioning. Prepare native executables explicitly with `make native-integration-build` first.
