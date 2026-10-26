# Hermit clipboard service

This is Airlock's first application on the external Hermit/Xen platform. The
`airlock-clipboard-core` crate owns clipboard policy and has no OS, allocation or
transport dependency. This crate adapts its requests to `xen-transport::Wire` and
runs the same state machine in a genuine Hermit PVH executable. Xen boot, PV time,
event channels, grants, queues and QEMU orchestration remain in `hermit-xen`.

## Ownership and trust

One authenticated connection owns one fixed 64 KiB buffer and one pending policy
decision. Transfers use 192-byte chunks inside the 224-byte transport envelope.
A complete copy publishes a generation; an authorized paste must name that exact
generation. Paste claims it exclusively at start, advances without rereads, and
never restores it on cancellation or failure. Zero-byte copies still require
explicit completion. Request and decision IDs increase without wrapping for the
service lifetime; a reconnect requires a fresh guest and authenticated epoch.

Time and caller identity enter the core through explicit arguments. Decisions
are installed through a separate trusted API, never a data-plane authorization
flag. Approval binds an operation, caller, epoch and absolute expiry. Content
expires with its copy approval (at most 30 seconds); transfers additionally have
a fixed five-second deadline. Progress cannot extend either. The adapter blocks
on the next expiry using the existing PV timer/event backend, with a ten-second
inactive-peer bound. Error, cancellation, expiry and disconnect clear retained
state; volatile writes erase the private payload buffer. Shared queue snapshots
and response temporaries are not a claim of whole-machine forensic zeroization.

The `lab-authority` feature enables **only a controlled dom0 authority**. The
Hermit executable grants its endpoint specifically to dom0. That peer may install
decisions and impersonate caller identities for tests; no requesting VM may ever
be attached to this endpoint. The console offer and numeric caller IDs are not
credentials. The laboratory does not implement production authentication or
policy provisioning. The normal executable starts disconnected and parks without issuing peer grants.
The machine artifact validator rejects laboratory images; enabling this feature
does not authorize their admission to a deployed machine.

The existing [Qubes GUI policy](../airlock-config/src/host/dom0/gui.policy) remains
unchanged: sys-gui initiates ClipboardCopy/ClipboardPaste and requests
`policy.EvalGUI +qubes.ClipboardPaste`. Production authority must originate from
that existing GUI action and policy evaluation. A future adapter must bind its
decision to the authenticated source, destination, current content generation,
expiry and connection epoch. It must not accept a VM's claimed identity or allow
this service to approve GUI actions. Clipboard bytes never appear in service
diagnostics; rejection events contain only request IDs and categories.

## Local development

Use matching **local** Hermit transport, builder and pinned submodules. From an
Airlock development worktree, select the integration worktree explicitly:

The committed Cargo dependency names the reviewed integration commit. During local
development, seed Cargo strictly from the local repositories (all Git network
protocols are disabled for this command). Initialize the integration worktree's
submodules from the primary local checkout first, including rust-vmm-ci.

```sh
ln -s ../hermit-xen-clipboard .hermit-xen
mkdir -p .airlock-logs
HERMIT_LOCAL=$(realpath .hermit-xen)
LOCAL_GIT_CONFIG="$PWD/.airlock-logs/clipboard-git.config"
git config --file "$LOCAL_GIT_CONFIG" url."file://$HERMIT_LOCAL".insteadOf https://github.com/airlockos-org/hermit-xen
git config --file "$LOCAL_GIT_CONFIG" url."file://$HERMIT_LOCAL/vendor/hermit-kernel".insteadOf https://github.com/airlockos-org/hermit-kernel.git
git config --file "$LOCAL_GIT_CONFIG" url."file://$HERMIT_LOCAL/vendor/rust-vmm-xen".insteadOf https://github.com/airlockos-org/rust-vmm-xen.git
git config --file "$LOCAL_GIT_CONFIG" url."file://$HERMIT_LOCAL/vendor/rust-vmm-xen/rust-vmm-ci".insteadOf https://github.com/rust-vmm/rust-vmm-ci.git
GIT_CONFIG_GLOBAL="$LOCAL_GIT_CONFIG" GIT_ALLOW_PROTOCOL=file \
  cargo --config net.git-fetch-with-cli=true check --locked \
  --manifest-path crates/Cargo.toml -p airlock-sys-clipboard
cargo test --locked --offline --manifest-path crates/Cargo.toml \
  -p airlock-clipboard-core -p airlock-sys-clipboard --all-features
cargo run --locked --offline --manifest-path crates/Cargo.toml -p airlock-dev \
  --bin clipboard-lab -- ../hermit-xen-clipboard test
cargo run --locked --offline --manifest-path crates/Cargo.toml -p airlock-dev \
  --bin clipboard-lab -- ../hermit-xen-clipboard peer-failure
```

The process-local Git configuration never changes global Git settings. The ignored
symlink selects the local builder, and the tool checks its HEAD against Cargo's
pin and rejects modified transport files. In prepared lab artifacts only, it
replaces the Git dependency with the copied local path. Both native tests and
Hermit builds therefore consume the same reviewed local transport source, without
fetching the published integration repository.

The workstation tool prepares a reduced source workspace and generated Nix under
`.airlock-logs/clipboard`, then invokes the local exported builders. `build` builds
without booting; `prepare` only stages sources. It uses `lab.lock` for the small
Hermit/musl build-std-compatible dependency set; the ordinary native workspace
retains its own lock. New dependencies require updating both locks and the Hermit
vendor union. Application builds use `--locked --offline`. Source files have their
own content-addressed input, so changing diagnostic metadata does not rebuild the
application. Source revisions, differences and build provenance remain beside
artifacts. Xen lifecycle, peer events and binary hashes remain in
`hermit-xen/.lab/runs`; two cycles reuse the same outer Xen/dom0 instance.

Airlock's existing package-source inventory includes the new workspace members;
shared-lock Git hashes are recorded in the Rust application builder. For published consumption later, publish
the reviewed integration commit and remove the process-local Git redirection, or
update Cargo's pin/lock and source hash to a subsequently reviewed revision. Use
that same revision in a Git flake input with `submodules=1` and update the lab
projection/vendor lock together. Until publication, a clean remote build cannot
fetch this local-only commit; use the local workflow above.

## Machine deployment boundary

`Vm::hermit` selects an independent guest backend with fixed memory, one vCPU,
no disks, network, GUI agent or qrexec. The production build constructor uses the
external pinned Hermit builder, emits a bounded ELF descriptor with its SHA-256,
application and integration revisions, and dependency-lock digest. Deployment
packaging strips DWARF and non-runtime store references from the ELF;
the external builder retains the original debug image. Source object identities remain
base64-encoded in provenance (avoiding Nix runtime references), and the final
executable is hashed after this transformation.
The deployment output permits only its own store reference, keeping the compiler
and dependency sources out of dom0's runtime closure. The executable reports its
build source revision for correlation with the admitted artifact; that diagnostic
does not grant authority. Local Nix
input overrides must select the same Git commit; a dirty path override is not a
replacement for a reviewed revision. Published use requires making the pinned
commits available upstream, without changing the local dependency contract.
The reviewed machine Git flake carries these inputs in its dependency lock. The
older offline runtime-candidate transport does not provision the Hermit toolchain;
use machine generations for this backend. Linux-only candidates keep their
existing offline input set.

The machine release retains the executable in its Nix closure. Existing source
approval, plan fingerprints and execution journals govern its configuration and
start/stop effects. A diskless `HermitVM` subclass reuses upstream Qubes/libvirt
lifecycle management. Admission and pre-start checks authenticate the complete
file, bounded static x86_64 PVH layout, and memory requirements. The subclass
checks the resulting domain XML before libvirt receives it.

An active Xen domain is only process state. Airlock captures a fresh boot
challenge and console boundary before starting the executable, then requires its
current-boot response. This reports **isolated execution**, not clipboard traffic
readiness. The protected observation associates the VM, generation, executable,
host boot and Xen domain ID; stop and failed-start events invalidate it. The
Xen console daemon writes to `/var/log/airlock-xen-console`, whose parent chain
is root-owned and not writable by the Qubes administration group. This is required
because console data participates in execution evidence. Existing historical Xen
logs remain available to boot diagnostics. The existing Qubes shutdown timeout
may kill a guest that does not acknowledge Xen shutdown. Updates and rollback
always start fresh volatile state.

The deployment completion specification requires the exact executable descriptor
and application execution identity. ELF parsing, Nix provenance, protected-file
checks, Qubes/libvirt execution and console observation remain trusted adapters,
not Verus proofs. The clipboard core's lifecycle invariants are documented beside
its state fields for future verification.

Connecting real clipboard traffic requires a separate trusted GUI-policy bridge.
It must bind authenticated source and destination identities, content generation,
expiry and connection epoch to the existing GUI policy result, provision grants
and event channels directly between authorized endpoints, and revoke them on
lifecycle changes. Dom0 must not become a runtime broker. Validate GUI denial and
approval with upstream Qubes tests before switching traffic; deployment of the
isolated executable leaves the existing Qubes clipboard workflow intact.
