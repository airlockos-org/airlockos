# Airlock configuration

This crate authors VM systems, dom0 services, topology and deployment contracts,
flake assembly and installation media in Rust. Rusix emits ordinary Nix artifacts;
NixOS and upstream Qubes still own module evaluation, Xen, qrexec, QubesDB and
VM lifecycle.

Machine declarations belong to the standalone `airlock-machine/src/` crate.
Each block declares a VM, configures its typed handle, then registers it.
The authoring model checks identities, role compatibility and relationships before
freezing a snapshot. Runtime services reuse the same identity and connection
contracts. Components own their package recipes and NixOS contributions.

The controller candidate is also a Rust crate. Its authoring API separates
ordinary host package/file changes from arbitrary modules, whose automatic
activation is staged for the next boot. Commit Rust declarations and dependency
locks for review. Preparation never applies a machine change.

Generated Nix is an inspectable build interface kept in the disposable
`$AIRLOCK_DATA_ROOT/cache/prepared/<hash>/` directory. `make prepare` emits this
content-addressed source tree and prints its `path:` flake reference. Set
`AIRLOCK_PREPARED_CACHE` to select another directory explicitly. Its receipt
records the source revision, working source contents and prepared file hashes.
Nix evaluates that tree after Rust compilation finishes; it never compiles the
authoring program during evaluation. Production build and deployment records
retain required artifacts independently of disposable workstation output.
Source maps remain available through inspection exports. Raw development logs
and receipts live under `$AIRLOCK_LOG_DIR`; lasting findings belong in Git.
