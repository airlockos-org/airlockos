# Deployment authorization and execution

This library decides whether proposed deployment effects are permitted. It binds
approval to the exact source, candidate, baseline and operation, then produces
requests for configuration, storage and VM lifecycle changes. It performs no I/O.
[Machine planning](../machine-planning/README.md) independently calculates required
effects; a required effect acquires no permission merely by being planned.

The coordinator's [approval adapter](../../airlock-dom0/service/src/coordinator/approval.rs)
authenticates records and carries owned authority from a reviewed plan through
durable publication to the Qubes adapter. Authority values cannot be cloned or
deserialized. A wire journal or progress record does not grant execution authority.
Cargo runs the same Rust bodies checked by Verus; specifications and proofs are
erased from ordinary builds.

The [crate documentation](src/lib.rs) describes approval and publication guarantees,
privileged routes and trusted boundaries. Each request module documents its own
scope and invariants beside the implementation. Proofs constrain authorized
requests; they do not prove faithful Qubes execution, filesystem durability, VM
isolation, complete observations or eventual recovery. Boot, local administration
and explicitly confirmed maintenance have separate policies.

## Verification

`make verify-prepare` explicitly installs the checksum-pinned Linux release and
its exact Rust toolchain, then verifies both domain libraries and vstd. `make verify` uses
prepared tools without provisioning them. The dedicated CI job runs the same
command, with the exact `vstd` version and transitive dependencies in Cargo.lock.
Ordinary Cargo and `test-quick` never install or run the prover. Tool preparation
uses Rust orchestration in `airlock-dev`; the [workspace pin](../../verus.json)
is shared by both crates and the Nix development shell.

The isolated storage worker decodes incoming declarations, then revalidates them
against a fresh Qubes observation under the database lock. Its typed policy returns
an opaque checked installation. Verified request selection retains the exact VM,
pool and ordered immutable definitions; completion cannot skip a selection.
Post-installation checks consume the same plan and preserve the original writable
root/private observations. Selection counts requests, not external success or
exactly-once execution. The adapter stops on errors before save. Python argument
construction, upstream execution and observation completeness remain trusted;
the installed policy and its filesystem checks are ordinary Rust. JSON remains
at the worker transport and observation boundaries, not the checked dispatch.

The native Qubes storage plugin also calls a typed in-process interface. Immutable
constructor options and persisted-path selection execute verified Rust. The same
verified lifecycle selector supplies ordered verification, mapper and generation
reference effects to the production engine, together with its admission-lock
requirement. Mapper availability is observed after acquiring that lock.
Filesystem observations, lock acquisition, device filtering, record
publication and faithful upstream Python execution remain adapter obligations.
CLI JSON remains a separate decoder/encoder for this engine; Python kwargs are
not routed through that decoder.

Cargo tests exercise the erased executable code; compile-fail doctests enforce
identity distinctions, evidence-versus-authority separation and request lifetimes.
The dom0 `durable_handoff` namespace scenario also exercises the real persistence
and process adapters, using the existing Rust command peer. It needs bubblewrap
and the explicitly built native test fixtures; CI prepares both.

On NixOS, use the Rust-authored prepared applications shell:
`nix develop "$(make --silent prepare)/crates#verification" -c make verify-prepare`.
It packages the same checksum-pinned release with Nix library/interpreter fixes;
rustup supplies the pinned compiler in the user's toolchain directory. With the
tools prepared, verification uses `make verify` in that shell. This workstation
tooling is separate from deployed configuration. The pin targets x86_64 Linux.

Upstream guidance: [Cargo integration](https://verus-lang.github.io/verus/guide/cargo_verus.html)
and [pinned Verus release](https://github.com/verus-lang/verus/releases/tag/release/0.2026.10.18.7d82994).
