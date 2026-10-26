# Airlock Agent Notes

- Preserve the Qubes architecture for the POC. Do not replace Xen, qrexec,
  QubesDB, qubesd, libvirt, or Qubes policy with new designs.
- Prefer upstream code, especially `CertainLach/nixos-qubes`, NixOS Xen support,
  and Qubes' own tests.
- Author first-party machine, package and image configuration in Rust/Rusix.
  Generated Nix remains the build interface to upstream NixOS and Qubes.
  Keep it outside Git in prepared source artifacts; commit Rust and locks. Keep
  existing Qubes runtime state such as `qubes.xml` where its architecture requires it.
- For physical lab development, read `docs/development-operations.md` first. Change
  and commit this repo, then use `make machine-plan` / `make machine-apply`
  with `DEPLOY_TARGET=...`; verify the resulting whole-machine generation.
  Never leave successful fixes only in a live VM, `/run`, or an ad-hoc overlay.
  Record any unavoidable diagnostic mutation and remove it before verification.
  A successful build is not a successful live deployment; report both separately.
- Keep development observation separate from production behavior. Observation
  tools should report state without expanding Qubes control authority.
- Before editing deployable system configuration for a live target, inspect its
  recorded deployed source and read-only status/verification. Compare that source
  with the checkout, including committed and uncommitted changes; a clean Git
  tree does not prove deployment. Record the baseline and starting revision.
- If older deployable changes, an unfinished/failed current deployment or a
  required reboot remain, stop new work and report them. Ask the user whether to
  deploy, discard or isolate the older work; do not do so automatically. If the
  deployed baseline cannot be established, stop rather than assume a match.
  Documentation/instruction-only changes do not require deployment; inspect mixed
  commits by content. Explicitly requested work to resolve the backlog may proceed.
- Recheck the baseline, deployment state and checkout immediately before
  submission. Stop if they changed beyond the user's authorized change; do not
  bundle intervening work into its review. Never bypass source approval or build
  a candidate just to discover whether older changes are pending.
- Match verification to the change. For routine package-list additions/removals,
  skip repository tests: review and commit the exact diff, obtain required source
  approval before evaluation/build, then apply and verify the requested package
  state. Keep normal Nix build checks enabled.
- For implementation, service, policy or deployment changes, run relevant tests;
  use `make test-quick` when shared behavior could be affected. Select Rust
  documentation and tooling checks using the rules below.
  Preserve clear logs and machine-readable output under `.airlock-logs/`.
- Do not add tests that merely repeat the configured package list.
- Keep regression coverage focused on distinct behavior and integration boundaries.
  Extend an existing scenario when it already exercises the relevant path. Avoid
  multiplying independent parameter dimensions, testing absent API names, or
  asserting exact generated script text when behavior is already covered. Retain
  cases for distinct failure modes, authorization and dependency tracking; do not
  use passing-test counts as a measure of coverage quality.
- Routine package-list additions/removals do not require documentation updates
  unless they change documented behavior, instructions or supported capabilities.
  Keep package selections in their Rust component; link there rather than maintain
  package inventories or installation/removal logs in docs. Git and deployment
  records provide the change history. Preserve dated validation evidence.
- Keep `test-quick` free of Nix evaluations, builds and automatic tool provisioning.
  `make test-nix` is opt-in; do not run it as a routine pre-deployment gate.
- Test Rust behavior with Cargo unit/integration tests and compile-fail doctests.
  Put process, filesystem and evaluation orchestration in Rust too. Keep Python
  fixtures only where upstream Qubes Python objects must be exercised.
  Avoid compiling ad-hoc Rust drivers when Cargo can exercise the same behavior.
  Do not add new Bash test scripts.
- Do not make full GUI support block the first qrexec/VM lifecycle milestone.
- Commit changes after each coherent conceptual change when practical. Use
  judgment about granularity, but avoid bundling unrelated work into one commit.
- Long Airlock image/template/VM iterations can grow the custom store quickly.
  Run `make gc-auto` periodically and after large failed build loops. Use only
  the guarded Airlock GC targets; do not garbage collect the host `/nix/store`.

## Documentation

- Write overview documentation for human orientation. Explain why a directory
  or component exists, its broad responsibilities, and the boundaries or design
  decisions that help a reader understand it. Keep directory READMEs short;
  leave file/crate inventories, API details and discoverable build commands in
  code and tooling, where agents can find them. Document operating steps only
  when they convey essential context that those sources do not provide.
- Code structure, types, tests, and source comments document implementation.
  Explain non-obvious decisions and invariants beside the relevant code.
- Product introductions and user guides belong in the sibling website project.
  Do not duplicate them here or add forwarding stubs.
- Keep repository prose to root guidance, essential operating instructions, and
  source-local notes that cannot be understood from the implementation alone.
- Preserve investigation and validation evidence in Git history. Do not recreate
  status, TODO, completed-work, or historical-report document collections.

## Rust documentation and formatting

These are the authoritative standards for first-party Rust in this repository,
including development tools and examples. `crates/Cargo.toml` is the application
workspace; `tools/rust-style/Cargo.toml` is a separate development workspace.
`crates/airlock-store-packer/Cargo.toml` has its own workspace and lockfile so
unrelated application changes cannot invalidate every image fragment. Its format
implementation is shared with runtime artifact transfer and follows these standards.
`airlock-machine/` is an independent repository with its own instructions;
vendored, generated and build output is outside this policy's editing scope.
There are currently no nested first-party Rust `AGENTS.md` files to reconcile.
Future nested instructions must link here rather than duplicate these standards.

- Keep workstation-only build and deployment tooling in `crates/airlock-dev/`;
  do not install its development transport in production VMs. Keep upstream Qubes
  API adapters thin and put Airlock policy and filesystem operations in Rust.
- Airlock crates are internal applications and libraries. Keep `publish = false`
  in every crate manifest; do not publish them to a package registry.
- Assume readers know Rust but may not know Airlock or Qubes. Explain domain
  concepts in plain language before introducing project-specific abstractions.
- Document what public types, traits and macros represent and why to use them.
  Lead method documentation with observable behavior, then implementation details.
  Use small examples when they clarify behavior. Review accidental public
  visibility instead of adding prose solely to silence a warning; preserve
  intended public APIs. Keep `#![warn(missing_docs)]` on public library crates,
  including `airlock-nix-core`, `airlock-image` and the reusable
  `airlock-vm-service` library;
  do not add blanket lint suppressions.
- Give every struct field a meaningful comment, including private and tuple
  fields, function-local structs, examples and fields emitted by macros. Public
  fields use Rust doc comments (`///`). Explain meaning, constraints or purpose;
  do not narrate Rust syntax or merely repeat the identifier.
- Treat examples as executable documentation. Begin example modules with one or
  two sentences of `//!` purpose documentation. Show normal user-facing Rust with
  minimal boilerplate; keep authoring code easy to find and split substantial
  examples into files when helpful. Apply the same field and formatting rules.
- In first-party examples, document every named function and method, including
  private helpers, and every type, trait, enum variant and field. Cover declarations
  inside macros and explain meaningful inputs, results, failure conditions and
  invariants. Apply the same standard to test helpers and adapter functions;
  comments should help a reader follow the example, not just repeat names.
- Use named placeholders in `format!` strings. Capture local names directly, as
  in `format!("{name}.nix")`; name expression arguments explicitly, as in
  `format!("{service}", service = operation.service())`. Avoid positional placeholders.
- Write embedded scripts and configuration documents as readable multiline text
  blocks rather than strings packed with `\n` escapes. For Rusix text with deferred
  values, use `nix_text!` with an indented raw multiline template and named placeholders.
  Preserve intentional whitespace and trailing newlines in the generated content.
- Stable rustfmt is canonical. Separate distinct sibling Rust item declarations
  with a blank line, including inside modules, impls, traits, extern blocks and
  function-local item lists. Keep comments, docs and attributes attached to their
  item. Consecutive plain `use` declarations can form one compact group; separate
  that group from other items.
- Review spacing between conceptual blocks inside function and method bodies,
  including closures, examples and macro templates. Use a blank line when moving
  from validation to the main operation, setup to processing, building a value to
  consuming it, one independent operation to another, or processing to result
  assembly. Keep tightly related statements together: a declaration and its
  immediate use usually belong in one block. Short functions performing one
  cohesive operation may need no internal blank lines. Do not mechanically
  separate every statement, split expressions into artificial sections, or add
  section comments merely to explain spacing.
- Function-body spacing requires semantic review. Stable rustfmt and the
  declaration-spacing checker enforce neither conceptual boundaries nor the
  grouping of related statements; passing those checks does not replace this
  review. Declaration spacing remains a separate automated rule.

### Automated checks and commands

Run from the repository root with stable Cargo/rustfmt/Clippy. The GTK welcome
window also needs GTK4/libadwaita development files and pkg-config. The dom0
service also needs libudev development files. On NixOS, enter the
explicitly prepared environment with `nix develop "$(make --silent prepare)/crates#desktop"` before running
workspace Cargo checks; `nix develop "$(make --silent prepare)/crates#desktop" -c make rust-check` runs the
full Rust check workflow directly. Quick test execution never provisions these tools:

```sh
make dev-tools-build    # explicitly prepare native workstation tools
make rust-fmt           # stable rustfmt for application, tooling and packer workspaces
make rust-fmt-check     # check without editing
make rust-spacing      # syntax-based check, locations and nonzero exit on gaps
make rust-spacing-fix  # run rustfmt first, then insert missing blank lines
make rust-style-test   # Cargo integration tests for the syntax checker
make rust-doc          # strict rustdoc, including feature-gated public APIs
make rust-check        # read-only style/docs checks, checker tests, Clippy and Cargo tests
```

The checker can also be invoked directly:

```sh
cargo run --locked --manifest-path tools/rust-style/Cargo.toml --bin check-rust-spacing
cargo run --locked --manifest-path tools/rust-style/Cargo.toml --bin check-rust-spacing -- --fix
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked --manifest-path crates/Cargo.toml
```

The [record-writing example](crates/airlock-common/nix/examples/update_record.rs)
shows lock and snapshot use without touching deployed state. Verify it directly
with `cargo run --locked --manifest-path crates/Cargo.toml -p airlock-nix-core --example update_record`;
run library doctests with `cargo test --locked --manifest-path crates/Cargo.toml -p airlock-nix-core --doc`.

`--fix` itself runs rustfmt before inserting separators. `--root DIRECTORY`
selects a fixture tree; otherwise the root is found from the tool's manifest,
independently of the caller's working directory. The checker parses Rust syntax,
does not follow symlinks or nested repositories, and excludes build/vendor/
generated directories, hidden output trees and files marked generated at the top.
Its parser dependencies belong only to the tooling workspace. `make rust-check`
runs in CI separately from `test-quick`; test execution never automatically builds tools.

### Review and verification scope

Automation checks rustfmt, declaration spacing and public documentation presence
through strict rustdoc. **Review still checks meaning**, private/tuple field
comments, conceptual function blocks, examples, opaque macro bodies and Rust
snippets inside strings or documentation. Syntax parsing cannot inspect those
opaque snippets; generated declarations must be reviewed at their macro template.

- Blank-line-only Rust edits: run `make rust-fmt` and `git diff --check`, and review
  the diff to confirm only spacing changed. Do not run tests, Clippy or rustdoc
  solely for whitespace changes; a simultaneous instruction clarification does
  not require those checks either.
- Prose, comments or Markdown links only: run `git diff --check` and verify changed
  links. Do not run Cargo tests, rustfmt, Clippy or rustdoc solely for these edits.
- Changed documentation code examples: verify the affected examples with focused
  doctests or example checks.
- Rust code, dependencies or build tooling: run appropriate tests, formatting
  checks and Clippy (`make rust-check` covers application, tooling and packer workspaces).
- Public API code or documentation-lint setup: also run strict rustdoc, as above;
  `make rust-doc` adds `--all-features` to cover the shared runtime and job-writer APIs.

Keep evidence in `.airlock-logs/`. Routine comments do not require rebuilding the
GUI just to refresh a test receipt; if running GUI tests for a code/tooling change,
prepare their artifact explicitly with `make ctrl-build` first.
