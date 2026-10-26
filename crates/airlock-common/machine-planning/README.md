# Machine planning

This library interprets decoded VM relationships and calculates required lifecycle
effects. Its graph kernel and topology interpreter serve machine authoring and
runtime planning; deployment-specific seed and GUI rules live in `deployment`.
It performs no I/O and grants no authority. Approval and durable execution belong
to [deployment core](../deployment/README.md), which depends on this crate's public
contracts. This crate has no dependency on deployment authorization.

Cargo executes the same Rust bodies checked by Verus. The crate owns its name,
index and mask conversions, so callers cannot replace a graph's identity table.

Guest initialization and health probes also use this crate's private-storage checks.
`PrivateMount` requires the expected block device at `/rw`; `ReadyStorage` additionally
requires unique, writable ext4 mounts of that filesystem's `/home` and `/usrlocal`
roots at `/home` and `/usr/local`, with `nosuid,nodev`. Device initialization is
refused while the private device or a destination is mounted. The guest adapter
reads live mountinfo, rejects source-directory overmounts and checks directory
aliases; login dependencies and pre-start checks enforce failure propagation.
These are snapshot guarantees. Kernel observations, mountinfo decoding, systemd,
upstream Qubes helpers and filesystem durability remain outside the proof boundary;
concurrent privileged mount changes can invalidate an observation.

Topology-managed IPC rules also cross a typed boundary here. The decoder consumes
the complete ordered wire declarations and either rejects the policy or preserves
every field, row and duplicate in its exact text encoding. Services cannot overlap
the protected bootstrap list; wildcard endpoints are denial-only, and dom0 is an
explicit source exception rather than an allowed target. Unsupported fields/actions
fail instead of silently disappearing. JSON decoding is a trusted adapter (`wire`);
the actual decoding decisions and renderer execute their Verus-checked bodies.

Setup retains policy destinations as an opaque selection rather than reading them
from diagnostic JSON. Its verified publication constructor binds only the selected
target; the informational preview cannot replace it. Native path conversion,
filesystem canonicalization and configured-directory checks remain adapter duties.
Publication and refresh types retain that complete policy and its exact target.
The filesystem adapter obtains publication evidence only after fsync/rename and
readback; the service adapter consumes its request's fixed argument vectors.
Completion requires matching final readback and a successful running-service
observation. Repeated apply re-establishes both barriers even for unchanged bytes.
This is a refresh acknowledgment, not a proof of Qubes' internal cache, global
policy precedence or immediate revocation of in-flight requests. Static policy
packages, filesystem/daemon truth and administrative path overrides remain trusted.

Before evaluation, the [authoring snapshot](../../airlock-config/src/model.rs)
uses `Relationships::ordered` to check its typed VM references. After
[NixOS normalization](../../airlock-config/src/topology/normalize.rs),
[release loading](../../airlock-dom0/service/src/state.rs) decodes `Topology`;
the deployment planner uses the same relationship interpreter. This shared path
does not prove that evaluation or decoding preserves the original source.

Users approve source and allowed VM effects before artifacts exist. The
[planner](../machine/src/planning.rs) passes decoded reference fields to the
verified [topology interpreter](src/topology.rs). Omission inherits the matching
host default; explicit null or empty settings suppress it. Both disposable-VM
properties share `default_dispvm`. Empty, dom0 and self references require no
provider. Other names must satisfy the Qubes guest-name grammar. Malformed
participating references fail; overridden defaults and omitted display edges are
not consulted. Device backends never inherit a host default.

`NamedGraph::new` accepts decoded declarations and a proposed lexical name table.
It verifies that this table contains exactly the declarations and explicit impact
seeds, rejects duplicate declaration identities, and constructs exactly the
internal effective dependency relation. External references remain in the named
relation without acquiring vertices. Its checked type invariant retains this
relationship provenance and the identity table. Named startup, shutdown and impact
methods own every mask and index-to-name conversion; callers cannot supply raw
indices, edges or replacement output names. Equivalent decoded topologies, defined
by their identity universe and effective named relation, produce identical
canonical name contents and equivalent graph relations. This does not assert byte
identity of edge-vector storage or uniqueness of complete serialized plans.

The production [deployment seed selector](src/deployment.rs) compares complete canonical domain
values, with absence distinguishing additions and removals. A candidate VM is
changed when its value differs or the machine's kernel definitions or host
preferences differ. Template definitions, policy and other host metadata do not
by themselves seed VM restarts. Changed and removed names seed impact propagation;
only candidate VMs already running or explicitly configured with boolean
`autostart = true` seed startup. A changed, stopped VM therefore need not start,
and an unchanged running VM remains a startup reconciliation root.

`SeedPlan` checks that configuration rows cover exactly the baseline/candidate
identities, with consistent presence, unique names and checked canonical graph
tables. It derives roots itself, interprets GUI eligibility and owns every named
planner call. Its constructor proves exact root membership; its cached impact
closure has a checked type invariant. Callers cannot supply replacement masks,
seeds or GUI omission sets after construction. `deterministic` proves equal root
sets for equivalent row values and running-set contents, including reordered
configuration rows. Existing named-graph determinism applies to the expansion.
This is a set theorem, not a complete serialized-plan uniqueness theorem.

GUI preservation means keeping eligible **clients** alive while `sys-gui` may
restart. An eligible client has identical baseline/candidate domain values, is
not `sys-gui`, advertises the exact baseline feature string
`airlock-gui-reconnect = "1"`, and effectively uses `sys-gui` as its baseline
GuiVM. The candidate must still declare that provider. Any hard reference to the
provider, including a device backend, disqualifies the client. Only that client's
soft display edge is omitted for impact propagation. Other dependency paths and
global changes can still make it affected. Reconnection is selected exactly for
running eligible clients outside the affected closure when `sys-gui` is affected.
Shutdown ordering always uses the full baseline graph. These decisions grant no
extra permission: GUI clients remain interruption effects checked by the original
approval and by the live shutdown inventory gate.

For live deployment planning, the verified power-state decision accepts only
`Running` and `Halted`; paused, transitional, unknown and missing states require a
new stable snapshot. The runtime adapter also rejects malformed and duplicate
rows. Boot, general status and maintenance retain separate observation policies.
A pure planning caller supplies its own running set; undeclared running VMs do
not become managed lifecycle targets. Inventory completeness and concurrent drift
remain external assumptions.

These methods execute the verified [graph kernel](src/graph.rs): forward
least closure for startup, reverse least closure for affected dependents, and
dependency-first permutations for ordering. The closure specification requires
inclusion of the seeds, closure under dependencies, and containment in every
other closed superset. This proves completeness and absence of unjustified
vertices without specifying a traversal algorithm. Equivalent edge relations,
including edge permutations and duplicates, have the same closure masks.

`Graph::startup` composes closure and ordering without an unverified intermediate
mask conversion. `Graph::shutdown` computes exactly the affected/running
intersection and reverses dependency order for selected endpoints. Cycles are
rejected even outside the selected operations: failure means no full topological
permutation exists. Endpoint bounds are an automatically checked type invariant;
wrong-size masks fail closed. The existing lexical ready-wave ordering is retained
and regression tested. An extensional uniqueness theorem for the complete
serialized plan, including tie order and metadata, is outside these proofs.

The [effect projection](src/effects.rs) classifies complete deployment-plan impact
without granting permission. Its mathematical relation is the union of each VM
impact source, including copy, GUI and PCI endpoints. The executable projection
proves both completeness and absence of invented names, rejects unknown fields,
and preserves unknown reboot requirements as requiring permission. Source review
and deployment authorization share this projection. Decoding fields into the
classified input remains an adapter obligation; operation authority belongs to
deployment core.

## Boundary and assumptions

Rust/Rusix evaluation, JSON decoding and typed-field projection supply the inputs.
The adapter must preserve every reference, feature and autostart value and encode
complete configuration values faithfully. Canonical encoding uses ordered maps and
normalizes signed floating zero to preserve existing typed equality. Decoding can
collapse duplicate JSON object keys before the checked declaration boundary;
duplicate decoded declaration/configuration rows are rejected here. Non-object
device containers and absent backend fields remain optional; non-array assignment
lists are invalid. GuestName/string collection conversion is a tested adapter.

The runtime adapter must supply complete, truthful Qubes observations. A pure
planning caller can supply an explicit running set, including recovery's saved
startup targets; this does not authenticate that evidence. Source snapshot selection,
recovery runtime reconstruction and fresh-live filtering remain coordinator
responsibilities. Deployment core verifies recovery's immutable endpoint selection
and its authority handoff. External effects and client survival are outside these proofs.
Selection of staging, retirement/restoration, copy and PCI operations, host-reboot
evidence and complete serialized-plan determinism remain outside the planner
correctness contracts. Their declared impact is projected separately.

`make verify` checks this crate and deployment core using the shared
[workspace pin](../../verus.json); `make verify-prepare` explicitly prepares the
toolchain. Ordinary Cargo compiles and tests the executable code without running
or provisioning Verus. Cross-crate approval composition belongs to deployment
core's [planning contracts](../deployment/src/planning.rs).
