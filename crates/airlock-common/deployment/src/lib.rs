//! Bind deployment effects to approval, durable publication and execution requests.
//! Machine planning determines required effects; this crate independently checks
//! their permission. Callers authenticate records and perform filesystem/Qubes I/O.
//! Cargo executes the same Rust bodies that Verus checks.
//!
//! ## Guarantees and their scope
//!
//! `review::check` has no preconditions. Its result is successful **if and only if**
//! `authorized(review, binding, candidate)` holds. That predicate requires matching
//! request, candidate location, source commit and dependency lock; an approved or
//! started status with review material; the guest restriction; a fresh baseline
//! when supplied; the same candidate for a started review; the same previous
//! operation for a consumed review; every proposed VM effect in the allowed set;
//! and permission for required or unknown reboot effects. Loop invariants and
//! termination measures prove membership checking for arbitrary lists, including
//! duplicates and empty lists.
//!
//! `AuthorizedPlan::reviewed` computes its own complete effect projection; its
//! `Identity` input has no effect list or reboot flag. The independent
//! [`affects` relation](../../machine-planning/src/effects.rs) names every source of VM
//! impact: configuration reconciliation (including unchanged declarations), configuration
//! changes, staging, shutdown, startup, dependency-expanded
//! impact, retirement, restoration, both private-copy endpoints, GUI providers and
//! clients, and both PCI-handoff endpoints. `PlanEffects::project` proves exact set
//! equivalence to that relation, including overlaps and duplicate names, and rejects
//! unclassified fields. Unknown reboot requirements consume reboot permission.
//! The checked constructor proves every such VM belongs to the original approval,
//! checks source/candidate/baseline/consumed-operation identity, and derives its own
//! startup and shutdown lists without changing their contents or order.
//!
//! The opaque plan retains the binding of the candidate, baseline, revision and
//! complete serialized plan. Its fresh-operation and recovery methods consume that
//! binding internally, accepting no replacement. Publication and dispatch compare
//! it again. Recovery can replan against new observations, but must freshly check
//! **all** effects against the original protected decision and preserve its stable
//! operation/authority through `RecoveryDecision`. This does not require identical
//! operation sets across attempts, or grant permission merely because an effect is
//! necessary.
//!
//! VM software, properties, services, storage and device configuration are scoped
//! through their VM targets. Machine policy, global preferences and host software
//! are approved as part of the exact source/candidate, with reboot permission checked
//! separately; there is no finer per-policy or per-device human capability in this
//! approval model. `retained_undeclared` reports VMs left untouched and grants no
//! operation. Source/lock fields and storage-copy receipts are identity or progress
//! metadata, not extra VM effects. Individual adapter arguments and effects absent
//! from the plan are not covered by the projection theorem.
//!
//! The ordinary wire adapter destructures every `DeploymentPlan` field explicitly;
//! new fields require classification. Unknown wire extensions fail at projection.
//! The coordinator additionally allows only the known `private_copies` extension
//! in `Plan.extra`, preventing flattened metadata from shadowing typed plan fields.
//! Malformed PCI transfers fail decoding. Explicit administrative/review-disabled
//! policies bypass human scope checking, but still require classified plans and
//! coherent GUI shutdown modes; they carry no human-approval theorem.
//!
//! `AuthorizedOperation::new` consumes checked startup and shutdown scopes and performs mandatory
//! identity selection. It returns a value only when saved and current authority
//! encodings match. Recovery retains the saved operation ID; legacy recovery adopts
//! the previous attempt ID; a new operation uses its attempt ID. The internal
//! `operation_id` comparison is not a callable alternative authorization API.
//! `AttemptId`, `OperationId`, `AuthorityBinding`, `PlanBinding` and `IntentBinding`
//! distinguish roles at the verified boundary; string comparisons remain internal.
//! These wrappers classify already decoded inputs, rather than authenticate them.
//! The coordinator encodes the `OperationAuthority` enum, including
//! the protected decision digest and candidate fingerprint. The decision digest
//! includes the original baseline and scope. Recovery rechecks review status and
//! the observed plan as well.
//!
//! `DurableOperation` owns a non-cloneable, volatile `Publication` gate:
//!
//! ```text
//! Unpublished --IntentSaved--> Intent --ApprovalSaved--> Ready
//! Ready --begin(exact attempt, exact intent)--> Executing --Verified--> Complete
//! any invalid event or interruption --> Blocked
//! ```
//!
//! `advance` is proved to implement `next`. The invariant requires both publication
//! acknowledgments before readiness, execution or completion. `preserves` proves
//! one-step preservation; `history_preserves` proves preservation and unchanged
//! identities for every finite event history by induction. `begin` succeeds exactly
//! when both barriers are acknowledged and both identities match, and consumes
//! readiness. Invalid order, interruption and uncertain completion cannot reopen a
//! gate. This proves one begin per gate, **not exactly-once external execution**.
//!
//! `AuthorizedOperation::publication` refuses a substituted attempt, operation,
//! authority or candidate/baseline/plan binding before returning an unready gate.
//! Production supplies `IntentSaved` only after authoritative intent and history
//! publication succeeds, then `ApprovalSaved` after the required approval update
//! succeeds. For administrative/review-disabled policies no approval
//! projection is required. Publication errors emit interruption and return no token.
//! `activate` calls `begin` before external execution and its caller reports verified
//! completion or uncertainty. The intent binding hashes the entire preflight record,
//! including attempt, candidate, baseline, operation authority and effect plan.
//!
//! `Targets::reviewed` calls the full review predicate and checks every lifecycle
//! target against both the plan's affected VMs and the original approved scope.
//! Its postconditions establish `effects::valid`: each retained target belongs to
//! the approved scope. Binding and publication preserve that scope; every gate
//! transition preserves the operation authority. `DurableOperation::request`
//! requires matching attempt, operation, authority and plan at runtime, and an
//! executing gate with both acknowledgments. Its postconditions bind the returned
//! target to the planned set and, using the constructor invariant, to the original
//! approval. No caller supplies an `authorised` boolean.
//!
//! The immutable plan binding covers candidate and baseline paths, both content
//! fingerprints, source revision and the complete plan. It excludes changing phases
//! and outcome observations. The full preflight digest is retained separately.
//! `StartRequest` has no public constructor or target setter, and borrows the gate
//! until dispatch; Rust prevents interruption/completion while it is outstanding.
//! The Qubes adapter accepts only that request and uses its checked target as the
//! sole VM argument. Explicit policy exemptions use the `policy_exempt` constructors: their
//! requests remain bounded by the plan and durable intent, but carry no human-review
//! theorem. Choosing these exemptions remains part of the trusted coordinator policy.
//!
//! `Shutdowns::reviewed` checks the explicit stop list with the same target checker.
//! It also checks every expected preserved GUI client against the candidate's effect
//! set and the original approval. A GUI preservation entry must name a stopped
//! `sys-gui`, contain clients, and exclude clients explicitly scheduled to stop.
//! Clients are GUI-interruption effects; their presence never grants permission to
//! shut them down. The shared review-plan extractor includes both GUI providers and
//! clients, even when other effect lists omit them.
//!
//! `DurableOperation::shutdown` checks the same identity bindings and executing gate
//! as startup. `ShutdownRequest` borrows that gate and carries an immutable target
//! and GUI mode. `arguments` is verified executable Rust: it emits only the fixed
//! wait/timeout arguments, the plan-selected `--force` flag when appropriate, and
//! the sole checked target. The external adapter converts those strings to process
//! arguments without accepting an independent VM name or force flag.
//!
//! Before dispatch, the coordinator retains every decoded Qubes inventory row in a
//! target-bound `ShutdownObservation`. The verified `inventory` module classifies
//! known non-halted states, including paused and transitional states, as active.
//! The opaque `PowerState` type requires that classifier for construction.
//! It selects every active peer for a live GuiVM query. The request gate checks all
//! rows: an uncertain state or missing active-peer query prevents execution, every
//! active GUI client must belong to the saved expected set, and hard dependents
//! block shutdown. Undeclared active peers also block force. Halted domains, dom0
//! and the explicit target need no peer query; uncertain states still block them.
//! The inventory decision is proved equivalent to its predicate, and
//! `approved_clients` composes it with the original checked scope: every active GUI
//! client in the supplied inventory is approved when a reviewed request succeeds.
//! Normal shutdown cannot acquire `--force` from a caller or ignore active GUI
//! clients. Recovery cannot replace the saved expected client set without changing
//! the checked plan binding.
//!
//! Crashes destroy this gate. Recovery consumes a checked `RecoveryDecision`, reuses
//! the original operation, and starts a fresh unready gate.
//! The finite-history theorem covers the volatile gate's interruption transitions;
//! it does **not** model disk contents across a crash. Missing, corrupt, conflicting
//! and stale records are refused by the reader and coordinator adapter. Verus
//! proves the checks on decoded relationships; JSON parsing, coordinator error
//! propagation and orchestration remain outside the proof boundary.
//! ## Privileged deployment routes
//!
//! Reviewed deployment is distinct from `config apply`/`config host`, boot setup, and explicit storage/maintenance commands; those administrative compatibility paths do not carry deployment-review authority. The setup executable is Rust; its thin shell launcher and the upstream Qubes API adapters still sit outside Verus.
//!
//! All new, resume and rollback attempts converge in `Coordinator::activate` after
//! intent publication and `DurableAuthorization::begin`. A phase records uncertainty,
//! not completion. The machine lock does not serialize external Qubes administrators.
//! The following inventory distinguishes deployment requests from other policies.
//!
//! | Route and plan evidence | Final boundary and current enforcement |
//! | --- | --- |
//! | VM creation/properties/features/services; explicit `configure` | Rust retains every desired domain in an opaque checked configuration plan, then issues verified create/setting requests. Native backend-derived boot settings use typed requests from original definitions or identity-checked storage outcomes. Template imports and admitted legacy helper behaviour remain trusted exceptions to per-setting coverage. Native deployment device assignments use separate typed requests, rather than the per-VM device helper. |
//! | Global preferences, labels, kernels, templates and qrexec policy | Fixed prepare/finish batch requests invoke the admitted native setup executable, which reconciles global configuration and writes managed policy/kernel files; Qubes CLI/local admin API performs mutation. Exact approved source/candidate is the authority, not an invented dom0 VM scope. No verified fine-grained dispatch. Template import may start a template through upstream postprocessing when configured to do so. |
//! | Private-copy preparation and execution; `private_copies` | `AuthorizedPlan::copies` retains the exact ordered source/destination pairs, preflight identities and target configuration. Verified `CopyPlan::prepare` checks the durable execution context, receipt and observed UUID/pool/VID, distinct disks, halted power classifications and capacity. `CopyIntent` becomes `CopyRequest` only after the adapter saves `Copying`; the private Qubes clone adapter accepts that request alone. Complete receipts skip overwrite; uncertain `Copying` receipts refuse automatic replay. Observation, durable acknowledgment and faithful Qubes execution remain trusted. Both endpoints are original approval effects. |
//! | Automatic network PCI handoff; `pci_handoff` | Verified Rust checks the complete structured assignment/attachment snapshot, network class, exact supported endpoints and ownership before dispatch. An opaque request retains the exact source-owned virtual assignment, including wildcard device identity, under the checked plan and executing durable context. The thin local Qubes Unassign adapter accepts that request alone. Native deployment subsequently reconciles PCI assignments through separate verified assignment requests; boot/manual setup retains its compatibility helper policy. |
//! | Declared and automatic PCI assignments; `configure` and admitted device definitions | `DevicePlan` retains the exact configuration name/index mapping and assignment parameters. Verified selections check original scope, complete context, physical identity and full ownership; device-ID wildcards cover all matching ports. Mutation requires a named halted observation. The thin Qubes API adapter accepts only `AssignmentRequest`; same-resource replacements require an additional verified removal request. Boot/manual device helpers remain separate. Existing VM device-declaration changes require migration and are rejected by normal planning. |
//! | Guest root/private/kernel/store requests; `configure` and admitted native backend | `StoragePlan` retains exact configure coordinates and original sources. Verified requests bind root import, private growth, kernel installation, store installation, derived boot settings and outcome-driven daemon restoration to the executing context. Native deployment consumes those requests directly; raw deployment volume mutation and VM removal are refused. Image resolution and storage's internal admission/attachment implementation remain trusted/runtime-checked boundaries. |
//! | Guest storage generation selection; `stage`, desired domain backend and admitted manifest generations | Original checked stage/configure fields derive complete generation obligations. `StagedGenerations` requires a concrete, full committed boot identity for every pinned or staged native VM and accounts explicitly for nonnative and unchanged/unpinned entries. Native setup consumes this opaque in-memory result under the same attempt/operation/authority/plan and durable gate, never re-reading `staged.json`; verified final argv preserves the exact generation. Before publication, `PinnedGenerations` checks the complete set and preserves any original target snapshot exactly. Journal v3 publishes those full identities in the authoritative intent before activation; the durable gate compares the actual journal snapshot with the pin. Recovery reauthenticates the saved generations and binds them to the new checked attempt without selecting replacements. Snapshots accumulate on first visiting each permitted endpoint and survive rollback/resume; old in-memory tokens are refused. Unchanged/unpinned legacy VMs retain existing/prepared semantics. Lookup/descriptor decoding, snapshot encoding and endpoint-registry validation, committed record authentication, numeric rendering and compatibility-map publication remain adapter duties. Missing saved generations stop recovery. Old journals can adopt explicit manifest pins, but unpinned required native selections without durable evidence refuse automatic recovery. |
//! | Retirement preparation/retire; `retire` and baseline domain | `RetirementPlan` binds exact baseline definitions to the checked retire field. Verified requests require canonical trash ID, matching configuration/UUID/volume set, halted power, and matching selected generation/system/manifest. A separate verified baseline pin precedes disruption. The reversible adapter consumes fixed autostart/tag/retention requests after the trash journal save. No VM deletion is selectable. |
//! | Restoration; `restore` and candidate domain | A separately checked restore namespace binds compatible class/template/private-state configuration. Verified requests require the named UUID/private volume and halted state, reject purge states and select only removal of the retired tag. Approved new root generations remain permitted. Metadata and root unlink use the validated canonical trash ID; filesystem execution remains trusted. |
//! | Host roots/view/controller; candidate host, transport and coordinator manifest | `HostPlan` retains the original typed prepared-host identity, admitted host/transport/controller and native storage service. Publication/validation yields an opaque `CheckedGeneration` bound to its full record and original execution context; mismatched responses cannot create it. Controller link publication and retention-root filesystem effects remain trusted adapters. |
//! | Host boot preparation/selection; candidate host and transaction | Profile, install, seal, bind and select requests require the checked generation plus the unchanged durable gate. Verified argv preserves exact system/generation/record identity; storage rechecks it under the pool lock. Verified installation arguments forward identity and pool/ESP context through the private mount child, which cannot omit it without explicit administration. Protect/checkpoint observe the running baseline; sealing may preserve other retained boot entries. Typed v2 boot bindings fix the full host receipt and release fingerprint. Verified snapshot/reconciliation checks exact guest maps and transaction endpoints; an opaque restoration emits only matching selection/status/guest/controller documents. Stage one revalidates and replays all writes before runtime. Legacy v1 lacks a full receipt/fingerprint. Bootloader behavior, canonical decoding/projections, filesystem truth/durability, protected inputs and successful stage-one exclusion remain adapter obligations. |
//! | Completion and verification metadata | Journal-v3 activation and explicit verification collect complete topology/storage/readiness facts, then consume an opaque `completion::VerifiedGuests` through one completion publisher. Verified checks require original snapshot classifications, exact saved generations/boot fields, selected feature/pool agreement, required running-system evidence and current attempt/operation/authority/plan/target/host-boot bindings. Verified host comparison distinguishes completion from required reboot. Maintenance verification timestamps require the same opaque result. Historical journals retain their explicit runtime/manifest checks. Phase/history/`latest.json` writes and atomic publication/fsync remain trusted adapters. |
//! | Verification and GUI observation | `qvm-ls`/prefs/features and fixed read-only qrexec probes observe runtime generation, boot IDs and reconnect status. No explicit GUI restart command is issued here. Qubes may start dependencies or terminate a shutdown target implicitly; those external effects are not proved. |
//! | Boot/post-boot trash quarantine | Separate boot/verification policy, outside `activate` and its durable gate. The protected trash record must match the registered UUID and complete volume set before normal shutdown, autostart suppression or tag repair. Unknown power refuses enforcement; known non-halted states require shutdown. These are ordinary runtime checks, not verified deployment requests. |
//! | Trash purge | Separate explicit maintenance confirmation and lock, not a call from `activate`. Verified intent selection checks canonical confirmation, original UUID/volumes/generation/system/manifest, retired tag and named halted state. The remove adapter consumes the publication-gated request; cleanup preserves the same VM/generation/trash root. Expiry/waiver, retained references and alias discovery remain ordinary runtime checks. This independent authority cannot be derived from a deployment request. |
//! | Generation/host pruning and scheduled maintenance | Separate maintenance policies and locks, not calls from `activate`. Completion only writes a maintenance request. Typed policy and maintenance plans preserve candidate identities across internal handoffs. Automatic guest-pin release requires a verified `ReleaseRequest`, preserving explicit manual retention. Opaque `ProtectionInventory` interpretation proves complete and sound projection of the supplied release and journal groups, including verified guest-to-pool namespace derivation. The collector verifies the union with raw selected/running observations, committed retention fields and recent-policy choices; selected and policy-recent references must resolve. Verified `ReclaimRequest` construction excludes every supplied exact-generation and effective-system reference; the generation-forget adapter consumes that request alone. Missing exact pins refuse collection before deletion. Age-policy selection, release/profile/root pruning, filesystem reference enumeration, authenticated decoding and external deletion remain ordinary runtime-checked Rust. Logical/physical request construction and complete typed pin resolution use the verified boundaries described below. |
//! | Admission, candidate preparation, baseline capture | Separate pre-execution protocols write protected artifacts, provenance, roots and baseline snapshots. Build workers, artifact transport, sys-ctrl and dom0 share one typed admission receipt. Verified authentication compares claims with independently inspected committed storage; whole-machine binding also checks exact candidate artifacts, sender, provenance/reuse policy and complete guest evidence. Candidate generation/provenance fields come from the opaque bound collection. Existing review/admission/boot policies still govern preparation; possession of a deployment request does not grant admission or arbitrary filesystem authority. |
//! | Boot setup/start, local development and administrative repair | Deliberate distinct policies. Checked boot carries opaque generation selections and verified retained/root/identity requests through native setup; reviewed deployment approval proofs do not apply. Raw lifecycle commands are rejected by the deployment runner. Raw non-lifecycle mutations, the native setup executable, older admitted compatibility helpers and storage subcommands remain trusted escape boundaries. |
//! ## Trusted boundaries
//!
//! - The adapter must decode and classify every security field faithfully, including
//!   copy endpoints, grouped GUI entries and PCI transfers. The projection and its
//!   complete approval check execute verified Rust; converting typed wire fields
//!   into `PlanEffects` remains tested ordinary Rust, not a decoding theorem.
//!   Unknown top-level extensions are refused, and storage identities/receipts are
//!   interpreted by existing storage adapters. Duplicate JSON keys may be collapsed
//!   by decoding before this boundary. Adapter tests cover each effect field. The [planning boundary](../../machine-planning/README.md)
//!   documents trusted decoding, configuration encoding and source/observation projection.
//!   Effect selection outside the verified lifecycle planner, canonical authority
//!   encoding, SHA-256 collision resistance and release fingerprint computation
//!   remain trusted.
//!   The adapter chooses fresh versus recovery baseline checking. During rollback it
//!   checks the original reviewed candidate here. Recovery's target/baseline selection
//!   and their equality at authority construction are verified; loading, fingerprint
//!   calculation, immutable-plan projection and calling the gates remain adapter duties.
//! - The process adapter must execute exactly the permitted target with the fixed
//!   start invocation or verified shutdown argv. Command resolution, argument encoding,
//!   subprocess creation, timeout escalation and Qubes behavior
//!   are trusted. The proof establishes an authorized request, not successful execution.
//! - The I/O adapter must decode the complete Qubes inventory without dropping rows,
//!   supply raw state fields to the verified classifier and record truthful GuiVM
//!   queries. Missing probes are checked, rather than assumed successful. Live hard
//!   references must still match the protected baseline. The machine lock
//!   serializes Airlock operations; it does not make Qubes observations and dispatch
//!   atomic against external administrators. Changes after observation, guest shutdown
//!   hooks, implicit VM deletion and other external effects are outside this proof.
//! - The machine lock, protected file ownership, approval origin, administrative
//!   authorization and review-required policy determine which inputs carry authority.
//!   This library cannot authenticate arbitrary data supplied by another Rust caller.
//! - Filesystem success must mean atomic same-filesystem publication with file and parent
//!   directory fsync. An error may have committed data; it never supplies an acknowledgment.
//!   Power-loss durability and agreement of current/history records are outside the
//!   proof boundary. Process-crash tests exercise the real adapter.
//! - Qubes effects depend on the coordinator's observation and reconciliation adapters.
//!   Direct helpers inherit the machine flock, preventing a new Airlock recovery
//!   while they retain its descriptor after coordinator death. Helpers that close
//!   descriptors or hand work to a daemon, and independent Qubes administrators,
//!   need separate fencing/reconciliation guarantees. The verified gate does not
//!   prove safe external replay, completion observations, VM isolation or storage integrity.
//! - The verified request constructors and argument encoders are production Rust. The
//!   coordinator's call graph, wire decoding and external dispatch adapters are audited
//!   ordinary Rust. Raw deployment lifecycle/device/volume guards protect the existing
//!   process entry points; they are not a proof that arbitrary new coordinator code cannot
//!   invoke a new subprocess or filesystem mutation. New routes must be classified and
//!   connected to a request boundary during review.
//! - Verus, Z3, Rust compilation, proof erasure and the standard-library specifications
//!   in pinned vstd form the proof toolchain's trusted base. No Airlock proof uses
//!   `assume`, `external_body` or an unchecked contract to omit executable obligations.
//! - Liveness is unproved. Eventual recovery requires retained valid records, successful
//!   I/O, exclusive scheduling, and terminating/reconcilable helpers. Revocation or
//!   damaged authority intentionally blocks execution.
//!
//! Storage attachment and checked boot setup retain their own verified generation identities.
//! `attachment::prepared::CheckedGeneration` accepts a prepared descriptor only when its boot
//! identity and the committed manifest agree with the requested pool, namespace, system, root,
//! kernel, calculated closure, original source and frontends, including any explicit generation
//! pin. Its accessors carry the original namespace and positive generation to loading. Native
//! admission and host publication pass typed receipts directly; JSON remains at file/CLI edges.
//! Descriptor/manifest decoding, checksums, closure hashing, faithful load dispatch and pool
//! exclusion remain adapter obligations; this match grants no deployment or write authority.
//! `boot::SelectedGeneration` compares every boot field against committed-record evidence;
//! its requests select the exact retained-only storage command, generation-specific root lookup,
//! halted root import and fixed kernel/system/root/store identity settings. Checked boot uses
//! an explicit topology-bound, digested handoff and an in-process native backend, rather than
//! optional staging environment variables. The storage receiver compares the decoded request
//! with freshly loaded committed records before Qubes observations or admission selection.
//! Partial legacy staging remains an explicit manual policy for unselected VMs.
//!
//! JSON/record projections, SHA-256 identity, generation authentication, path and decimal
//! rendering, filesystem publication, process invocation and truthful external observations
//! remain adapter assumptions. Global policy/kernel/template/default reconciliation, private
//! resizing, boot-option construction and other backend settings do not acquire a complete
//! boot orchestration theorem from these selected-generation requests. The admitted legacy
//! batch executor retains its documented separate policy.
//! `boot::acceptance` verifies capability projection and complete same-instance boot acceptance.
//! Generation and service evidence have opaque constructors; missing capabilities, substituted
//! requirements, host boots, VM instances and publication scopes are rejected. Both supervisor
//! readiness publication paths consume an `AcceptedBoot` produced from fresh probes against
//! selected boot inputs; prior systemd success and persisted readiness are not accepted as evidence.
//! The installed policy distinguishes usable desktop startup from full autostart/service readiness.
//! Topology-to-requirement-set projection, probe dispatch, policy decoding, lock orchestration and
//! marker publication remain ordinary Rust. Probes must truthfully report the requested guest;
//! host-boot/Xen IDs must identify an incarnation without reuse during collection. Observations
//! are sequential and external administrators are not excluded by the machine lock: this proves
//! compatibility of collected evidence, not an atomic global snapshot or continuing health.
//! Input evidence covers receiver readiness and active forwarding discovery, not physical delivery
//! of every keyboard/mouse event. Explicit recovery acknowledgement remains a distinct console policy.
//!
//! Deployment completion proves correspondence of the collected observations, not an atomic
//! machine snapshot. Journal provenance, topology/readiness-scope projections, probe dispatch,
//! full record projection and the coordinator's publication call graph remain adapter duties.
//! Guest probes report their running system path, not the numeric storage generation mounted
//! inside Xen. Storage/Qubes observations must truthfully describe the selected generation;
//! independent administrators can change state after a probe. A prior successful journal or
//! stage-one restoration remains historical evidence, not proof of current guest readiness.
//! Unchanged/unpinned entries keep their explicit existing-storage policy. V1/V2/legacy
//! journals cannot acquire an exact-original-generation theorem absent their own snapshot.
//!
//! Native setup reports carry a typed run, effective-topology fingerprint, scope and phase.
//! `setup::Evidence` verifies that merging reports preserves failures, applied mode, unsupported
//! counts and pending work; its completion token binds the exact requested run/configuration/scope.
//! Deployment post-configuration progress consumes that token through its completion adapter.
//! Setup v4 independently derives required tasks from the effective topology and requested scope.
//! Verified expansion requires global preparation and configuration, backend and device work for
//! every selected VM, including explicit not-applicable outcomes. The coordinator checks exact,
//! distinct task correspondence and matching run/topology identities, applied success and no
//! blockers for every task; missing helper logs cannot remove required work. Preparation must
//! match the root scope. Per-VM results retain blockers independently of diagnostic logs.
//! JSON decoding, setup-scope selection, wire/task projections, truthful task publication and
//! fingerprints remain ordinary Rust. Task evidence records successful adapter returns rather
//! than proving external Qubes effects or ongoing machine health. Generation attachment retains
//! its separate verified selection checks; task coverage does not re-prove generation identity.
//! Missing or incomplete evidence prevents completion. Receipt persistence, directory ownership
//! and truthful same-run snapshots remain filesystem/adapter assumptions; these proofs do not
//! establish power-loss durability or exactly-once execution.
//! Negotiated v3 helpers retain the earlier bound-report guarantee without task completeness.
//! Setup v2 and shell-era helpers keep their mandatory success/unsupported/pending checks.
//! Compatibility is selected by protocol negotiation, never by malformed new report contents.
//!
//! Boot quarantine, retention/reference discovery and other maintenance policies have separate
//! authority and incomplete proof coverage. Below those policy boundaries, truthful observations,
//! durable acknowledgments, process resolution and faithful filesystem/Qubes execution remain
//! necessary environmental assumptions.
//!
//! Retention inventory proves complete and sound interpretation of the supplied decoded source groups
//! and preserves their union through reclamation. Filesystem enumeration, journal authentication,
//! snapshot/topology correspondence, raw field projection and CLI transport remain adapter duties.
//! Recent-generation ranking remains policy input; its complete chosen set is preserved. Verified
//! deduplication preserves all distinct requirements across retry histories. The coordinator holds
//! machine exclusion while its storage receiver loads committed manifests and live references under the pool lock. The receiver adds
//! all selected, running, retained and policy-recent generations before requesting reclamation;
//! supplied exact pins must exist. Stale running references lacking logical records retain their separate
//! physical-pin handling; they never invent a committed record. Source references conservatively protect
//! every matching generation.
//! Resource tracing preserves exactly every supplied manifest's objects, shared tar terminator,
//! canonical view and optional root, plus every pending object and pinned physical segment.
//! A single verified constructor accounts for the complete supplied logical source collection;
//! repeated extensions preserve earlier requirements. Invalid names or physical-range arithmetic
//! refuse tracing. Ordinary Rust decodes mandatory manifest fields, checks view/list correspondence
//! and physical bounds, and validates surviving root references before GC starts deleting.
//! Physical segment deletion adds an exact verified index over the original trace. Only an unpinned,
//! sealed, noncurrent segment can produce an opaque request; its original pool and exact filename
//! reach the shared GC/compaction adapter through verified accessors. Borrowing the trace prevents
//! extending that source while a permission survives. The adapter consumes the request, rechecks
//! physical identity, lifecycle and current selection under segment exclusion, then unlinks only files.
//! A sealed, unreferenced metadata-only remainder can finish its interrupted unlink. A remaining blob
//! without metadata, or any referenced missing bytes, refuses cleanup. Repeated cleanup rebuilds requests
//! from fresh observations.
//! Runtime mapping observations distinguish present, absent and unknown. The verified classifier
//! accounts for every name in a supplied complete inventory; failed or malformed evidence cannot
//! produce absence. Runtime-pin release requires exact-name absence and a known lifecycle, with
//! preparing pins retained during collection. A consumed permission preserves its original pool
//! and mapping through release. Ordinary Rust checks report completeness, persisted identity and
//! schema, and obtains the kernel inventory. Successful truthful enumeration and admission-lock
//! exclusion of Airlock attach operations remain assumptions; independent kernel/administrator
//! changes between observation and execution are not excluded by these proofs.
//! Logical object/fragment metadata, software views and root artifacts also require consumed deletion
//! permissions against the original trace. Their verified index preserves every category and full
//! identity, including collisions in its numeric lookup buckets. Requests retain their original pool
//! and target, and borrow the immutable trace through dispatch. Collection validates every proposed
//! logical target before forgetting generations; the adapter checks path confinement, file kinds
//! and mounts again before removing anything. Metadata unlink cannot recursively remove a directory.
//! Physical protection resolution checks one category/identity-preserving row for every entry in the
//! original logical trace, including duplicates. Objects require one current range; views require a
//! nonempty range collection; separate root artifacts carry no segment ranges. Unclassified physical
//! inputs refuse this logical interpreter. All supplied resolutions and every retained consumer's
//! ranges contribute exactly their segment identities, without granting deletion through diagnostic
//! maps. Running references always retain their pins; runtime observations preserve uncertain outcomes
//! and interrupted preparations. Mismatched observation names and invalid retained ranges refuse the
//! entire pass. GC and compaction consume an opaque `PhysicalProtection`, borrowing the original logical
//! trace, before building segment deletion's verified index in the same pool.
//! Filesystem discovery, record decoding and source-to-core field conversion remain ordinary Rust.
//! Canonical object lookup checks the original entry/schema and rejects conflicting current locations;
//! missing required lookups and invalid backing bounds stop cleanup before deletion. View-range and
//! running/kernel-source enumeration must supply the complete records; Verus does not prove JSON
//! decoding, faithful extent coordinates, backing contents or filesystem/kernel observation truth.
//! Relocation captures the original logical identity, physical range and complete decoded-record
//! fingerprint before copying. A replacement request requires unchanged pool, length and content digest
//! in a nonoverlapping range. Publication permission additionally checks the fresh original snapshot
//! and the same pool/attempt's preparing transaction; stale, completed and aborted attempts refuse.
//! The adapter derives the target object and replacement coordinates from that permission and
//! preflights logical-mirror repair before canonical publication. A crash after canonical publication
//! is reconciled from the current canonical record, never by replaying the interrupted copy.
//! Verified mirror requests preserve object/path/tree identity and immutable contents, and require both
//! observed record fingerprints to remain unchanged. Old mirror coordinates need not still have backing
//! bytes: they are repaired from independently verified current canonical bytes. Checked per-entry map
//! refresh preserves the original object, logical offset, pool, fragment length and digest. Running
//! references keep their original physical pins, and explicit host/builder file-map pins skip refresh.
//! Copy/append/hash execution, decoded-record fingerprinting, atomic publication order and durability,
//! complete map assembly, and discovery of pinned maps remain tested adapter obligations. These request
//! contracts do not prove the full filesystem crash protocol or append allocator correct.
//! Admission wire records are shared by sender and receiver; decoding a receipt alone produces no
//! authority. The production authentication gate compares guest/runtime namespace, generation, manifest,
//! system, complete root identity, kernel, closure hash and provenance with independent committed storage.
//! Actual inspection, verification, retention and approval-source facts are mandatory. Whole-machine
//! candidate binding additionally requires the controller sender, exact expected immutable artifacts and
//! closure source, and the original protected release fingerprint. Fresh receipts require the current
//! source; explicit reuse may preserve older provenance only after every actual artifact binding succeeds.
//! A checked collection requires every supplied expected guest exactly once, with complete matching
//! expectations and one original release fingerprint. Candidate generation and provenance publication
//! reads the original evidence through verified accessors. Guest-only preparation retains its distinct
//! sender/approval policy and does not acquire whole-machine binding authority.
//! Root metadata validation, typed-field projection, complete topology/catalog enumeration, protected
//! release and committed-record authentication, hashes, transport framing and candidate serialization
//! remain adapter duties. Storage admission is not deployment activation authority; existing protected
//! source approval, complete effect checks and durable execution gates still apply.
//! The administrative configuration pipeline separately consumes content-bound validator v2 records.
//! Its shared production gates require complete, distinct successful mandatory checks, exact original
//! submitted bundle/manifest/commit, independently inspected Git head and all evaluated/prepared-source
//! digests. Opaque validation and resolution values carry those inputs through source resolution.
//! Setup and host apply consume private checked snapshots, while explicit stage retries reauthenticate
//! the original archive and refuse substituted resolution inputs or output bytes. Old unbound validation
//! receipts require fresh validation before activation; historical vault evidence grants no authority.
//! JSON source-descriptor normalization checks that resolution changes only declared source fields;
//! that recursive projection, schema decoding, hashes, Git/Nix behavior, authenticated offline-role
//! transport, filesystem snapshots and faithful adapter execution remain tested/trusted boundaries.
//! Verus proves evidence correspondence and complete-check gates, not truthful evaluation, faithful
//! Nix source resolution, or correctness of every configuration action. These administrative decisions
//! do not acquire reviewed deployment approval or its durable transaction guarantees.
//! Direct administrative `config resolve`/`config host` commands retain their explicit local policy;
//! they cannot be counted as consumers of this validated pipeline merely because they share adapters.
//! Record decoding, faithful request-to-path dispatch, lock discipline, truthful observations and
//! actual unlink/fsync remain trusted. Recursive removal checks mounts and does not follow symlinks,
//! but these filesystem properties are tested adapter contracts, not Verus theorems.
//! These snapshots do not exclude independent raw filesystem writers, prove root contents or establish
//! exactly-once execution or power-loss durability.
//! Pin-release classification is rechecked under the same storage lock, so a newer manual retention
//! update is not overwritten. Repeated collection rebuilds protections and requests; it does not replay
//! cached deletion authority. Independent raw filesystem writers, durable publication, physical-byte
//! deletion and manual retirement remain outside this theorem. Collection affects immutable software
//! generations, not private VM volumes. It neither proves exactly-once cleanup nor eventual reclamation.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub mod review;

pub mod publication;

pub mod effects;

pub mod inventory;

pub mod operation;

pub mod planning;

pub mod recovery;

/// Exact guest-generation observations required before deployment completion.
pub mod completion;

/// Candidate-bound admission evidence checked against independently inspected generations.
pub use airlock_machine_planning::admission;

/// Protection evidence shared by automatic pin release and locked storage reclamation.
pub mod retention;

pub mod plan;

pub mod configuration;

pub mod copy;

pub mod host;

pub mod retirement;

pub mod pci;

pub mod devices;

pub mod storage;

pub mod attachment;

pub mod purge;

pub mod boot;

/// Setup report aggregation and bound completion decisions.
pub mod setup;

/// Immutable-volume callback decisions shared with the installed Qubes plugin.
pub mod volume_lifecycle;
