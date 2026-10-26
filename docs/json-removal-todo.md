# Unnecessary internal JSON: TODO

Ordered removal tasks from the code review, starting with execution boundaries.
Each item replaces avoidable JSON glue with direct Rust values. This list excludes
the separate proposals to strengthen legitimate JSON protocols and records.
Existing transport, persistence, diagnostic and upstream formats stay in place.

1. [x] **Carry checked storage installations directly into Qubes dispatch.**
   Replace the in-process `Fn(Value) -> Result<Value>` validation callback with
   typed requests and a checked installation result. Dispatch must consume the
   checked VM, pool and ordered volume definitions without extracting them from
   a JSON object. Retain JSON at the isolated worker's process boundary.
   Sources: [storage adapter](../crates/airlock-common/qubes/src/storage.rs),
   [installation checks](../crates/airlock-dom0/service/src/store/domain/attachment.rs),
   [guard dispatch](../crates/airlock-dom0/service/src/store/qubes_inspect.rs).

2. [x] **Remove JSON requests between the native Qubes plugin and Rust engine.**
   Replace the plugin's in-process JSON operation objects with typed engine calls
   or request/result enums. Keep conversion of upstream Python objects at the
   adapter edge and retain the existing serialized CLI interface.
   Sources: [plugin entry point](../crates/airlock-qubes-python/src/lib.rs),
   [storage callbacks](../crates/airlock-qubes-python/src/storage.rs),
   [engine dispatch](../crates/airlock-dom0/service/src/store/qubes_inspect.rs).

3. [x] **Stop retrieving executable setup parameters from diagnostic JSON.**
   Store policy installation and preview paths as typed session fields. Use those
   fields during setup; copy their values into diagnostics only for reporting.
   Sources: [session](../crates/airlock-dom0/service/src/setup_config/runtime.rs),
   [setup preparation](../crates/airlock-dom0/service/src/setup_config/run.rs).

4. [ ] **Remove JSON round trips from internal storage helper calls.**
   Pass typed prepared-generation verification inputs directly instead of
   serializing setup arguments. Return typed generation identities and admission
   receipts from internal calls; serialize only in their CLI adapters. Apply the
   same separation to host receipt publication, which currently decodes an
   internal `Value` back into `HostReceipt`.
   Sources: [domain admission](../crates/airlock-dom0/service/src/store/domain.rs),
   [prepared storage](../crates/airlock-dom0/service/src/store/prepared.rs),
   [generation admission](../crates/airlock-dom0/service/src/store/generations.rs),
   [host publication](../crates/airlock-dom0/service/src/store/host_machine.rs).

5. [ ] **Check relocation extents directly as Rust values.**
   Replace the typed `Extent` to JSON conversion before extent validation with
   a typed validation entry point. Keep all backing-path, content and range checks.
   Sources: [relocation](../crates/airlock-dom0/service/src/store/relocation.rs),
   [extent validation](../crates/airlock-dom0/service/src/store/segments.rs).

6. [ ] **Compare typed records without serializing them to JSON first.**
   Replace serialization-only comparisons of storage snapshots, controller jobs
   and review bindings with explicit typed equality. Preserve comparison of every
   field currently covered, including retained extension metadata. Do not change
   serialization used for persisted content hashes or operation identities.
   Sources: [storage snapshots](../crates/airlock-dom0/service/src/store/domain.rs),
   [controller jobs](../crates/airlock-sys-ctrl/service/src/controller.rs),
   [review bindings](../crates/airlock-dom0/service/src/coordinator/reviews.rs).

7. [ ] **Pass image label declarations without temporary JSON objects.**
   Pass label names and optional colors from VM plans directly to label allocation
   through a small typed declaration or borrowed fields.
   Source: [offline Qubes assembly](../crates/airlock-image/src/runtime/qubes.rs).

8. [ ] **Replace JSON-based enum conversions with direct Rust conversions.**
   Parse setup scope and phase directly, and convert storage modes using explicit
   enum mappings or string methods. Preserve accepted spellings and rejection of
   unsupported values.
   Sources: [setup session](../crates/airlock-dom0/service/src/setup_config/runtime.rs),
   [setup selection](../crates/airlock-dom0/service/src/setup_config/selection.rs),
   [storage handoff](../crates/airlock-dom0/service/src/store/handoff.rs),
   [generation staging](../crates/airlock-dom0/service/src/coordinator/staging.rs).
