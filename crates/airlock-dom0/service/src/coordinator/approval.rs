//! Validate authority without consuming it; publish intent before updating its status.
//! The machine lock must span validation, publication and all external effects.
//!
//! `latest.json` is the authoritative current operation. Its preflight record
//! binds both release fingerprints, the planned effects, the protected decision
//! digest and a stable operation ID. Transaction history and `DeploymentStarted`
//! are projections: publish current intent, then history, then approval status.
//! Only successful completion of those writes yields `DurableAuthorization`.
//! A crash at any later point leaves a discoverable operation to resume/rollback.
//! Recovery creates a new attempt but preserves the operation and authority;
//! it rechecks the protected decision and bounds the newly observed plan again.
//!
//! A phase means an effect may have started, not that it completed. Neither an
//! I/O error nor a subprocess error proves that nothing happened. Resume uses
//! the Qubes/storage observation and reconciliation paths; completion
//! is recorded only after their verification. There is no exactly-once claim.
//!
//! Recovery from a native journal without an operation identity uses that
//! journal's attempt ID after fingerprint and approval checks. A legacy started
//! approval without a journal can retry only against its original reviewed
//! baseline and candidate. After a boot change it fails stale; recovery must not
//! invent its missing intent.
//! This coordinator writes native v2 journals, whose version marker makes
//! unsupported coordinators reject the record. Recovery requires a v2-capable
//! coordinator to interpret the operation binding.
//!
//! `airlock-deployment-core` contains the Verus-checked executable review predicate,
//! complete classified effect projection and scope checks, recovery evidence/endpoint
//! decisions, owned operation identity, publication gate and exact lifecycle requests.
//! Recovery consumes that decision before publication.
//! This adapter owns
//! decoding/classification of complete wire fields, canonical hashing, policy exceptions
//! and truthful I/O acknowledgments; it is not itself verified by Verus.
//! See that crate's README for the exact theorem and trusted-boundary inventory.
//! Filesystem crash consistency, helper fencing, external replay safety
//! and eventual progress are outside the proof boundary.

use super::*;
use airlock_deployment_core::{
    effects::{GuiPreservation, ShutdownObservation, ShutdownRequest, StartRequest},
    operation::{
        AttemptId, AuthorityBinding, AuthorizedOperation, DurableOperation, IntentBinding,
        OperationId, PlanBinding,
    },
    plan::AuthorizedPlan,
    publication::Event,
    recovery::RecoveryDecision,
    review,
};
use airlock_nix_core::identity::BaselineFingerprint;

pub(super) struct CheckedAuthorization {
    // Immutable evidence copied into the authoritative deployment journal.
    authority: OperationAuthority,
    // Protected decision whose deployment status is a reconciled projection.
    approval: Option<ApprovalRecord>,
    // Complete checked impact and its immutable candidate/baseline/plan binding.
    plan: AuthorizedPlan,
    // Exact VM definitions captured before publication and retained through recovery.
    configuration: airlock_deployment_core::configuration::ConfigurationPlan,
    // Exact copy pairs and resource definitions from the same approved preflight plan.
    copies: airlock_deployment_core::copy::CopyPlan,
    // Exact declared PCI assignments and automatic-network rules from the approved topology.
    devices: airlock_deployment_core::devices::DevicePlan,
    // Native storage sources and capacity captured from the same checked configuration.
    storage: airlock_deployment_core::storage::StoragePlan,
    // Specific PCI endpoints retained from the complete checked effect plan.
    pci: airlock_deployment_core::pci::HandoffPlan,
    // Admitted host, controller and storage adapter captured before intent publication.
    host: airlock_deployment_core::host::HostPlan,
    // Exact baseline retirement namespace and resource definitions.
    retirements: airlock_deployment_core::retirement::RetirementPlan,
    // Exact candidate restoration namespace and private-storage compatibility.
    restorations: airlock_deployment_core::retirement::RetirementPlan,
    // Captured recovery inputs cannot be dropped to mint a fresh operation after review.
    recovery: Option<RecoveryAuthorization>,
}

/// Immutable recovery evidence captured with the freshly checked effect scope.
struct RecoveryAuthorization {
    // Prior intent supplied to the approval check, not a later caller-selected journal.
    prior: airlock_deployment_core::recovery::Journal,
    // Target loaded and fingerprinted when this plan was authorized.
    release: airlock_deployment_core::recovery::Release,
    // Possible live baseline used by this exact planning attempt.
    baseline: airlock_deployment_core::recovery::Release,
}

/// Only successful intent and approval publication permits entering activation.
pub(crate) struct DurableAuthorization {
    // Can only be constructed by consuming the checked operation and scope.
    operation: DurableOperation,
    // VM configuration can only dispatch definitions from the same complete checked plan.
    configuration: airlock_deployment_core::configuration::ConfigurationPlan,
    // Exact copy pairs and resource definitions from the same approved preflight plan.
    copies: airlock_deployment_core::copy::CopyPlan,
    // Exact declared PCI assignments and automatic-network rules from the approved topology.
    devices: airlock_deployment_core::devices::DevicePlan,
    // Native storage sources and capacity captured from the same checked configuration.
    storage: airlock_deployment_core::storage::StoragePlan,
    // Specific PCI endpoints retained from the complete checked effect plan.
    pci: airlock_deployment_core::pci::HandoffPlan,
    // Admitted host, controller and storage adapter captured before intent publication.
    host: airlock_deployment_core::host::HostPlan,
    // Exact baseline retirement namespace and resource definitions.
    retirements: airlock_deployment_core::retirement::RetirementPlan,
    // Exact candidate restoration namespace and private-storage compatibility.
    restorations: airlock_deployment_core::retirement::RetirementPlan,
}

/// Checked operation identity and scope, required by the persistence adapter.
pub(super) struct AuthorizedDeployment {
    // Opaque verified value; neither journal decoding nor this adapter can construct its fields.
    operation: AuthorizedOperation,
    // Configuration authority paired with the operation's immutable plan binding.
    configuration: airlock_deployment_core::configuration::ConfigurationPlan,
    // Exact copy pairs and resource definitions from the same approved preflight plan.
    copies: airlock_deployment_core::copy::CopyPlan,
    // Exact declared PCI assignments and automatic-network rules from the approved topology.
    devices: airlock_deployment_core::devices::DevicePlan,
    // Native storage sources and capacity captured from the same checked configuration.
    storage: airlock_deployment_core::storage::StoragePlan,
    // Specific PCI endpoints retained from the complete checked effect plan.
    pci: airlock_deployment_core::pci::HandoffPlan,
    // Admitted host, controller and storage adapter captured before intent publication.
    host: airlock_deployment_core::host::HostPlan,
    // Exact baseline retirement namespace and resource definitions.
    retirements: airlock_deployment_core::retirement::RetirementPlan,
    // Exact candidate restoration namespace and private-storage compatibility.
    restorations: airlock_deployment_core::retirement::RetirementPlan,
    // Wire authority preserved for serializing the exact selected operation.
    authority: OperationAuthority,
    // Status projection updated only after intent publication succeeds.
    approval: Option<ApprovalRecord>,
}

impl DurableAuthorization {
    /// Enter storage execution only with selections captured before this intent was published.
    pub(super) fn activate_pinned(
        &self,
        record: &Record,
        pinned: airlock_deployment_core::storage::staging::persistence::PinnedGenerations,
    ) -> Result<airlock_deployment_core::storage::staging::StagedGenerations> {
        self.storage
            .activate_pinned(
                &self.operation,
                &effect_context(record)?,
                pinned,
                &super::staging::current_snapshot(record)?,
            )
            .context("pinned generations differ from published execution intent")
    }

    /// Backend setup consumes the accepted in-memory staging result, never a raw map.
    pub(crate) fn staged_storage<'a>(
        &'a self,
        record: &Record,
        index: usize,
        staged: &'a airlock_deployment_core::storage::staging::StagedGenerations,
    ) -> Result<Option<airlock_deployment_core::storage::staging::StagedBackend<'a>>> {
        let definition = self
            .storage
            .definitions()
            .get(index)
            .context("missing checked storage definition")?;
        if definition.native.is_none() {
            return Ok(None);
        }
        self.storage
            .select_staged(&self.operation, &effect_context(record)?, staged, index)
            .map(Some)
            .context("staged backend differs from executing deployment")
    }

    /// Observe exact retained device definitions without granting mutation permission.
    pub(crate) fn device_definitions(&self) -> &[airlock_deployment_core::devices::Definition] {
        self.devices.definitions()
    }

    /// Select a declaration from its checked VM/assignment indices and named hardware observations.
    pub(crate) fn device_explicit<'a>(
        &'a self,
        record: &Record,
        vm: usize,
        assignment: usize,
        hardware: &'a airlock_deployment_core::pci::Device,
        observed: &airlock_deployment_core::devices::Observation,
    ) -> Result<airlock_deployment_core::devices::AssignmentIntent<'a>> {
        self.devices
            .explicit(
                &self.operation,
                &effect_context(record)?,
                vm,
                assignment,
                hardware,
                observed,
            )
            .context("declared PCI assignment differs from scope, identity or ownership")
    }

    /// Automatic discovery still requires original scope, executing intent and eligible network hardware.
    pub(crate) fn device_automatic<'a>(
        &'a self,
        record: &Record,
        vm: usize,
        hardware: &'a airlock_deployment_core::pci::Device,
        observed: &airlock_deployment_core::devices::Observation,
    ) -> Result<airlock_deployment_core::devices::AssignmentIntent<'a>> {
        self.devices
            .automatic(
                &self.operation,
                &effect_context(record)?,
                vm,
                hardware,
                observed,
            )
            .context("automatic PCI assignment differs from scope, eligibility or ownership")
    }

    /// Bind the complete observed handoff to the original endpoint fields and executing gate.
    pub(super) fn pci<'a>(
        &'a self,
        record: &Record,
        observed: &'a airlock_deployment_core::pci::CheckedObservation,
    ) -> Result<airlock_deployment_core::pci::Handoff<'a>> {
        self.pci
            .execution(&self.operation, &effect_context(record)?, observed)
            .context("PCI handoff differs from the checked plan or durable execution context")
    }

    /// Pin only a baseline and transaction/VM root selected by the checked retirement plan.
    pub(super) fn retirement_pin<'a>(
        &'a self,
        record: &Record,
        index: usize,
        receipt: &airlock_deployment_core::retirement::Receipt,
    ) -> Result<airlock_deployment_core::retirement::RetirementPin<'a>> {
        self.retirements
            .pin(&self.operation, &effect_context(record)?, index, receipt)
            .context("retirement baseline pin denied")
    }

    /// Select reversible retirement/restoration with exact trash, VM and storage identities.
    pub(super) fn retirement<'a>(
        &'a self,
        record: &Record,
        index: usize,
        kind: airlock_deployment_core::retirement::Kind,
        receipt: &'a airlock_deployment_core::retirement::Receipt,
        observed: &airlock_deployment_core::retirement::Observation,
    ) -> Result<airlock_deployment_core::retirement::RetirementRequest<'a>> {
        let plan = match kind {
            airlock_deployment_core::retirement::Kind::Retire => &self.retirements,
            airlock_deployment_core::retirement::Kind::Restore => &self.restorations,
        };
        plan.request(
            &self.operation,
            &effect_context(record)?,
            index,
            receipt,
            observed,
        )
        .context("retirement/restoration identity, storage, power or authority check failed")
    }

    /// Select only a retained host operation under the unchanged executing deployment.
    pub(super) fn host<'a>(
        &'a self,
        record: &Record,
        action: airlock_deployment_core::host::Action,
    ) -> Result<airlock_deployment_core::host::HostRequest<'a>> {
        self.host
            .request(&self.operation, &effect_context(record)?, action)
            .context("host execution authority differs or is not executing")
    }

    /// Candidate boot effects require the checked result from this exact durable context.
    pub(super) fn host_checked<'a>(
        &'a self,
        record: &Record,
        action: airlock_deployment_core::host::Action,
        receipt: &'a airlock_deployment_core::host::CheckedGeneration,
    ) -> Result<airlock_deployment_core::host::HostRequest<'a>> {
        self.host
            .request_checked(&self.operation, &effect_context(record)?, action, receipt)
            .context("checked host generation or execution authority differs")
    }

    /// Select an exact approved private-copy pair; uncertainty never returns a clone request.
    pub(super) fn copy<'a>(
        &'a self,
        record: &Record,
        index: usize,
        receipt: &airlock_deployment_core::copy::Receipt,
        observed: &'a airlock_deployment_core::copy::Observation,
    ) -> Result<Option<airlock_deployment_core::copy::CopyIntent<'a>>> {
        self.copies.prepare(&self.operation, &effect_context(record)?, index, receipt, observed)
            .map_err(|denial| anyhow::anyhow!("private copy denied: {denial:?}; uncertain copies require explicit reconciliation"))
    }

    /// Borrow immutable configuration inputs for observation, without mutation permission.
    pub(crate) fn configuration_definitions(
        &self,
    ) -> &[airlock_deployment_core::configuration::Definition] {
        self.configuration.definitions()
    }

    /// Select VM creation from the retained definition and current durable operation.
    pub(crate) fn configuration_create<'a>(
        &'a self,
        record: &Record,
        index: usize,
        exists: bool,
    ) -> Result<Option<airlock_deployment_core::configuration::CreateRequest<'a>>> {
        self.configuration
            .create(&self.operation, &effect_context(record)?, index, exists)
            .map_err(|denial| anyhow::anyhow!("configuration creation denied: {denial:?}"))
    }

    /// Admit only a declared key/value for the observed halted VM.
    pub(crate) fn configuration_setting<'a>(
        &'a self,
        record: &Record,
        selection: airlock_deployment_core::configuration::Selection,
        observation: &airlock_deployment_core::configuration::SettingObservation,
    ) -> Result<Option<airlock_deployment_core::configuration::SettingRequest<'a>>> {
        self.configuration
            .setting(
                &self.operation,
                &effect_context(record)?,
                selection,
                observation,
            )
            .map_err(|denial| anyhow::anyhow!("configuration setting denied: {denial:?}"))
    }

    /// Global preparation/finish and legacy compatibility retain the complete checked namespace.
    pub(super) fn configuration_batch<'a>(
        &'a self,
        record: &Record,
        phase: airlock_deployment_core::configuration::SetupPhase,
    ) -> Result<airlock_deployment_core::configuration::BatchRequest<'a>> {
        self.configuration
            .batch(&self.operation, &effect_context(record)?, phase)
            .map_err(|denial| anyhow::anyhow!("configuration batch denied: {denial:?}"))
    }

    /// Request a shutdown mode selected from the immutable checked plan and fresh observations.
    pub(super) fn shutdown<'a>(
        &'a self,
        record: &Record,
        name: &GuestName,
        observation: &ShutdownObservation,
    ) -> Result<ShutdownRequest<'a>> {
        let operation = record
            .metadata
            .details
            .operation
            .as_ref()
            .context("missing durable operation")?;
        self.operation
            .shutdown(
                &AttemptId::new(record.id.as_str().to_owned()),
                &OperationId::new(operation.id.as_str().to_owned()),
                &AuthorityBinding::new(serde_json::to_string(&operation.authority)?),
                &PlanBinding::new(record_plan_binding(record)?),
                name.as_str().to_owned(),
                observation,
            )
            .context("VM shutdown or its clients differ from the authorized executing intent")
    }

    /// Request the exact planned VM only while its own durable intent is executing.
    pub(super) fn start<'a>(
        &'a self,
        record: &Record,
        name: &GuestName,
    ) -> Result<StartRequest<'a>> {
        let operation = record
            .metadata
            .details
            .operation
            .as_ref()
            .context("missing durable operation")?;
        self.operation
            .request(
                &AttemptId::new(record.id.as_str().to_owned()),
                &OperationId::new(operation.id.as_str().to_owned()),
                &AuthorityBinding::new(serde_json::to_string(&operation.authority)?),
                &PlanBinding::new(record_plan_binding(record)?),
                name.as_str().to_owned(),
            )
            .context("VM start differs from the authorized executing intent")
    }

    pub(super) fn check(&self, record: &Record) -> Result<()> {
        ensure!(
            self.operation.permits(
                &AttemptId::new(record.id.as_str().to_owned()),
                &IntentBinding::new(state::digest(&serde_json::to_value(record)?)?)
            ),
            "durable authorization intent differs or is not ready"
        );
        Ok(())
    }

    /// Consume readiness before entering external execution, rejecting token reuse.
    pub(super) fn begin(&mut self, record: &Record) -> Result<()> {
        self.check(record)
            .inspect_err(|_| self.operation.advance(Event::Interrupted))?;
        ensure!(
            self.operation.begin(
                &AttemptId::new(record.id.as_str().to_owned()),
                &IntentBinding::new(state::digest(&serde_json::to_value(record)?)?)
            ),
            "durable authorization is not ready"
        );
        Ok(())
    }

    /// Report verification or uncertainty; neither permits another execution.
    pub(super) fn finish(&mut self, verified: bool) {
        self.operation.advance(if verified {
            Event::Verified
        } else {
            Event::Interrupted
        });
    }
}

impl CheckedAuthorization {
    /// Allocate a fresh operation; recovery uses the decision-consuming constructor instead.
    pub(super) fn operation(self, attempt: &TransactionId) -> Result<AuthorizedDeployment> {
        ensure!(
            self.recovery.is_none(),
            "recovery requires a checked reconciliation decision"
        );
        let operation = self
            .plan
            .operation(
                AttemptId::new(attempt.as_str().to_owned()),
                AuthorityBinding::new(serde_json::to_string(&self.authority)?),
            )
            .context("new deployment authority rejected")?;
        Ok(AuthorizedDeployment {
            operation,
            configuration: self.configuration,
            copies: self.copies,
            devices: self.devices,
            storage: self.storage,
            pci: self.pci,
            host: self.host,
            retirements: self.retirements,
            restorations: self.restorations,
            authority: self.authority,
            approval: self.approval,
        })
    }

    /// Recovery must consume the accepted record reconciliation as well as fresh scope checks.
    pub(super) fn recover(
        self,
        attempt: &TransactionId,
        decision: RecoveryDecision,
    ) -> Result<AuthorizedDeployment> {
        let recovery = self
            .recovery
            .context("new authorization cannot be used as recovery")?;
        let operation = self
            .plan
            .recover(
                decision,
                &recovery.prior,
                &recovery.release,
                &recovery.baseline,
                AttemptId::new(attempt.as_str().to_owned()),
                AuthorityBinding::new(serde_json::to_string(&self.authority)?),
            )
            .context("recovery identity, authority or release pair changed")?;
        Ok(AuthorizedDeployment {
            operation,
            configuration: self.configuration,
            copies: self.copies,
            devices: self.devices,
            storage: self.storage,
            pci: self.pci,
            host: self.host,
            retirements: self.retirements,
            restorations: self.restorations,
            authority: self.authority,
            approval: self.approval,
        })
    }
}

impl AuthorizedDeployment {
    /// Read-only resolution uses the same original definitions later consumed by execution.
    pub(super) fn storage_plan(&self) -> &airlock_deployment_core::storage::StoragePlan {
        &self.storage
    }

    /// Serialize the selected identity; the record is evidence, not an execution token.
    pub(super) fn record(&self) -> Result<DeploymentOperation> {
        Ok(DeploymentOperation {
            id: self.operation.id().as_str().to_owned().try_into()?,
            authority: self.authority.clone(),
        })
    }
}

/// Re-extract immutable operation identities from the journal at every effect request.
pub(super) fn effect_context(
    record: &Record,
) -> Result<airlock_deployment_core::operation::ExecutionContext> {
    let operation = record
        .metadata
        .details
        .operation
        .as_ref()
        .context("missing durable operation")?;
    Ok(airlock_deployment_core::operation::ExecutionContext {
        attempt: AttemptId::new(record.id.as_str().to_owned()),
        operation: OperationId::new(operation.id.as_str().to_owned()),
        authority: AuthorityBinding::new(serde_json::to_string(&operation.authority)?),
        plan: PlanBinding::new(record_plan_binding(record)?),
    })
}

/// Hash decision inputs only: deployment status and timestamps are derived output.
fn decision(approval: &ApprovalRecord) -> Result<ApprovalFingerprint> {
    state::digest(&json!({
        "request_id": approval.request_id,
        "binding": approval.binding,
        "review_fingerprint": approval.review_fingerprint,
        "baseline_state": approval.baseline_state,
        "scope": approval.scope,
    }))?
    .parse()
}

/// Bind the plan to both release snapshots before any journal or status publication.
fn plan_binding(
    release: &Path,
    baseline: &Path,
    fingerprint: &ReleaseFingerprint,
    previous_fingerprint: &ReleaseFingerprint,
    revision: &airlock_nix_core::identity::GitRevision,
    plan: &Plan,
) -> Result<String> {
    state::digest(&json!({
        "release": release, "baseline": baseline,
        "fingerprint": fingerprint, "previous_fingerprint": previous_fingerprint,
        "revision": revision, "plan": plan,
    }))
}

/// Project only immutable execution inputs; phase and outcome observations may change.
pub(super) fn record_plan_binding(record: &Record) -> Result<String> {
    let native = record.metadata.origin.require_native()?;
    plan_binding(
        record.release.as_path(),
        record.previous.as_path(),
        &native.release_fingerprint,
        &native.previous_fingerprint,
        &record.revision,
        &record.plan,
    )
}

/// Retain GUI grouping from the same wire plan used for complete impact projection.
fn gui_plan(plan: &Plan) -> Vec<GuiPreservation> {
    plan.gui_reconnect
        .iter()
        .map(|(provider, clients)| GuiPreservation {
            provider: provider.as_str().to_owned(),
            clients: clients.iter().map(|v| v.as_str().to_owned()).collect(),
        })
        .collect()
}

/// Decode the complete plan without allowing flattened metadata to shadow typed effects.
fn review_plan(plan: &Plan) -> Result<DeploymentPlan> {
    ensure!(
        plan.extra.keys().all(|key| key == "private_copies"),
        "deployment contains unsupported or shadowed effect fields"
    );
    Ok(serde_json::from_value(serde_json::to_value(plan)?)?)
}

/// Pure authorization checks shared by initial publication and every recovery attempt.
fn check_review(
    approval: &ApprovalRecord,
    binding: &ReleaseBinding,
    reviewed: &Release,
    plan: &Plan,
    baseline: Option<&BaselineFingerprint>,
    previous: Option<&Record>,
    plan_binding: PlanBinding,
) -> Result<AuthorizedPlan> {
    let gui = gui_plan(plan);
    let plan = review_plan(plan)?;
    let review = review::Review {
        request: approval.request_id.as_str(),
        revision: approval.binding.revision.as_str(),
        lock: approval.binding.lock_hash.as_str(),
        guest: match &approval.binding.target {
            ReviewTarget::Guest { target } => Some(target.as_str()),
            ReviewTarget::Machine { .. } => None,
        },
        baseline: approval.baseline_state.as_str(),
        fingerprint: approval.review_fingerprint.as_ref().map(|v| v.as_str()),
        status: match approval.status {
            ApprovalStatus::Approved => review::Status::Approved,
            ApprovalStatus::DeploymentStarted => review::Status::Started,
            ApprovalStatus::AwaitingApproval
            | ApprovalStatus::Rejected
            | ApprovalStatus::Cancelled
            | ApprovalStatus::ScopeExceeded => review::Status::Denied,
        },
        release: approval.release.as_ref().map(|v| v.as_str()),
        operation: approval.deployment_operation.as_ref().map(|v| v.as_str()),
        allowed: approval
            .scope
            .allowed_vms()
            .iter()
            .map(|v| v.as_str())
            .collect(),
        allow_reboot: approval.scope.allows_reboot(),
    };
    let bound = review::Binding {
        request: binding.request_id.as_str(),
        release: binding.release.as_str(),
        revision: binding.revision.as_str(),
        lock: binding.lock_hash.as_str(),
    };
    let candidate = review::Identity {
        release: reviewed.path.to_str().context("non-UTF8 release path")?,
        revision: reviewed.manifest.revision.as_str(),
        lock: reviewed.manifest.lock_hash.as_str(),
        guest: reviewed
            .manifest
            .guest_admission
            .as_ref()
            .map(|a| a.domain.as_str()),
        baseline: baseline.map(|v| v.as_str()),
        previous_operation: previous
            .and_then(|r| r.metadata.details.operation.as_ref())
            .map(|o| o.id.as_str()),
    };
    let checked = AuthorizedPlan::reviewed(
        &review,
        &bound,
        &candidate,
        &plan.effects(),
        gui,
        plan_binding,
    );
    checked.map_err(|reason| {
        let message = match reason {
            review::Denial::Unsupported => "deployment contains unclassified effects",
            review::Denial::Candidate => "approved release identity changed",
            review::Denial::Review => "source has no approved review",
            review::Denial::Source => "approval source differs",
            review::Denial::Guest => "guest approval target differs",
            review::Denial::Baseline => "stale_review: deployed baseline changed",
            review::Denial::StartedCandidate => "started approval candidate differs",
            review::Denial::Operation => "approval belongs to another durable operation",
            review::Denial::Scope => {
                // Preserve existing structured RPC diagnostics, but never turn
                // a verified denial into success if the diagnostic code disagrees.
                return approval
                    .scope
                    .check(&plan)
                    .err()
                    .map(anyhow::Error::from)
                    .unwrap_or_else(|| {
                        anyhow::anyhow!("deployment effects exceed approved scope")
                    });
            }
        };
        anyhow::anyhow!(message)
    })
}

impl Coordinator {
    /// Check the applicable review policy, then capture every resource plan before publication.
    pub(super) fn authorize(
        &self,
        release: &Release,
        baseline: &Release,
        plan: &Plan,
        previous: Option<&Record>,
        administrative: bool,
    ) -> Result<CheckedAuthorization> {
        ensure!(
            plan.revision
                .as_ref()
                .is_none_or(|revision| revision == &release.manifest.revision),
            "plan revision differs from deployment target"
        );
        let classified = review_plan(plan)?;
        let recovery = previous
            .map(|previous| -> Result<_> {
                Ok(RecoveryAuthorization {
                    prior: super::recovery::journal(previous)?,
                    release: super::recovery::release(release)?,
                    baseline: super::recovery::release(baseline)?,
                })
            })
            .transpose()?;
        let plan_binding = plan_binding(
            &release.path,
            &baseline.path,
            release.fingerprint(),
            baseline.fingerprint(),
            &release.manifest.revision,
            plan,
        )?;
        let host_definition = super::host::definition(release, previous.is_some())?;
        let service = host_definition.service.clone();

        let (checked_plan, authority, approval) =
            if administrative || !Path::new("/etc/airlock/review-required").try_exists()? {
                let checked_plan = AuthorizedPlan::policy_exempt(
                    &classified.effects(),
                    gui_plan(plan),
                    PlanBinding::new(plan_binding),
                )
                .context("unclassified effects or invalid shutdown preservation plan")?;
                let authority = if administrative {
                    OperationAuthority::Administrative
                } else {
                    OperationAuthority::ReviewNotRequired
                };

                (checked_plan, authority, None)
            } else {
                let (checked_plan, authority, approval) = self.reviewed_authorization(
                    release,
                    baseline,
                    plan,
                    previous,
                    PlanBinding::new(plan_binding),
                )?;

                (checked_plan, authority, Some(approval))
            };

        // Policy exemptions skip human review, never exact resource-plan validation.
        Ok(CheckedAuthorization {
            authority,
            approval,
            retirements: checked_plan
                .retirement(
                    super::retirement::definitions(
                        plan,
                        release,
                        baseline,
                        airlock_deployment_core::retirement::Kind::Retire,
                        &service,
                    )?,
                    airlock_deployment_core::retirement::Kind::Retire,
                )
                .context("retirement definitions differ from checked plan")?,
            restorations: checked_plan
                .retirement(
                    super::retirement::definitions(
                        plan,
                        release,
                        baseline,
                        airlock_deployment_core::retirement::Kind::Restore,
                        &service,
                    )?,
                    airlock_deployment_core::retirement::Kind::Restore,
                )
                .context("restoration definitions differ from checked plan")?,
            devices: checked_plan
                .devices(crate::setup_config::devices::definitions(
                    &release.raw_topology,
                )?)
                .context("device definitions differ from checked configuration scope")?,
            storage: checked_plan
                .storage(crate::setup_config::backend::definitions(
                    &release.raw_topology,
                    &service,
                    &release.manifest.staged_generations,
                )?)
                .context("storage definitions differ from checked configuration scope")?,
            pci: checked_plan.pci_handoff(),
            host: checked_plan.host(host_definition),
            copies: checked_plan
                .copies(super::migration::copy_definitions(plan)?)
                .context("private copy definitions differ from checked plan")?,
            configuration: checked_plan
                .configuration(
                    crate::setup_config::reconcile::definitions(
                        &release.raw_topology,
                        release.manifest.setup.as_str(),
                        &release.path.join("topology.json"),
                    )?,
                    airlock_deployment_core::configuration::Helper {
                        program: release.manifest.setup.as_str().into(),
                        topology: release
                            .path
                            .join("topology.json")
                            .to_str()
                            .context("invalid topology path")?
                            .into(),
                    },
                )
                .context("configuration definitions differ from checked plan")?,
            plan: checked_plan,
            recovery,
        })
    }

    /// Load and validate the protected decision, returning its bound plan and audit authority.
    /// Recovery uses the original reviewed release; fresh review also checks the live baseline.
    fn reviewed_authorization(
        &self,
        release: &Release,
        baseline: &Release,
        plan: &Plan,
        previous: Option<&Record>,
        plan_binding: PlanBinding,
    ) -> Result<(AuthorizedPlan, OperationAuthority, ApprovalRecord)> {
        let recovery_release = previous
            .map(|old| {
                let path = match old
                    .metadata
                    .details
                    .operation
                    .as_ref()
                    .map(|o| &o.authority)
                {
                    Some(OperationAuthority::Reviewed { release, .. }) => release,
                    _ => &old.release,
                };
                Release::load(path.as_path())
            })
            .transpose()?;
        let reviewed = recovery_release.as_ref().unwrap_or(release);
        reviewed.trust()?;

        let digest = Sha256::digest(reviewed.path.as_os_str().as_encoded_bytes());
        let key = format!("{digest:x}");
        let bp = self
            .state
            .join("reviews/bindings")
            .join(format!("{key}.json"));
        state::trusted(&bp).context("activation requires a human-approved source and scope")?;
        let binding: ReleaseBinding = state::read(&bp)?;
        let rp = self.review_path(&binding.request_id);
        state::trusted(&rp)?;
        let approval: ApprovalRecord = state::read(&rp)?;

        let fingerprint: Option<BaselineFingerprint> = if previous.is_none() {
            let fingerprint = state::digest(&json!({
                "selection": self.selection()?,
                "boot_id": state::boot_id()?,
                "host": state::host()?,
                "revision": baseline.manifest.revision,
                "lock_hash": baseline.manifest.lock_hash,
            }))?;
            Some(fingerprint.parse()?)
        } else {
            None
        };
        let checked_plan = check_review(
            &approval,
            &binding,
            reviewed,
            plan,
            fingerprint.as_ref(),
            previous,
            plan_binding,
        )?;

        let authority = OperationAuthority::Reviewed {
            request_id: approval.request_id.clone(),
            decision: decision(&approval)?,
            release: binding.release,
            fingerprint: reviewed.fingerprint().clone(),
        };

        Ok((checked_plan, authority, approval))
    }

    /// Publish the authoritative intent and repairable projections before effects.
    ///
    /// An error may follow a successful rename. Never infer non-publication from
    /// an error: discard the in-memory attempt and recover from latest.json.
    pub(super) fn publish_intent(
        &self,
        record: &Record,
        authorization: AuthorizedDeployment,
    ) -> Result<DurableAuthorization> {
        self.publish_intent_with(record, authorization, &mut |path, value| {
            state::save(path, value)
        })
    }

    fn publish_intent_with(
        &self,
        record: &Record,
        authorization: AuthorizedDeployment,
        save: &mut impl FnMut(&Path, &Value) -> Result<()>,
    ) -> Result<DurableAuthorization> {
        ensure!(
            matches!(
                record.metadata.origin.require_native()?.native_coordinator,
                NativeVersion::V2 | NativeVersion::V3
            ),
            "durable intent requires journal v2 or v3"
        );
        if matches!(
            record.metadata.origin.require_native()?.native_coordinator,
            NativeVersion::V3
        ) {
            super::staging::current_snapshot(record)?;
        }
        let operation = record
            .metadata
            .details
            .operation
            .as_ref()
            .context("missing durable operation")?;
        ensure!(
            operation.authority == authorization.authority,
            "intent authority differs"
        );
        ensure!(
            record.phase == Phase::Preflight,
            "intent must precede activation"
        );
        let mut durable = authorization
            .operation
            .publication(
                &AttemptId::new(record.id.as_str().to_owned()),
                &OperationId::new(operation.id.as_str().to_owned()),
                &AuthorityBinding::new(serde_json::to_string(&operation.authority)?),
                &PlanBinding::new(record_plan_binding(record)?),
                IntentBinding::new(state::digest(&serde_json::to_value(record)?)?),
            )
            .context("authorized operation or plan differs from intent")?;
        self.persist_with(record, save)
            .inspect_err(|_| durable.advance(Event::Interrupted))?;
        durable.advance(Event::IntentSaved);

        if let Some(mut approval) = authorization.approval {
            let OperationAuthority::Reviewed { release, .. } = &operation.authority else {
                bail!("reviewed intent required");
            };
            approval.status = ApprovalStatus::DeploymentStarted;
            approval.release = Some(release.clone());
            approval.started_at.get_or_insert_with(state::now);
            approval.deployment_operation = Some(operation.id.clone());
            save(
                &self.review_path(&approval.request_id),
                &serde_json::to_value(approval)?,
            )
            .inspect_err(|_| durable.advance(Event::Interrupted))?;
        }
        durable.advance(Event::ApprovalSaved);
        Ok(DurableAuthorization {
            operation: durable,
            configuration: authorization.configuration,
            copies: authorization.copies,
            devices: authorization.devices,
            storage: authorization.storage,
            pci: authorization.pci,
            host: authorization.host,
            retirements: authorization.retirements,
            restorations: authorization.restorations,
        })
    }
}

#[cfg(test)]
mod tests;
