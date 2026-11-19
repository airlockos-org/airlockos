//! A source review asks a human to approve a commit before evaluation or building.
//! A later deployment plan must match that source and stay within its effect limits.
//!
//! `ApprovedChange` and `ApprovedDeployment` cannot be deserialized or directly
//! constructed. They prove the checks below ran, not that input came from a
//! trusted GUI, that dom0 granted authority, or that a deployment succeeded.

use crate::{Error, Result, identity::*, wire::string_enum};
use airlock_machine_planning::effects::PlanEffects;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Maximum permitted effects of a source approval.
///
/// VM names are deduplicated and sorted. Scope checking includes both endpoints
/// of private-volume copies and rejects unknown reboot requirements unless allowed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ScopeWire", into = "ScopeWire")]
pub struct Scope {
    /// VM names whose configuration or runtime may be affected by approval.
    allowed_vms: Vec<VmName>,
    /// Whether the approved change may require a later user-initiated reboot.
    allow_reboot: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeWire {
    /// VM names whose configuration or runtime may be affected by approval.
    allowed_vms: Vec<VmName>,
    /// Whether the approved change may require a later user-initiated reboot.
    allow_reboot: bool,
}

impl Scope {
    /// Validate 1–4096 supplied VM names, deduplicate them and record reboot permission.
    pub fn new(allowed_vms: Vec<VmName>, allow_reboot: bool) -> Result<Self> {
        if allowed_vms.is_empty() || allowed_vms.len() > 4096 {
            return Err(Error::InvalidField {
                field: "approval scope",
                expected: "1–4096 VM names",
            });
        }

        Ok(Self {
            allowed_vms: allowed_vms
                .into_iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            allow_reboot,
        })
    }

    /// Return the sorted, unique VM names permitted by this approval.
    pub fn allowed_vms(&self) -> &[VmName] {
        &self.allowed_vms
    }

    /// Return whether this approval permits a change that may require rebooting.
    pub fn allows_reboot(&self) -> bool {
        self.allow_reboot
    }

    /// Reject effects outside the VM set or beyond the recorded reboot permission.
    pub fn check(&self, plan: &DeploymentPlan) -> Result<()> {
        let effects = plan.effects();
        let projection = effects.project().ok_or(Error::InvalidField {
            field: "deployment effects",
            expected: "only classified plan fields",
        })?;
        let outside = projection
            .into_iter()
            .filter(|name| {
                !self
                    .allowed_vms
                    .iter()
                    .any(|allowed| allowed.as_str() == *name)
            })
            .map(str::parse)
            .collect::<Result<BTreeSet<VmName>>>()?
            .into_iter()
            .collect::<Vec<_>>();
        if !outside.is_empty() {
            return Err(Error::ScopeExceeded { names: outside });
        }

        if !self.allow_reboot && effects.requires_reboot_permission() {
            return Err(Error::RebootNotApproved);
        }
        Ok(())
    }
}

impl TryFrom<ScopeWire> for Scope {
    type Error = Error;

    fn try_from(value: ScopeWire) -> Result<Self> {
        Self::new(value.allowed_vms, value.allow_reboot)
    }
}

impl From<Scope> for ScopeWire {
    fn from(value: Scope) -> Self {
        Self {
            allowed_vms: value.allowed_vms,
            allow_reboot: value.allow_reboot,
        }
    }
}

/// Scope of a deployment: the whole machine or one non-dom0 guest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeploymentTarget {
    /// Whole-machine configuration, including dom0 and declared guests.
    Machine,
    /// One guest system update, identified independently from its source commit.
    Guest(
        /// Validated non-dom0 VM targeted by this deployment.
        GuestName,
    ),
}

/// Source plus the operation's machine/guest target. A Git revision alone does
/// not identify a guest candidate: several guests can be built from one commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateIdentity {
    /// Candidate Git commit and dependency-lock digest used as build inputs.
    pub source: SourceIdentity,
    /// Whole-machine or single-guest target, completing the candidate identity.
    pub target: DeploymentTarget,
}

string_enum! {
    /// Supported source-review request format at the GUI boundary.
    pub enum RequestSchema ("approval request schema") {
        /// Version one of this wire record.
        V1 => "airlock.ctrl-approval-request.v1",
    }
}

string_enum! {
    /// Supported human-decision reply format at the GUI boundary.
    pub enum ResponseSchema ("approval response schema") {
        /// Version one of this wire record.
        V1 => "airlock.ctrl-approval-response.v1",
    }
}

string_enum! {
    /// Whether the reviewed work covers the machine or one guest.
    enum Family ("deployment family") {
        /// Work concerns the whole-machine configuration.
        Machine => "machine",
        /// Work concerns a single non-dom0 guest.
        Guest => "guest",
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestWire {
    /// Wire format identifier used to reject unsupported record versions.
    schema: RequestSchema,
    /// Correlation identity used to associate requests, decisions and status replies.
    request_id: ReviewId,
    /// Git commit recorded as the deployed source before this change.
    baseline: GitRevision,
    /// Git commit identifying the candidate source tree.
    revision: GitRevision,
    /// SHA-256 of flake.lock, binding the source to its dependency versions.
    lock_hash: LockHash,
    /// Selects whole-machine work or an operation on one guest.
    family: Family,
    /// Guest target; absent for a whole-machine request.
    target: Option<GuestName>,
    /// Maximum VM impact and reboot permission recorded for this review.
    scope: Scope,
}

/// Source-bound request for human review before evaluation or building.
///
/// Parsing checks the machine/guest target shape, source identities and proposed
/// scope. It does not authenticate the requester or authorize deployment.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "RequestWire", into = "RequestWire")]
pub struct ReviewRequest {
    /// Correlation identity used to associate requests, decisions and status replies.
    request_id: ReviewId,
    /// Git commit recorded as the deployed source before this change.
    baseline: GitRevision,
    /// Source and target being reviewed or prepared for deployment.
    candidate: CandidateIdentity,
    /// Initial effect limits proposed for human review.
    scope: Scope,
}

impl ReviewRequest {
    /// Return the protected review identity used to match a human response.
    pub fn request_id(&self) -> &ReviewId {
        &self.request_id
    }

    /// Return the source commit recorded as deployed when review began.
    pub fn baseline(&self) -> &GitRevision {
        &self.baseline
    }

    /// Return the candidate commit and dependency-lock identity.
    pub fn source(&self) -> &SourceIdentity {
        &self.candidate.source
    }

    /// Return whether the request covers the machine or one named guest.
    pub fn target(&self) -> &DeploymentTarget {
        &self.candidate.target
    }

    /// Return the complete source-and-target identity under review.
    pub fn candidate(&self) -> &CandidateIdentity {
        &self.candidate
    }

    /// Return the initial effect limits proposed for human review.
    pub fn scope(&self) -> &Scope {
        &self.scope
    }
}

impl TryFrom<RequestWire> for ReviewRequest {
    type Error = Error;

    fn try_from(value: RequestWire) -> Result<Self> {
        let target = match (value.family, value.target) {
            (Family::Machine, None) => DeploymentTarget::Machine,
            (Family::Guest, Some(name)) => DeploymentTarget::Guest(name),
            _ => {
                return Err(Error::InvalidField {
                    field: "approval target",
                    expected: "machine with no target, or guest with a VM name",
                });
            }
        };

        Ok(Self {
            request_id: value.request_id,
            baseline: value.baseline,
            candidate: CandidateIdentity {
                source: SourceIdentity {
                    revision: value.revision,
                    lock_hash: value.lock_hash,
                },
                target,
            },
            scope: value.scope,
        })
    }
}

impl From<ReviewRequest> for RequestWire {
    fn from(value: ReviewRequest) -> Self {
        let (family, target) = match value.candidate.target {
            DeploymentTarget::Machine => (Family::Machine, None),
            DeploymentTarget::Guest(name) => (Family::Guest, Some(name)),
        };

        Self {
            schema: RequestSchema::V1,
            request_id: value.request_id,
            baseline: value.baseline,
            revision: value.candidate.source.revision,
            lock_hash: value.candidate.source.lock_hash,
            family,
            target,
            scope: value.scope,
        }
    }
}

string_enum! {
    /// Human choice returned from the review window, independent of work completion.
    pub enum Decision ("human decision") {
        /// Approve the source and reviewed scope for subsequent work.
        Approve => "approve",
        /// Decline the reviewed change.
        Reject => "reject",
        /// Review ended without an approval decision.
        Cancelled => "cancelled",
    }
}

/// An unauthenticated wire reply, including rejections and cancellation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewResponse {
    /// Wire format identifier used to reject unsupported record versions.
    pub schema: ResponseSchema,
    /// Correlation identity used to associate requests, decisions and status replies.
    pub request_id: ReviewId,
    /// Git commit identifying the candidate source tree.
    pub revision: GitRevision,
    /// SHA-256 of flake.lock, binding the source to its dependency versions.
    pub lock_hash: LockHash,
    /// Digest of the complete material presented for human review.
    pub review_fingerprint: ReviewFingerprint,
    /// Human choice returned by the review window, distinct from deployment success.
    pub decision: Decision,
    /// Maximum VM impact and reboot permission recorded for this review.
    pub scope: Scope,
}

/// The caller must obtain these observations from the authoritative source and
/// deployed baseline. A candidate's parent commit is not a deployed baseline.
#[derive(Clone, Debug)]
pub struct ReviewObservation {
    /// Git commit recorded as the deployed source before this change.
    pub baseline: GitRevision,
    /// Fingerprint of the deployed selection, used to detect a stale review.
    pub baseline_state: BaselineFingerprint,
    /// Source and target independently observed at the authority boundary.
    pub candidate: CandidateIdentity,
}

/// Review request paired with the baseline state observed before a human decision.
///
/// Consume it with [`Self::decide`] to check the response exactly once.
#[derive(Debug)]
pub struct PendingReview {
    /// Original source-bound request retained to check the response.
    request: ReviewRequest,
    /// Fingerprint of the deployed selection, used to detect a stale review.
    baseline_state: BaselineFingerprint,
}

/// Checked human decision; only approval carries a source-and-scope binding.
#[derive(Debug)]
pub enum ReviewOutcome {
    /// Approval passed the request, candidate and current-baseline checks.
    Approved(
        /// Checked source/scope binding; it grants no deployment authority by itself.
        Box<ApprovedChange>,
    ),
    /// The human declined the change; no checked approval is produced.
    Rejected,
    /// The review ended without a decision to deploy.
    Cancelled,
}

impl PendingReview {
    /// Reject mismatched source or target observations and capture the deployed baseline.
    pub fn new(request: ReviewRequest, observed: &ReviewObservation) -> Result<Self> {
        if request.baseline != observed.baseline || request.candidate != observed.candidate {
            return Err(Error::BindingMismatch {
                field: "reviewed source, target or deployed baseline",
            });
        }

        Ok(Self {
            request,
            baseline_state: observed.baseline_state.clone(),
        })
    }

    /// Consume the pending review exactly once. Only approval produces a checked
    /// change. The human may edit scope in the GUI, as in the current protocol.
    pub fn decide(
        self,
        response: ReviewResponse,
        current: &ReviewObservation,
    ) -> Result<ReviewOutcome> {
        if response.request_id != self.request.request_id {
            return Err(Error::BindingMismatch {
                field: "review request ID",
            });
        }
        if response.revision != self.request.candidate.source.revision
            || response.lock_hash != self.request.candidate.source.lock_hash
        {
            return Err(Error::BindingMismatch {
                field: "review response source",
            });
        }

        match response.decision {
            Decision::Reject => Ok(ReviewOutcome::Rejected),
            Decision::Cancelled => Ok(ReviewOutcome::Cancelled),
            Decision::Approve => {
                let approved = ApprovedChange {
                    request: self.request,
                    baseline_state: self.baseline_state,
                    fingerprint: response.review_fingerprint,
                    scope: response.scope,
                };
                approved.recheck(current)?;
                Ok(ReviewOutcome::Approved(Box::new(approved)))
            }
        }
    }
}

/// Source approval checked against a matching request and observed deployed state.
///
/// Use [`Self::recheck`] before work and [`Self::bind_plan`] after planning. This
/// value proves local consistency checks ran; dom0 still controls actual authority.
#[derive(Debug)]
pub struct ApprovedChange {
    /// Original source-bound request retained to check the response.
    request: ReviewRequest,
    /// Fingerprint of the deployed selection, used to detect a stale review.
    baseline_state: BaselineFingerprint,
    /// Digest returned with the approved review material.
    fingerprint: ReviewFingerprint,
    /// Final effect limits accepted by the human reviewer.
    scope: Scope,
}

impl ApprovedChange {
    /// Return the original source-bound request that passed the response checks.
    pub fn request(&self) -> &ReviewRequest {
        &self.request
    }

    /// Return the final impact limits accepted by the human reviewer.
    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    /// Return the digest binding the response to the reviewed material.
    pub fn fingerprint(&self) -> &ReviewFingerprint {
        &self.fingerprint
    }

    /// Reject a changed deployed baseline or a different candidate source/target.
    ///
    /// Call immediately before evaluation, building or activation.
    pub fn recheck(&self, current: &ReviewObservation) -> Result<()> {
        if self.baseline_state != current.baseline_state
            || self.request.baseline != current.baseline
        {
            return Err(Error::StaleReview);
        }

        if self.request.candidate != current.candidate {
            return Err(Error::BindingMismatch {
                field: "current candidate source or target",
            });
        }
        Ok(())
    }

    /// Consume this approval and reject a plan with different inputs or excess effects.
    ///
    /// The current deployed baseline is rechecked before producing the binding.
    pub fn bind_plan(
        self,
        current: &ReviewObservation,
        prepared: PreparedPlan,
    ) -> Result<ApprovedDeployment> {
        self.recheck(current)?;
        if prepared.candidate != self.request.candidate {
            return Err(Error::BindingMismatch {
                field: "deployment plan source or target",
            });
        }

        self.scope.check(&prepared.plan)?;

        Ok(ApprovedDeployment {
            approval: self,
            prepared,
        })
    }
}

/// A checked source/scope/plan relationship. It grants no runtime authority and
/// says nothing about build completion, activation, or reboot completion.
#[derive(Debug)]
pub struct ApprovedDeployment {
    /// Checked source approval whose impact limits this deployment.
    approval: ApprovedChange,
    /// Candidate-bound plan checked against the approved scope.
    prepared: PreparedPlan,
}

impl ApprovedDeployment {
    /// Borrow the source approval whose scope was checked against this plan.
    pub fn approval(&self) -> &ApprovedChange {
        &self.approval
    }

    /// Borrow the deployment effects that passed the approval scope checks.
    pub fn plan(&self) -> &DeploymentPlan {
        &self.prepared.plan
    }

    /// Return the source and target whose plan passed the approval checks.
    pub fn candidate(&self) -> &CandidateIdentity {
        &self.prepared.candidate
    }
}

/// A plan paired with the complete candidate identity obtained by its producer.
/// Runtime adapters must obtain that identity from the actual build manifest;
/// this value does not authenticate the producer or grant deployment authority.
#[derive(Debug)]
pub struct PreparedPlan {
    /// Source and target being reviewed or prepared for deployment.
    candidate: CandidateIdentity,
    /// VM impact and reboot requirements computed for this candidate.
    plan: DeploymentPlan,
}

impl PreparedPlan {
    /// Reject a plan with a missing/different revision or a conflicting lock hash.
    ///
    /// An absent plan lock hash is accepted; the supplied candidate still records it.
    pub fn new(candidate: CandidateIdentity, plan: DeploymentPlan) -> Result<Self> {
        if plan.revision.as_ref() != Some(&candidate.source.revision)
            || plan
                .lock_hash
                .as_ref()
                .is_some_and(|hash| hash != &candidate.source.lock_hash)
        {
            return Err(Error::BindingMismatch {
                field: "deployment plan source",
            });
        }

        Ok(Self { candidate, plan })
    }

    /// Return the producer-supplied complete identity paired with this plan.
    pub fn candidate(&self) -> &CandidateIdentity {
        &self.candidate
    }

    /// Borrow the effects supplied by the plan producer; this does not authenticate them.
    pub fn plan(&self) -> &DeploymentPlan {
        &self.plan
    }
}

/// Knowledge of whether activating the selected host system requires a later reboot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebootRequirement {
    /// The plan did not establish whether a reboot is needed.
    Unknown,
    /// The plan explicitly requires a host reboot.
    Required,
    /// The plan explicitly reports no host reboot requirement.
    NotRequired,
}

/// Complete classified deployment impact, including copy, GUI and PCI endpoints.
/// Shared by planning, review, activation and the durable deployment journal.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentPlan {
    /// VMs explicitly reconciled by the configuration executor.
    #[serde(default)]
    pub configure: Vec<GuestName>,
    /// Git commit identifying the candidate source tree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<GitRevision>,
    /// SHA-256 of flake.lock, binding the source to its dependency versions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock_hash: Option<LockHash>,
    /// VMs whose declared configuration differs from the baseline.
    pub changed: Vec<GuestName>,
    /// VMs to stop before applying the configuration.
    pub stop: Vec<GuestName>,
    /// VMs to start after applying the configuration.
    pub start: Vec<GuestName>,
    /// VMs to remove from active configuration while retaining recoverable data.
    #[serde(default)]
    pub retire: Vec<GuestName>,
    /// Previously retired VMs to restore to active configuration.
    #[serde(default)]
    pub restore: Vec<GuestName>,
    /// VMs whose new system generations must be prepared before activation.
    #[serde(default)]
    pub stage: Vec<GuestName>,
    /// Additional VM impact explicitly reported by the plan producer.
    #[serde(default)]
    pub affected: Vec<GuestName>,
    /// Private-volume transfers whose source and destination both count as impact.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub private_copies: Vec<PrivateCopy>,
    /// GUI providers and surviving clients affected by a forced provider restart.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub gui_reconnect: BTreeMap<GuestName, Vec<GuestName>>,
    /// Device ownership changes count at both the previous and new VM.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pci_handoff: Option<PciHandoff>,
    /// Retained declarations are informational; this field requests no VM operation.
    #[serde(default)]
    pub retained_undeclared: Vec<GuestName>,
    /// Whether the selected host differs enough to need a reboot.
    pub host_reboot_required: Option<bool>,
    /// Changes to reviewed startup settings, indexed by their affected firewall VM.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub firewall_parameters: BTreeMap<GuestName, FirewallParameterChange>,
}

impl Default for DeploymentPlan {
    fn default() -> Self {
        Self {
            configure: Vec::new(),
            revision: None,
            lock_hash: None,
            changed: Vec::new(),
            stop: Vec::new(),
            start: Vec::new(),
            retire: Vec::new(),
            restore: Vec::new(),
            stage: Vec::new(),
            affected: Vec::new(),
            private_copies: Vec::new(),
            gui_reconnect: BTreeMap::new(),
            pci_handoff: None,
            retained_undeclared: Vec::new(),
            host_reboot_required: Some(false),
            firewall_parameters: BTreeMap::new(),
        }
    }
}

/// When a reviewed firewall parameter selection becomes effective.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FirewallParameterActivation {
    /// The firewall reads the selected settings when it starts.
    NextVmStart,
}

/// Reviewed before and after settings for one firewall VM.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallParameterChange {
    /// Previous explicit settings, if the old declaration supplied them.
    pub before: Option<airlock_firewall_parameters::Limits>,
    /// New explicit settings, if the new declaration supplies them.
    pub after: Option<airlock_firewall_parameters::Limits>,
    /// The lifecycle point at which the new settings take effect.
    pub activation: FirewallParameterActivation,
    /// Whether the observed VM must restart to select the new settings.
    pub restart_required: bool,
    /// Whether the candidate retains the old executable backend.
    pub executable_unchanged: bool,
    /// Immutable executable selected by the new declaration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<crate::store_path::StoreFile>,
}

/// PCI ownership transfer, with no implicit or unclassified extra operations.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PciHandoff {
    /// Previous owner of the transferred hardware.
    pub from: GuestName,
    /// New owner of the transferred hardware.
    pub to: GuestName,
}

/// Private-data transfer between VMs, counted at both ends during scope checking.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateCopy {
    /// Private volume whose contents will seed the target VM.
    source: PrivateCopySource,
    /// Destination VM receiving the private-volume contents.
    target_name: VmName,
    /// Additional record metadata retained without treating it as authority.
    #[serde(flatten)]
    details: BTreeMap<String, serde_json::Value>,
}

/// Source VM and additional storage metadata for a private-volume transfer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateCopySource {
    /// Source VM whose private-volume contents will be copied.
    domain: VmName,
    /// Additional record metadata retained without treating it as authority.
    #[serde(flatten)]
    details: BTreeMap<String, serde_json::Value>,
}

impl PrivateCopy {
    /// Borrow the source private-volume description.
    pub fn source(&self) -> &PrivateCopySource {
        &self.source
    }

    /// Return the VM that will receive the copied private data.
    pub fn target_name(&self) -> &VmName {
        &self.target_name
    }

    /// Borrow unmodeled plan metadata without interpreting it as authority.
    pub fn details(&self) -> &BTreeMap<String, serde_json::Value> {
        &self.details
    }
}

impl PrivateCopySource {
    /// Return the VM whose private data supplies the copy.
    pub fn domain(&self) -> &VmName {
        &self.domain
    }

    /// Borrow unmodeled plan metadata without interpreting it as authority.
    pub fn details(&self) -> &BTreeMap<String, serde_json::Value> {
        &self.details
    }
}

impl DeploymentPlan {
    /// Return the source revision reported by the producer, if supplied.
    pub fn revision(&self) -> Option<&GitRevision> {
        self.revision.as_ref()
    }

    /// Return the dependency-lock digest reported by the producer, if supplied.
    pub fn lock_hash(&self) -> Option<&LockHash> {
        self.lock_hash.as_ref()
    }

    /// Return VMs whose declared configuration changed.
    pub fn changed(&self) -> &[GuestName] {
        &self.changed
    }

    /// Return VMs the plan intends to stop before configuration.
    pub fn stop(&self) -> &[GuestName] {
        &self.stop
    }

    /// Return VMs the plan intends to start after configuration.
    pub fn start(&self) -> &[GuestName] {
        &self.start
    }

    /// Return VMs to remove from active configuration while retaining their data.
    pub fn retire(&self) -> &[GuestName] {
        &self.retire
    }

    /// Return previously retired VMs to restore.
    pub fn restore(&self) -> &[GuestName] {
        &self.restore
    }

    /// Return VMs whose new system generations must be prepared.
    pub fn stage(&self) -> &[GuestName] {
        &self.stage
    }

    /// Return additional VM impact explicitly reported by the producer.
    pub fn affected(&self) -> &[GuestName] {
        &self.affected
    }

    /// Return private-volume transfers; both endpoints count as affected.
    pub fn private_copies(&self) -> &[PrivateCopy] {
        &self.private_copies
    }

    /// Classify every wire field before the verified projection is evaluated.
    /// Exhaustive destructuring makes additions to this wire type require a decision.
    /// Storage identities and receipts describe the named copy, not additional VM effects.
    pub fn effects(&self) -> PlanEffects<'_> {
        let Self {
            configure,
            revision: _,
            lock_hash: _,
            changed,
            stop,
            start,
            retire,
            restore,
            stage,
            affected,
            private_copies,
            gui_reconnect,
            pci_handoff,
            retained_undeclared: _,
            host_reboot_required,
            firewall_parameters,
        } = self;
        // Borrow typed names without changing their identities at the proof boundary.
        fn names(values: &[GuestName]) -> Vec<&str> {
            values.iter().map(GuestName::as_str).collect()
        }

        let mut unknown = Vec::new();
        for PrivateCopy {
            source,
            target_name: _,
            details,
        } in private_copies
        {
            let PrivateCopySource {
                domain: _,
                details: source_details,
            } = source;
            unknown.extend(
                details
                    .keys()
                    .filter(|key| !matches!(key.as_str(), "target_config" | "target" | "status"))
                    .map(String::as_str),
            );
            unknown.extend(
                source_details
                    .keys()
                    .filter(|key| !matches!(key.as_str(), "uuid" | "pool" | "vid"))
                    .map(String::as_str),
            );
        }

        PlanEffects {
            configure: names(configure),
            changed: names(changed),
            stage: names(stage),
            stop: names(stop),
            start: names(start),
            affected: names(affected),
            retire: names(retire),
            restore: names(restore),
            copy_sources: private_copies
                .iter()
                .map(|copy| copy.source.domain.as_str())
                .collect(),
            copy_targets: private_copies
                .iter()
                .map(|copy| copy.target_name.as_str())
                .collect(),
            gui_providers: gui_reconnect.keys().map(GuestName::as_str).collect(),
            gui_clients: gui_reconnect
                .values()
                .flatten()
                .map(GuestName::as_str)
                .collect(),
            pci_sources: pci_handoff
                .iter()
                .map(|PciHandoff { from, to: _ }| from)
                .map(GuestName::as_str)
                .collect(),
            pci_targets: pci_handoff
                .iter()
                .map(|PciHandoff { from: _, to }| to)
                .map(GuestName::as_str)
                .collect(),
            firewall_parameters: firewall_parameters.keys().map(GuestName::as_str).collect(),
            unknown,
            reboot: *host_reboot_required,
        }
    }

    /// Return the sorted union of all known VM effects, including copy endpoints.
    pub fn affected_vms(&self) -> BTreeSet<&VmName> {
        let mut names = [
            &self.configure,
            &self.changed,
            &self.stop,
            &self.start,
            &self.retire,
            &self.restore,
            &self.stage,
            &self.affected,
        ]
        .into_iter()
        .flatten()
        .map(GuestName::as_vm_name)
        .collect::<BTreeSet<_>>();
        for copy in &self.private_copies {
            names.insert(&copy.source.domain);
            names.insert(&copy.target_name);
        }
        for (provider, clients) in &self.gui_reconnect {
            names.insert(provider.as_vm_name());
            names.extend(clients.iter().map(GuestName::as_vm_name));
        }

        if let Some(handoff) = &self.pci_handoff {
            names.insert(handoff.from.as_vm_name());
            names.insert(handoff.to.as_vm_name());
        }
        names.extend(self.firewall_parameters.keys().map(GuestName::as_vm_name));
        names
    }

    /// Return the explicit reboot requirement, preserving unknown as a distinct result.
    pub fn reboot_requirement(&self) -> RebootRequirement {
        match self.host_reboot_required {
            Some(true) => RebootRequirement::Required,
            Some(false) => RebootRequirement::NotRequired,
            None => RebootRequirement::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Both ends of a device transfer consume VM scope, even without lifecycle actions.
    #[test]
    fn pci_handoff_requires_both_endpoints() {
        let plan: DeploymentPlan = serde_json::from_value(json!({
            "changed": [], "stop": [], "start": [], "host_reboot_required": false,
            "pci_handoff": {"from": "usr-assistant", "to": "sys-net"}
        }))
        .unwrap();
        let scope = Scope::new(vec!["usr-assistant".parse().unwrap()], false).unwrap();
        assert!(matches!(
            scope.check(&plan),
            Err(Error::ScopeExceeded { .. })
        ));
    }

    /// Wire interpretation supplies every field to the shared verified projection.
    #[test]
    fn complete_wire_projection_and_informational_metadata() {
        let plan: DeploymentPlan = serde_json::from_value(json!({
            "changed": ["usr-changed"], "stage": ["usr-stage"],
            "stop": ["usr-stop"], "start": ["usr-start"], "affected": ["usr-affected"],
            "retire": ["usr-retire"], "restore": ["usr-restore"],
            "private_copies": [{"source": {"domain": "usr-source"}, "target_name": "usr-target"}],
            "gui_reconnect": {"sys-gui": ["usr-client"]},
            "pci_handoff": {"from": "usr-pci-from", "to": "usr-pci-to"},
            "retained_undeclared": ["usr-untouched"], "host_reboot_required": false
        }))
        .unwrap();
        let expected = [
            "usr-changed",
            "usr-stage",
            "usr-stop",
            "usr-start",
            "usr-affected",
            "usr-retire",
            "usr-restore",
            "usr-source",
            "usr-target",
            "sys-gui",
            "usr-client",
            "usr-pci-from",
            "usr-pci-to",
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        let effects = plan.effects();
        assert_eq!(
            effects
                .project()
                .unwrap()
                .into_iter()
                .collect::<BTreeSet<_>>(),
            expected
        );
        let scope = Scope::new(
            expected.iter().map(|name| name.parse().unwrap()).collect(),
            false,
        )
        .unwrap();
        scope.check(&plan).unwrap();
        assert_eq!(
            plan.affected_vms()
                .into_iter()
                .map(VmName::as_str)
                .collect::<BTreeSet<_>>(),
            expected
        );
    }

    /// Unknown fields cannot become silently ignored future privileged operations.
    #[test]
    fn unknown_and_malformed_effect_extensions_are_rejected() {
        let base = json!({"changed": [], "stop": [], "start": [], "host_reboot_required": false});
        let scope = Scope::new(vec!["usr-home".parse().unwrap()], false).unwrap();
        for (field, value) in [
            (
                "private_copies",
                json!([{"source": {"domain": "usr-home"}, "target_name": "usr-home", "future_effect": "sys-net"}]),
            ),
            (
                "private_copies",
                json!([{"source": {"domain": "usr-home", "future_effect": "sys-net"}, "target_name": "usr-home"}]),
            ),
        ] {
            let mut raw = base.clone();
            raw[field] = value;
            let plan: DeploymentPlan = serde_json::from_value(raw).unwrap();
            assert!(scope.check(&plan).is_err(), "unclassified {field}");
        }
        let mut unknown = base.clone();
        unknown["future_effect"] = json!({"vm": "sys-net"});
        assert!(serde_json::from_value::<DeploymentPlan>(unknown).is_err());
        for value in [
            json!({"from": "usr-home"}),
            json!({"from": null, "to": "usr-home"}),
            json!({"from": "usr-home", "to": "usr-home", "extra": true}),
            json!("unknown"),
        ] {
            let mut raw = base.clone();
            raw["pci_handoff"] = value;
            assert!(serde_json::from_value::<DeploymentPlan>(raw).is_err());
        }
    }
}
