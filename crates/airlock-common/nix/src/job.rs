//! Controller observations. Reading a snapshot never grants authority, advances
//! a job, probes a VM, or overwrites the worker's record.

use crate::{
    Error, Result,
    identity::{JobId, ReviewId},
    wire::string_enum,
};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use std::collections::BTreeMap;

string_enum! {
    /// Observable controller worker phase; approval is recorded separately.
    pub enum JobStatus ("controller job status") {
        /// Accepted but not yet awaiting a human decision.
        Queued => "queued",
        /// The source review is waiting for the human reviewer.
        AwaitingApproval => "awaiting_approval",
        /// Approved work is evaluating, building or preparing its artifacts.
        Building => "building",
        /// Planning completed; activation has not been requested by this outcome.
        Planned => "planned",
        /// The requested artifacts were built; this does not imply activation.
        Built => "built",
        /// Work was handed to the deployment worker; follow deployment status.
        DeploymentStarted => "deployment_started",
        /// The human declined the requested change.
        Rejected => "rejected",
        /// Review ended without an approval decision.
        Cancelled => "cancelled",
        /// Computed effects exceeded the recorded approval limits.
        ScopeExceeded => "scope_exceeded",
        /// Deployed state changed after the source review began.
        StaleReview => "stale_review",
        /// The operation failed; consult the saved diagnostic context.
        Failed => "failed",
    }
}

impl JobStatus {
    /// Return whether the submission is queued, awaiting review or still building.
    ///
    /// `false` does not prove activation succeeded; deployment monitoring is separate.
    pub fn is_active(self) -> bool {
        match self {
            Self::Queued | Self::AwaitingApproval | Self::Building => true,
            Self::Planned
            | Self::Built
            | Self::DeploymentStarted
            | Self::Rejected
            | Self::Cancelled
            | Self::ScopeExceeded
            | Self::StaleReview
            | Self::Failed => false,
        }
    }
}

string_enum! {
    /// Worker phases before a human decision is available.
    pub enum PendingStatus ("pending job status") {
        /// Accepted but not yet awaiting a human decision.
        Queued => "queued",
        /// The source review is waiting for the human reviewer.
        AwaitingApproval => "awaiting_approval",
    }
}

string_enum! {
    /// Worker phases reachable after durable human approval.
    pub enum ApprovedStatus ("approved job status") {
        /// Approved work is evaluating, building or preparing its artifacts.
        Building => "building",
        /// Planning completed; activation has not been requested by this outcome.
        Planned => "planned",
        /// The requested artifacts were built; this does not imply activation.
        Built => "built",
        /// Work was handed to the deployment worker; follow deployment status.
        DeploymentStarted => "deployment_started",
        /// Computed effects exceeded the recorded approval limits.
        ScopeExceeded => "scope_exceeded",
        /// Deployed state changed after the source review began.
        StaleReview => "stale_review",
        /// The operation failed; consult the saved diagnostic context.
        Failed => "failed",
    }
}

string_enum! {
    /// Terminal reason a request stopped, suitable for submission feedback.
    pub enum StopReason ("stopped job status") {
        /// The human declined the requested change.
        Rejected => "rejected",
        /// Review ended without an approval decision.
        Cancelled => "cancelled",
        /// Computed effects exceeded the recorded approval limits.
        ScopeExceeded => "scope_exceeded",
        /// Deployed state changed after the source review began.
        StaleReview => "stale_review",
        /// The operation failed; consult the saved diagnostic context.
        Failed => "failed",
    }
}

impl From<PendingStatus> for JobStatus {
    fn from(value: PendingStatus) -> Self {
        match value {
            PendingStatus::Queued => Self::Queued,
            PendingStatus::AwaitingApproval => Self::AwaitingApproval,
        }
    }
}

impl From<ApprovedStatus> for JobStatus {
    fn from(value: ApprovedStatus) -> Self {
        match value {
            ApprovedStatus::Building => Self::Building,
            ApprovedStatus::Planned => Self::Planned,
            ApprovedStatus::Built => Self::Built,
            ApprovedStatus::DeploymentStarted => Self::DeploymentStarted,
            ApprovedStatus::ScopeExceeded => Self::ScopeExceeded,
            ApprovedStatus::StaleReview => Self::StaleReview,
            ApprovedStatus::Failed => Self::Failed,
        }
    }
}

impl From<StopReason> for JobStatus {
    fn from(value: StopReason) -> Self {
        match value {
            StopReason::Rejected => Self::Rejected,
            StopReason::Cancelled => Self::Cancelled,
            StopReason::ScopeExceeded => Self::ScopeExceeded,
            StopReason::StaleReview => Self::StaleReview,
            StopReason::Failed => Self::Failed,
        }
    }
}

impl StopReason {
    /// Return the submission exit status for rejection, cancellation or failure.
    pub fn exit_code(self) -> u8 {
        match self {
            Self::Rejected => 20,
            Self::Cancelled => 21,
            Self::ScopeExceeded => 22,
            Self::StaleReview => 23,
            Self::Failed => 1,
        }
    }
}

impl TryFrom<JobStatus> for StopReason {
    type Error = Error;

    fn try_from(status: JobStatus) -> Result<Self> {
        match status {
            JobStatus::Rejected => Ok(Self::Rejected),
            JobStatus::Cancelled => Ok(Self::Cancelled),
            JobStatus::ScopeExceeded => Ok(Self::ScopeExceeded),
            JobStatus::StaleReview => Ok(Self::StaleReview),
            JobStatus::Failed => Ok(Self::Failed),
            JobStatus::Queued
            | JobStatus::AwaitingApproval
            | JobStatus::Building
            | JobStatus::Planned
            | JobStatus::Built
            | JobStatus::DeploymentStarted => Err(Error::InvalidJob {
                reason: "job status does not describe a stopped request",
            }),
        }
    }
}

string_enum! {
    /// Durable approval marker retained after subsequent work succeeds or fails.
    pub enum StoredDecision ("stored decision") {
        /// The human approved the reviewed source and impact scope.
        Approved => "approved",
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct JobWire {
    /// Correlation identity used to associate requests, decisions and status replies.
    request_id: JobId,
    /// Persisted worker phase, validated together with the approval decision.
    status: JobStatus,
    /// Durable human approval, preserved even if later work fails.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    decision: Option<StoredDecision>,
    /// Protected source-review identity, when one has been allocated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authorization_id: Option<ReviewId>,
    // Request/result extensions remain untrusted observations, not executable
    // intents or evidence that the supplied source was actually authorized.
    #[serde(flatten)]
    details: BTreeMap<String, serde_json::Value>,
}

// A recorded approval always carries its authorization ID and a post-approval
// phase. Pending and stopped jobs cannot accidentally acquire that decision.
#[derive(Clone, Debug, PartialEq, Eq)]
enum JobState {
    Queued {
        /// Protected source-review identity, when one has been allocated.
        authorization_id: Option<ReviewId>,
    },
    AwaitingApproval {
        /// Protected source-review identity, when one has been allocated.
        authorization_id: ReviewId,
    },
    Approved {
        /// Protected source-review identity, when one has been allocated.
        authorization_id: ReviewId,
        /// Post-approval worker phase, distinct from the durable human decision.
        status: ApprovedStatus,
    },
    Stopped {
        /// Protected source-review identity, when one has been allocated.
        authorization_id: Option<ReviewId>,
        /// Terminal reason retained when no durable approved state was reached.
        reason: StopReason,
    },
}

/// Read-only worker record whose approval decision remains visible after work ends.
/// Equality includes request identity, validated worker state and all retained details.
///
/// Deserialize saved job JSON to inspect feedback; parsing does not grant authority
/// or resume a worker. Invalid phase/decision combinations are rejected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "JobWire", into = "JobWire")]
pub struct JobSnapshot {
    /// Correlation identity used to associate requests, decisions and status replies.
    request_id: JobId,
    /// Validated relationship between worker phase and recorded approval.
    state: JobState,
    /// Additional record metadata retained without treating it as authority.
    details: BTreeMap<String, serde_json::Value>,
}

impl TryFrom<JobWire> for JobSnapshot {
    type Error = Error;

    fn try_from(value: JobWire) -> Result<Self> {
        let state = match value.decision {
            Some(StoredDecision::Approved) => {
                let authorization_id = value.authorization_id.ok_or(Error::InvalidJob {
                    reason: "approved decision is missing its authorization ID",
                })?;

                let status = match value.status {
                    JobStatus::Building => ApprovedStatus::Building,
                    JobStatus::Planned => ApprovedStatus::Planned,
                    JobStatus::Built => ApprovedStatus::Built,
                    JobStatus::DeploymentStarted => ApprovedStatus::DeploymentStarted,
                    JobStatus::ScopeExceeded => ApprovedStatus::ScopeExceeded,
                    JobStatus::StaleReview => ApprovedStatus::StaleReview,
                    JobStatus::Failed => ApprovedStatus::Failed,
                    JobStatus::Queued
                    | JobStatus::AwaitingApproval
                    | JobStatus::Rejected
                    | JobStatus::Cancelled => {
                        return Err(Error::InvalidJob {
                            reason: "approval decision conflicts with job status",
                        });
                    }
                };

                JobState::Approved {
                    authorization_id,
                    status,
                }
            }
            None => match value.status {
                JobStatus::Queued => JobState::Queued {
                    authorization_id: value.authorization_id,
                },
                JobStatus::AwaitingApproval => JobState::AwaitingApproval {
                    authorization_id: value.authorization_id.ok_or(Error::InvalidJob {
                        reason: "awaiting approval is missing its authorization ID",
                    })?,
                },
                JobStatus::Building
                | JobStatus::Planned
                | JobStatus::Built
                | JobStatus::DeploymentStarted => {
                    return Err(Error::InvalidJob {
                        reason: "work started without a recorded approval decision",
                    });
                }
                status @ (JobStatus::Rejected
                | JobStatus::Cancelled
                | JobStatus::ScopeExceeded
                | JobStatus::StaleReview
                | JobStatus::Failed) => {
                    let reason = StopReason::try_from(status)?;
                    JobState::Stopped {
                        authorization_id: value.authorization_id,
                        reason,
                    }
                }
            },
        };

        Ok(Self {
            request_id: value.request_id,
            state,
            details: value.details,
        })
    }
}

impl From<JobSnapshot> for JobWire {
    fn from(value: JobSnapshot) -> Self {
        let (status, decision, authorization_id) = match value.state {
            JobState::Queued { authorization_id } => (JobStatus::Queued, None, authorization_id),
            JobState::AwaitingApproval { authorization_id } => {
                (JobStatus::AwaitingApproval, None, Some(authorization_id))
            }
            JobState::Approved {
                authorization_id,
                status,
            } => (
                status.into(),
                Some(StoredDecision::Approved),
                Some(authorization_id),
            ),
            JobState::Stopped {
                authorization_id,
                reason,
            } => (reason.into(), None, authorization_id),
        };

        Self {
            request_id: value.request_id,
            status,
            decision,
            authorization_id,
            details: value.details,
        }
    }
}

impl JobSnapshot {
    // Writers can construct and transition records without bypassing model
    // invariants. Protected dom0 authority must still be checked by the caller.
    /// Create a queued record without a review identity or approval decision.
    #[cfg(feature = "job-writer")]
    pub fn queued(request_id: JobId) -> Self {
        Self {
            request_id,
            state: JobState::Queued {
                authorization_id: None,
            },
            details: BTreeMap::new(),
        }
    }

    /// Move a queued record into review, rejecting any already-started state.
    #[cfg(feature = "job-writer")]
    pub fn awaiting(&mut self, authorization_id: ReviewId) -> Result<()> {
        if !matches!(self.state, JobState::Queued { .. }) {
            return Err(Error::InvalidJob {
                reason: "only a queued job can start review",
            });
        }

        self.state = JobState::AwaitingApproval { authorization_id };
        Ok(())
    }

    /// Record approval only for the pending review identity and enter the building phase.
    ///
    /// The caller must independently authenticate the protected dom0 decision.
    #[cfg(feature = "job-writer")]
    pub fn approved(&mut self, authorization_id: &ReviewId) -> Result<()> {
        if !matches!(&self.state, JobState::AwaitingApproval { authorization_id: id } if id == authorization_id)
        {
            return Err(Error::InvalidJob {
                reason: "approval differs from the pending review",
            });
        }

        self.state = JobState::Approved {
            authorization_id: authorization_id.clone(),
            status: ApprovedStatus::Building,
        };
        Ok(())
    }

    /// Finish approved building work, rejecting unapproved or already-finished records.
    #[cfg(feature = "job-writer")]
    pub fn finish(&mut self, status: ApprovedStatus) -> Result<()> {
        let JobState::Approved {
            status: current, ..
        } = &mut self.state
        else {
            return Err(Error::InvalidJob {
                reason: "work cannot finish without recorded approval",
            });
        };
        if *current != ApprovedStatus::Building {
            return Err(Error::InvalidJob {
                reason: "job has already finished",
            });
        }

        *current = status;
        Ok(())
    }

    /// Record a terminal failure or pre-approval stop while preserving any durable approval.
    #[cfg(feature = "job-writer")]
    pub fn stop(&mut self, reason: StopReason) -> Result<()> {
        if let JobState::Approved { .. } = &self.state {
            let status = match reason {
                StopReason::Failed => ApprovedStatus::Failed,
                StopReason::ScopeExceeded => ApprovedStatus::ScopeExceeded,
                StopReason::StaleReview => ApprovedStatus::StaleReview,
                StopReason::Rejected | StopReason::Cancelled => {
                    return Err(Error::InvalidJob {
                        reason: "an approved decision cannot be withdrawn by observation",
                    });
                }
            };
            return self.finish(status);
        }

        self.state = JobState::Stopped {
            authorization_id: self.authorization_id().cloned(),
            reason,
        };
        Ok(())
    }

    /// Borrow untrusted extension metadata without interpreting it as authority.
    #[cfg(feature = "job-writer")]
    pub fn detail(&self, key: &str) -> Option<&serde_json::Value> {
        self.details.get(key)
    }

    /// Set extension metadata without allowing it to shadow the validated job identity or phase.
    ///
    /// # Panics
    ///
    /// Panics for request_id, status, decision or authorization_id keys.
    #[cfg(feature = "job-writer")]
    pub fn set_detail(&mut self, key: &str, value: serde_json::Value) {
        assert!(!matches!(
            key,
            "request_id" | "status" | "decision" | "authorization_id"
        ));

        self.details.insert(key.to_owned(), value);
    }

    /// Return the controller job identity used by follow-up status queries.
    pub fn request_id(&self) -> &JobId {
        &self.request_id
    }

    /// Return the current worker phase independently of its approval decision.
    pub fn status(&self) -> JobStatus {
        self.submission_feedback().job_status()
    }

    /// Return durable approval if recorded, including after a later worker failure.
    pub fn decision(&self) -> Option<StoredDecision> {
        match &self.state {
            JobState::Approved { .. } => Some(StoredDecision::Approved),
            JobState::Queued { .. }
            | JobState::AwaitingApproval { .. }
            | JobState::Stopped { .. } => None,
        }
    }

    /// Return the protected source-review identity, if one has been allocated.
    pub fn authorization_id(&self) -> Option<&ReviewId> {
        match &self.state {
            JobState::Queued { authorization_id }
            | JobState::Stopped {
                authorization_id, ..
            } => authorization_id.as_ref(),
            JobState::AwaitingApproval { authorization_id }
            | JobState::Approved {
                authorization_id, ..
            } => Some(authorization_id),
        }
    }

    /// Approval stays observable after later work finishes or fails.
    pub fn submission_feedback(&self) -> SubmissionFeedback {
        match &self.state {
            JobState::Queued { .. } => SubmissionFeedback::Pending(PendingStatus::Queued),
            JobState::AwaitingApproval { .. } => {
                SubmissionFeedback::Pending(PendingStatus::AwaitingApproval)
            }
            JobState::Approved { status, .. } => SubmissionFeedback::Approved(*status),
            JobState::Stopped { reason, .. } => SubmissionFeedback::Stopped(*reason),
        }
    }
}

/// Each category accepts only its own phases. In particular a pending failure
/// and an approved queued job cannot be constructed. Continuing is derived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmissionFeedback {
    /// The human approved; the worker phase still determines subsequent progress.
    Approved(
        /// Current phase after durable approval, even if later work fails.
        ApprovedStatus,
    ),
    /// No human decision is yet available; the submission must keep waiting.
    Pending(
        /// Pre-decision phase while the submission is still waiting.
        PendingStatus,
    ),
    /// The request ended without a durable approved outcome.
    Stopped(
        /// Reason the request ended before a durable approved outcome.
        StopReason,
    ),
}

impl SubmissionFeedback {
    /// Return the worker phase represented by this feedback category.
    pub fn job_status(self) -> JobStatus {
        match self {
            Self::Approved(status) => status.into(),
            Self::Pending(status) => status.into(),
            Self::Stopped(reason) => reason.into(),
        }
    }

    /// Return `None` while waiting, zero for approval, or the terminal failure code.
    ///
    /// Zero acknowledges human approval; it does not certify a completed deployment.
    pub fn exit_code(self) -> Option<u8> {
        match self {
            Self::Approved(_) => Some(0),
            Self::Pending(_) => None,
            Self::Stopped(reason) => Some(reason.exit_code()),
        }
    }
}

impl Serialize for SubmissionFeedback {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let approved = matches!(self, Self::Approved(_));
        let mut output =
            serializer.serialize_struct("SubmissionFeedback", if approved { 3 } else { 2 })?;
        let status = match self {
            Self::Approved(_) => "approved",
            Self::Pending(_) => "pending",
            Self::Stopped(_) => "stopped",
        };
        output.serialize_field("status", status)?;
        output.serialize_field("job_status", &self.job_status())?;
        if approved {
            output.serialize_field("continuing", &self.job_status().is_active())?;
        }

        output.end()
    }
}
