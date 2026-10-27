//! The review window displays a source-bound request and returns a human decision.
//! Wire validation is shared with the controller; only dom0 grants authority.

use crate::model::Review;
use airlock_nix_core::{
    review::{DeploymentTarget, ResponseSchema, ReviewRequest, ReviewResponse, Scope},
    state::read_json,
};
use anyhow::{Result, anyhow, ensure};
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

pub use airlock_nix_core::review::Decision as ApprovalDecision;

/// Shared decision slot read by the launcher after the review window closes.
pub type Reply = Arc<Mutex<Option<ReviewResponse>>>;

pub const REBOOT_NOTICE: &str =
    "May be required. Confirmed after building; you choose when to restart.";

/// Read a bounded request and reject mismatches with the displayed source.
///
/// The shared decoder also checks schema, target, identities and VM scope,
/// rejects duplicate keys and refuses symlinks and non-regular files.
pub fn load_request(path: &Path, review: &Review) -> Result<ReviewRequest> {
    let request: ReviewRequest = read_json(path, 65536)?;
    ensure!(
        request.baseline().as_str() == review.baseline.commit
            && request.source().revision.as_str() == review.candidate.commit
            && Some(request.source().lock_hash.as_str()) == review.lock_hash.as_deref(),
        "approval request differs from reviewed source"
    );

    Ok(request)
}

/// Bind the human choice and final scope to the request and displayed review.
pub fn response(
    request: &ReviewRequest,
    review: &Review,
    decision: ApprovalDecision,
    scope: Scope,
) -> Result<ReviewResponse> {
    Ok(ReviewResponse {
        schema: ResponseSchema::V1,
        request_id: request.request_id().clone(),
        revision: request.source().revision.clone(),
        lock_hash: request.source().lock_hash.clone(),
        review_fingerprint: review.fingerprint.parse()?,
        decision,
        scope,
    })
}

/// Validated approval request, editable scope and response slot for one review window.
pub struct Session {
    /// Validated launch request bound to the displayed source review.
    pub request: ReviewRequest,
    /// Editable VM scope text parsed when constructing the final decision.
    pub allowed_vms: String,
    /// Shared response slot consumed by the launching controller after window exit.
    pub reply: Reply,
}

impl Session {
    /// Parse edited names with the controller's VM grammar and scope constraints.
    ///
    /// Approval covers a possible required reboot; the user still controls when it happens.
    pub fn scope(&self) -> Option<Scope> {
        let names = self
            .allowed_vms
            .split([',', ' ', '\n'])
            .filter(|s| !s.is_empty())
            .map(str::parse)
            .collect::<airlock_nix_core::Result<Vec<_>>>()
            .ok()?;
        Scope::new(names, true).ok()
    }

    /// Publish the human reply, returning validation errors without closing the window.
    pub fn finish(&self, review: &Review, decision: ApprovalDecision) -> Result<()> {
        let scope = if decision == ApprovalDecision::Approve {
            self.scope()
                .ok_or_else(|| anyhow!("invalid permitted VM names"))?
        } else {
            self.request.scope().clone()
        };
        let response = response(&self.request, review, decision, scope)?;
        *self
            .reply
            .lock()
            .map_err(|_| anyhow!("approval reply is unavailable"))? = Some(response);
        Ok(())
    }

    /// Append the current approval scope to the complete review text for clipboard inspection.
    pub fn copy_text(&self, base_report: &str) -> Result<String> {
        let (family, target) = match self.request.target() {
            DeploymentTarget::Machine => ("machine", None),
            DeploymentTarget::Guest(name) => ("guest", Some(name)),
        };

        let mut report = base_report.to_owned();
        report.push_str("\n## Approval scope\n\n");
        report.push_str(&serde_json::to_string_pretty(&serde_json::json!({
            "request_id": self.request.request_id(), "family": family,
            "target": target, "scope": self.scope(),
            "system_reboot": REBOOT_NOTICE,
            "purpose": "Approval permits evaluation, building and deployment within this scope, including changes that require a reboot. The final deployment plan is not yet known."
        }))?);
        report.push('\n');
        Ok(report)
    }
}
