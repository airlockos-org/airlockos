//! Reuse machine transport without granting deployment or a general import endpoint.
//! The wrapper admits only sys-ctrl; protected review is mandatory even on development images.

use super::*;
use airlock_nix_core::build_cache::{MAX_BYTES, Request, SCHEMA};

impl Receiver {
    /// Authenticate before receiving bytes, then let the locked coordinator publish checked inputs.
    pub(super) fn build_cache(&self, input: &mut transfer::Input) -> Result<Value> {
        let request: Request = message(input, process::LIMIT as u64)?;
        request.validate()?;
        let mut lock = self.transfer_lock(Some(&request.review_authorization))?;
        let approval: crate::model::ApprovalRecord = serde_json::from_value(self.engine(
            &self.engine,
            &["review-control"],
            Some(
                &json!({"op":"check", "request_id":request.review_authorization,
                "revision":request.revision, "lock_hash":request.lock_hash}),
            ),
        )?)?;
        ensure!(
            approval.binding == crate::coordinator::Coordinator::build_binding(&request),
            "build publication differs from approved source or target"
        );
        let imported =
            self.import_paths(&request.metadata, SCHEMA, input, Some(&mut lock), MAX_BYTES)?;
        lock.update_phase("Preparing pool build admission".into())?;
        let mut result = self.engine(
            &self.engine,
            &["build-prepare"],
            Some(&serde_json::to_value(&request)?),
        )?;
        result["paths_transferred"] = json!(imported.missing.len());
        result["nar_bytes"] = json!(imported.imported.nar_bytes);
        result["compressed_bytes"] = json!(imported.imported.compressed_bytes);
        result["timings"] = json!({"inventory_seconds":imported.inventory_seconds,
            "import_seconds":imported.import_seconds});
        Ok(result)
    }
}
