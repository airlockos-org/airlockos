//! A source approval permits publishing inputs of that exact completed build, never activation.
//! Existing verified review equality and publication gates carry the protected binding through
//! durable intent to pool effects. Nix's graph/validity results, hashing, locks and filesystem
//! acknowledgments are trusted adapters; this does not attest compiler output correctness.

use super::*;
use airlock_deployment_core::publication::{Event, Publication};
use airlock_nix_core::{
    build_cache::{Request, SCHEMA, Tools},
    identity::LockHash,
};
use std::fs::File;

mod retention;

/// Temporary Nix roots are owned by protected preparation records, never by the guest.
const METADATA_ROOTS: &str = "/nix/var/nix/gcroots/airlock-build-publications";

impl Coordinator {
    /// Classify the wire scope without granting authority; ReviewBinding equality is verified.
    pub(crate) fn build_binding(request: &Request) -> ReviewBinding {
        ReviewBinding {
            revision: request.revision.clone(),
            lock_hash: request.lock_hash.clone(),
            target: match &request.target {
                Some(target) => ReviewTarget::Guest {
                    target: target.clone(),
                },
                None => ReviewTarget::Machine { target: () },
            },
            extra: BTreeMap::new(),
        }
    }

    /// Bind reusable compiled inputs to protected review before any bulk bytes enter the pool.
    pub fn prepare_build_cache(&self) -> Result<Value> {
        let request: Request = reviews::input(airlock_nix_core::runtime::process::LIMIT as u64)?;
        request.validate()?;
        let _guard = MachineLock::acquire(
            &self.state,
            "Build publication preparation",
            "Bind compilation inputs to the original reviewed build",
            MachineOperation::Admission,
        )?;
        self.ensure_no_pruning()?;
        let approval = self.approved_review(
            &request.review_authorization,
            &request.revision,
            &request.lock_hash,
        )?;
        ensure!(
            approval.binding == Self::build_binding(&request),
            "publication scope differs from review"
        );
        let fingerprint = request.fingerprint()?;
        let directory = self.state.join("build-publications");
        let path = directory.join(format!("{fingerprint}.json"));
        let previous: Option<Value> = state::optional(&path)?;
        let approval_hash = state::digest(&serde_json::to_value(&approval)?)?;
        if let Some(previous) = &previous {
            ensure!(
                previous["request"] == serde_json::to_value(&request)?,
                "build preparation identity conflict"
            );
            if airlock_deployment_core::publication::completion_matches(
                previous["status"] == "committed",
                previous["request_hash"].as_str().unwrap_or_default(),
                fingerprint.as_str(),
                previous["approval_hash"].as_str().unwrap_or_default(),
                &approval_hash,
                previous["boot_id"].as_str().unwrap_or_default(),
                state::boot_id()?.as_str(),
            ) && crate::store::completed_build_cache(&request, &previous["receipt"])?
            {
                release_metadata_root(&fingerprint)?;
                let mut receipt = previous["receipt"]["build_publication"].clone();
                receipt["reused"] = json!(true);
                return Ok(receipt);
            }
        }
        Tools {
            nix: "nix",
            nix_store: "nix-store",
        }
        .prepare(&request)?;
        // A direct Nix GC root retains the recipe itself and its references.
        // --realise on a .drv would instead request its compiled outputs in dom0.
        let roots = Path::new(METADATA_ROOTS);
        state::directory(&directory)?;
        state::directory(roots)?;
        retention::capacity(&directory, roots, &fingerprint)?;
        let pin = roots.join(fingerprint.as_str());
        if pin.is_symlink() {
            ensure!(
                fs::read_link(&pin)? == Path::new(request.derivation.as_str()),
                "build metadata root differs"
            );
        } else {
            std::os::unix::fs::symlink(request.derivation.as_str(), &pin)?;
        }
        File::open(roots)?.sync_all()?;
        let record = json!({"schema":SCHEMA, "request":request, "request_hash":fingerprint,
            "approval_hash":approval_hash, "boot_id":state::boot_id()?, "metadata_root":pin,
            "status":"prepared", "previous_progress":previous.and_then(|v|v.get("progress").cloned())});
        state::save(&path, &record)?;
        Ok(
            json!({"schema":SCHEMA, "request_hash":fingerprint, "result":request.result,
            "build":"complete", "admission":"prepared", "publication":"pending", "activated":false}),
        )
    }

    /// Receive directly into the shared pool, then reconcile additive successors under fresh approval.
    pub fn receive_build_cache(&self, token: &LockHash, caller: &str) -> Result<Value> {
        ensure!(caller == "sys-ctrl", "build publication requires sys-ctrl");
        let _guard = MachineLock::acquire(
            &self.state,
            "Build publication",
            "Admit reviewed compilation inputs without activating software",
            MachineOperation::Admission,
        )?;
        self.ensure_no_pruning()?;
        let journal = self
            .state
            .join("build-publications")
            .join(format!("{token}.json"));
        state::trusted(&journal)?;
        let mut record: Value = state::read(&journal)?;
        ensure!(
            record["status"] != "retiring",
            "build preparation is retiring; prepare the approved build again"
        );
        let request: Request = serde_json::from_value(record["request"].clone())?;
        request.validate()?;
        ensure!(
            request.fingerprint()? == *token
                && record["schema"] == SCHEMA
                && record["boot_id"] == json!(state::boot_id()?),
            "build preparation is invalid or stale"
        );
        let approval = self.approved_review(
            &request.review_authorization,
            &request.revision,
            &request.lock_hash,
        )?;
        ensure!(
            approval.binding == Self::build_binding(&request)
                && record["approval_hash"] == state::digest(&serde_json::to_value(&approval)?)?,
            "protected source approval changed before build admission"
        );
        Tools {
            nix: "nix",
            nix_store: "nix-store",
        }
        .prepare(&request)?;
        let attempt = format!(
            "{boot}:{pid}:{time}",
            boot = state::boot_id()?,
            pid = std::process::id(),
            time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        );
        let binding = state::digest(&json!({"request":request, "approval":approval}))?;
        let mut gate = Publication::new(attempt.clone(), binding.clone());
        record["attempt"] = json!(attempt);
        record["binding"] = json!(binding);
        record["status"] = json!("receiving");
        record["progress"] = json!({});
        state::save(&journal, &record)?;
        gate.advance(Event::IntentSaved);
        record["status"] = json!("authorized");
        state::save(&journal, &record)?;
        gate.advance(Event::ApprovalSaved);
        ensure!(
            gate.begin(&attempt, &binding),
            "publication intent was not acknowledged"
        );
        let _recording = self.progress(&format!(
            "build-{review}",
            review = request.review_authorization
        ));
        let received = crate::store::receive_build_cache(
            &request,
            &gate,
            &attempt,
            &binding,
            |stage, observation| {
                record["progress"][stage] = observation.clone();
                state::save(&journal, &record)
            },
        );
        match received {
            Ok(mut receipt) => {
                gate.advance(Event::Verified);
                receipt["build_publication"] = json!({"schema":SCHEMA, "request_hash":token,
                    "result":request.result, "build":"complete", "admission":"complete",
                    "publication":"complete", "views":receipt["builder_views"],
                    "adoption":"next-stopped-start", "activated":false});
                receipt
                    .as_object_mut()
                    .context("invalid admission receipt")?
                    .remove("builder_views");
                record["status"] = json!("committed");
                record["receipt"] = receipt.clone();
                state::save(&journal, &record)?;
                // Committed pool generations now retain the source and recipe objects.
                // Release temporary host-store ownership only after that acknowledgement;
                // an interrupted attempt keeps its recorded root for recovery/retirement.
                release_metadata_root(token)?;
                Ok(receipt)
            }
            Err(error) => {
                gate.advance(Event::Interrupted);
                record["status"] = json!("interrupted");
                record["error"] = json!(format!("{error:#}"));
                state::save(&journal, &record)?;
                Err(error
                    .context("admission/publication may be partial; retry the same approved build"))
            }
        }
    }
}

/// A committed pool receipt owns these objects before temporary host roots are
/// released. Retry also closes the crash window between receipt and root removal.
fn release_metadata_root(token: &LockHash) -> Result<()> {
    let roots = Path::new(METADATA_ROOTS);
    if !roots.try_exists()? {
        return Ok(());
    }
    match fs::remove_file(roots.join(token.as_str())) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    File::open(roots)?.sync_all()?;
    Ok(())
}
