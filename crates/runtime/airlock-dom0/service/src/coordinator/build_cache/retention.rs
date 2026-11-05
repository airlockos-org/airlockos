//! A preparation owns metadata until publication completes or its original authority expires.
//! Machine exclusion serializes review changes, receivers and retirement. Pending private
//! builds keep their builder base; additive bases retain those dependencies until private
//! overlays are deliberately retired. This pass never prunes a writable builder store.

use super::*;
use airlock_deployment_core::attachment::runtime_namespace;
use airlock_deployment_core::retention::Protection;
use airlock_machine_planning::build_publication::{self as policy, Retirement};
use serde::Deserialize;

/// Complete bounded source inventory, retaining decoded maps only for the current record.
struct Inventory {
    // Original preparations selected to end ownership in this pass.
    retire: Vec<Retirement>,
    // Live or deferred preparations protecting their full admitted derivation closure.
    protections: Vec<Protection>,
}

/// Protected record stages; a durable retirement intent cannot be used by a receiver.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Stage {
    /// Metadata and original review are durable; bulk transfer has not begun.
    Prepared,
    /// The receiver owns durable transfer intent.
    Receiving,
    /// Durable authorization permits the current pool transfer.
    Authorized,
    /// A failed attempt retains its original inputs for a freshly authorized retry.
    Interrupted,
    /// Complete builder views now retain the admitted inputs.
    Committed,
    /// Durable retirement intent ends receiver ownership and permits cleanup recovery.
    Retiring,
}

/// Enumerate a bounded private namespace; malformed records remain errors, never empty state.
fn entries(directory: &Path, roots: bool) -> Result<Vec<PathBuf>> {
    if !directory.try_exists()? {
        return Ok(Vec::new());
    }
    state::trusted(directory)?;
    let mut paths = Vec::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if roots
            || path
                .extension()
                .is_some_and(|extension| extension == "json")
        {
            paths.push(path);
            ensure!(
                paths.len() <= policy::MAX_PREPARATIONS,
                "build preparation inventory exceeds its bound"
            );
        }
    }
    paths.sort();
    Ok(paths)
}

/// Reject new preparation work before it can create an unowned metadata root.
pub(super) fn capacity(directory: &Path, roots: &Path, identity: &LockHash) -> Result<()> {
    for (directory, is_root) in [(directory, false), (roots, true)] {
        let count = entries(directory, is_root)?.len();
        let path = directory.join(if is_root {
            identity.to_string()
        } else {
            format!("{identity}.json")
        });
        ensure!(
            policy::preparation_fits(count, fs::symlink_metadata(path).is_ok()),
            "build preparation capacity exhausted; retire completed or expired preparations first"
        );
    }
    Ok(())
}

/// Decode the exact original request before an observation can affect ownership.
fn request(record: &Value, identity: &LockHash) -> Result<Request> {
    let request: Request = serde_json::from_value(record["request"].clone())?;
    request.validate()?;
    ensure!(
        record["schema"] == SCHEMA
            && record["request_hash"] == json!(identity)
            && request.fingerprint()? == *identity,
        "build preparation record identity differs"
    );
    Ok(request)
}

impl Coordinator {
    /// Keep all preparations in the machine's complete protection inventory until retirement.
    pub(in crate::coordinator) fn build_cache_protections(&self) -> Result<Vec<Protection>> {
        Ok(self.build_cache_inventory(0)?.protections)
    }

    /// Read authority under machine exclusion; I/O errors never imply revocation.
    fn build_cache_inventory(&self, maximum: usize) -> Result<Inventory> {
        let directory = self.state.join("build-publications");
        let paths = entries(&directory, false)?;
        let mut inventory = Inventory {
            retire: Vec::new(),
            protections: Vec::new(),
        };
        let boot = state::boot_id()?;
        // Read-only protection construction is also used during an active deployment.
        // It conservatively retains every record without requiring that deployment to finish.
        let baseline = if maximum > 0 && !paths.is_empty() {
            Some(self.review_baseline()?.1)
        } else {
            None
        };
        let mut known = BTreeSet::new();
        for path in paths {
            state::trusted(&path)?;
            let identity: LockHash = path
                .file_stem()
                .and_then(|name| name.to_str())
                .context("invalid build preparation filename")?
                .parse()?;
            known.insert(identity.to_string());
            let record: Value = state::read(&path)?;
            let request = request(&record, &identity)?;
            if maximum == 0 {
                inventory.protections.push(Protection::System {
                    domain: runtime_namespace(airlock_nix_core::build_cache::DOMAIN),
                    system: request.derivation.to_string(),
                });
                continue;
            }
            let stage: Stage = serde_json::from_value(record["status"].clone())?;
            let completed = matches!(stage, Stage::Committed | Stage::Retiring);
            let same_boot = record["boot_id"]
                .as_str()
                .context("missing build boot identity")?
                == boot.as_str();
            let live = if same_boot && !completed {
                let approval_path = self.review_path(&request.review_authorization);
                let approval: Option<ApprovalRecord> = state::optional(&approval_path)?;
                if let Some(approval) = approval {
                    state::trusted(&approval_path)?;
                    approval.request_id == request.review_authorization
                        && approval.status == ApprovalStatus::Approved
                        && approval.review_fingerprint.is_some()
                        && approval.binding == Self::build_binding(&request)
                        && baseline.as_ref() == Some(&approval.baseline_state)
                        && record["approval_hash"]
                            == state::digest(&serde_json::to_value(&approval)?)?
                } else {
                    false
                }
            } else {
                false
            };
            let retirement = policy::retire(identity.to_string(), completed, live);
            if inventory.retire.len() < maximum
                && let Some(retirement) = retirement
            {
                inventory.retire.push(retirement);
            } else {
                inventory.protections.push(Protection::System {
                    domain: runtime_namespace(airlock_nix_core::build_cache::DOMAIN),
                    system: request.derivation.to_string(),
                });
            }
        }
        // A crash between root creation and the atomic record write leaves no active
        // owner. The machine lock excludes that construction interval during this scan.
        for path in entries(Path::new(METADATA_ROOTS), true)? {
            let identity: LockHash = path
                .file_name()
                .and_then(|name| name.to_str())
                .context("invalid build metadata root name")?
                .parse()?;
            if !known.contains(identity.as_str()) && inventory.retire.len() < maximum {
                inventory.retire.push(
                    policy::retire(identity.to_string(), false, false)
                        .context("orphan retirement refused")?,
                );
            }
        }
        Ok(inventory)
    }

    /// End acknowledged ownership, then release only automatic scratch-admission pins.
    /// Current builder generations, explicit rollback retention and physical pins remain intact.
    pub(in crate::coordinator) fn maintain_build_cache(&self) -> Result<Value> {
        let directory = self.state.join("build-publications");
        let roots = Path::new(METADATA_ROOTS);
        let pool = Path::new("/var/lib/airlock/closure-store/domains")
            .join(runtime_namespace(airlock_nix_core::build_cache::DOMAIN));
        if !directory.try_exists()? && !roots.try_exists()? && !pool.try_exists()? {
            return Ok(json!({"status":"idle","collect":false}));
        }
        self.review_baseline()?;
        let inventory = self.build_cache_inventory(policy::MAX_RETIREMENTS)?;
        for retirement in &inventory.retire {
            let identity: LockHash = retirement.identity().parse()?;
            let journal = directory.join(format!("{identity}.json"));
            let mut expected = None;
            if let Some(mut record) = state::optional::<Value>(&journal)? {
                state::trusted(&journal)?;
                expected = Some(request(&record, &identity)?.derivation);
                record["status"] = json!("retiring");
                state::save(&journal, &record)?;
            }
            let pin = roots.join(retirement.identity());
            match fs::symlink_metadata(&pin) {
                Ok(metadata) => {
                    ensure!(
                        metadata.file_type().is_symlink(),
                        "build metadata root is not a symlink"
                    );
                    let target = fs::read_link(&pin)?;
                    let target: StorePath =
                        target.to_str().context("invalid metadata root")?.parse()?;
                    ensure!(
                        target.as_str().ends_with(".drv")
                            && expected.as_ref().is_none_or(|expected| *expected == target),
                        "build metadata root target changed"
                    );
                    fs::remove_file(&pin)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            if roots.try_exists()? {
                File::open(roots)?.sync_all()?;
            }
        }
        let mut report = crate::store::release_build_cache(inventory.protections)?;
        let identities: Vec<_> = inventory
            .retire
            .iter()
            .map(|retirement| retirement.identity().to_owned())
            .collect();
        for identity in &identities {
            state::unlink(&directory.join(format!("{identity}.json")))?;
        }
        report["retired_preparations"] = json!(identities);
        report["status"] = json!("passed");
        report["collect"] = json!(pool.try_exists()? || !inventory.retire.is_empty());
        state::save(&self.state.join("maintenance/build-cache.json"), &report)?;
        Ok(report)
    }
}
