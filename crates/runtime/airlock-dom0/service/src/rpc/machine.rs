//! A transport release carries host files and receipts for already admitted guests.
//! Importing it grants no activation authority. Prepared tokens bind a checked
//! candidate and machine-state snapshot so a later apply must revalidate both.

use super::*;
use crate::{
    model::{GuestTransport, StoreFile, StorePath},
    state,
};
use airlock_nix_core::identity::{BaselineFingerprint, GitRevision, GuestName, LockHash};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Instant,
};

pub(super) const SCHEMA: &str = "airlock.sys-ctrl-machine-release.v2";

#[derive(Deserialize)]
enum Schema {
    #[serde(rename = "airlock.sys-ctrl-machine-release.v2")]
    V2,
}

#[derive(Deserialize)]
enum Profile {
    #[serde(rename = "usb-lab")]
    UsbLab,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    // Supported wire format; unknown versions fail before inventory or import.
    #[serde(rename = "schema")]
    _schema: Schema,
    // Immutable object containing the machine transport manifest.
    release: StorePath,
    // Exact reviewed source commit expected in the imported manifest.
    revision: GitRevision,
    // Dependency-lock digest expected in the imported manifest.
    lock_hash: LockHash,
    // Physical-machine profile supported by this transport.
    #[serde(rename = "profile")]
    _profile: Profile,
    // Export inventory; absent only when reusing a prepared candidate.
    paths: Option<BTreeMap<StorePath, u64>>,
    // Guest pool receipts authenticated later by the coordinator.
    receipts: Option<BTreeMap<GuestName, Value>>,
    // Protected prepared-record identity; apply never imports another stream.
    prepared: Option<ReviewId>,
    // Human source authorization checked by the installed coordinator.
    review_authorization: Option<ReviewId>,
}

#[derive(Deserialize)]
struct Manifest {
    // The transport must be a supported machine release, not arbitrary Nix data.
    schema: String,
    // Source commit bound to the release imported through Nix.
    revision: GitRevision,
    // Dependency-lock digest bound to that same immutable release.
    #[serde(rename = "lockHash")]
    lock_hash: LockHash,
    // Only physical machine releases are accepted by these qrexec endpoints.
    #[serde(rename = "profile")]
    _profile: Profile,
    // Guest bytes belong to admitted pool generations, outside this Nix stream.
    #[serde(rename = "guestTransport")]
    _transport: GuestTransport,
    // Release-matched coordinator used when protected review is disabled.
    coordinator: StoreFile,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Checked {
    // Complete validated effects, compared again immediately before apply.
    plan: Value,
    // Fingerprint of runtime state and retained artifacts used for that plan.
    state: BaselineFingerprint,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Prepared {
    // Local candidate assembled from exact admitted artifacts and receipts.
    candidate: ReleasePath,
    // Locally selected executable which validated the saved candidate.
    coordinator: PathBuf,
    // Immutable transport object whose provenance must match a later apply.
    release: StorePath,
    // Source commit of this exact prepared plan.
    revision: GitRevision,
    // Dependency-lock digest of this exact prepared plan.
    lock_hash: LockHash,
    // Effects shown during planning and rechecked before detached activation.
    plan: Value,
    // Runtime fingerprint required by the detached apply command.
    state: BaselineFingerprint,
}

impl Receiver {
    fn check_review(&self, header: &Header) -> Result<()> {
        if let Some(result) = self.approval(
            header.review_authorization.as_ref(),
            &header.revision,
            &header.lock_hash,
        )? {
            ensure!(
                result["binding"]["family"] == "machine",
                "whole-machine operation requires whole-machine approval"
            );
        }
        Ok(())
    }

    fn checked(&self, engine: &Path, candidate: &ReleasePath) -> Result<Checked> {
        self.candidate_path(candidate)?;
        Ok(serde_json::from_value(self.engine(
            engine,
            &["prepared-check", candidate.as_str()],
            None,
        )?)?)
    }

    fn save_prepared(
        &self,
        header: &Header,
        candidate: ReleasePath,
        engine: &Path,
    ) -> Result<(String, Checked)> {
        let checked = self.checked(engine, &candidate)?;
        let saved = Prepared {
            candidate,
            coordinator: engine.to_owned(),
            release: header.release.clone(),
            revision: header.revision.clone(),
            lock_hash: header.lock_hash.clone(),
            plan: checked.plan.clone(),
            state: checked.state.clone(),
        };
        let value = serde_json::to_value(saved)?;
        let token = state::digest(&value)?;
        state::save(
            &self.state.join("prepared").join(format!("{token}.json")),
            &value,
        )?;
        Ok((token, checked))
    }

    fn apply_prepared(&self, header: &Header, token: &ReviewId) -> Result<Value> {
        let path = self.state.join("prepared").join(format!("{token}.json"));
        state::trusted(&path)?;
        let raw: Value = state::read(&path)?;
        ensure!(
            state::digest(&raw)? == token.as_str(),
            "prepared candidate record checksum mismatch"
        );
        let saved: Prepared = serde_json::from_value(raw)?;
        ensure!(
            saved.release == header.release
                && saved.revision == header.revision
                && saved.lock_hash == header.lock_hash,
            "prepared candidate identity mismatch"
        );
        ensure!(
            saved.coordinator.is_absolute(),
            "invalid prepared coordinator"
        );
        let engine = if self.review_required {
            &self.engine
        } else {
            &saved.coordinator
        };

        let started = Instant::now();
        let checked = self.checked(engine, &saved.candidate)?;
        ensure!(
            checked.plan == saved.plan && checked.state == saved.state,
            "prepared candidate is stale; run machine-plan again"
        );
        self.bind(header.review_authorization.as_ref(), &saved.candidate)?;
        let unit = self.detach(
            engine,
            &[
                "apply",
                saved.candidate.as_str(),
                "--expected-state",
                saved.state.as_str(),
            ],
        )?;
        Ok(
            json!({"schema":SCHEMA,"release":saved.candidate,"source_release":saved.release,
            "plan":saved.plan,"prepared":token,"prepared_reused":true,"unit":unit,
            "paths_transferred":0,"nar_bytes":0,"compressed_bytes":0,
            "timings":{"prepared_check_seconds":started.elapsed().as_secs_f64()}}),
        )
    }

    pub(super) fn machine(
        &self,
        action: MachineAction,
        input: &mut transfer::Input,
    ) -> Result<Value> {
        let header: Header = message(input, state::LIMIT)?;
        if header.prepared.is_some() {
            ensure!(
                action == MachineAction::Apply,
                "prepared tokens are only accepted for apply"
            );
            ensure!(
                header.paths.is_none() && header.receipts.is_none(),
                "prepared apply cannot include another transfer"
            );
        } else {
            let paths = header.paths.as_ref().context("missing release inventory")?;
            ensure!(
                paths.contains_key(&header.release) && paths.len() <= 100000,
                "invalid release inventory"
            );
        }
        if header.prepared.is_none() && action != MachineAction::Prepare {
            ensure!(
                header.receipts.is_some(),
                "missing guest admission receipts"
            );
        }
        let mut transfer_lock = if header.prepared.is_none() {
            Some(self.transfer_lock(header.review_authorization.as_ref())?)
        } else {
            None
        };
        self.check_review(&header)?;
        if let Some(token) = &header.prepared {
            return self.apply_prepared(&header, token);
        }

        let started = Instant::now();
        let paths = header.paths.as_ref().context("missing release inventory")?;
        let inventory = process::run(
            Command::new("nix").args([
                "--extra-experimental-features",
                "nix-command",
                "path-info",
                "--all",
            ]),
            None,
            Some(Duration::from_secs(120)),
        )?
        .checked("read Nix inventory")?;
        let valid = std::str::from_utf8(&inventory)?
            .lines()
            .filter(|line| !line.is_empty())
            .map(str::parse)
            .collect::<std::result::Result<BTreeSet<StorePath>, _>>()?;
        let missing: Vec<_> = paths
            .keys()
            .filter(|path| !valid.contains(*path))
            .cloned()
            .collect();
        let required = missing.iter().try_fold(0u64, |size, path| {
            size.checked_add(paths[path])
                .context("release inventory size overflow")
        })?;
        let space = rustix::fs::statvfs("/nix/store")?;
        let available = space
            .f_bavail
            .checked_mul(space.f_frsize)
            .context("store space overflow")?;
        let budget = available
            .checked_sub(2 * 1024 * 1024 * 1024)
            .context("insufficient dom0 store space for release import")?;
        ensure!(
            required <= budget,
            "insufficient dom0 store space for release import"
        );
        emit(&json!({"schema":SCHEMA,"missing":missing}))?;
        let inventory_seconds = started.elapsed().as_secs_f64();

        let started = Instant::now();
        if let Some(lock) = &mut transfer_lock {
            lock.update_phase("Importing transport release".into())?;
        }
        let imported = transfer::import(input, budget, &missing)?;
        let import_seconds = started.elapsed().as_secs_f64();
        let manifest: Manifest =
            state::read(&Path::new(header.release.as_str()).join("release.json"))?;
        ensure!(
            manifest.schema == "airlock.machine-release.v1"
                && manifest.revision == header.revision
                && manifest.lock_hash == header.lock_hash,
            "imported release provenance differs from request"
        );
        ensure!(
            manifest
                .coordinator
                .as_str()
                .ends_with("/bin/airlock-dom0-service"),
            "invalid release coordinator"
        );

        self.check_review(&header)?;
        if let Some(lock) = &mut transfer_lock {
            lock.update_phase("Preparing machine candidate".into())?;
        }
        if action == MachineAction::Prepare {
            let mut result = self.engine(
                &self.engine,
                &[
                    "admission-prepare",
                    header.release.as_str(),
                    "--caller",
                    "sys-ctrl",
                ],
                None,
            )?;
            ensure!(result.is_object(), "invalid preparation response");
            result["paths_transferred"] = json!(missing.len());
            result["nar_bytes"] = json!(imported.nar_bytes);
            result["compressed_bytes"] = json!(imported.compressed_bytes);
            result["timings"] = json!({"inventory_validation_seconds":inventory_seconds,
                "transfer_decompress_import_seconds":import_seconds});
            return Ok(result);
        }
        let engine = if self.review_required {
            self.engine.clone()
        } else {
            PathBuf::from(manifest.coordinator.as_str())
        };
        let receipts = serde_json::to_value(
            header
                .receipts
                .as_ref()
                .context("missing guest admission receipts")?,
        )?;
        let binding = self.engine(
            &engine,
            &["machine-bind", header.release.as_str(), "-"],
            Some(&receipts),
        )?;
        let candidate: ReleasePath = serde_json::from_value(binding["candidate"].clone())?;
        self.candidate_path(&candidate)?;
        let plan = self.engine(&engine, &["plan", candidate.as_str()], None)?;
        self.bind(header.review_authorization.as_ref(), &candidate)?;

        state::directory(&self.state.join("roots"))?;
        let root = self.state.join("roots").join(format!(
            "pending-{}",
            candidate
                .as_path()
                .file_name()
                .context("candidate has no name")?
                .to_str()
                .context("non-UTF-8 candidate")?
        ));
        process::run(
            Command::new("nix-store")
                .arg("--add-root")
                .arg(&root)
                .args(["--realise", header.release.as_str()]),
            None,
            Some(Duration::from_secs(120)),
        )?
        .checked("pin transport release")?;
        fs::File::open(self.state.join("roots"))?.sync_all()?;
        let mut result = json!({"schema":SCHEMA,"release":candidate,"source_release":header.release,
            "plan":plan,"paths_transferred":missing.len(),"nar_bytes":imported.nar_bytes,
            "compressed_bytes":imported.compressed_bytes,"timings":{
                "inventory_validation_seconds":inventory_seconds,"transfer_decompress_import_seconds":import_seconds}});
        if let Some(timings) = binding["timings"].as_object() {
            result["timings"]
                .as_object_mut()
                .expect("timings object")
                .extend(timings.clone());
        }
        if action == MachineAction::Plan {
            let (token, checked) = self.save_prepared(&header, candidate, &engine)?;
            result["prepared"] = json!(token);
            result["plan"] = checked.plan;
        } else {
            result["unit"] = json!(self.detach(&engine, &["apply", candidate.as_str()])?);
        }
        Ok(result)
    }
}
