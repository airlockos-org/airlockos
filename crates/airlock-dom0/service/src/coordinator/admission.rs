//! Authorize an inactive storage import for one exact, reviewed machine candidate.
//! Payload negotiation and storage integrity remain in the closure-store engine.

use super::*;
use airlock_nix_core::identity::LockHash;
use airlock_nix_core::{admission::ExpectedAdmission, root_artifact::RootDescriptor};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Admission {
    // Version of the protected artifact-admission record.
    schema: String,
    // Immutable transport release whose inventory was inspected.
    release: ReleasePath,
    // Qubes caller authorized to send these artifacts.
    caller: String,
    // Boot identity at which the candidate was authorized.
    boot_id: BootId,
    // Deployed selection and transaction at authorization time.
    state: Value,
    // Exact permitted system, closure, root and build identities for each guest.
    guests: BTreeMap<GuestName, ExpectedAdmission>,
    // Fingerprint preventing release edits after preparation.
    release_fingerprint: ReleaseFingerprint,
}

impl Coordinator {
    fn admission_state(&self) -> Result<Value> {
        let latest: Option<Record> = state::optional(&self.state.join("latest.json"))?;
        if let Some(record) = &latest {
            ensure!(
                record.phase == Phase::Complete,
                "finish or recover the current deployment and required reboot first"
            );
        }
        Ok(json!({"selection":self.selection()?,"latest":latest}))
    }

    /// Prepare a candidate-bound inactive artifact import for the controller caller only.
    pub fn admission_prepare(&self, path: &Path, caller: &str) -> Result<Value> {
        ensure!(
            caller == "sys-ctrl",
            "candidate admission requires sys-ctrl"
        );
        let _guard = MachineLock::acquire(
            &self.state,
            "Artifact admission",
            "Validate a release before importing artifacts",
            MachineOperation::Admission,
        )?;
        self.ensure_no_pruning()?;
        let r = Release::load(path)?;
        r.trust()?;
        self.ensure_available(&r)?;
        ensure!(
            r.manifest.guest_transport == Some(GuestTransport::DirectPoolV1)
                && !r.topology.domains.is_empty(),
            "candidate requires direct pool admission"
        );
        let roots: BTreeMap<GuestName, RootDescriptor> =
            state::read(&r.path.join("root-artifacts.json"))?;
        ensure!(
            roots.keys().collect::<BTreeSet<_>>()
                == r.topology
                    .domains
                    .iter()
                    .filter(|(_, d)| d.backend.hermit().is_none())
                    .map(|(name, _)| name)
                    .collect(),
            "candidate root inventory differs from domains"
        );
        for (name, refs) in planning::dependencies(&r.topology, false)? {
            ensure!(
                refs.iter().all(|n| r.topology.domains.contains_key(n)),
                "{name}: candidate has undeclared dependencies"
            );
        }
        let plan = self.plan(&r)?;
        let mut guests = BTreeMap::new();
        for (name, d) in &r.topology.domains {
            if d.backend.hermit().is_some() {
                continue;
            }
            roots[name].validate()?;
            ensure!(
                d.backend
                    .nixos()?
                    .root
                    .source
                    .as_str()
                    .ends_with("/root.img"),
                "invalid candidate root source"
            );
            guests.insert(
                name.clone(),
                ExpectedAdmission {
                    domain: name.clone(),
                    system: d.backend.system.source.clone(),
                    closure_source: d.backend.nixos()?.store.source.clone(),
                    root_source: d.backend.nixos()?.root.source.clone(),
                    kernel_name: d.backend.nixos()?.kernel.name.clone(),
                    source_revision: r.manifest.revision.clone(),
                    lock_hash: r.manifest.lock_hash.clone(),
                    root_artifact: roots[name].clone(),
                },
            );
        }
        let record = Admission {
            schema: "airlock.machine-admission.v1".into(),
            release: ReleasePath::from_path(&r.path)?,
            caller: caller.into(),
            boot_id: state::boot_id()?,
            state: self.admission_state()?,
            guests,
            release_fingerprint: r.fingerprint().clone(),
        };
        let token = state::digest(&serde_json::to_value(&record)?)?;
        self.pin(&format!("admission-{token}"), &r.path)?;
        r.recheck()?;
        state::save(
            &self.state.join("admissions").join(format!("{token}.json")),
            &record,
        )?;
        Ok(
            json!({"schema":record.schema,"admission":token,"domains":record.guests.keys().collect::<Vec<_>>(),"release":record.release,"plan":plan,"activated":false}),
        )
    }

    /// Validate a prepared import then run storage negotiation while retaining the machine lock.
    pub fn admission_receive(&self, argument: &str, caller: &str) -> Result<()> {
        ensure!(
            caller == "sys-ctrl",
            "candidate admission requires sys-ctrl"
        );
        let (token, name) = argument
            .split_once('.')
            .context("candidate admission requires token and domain")?;
        let _: LockHash = token.parse()?;
        let name: GuestName = name.parse()?;
        let _guard = MachineLock::acquire(
            &self.state,
            "Artifact admission",
            "Receive candidate-bound guest artifacts",
            MachineOperation::Admission,
        )?;
        let path = self.state.join("admissions").join(format!("{token}.json"));
        state::trusted(&path)?;
        let record: Admission = state::read(&path)?;
        ensure!(
            state::digest(&serde_json::to_value(&record)?)? == token
                && record.schema == "airlock.machine-admission.v1"
                && record.caller == caller,
            "candidate admission identity mismatch"
        );
        ensure!(
            record.boot_id == state::boot_id()? && record.state == self.admission_state()?,
            "candidate admission is stale; prepare the release again"
        );
        self.ensure_no_pruning()?;
        let r = Release::load(record.release.as_path())?;
        r.trust()?;
        self.ensure_available(&r)?;
        ensure!(
            r.fingerprint() == &record.release_fingerprint,
            "candidate source changed after admission preparation"
        );
        let identity = record
            .guests
            .get(&name)
            .context("domain is not in the prepared candidate")?;
        let directory = self.state.join("admissions");
        let mut file = tempfile::NamedTempFile::new_in(directory)?;
        use std::io::Write;
        serde_json::to_writer(file.as_file_mut(), identity)?;
        file.flush()?;
        self.store().receive(&name, caller, file.path())
    }
}
