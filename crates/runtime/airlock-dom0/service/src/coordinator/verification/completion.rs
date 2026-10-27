//! Both deployment publishers consume the same checked guest observations.
//! Historical journals retain their existing runtime checks without acquiring the v3 theorem.

use super::*;
use airlock_deployment_core::completion::{self, VerifiedGuests};

/// Internal distinction between exact journal-v3 evidence and historical compatibility checks.
enum Evidence {
    /// The Verus production decision accepted all topology coordinates and original pins.
    Journal(VerifiedGuests),
    /// An older journal has no full target snapshot; existing manifest/runtime checks passed.
    Historical,
}

/// Completion for one journal, fingerprinted target and host boot; callers cannot fabricate it.
pub(in crate::coordinator) struct VerifiedDeployment {
    // Proof result, or the explicitly separate historical compatibility policy.
    evidence: Evidence,
    // Attempt whose machine observations were collected.
    attempt: TransactionId,
    // Release path and immutable fingerprint checked with those observations.
    target: String,
    // Host boot in which all probes ran.
    boot: BootId,
    // Original status projection, retained rather than independently resupplied by the publisher.
    observed: BTreeMap<GuestName, Observation>,
}

/// Determine compatibility from the decoded version, never from a missing or malformed snapshot.
fn pinned(record: &Record) -> bool {
    match &record.metadata.origin {
        JournalOrigin::Native(n) => match n.native_coordinator {
            NativeVersion::V3 => true,
            NativeVersion::V1 | NativeVersion::V2 => false,
        },
        JournalOrigin::Legacy {} => false,
    }
}

impl VerifiedDeployment {
    /// Recheck original bindings and let verified Rust choose complete versus awaiting host reboot.
    pub(in crate::coordinator) fn phase(
        &self,
        coordinator: &Coordinator,
        release: &Release,
        record: &Record,
        host: &StorePath,
    ) -> Result<Phase> {
        coordinator.check_recorded_release(release, record)?;
        let target = super::super::staging::target(&record.release, release.fingerprint())?;
        let boot = state::boot_id()?;
        ensure!(
            record.id == self.attempt && target == self.target && boot == self.boot,
            "deployment completion context changed"
        );
        match &self.evidence {
            Evidence::Journal(checked) => {
                ensure!(pinned(record), "journal completion policy changed");
                let status = checked
                    .status(
                        &super::super::approval::effect_context(record)?,
                        &target,
                        boot.as_str(),
                        host.as_str(),
                    )
                    .context("deployment completion identity or host boot changed")?;
                Ok(match status {
                    completion::Status::Complete => Phase::Complete,
                    completion::Status::RebootRequired => Phase::RebootRequired,
                })
            }
            Evidence::Historical => {
                ensure!(
                    !pinned(record),
                    "v3 completion requires exact journal generation evidence"
                );
                Ok(if host == &release.manifest.host {
                    Phase::Complete
                } else {
                    Phase::RebootRequired
                })
            }
        }
    }
}

impl Coordinator {
    /// Collect existing runtime probes and require exact, complete v3 journal correspondence.
    pub(in crate::coordinator) fn verify_deployment(
        &self,
        release: &Release,
        record: &mut Record,
        required: &BTreeSet<GuestName>,
    ) -> Result<VerifiedDeployment> {
        self.check_recorded_release(release, record)?;
        let boot = state::boot_id()?;
        let target = super::super::staging::target(&record.release, release.fingerprint())?;
        let input = if pinned(record) {
            Some(completion::Inputs {
                context: super::super::approval::effect_context(record)?,
                target: target.clone(),
                boot: boot.as_str().to_owned(),
                host: release.manifest.host.to_string(),
                definitions: crate::setup_config::backend::definitions(
                    &release.raw_topology,
                    "",
                    &release.manifest.staged_generations,
                )?,
                stage: record.plan.stage.iter().map(ToString::to_string).collect(),
                running: required.iter().map(ToString::to_string).collect(),
                snapshot: super::super::staging::current_snapshot(record)?,
            })
        } else {
            None
        };

        let (observed, facts) = self.observe_topology(release, required)?;
        let evidence = match input {
            Some(input) => Evidence::Journal(VerifiedGuests::check(input, &facts).context(
                "deployment guest observations differ from journal selections or required coverage",
            )?),
            None => Evidence::Historical,
        };

        // Preserve progress diagnostics, but publish success only through the opaque result below.
        record.observed = observed.clone();

        Ok(VerifiedDeployment {
            evidence,
            attempt: record.id.clone(),
            target,
            boot,
            observed,
        })
    }

    /// Publish success and enable maintenance only after consuming checked completion evidence.
    pub(in crate::coordinator) fn complete_deployment(
        &self,
        release: &Release,
        record: &mut Record,
        lock: &mut MachineLock,
        verified: VerifiedDeployment,
    ) -> Result<()> {
        release.recheck()?;
        let host = state::host()?;
        let phase = verified.phase(self, release, record, &host)?;
        record.observed = verified.observed.clone();
        record.host_running = Some(host);
        record.host_selected = Some(release.manifest.host.clone());
        record.verified_at = Some(state::now());
        self.publish_phase(record, phase, lock)?;
        self.record_verified(release, record, &verified)
    }
}
