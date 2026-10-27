//! Selection describes intent, not applied configuration. Recovery always compares
//! the journal's immutable endpoints and reobserves external state before mutation.

use super::*;
use airlock_deployment_core::{
    operation::{AuthorityBinding, OperationId, PreviousOperation},
    recovery::{self, RecoveryDecision},
};

/// Project a loaded, fingerprint-checked release into the verified decision boundary.
pub(super) fn release(r: &Release) -> Result<recovery::Release> {
    Ok(recovery::Release {
        path: r
            .path
            .to_str()
            .context("non-UTF8 recovery release")?
            .to_owned(),
        fingerprint: r.fingerprint().as_str().to_owned(),
    })
}

/// Decode evidence without granting it execution authority; legacy journals fail closed.
pub(super) fn journal(record: &Record) -> Result<recovery::Journal> {
    let native = record.metadata.origin.require_native()?;
    Ok(recovery::Journal {
        attempt: record.id.as_str().to_owned(),
        operation: record
            .metadata
            .details
            .operation
            .as_ref()
            .map(|o| -> Result<_> {
                Ok(PreviousOperation {
                    id: OperationId::new(o.id.as_str().to_owned()),
                    authority: AuthorityBinding::new(serde_json::to_string(&o.authority)?),
                })
            })
            .transpose()?,
        candidate: match record
            .metadata
            .details
            .operation
            .as_ref()
            .map(|o| &o.authority)
        {
            Some(OperationAuthority::Reviewed {
                release,
                fingerprint,
                ..
            }) => Some(recovery::Release {
                path: release.to_string(),
                fingerprint: fingerprint.to_string(),
            }),
            _ => None,
        },
        release: recovery::Release {
            path: record.release.to_string(),
            fingerprint: native.release_fingerprint.to_string(),
        },
        previous: recovery::Release {
            path: record.previous.to_string(),
            fingerprint: native.previous_fingerprint.to_string(),
        },
        plan: super::approval::record_plan_binding(record)?,
        progress: match record.phase {
            Phase::Complete => recovery::Progress::Complete,
            Phase::RebootRequired => recovery::Progress::RebootRequired,
            _ => recovery::Progress::Interrupted,
        },
    })
}

impl Coordinator {
    /// Fail closed if an affected VM was restarted after planning or a shutdown outcome was uncertain.
    /// The union includes halted-at-planning targets removed from the explicit stop list.
    pub(super) fn require_quiescent(&self, record: &Record) -> Result<()> {
        let required: BTreeSet<_> = record
            .plan
            .changed
            .iter()
            .chain(&record.plan.affected)
            .chain(&record.plan.retire)
            .chain(&record.plan.stop)
            .map(ToString::to_string)
            .collect();
        let active: Vec<_> = self
            .deployment_running()?
            .iter()
            .map(ToString::to_string)
            .collect();
        ensure!(
            recovery::quiescent(&required.into_iter().collect::<Vec<_>>(), &active),
            "deployment VM state changed or shutdown is incomplete; reconcile before configuration"
        );
        Ok(())
    }

    /// Validate selected intent independently of progress; it cannot select the recovery baseline.
    pub(super) fn recovery_decision(
        &self,
        record: &Record,
        mode: ApplyMode,
    ) -> Result<RecoveryDecision> {
        let mode = match mode {
            ApplyMode::Resume => recovery::Mode::Resume,
            ApplyMode::Rollback => recovery::Mode::Rollback,
            ApplyMode::New => bail!("recovery mode required"),
        };
        let selected = self
            .selection()?
            .map(|s| -> Result<_> {
                let saved = self.record(&s.transaction)?;
                let loaded = Release::load(s.release.as_path())?;
                loaded.trust()?;
                self.check_recorded_release(&loaded, &saved)?;
                ensure!(
                    s.profile == loaded.manifest.profile,
                    "selected recovery profile differs"
                );
                Ok(recovery::Selection {
                    attempt: s.transaction.as_str().to_owned(),
                    release: s.release.to_string(),
                    previous: s.previous.to_string(),
                    journal: journal(&saved)?,
                })
            })
            .transpose()?;
        let bootstrap = self.state.join("baseline");
        RecoveryDecision::reconcile(
            journal(record)?,
            selected.as_ref(),
            bootstrap.to_str().context("non-UTF8 baseline")?,
            mode,
        )
        .context("conflicting or ambiguous deployment recovery records")
    }
}
