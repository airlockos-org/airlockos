//! Derive a parameter-only request from the reviewed checkout and deployed source.
//! Git supplies the immutable tree comparison. Dom0 owns the selected runtime
//! settings and the authority to plan or apply changes to that selection.

use super::*;
use airlock_firewall_parameters::{Limits, MAX_DOCUMENT_BYTES};
use airlock_nix_core::runtime::protocol::{
    FIREWALL_SETTINGS_FILE, FirewallSettingsSchema, FirewallSettingsUpdate,
};

/// Read a bounded regular file from the commit itself, independent of the worktree.
fn settings(repo: &str, revision: &GitRevision) -> Result<Option<Limits>> {
    let tree = process::output(
        "git",
        &[
            "--no-replace-objects",
            "-C",
            repo,
            "ls-tree",
            revision.as_str(),
            "--",
            FIREWALL_SETTINGS_FILE,
        ],
    )?;
    if !tree.starts_with(b"100644 blob ") {
        return Ok(None);
    }

    let object = format!("{revision}:{FIREWALL_SETTINGS_FILE}");
    let size: usize = process::text(
        "git",
        &[
            "--no-replace-objects",
            "-C",
            repo,
            "cat-file",
            "-s",
            &object,
        ],
    )?
    .parse()
    .map_err(|_| Error::Message("invalid Git object size".into()))?;
    require(
        (1..=MAX_DOCUMENT_BYTES).contains(&size),
        "firewall parameter document is outside its size bound",
    )?;
    let bytes = process::output(
        "git",
        &[
            "--no-replace-objects",
            "-C",
            repo,
            "cat-file",
            "blob",
            &object,
        ],
    )?;
    require(bytes.len() == size, "Git object size changed")?;
    Ok(Some(decode(&bytes)?))
}

/// Both full trees must be locally available and differ in exactly the data file.
fn parameter_delta(
    repo: &str,
    baseline: &SourceIdentity,
    candidate: &SourceIdentity,
) -> Result<Option<(Limits, Limits)>> {
    if baseline.lock_hash != candidate.lock_hash || baseline.revision == candidate.revision {
        return Ok(None);
    }

    if process::output(
        "git",
        &[
            "--no-replace-objects",
            "-C",
            repo,
            "cat-file",
            "-e",
            &format!("{revision}^{{commit}}", revision = baseline.revision),
        ],
    )
    .is_err()
    {
        return Ok(None);
    }

    let comparison = process::run(
        Command::new("git").args([
            "--no-replace-objects",
            "-C",
            repo,
            "diff-tree",
            "--quiet",
            "--no-renames",
            "--no-ext-diff",
            "--no-textconv",
            "--ignore-submodules=none",
            "-r",
            baseline.revision.as_str(),
            candidate.revision.as_str(),
            "--",
            ".",
            &format!(":(top,exclude){FIREWALL_SETTINGS_FILE}"),
        ]),
        None,
        None,
    )?;
    if comparison.status.code() == Some(1) {
        return Ok(None);
    }
    comparison.checked("compare committed source outside the firewall settings file")?;

    let before = settings(repo, &baseline.revision)?;
    let after = settings(repo, &candidate.revision)?;
    Ok(before.zip(after).filter(|(before, after)| before != after))
}

/// Submit a typed settings update through the existing machine endpoint when eligible.
pub(super) fn execute(grant: &Grant, lock: &OperationLock, profile: &str) -> Result<Option<Value>> {
    // The physical machine owns this declared parameter data. The embedded
    // QEMU profile has its own independent topology and configuration.
    if profile != "usb-lab" {
        return Ok(None);
    }
    let status = process::rpc(
        "airlock.Ctrl.MachineControl",
        &json!({"schema":"airlock.machine-control.v1","action":"status"}),
        None,
    )?;
    let Some(source) = status["firewall_parameters"]["sys-firewall"].get("settings_source") else {
        return Ok(None);
    };
    let baseline: SourceIdentity = serde_json::from_value(source.clone())?;
    let candidate = grant.header.source();
    let Some((before, after)) =
        parameter_delta("/home/user/dev/airlockos-machine", &baseline, &candidate)?
    else {
        return Ok(None);
    };

    grant.check(lock)?;
    let request = FirewallSettingsUpdate {
        schema: FirewallSettingsSchema::V1,
        baseline,
        candidate,
        before,
        after,
        review_authorization: grant.id.clone(),
    };
    let service = if grant.header.action.is_plan() {
        "airlock.Ctrl.MachinePlan"
    } else {
        "airlock.Ctrl.MachineApply"
    };
    let result = progress::phase("planning_firewall_settings", || {
        process::rpc(service, &request, None)
    })?;
    check_plan(&result, grant)?;
    Ok(Some(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compare real committed files, including a mixed change with the same lock.
    #[test]
    fn only_a_changed_parameter_document_qualifies() -> Result<()> {
        let work = tempfile::tempdir()?;
        let repo = work.path().to_str().unwrap();
        let git = |args: &[&str]| {
            let mut argv = vec!["-C", repo];
            argv.extend_from_slice(args);
            process::text("git", &argv)
        };
        git(&["init", "-q"])?;
        let commit = || -> Result<SourceIdentity> {
            git(&["add", "--all"])?;
            git(&[
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "user.name=Fixture",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-qm",
                "Fixture commit",
            ])?;
            Ok(SourceIdentity {
                revision: git(&["rev-parse", "HEAD"])?.parse()?,
                lock_hash: "a".repeat(64).parse()?,
            })
        };
        let source = work.path().join(FIREWALL_SETTINGS_FILE);
        let mut parameters = *Limits::defaults().document();
        fs::write(&source, serde_json::to_vec(&parameters)?)?;
        let baseline = commit()?;

        parameters.report_interval_seconds = 15;
        fs::write(&source, serde_json::to_vec(&parameters)?)?;
        let candidate = commit()?;
        let (before, after) = parameter_delta(repo, &baseline, &candidate)?.unwrap();
        assert_eq!(before.document().report_interval_seconds, 30);
        assert_eq!(after.document().report_interval_seconds, 15);

        fs::write(work.path().join("other-config"), "other configuration")?;
        let mixed = commit()?;
        assert!(parameter_delta(repo, &baseline, &mixed)?.is_none());
        Ok(())
    }
}
