//! A host boot restores its own release, journal and guest-generation snapshot.
//! All evidence is checked before publication. Stage one always replays these writes
//! before handing control to runtime coordination; partial publication never attests completion.
//! Pool/machine exclusion, filesystem truth, canonical decoding and SHA-256 remain trusted.

use super::{HostReceipt, fs::*, host, records};
use crate::{
    model::{ReleaseFingerprint, Selection},
    state,
};
use airlock_deployment_core::host::boot::{self, Effect, Restoration, RestoreRequest};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{
    fs,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
};

mod wire;

use wire::{BootBinding, Generations, Status};

/// A host's positive generation selects its binding, never a field from that binding itself.
fn binding_path(storage: &Path, receipt: &HostReceipt) -> PathBuf {
    storage
        .join("generations")
        .join(receipt.generation.to_string())
        .join("machine.json")
}

/// Map a protected logical release into this root without allowing a symlink escape.
fn release_path(machine: &Path, logical_machine: &Path, selection: &Selection) -> Result<PathBuf> {
    let relative = selection.release.as_path().strip_prefix(logical_machine)?;
    ensure!(
        !relative.as_os_str().is_empty(),
        "boot release is not a candidate"
    );
    let release = machine.join(relative);
    let canonical_machine = fs::canonicalize(machine)?;
    let canonical_release = fs::canonicalize(&release)?;
    ensure!(
        canonical_release.starts_with(&canonical_machine) && canonical_release == release,
        "boot release escapes its machine state"
    );
    Ok(release)
}

/// Load a complete release plus the independently addressed journal and staged map.
fn evidence(
    machine: &Path,
    logical_machine: &Path,
    selection: &Selection,
) -> Result<boot::Release> {
    let release = state::Release::load(&release_path(machine, logical_machine, selection)?)?;
    let staged: Generations = state::read(&release.path.join("staged.json"))?;
    let status: Status = state::read(
        &machine
            .join("transactions")
            .join(selection.transaction.as_str())
            .join("status.json"),
    )?;

    Ok(boot::Release {
        path: selection.release.to_string(),
        host: release.manifest.host.to_string(),
        profile: release.manifest.profile.to_string(),
        fingerprint: release.fingerprint().to_string(),
        declared: wire::guests(&release.manifest.staged_generations)?,
        staged: wire::guests(&staged)?,
        status: status.verified()?,
    })
}

/// Candidate binding may precede final status; a baseline checkpoint must already be restorable.
enum Publication {
    /// Current authorised candidate, immediately before final boot selection.
    Candidate,
    /// Preserve the running host's completed baseline, never an interrupted selection.
    Checkpoint,
}

pub(super) fn save(
    root: &Path,
    storage: &Path,
    machine: &Path,
    receipt: &HostReceipt,
) -> Result<()> {
    publish_snapshot(root, storage, machine, receipt, Publication::Candidate).map(|_| ())
}

/// Preserve an existing boot binding when the running host has an unfinished live selection.
pub(super) fn checkpoint(
    root: &Path,
    storage: &Path,
    machine: &Path,
    receipt: &HostReceipt,
) -> Result<bool> {
    publish_snapshot(root, storage, machine, receipt, Publication::Checkpoint)
}

/// Capture one typed host identity; only the candidate path can snapshot the precommit phase.
fn publish_snapshot(
    root: &Path,
    storage: &Path,
    machine: &Path,
    receipt: &HostReceipt,
    publication: Publication,
) -> Result<bool> {
    let boot = receipt.observation()?;
    let selection: Option<Selection> = state::optional(&machine.join("selection.json"))?;
    let release = selection
        .as_ref()
        .map(|s| evidence(machine, machine, s))
        .transpose()?;
    let staged: Generations = if let Some(s) = &selection {
        state::read(&release_path(machine, machine, s)?.join("staged.json"))?
    } else {
        let mut staged = Generations::new();
        for directory in children(&root.join("domains"))? {
            let name = directory
                .file_name()
                .and_then(|s| s.to_str())
                .context("invalid domain directory")?;
            if let Some(domain) = name.strip_suffix("-runtime-store")
                && let Some(generation) = records::current(root, name)?
            {
                staged.insert(domain.parse()?, generation.to_string().parse()?);
            }
        }
        staged
    };
    let fingerprint: Option<ReleaseFingerprint> = release
        .as_ref()
        .map(|r| r.fingerprint.parse())
        .transpose()?;
    let binding = BootBinding::Current {
        system: receipt.system.clone(),
        generation: receipt.generation,
        host_record: receipt.binding()?,
        selection,
        release_fingerprint: fingerprint,
        staged,
    };
    let checked = binding.verified()?;
    if matches!(publication, Publication::Checkpoint) {
        if Restoration::reconcile(&checked, &boot, release.as_ref()).is_none() {
            return Ok(false);
        }
    } else {
        ensure!(
            boot::snapshot(&checked, &boot, release.as_ref()),
            "inconsistent machine boot snapshot"
        );
    }

    write(&binding_path(storage, receipt), &binding, 0o600)?;
    Ok(true)
}

pub(super) fn restore(sysroot: &Path, receipt: &HostReceipt) -> Result<()> {
    restore_with(sysroot, receipt, |_| Ok(()))
}

/// The hook represents interruption before publication or immediately after a durable effect.
/// Production supplies a no-op; tests replay the same production loop after each interruption.
fn restore_with(
    sysroot: &Path,
    receipt: &HostReceipt,
    mut boundary: impl FnMut(usize) -> Result<()>,
) -> Result<()> {
    let storage = sysroot.join(host::HOST.trim_start_matches('/'));
    let machine = sysroot.join(host::MACHINE.trim_start_matches('/'));
    let boot = receipt.observation()?;
    let path = binding_path(&storage, receipt);
    let Some(binding) = state::optional::<BootBinding>(&path)? else {
        ensure!(
            receipt.generation.get() == 1
                && state::optional::<Selection>(&machine.join("selection.json"))?.is_none()
                && state::optional::<Value>(&machine.join("latest.json"))?.is_none()
                && state::optional::<Generations>(&storage.join("boot-staged.json"))?.is_none(),
            "host generation has no machine boot binding"
        );
        // Initial images may precede machine transactions. No restoration authority is created.
        return Ok(());
    };
    let release = binding
        .selection()
        .map(|s| evidence(&machine, Path::new(host::MACHINE), s))
        .transpose()?;
    let checked = binding.verified()?;
    let mut plan = Restoration::reconcile(&checked, &boot, release.as_ref())
        .context("inconsistent or incomplete machine boot binding; use independent recovery")?;

    boundary(0)?;
    mkdir_all(&machine)?;
    let mut completed = 0;
    while let Some(effect) = plan.next_effect() {
        apply(&machine, &storage, effect)?;
        completed += 1;
        boundary(completed)?;
    }
    Ok(())
}

/// Publish only payloads chosen by the verified restoration plan. Errors stop stage one.
/// Successful replay overwrites the same documents and link; it never copies private guest data.
fn apply(machine: &Path, storage: &Path, request: RestoreRequest) -> Result<()> {
    match request.into_effect() {
        Effect::Selection(document) => publish(&machine.join("selection.json"), document),
        Effect::Latest(document) => publish(&machine.join("latest.json"), document),
        Effect::Guests(document) => publish(&storage.join("boot-staged.json"), Some(document)),
        Effect::Controller(system) => {
            let temporary = machine.join("controller.new");
            match fs::remove_file(&temporary) {
                Ok(()) => (),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(error.into()),
            }
            symlink(format!("{system}/sw/bin/airlock-dom0-service"), &temporary)?;
            fs::rename(temporary, machine.join("controller"))?;
            sync_dir(machine)
        }
    }
}

/// Both creation and removal are durable before the next publication is requested.
fn publish(path: &Path, document: Option<String>) -> Result<()> {
    if let Some(document) = document {
        atomic(path, format!("{document}\n").as_bytes(), 0o644)
    } else {
        match fs::remove_file(path) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
        sync_dir(path.parent().context("publication has no parent")?)
    }
}

#[cfg(test)]
mod tests;
