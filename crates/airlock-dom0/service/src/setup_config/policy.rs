//! Publish the verified topology-policy bytes and acknowledge the upstream service refresh.
//! Static/bootstrap policy and Qubes' first-match evaluation remain separate. The acknowledgment
//! proves neither the daemon's internal cache contents nor a revocation fence for in-flight RPCs.
//!
//! Normal setup preparation (including boot, resume and rollback) and the explicit administrative
//! `setup-config policy` command converge here. The latter and environment path overrides retain
//! their administrative trust boundary; they do not acquire a human-review authorization theorem.
//! These policy types do not themselves bind a deployment approval, candidate or saved plan;
//! coordinator authorization and protected configuration loading remain separate boundaries.
//! Machine authoring and runtime share the daemon's default directory/filename contract. An
//! administrator changing those paths must also configure Qubes to read them.
//!
//! The guarded sequence is checked declarations -> exact text -> file fsync -> rename -> parent
//! fsync -> matching readback -> fixed service refresh -> running-service observation -> matching
//! readback. No JSON acknowledgment is trusted on retry. Own writers serialize through a stable
//! lock; trusted directory ownership, external root writers and the kernel remain assumptions.
//! Injected errors model interruptions
//! at the actual I/O boundaries, not power-loss behavior or exactly-once execution.
//!
//! Immutable bootstrap/diagnostics rules, Nix normalization's terminal denials, static-link refresh
//! during daemon bootstrap and Qubes' complete ordered-policy evaluation are outside these proofs.
//! The bootstrap placeholder uses the same verified empty header, without claiming a live refresh.

use crate::process::Runner;
use airlock_machine_planning::ipc_policy::{
    CheckedPolicy, Declaration, Installation, PolicyPaths, PublishedPolicy, RefreshKind,
    RefreshOutcome, RefreshRequest,
};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::Value;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    time::Duration,
};

const MARKER: &str = "# Managed by Airlock setup-config.";

const LIMIT: u64 = 4 * 1024 * 1024;

/// Decode directly into the raw fields consumed by Verus; there is no second rule projection.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePolicy {
    // Complete ordered declaration list; malformed/missing arrays cannot default to an empty policy.
    rules: Vec<Declaration>,
}

/// Legacy omitted/null policy means no topology-owned rules; present policies must decode completely.
fn checked(topology: &Value) -> Result<CheckedPolicy> {
    let raw = match topology.get("qrexec_policy") {
        None | Some(Value::Null) => Vec::new(),
        Some(value) => {
            serde_json::from_value::<WirePolicy>(value.clone())
                .context("invalid topology qrexec policy")?
                .rules
        }
    };
    CheckedPolicy::decode(raw).context("unsupported or unsafe topology qrexec policy rule")
}

/// Resolve parent aliases without following the final file, including missing descendant directories.
fn coordinate(path: &Path) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    ensure!(
        path.components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "noncanonical policy path"
    );
    let name = path.file_name().context("policy path has no filename")?;
    let parent = path.parent().context("policy path has no parent")?;
    let mut ancestor = parent;
    while !ancestor.try_exists()? {
        ancestor = ancestor
            .parent()
            .context("policy parent has no existing ancestor")?;
    }
    Ok(fs::canonicalize(ancestor)?
        .join(parent.strip_prefix(ancestor)?)
        .join(name))
}

/// Persist newly created directory names as well as their contents.
fn directory(path: &Path) -> Result<()> {
    let mut missing = Vec::new();
    let mut ancestor = path;
    while !ancestor.try_exists()? {
        missing.push(ancestor.to_owned());
        ancestor = ancestor
            .parent()
            .context("policy directory has no ancestor")?;
    }
    fs::create_dir_all(path)?;
    for created in missing {
        File::open(&created)?.sync_all()?;
        File::open(created.parent().context("policy directory parent")?)?.sync_all()?;
    }
    Ok(())
}

/// Exclude concurrent Airlock writers until publication, refresh and final readback have completed.
struct PolicyLock {
    // Open descriptor retains exclusion across rename and service operations.
    file: File,
    // Stable, hidden lock name; Qubes does not interpret it as a policy file.
    path: PathBuf,
}

impl PolicyLock {
    /// Never follow a lock symlink or wait indefinitely for a competing setup process.
    fn acquire(path: PathBuf) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .open(&path)?;
        ensure!(
            file.metadata()?.is_file(),
            "policy lock is not a regular file"
        );
        file.try_lock()
            .context("topology policy writer is already active")?;
        let lock = Self { file, path };
        lock.check()?;
        Ok(lock)
    }

    /// Detect replacement of the name holding our exclusion; external administrators remain unsynchronized.
    fn check(&self) -> Result<()> {
        let held = self.file.metadata()?;
        let named = fs::symlink_metadata(&self.path)?;
        ensure!(
            named.is_file() && held.dev() == named.dev() && held.ino() == named.ino(),
            "policy lock was replaced"
        );
        Ok(())
    }
}

impl Drop for PolicyLock {
    fn drop(&mut self) {
        // Close-on-exec does not close a descriptor during the fork-to-exec window.
        // Release this completed lease explicitly even if another process inherited it.
        let _ = self.file.unlock();
    }
}

/// Read one bounded, independently owned policy without following links or blocking on special files.
fn current(target: &Path) -> Result<Option<String>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(target)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.nlink() == 1 && metadata.mode() & 0o022 == 0,
        "policy is not a protected regular file"
    );
    let mut text = String::new();
    file.take(LIMIT + 1).read_to_string(&mut text)?;
    ensure!(text.len() as u64 <= LIMIT, "policy exceeds size limit");
    ensure!(
        text.lines().next() == Some(MARKER),
        "qrexec policy file exists but is not Airlock-managed: {target}",
        target = target.display()
    );
    Ok(Some(text))
}

/// Deterministic interruption points around actual publication and external service operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Boundary {
    /// No policy publication has begun.
    BeforePublication,
    /// The private, ignored temporary file contains the complete policy.
    Written,
    /// Policy bytes and mode were fsynced before exposing the final name.
    FileSynced,
    /// The final name has changed, but its directory has not yet been fsynced.
    Renamed,
    /// Directory fsync acknowledged durable publication.
    DirectorySynced,
    /// Publication readback passed; no refresh has been dispatched.
    BeforeRefresh,
    /// The refresh command and active-service query succeeded, before final policy readback.
    Refreshed,
}

/// Keep the active path whole and expose only fsynced policy bytes through its final name.
fn atomic(
    target: &Path,
    text: &str,
    checkpoint: &mut impl FnMut(Boundary) -> Result<()>,
) -> Result<()> {
    let parent = target.parent().context("policy parent")?;
    directory(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o644))?;
    temporary.write_all(text.as_bytes())?;
    checkpoint(Boundary::Written)?;
    temporary.as_file().sync_all()?;
    checkpoint(Boundary::FileSynced)?;
    temporary.persist(target).map_err(|error| error.error)?;
    checkpoint(Boundary::Renamed)?;
    File::open(parent)?.sync_all()?;
    checkpoint(Boundary::DirectorySynced)?;
    Ok(())
}

/// The only adapter constructor of publication evidence follows all durability barriers and readback.
fn publish(
    installation: Installation,
    checkpoint: &mut impl FnMut(Boundary) -> Result<()>,
) -> Result<PublishedPolicy> {
    checkpoint(Boundary::BeforePublication)?;
    atomic(
        Path::new(installation.target()),
        installation.text(),
        checkpoint,
    )?;
    let target = installation.target().to_owned();
    let observed = current(Path::new(&target))?.context("published policy disappeared")?;
    installation
        .published(&target, &observed)
        .context("published policy differs from the checked policy")
}

/// Keep external command outcomes separate from the verified policy and its exact publication binding.
trait Service {
    /// Request only the fixed service/operation arguments selected by the verified request.
    fn refresh(&mut self, request: &RefreshRequest, kind: RefreshKind) -> Result<bool>;

    /// Observe that same upstream daemon after refresh; try-restart of an inactive daemon is insufficient.
    fn active(&mut self, request: &RefreshRequest) -> Result<bool>;
}

/// Thin upstream systemd adapter; it cannot accept an independent service name or policy payload.
struct Systemd;

impl Service for Systemd {
    fn refresh(&mut self, request: &RefreshRequest, kind: RefreshKind) -> Result<bool> {
        let args = request
            .arguments(kind)
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>();
        let output = Runner::default().capture("systemctl", &args, Duration::from_secs(60), &[])?;
        Ok(!output.limited && output.status.success())
    }

    fn active(&mut self, request: &RefreshRequest) -> Result<bool> {
        let args = request
            .active_arguments()
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>();
        let output = Runner::default().capture("systemctl", &args, Duration::from_secs(60), &[])?;
        Ok(!output.limited && output.status.success())
    }
}

/// Selected execution destinations; reporting can borrow them but cannot reconstruct this binding.
pub(super) struct Paths {
    // Verified role binding, retained through preview creation and publication selection.
    binding: PolicyPaths,
}

impl Paths {
    /// Select the configured target and its setup-local informational preview.
    pub(super) fn configured(logs: &Path) -> Result<Self> {
        let target = configured_target()?;
        let name = target
            .file_name()
            .and_then(|name| name.to_str())
            .context("policy filename")?;
        Self::new(&target, &logs.join(format!("{name}.rendered")))
    }

    /// Preserve native path roles; alias and daemon-directory checks remain at the I/O boundary.
    pub(super) fn new(target: &Path, rendered: &Path) -> Result<Self> {
        let target = target
            .to_str()
            .context("policy target is not UTF-8")?
            .to_owned();
        let rendered = rendered
            .to_str()
            .context("policy preview is not UTF-8")?
            .to_owned();
        Ok(Self {
            binding: PolicyPaths::new(target, rendered)
                .context("policy target and preview must be nonempty and distinct")?,
        })
    }

    /// Exact selected installation destination, independent of diagnostic JSON.
    pub(super) fn target(&self) -> &Path {
        Path::new(self.binding.target())
    }

    /// Exact selected informational output, independent of diagnostic JSON.
    pub(super) fn rendered(&self) -> &Path {
        Path::new(self.binding.rendered())
    }

    /// Resolve both destinations together, then retain their distinct roles at publication.
    fn canonical(&self) -> Result<Self> {
        Self::new(&coordinate(self.target())?, &coordinate(self.rendered())?)
    }
}

/// The installed daemon path contract; explicit overrides retain the administrative trust boundary.
fn configured_target() -> Result<PathBuf> {
    let directory = std::env::var_os("AIRLOCK_QUBES_POLICY_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| airlock_machine_core::services::policy_directory().into());
    let name = std::env::var("AIRLOCK_QUBES_MANAGED_POLICY_FILE")
        .unwrap_or_else(|_| airlock_machine_core::services::policy_filename().into());
    ensure!(
        Path::new(&name)
            .file_name()
            .is_some_and(|filename| filename == name.as_str()),
        "invalid managed policy filename"
    );
    Ok(directory.join(name))
}

/// Refresh even an unchanged file: a previous attempt may have crashed after rename or failed reload.
fn reconcile_paths(
    topology: &Value,
    paths: &Paths,
    apply: bool,
    service: &mut impl Service,
    checkpoint: &mut impl FnMut(Boundary) -> Result<()>,
) -> Result<bool> {
    let policy = checked(topology)?;
    ensure!(
        policy.text().len() as u64 <= LIMIT,
        "rendered policy exceeds size limit"
    );
    let paths = paths.canonical()?;
    let target = paths.target();
    let rendered = paths.rendered();
    let filename = target
        .file_name()
        .and_then(|name| name.to_str())
        .context("policy filename")?;
    ensure!(
        !filename.starts_with('.')
            && filename.ends_with(".policy")
            && filename
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte)),
        "target must be a visible .policy file"
    );
    let parent = target.parent().context("policy parent")?;
    let lock_path = parent.join(format!(".{filename}.lock"));
    ensure!(
        rendered != target
            && rendered != lock_path
            && !(rendered.parent() == target.parent()
                && rendered
                    .extension()
                    .is_some_and(|extension| extension == "policy")),
        "policy preview must not replace an active policy or writer lock"
    );
    let lock = if apply {
        directory(parent)?;
        Some(PolicyLock::acquire(lock_path)?)
    } else {
        None
    };
    let old = current(target)?;
    let changed = old.as_deref() != Some(policy.text());
    // Atomic preview publication also avoids following an existing preview symlink/hard link.
    atomic(rendered, policy.text(), &mut |_| Ok(()))?;
    if !apply {
        return Ok(changed);
    }
    let lock = lock.as_ref().context("policy writer lock")?;
    lock.check()?;
    let installation = paths.binding.installation(policy);
    let request = publish(installation, checkpoint)?.request();
    checkpoint(Boundary::BeforeRefresh)?;
    let refreshed = service.refresh(&request, RefreshKind::Reload)?
        || service.refresh(&request, RefreshKind::Restart)?;
    ensure!(
        refreshed && service.active(&request)?,
        "qrexec policy refresh failed or daemon is inactive"
    );
    checkpoint(Boundary::Refreshed)?;
    lock.check()?;
    let target_text = request.target().to_owned();
    let observed =
        current(Path::new(&target_text))?.context("policy disappeared during refresh")?;
    let _acknowledged = request
        .complete(&target_text, &observed, RefreshOutcome::Running)
        .context("policy changed during refresh; retry from checked publication")?;
    Ok(changed)
}

/// Validate the entire policy, durably publish its exact encoding, and require a running refreshed daemon.
/// The return value reports byte changes; even false still requires refresh acknowledgment in apply mode.
pub(super) fn reconcile(topology: &Value, paths: &Paths, apply: bool) -> Result<bool> {
    // Preserve the installed daemon's path check for both setup and explicit administrative callers.
    ensure!(
        coordinate(paths.target())? == coordinate(&configured_target()?)?,
        "policy target differs from the configured daemon policy file"
    );
    reconcile_paths(topology, paths, apply, &mut Systemd, &mut |_| Ok(()))
}

/// Keep interruption scenarios focused on real I/O while exercising the typed production boundary.
#[cfg(test)]
fn reconcile_with(
    topology: &Value,
    rendered: &Path,
    target: &Path,
    apply: bool,
    service: &mut impl Service,
    checkpoint: &mut impl FnMut(Boundary) -> Result<()>,
) -> Result<bool> {
    reconcile_paths(
        topology,
        &Paths::new(target, rendered)?,
        apply,
        service,
        checkpoint,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::symlink;

    /// One bounded allow plus a terminal denial; source identity remains literal throughout the path.
    fn topology() -> Value {
        json!({"qrexec_policy":{"rules":[
            {"service":"airlock.Test","argument":"*","source":"dom0","target":"usr-home","action":"allow"},
            {"service":"airlock.Test","argument":"*","source":"@anyvm","target":"@anyvm","action":"deny"}
        ]}})
    }

    /// Inert service adapter recording the same verified argument vectors used by systemd.
    struct Fake {
        // Whether reload is supported and acknowledged.
        reload: bool,
        // Whether try-restart exits successfully, independently of service activity.
        restart: bool,
        // Current service health observation.
        running: bool,
        // Fixed command vectors actually selected by the verified request.
        calls: Vec<Vec<String>>,
        // A privileged external change injected while observing the daemon.
        replace: Option<(PathBuf, String)>,
    }

    impl Default for Fake {
        fn default() -> Self {
            Self {
                reload: false,
                restart: true,
                running: true,
                calls: Vec::new(),
                replace: None,
            }
        }
    }

    impl Service for Fake {
        fn refresh(&mut self, request: &RefreshRequest, kind: RefreshKind) -> Result<bool> {
            self.calls.push(request.arguments(kind));
            Ok(match kind {
                RefreshKind::Reload => self.reload,
                RefreshKind::Restart => self.restart,
            })
        }

        fn active(&mut self, request: &RefreshRequest) -> Result<bool> {
            self.calls.push(request.active_arguments());
            if let Some((path, contents)) = self.replace.take() {
                fs::write(path, contents)?;
            }
            Ok(self.running)
        }
    }

    /// Every invalid declared row prevents filesystem and service effects, including unknown wire fields.
    /// A descriptor inherited during process creation must not prolong a completed writer lease.
    #[test]
    fn writer_lock_releases_even_with_an_inherited_descriptor() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join(".90-airlock.policy.lock");
        let lock = PolicyLock::acquire(path.clone())?;
        let inherited = lock.file.try_clone()?;
        drop(lock);

        let retry = PolicyLock::acquire(path)?;
        drop(inherited);
        drop(retry);
        Ok(())
    }

    #[test]
    fn invalid_or_unknown_rules_never_publish() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let target = temporary.path().join("90-airlock.policy");
        let preview = temporary.path().join("rendered");
        for invalid in [
            json!({"qrexec_policy":{"rules":null}}),
            json!({"qrexec_policy":{}}),
            json!({"qrexec_policy":{"rules":[{"service":"airlock.Test","argument":"*","source":"dom0","target":"usr-home","action":"allow","target_override":"dom0"}]}}),
            json!({"qrexec_policy":{"rules":[],"include":"other.policy"}}),
        ] {
            let mut fake = Fake::default();
            assert!(
                reconcile_with(
                    &invalid,
                    &preview,
                    &target,
                    true,
                    &mut fake,
                    &mut |_| Ok(())
                )
                .is_err()
            );
            assert!(!target.exists());
            assert!(!preview.exists());
            assert!(fake.calls.is_empty());
        }
        // Omitted policy retains the explicit legacy empty-policy contract.
        assert!(
            checked(&json!({}))?
                .text()
                .lines()
                .all(|line| line.starts_with('#'))
        );
        Ok(())
    }

    /// Plan mode creates only a preview; unmanaged policy and preview aliases cannot bypass checking.
    #[test]
    fn preview_cannot_replace_active_or_unmanaged_policy() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let target = temporary.path().join("90-airlock.policy");
        let preview = temporary.path().join("rendered");
        let mut fake = Fake::default();
        assert!(reconcile_with(
            &topology(),
            &preview,
            &target,
            false,
            &mut fake,
            &mut |_| Ok(())
        )?);
        assert!(!target.exists());
        assert!(fake.calls.is_empty());
        assert!(
            reconcile_with(
                &topology(),
                &target,
                &target,
                false,
                &mut fake,
                &mut |_| Ok(())
            )
            .is_err()
        );
        let alias = temporary.path().join("alias");
        symlink(temporary.path(), &alias)?;
        assert!(
            reconcile_with(
                &topology(),
                &alias.join("90-airlock.policy"),
                &target,
                false,
                &mut fake,
                &mut |_| Ok(())
            )
            .is_err()
        );
        fs::write(&target, "# administrator policy\n")?;
        assert!(
            reconcile_with(
                &topology(),
                &preview,
                &target,
                true,
                &mut fake,
                &mut |_| Ok(())
            )
            .is_err()
        );
        assert_eq!(fs::read_to_string(&target)?, "# administrator policy\n");
        Ok(())
    }

    /// Interrupt actual persistence operations and retry from fresh readback, never from a saved success flag.
    #[test]
    fn every_publication_interruption_has_a_safe_retry() -> Result<()> {
        for boundary in [
            Boundary::BeforePublication,
            Boundary::Written,
            Boundary::FileSynced,
            Boundary::Renamed,
            Boundary::DirectorySynced,
            Boundary::BeforeRefresh,
            Boundary::Refreshed,
        ] {
            let temporary = tempfile::tempdir()?;
            let target = temporary.path().join("90-airlock.policy");
            let preview = temporary.path().join("rendered");
            let old = checked(&json!({}))?.text().to_owned();
            fs::write(&target, &old)?;
            let mut fake = Fake::default();
            let result = reconcile_with(
                &topology(),
                &preview,
                &target,
                true,
                &mut fake,
                &mut |point| {
                    ensure!(point != boundary, "injected interruption at {point:?}");
                    Ok(())
                },
            );
            assert!(result.is_err(), "interruption at {boundary:?}");
            let expected = checked(&topology())?.text().to_owned();
            let observed = fs::read_to_string(&target)?;
            assert!(observed == old || observed == expected);
            if boundary != Boundary::Refreshed {
                assert!(fake.calls.is_empty());
            }
            fake.calls.clear();
            assert_eq!(
                reconcile_with(
                    &topology(),
                    &preview,
                    &target,
                    true,
                    &mut fake,
                    &mut |_| Ok(())
                )?,
                observed != expected
            );
            assert_eq!(fs::read_to_string(&target)?, expected);
            assert_eq!(fake.calls.len(), 3);
            fake.calls.clear();
            assert!(!reconcile_with(
                &topology(),
                &preview,
                &target,
                true,
                &mut fake,
                &mut |_| Ok(())
            )?);
            assert_eq!(fake.calls.len(), 3);
        }
        Ok(())
    }

    /// An inactive daemon, failed refresh or concurrent content substitution cannot acknowledge readiness.
    #[test]
    fn uncertain_or_conflicting_service_outcomes_cannot_complete() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let target = temporary.path().join("90-airlock.policy");
        let preview = temporary.path().join("rendered");
        let mut fake = Fake {
            running: false,
            ..Fake::default()
        };
        assert!(
            reconcile_with(
                &topology(),
                &preview,
                &target,
                true,
                &mut fake,
                &mut |_| Ok(())
            )
            .is_err()
        );
        fake.running = true;
        fake.restart = false;
        assert!(
            reconcile_with(
                &topology(),
                &preview,
                &target,
                true,
                &mut fake,
                &mut |_| Ok(())
            )
            .is_err()
        );
        fake.restart = true;
        fake.replace = Some((target.clone(), checked(&json!({}))?.text().to_owned()));
        assert!(
            reconcile_with(
                &topology(),
                &preview,
                &target,
                true,
                &mut fake,
                &mut |_| Ok(())
            )
            .is_err()
        );
        assert!(reconcile_with(
            &topology(),
            &preview,
            &target,
            true,
            &mut fake,
            &mut |_| Ok(())
        )?);
        Ok(())
    }

    /// Protected writer identity and regular-file checks refuse links and concurrent publications.
    #[test]
    fn writer_exclusion_and_link_protection_are_enforced() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let lock_path = temporary.path().join(".90-airlock.policy.lock");
        let lock = PolicyLock::acquire(lock_path.clone())?;
        assert!(PolicyLock::acquire(lock_path.clone()).is_err());
        fs::remove_file(&lock_path)?;
        fs::write(&lock_path, "replaced")?;
        assert!(lock.check().is_err());
        drop(lock);
        let real = temporary.path().join("real");
        fs::write(&real, checked(&topology())?.text())?;
        let target = temporary.path().join("90-airlock.policy");
        symlink(&real, &target)?;
        assert!(current(&target).is_err());
        fs::remove_file(&target)?;
        fs::hard_link(&real, &target)?;
        assert!(current(&target).is_err());
        Ok(())
    }
}
