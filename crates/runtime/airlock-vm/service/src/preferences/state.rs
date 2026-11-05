//! Private baseline journal and desired/applied status; remote snapshots never survive a session.

use super::{Config, settings::Baseline};
use airlock_desktop_preferences::Snapshot;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// Session-local status, with no claim of a transaction across toolkit adapters.
#[derive(Serialize, Deserialize)]
pub(super) struct Status {
    /// Current machine-owned GUI association, or none when configuration is invalid.
    pub(super) config: Option<Config>,
    /// Whether initial convergence or the bounded fallback decision has completed.
    pub(super) ready: bool,
    /// Applied, waiting, degraded or disabled; transport loss can retain applied settings.
    pub(super) phase: String,
    /// Last fully validated desired snapshot from this source, held only in this session.
    pub(super) desired: Option<Snapshot>,
    /// Snapshot for which every available adapter converged; none on partial failure.
    pub(super) applied: Option<Snapshot>,
    /// Local capability and asset fallbacks visible to diagnostics.
    pub(super) limitations: Vec<String>,
    /// Bounded local failure description, distinct from successful application.
    pub(super) error: Option<String>,
}

/// Local locations, never derived from remote names or font/theme strings.
pub(super) struct Paths {
    /// Private directory cleared when the graphical runtime directory goes away.
    pub(super) runtime: PathBuf,
    /// Durable baseline needed to undo managed overrides after a process crash.
    journal: PathBuf,
}

impl Paths {
    /// Use the graphical user's standard runtime and state directories.
    pub(super) fn new() -> Result<Self> {
        let runtime = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .context("missing graphical runtime directory")?;
        let state = std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or(
                PathBuf::from(std::env::var_os("HOME").context("missing home directory")?)
                    .join(".local/state"),
            );
        Self::at(&runtime, &state)
    }

    /// Create private owned state beneath explicit local roots (also used by isolated tests).
    pub(super) fn at(runtime: &Path, state: &Path) -> Result<Self> {
        let runtime = runtime.join("airlock-desktop-preferences");
        private_directory(&runtime)?;
        fs::create_dir_all(state)?;
        let state = state.join("airlock-desktop-preferences");
        private_directory(&state)?;
        Ok(Self {
            runtime,
            journal: state.join("baseline.json"),
        })
    }

    /// Hold one agent/restorer for this user, including across overlapping restart attempts.
    pub(super) fn lock(&self) -> Result<File> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(self.journal.with_file_name("owner.lock"))?;
        file.try_lock()
            .context("desktop preferences agent already active")?;
        Ok(file)
    }

    /// Save the untouched baseline before the first managed write.
    pub(super) fn save(&self, baseline: &Baseline) -> Result<()> {
        atomic_json(&self.journal, baseline)
    }

    /// Recover an interrupted session without reusing any cached remote preferences.
    pub(super) fn baseline(&self) -> Result<Option<Baseline>> {
        match read_json(&self.journal, 65536) {
            Ok(value) => Ok(Some(value)),
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    /// Remove the recovery record only after every captured managed field was restored.
    pub(super) fn restored(&self) -> Result<()> {
        if self.journal.exists() {
            fs::remove_file(&self.journal)?;
        }
        Ok(())
    }

    /// Atomically report the local convergence outcome for readiness and diagnostics.
    pub(super) fn status(&self, status: &Status) -> Result<()> {
        atomic_json(&self.runtime.join("status.json"), status)
    }

    /// Remove stale readiness when stopping or beginning a different graphical session.
    pub(super) fn clear_status(&self) -> Result<()> {
        match fs::remove_file(self.runtime.join("status.json")) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

/// Refuse symlinks and other users' state rather than changing existing permissions.
fn private_directory(path: &Path) -> Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir()
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.mode() & 0o077 == 0,
        "preferences state directory is not private"
    );
    Ok(())
}

/// Read bounded regular files, allowing machine configuration to use NixOS symlinks.
pub(super) fn read_json<T: DeserializeOwned>(path: &Path, limit: u64) -> Result<T> {
    // Machine configuration may be a normal NixOS /etc symlink. Other callers
    // use private directories; no field from the wire selects any of these paths.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
        .open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "preferences record is not a regular file"
    );
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "preferences record too large");
    Ok(serde_json::from_slice(&bytes)?)
}

/// Preserve a durable baseline/status before any observer can see an incomplete record.
fn atomic_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut file = tempfile::NamedTempFile::new_in(path.parent().context("record parent")?)?;
    file.write_all(&serde_json::to_vec(value)?)?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    File::open(path.parent().unwrap())?.sync_all()?;
    Ok(())
}
