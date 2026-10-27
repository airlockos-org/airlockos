//! Serialize machine mutations and explain which operation holds exclusion.
//! The kernel flock is authoritative; owner JSON is only a verified diagnostic.

use crate::{
    model::{BootId, MachineOperation, Phase, TransactionId},
    state,
};
use anyhow::{Context, Result, ensure};
use rustix::fs::{FlockOperation, Mode, OFlags, flock, open};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fmt,
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    num::{NonZeroU32, NonZeroU64},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum OperationLabel {
    Native(
        /// Recognized native operation or phase used by this service.
        MachineOperation,
    ),
    External(
        /// Operation or phase label written by a compatible external coordinator.
        String,
    ),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum PhaseLabel {
    Native(
        /// Recognized native operation or phase used by this service.
        Phase,
    ),
    External(
        /// Operation or phase label written by a compatible external coordinator.
        String,
    ),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Owner {
    /// Human-readable entity currently performing the machine operation.
    owner: String,
    /// Why the owner needs the whole-machine mutation lock.
    reason: String,
    /// Kind of work for which the named owner is holding exclusion.
    operation: OperationLabel,
    /// Process identity checked against the current boot and process start time.
    pid: NonZeroU32,
    /// Host boot identity, preventing metadata from a prior boot being trusted.
    boot_id: BootId,
    /// Process start time from procfs, preventing PID reuse from matching a stale owner.
    process_start: String,
    /// Open descriptor number used to verify the recorded lock holder.
    lock_fd: u32,
    /// Random seek position tying diagnostics to this lock acquisition.
    lock_position: NonZeroU64,
    /// Wall-clock acquisition time in seconds since the Unix epoch.
    acquired_at: f64,
    /// Monotonic acquisition time used to compute trustworthy elapsed duration.
    acquired_monotonic: f64,
    /// Latest reported phase of the operation; diagnostic rather than authorization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    phase: Option<PhaseLabel>,
    /// Associated transaction text, if the operation has created a journal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    operation_id: Option<String>,
    /// Additional protocol metadata retained without treating it as authority.
    #[serde(flatten)]
    extra: std::collections::BTreeMap<String, Value>,
}

/// Contended machine lock with verified owner context when process inspection succeeds.
#[derive(Clone, Debug)]
pub struct HeldLock {
    /// Kernel-checked owner metadata paired with elapsed seconds, or unknown.
    verified: Option<(Owner, f64)>,
}

impl HeldLock {
    fn name(&self) -> &str {
        self.verified
            .as_ref()
            .map_or("Unknown operation", |(o, _)| o.owner.as_str())
    }

    fn reason(&self) -> &str {
        self.verified
            .as_ref()
            .map_or("Current owner details could not be verified", |(o, _)| {
                o.reason.as_str()
            })
    }
}

impl Serialize for HeldLock {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Verified<'a> {
            /// Owner record whose process and descriptor still match the kernel lock.
            #[serde(flatten)]
            owner: &'a Owner,
            /// Reports kernel contention independently of the diagnostic metadata.
            held: bool,
            /// Signals that owner metadata matched the live kernel lock.
            verified: bool,
            /// Elapsed hold duration calculated from the monotonic clock.
            elapsed_seconds: f64,
        }

        #[derive(Serialize)]
        struct Unknown<'a> {
            /// Reports kernel contention despite unavailable owner verification.
            held: bool,
            /// False because no diagnostic owner could be authenticated.
            verified: bool,
            /// Fallback label explaining that the holder could not be identified.
            owner: &'a str,
            /// Fallback diagnostic explaining the missing verified owner context.
            reason: &'a str,
        }
        match &self.verified {
            Some((owner, elapsed_seconds)) => Verified {
                owner,
                held: true,
                verified: true,
                elapsed_seconds: *elapsed_seconds,
            }
            .serialize(serializer),
            None => Unknown {
                held: true,
                verified: false,
                owner: self.name(),
                reason: self.reason(),
            }
            .serialize(serializer),
        }
    }
}

/// Contention error carrying a serializable owner/reason diagnostic for the caller.
#[derive(Debug)]
pub struct Busy(
    /// Contended lock observation explaining who holds it and why, when verifiable.
    pub HeldLock,
);

impl fmt::Display for Busy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "another machine operation holds the lock: {} — {}",
            self.0.name(),
            self.0.reason()
        )
    }
}

impl std::error::Error for Busy {}

fn monotonic() -> f64 {
    let t = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    t.tv_sec as f64 + t.tv_nsec as f64 / 1e9
}

fn start(pid: u64) -> Result<String> {
    let s = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    Ok(s.rsplit_once(')')
        .context("invalid process identity")?
        .1
        .split_whitespace()
        .nth(19)
        .context("missing process start")?
        .to_owned())
}

fn unknown() -> HeldLock {
    HeldLock { verified: None }
}

fn holder(file: &File, path: &Path) -> Result<HeldLock> {
    use std::os::unix::fs::MetadataExt;
    let owner: Owner = state::read(&path.with_file_name("lock.owner.json"))?;
    ensure!(
        !owner.owner.is_empty() && !owner.reason.is_empty(),
        "invalid owner"
    );
    ensure!(
        !["held", "verified", "elapsed_seconds"]
            .iter()
            .any(|k| owner.extra.contains_key(*k)),
        "owner record contains observation fields"
    );

    let pid = u64::from(owner.pid.get());
    let fd = owner.lock_fd;
    ensure!(
        owner.boot_id == state::boot_id()? && owner.process_start == start(pid)?,
        "stale owner identity"
    );

    let a = file.metadata()?;
    let b = fs::metadata(format!("/proc/{pid}/fd/{fd}"))?;
    ensure!(
        a.dev() == b.dev() && a.ino() == b.ino(),
        "owner descriptor changed"
    );

    let info = fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}"))?;
    let position = info
        .lines()
        .find_map(|l| l.strip_prefix("pos:"))
        .context("missing descriptor position")?
        .trim()
        .parse::<u64>()?;
    ensure!(
        owner.lock_position.get() == position
            && info
                .lines()
                .any(|l| l.starts_with("lock:") && l.contains("FLOCK") && l.contains("WRITE")),
        "lock acquisition changed"
    );

    let now = monotonic();
    ensure!(
        owner.acquired_monotonic.is_finite()
            && owner.acquired_monotonic >= 0.0
            && owner.acquired_monotonic <= now,
        "invalid acquisition time"
    );

    let elapsed = now - owner.acquired_monotonic;
    Ok(HeldLock {
        verified: Some((owner, elapsed)),
    })
}

/// Report kernel contention without creating a lock file or publishing owner metadata.
///
/// A held lock may have unknown diagnostics; `None` means no contention was observed.
pub fn status(path: &Path) -> Result<Option<HeldLock>> {
    let fd = match open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let file = File::from(fd);
    ensure!(
        file.metadata()?.is_file(),
        "machine lock is not a regular file"
    );

    match flock(&file, FlockOperation::NonBlockingLockShared) {
        Ok(()) => {
            flock(&file, FlockOperation::Unlock)?;
            Ok(None)
        }
        Err(rustix::io::Errno::WOULDBLOCK) => {
            Ok(Some(holder(&file, path).unwrap_or_else(|_| unknown())))
        }
        Err(e) => Err(e.into()),
    }
}

/// Exclusive machine-operation guard, inherited by helpers until their work finishes.
///
/// Owner metadata explains contention but never replaces the kernel lock.
pub struct MachineLock {
    /// Open flock descriptor inherited by helpers to preserve exclusion.
    _file: File,
    /// Path of the advisory owner record removed when this guard drops.
    metadata: PathBuf,
    /// Current operation identity and phase published to observers.
    owner: Owner,
}

impl MachineLock {
    /// Acquire nonblocking whole-machine exclusion as dom0 root or report contention.
    ///
    /// Publish owner context and let executed helpers inherit the lock descriptor.
    pub fn acquire(
        root: &Path,
        owner: &str,
        reason: &str,
        operation: MachineOperation,
    ) -> Result<Self> {
        ensure!(
            rustix::process::geteuid().is_root(),
            "machine mutations require dom0 root"
        );

        state::directory(root)?;
        let path = root.join("lock");
        let fd = open(
            &path,
            OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::from_raw_mode(0o600),
        )?;
        let mut file = File::from(fd);
        ensure!(
            file.metadata()?.is_file(),
            "machine lock is not a regular file"
        );
        state::trusted(&path)?;

        match flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {}
            Err(rustix::io::Errno::WOULDBLOCK) => {
                return Err(Busy(holder(&file, &path).unwrap_or_else(|_| unknown())).into());
            }
            Err(e) => return Err(e.into()),
        }

        let metadata = root.join("lock.owner.json");
        if metadata.try_exists()? {
            fs::remove_file(&metadata)?;
        }

        let mut bytes = [0u8; 4];
        File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        let position = u32::from_ne_bytes(bytes) as u64 + 1;
        file.seek(SeekFrom::Start(position))?;

        let owner = Owner {
            owner: owner.to_owned(),
            reason: reason.to_owned(),
            operation: OperationLabel::Native(operation),
            pid: NonZeroU32::new(std::process::id()).context("invalid process ID")?,
            boot_id: state::boot_id()?,
            process_start: start(std::process::id().into())?,
            lock_fd: file.as_raw_fd().try_into()?,
            lock_position: NonZeroU64::new(position).context("invalid lock position")?,
            acquired_at: state::now(),
            acquired_monotonic: monotonic(),
            phase: None,
            operation_id: None,
            extra: std::collections::BTreeMap::new(),
        };
        state::save(&metadata, &owner)?;

        // A helper may outlive a killed coordinator. Keep the same flock open
        // across exec so it cannot overlap a recovery while retaining this fd.
        rustix::io::fcntl_setfd(&file, rustix::io::FdFlags::empty())?;

        Ok(Self {
            _file: file,
            metadata,
            owner,
        })
    }

    /// Publish the current phase and optional transaction without releasing exclusion.
    pub fn update(&mut self, phase: Phase, transaction: Option<&TransactionId>) -> Result<()> {
        self.owner.phase = Some(PhaseLabel::Native(phase));
        if let Some(id) = transaction {
            self.owner.operation_id = Some(id.as_str().to_owned());
        }

        state::save(&self.metadata, &self.owner)
    }
}

impl Drop for MachineLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.metadata);
    }
}
