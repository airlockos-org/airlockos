//! Bounded child processes and durable user-owned records for desktop commands.

use airlock_nix_core::state::{OperationKind, OperationLock, OperationOwner, StateStore};
use anyhow::{Context, Result, ensure};
use rustix::process::{Pid, Signal, WaitId, WaitIdOptions};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    fs::{self, File},
    io::{self, Cursor, Read, Seek, Take, Write},
    os::unix::{
        fs::{DirBuilderExt, MetadataExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

const LIMIT: u64 = 32 * 1024 * 1024;

/// Bounded output retained after the helper and its process group have been stopped.
pub struct Output {
    /// Reaped leader status, including unsuccessful exit or cancellation.
    pub status: ExitStatus,
    /// Standard output, bounded independently from diagnostics.
    pub stdout: Vec<u8>,
    /// Standard error, bounded independently from the protocol reply.
    pub stderr: Vec<u8>,
}

impl Output {
    /// Return stdout only after successful exit, retaining helper diagnostics on failure.
    pub fn checked(self) -> Result<Vec<u8>> {
        ensure!(
            self.status.success(),
            "helper failed ({}): {}",
            self.status,
            String::from_utf8_lossy(&self.stderr)
        );
        Ok(self.stdout)
    }
}

struct Group {
    // Leader remains unreaped until group cleanup, preventing PID reuse.
    child: Child,
    // True only after wait has released the process identity.
    reaped: bool,
}

impl Group {
    fn kill(&mut self) {
        let _ = rustix::process::kill_process_group(Pid::from_child(&self.child), Signal::KILL);
        // A helper may move into another existing group. Its unreaped PID still
        // identifies the direct child, so it must also be cancelled individually.
        let _ = self.child.kill();
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        if !self.reaped {
            self.kill();
            let _ = self.child.wait();
        }
    }
}

/// A helper request held in memory, optionally followed by bytes from a regular file.
/// Restricting sources avoids an arbitrary blocking reader defeating process cancellation.
pub struct Input {
    // Protocol header or complete small request, sent before any file bytes.
    prefix: Cursor<Vec<u8>>,
    // Optional bounded payload; the descriptor remains pinned throughout the transfer.
    file: Option<Take<File>>,
}

impl Input {
    /// Send a complete in-memory request without a payload file.
    pub fn bytes(bytes: Vec<u8>) -> Self {
        Self {
            prefix: Cursor::new(bytes),
            file: None,
        }
    }

    /// Send a prefix followed by exactly `length` bytes from the file's current position.
    /// Reject non-regular descriptors; premature EOF is an error during transmission.
    pub fn file(prefix: Vec<u8>, file: File, length: u64) -> Result<Self> {
        ensure!(
            file.metadata()?.is_file(),
            "helper input must be a regular file"
        );
        Ok(Self {
            prefix: Cursor::new(prefix),
            file: Some(file.take(length)),
        })
    }

    fn complete(&self) -> bool {
        self.prefix.position() == self.prefix.get_ref().len() as u64
            && self.file.as_ref().is_none_or(|f| f.limit() == 0)
    }

    fn read(&mut self, buffer: &mut [u8]) -> Result<usize> {
        let count = self.prefix.read(buffer)?;
        if count != 0 {
            return Ok(count);
        }
        match &mut self.file {
            Some(file) if file.limit() != 0 => {
                let count = file.read(buffer)?;
                ensure!(
                    count != 0,
                    "helper input file ended before its declared length"
                );
                Ok(count)
            }
            _ => Ok(0),
        }
    }
}

/// Execute a fixed command with bounded output and an optional streamed request.
/// Nonblocking pipe writes keep helper backpressure within the deadline, without a
/// writer thread that could outlive cancellation. Local regular-file I/O still
/// depends on the filesystem; this is process control rather than a filesystem timeout.
pub fn run(command: &mut Command, mut input: Option<Input>, timeout: Duration) -> Result<Output> {
    let mut stdout = tempfile::tempfile()?;
    let mut stderr = tempfile::tempfile()?;
    let child = command
        .process_group(0)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(stdout.try_clone()?)
        .stderr(stderr.try_clone()?)
        .spawn()
        .with_context(|| format!("start {}", command.get_program().to_string_lossy()))?;
    let mut group = Group {
        child,
        reaped: false,
    };
    let mut pipe = group.child.stdin.take();
    if let Some(pipe) = &pipe {
        let flags = rustix::fs::fcntl_getfl(pipe)?;
        rustix::fs::fcntl_setfl(pipe, flags | rustix::fs::OFlags::NONBLOCK)?;
    }
    let mut buffer = [0u8; 64 * 1024];
    let mut length = 0;
    let mut offset = 0;

    let deadline = Instant::now()
        .checked_add(timeout)
        .context("helper timeout is too large")?;
    loop {
        ensure!(
            stdout.metadata()?.len() <= LIMIT && stderr.metadata()?.len() <= LIMIT,
            "helper exceeded output limit"
        );
        ensure!(Instant::now() < deadline, "helper timed out");
        let mut progressed = false;
        if let (Some(request), Some(writer)) = (&mut input, &pipe) {
            if offset == length {
                length = request.read(&mut buffer)?;
                offset = 0;
            }
            if offset < length {
                match rustix::io::write(writer, &buffer[offset..length]) {
                    Ok(0) => anyhow::bail!("helper stopped accepting input"),
                    Ok(count) => {
                        offset += count;
                        progressed = true;
                    }
                    Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if offset == length && request.complete() {
                // EOF is part of the protocol: receivers validate no trailing payload.
                pipe = None;
            }
        }

        match rustix::process::waitid(
            WaitId::Pid(Pid::from_child(&group.child)),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        ) {
            Ok(Some(_)) => {
                ensure!(
                    pipe.is_none(),
                    "helper exited before receiving the complete request"
                );
                break;
            }
            Ok(None) | Err(rustix::io::Errno::INTR) => {
                if !progressed {
                    thread::sleep(Duration::from_millis(1));
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    // Keep the leader unreaped until signalling descendants, preventing PID reuse.
    group.kill();
    ensure!(
        stdout.metadata()?.len() <= LIMIT && stderr.metadata()?.len() <= LIMIT,
        "helper exceeded output limit"
    );
    let status = group.child.wait()?;
    group.reaped = true;

    stdout.rewind()?;
    stderr.rewind()?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    stdout.take(LIMIT).read_to_end(&mut out)?;
    stderr.take(LIMIT).read_to_end(&mut err)?;
    Ok(Output {
        status,
        stdout: out,
        stderr: err,
    })
}

/// Resolve an executable override used by packaging or isolated command fixtures.
pub fn tool(variable: &str, default: &str) -> std::ffi::OsString {
    std::env::var_os(variable).unwrap_or_else(|| default.into())
}

/// Capture successful helper text with a deadline and reject invalid UTF-8.
pub fn text(command: &mut Command, timeout: Duration) -> Result<String> {
    Ok(String::from_utf8(run(command, None, timeout)?.checked()?)?
        .trim()
        .to_owned())
}

/// Return an absolute per-user state directory without creating it.
pub fn state_root(component: &str) -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    let root = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(home).join(".local/state"));
    ensure!(root.is_absolute(), "XDG state directory must be absolute");
    Ok(root.join(component))
}

/// Create user-owned state directories and reject symlinks or writable shared leaves.
pub fn directory(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "state directory must be absolute");
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir()
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.mode() & 0o022 == 0,
        "unsafe user state directory"
    );
    Ok(())
}

/// Publish a private JSON record with file and directory fsync.
pub fn save(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path.parent().context("record has no parent")?;
    directory(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer(&mut temporary, value)?;
    temporary.write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|e| e.error)?;
    sync(parent)
}

/// Read bounded, duplicate-key-free JSON, treating only absence as no record.
pub fn read<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(Some(airlock_nix_core::state::read_json(path, LIMIT)?)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Make directory-entry changes durable before acknowledging publication or removal.
pub fn sync(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

/// Wait briefly for a named user operation and preserve verified contention diagnostics.
pub fn lock(root: &Path, key: &str, reason: &str) -> Result<OperationLock> {
    directory(root)?;
    let store = StateStore::initialize(root)?;
    let owner = OperationOwner::new(
        "Airlock desktop integration".into(),
        reason.into(),
        OperationKind::Maintenance,
    )?;
    let key = key.parse()?;
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match store.try_operation(&key, owner.clone()) {
            Ok(guard) => return Ok(guard),
            Err(airlock_nix_core::Error::Busy { .. }) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20))
            }
            Err(error) => return Err(error.into()),
        }
    }
}
