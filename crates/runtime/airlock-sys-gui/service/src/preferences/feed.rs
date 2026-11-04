//! Private atomic publication, kept separate from admission locks and session state.

use super::MAX_AGE;
use airlock_desktop_preferences::{FrameDecoder, MAX_FRAME_LEN, Snapshot, encode_frame};
use anyhow::{Context, Result, ensure};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Reject symlinks and directories writable/readable by other login users.
pub(super) fn check_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir()
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.mode() & 0o077 == 0,
        "preferences directory must be private and owned by the session user"
    );
    Ok(())
}

/// Create only a private directory, or validate the existing one without changing its permissions.
pub(super) fn private_directory(path: &Path) -> Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    check_directory(path)
}

/// Open bounded admission/publisher lock files without following a symlink.
pub(super) fn lock_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.mode() & 0o077 == 0,
        "invalid preferences lock file"
    );
    Ok(file)
}

/// The sole session writer; its lock stays outside the exported directory.
pub(super) struct Publisher {
    /// Private directory containing only the current frame and atomic-write temporaries.
    directory: PathBuf,
    /// Exclusive ownership prevents two sessions racing to publish conflicting state.
    _owner: File,
}

impl Publisher {
    /// Establish single-writer ownership and discard any previous session's frame.
    pub(super) fn new(root: &Path) -> Result<Self> {
        let owner = lock_file(&root.join("publisher.lock"))?;
        owner
            .try_lock()
            .context("preferences publisher already running")?;
        let directory = root.join("feed");
        private_directory(&directory)?;
        match fs::remove_file(directory.join("snapshot")) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(Self {
            directory,
            _owner: owner,
        })
    }

    /// Replace the complete snapshot; readers opening the old inode still get a complete frame.
    pub(super) fn publish(&self, snapshot: &Snapshot) -> Result<()> {
        let frame = encode_frame(snapshot)?;
        let mut temporary = tempfile::NamedTempFile::new_in(&self.directory)?;
        temporary.write_all(&frame)?;
        temporary.persist(self.directory.join("snapshot"))?;
        Ok(())
    }
}

impl Drop for Publisher {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.directory.join("snapshot"));
    }
}

/// Read only a current, regular, bounded and completely validated frame.
pub(super) fn read(directory: &Path) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(directory.join("snapshot"))?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= MAX_FRAME_LEN as u64,
        "invalid preferences feed file"
    );
    let age = SystemTime::now()
        .duration_since(metadata.modified()?)
        .context("preferences feed timestamp is in the future")?;
    ensure!(age <= MAX_AGE, "preferences publisher heartbeat expired");
    let mut frame = Vec::new();
    file.take(MAX_FRAME_LEN as u64 + 1)
        .read_to_end(&mut frame)?;
    ensure!(
        frame.len() <= MAX_FRAME_LEN,
        "preferences feed exceeds frame limit"
    );
    let mut input = frame.as_slice();
    let mut decoder = FrameDecoder::default();
    ensure!(
        decoder.decode(&mut input)?.is_some() && input.is_empty(),
        "preferences feed must contain exactly one snapshot"
    );
    decoder.finish()?;
    Ok(frame)
}
