//! Canonical Nix package serialization shared by image packing and runtime artifact transfer.
//! This independent Cargo workspace keeps image-fragment cache keys tied only to the
//! packing format and its dependencies, rather than deployment code or the application lockfile.
//! These helpers describe bytes and path spelling; they grant no storage authority.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod tree;

#[cfg(test)]
mod tests;

pub use tree::tree_hash;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    path::Path,
    process::{Command, Stdio},
};
use tree::{entry, hash};

/// Cached fragment's content identity, independent of the pool that will receive it.
#[derive(Clone, Deserialize, Serialize)]
pub struct Fragment {
    /// Version of the build-time fragment representation.
    pub schema: String,
    /// Exact logical store root whose basename is the archive's only top-level entry.
    pub path: String,
    /// Canonical tree identity used by ordinary pool admission.
    pub tree_hash: String,
    /// Length of the tar stream without its two terminating zero blocks.
    pub size: u64,
    /// SHA-256 of those exact fragment bytes.
    pub sha256: String,
}

/// Reject malformed store roots at the cross-VM artifact boundary.
pub fn validate_store_path(path: &str) -> Result<&str> {
    let name = entry(path)?;
    let (hash, name) = name
        .split_once('-')
        .context("invalid Nix artifact basename")?;
    ensure!(
        hash.len() == 32
            && hash
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            && !name.is_empty(),
        "invalid Nix store path in artifact"
    );
    Ok(path)
}

/// Build a deterministic POSIX tar fragment without its two terminating zero blocks.
pub fn create_tar_fragment(source: &Path, target: &Path) -> Result<()> {
    let output = Command::new("tar")
        .args([
            "--format=posix",
            "--pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime",
            "--hard-dereference",
            "--sort=name",
            "--numeric-owner",
            "--owner=0",
            "--group=0",
            "--mtime=@1",
            "--blocking-factor=1",
            "-cf",
        ])
        .arg(target)
        .arg("-C")
        .arg(source.parent().context("object source has no parent")?)
        .arg("--")
        .arg(source.file_name().context("object source has no name")?)
        .stdin(Stdio::null())
        .output()?;
    ensure!(
        output.status.success(),
        "tar failed: {error}",
        error = String::from_utf8_lossy(&output.stderr)
    );

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(target)?;
    let size = file.metadata()?.len();
    ensure!(
        size >= 1024 && size % 512 == 0,
        "invalid tar fragment length"
    );

    file.seek(SeekFrom::Start(size - 1024))?;
    let mut trailer = [0; 1024];
    file.read_exact(&mut trailer)?;
    ensure!(trailer == [0; 1024], "nonstandard tar EOF");
    file.set_len(size - 1024)?;
    Ok(())
}

/// Require the canonical hexadecimal digest representation used in cached metadata.
fn digest(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid cached digest"
    );
    Ok(())
}

/// Read a Nix-produced descriptor and reject a mismatched path or malformed byte range.
/// Payload bytes are checked while appending to the destination pool, avoiding another full read here.
pub fn fragment(directory: &Path, logical: &str) -> Result<Fragment> {
    validate_store_path(logical)?;
    let value: Fragment = serde_json::from_reader(File::open(directory.join("metadata.json"))?)?;
    ensure!(
        value.schema == "airlock.store-fragment.v1" && value.path == logical,
        "cached fragment identity mismatch"
    );
    digest(&value.sha256)?;
    digest(&value.tree_hash)?;
    let metadata = fs::symlink_metadata(directory.join("object.tar"))?;
    ensure!(
        metadata.is_file()
            && metadata.len() == value.size
            && value.size > 0
            && value.size.is_multiple_of(512),
        "cached fragment length mismatch"
    );
    Ok(value)
}

/// Pack one immutable package into a fresh output using the same representation as qrexec transfer.
pub fn pack(logical: &str, source: &Path, output: &Path) -> Result<Fragment> {
    validate_store_path(logical)?;
    ensure!(
        source.file_name() == Path::new(logical).file_name(),
        "cached source basename mismatch"
    );

    fs::create_dir(output)?;
    let tree_hash = tree_hash(source)?;
    let path = output.join("object.tar");
    create_tar_fragment(source, &path)?;

    let value = Fragment {
        schema: "airlock.store-fragment.v1".into(),
        path: logical.into(),
        tree_hash,
        size: fs::metadata(&path)?.len(),
        sha256: hash(&path)?,
    };
    fs::write(output.join("metadata.json"), serde_json::to_vec(&value)?)?;
    Ok(value)
}
