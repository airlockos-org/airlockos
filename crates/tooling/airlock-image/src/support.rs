//! Shared command reporting and durable preparation records.

use airlock_nix_core::runtime::process;
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    process::Command,
};

pub(crate) fn root_only() -> Result<()> {
    ensure!(
        rustix::process::geteuid().is_root(),
        "Run this action with sudo."
    );
    Ok(())
}

pub(crate) fn captured(command: &mut Command, input: Option<Vec<u8>>) -> Result<process::Output> {
    Ok(process::run(command, input, None)?)
}

pub(crate) fn output(command: &mut Command) -> Result<String> {
    let result = captured(command, None)?;
    ensure!(
        result.status.success(),
        "{command:?}: {stdout}{stderr}",
        stdout = String::from_utf8_lossy(&result.stdout),
        stderr = String::from_utf8_lossy(&result.stderr)
    );
    if !result.stderr.is_empty() {
        std::io::stdout().write_all(&result.stderr)?;
    }
    Ok(String::from_utf8(result.stdout)?.trim().to_owned())
}

pub(crate) fn run(command: &mut Command) -> Result<()> {
    let status = command
        .status()
        .with_context(|| format!("start {command:?}"))?;
    ensure!(status.success(), "{command:?}: {status}");
    Ok(())
}

pub(crate) fn reported(
    command: &mut Command,
    input: Option<Vec<u8>>,
    allowed: &[i32],
) -> Result<()> {
    let result = process::run(command, input, None)?;
    let ok = result
        .status
        .code()
        .is_some_and(|code| allowed.contains(&code));
    let mut stream: Box<dyn Write> = if ok {
        Box::new(std::io::stdout())
    } else {
        Box::new(std::io::stderr())
    };
    stream.write_all(&result.stdout)?;
    stream.write_all(&result.stderr)?;
    ensure!(ok, "{command:?}: {}", result.status);
    Ok(())
}

pub(crate) fn digest(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

pub(crate) fn file_digest(path: &Path) -> Result<String> {
    let mut file = regular(path)?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0; 8 * 1024 * 1024];
    loop {
        let size = file.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        hash.update(&buffer[..size]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

pub(crate) fn regular(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
        .open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "expected a regular file: {}",
        path.display()
    );
    Ok(file)
}

pub(crate) fn read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    regular(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "input too large: {}",
        path.display()
    );
    Ok(bytes)
}

pub(crate) fn json(path: &Path) -> Result<serde_json::Value> {
    Ok(serde_json::from_slice(&read(path, 32 * 1024 * 1024)?)?)
}

pub(crate) fn atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("output has no parent")?;
    fs::create_dir_all(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

pub(crate) fn atomic_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    atomic(path, &bytes)
}

#[cfg(feature = "qubes")]
pub(crate) fn input_json(
    command: &mut Command,
    value: &impl Serialize,
) -> Result<serde_json::Value> {
    let result = captured(command, Some(serde_json::to_vec(value)?))?;
    ensure!(
        result.status.success(),
        "{command:?}: {stdout}{stderr}",
        stdout = String::from_utf8_lossy(&result.stdout),
        stderr = String::from_utf8_lossy(&result.stderr)
    );
    Ok(serde_json::from_slice(&result.stdout)?)
}
