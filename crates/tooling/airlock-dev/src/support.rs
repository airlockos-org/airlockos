//! Bounded command capture and atomic local developer records.

use airlock_nix_core::runtime::process;
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    process::Command,
    time::Duration,
};

pub(crate) fn output(command: &mut Command) -> Result<Vec<u8>> {
    Ok(process::run(command, None, None)?.checked("development helper")?)
}

pub(crate) fn text(command: &mut Command) -> Result<String> {
    Ok(String::from_utf8(output(command)?)?.trim().to_owned())
}

pub(crate) fn input(command: &mut Command, bytes: Vec<u8>, timeout: Duration) -> Result<Vec<u8>> {
    Ok(process::run(command, Some(bytes), Some(timeout))?.checked("development helper")?)
}

pub(crate) fn git(root: &Path, arguments: &[&str]) -> Result<String> {
    text(Command::new("git").arg("-C").arg(root).args(arguments))
}

pub(crate) fn digest(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

fn regular(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::NOFOLLOW).bits() as i32)
        .open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "expected a regular source artifact: {}",
        path.display()
    );
    Ok(file)
}

pub(crate) fn hash(path: &Path) -> Result<String> {
    let mut file = regular(path)?;
    let mut digest = Sha256::new();
    let mut bytes = [0; 65536];

    loop {
        let size = file.read(&mut bytes)?;
        if size == 0 {
            break;
        }
        digest.update(&bytes[..size]);
    }

    Ok(format!("{:x}", digest.finalize()))
}

pub(crate) fn json(path: &Path) -> Result<serde_json::Value> {
    let mut bytes = Vec::new();
    regular(path)?
        .take(32 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 32 * 1024 * 1024, "JSON input exceeds limit");
    Ok(airlock_nix_core::state::parse_json(&bytes, path)?)
}

pub(crate) fn atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;

    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;

    temporary
        .persist(path)
        .context("publish development record")?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

pub(crate) fn record(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    atomic(path, &bytes)
}

pub(crate) fn print(value: &impl serde::Serialize) -> Result<()> {
    serde_json::to_writer(std::io::stdout().lock(), value)?;
    println!();
    Ok(())
}

pub(crate) fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

pub(crate) fn join(words: &[&str]) -> String {
    words.iter().map(|s| quote(s)).collect::<Vec<_>>().join(" ")
}
