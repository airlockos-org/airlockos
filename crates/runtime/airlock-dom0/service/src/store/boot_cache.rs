//! Reclaim duplicate EFI cache bytes only after authenticating every retained boot entry.
//! The cache is copied to another filesystem before any source file is removed.

use super::{boot_artifacts, fs::*};
use crate::{lock::MachineLock, model::MachineOperation};
use anyhow::{Context, Result, ensure};
use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

#[derive(Args)]
pub(crate) struct Request {
    // Mounted EFI filesystem containing the sealed boot entries.
    #[arg(long, default_value = "/boot")]
    esp: PathBuf,
    // Authenticated descriptors retained by the native storage service.
    #[arg(long, default_value = "/var/lib/airlock/closure-store/host/artifacts")]
    descriptors: PathBuf,
    // Recovery copies must live on another filesystem from the ESP.
    #[arg(long, default_value = "/var/lib/airlock/boot-cache-quarantine")]
    quarantine_root: PathBuf,
    // Explicitly copy and reclaim; omission performs read-only inspection.
    #[arg(long)]
    apply: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Fingerprint {
    // Complete file length; truncated artifacts are refused before reclamation.
    size: u64,
    // SHA-256 binding the exact retained payload bytes.
    sha256: String,
}

#[derive(PartialEq, Eq, Serialize)]
struct CachedFile {
    // Single cache filename; paths and links cannot nominate other data.
    name: String,
    // Exact bytes copied and checked again before removal.
    #[serde(flatten)]
    fingerprint: Fingerprint,
}

#[derive(PartialEq, Eq, Serialize)]
struct Plan {
    // Identifies the read-only inventory and recovery receipt format.
    schema: &'static str,
    // EFI mount whose upstream duplicate cache was inspected.
    esp: PathBuf,
    // Every boot entry must be authenticated before files can be removed.
    sealed_entries: usize,
    // Sum of cache bytes that would be reclaimed, with checked arithmetic.
    bytes: u64,
    // Complete inventory checked again after copying recovery data.
    files: Vec<CachedFile>,
}

fn fingerprint(path: &Path) -> Result<Fingerprint> {
    ensure!(
        fs::symlink_metadata(path)?.is_file(),
        "boot artifact is not a regular file"
    );
    let metadata = fs::metadata(path)?;
    let digest = hash(path)?;
    let after = fs::metadata(path)?;
    ensure!(
        metadata.dev() == after.dev()
            && metadata.ino() == after.ino()
            && metadata.len() == after.len()
            && metadata.mtime() == after.mtime()
            && metadata.mtime_nsec() == after.mtime_nsec()
            && metadata.ctime() == after.ctime()
            && metadata.ctime_nsec() == after.ctime_nsec(),
        "boot artifact changed while hashing"
    );
    Ok(Fingerprint {
        size: metadata.len(),
        sha256: digest,
    })
}

fn inspect(esp: &Path, descriptors: &Path) -> Result<Plan> {
    let mut authenticated = BTreeMap::<String, Fingerprint>::new();
    for descriptor in children(descriptors)?
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
    {
        let record: Value = read(&descriptor)?;
        ensure!(
            record["schema"] == "airlock.host-boot-artifacts.v1",
            "unknown boot artifact descriptor"
        );
        for entry in record["entries"]
            .as_array()
            .context("boot descriptor entries")?
        {
            for (name, value) in entry["files"]
                .as_object()
                .context("boot descriptor files")?
            {
                ensure!(
                    name.starts_with("EFI/airlock/") || name.starts_with("loader/entries/airlock-"),
                    "descriptor contains an unsealed path"
                );
                boot_artifacts::safe_artifact(esp, name)?;
                let expected: Fingerprint = serde_json::from_value(value.clone())?;
                if let Some(previous) = authenticated.insert(name.clone(), expected.clone()) {
                    ensure!(
                        previous == expected,
                        "conflicting boot artifact fingerprints"
                    );
                }
            }
        }
    }
    ensure!(!authenticated.is_empty(), "no sealed boot artifacts");
    for (name, expected) in &authenticated {
        ensure!(
            fingerprint(&boot_artifacts::safe_artifact(esp, name)?)? == *expected,
            "retained boot artifact failed verification: {name}"
        );
    }

    let entries: Vec<_> = children(&esp.join("loader/entries"))?
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e == "conf"))
        .collect();
    ensure!(!entries.is_empty(), "no boot entries");
    for entry in &entries {
        let name = entry
            .strip_prefix(esp)?
            .to_str()
            .context("boot entry name")?;
        ensure!(authenticated.contains_key(name), "unsealed boot entry");
        let contents = fs::read_to_string(entry)?;
        let mut efi = Vec::new();
        for line in contents
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty() && !s.starts_with('#'))
        {
            if let Some((key, value)) = line.split_once(char::is_whitespace) {
                ensure!(
                    !matches!(key, "linux" | "initrd" | "devicetree"),
                    "unsupported direct boot payload reference"
                );
                if key == "efi" {
                    efi.push(value.trim());
                }
            }
        }
        ensure!(
            efi.len() == 1
                && efi[0].starts_with("/EFI/airlock/")
                && !contents.contains("/EFI/nixos/"),
            "boot entry does not use a sealed EFI binary"
        );
        let relative = efi[0].trim_start_matches('/');
        ensure!(
            authenticated.contains_key(relative),
            "EFI binary is not authenticated"
        );
        let binary = boot_artifacts::safe_artifact(esp, relative)?;
        let config = boot_artifacts::xen_config(&binary)?;
        let kernel = config
            .get("kernel")
            .context("missing embedded Xen kernel")?
            .split_whitespace()
            .next()
            .context("empty Xen kernel")?;
        let ramdisk = config
            .get("ramdisk")
            .context("missing embedded Xen ramdisk")?;
        for name in [kernel, ramdisk] {
            component(name)?;
            let path = binary.parent().context("EFI parent")?.join(name);
            let name = path.strip_prefix(esp)?.to_str().context("payload name")?;
            ensure!(
                authenticated.contains_key(name),
                "embedded Xen payload is not authenticated"
            );
        }
    }

    let cache = esp.join("EFI/nixos");
    let mut files = Vec::new();
    let mut bytes = 0u64;
    for path in children(&cache)? {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .context("cache filename")?;
        let metadata = fs::symlink_metadata(&path)?;
        if name == ".extra-files" && metadata.is_dir() && children(&path)?.is_empty() {
            continue;
        }
        ensure!(metadata.is_file(), "unsupported EFI cache object");
        ensure!(
            name.ends_with(".efi") || name.ends_with(".tmp"),
            "unknown upstream EFI cache filename"
        );
        let fingerprint = fingerprint(&path)?;
        bytes = bytes
            .checked_add(fingerprint.size)
            .context("cache size overflow")?;
        files.push(CachedFile {
            name: name.into(),
            fingerprint,
        });
    }
    Ok(Plan {
        schema: "airlock.boot-cache-quarantine.v1",
        esp: esp.into(),
        sealed_entries: entries.len(),
        bytes,
        files,
    })
}

pub(crate) fn execute(state: &Path, request: Request) -> Result<Value> {
    let esp = fs::canonicalize(request.esp)?;
    let descriptors = fs::canonicalize(request.descriptors)?;
    if !request.apply {
        return Ok(serde_json::to_value(inspect(&esp, &descriptors)?)?);
    }
    let _lock = MachineLock::acquire(
        state,
        "airlock-dom0-service",
        "copy authenticated EFI cache to recovery storage before reclaiming ESP space",
        MachineOperation::Maintenance,
    )?;
    let plan = inspect(&esp, &descriptors)?;
    mkdir_all(&request.quarantine_root)?;
    ensure!(
        !request.quarantine_root.is_symlink(),
        "quarantine root is a symlink"
    );
    let root = fs::canonicalize(request.quarantine_root)?;
    ensure!(
        fs::metadata(&esp)?.dev() != fs::metadata(&root)?.dev(),
        "quarantine must be on another filesystem"
    );
    let space = rustix::fs::statvfs(&root)?;
    ensure!(
        space
            .f_bavail
            .checked_mul(space.f_frsize)
            .context("free space overflow")?
            >= plan
                .bytes
                .checked_add(256 * 1024 * 1024)
                .context("quarantine size overflow")?,
        "insufficient space for reversible quarantine"
    );
    let destination = tempfile::Builder::new()
        .prefix("quarantine-")
        .tempdir_in(&root)?
        .keep();
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o700))?;
    sync_dir(&root)?;
    let mut receipt = serde_json::to_value(&plan)?;
    receipt["status"] = json!("copying");
    write(&destination.join("receipt.json"), &receipt, 0o600)?;

    for entry in &plan.files {
        let source = esp.join("EFI/nixos").join(&entry.name);
        let target = destination.join(&entry.name);
        let mut from = OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&source)?;
        let mut to = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&target)?;
        std::io::copy(&mut from, &mut to)?;
        to.sync_all()?;
        ensure!(
            fingerprint(&target)? == entry.fingerprint
                && fingerprint(&source)? == entry.fingerprint,
            "EFI cache changed while copying"
        );
    }
    ensure!(
        inspect(&esp, &descriptors)? == plan,
        "boot state changed while copying"
    );
    sync_dir(&destination)?;
    for entry in &plan.files {
        fs::remove_file(esp.join("EFI/nixos").join(&entry.name))?;
    }
    sync_dir(&esp.join("EFI/nixos"))?;
    receipt["status"] = json!("complete");
    receipt["destination"] = json!(destination);
    write(&destination.join("receipt.json"), &receipt, 0o600)?;
    Ok(receipt)
}
