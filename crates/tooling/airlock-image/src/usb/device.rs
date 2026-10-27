//! Resolve a hardware serial to an unused USB disk before destructive access.

use crate::support::{output, root_only, run};
use airlock_provisioning_core as verified;
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    fs::{self, File},
    os::fd::AsRawFd,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Debug, PartialEq, Eq)]
struct Identity {
    // Kernel block-device number; names alone can be reused after unplugging.
    device: u64,
    // Kernel disk sequence changes even when a replacement reuses the same number.
    sequence: u64,
}

fn identity(path: &Path) -> Result<Identity> {
    let info = fs::metadata(path)?;
    ensure!(
        info.file_type().is_block_device(),
        "Target is not a block device."
    );
    let sys = PathBuf::from(format!(
        "/sys/dev/block/{}:{}",
        rustix::fs::major(info.rdev()),
        rustix::fs::minor(info.rdev())
    ));
    let sequence: u64 = fs::read_to_string(sys.join("diskseq"))?.trim().parse()?;
    ensure!(sequence > 0, "Missing kernel disk sequence");
    Ok(Identity {
        device: info.rdev(),
        sequence,
    })
}

#[derive(Debug, Deserialize)]
pub(crate) struct Disk {
    // Kernel block-device path reported by lsblk, never a user shorthand.
    pub(crate) name: PathBuf,
    // Only top-level "disk" objects are eligible for writing.
    #[serde(rename = "type")]
    kind: String,
    // Hardware transport must be USB for a provisionable disk.
    tran: Option<String>,
    // Capacity in bytes used before opening the target.
    pub(crate) size: u64,
    // Informational hardware model included in the inspection report.
    pub(crate) model: Option<String>,
    // Stable hardware identity checked again immediately before mutation.
    pub(crate) serial: Option<String>,
    // Kernel write protection; a protected device cannot be selected.
    ro: bool,
    // Nonempty entries indicate mounted filesystems or active swap.
    #[serde(default)]
    mountpoints: Option<Vec<Option<String>>>,
    // Partition and device-mapper descendants must also be unused.
    #[serde(default)]
    children: Vec<Disk>,
    // Root filesystem label used when validating a personalization mount.
    label: Option<String>,
    // Captured only from kernel state, never accepted from lsblk JSON.
    #[serde(skip)]
    identity: Option<Identity>,
    // Set only after the whole descendant tree passed mounted/swap and holder checks.
    #[serde(skip)]
    unused: bool,
}

#[derive(Deserialize)]
struct Inventory {
    // Tree roots returned by one consistent lsblk invocation.
    blockdevices: Vec<Disk>,
}

impl Disk {
    /// Project real kernel/inventory facts; preparing a mounted disk never claims an unused observation.
    pub(super) fn evidence(&self) -> Result<verified::Observation> {
        let identity = self.identity.as_ref().context("USB identity unavailable")?;
        Ok(verified::Observation {
            disk: verified::Disk {
                name: self
                    .name
                    .to_str()
                    .context("non-UTF-8 USB device")?
                    .to_owned(),
                number: identity.device,
                sequence: identity.sequence,
                serial: self
                    .serial
                    .as_ref()
                    .context("USB serial unavailable")?
                    .clone(),
                bytes: self.size,
            },
            usb: self.tran.as_deref() == Some("usb"),
            whole: self.kind == "disk",
            writable: !self.ro,
            unmounted: self.unused,
            unheld: self.unused,
        })
    }

    /// Require an explicit write intent and the independently supplied serial before selecting an image policy.
    pub(super) fn confirm(
        &self,
        intent: verified::Intent,
        serial: &str,
    ) -> Result<verified::ConfirmedUsb> {
        verified::SelectedUsb::check(self.evidence()?)
            .and_then(|d| d.confirm(intent, serial))
            .context("USB write intent or serial confirmation does not match the eligible disk")
    }

    fn usb(&self) -> bool {
        self.kind == "disk" && self.tran.as_deref() == Some("usb")
    }

    fn mounted(&self) -> bool {
        self.mountpoints
            .as_ref()
            .is_some_and(|points| points.iter().flatten().any(|p| !p.is_empty()))
    }

    pub(crate) fn same_disk(&self, current: &Self) -> Result<()> {
        ensure!(
            self.identity.is_some()
                && self.identity == current.identity
                && self.name == current.name
                && self.serial == current.serial
                && self.size == current.size,
            "USB identity changed; stop and select the device again"
        );
        Ok(())
    }

    pub(crate) fn partition(&self, by_id: &Path) -> Result<PathBuf> {
        let link = format!("{}-part2", by_id.display());
        let partition = fs::canonicalize(&link)
            .with_context(|| format!("resolve USB root partition {link}"))?;
        self.validate_partition(&partition)?;
        Ok(partition)
    }

    fn validate_partition(&self, partition: &Path) -> Result<()> {
        ensure!(
            self.children
                .iter()
                .any(|child| child.name == partition && child.kind == "part"),
            "Root partition does not belong to the selected USB"
        );
        let info = fs::metadata(partition)?;
        ensure!(
            info.file_type().is_block_device(),
            "Root partition is not a block device"
        );
        let sys = PathBuf::from(format!(
            "/sys/dev/block/{}:{}",
            rustix::fs::major(info.rdev()),
            rustix::fs::minor(info.rdev())
        ));
        let disk = self.identity.as_ref().context("USB identity unavailable")?;
        let parent = fs::canonicalize(format!(
            "/sys/dev/block/{}:{}",
            rustix::fs::major(disk.device),
            rustix::fs::minor(disk.device)
        ))?;
        ensure!(
            fs::canonicalize(&sys)?.parent() == Some(parent.as_path())
                && fs::read_to_string(sys.join("partition"))?.trim() == "2",
            "Root partition identity changed"
        );
        Ok(())
    }

    pub(crate) fn flatten(&self) -> Vec<&Self> {
        let mut result = vec![self];
        for child in &self.children {
            result.extend(child.flatten());
        }
        result
    }
}

pub(crate) fn disks() -> Result<Vec<Disk>> {
    Ok(
        serde_json::from_str::<Inventory>(&output(Command::new("lsblk").args([
            "--json",
            "--bytes",
            "--paths",
            "--output",
            "NAME,TYPE,TRAN,SIZE,MODEL,SERIAL,RO,MOUNTPOINTS,LABEL",
        ]))?)?
        .blockdevices,
    )
}

pub(crate) fn by_id(device: &Path) -> Result<()> {
    ensure!(
        device.parent() == Some(Path::new("/dev/disk/by-id"))
            && device
                .file_name()
                .is_some_and(|s| s.as_encoded_bytes().starts_with(b"usb-")),
        "Use a whole-disk /dev/disk/by-id/usb-… path, not /dev/sdX."
    );
    Ok(())
}

pub(crate) fn checked(device: &Path) -> Result<Disk> {
    inspect(device, true)
}

pub(crate) fn inspect(device: &Path, unused: bool) -> Result<Disk> {
    by_id(device)?;
    let target = fs::canonicalize(device)
        .with_context(|| format!("resolve USB device {}", device.display()))?;
    ensure!(
        fs::metadata(&target)?.file_type().is_block_device(),
        "Target is not a block device."
    );
    let before = identity(&target)?;
    let mut disk = disks()?
        .into_iter()
        .find(|disk| disk.name == target)
        .context("Target is not a top-level disk.")?;
    ensure!(
        disk.usb() && !disk.ro,
        "Target must be a writable USB disk."
    );
    ensure!(
        disk.serial.as_ref().is_some_and(|s| !s.trim().is_empty()),
        "Refusing a USB device without a stable serial."
    );

    if unused {
        for child in disk.flatten() {
            ensure!(
                !child.mounted(),
                "Mounted/in-use target: {}; unmount it first.",
                child.name.display()
            );
            let holders = Path::new("/sys/class/block")
                .join(child.name.file_name().context("invalid block name")?)
                .join("holders");
            ensure!(
                fs::read_dir(holders)?.next().is_none(),
                "Active device holders: {}",
                child.name.display()
            );
        }
    }
    let after = identity(&target)?;
    ensure!(before == after, "USB changed during inspection");
    disk.identity = Some(after);
    disk.unused = unused;
    Ok(disk)
}

/// Inspect the opened destination's inode and query its pinned device node for incarnation and capacity.
/// `blockdev` reopens the proc link for read-only ioctls; this is not an atomic kernel snapshot.
pub(super) fn opened(file: &File) -> Result<verified::OpenedDisk> {
    let metadata = file.metadata()?;
    ensure!(
        metadata.file_type().is_block_device(),
        "opened USB destination is not a block device"
    );
    let path = format!(
        "/proc/{process}/fd/{descriptor}",
        process = std::process::id(),
        descriptor = file.as_raw_fd()
    );
    let sequence = output(Command::new("blockdev").arg("--getdiskseq").arg(&path))?.parse()?;
    let bytes = output(Command::new("blockdev").arg("--getsize64").arg(&path))?.parse()?;
    Ok(verified::OpenedDisk {
        number: metadata.rdev(),
        sequence,
        bytes,
    })
}

pub(crate) fn select(serial: &str) -> Result<PathBuf> {
    ensure!(!serial.trim().is_empty(), "Supply a non-empty USB serial.");
    let inventory = disks()?;

    let mut matches = BTreeMap::new();
    let mut entries = fs::read_dir("/dev/disk/by-id")?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry.file_name();
        let text = name.to_string_lossy();
        if !text.starts_with("usb-")
            || text
                .rsplit_once("-part")
                .is_some_and(|(_, s)| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        {
            continue;
        }
        let Ok(target) = fs::canonicalize(entry.path()) else {
            continue;
        };
        if inventory
            .iter()
            .any(|d| d.name == target && d.usb() && d.serial.as_deref() == Some(serial))
        {
            matches.insert(target, entry.path());
        }
    }

    ensure!(
        matches.len() == 1,
        "Expected exactly one attached whole-disk USB with serial {serial:?}; found {}.",
        matches.len()
    );
    matches.into_values().next().context("missing selected USB")
}

pub(crate) fn unmount(device: &Path, selected: &Disk) -> Result<()> {
    root_only()?;
    let disk = inspect(device, false)?;
    selected.same_disk(&disk)?;
    let target = &disk.name;

    for child in disk.flatten().into_iter().rev() {
        if &child.name != target && child.mounted() {
            println!("Unmounting {}…", child.name.display());
            run(Command::new("umount").arg("--all-targets").arg(&child.name))?;
        }
    }
    Ok(())
}

/// Keep the written device pinned without retaining the writer's exclusive block-device claim.
pub(crate) fn release_writer(destination: File) -> Result<File> {
    let descriptor = destination.as_raw_fd();
    let pinned = rustix::fs::open(
        format!("/proc/self/fd/{descriptor}"),
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;

    // Opening this proc link with O_PATH pins the same inode without opening the
    // block device. blockdev reopens it normally and must be able to acquire its
    // own partition-scan claim, which the original O_EXCL writer would prevent.
    drop(destination);
    Ok(File::from(pinned))
}

pub(crate) fn check_mount(root: &Path, selected: Option<&Disk>) -> Result<Disk> {
    let mounts: serde_json::Value = serde_json::from_str(&output(
        Command::new("findmnt")
            .args(["--json", "--mountpoint"])
            .arg(root)
            .args(["--output", "SOURCE,FSTYPE"]),
    )?)?;
    let entries = mounts["filesystems"]
        .as_array()
        .context("missing root mount")?;
    ensure!(
        entries.len() == 1 && entries[0]["fstype"] == "ext4",
        "Expected the USB ext4 root mount."
    );
    let source = fs::canonicalize(
        entries[0]["source"]
            .as_str()
            .context("missing mount source")?,
    )?;
    let matches = disks()?
        .into_iter()
        .filter(|d| {
            d.usb()
                && d.children
                    .iter()
                    .any(|c| c.name == source && c.label.as_deref() == Some("airlock-usb"))
        })
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "Root must be the airlock-usb filesystem on a USB disk."
    );
    ensure!(
        fs::read_to_string(root.join("airlock-usb-image"))? == super::MARKER,
        "Missing USB image marker."
    );

    let mut disk = matches.into_iter().next().context("USB root missing")?;
    ensure!(
        !disk.ro && disk.serial.as_ref().is_some_and(|s| !s.trim().is_empty()),
        "USB root lacks a writable disk with a serial"
    );
    disk.identity = Some(identity(&disk.name)?);
    if let Some(selected) = selected {
        selected.same_disk(&disk)?;
    }
    disk.validate_partition(&source)?;
    Ok(disk)
}

pub(crate) fn stats_path(device: &Path) -> Option<PathBuf> {
    let info = fs::metadata(device).ok()?;
    if !info.file_type().is_block_device() {
        return None;
    }
    Some(PathBuf::from(format!(
        "/sys/dev/block/{}:{}/stat",
        rustix::fs::major(info.rdev()),
        rustix::fs::minor(info.rdev())
    )))
}
