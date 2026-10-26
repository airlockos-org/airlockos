//! Expand only the seed image's known GPT layout, preserving partition identities.

use super::{MARKER, device};
use crate::support::{atomic_json, output, reported, root_only, run};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Clone, Deserialize, Serialize, PartialEq)]
pub(crate) struct Partition {
    // Kernel partition path; order and numbering must match the seed.
    pub(crate) node: String,
    // First 512-byte sector, preserved throughout expansion.
    pub(crate) start: u64,
    // Number of 512-byte sectors occupied by this partition.
    pub(crate) size: u64,
    // GPT role GUID, distinguishing the ESP from the Linux root.
    #[serde(rename = "type")]
    kind: String,
    // Stable partition UUID, required before any layout mutation.
    uuid: String,
    // Preserve every additional sfdisk field when comparing identities.
    #[serde(flatten)]
    other: BTreeMap<String, Value>,
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct Table {
    // Only GPT has the backup-header semantics used here.
    label: String,
    // Whole-disk path reported by sfdisk, checked against the selected USB.
    device: String,
    // Logical sector size; Airlock seed images require 512 bytes.
    sectorsize: u64,
    // Disk UUID, which must survive header relocation.
    id: String,
    // Last usable sector following the secondary GPT header relocation.
    pub(crate) lastlba: u64,
    // Exactly two entries: ESP followed by root.
    pub(crate) partitions: Vec<Partition>,
    // Keep unmodeled diagnostic fields in recovery records.
    #[serde(flatten)]
    other: BTreeMap<String, Value>,
}

pub(crate) fn checked_layout(
    table: &Table,
    target: &Path,
    partition: &Path,
    disk_bytes: u64,
) -> Result<()> {
    ensure!(table.label == "gpt", "Root expansion requires GPT.");
    ensure!(table.sectorsize == 512, "Expected 512-byte image sectors.");
    ensure!(
        Path::new(&table.device) == target,
        "Partition table device mismatch."
    );
    ensure!(
        table.partitions.len() == 2,
        "Expected exactly ESP and root; refusing a custom layout."
    );

    let (esp, root) = (&table.partitions[0], &table.partitions[1]);
    ensure!(
        esp.node == format!("{}1", target.display()) && Path::new(&root.node) == partition,
        "Unexpected partition numbering/order."
    );
    ensure!(
        esp.kind
            .eq_ignore_ascii_case("C12A7328-F81F-11D2-BA4B-00A0C93EC93B")
            && root
                .kind
                .eq_ignore_ascii_case("0FC63DAF-8483-4772-8E79-3D69D8477DE4"),
        "Expected EFI system partition followed by Linux root."
    );

    let esp_end = esp
        .start
        .checked_add(esp.size)
        .context("ESP sector overflow")?;
    let root_end = root
        .start
        .checked_add(root.size)
        .context("root sector overflow")?;
    ensure!(
        esp.start >= 34
            && esp.size > 0
            && esp_end <= root.start
            && root.size > 0
            && root_end <= (disk_bytes / 512).saturating_sub(33),
        "Invalid or overlapping partition boundaries."
    );
    ensure!(
        !root.uuid.is_empty() && !esp.uuid.is_empty() && !table.id.is_empty(),
        "Missing partition identities."
    );
    Ok(())
}

pub(crate) fn checked_result(before: &Table, after: &Table) -> Result<()> {
    ensure!(before.id == after.id, "Disk UUID changed during expansion.");
    ensure!(
        before.partitions.len() == 2 && after.partitions.len() == 2,
        "Unexpected partition count after expansion"
    );
    ensure!(
        before.partitions[0] == after.partitions[0],
        "ESP changed during expansion."
    );

    let mut expected = before.partitions[1].clone();
    let new = &after.partitions[1];
    ensure!(
        new.size >= expected.size,
        "Refusing to shrink the root partition."
    );
    expected.size = new.size;
    ensure!(
        &expected == new,
        "Root start/identity changed; refusing filesystem resize."
    );
    ensure!(
        after
            .lastlba
            .checked_add(1)
            .and_then(|v| v.checked_sub(new.start))
            .and_then(|v| v.checked_sub(new.size))
            .is_some_and(|free| free < 2048),
        "Root partition did not expand to the end of usable space."
    );
    Ok(())
}

pub(crate) fn fills_disk(table: &Table, bytes: u64) -> bool {
    table.partitions.get(1).is_some_and(|root| {
        (bytes / 512)
            .checked_sub(1)
            .and_then(|last| last.checked_sub(table.lastlba))
            .is_some_and(|free| free < 2048)
            && table
                .lastlba
                .checked_add(1)
                .and_then(|v| v.checked_sub(root.start))
                .and_then(|v| v.checked_sub(root.size))
                .is_some_and(|free| free < 2048)
    })
}

pub(crate) fn check_ext4(partition: &Path) -> Result<()> {
    reported(
        Command::new("e2fsck").args(["-f", "-p"]).arg(partition),
        None,
        &[0, 1],
    )
    .context("Filesystem check failed; stopping.")
}

pub(crate) fn kernel_size(partition: &Path, expected: u64) -> Result<()> {
    run(Command::new("udevadm").arg("settle"))?;
    let bytes: u64 = output(Command::new("blockdev").arg("--getsize64").arg(partition))?.parse()?;
    ensure!(
        bytes == expected,
        "Kernel partition size is stale. Unplug/replug this USB, then rerun make usb-dev-install with the same USB_SERIAL; no filesystem resize was attempted."
    );
    Ok(())
}

pub(crate) struct Mounted {
    // Mountpoint owned until a successful unmount; never recursively deleted.
    root: PathBuf,
    // Failed unmounts leave the mountpoint intact for explicit recovery.
    active: bool,
}

impl Mounted {
    pub(crate) fn new(partition: &Path, root: &Path, options: &str) -> Result<Self> {
        run(Command::new("mount")
            .arg("-o")
            .arg(options)
            .arg(partition)
            .arg(root))?;
        Ok(Self {
            root: root.to_owned(),
            active: true,
        })
    }

    pub(crate) fn unmount(mut self) -> Result<()> {
        run(Command::new("umount").arg(&self.root))?;
        self.active = false;
        fs::remove_dir(&self.root)?;
        Ok(())
    }
}

impl Drop for Mounted {
    fn drop(&mut self) {
        if self.active {
            match run(Command::new("umount").arg(&self.root)) {
                Ok(()) => {
                    let _ = fs::remove_dir(&self.root);
                }
                Err(error) => {
                    eprintln!("USB remains mounted at {}: {error:#}", self.root.display())
                }
            }
        }
    }
}

fn table(target: &Path) -> Result<Table> {
    let data: Value =
        serde_json::from_str(&output(Command::new("sfdisk").arg("--json").arg(target))?)?;
    Ok(serde_json::from_value(data["partitiontable"].clone())?)
}

fn blkid(partition: &Path, field: &str) -> Result<String> {
    output(
        Command::new("blkid")
            .args(["-s", field, "-o", "value"])
            .arg(partition),
    )
}

/// Wait for partition-change events before verifying the disk and its recreated device links.
pub(crate) fn change_table(
    command: &mut Command,
    input: Option<Vec<u8>>,
    recheck: impl FnOnce() -> Result<()>,
) -> Result<()> {
    reported(command, input, &[0])?;
    run(Command::new("udevadm").arg("settle")).context("wait for USB partition-table events")?;

    recheck().context("verify USB identity after partition-table change")
}

pub(crate) fn backup_location(backup_base: &Path, info: &device::Disk) -> Result<()> {
    let mut existing = backup_base.to_owned();
    while !existing.exists() {
        existing = existing
            .parent()
            .context("backup path has no existing ancestor")?
            .to_owned();
    }
    let backup_device = fs::metadata(existing)?.dev();
    for child in info.flatten() {
        ensure!(
            fs::metadata(&child.name)?.rdev() != backup_device,
            "Save expansion backups off the target USB."
        );
    }

    fs::create_dir_all(backup_base)?;
    let probe = tempfile::NamedTempFile::new_in(backup_base)?;
    probe.as_file().sync_all()?;
    Ok(())
}

pub(crate) fn expand(device: &Path, selected: &device::Disk, backup_base: &Path) -> Result<()> {
    root_only()?;
    let info = device::checked(device)?;
    selected.same_disk(&info)?;
    let serial = info.serial.as_deref().context("USB serial missing")?;
    let target = &info.name;
    let partition = info.partition(device)?;
    let before = table(target)?;
    checked_layout(&before, target, &partition, info.size)?;
    ensure!(blkid(&partition, "TYPE")? == "ext4", "Expected ext4 root.");
    ensure!(
        blkid(&partition, "LABEL")? == "airlock-usb",
        "Expected airlock-usb root label."
    );
    let filesystem_uuid = blkid(&partition, "UUID")?;
    let root = tempfile::Builder::new()
        .prefix("airlock-grow-check-")
        .tempdir_in("/run")?
        .keep();
    let mount = Mounted::new(&partition, &root, "ro,noload,nosuid,nodev,noexec")?;
    ensure!(
        fs::read_to_string(root.join("airlock-usb-image"))? == MARKER,
        "Missing Airlock image marker."
    );
    mount.unmount()?;

    backup_location(backup_base, &info)?;
    let backup = tempfile::Builder::new()
        .prefix("grow-")
        .tempdir_in(backup_base)?
        .keep();
    atomic_json(&backup.join("before.json"), &before)?;
    fs::write(
        backup.join("partition-table.sfdisk"),
        format!(
            "{}\n",
            output(Command::new("sfdisk").arg("--dump").arg(target))?
        ),
    )?;
    reported(
        Command::new("sfdisk")
            .arg("--backup-file")
            .arg(backup.join("partition-table"))
            .arg("--backup-pt-sectors")
            .arg(target),
        None,
        &[0],
    )?;
    run(Command::new("sync").arg("-f").arg(&backup))?;
    println!("Root expansion recovery metadata: {}", backup.display());

    let recheck = || -> Result<()> {
        let latest = device::checked(device)?;
        selected.same_disk(&latest)?;
        ensure!(
            latest.partition(device)? == partition,
            "USB root partition changed during expansion"
        );
        ensure!(
            latest.name == *target
                && latest.serial.as_deref() == Some(serial)
                && latest.size == info.size,
            "USB identity changed during expansion."
        );
        Ok(())
    };

    recheck()?;
    check_ext4(&partition)?;
    recheck()?;
    if !fills_disk(&before, info.size) {
        change_table(
            Command::new("sfdisk")
                .args(["--lock=yes", "--relocate", "gpt-bak-std"])
                .arg(target),
            None,
            recheck,
        )?;
        change_table(
            Command::new("sfdisk")
                .args([
                    "--lock=yes",
                    "--wipe=never",
                    "--wipe-partitions=never",
                    "-N",
                    "2",
                ])
                .arg(target),
            Some(b", +\n".to_vec()),
            recheck,
        )?;
    }

    let after = table(target)?;
    checked_layout(&after, target, &partition, info.size)?;
    checked_result(&before, &after)?;
    let bytes = after.partitions[1]
        .size
        .checked_mul(512)
        .context("root byte size overflow")?;

    kernel_size(&partition, bytes)?;
    recheck()?;
    reported(Command::new("resize2fs").arg(&partition), None, &[0])?;
    recheck()?;
    check_ext4(&partition)?;
    ensure!(
        blkid(&partition, "UUID")? == filesystem_uuid,
        "Filesystem UUID changed."
    );

    run(&mut Command::new("sync"))?;
    atomic_json(
        &backup.join("result.json"),
        &json!({
            "schema": "airlock.usb-root-expansion.v1",
            "serial": serial,
            "device": target,
            "filesystem_uuid": filesystem_uuid,
            "root_bytes_before": before.partitions[1].size * 512,
            "root_bytes_after": bytes,
            "partition_table": after,
            "status": "complete",
        }),
    )?;
    run(Command::new("sync").arg("-f").arg(&backup))?;
    println!(
        "USB root expanded to {:.1} GiB; filesystem checked.",
        bytes as f64 / 1024f64.powi(3)
    );
    Ok(())
}
