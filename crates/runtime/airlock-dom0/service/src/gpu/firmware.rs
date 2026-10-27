//! VFCT is an ACPI wrapper carrying a GPU's unchanged VBIOS ROM to its VM address.
//! Preparation validates the host table and emits only the single selected image.

#[cfg(test)]
mod tests;

use super::{Bdf, assignment, bounded, path};
use anyhow::{Context, Result, ensure};
use clap::Args as ClapArgs;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

const MAX: u64 = 8 * 1024 * 1024;

#[derive(ClapArgs)]
pub(super) struct Args {
    /// Host firmware table to inspect; no PCI controls are accessed.
    #[arg(long)]
    input: PathBuf,
    /// Previously recorded source-table SHA-256, checked before parsing.
    #[arg(long)]
    sha256: String,
    /// Host address used to select exactly one firmware image.
    #[arg(long)]
    host_bdf: Bdf,
    /// Observed destination address; must agree with the VM's PCI layout.
    #[arg(long)]
    guest_bdf: Bdf,
    /// Expected PCI vendor identifier in hexadecimal.
    #[arg(long, default_value = "1002")]
    vendor: String,
    /// Expected PCI device identifier in hexadecimal.
    #[arg(long)]
    device: String,
    /// New output directory; omission performs read-only validation.
    #[arg(long)]
    out_dir: Option<PathBuf>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Manifest {
    /// Version of the firmware evidence format.
    schema: u8,
    /// Provenance hash of the original host ACPI table, not a firmware signature.
    source_sha256: String,
    /// Number of nonempty images observed before filtering.
    source_image_count: usize,
    /// Physical PCI address matched in the source wrapper.
    pub host_bdf: Bdf,
    /// Address written into the filtered wrapper, leaving ROM bytes unchanged.
    guest_bdf: Bdf,
    /// Canonical four-digit PCI vendor identifier.
    pub vendor: String,
    /// Canonical four-digit PCI device identifier.
    pub device: String,
    /// Exact validated ROM size in bytes.
    rom_bytes: usize,
    /// Digest of the ROM preserved verbatim in the new table.
    rom_sha256: String,
    /// Size of the filtered ACPI table.
    guest_vfct_bytes: usize,
    /// Digest used to reject artifact changes before XML rendering.
    pub guest_vfct_sha256: String,
    /// Always false: this tool changes the wrapper, never the ROM.
    rom_modified: bool,
    /// True only after the emitted table's checksum was computed.
    guest_vfct_checksum_valid: bool,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Prepared {
    /// Firmware validation evidence for this exact startup attempt.
    #[serde(flatten)]
    pub firmware: Manifest,
    /// Non-administrative VM whose UUID is also checked in libvirt XML.
    pub domain: airlock_nix_core::identity::GuestName,
    /// Qubes UUID copied from the checked live snapshot.
    pub domain_uuid: String,
    /// Qubes port that resolved to the firmware's physical GPU.
    pub port_id: String,
    /// Explicit bus-zero slot shared by XML and filtered VFCT.
    pub guest_slot: u8,
    /// Source sysfs ACPI table retained as provenance.
    source: PathBuf,
    /// Fresh read-only firmware file, never a reused per-VM filename.
    pub table_path: PathBuf,
}

impl Prepared {
    pub(super) fn current(&self, vm: &assignment::Vm, slot: u8) -> Result<()> {
        let selected = assignment::selected(vm, slot)?;
        ensure!(
            self.domain == vm.name
                && self.domain_uuid == vm.uuid
                && self.guest_slot == slot
                && self.port_id == selected.port_id
                && self.firmware.host_bdf == selected.host_bdf
                && super::hex(&self.firmware.vendor)? == u32::from(selected.vendor)
                && super::hex(&self.firmware.device)? == u32::from(selected.device),
            "GPU assignment changed after VFCT preparation"
        );
        ensure!(
            self.firmware.schema == 1
                && !self.firmware.rom_modified
                && self.firmware.guest_vfct_checksum_valid
                && self.firmware.guest_bdf
                    == Bdf {
                        bus: 0,
                        device: slot,
                        function: 0
                    },
            "invalid prepared VFCT metadata"
        );
        let output = path("AIRLOCK_GPU_OUTPUT", "/run/airlock-amd-vbios");
        crate::model::absolute(output.to_str().context("non-UTF-8 firmware directory")?)?;
        let parent = self
            .table_path
            .parent()
            .context("prepared VFCT has no directory")?;
        ensure!(
            self.table_path
                .file_name()
                .is_some_and(|name| name == "vfct.bin")
                && parent.parent() == Some(output.as_path())
                && parent
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(&format!("{}-", vm.uuid))),
            "prepared VFCT is outside its startup artifact directory"
        );
        crate::state::trusted(parent)?;
        let file = fs::File::from(rustix::fs::open(
            &self.table_path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?);
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.uid() == 0
                && metadata.nlink() == 1
                && metadata.mode() & 0o777 == 0o400,
            "prepared VFCT changed or has unsafe ownership/permissions"
        );
        let mut data = Vec::new();
        file.take(MAX + 1).read_to_end(&mut data)?;
        ensure!(
            data.len() as u64 <= MAX
                && digest(&data) == self.firmware.guest_vfct_sha256
                && data.len() == self.firmware.guest_vfct_bytes,
            "prepared VFCT changed before domain creation"
        );
        // Validate the filtered table itself rather than trusting its manifest's
        // checksum flag or ROM metadata at the final startup gate.
        let (_, _, actual) = prepare(
            &data,
            self.firmware.guest_bdf,
            self.firmware.guest_bdf,
            selected.vendor,
            selected.device,
            &self.firmware.guest_vfct_sha256,
        )?;
        ensure!(
            actual.rom_sha256 == self.firmware.rom_sha256
                && actual.rom_bytes == self.firmware.rom_bytes
                && actual.source_image_count == 1,
            "prepared VFCT ROM metadata changed"
        );
        Ok(())
    }
}

pub(super) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn word(bytes: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        bytes
            .get(at..at + 2)
            .context("truncated firmware word")?
            .try_into()?,
    ))
}

fn dword(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(at..at + 4)
            .context("truncated firmware word")?
            .try_into()?,
    ))
}

fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |sum, b| sum.wrapping_add(*b))
}

fn validate_rom(rom: &[u8], vendor: u16, device: u16) -> Result<()> {
    ensure!(
        rom.len() >= 0x4a && rom[..2] == [0x55, 0xaa],
        "missing VBIOS ROM signature"
    );
    ensure!(
        usize::from(rom[2]) * 512 == rom.len() && checksum(rom) == 0,
        "VBIOS length or checksum mismatch"
    );
    let atom = usize::from(word(rom, 0x48)?);
    ensure!(
        atom >= 0x4a
            && atom + 8 <= rom.len()
            && matches!(&rom[atom + 4..atom + 8], b"ATOM" | b"MOTA"),
        "missing or out-of-bounds ATOM header"
    );
    let pcir = usize::from(word(rom, 0x18)?);
    ensure!(
        pcir >= 0x1a && pcir + 0x18 <= rom.len() && &rom[pcir..pcir + 4] == b"PCIR",
        "missing or out-of-bounds PCI ROM header"
    );
    ensure!(
        word(rom, pcir + 4)? == vendor && word(rom, pcir + 6)? == device,
        "PCI ROM vendor/device mismatch"
    );
    ensure!(
        usize::from(word(rom, pcir + 0x10)?) * 512 == rom.len(),
        "PCI ROM image length mismatch"
    );
    Ok(())
}

fn prepare(
    data: &[u8],
    host: Bdf,
    guest: Bdf,
    vendor: u16,
    device: u16,
    expected: &str,
) -> Result<(Vec<u8>, Vec<u8>, Manifest)> {
    ensure!(
        expected.len() == 64 && digest(data) == expected.to_ascii_lowercase(),
        "source VFCT SHA-256 mismatch"
    );
    ensure!(
        data.len() >= 76 && data.len() as u64 <= MAX,
        "VFCT size outside supported bounds"
    );
    ensure!(
        &data[..4] == b"VFCT"
            && dword(data, 4)? as usize == data.len()
            && data[8] == 1
            && checksum(data) == 0,
        "invalid VFCT header, revision, length or checksum"
    );
    let mut offset = dword(data, 52)? as usize;
    ensure!(
        offset >= 76 && offset <= data.len() - 28 && dword(data, 56)? == 0,
        "unsupported VFCT image/library offsets"
    );

    let mut selected = None;
    let mut count = 0;
    while offset < data.len() {
        let header = data
            .get(offset..offset + 28)
            .context("truncated VFCT image header")?;
        offset += 28;
        let size = dword(header, 24)? as usize;
        let end = offset.checked_add(size).context("VFCT image overflow")?;
        let rom = data.get(offset..end).context("truncated VFCT image")?;
        if size != 0 {
            count += 1;
            if [dword(header, 0)?, dword(header, 4)?, dword(header, 8)?]
                == [
                    u32::from(host.bus),
                    u32::from(host.device),
                    u32::from(host.function),
                ]
                && word(header, 12)? == vendor
                && word(header, 14)? == device
            {
                ensure!(
                    selected.is_none(),
                    "expected exactly one matching host GPU VBIOS"
                );
                selected = Some((header.to_vec(), rom.to_vec()));
            }
        } else {
            ensure!(
                header.iter().all(|b| *b == 0),
                "unsupported nonempty VFCT entry without image"
            );
        }
        offset = end;
    }
    let (mut header, rom) = selected.context("expected exactly one matching host GPU VBIOS")?;
    validate_rom(&rom, vendor, device)?;

    let mut table = vec![0u8; 76];
    table[..4].copy_from_slice(b"VFCT");
    table[8] = 1;
    table[10..16].copy_from_slice(b"ALLOCK");
    table[16..24].copy_from_slice(b"GPUVBIOS");
    table[24..28].copy_from_slice(&1u32.to_le_bytes());
    table[28..32].copy_from_slice(b"ALCK");
    table[32..36].copy_from_slice(&1u32.to_le_bytes());
    table[52..56].copy_from_slice(&76u32.to_le_bytes());
    for (at, value) in [(0, guest.bus), (4, guest.device), (8, guest.function)] {
        header[at..at + 4].copy_from_slice(&u32::from(value).to_le_bytes());
    }
    table.extend(header);
    table.extend(&rom);
    let size = u32::try_from(table.len())?;
    table[4..8].copy_from_slice(&size.to_le_bytes());
    table[9] = 0u8.wrapping_sub(checksum(&table));
    let manifest = Manifest {
        schema: 1,
        source_sha256: digest(data),
        source_image_count: count,
        host_bdf: host,
        guest_bdf: guest,
        vendor: format!("{vendor:04x}"),
        device: format!("{device:04x}"),
        rom_bytes: rom.len(),
        rom_sha256: digest(&rom),
        guest_vfct_bytes: table.len(),
        guest_vfct_sha256: digest(&table),
        rom_modified: false,
        guest_vfct_checksum_valid: checksum(&table) == 0,
    };
    Ok((table, rom, manifest))
}

fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub(super) fn execute(args: Args) -> Result<serde_json::Value> {
    let data = bounded(&args.input, MAX)?;
    let (table, rom, report) = prepare(
        &data,
        args.host_bdf,
        args.guest_bdf,
        super::hex(&args.vendor)?.try_into()?,
        super::hex(&args.device)?.try_into()?,
        &args.sha256,
    )?;
    if let Some(output) = args.out_dir {
        fs::DirBuilder::new().mode(0o700).create(&output)?;
        write(&output.join("guest-vfct.bin"), &table)?;
        write(&output.join("gpu.rom"), &rom)?;
        write(
            &output.join("manifest.json"),
            &serde_json::to_vec_pretty(&report)?,
        )?;
        fs::File::open(&output)?.sync_all()?;
    }
    Ok(serde_json::to_value(report)?)
}

pub(super) fn prepare_start(vm: &assignment::Vm, slot: u8) -> Result<Prepared> {
    let gpu = assignment::selected(vm, slot)?;
    let source = path("AIRLOCK_GPU_VFCT", "/sys/firmware/acpi/tables/VFCT");
    let data = bounded(&source, MAX)?;
    let (table, _, firmware) = prepare(
        &data,
        gpu.host_bdf,
        Bdf {
            bus: 0,
            device: slot,
            function: 0,
        },
        gpu.vendor,
        gpu.device,
        &digest(&data),
    )?;

    let output = path("AIRLOCK_GPU_OUTPUT", "/run/airlock-amd-vbios");
    crate::state::directory(&output)?;
    ensure!(
        fs::metadata(&output)?.permissions().mode() & 0o077 == 0,
        "firmware runtime directory must be root-owned mode 0700"
    );
    let directory = tempfile::Builder::new()
        .prefix(&format!("{}-", vm.uuid))
        .tempdir_in(&output)?;
    let report = Prepared {
        firmware,
        domain: vm.name.clone(),
        domain_uuid: vm.uuid.clone(),
        port_id: gpu.port_id,
        guest_slot: slot,
        source,
        table_path: directory.path().join("vfct.bin"),
    };
    write(&report.table_path, &table)?;
    write(
        &directory.path().join("manifest.json"),
        &serde_json::to_vec_pretty(&report)?,
    )?;
    fs::File::open(directory.path())?.sync_all()?;
    let _ = directory.keep();
    fs::File::open(output)?.sync_all()?;
    Ok(report)
}
