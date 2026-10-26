//! Immutable Hermit boot identities and bounded Xen PVH executable validation.
//!
//! A valid image is not deployment authority. Admission must bind this complete
//! descriptor to reviewed source and the approved machine plan. The ELF checks
//! constrain the loader input; they do not establish application correctness.

use crate::{
    identity::{GitRevision, LockHash},
    store_path::StoreFile,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Largest executable accepted, including debugging information.
pub const MAX_EXECUTABLE_BYTES: u64 = 64 * 1024 * 1024;

/// Runtime authority compiled into the service, independently of its VM role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorityMode {
    /// No peer grants or clipboard authorization; safe for isolated deployment.
    Disconnected,
    /// Controlled test peer only; inadmissible to a production machine.
    Laboratory,
}

/// Versioned boot contract, rejecting unknown protocols during decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Schema {
    /// Static x86-64 Hermit ELF with a Xen physical PVH entry note.
    #[serde(rename = "airlock.hermit-pvh.v1")]
    V1,
}

/// Complete immutable executable and build identity retained by a generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    /// Loader protocol selected by this artifact.
    pub schema: Schema,
    /// Executable within an immutable Nix store object.
    pub executable: StoreFile,
    /// Digest of every executable byte, including ELF notes.
    pub sha256: LockHash,
    /// Exact file size, bounded before reading or allocating an admission buffer.
    pub bytes: u64,
    /// Reviewed Airlock application source commit.
    pub source_revision: GitRevision,
    /// Integration commit pinning the Hermit kernel and Xen submodules.
    pub integration_revision: GitRevision,
    /// Dependency lock digest binding the compiler and builder inputs.
    pub build_lock: LockHash,
    /// Whether the executable contains the controlled test authority.
    pub authority: AuthorityMode,
}

/// Image validation failed before the executable could be selected for boot.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid Hermit artifact: {0}")]
pub struct InvalidArtifact(
    /// Fixed diagnostic category; never contains application data.
    &'static str,
);

/// Loader facts derived from authenticated bytes rather than caller metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Image {
    /// Physical PVH entry point advertised by the unique Xen ELF note.
    pub entry: u64,
    /// Exclusive upper bound of loaded physical memory.
    pub memory_end: u64,
}

impl Descriptor {
    /// Reject unbounded images and laboratory authority outside an isolated test machine.
    pub fn validate(&self, laboratory: bool) -> Result<(), InvalidArtifact> {
        require(
            (64..=MAX_EXECUTABLE_BYTES).contains(&self.bytes),
            "file size",
        )?;
        require(
            laboratory || self.authority == AuthorityMode::Disconnected,
            "laboratory authority",
        )
    }

    /// Authenticate the entire executable and validate its bounded static PVH layout.
    /// The caller checks [`Self::validate`] before allocating the file buffer.
    pub fn verify(
        &self,
        bytes: &[u8],
        memory_bytes: u64,
        laboratory: bool,
    ) -> Result<Image, InvalidArtifact> {
        self.validate(laboratory)?;
        require(bytes.len() as u64 == self.bytes, "file size mismatch")?;
        require(
            format!("{digest:x}", digest = Sha256::digest(bytes)) == self.sha256.as_str(),
            "digest mismatch",
        )?;
        inspect(bytes, memory_bytes)
    }
}

/// Keep malformed-file rejection separate from authorization and I/O failures.
fn require(condition: bool, reason: &'static str) -> Result<(), InvalidArtifact> {
    if condition {
        Ok(())
    } else {
        Err(InvalidArtifact(reason))
    }
}

/// Read one bounded little-endian ELF integer without casts or unchecked indexing.
fn integer(bytes: &[u8], offset: usize, size: usize) -> Result<u64, InvalidArtifact> {
    let end = offset
        .checked_add(size)
        .ok_or(InvalidArtifact("integer overflow"))?;
    let input = bytes
        .get(offset..end)
        .ok_or(InvalidArtifact("truncated header"))?;
    let mut value = [0; 8];
    value[..size].copy_from_slice(input);
    Ok(u64::from_le_bytes(value))
}

/// Validate ELF64 and its Xen physical-entry note without relying on section headers.
fn inspect(bytes: &[u8], memory_bytes: u64) -> Result<Image, InvalidArtifact> {
    require(
        bytes.len() >= 64 && bytes.len() as u64 <= MAX_EXECUTABLE_BYTES,
        "file size",
    )?;
    require(&bytes[..8] == b"\x7fELF\x02\x01\x01\xff", "ELF identity")?;
    require(
        integer(bytes, 16, 2)? == 2 && integer(bytes, 18, 2)? == 62 && integer(bytes, 20, 4)? == 1,
        "ELF architecture",
    )?;
    require(
        integer(bytes, 52, 2)? == 64 && integer(bytes, 54, 2)? == 56,
        "header size",
    )?;
    let count = integer(bytes, 56, 2)?;
    require((1..=64).contains(&count), "program header count")?;
    let table = integer(bytes, 32, 8)?;
    require(
        table >= 64
            && table
                .checked_add(count * 56)
                .is_some_and(|end| end <= bytes.len() as u64),
        "program header table",
    )?;

    let mut loads = Vec::new();
    let mut executable_ranges = Vec::new();
    let mut entry = None;
    let mut memory_end = 0;
    for index in 0..count {
        let header = (table + index * 56) as usize;
        let kind = integer(bytes, header, 4)?;
        require(kind != 2 && kind != 3, "dynamic executable")?;
        let flags = integer(bytes, header + 4, 4)?;
        let offset = integer(bytes, header + 8, 8)?;
        let virtual_address = integer(bytes, header + 16, 8)?;
        let address = integer(bytes, header + 24, 8)?;
        let file_size = integer(bytes, header + 32, 8)?;
        let memory_size = integer(bytes, header + 40, 8)?;
        let alignment = integer(bytes, header + 48, 8)?;
        require(
            offset
                .checked_add(file_size)
                .is_some_and(|end| end <= bytes.len() as u64),
            "segment file bounds",
        )?;
        if kind == 1 {
            require(
                file_size <= memory_size
                    && memory_size > 0
                    && address >= 0x100000
                    && virtual_address == address,
                "load layout",
            )?;
            let end = address
                .checked_add(memory_size)
                .ok_or(InvalidArtifact("load overflow"))?;
            require(end <= memory_bytes, "guest memory bounds")?;
            require(
                alignment <= 1
                    || (alignment.is_power_of_two() && address % alignment == offset % alignment),
                "load alignment",
            )?;
            require(flags & !7 == 0 && flags & 3 != 3, "load permissions")?;
            require(
                loads
                    .iter()
                    .all(|&(start, stop, _)| end <= start || address >= stop),
                "overlapping loads",
            )?;
            loads.push((address, end, flags & 1 != 0));
            if flags & 1 != 0 {
                executable_ranges.push(address..address + file_size);
            }
            memory_end = memory_end.max(end);
        } else if kind == 4 {
            require(file_size <= 4096, "note size")?;
            let notes = &bytes[offset as usize..(offset + file_size) as usize];
            let mut cursor = 0;
            while cursor < notes.len() {
                let name_size = integer(notes, cursor, 4)? as usize;
                let data_size = integer(notes, cursor + 4, 4)? as usize;
                let note_kind = integer(notes, cursor + 8, 4)?;
                let name = cursor + 12;
                // Note segment and u32 sizes are bounded before alignment arithmetic.
                require(name_size <= 4096 && data_size <= 4096, "note bounds")?;
                let data = name + name_size.next_multiple_of(4);
                let end = data + data_size.next_multiple_of(4);
                require(end <= notes.len(), "note bounds")?;
                if &notes[name..name + name_size] == b"Xen\0" && note_kind == 18 {
                    require(entry.is_none() && data_size == 8, "PVH note")?;
                    entry = Some(integer(notes, data, 8)?);
                }
                cursor = end;
            }
        }
    }
    let entry = entry.ok_or(InvalidArtifact("missing PVH entry"))?;
    require(
        entry <= u32::MAX as u64 && executable_ranges.iter().any(|range| range.contains(&entry)),
        "PVH entry outside executable segment",
    )?;
    let elf_entry = integer(bytes, 24, 8)?;
    require(
        executable_ranges
            .iter()
            .any(|range| range.contains(&elf_entry)),
        "ELF entry outside executable segment",
    )?;
    Ok(Image { entry, memory_end })
}

#[cfg(test)]
mod tests;
