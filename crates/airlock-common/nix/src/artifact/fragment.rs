//! Validate package streams once and retain the metadata needed to index their immutable contents.

use super::util::hex;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

/// Digests and file metadata derived from one validated package stream.
pub struct Identity {
    /// Canonical file-tree identity, independent of tar header representation.
    pub tree_hash: String,
    /// SHA-256 of the exact fragment bytes, excluding tar end markers.
    pub sha256: String,
    /// File headers and data offsets, reusable without reading file contents.
    pub index: Vec<IndexEntry>,
}

/// One file in an already validated immutable package fragment.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IndexEntry {
    /// Full path within the fragment, including its Nix store basename.
    pub path: PathBuf,
    /// Tar entry type: ordinary file, directory or symbolic link.
    pub kind: u8,
    /// Unix permissions, including executable and special mode bits.
    pub mode: u32,
    /// File length in bytes; directories and symlinks have no payload.
    pub size: u64,
    /// Link target for symbolic links only.
    pub link: Option<PathBuf>,
    /// Payload offset relative to the beginning of this fragment.
    pub offset: u64,
}

impl IndexEntry {
    fn from_entry<R: Read>(entry: &tar::Entry<'_, R>) -> Result<Self> {
        Ok(Self {
            path: entry.path()?.into_owned(),
            kind: entry.header().entry_type().as_byte(),
            mode: entry.header().mode()? & 0o7777,
            size: entry.size(),
            link: entry.link_name()?.map(|path| path.into_owned()),
            offset: entry.raw_file_position(),
        })
    }
}

/// Copies only bytes consumed by the validator, keeping payload and transport hashes in one pass.
struct CopyingReader<R, W> {
    // Incoming fragment, bounded by its outer tar member.
    input: R,
    // Unpublished storage or the outgoing transport.
    output: W,
    // Running digest of exactly the bytes copied.
    digest: Sha256,
    // Number of copied bytes, checked against the advertised fragment length.
    copied: u64,
}

impl<R: Read, W: Write> Read for CopyingReader<R, W> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.input.read(buffer)?;
        self.output.write_all(&buffer[..count])?;
        self.digest.update(&buffer[..count]);
        self.copied += count as u64;
        Ok(count)
    }
}

/// Check an entire package fragment while copying it to its destination.
/// Hashes describe the received bytes and file tree; malformed paths and trailing
/// archive data fail before callers can publish the destination.
pub fn inspect(input: impl Read, output: impl Write, length: u64, name: &str) -> Result<Identity> {
    let mut archive = tar::Archive::new(CopyingReader {
        input,
        output,
        digest: Sha256::new(),
        copied: 0,
    });
    let mut index = Vec::new();
    let mut records = BTreeMap::new();
    let mut end = 0;
    for item in archive.entries()? {
        let mut item = item?;
        end = item
            .raw_file_position()
            .checked_add(
                item.size()
                    .div_ceil(512)
                    .checked_mul(512)
                    .context("tar member length overflow")?,
            )
            .context("tar extent overflow")?;
        index.push(IndexEntry::from_entry(&item)?);
        let path = item.path()?.into_owned();
        ensure!(
            !path.is_absolute()
                && !path
                    .components()
                    .any(|c| c == std::path::Component::ParentDir),
            "unsafe object tar path"
        );
        let mut components = path.components();
        ensure!(
            components.next().is_some_and(|c| c.as_os_str() == name),
            "object tar path has wrong root"
        );
        let relative = components.collect::<PathBuf>();
        let kind = item.header().entry_type();
        ensure!(
            kind.is_file() || item.size() == 0,
            "non-file tar member has payload"
        );
        let mode = item.header().mode()? & 0o7777;
        let (kind, value) = if kind.is_dir() {
            ('D', String::new())
        } else if kind.is_symlink() {
            (
                'L',
                item.link_name()?
                    .context("missing symlink target")?
                    .to_str()
                    .context("non-UTF8 symlink")?
                    .to_owned(),
            )
        } else {
            ensure!(kind.is_file(), "unsupported object tar member type");
            let mut digest = Sha256::new();
            let mut buffer = [0; 1024 * 1024];
            loop {
                let count = item.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                digest.update(&buffer[..count]);
            }
            ('F', hex(&digest.finalize()))
        };
        ensure!(
            records.insert(relative, (kind, mode, value)).is_none(),
            "duplicate object tar path"
        );
    }
    ensure!(
        length > 0 && end == length,
        "object fragment has an embedded terminator or trailing bytes"
    );

    let (kind, mode, value) = records
        .remove(Path::new(""))
        .context("object tar has no root")?;
    let mut digest = Sha256::new();
    match kind {
        'L' => {
            ensure!(records.is_empty(), "symlink tar root has children");
            digest.update(b"L\0");
            digest.update(value);
        }
        'F' => {
            ensure!(records.is_empty(), "file tar root has children");
            digest.update(format!("F\0{mode:o}\0"));
            digest.update(value);
        }
        'D' => {
            for path in records.keys() {
                let mut parent = path.parent();
                while let Some(path) = parent.filter(|path| !path.as_os_str().is_empty()) {
                    ensure!(
                        records.get(path).is_some_and(|(kind, _, _)| *kind == 'D'),
                        "object tar member has a missing or non-directory parent"
                    );
                    parent = path.parent();
                }
            }
            digest.update(b"D\0");
            for (path, (kind, mode, value)) in records {
                let path = path.to_str().context("non-UTF8 tar path")?;
                match kind {
                    'L' => digest.update(format!("L\0{path}\0{value}\0")),
                    'D' => digest.update(format!("D\0{path}\0{mode:o}\0")),
                    'F' => {
                        digest.update(format!("F\0{path}\0{mode:o}\0"));
                        digest.update(value);
                        digest.update(b"\0");
                    }
                    _ => unreachable!(),
                }
            }
        }
        _ => unreachable!(),
    }
    let copied = archive.into_inner();
    ensure!(copied.copied == length, "truncated package fragment");
    Ok(Identity {
        tree_hash: hex(&digest.finalize()),
        sha256: hex(&copied.digest.finalize()),
        index,
    })
}

/// Read headers from a previously admitted fragment without rereading its file data.
/// The caller must establish the extent's stored identity before using this cache input.
pub fn index(mut file: std::fs::File, offset: u64, length: u64) -> Result<Vec<IndexEntry>> {
    ensure!(
        length > 0
            && offset
                .checked_add(length)
                .is_some_and(|end| file.metadata().is_ok_and(|metadata| end <= metadata.len())),
        "fragment lies outside its backing file"
    );
    file.seek(SeekFrom::Start(offset))?;
    let mut archive = tar::Archive::new(RangeReader {
        file,
        start: offset,
        length,
        position: 0,
    });
    let mut result = Vec::new();
    for entry in archive.entries_with_seek()? {
        result.push(IndexEntry::from_entry(&entry?)?);
    }
    ensure!(
        result
            .last()
            .is_some_and(|entry| entry.offset + entry.size.div_ceil(512) * 512 == length),
        "invalid cached fragment extent"
    );
    Ok(result)
}

/// A seekable fragment cannot read adjacent objects in its backing segment.
struct RangeReader {
    // Open backing file, never reopened through an untrusted path during a scan.
    file: std::fs::File,
    // Physical beginning of the admitted extent.
    start: u64,
    // Maximum visible byte count.
    length: u64,
    // Current position relative to the extent start.
    position: u64,
}

impl Read for RangeReader {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = (bytes.len() as u64).min(self.length - self.position) as usize;
        let read = self.file.read(&mut bytes[..count])?;
        self.position += read as u64;
        Ok(read)
    }
}

impl Seek for RangeReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let position = match position {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::Current(value) => i128::from(self.position) + i128::from(value),
            SeekFrom::End(value) => i128::from(self.length) + i128::from(value),
        };
        if !(0..=i128::from(self.length)).contains(&position) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek outside fragment",
            ));
        }
        self.file
            .seek(SeekFrom::Start(self.start + position as u64))?;
        self.position = position as u64;
        Ok(self.position)
    }
}

/// Append metadata-only tar records with offsets into the VM's exact object map.
/// EROFS's existing OCI index reader takes file offsets from the device-major
/// bytes and omits regular-file payloads. Only locally derived indexes use this
/// encoding; the artifact wire protocol continues to carry ordinary tar data.
pub fn append_index<W: Write>(
    archive: &mut tar::Builder<W>,
    entries: &[IndexEntry],
    name: &str,
    base: u64,
    length: u64,
) -> Result<()> {
    for entry in entries {
        let mut components = entry.path.components();
        ensure!(
            components
                .next()
                .is_some_and(|part| part.as_os_str() == name)
                && components.all(|part| matches!(part, std::path::Component::Normal(_))),
            "unsafe cached index path"
        );
        ensure!(
            entry
                .offset
                .checked_add(entry.size)
                .is_some_and(|end| end <= length),
            "cached index exceeds object bounds"
        );
        let kind = tar::EntryType::new(entry.kind);
        ensure!(
            kind.is_file() || kind.is_dir() || kind.is_symlink(),
            "invalid cached index type"
        );
        let mut header = tar::Header::new_ustar();
        header.set_entry_type(kind);
        header.set_mode(entry.mode);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(1);
        header.set_size(entry.size);
        if kind.is_file() {
            let offset = base
                .checked_add(entry.offset)
                .context("file index offset overflow")?;
            header.as_mut_bytes()[329..337].copy_from_slice(&offset.to_le_bytes());
        }
        // POSIX extensions preserve long UTF-8 paths and targets. Use a short
        // placeholder in the following header; EROFS resolves the extension.
        let path = entry.path.to_str().context("non-UTF8 index path")?;
        let link = entry
            .link
            .as_ref()
            .map(|path| path.to_str().context("non-UTF8 index link"))
            .transpose()?;
        let mut extensions = vec![("path", path.as_bytes())];
        if let Some(link) = link {
            extensions.push(("linkpath", link.as_bytes()));
        }
        archive.append_pax_extensions(extensions)?;
        if kind.is_symlink() {
            header.set_link_name("link")?;
        }
        header.set_cksum();
        // This format deliberately has headers but no ordinary-file payload.
        archive.append_data(&mut header, "entry", io::empty())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };

    /// Streaming identities match the established wire format for every supported object type.
    #[test]
    fn inspection_preserves_tree_identity_and_rejects_trailing_data() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let name = "00000000000000000000000000000000-object";
        let source = temporary.path().join(name);
        for kind in ["file", "directory", "symlink"] {
            match kind {
                "file" => fs::write(&source, b"payload")?,
                "directory" => {
                    fs::create_dir(&source)?;
                    let long = source.join("long-name-".repeat(20));
                    fs::write(&long, b"payload")?;
                    fs::set_permissions(&long, fs::Permissions::from_mode(0o755))?;
                    fs::hard_link(&long, source.join("hard"))?;
                    symlink("target-".repeat(30), source.join("link"))?;
                }
                "symlink" => symlink("target", &source)?,
                _ => unreachable!(),
            }
            let tar = temporary.path().join("object.tar");
            crate::artifact::create_tar_fragment(&source, &tar)?;
            let bytes = fs::read(&tar)?;
            let mut copied = Vec::new();
            let value = inspect(bytes.as_slice(), &mut copied, bytes.len() as u64, name)?;
            assert_eq!(copied, bytes);
            assert_eq!(value.tree_hash, crate::artifact::tree_hash(&source)?);
            assert_eq!(value.sha256, hex(&Sha256::digest(&bytes)));
            assert_eq!(
                serde_json::to_value(&value.index)?,
                serde_json::to_value(index(std::fs::File::open(&tar)?, 0, bytes.len() as u64)?)?
            );
            let mut trailing = bytes.clone();
            trailing.extend_from_slice(&[0; 1024]);
            assert!(inspect(trailing.as_slice(), io::sink(), trailing.len() as u64, name).is_err());
            assert!(
                inspect(
                    &bytes[..bytes.len() - 1],
                    io::sink(),
                    bytes.len() as u64,
                    name
                )
                .is_err()
            );
            assert!(
                inspect(
                    bytes.as_slice(),
                    io::sink(),
                    bytes.len() as u64,
                    "wrong-root"
                )
                .is_err()
            );
            if kind == "directory" {
                fs::remove_dir_all(&source)?;
            } else {
                fs::remove_file(&source)?;
            }
        }
        Ok(())
    }
}
