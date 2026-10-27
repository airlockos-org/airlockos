//! Copy only after consuming the checked disk, image and write-mode binding.
//!
//! Verus checks the production request decisions in `airlock-provisioning-core`. This adapter owns
//! the actual source/destination files and performs the observations supplied to those decisions.
//! Hashing, field projection, Nix output-to-image resolution, kernel observations and faithful I/O
//! remain trusted. Metadata checks detect ordinary concurrent source changes; they do not make the
//! source immutable or the disk observations atomic. The proof covers permission for the first write,
//! not copy-loop correctness, crash durability, later partition growth or personalization.

use super::{
    device,
    progress::{self, Progress},
};
use crate::support::run;
use airlock_provisioning_core as verified;
use anyhow::{Context, Result, ensure};
use rustix::fs::{SeekFrom as NativeSeek, seek};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, Metadata},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::Command,
};

const CHUNK: usize = 8 * 1024 * 1024;

/// Project actual descriptor metadata without substituting a later pathname lookup.
fn version(metadata: &Metadata) -> verified::ImageVersion {
    verified::ImageVersion {
        device: metadata.dev(),
        inode: metadata.ino(),
        bytes: metadata.len(),
        modified: metadata.mtime(),
        modified_ns: metadata.mtime_nsec(),
        changed: metadata.ctime(),
        changed_ns: metadata.ctime_nsec(),
    }
}

/// Pinned source descriptor and the evidence obtained by hashing that exact file.
pub(super) struct CheckedSource {
    // Opened source, never reopened by pathname for copying.
    file: File,
    // Stable descriptor metadata, actual digest and supplying publication.
    evidence: verified::CheckedImage,
}

impl CheckedSource {
    /// Hash the opened source and require its original image policy before any target unmounting.
    pub(super) fn check(
        mut file: File,
        before: &Metadata,
        publication: Option<String>,
        authority: &verified::Authority,
    ) -> Result<Self> {
        file.seek(SeekFrom::Start(512))?;
        let mut header = [0; 8];
        file.read_exact(&mut header)?;
        file.rewind()?;
        let mut hash = Sha256::new();
        let mut bytes = vec![0; CHUNK];
        loop {
            let read = file.read(&mut bytes)?;
            if read == 0 {
                break;
            }
            hash.update(&bytes[..read]);
        }
        let digest = format!("{digest:x}", digest = hash.finalize());
        let after = file.metadata()?;
        let evidence = verified::CheckedImage::check(
            version(before),
            version(&after),
            digest,
            publication,
            after.is_file(),
            &header == b"EFI PART",
        )
        .context(
            "image changed while hashing, is not a regular GPT image, or has an invalid digest",
        )?;
        ensure!(
            authority.accepts(&evidence),
            "image digest or supplying build output differs from original write authority"
        );
        file.rewind()?;
        Ok(Self { file, evidence })
    }
}

/// Both opened descriptors and the verified request move together into the only production image-copy entry point.
pub(super) struct WriteRequest {
    // Pinned and checked image source.
    source: File,
    // Exclusively opened destination, checked through this exact descriptor before construction.
    destination: File,
    // Complete original disk/image/mode binding.
    evidence: verified::WriteRequest,
    // Fresh unused-disk snapshot for post-write observations.
    disk: device::Disk,
    // Original by-id path used only for subsequent read-only identity rechecks.
    by_id: PathBuf,
}

impl WriteRequest {
    /// Inspect the actual opened USB, then require exact target, source, capacity and image-policy agreement.
    pub(super) fn new(
        source: CheckedSource,
        destination: File,
        authority: verified::Authority,
        by_id: &Path,
        mode: verified::CopyMode,
    ) -> Result<Self> {
        let disk = device::checked(by_id)?;
        let observed = disk.evidence()?;
        let opened = device::opened(&destination)?;
        let current_source = version(&source.file.metadata()?);
        let evidence = authority.request(source.evidence, &observed, &opened, &current_source, mode)
            .context("USB write request differs from confirmed disk, checked image, supplying output or fresh unused state")?;
        Ok(Self {
            source: source.file,
            destination,
            evidence,
            disk,
            by_id: by_id.to_owned(),
        })
    }
}

/// Consume a verified request; callers cannot supply replacement descriptors, bounds or verification flags.
pub(super) fn execute(mut request: WriteRequest) -> Result<()> {
    let written = copy(
        &mut request.source,
        &mut request.destination,
        request.evidence.sparse(),
        request.evidence.bytes(),
    )?;
    ensure!(
        request
            .evidence
            .source_matches(&version(&request.source.metadata()?)),
        "image changed while writing"
    );
    progress::waiting("Flushing USB device", Some(&request.disk.name), || {
        Ok(request.destination.sync_all()?)
    })?;
    request.disk.same_disk(&device::checked(&request.by_id)?)?;
    if request.evidence.verify() {
        request.destination.rewind()?;
        let mut hash = Sha256::new();
        let size = request.evidence.bytes();
        let mut remaining = size;
        let mut bytes = vec![0; CHUNK];
        let mut progress = Progress::new("Verifying image", size);
        while remaining > 0 {
            let count = remaining.min(bytes.len() as u64) as usize;
            let read = request.destination.read(&mut bytes[..count])?;
            ensure!(read != 0, "Unexpected end of USB during verification.");
            hash.update(&bytes[..read]);
            remaining -= read as u64;
            progress.report(size - remaining);
        }
        ensure!(
            format!("{digest:x}", digest = hash.finalize()) == request.evidence.digest(),
            "USB read-back verification failed."
        );
    }
    let pinned = device::release_writer(request.destination)?;
    request.disk.same_disk(&device::checked(&request.by_id)?)?;
    println!("Refreshing USB partition table…");
    run(Command::new("blockdev").arg("--rereadpt").arg(format!("/proc/{process}/fd/{descriptor}",process=std::process::id(),descriptor=std::os::fd::AsRawFd::as_raw_fd(&pinned))))
        .context("Image written and flushed, but partition refresh failed; expansion and personalization have not run.")?;
    request.disk.same_disk(&device::checked(&request.by_id)?)?;
    if request.evidence.verify() {
        println!("Image fully written ({written} bytes), flushed and verified.");
    } else {
        println!(
            "Image {mode} written ({written} bytes) and flushed; full read-back verification was skipped.",
            mode = if request.evidence.sparse() {
                "sparsely"
            } else {
                "fully"
            }
        );
    }
    println!("Previous USB contents were overwritten and are not recoverable by this tool.");
    Ok(())
}

fn extents(source: &File, size: u64) -> Result<Vec<(u64, u64)>> {
    let mut result = Vec::new();
    let mut offset = 0;
    while offset < size {
        let start =
            match seek(source, NativeSeek::Data(offset)) {
                Ok(start) => start,
                Err(rustix::io::Errno::NXIO) => break,
                Err(error) => return Err(error).context(
                    "Source filesystem does not support sparse image extents; use --full-write.",
                ),
            };
        let end = seek(source, NativeSeek::Hole(start))?.min(size);
        ensure!(
            start >= offset && start < end,
            "Invalid sparse image extent"
        );
        result.push((start, end));
        ensure!(
            result.len() <= 1_000_000,
            "Image has too many sparse extents"
        );
        offset = end;
    }

    Ok(result)
}

fn copy(source: &mut File, destination: &mut File, sparse: bool, size: u64) -> Result<u64> {
    ensure!(
        source.metadata()?.len() == size,
        "Image changed size before writing"
    );
    let ranges = if sparse {
        extents(source, size)?
    } else {
        vec![(0, size)]
    };

    let total: u64 = ranges.iter().map(|(a, b)| b - a).sum();
    let mut progress = Progress::new(
        if sparse {
            "Writing sparse extents"
        } else {
            "Writing image"
        },
        total,
    );
    let mut buffer = vec![0; CHUNK];
    let mut copied = 0;

    for (start, end) in ranges {
        source.seek(SeekFrom::Start(start))?;
        destination.seek(SeekFrom::Start(start))?;
        let mut remaining = end - start;
        while remaining > 0 {
            let size = source.read(&mut buffer[..remaining.min(CHUNK as u64) as usize])?;
            ensure!(size != 0, "Unexpected end of image extent.");
            destination.write_all(&buffer[..size])?;
            copied += size as u64;
            remaining -= size as u64;
            progress.report(copied);
        }
    }

    ensure!(
        source.metadata()?.len() == size,
        "Image changed size while writing"
    );
    progress.report(copied);

    Ok(copied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions};

    /// A test-only standalone command binds an independent digest without touching a block device.
    fn authority(digest: String) -> verified::Authority {
        verified::SelectedUsb::check(verified::Observation {
            disk: verified::Disk {
                name: "/dev/fixture".into(),
                number: 1,
                sequence: 1,
                serial: "fixture".into(),
                bytes: 4 * 1024 * 1024,
            },
            usb: true,
            whole: true,
            writable: true,
            unmounted: true,
            unheld: true,
        })
        .unwrap()
        .confirm(verified::Intent::Write, "fixture")
        .unwrap()
        .direct(digest)
        .unwrap()
    }

    /// Hashing and copying retain the same descriptor even if its old pathname now names another file.
    #[test]
    fn checked_source_keeps_the_open_file_and_refuses_regular_destinations() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join("image.img");
        let mut image = vec![0; 2 * 1024 * 1024];
        image[512..520].copy_from_slice(b"EFI PART");
        fs::write(&path, &image)?;
        let source = File::open(&path)?;
        fs::rename(&path, temporary.path().join("original.img"))?;
        fs::write(&path, b"replacement")?;
        let before = source.metadata()?;
        let digest = format!("{digest:x}", digest = Sha256::digest(&image));
        let mut checked = CheckedSource::check(source, &before, None, &authority(digest))?;
        assert_ne!(checked.file.metadata()?.ino(), fs::metadata(&path)?.ino());
        let mut content = Vec::new();
        checked.file.read_to_end(&mut content)?;
        assert_eq!(content, image);
        assert!(device::opened(&checked.file).is_err());
        Ok(())
    }

    /// A changed source size must fail before the first destination write, rather than supply new bounds.
    #[test]
    fn changed_image_size_cannot_replace_the_checked_write_bound() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let image = temporary.path().join("image");
        let target = temporary.path().join("target");
        fs::write(&image, b"image grew")?;
        fs::write(&target, b"untouched")?;
        assert!(
            copy(
                &mut File::open(&image)?,
                &mut OpenOptions::new().read(true).write(true).open(&target)?,
                false,
                5,
            )
            .is_err()
        );
        assert_eq!(fs::read(&target)?, b"untouched");
        Ok(())
    }

    /// Plain-file tests exercise the copy adapter without exposing a raw production write entry point.
    #[test]
    fn sparse_holes_and_full_materialization_remain_distinct() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let image = temporary.path().join("seed.img");
        let mut source = File::create(&image)?;
        source.write_all(b"first")?;
        source.seek(SeekFrom::Start(1024 * 1024))?;
        source.write_all(b"last")?;
        let content = fs::read(&image)?;
        for sparse in [true, false] {
            let target = temporary.path().join(format!("target-{sparse}"));
            fs::write(&target, vec![b'x'; content.len()])?;
            let count = copy(
                &mut File::open(&image)?,
                &mut OpenOptions::new().read(true).write(true).open(&target)?,
                sparse,
                content.len() as u64,
            )?;
            let bytes = fs::read(target)?;
            assert_eq!(&bytes[..5], b"first");
            assert_eq!(&bytes[bytes.len() - 4..], b"last");
            if sparse {
                assert!(count < content.len() as u64);
                assert_eq!(bytes[512 * 1024], b'x');
            } else {
                assert_eq!(count, content.len() as u64);
                assert_eq!(bytes, content);
            }
        }
        Ok(())
    }
}
