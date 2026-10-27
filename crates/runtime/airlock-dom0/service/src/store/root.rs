//! Retained immutable boot disks bind root bytes to committed pool generations.

use super::fs::*;
use anyhow::{Context, Result, ensure};
use std::{
    fs::{File, Permissions},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

pub(super) use airlock_nix_core::artifact::{
    RootDescriptor as Descriptor, decode_root as decode, encode_root as encode,
};

pub(super) fn reusable(root: &Path, descriptor: &Descriptor) -> Result<Option<PathBuf>> {
    descriptor.validate()?;
    let directory = root.join("root-artifacts").join(&descriptor.sha256);
    for path in [
        &directory,
        directory.parent().context("artifact parent missing")?,
    ] {
        ensure!(!path.is_symlink(), "root artifact directory is a symlink");
    }
    if !directory.try_exists()? {
        return Ok(None);
    }
    let image = directory.join("root.img");
    ensure!(
        !image.is_symlink() && !directory.join("artifact.json").is_symlink() && image.is_file(),
        "invalid root artifact files"
    );
    ensure!(
        std::fs::metadata(&image)?.permissions().mode() & 0o222 == 0,
        "root artifact is writable"
    );
    let recorded: Descriptor = read(&directory.join("artifact.json"))?;
    ensure!(
        recorded == *descriptor && encode(&image, None)? == *descriptor,
        "retained root artifact failed verification"
    );
    Ok(Some(image))
}

pub(super) fn install(root: &Path, payload: &Path, descriptor: &Descriptor) -> Result<PathBuf> {
    if let Some(image) = reusable(root, descriptor)? {
        return Ok(image);
    }
    let directory = root.join("root-artifacts").join(&descriptor.sha256);
    let parent = directory.parent().context("missing artifact parent")?;
    mkdir_all(parent)?;
    let temporary = tempfile::tempdir_in(root.join("tmp"))?;
    let image = temporary.path().join("root.img");
    decode(payload, &image, descriptor)?;
    std::fs::set_permissions(&image, Permissions::from_mode(0o444))?;
    File::open(&image)?.sync_all()?;
    write(&temporary.path().join("artifact.json"), descriptor, 0o644)?;
    sync_dir(temporary.path())?;
    std::fs::rename(temporary.path(), &directory)?;
    sync_dir(parent)?;
    Ok(directory.join("root.img"))
}

pub(super) fn source(source: &Path, physical: &Path) -> Result<PathBuf> {
    let mut path = if source.starts_with("/nix/store") {
        physical.join(source.strip_prefix("/nix/store")?)
    } else {
        source.to_path_buf()
    };
    if path.is_dir() {
        path.push("root.img");
    }
    Ok(path)
}

pub(super) fn admit(root: &Path, source_path: &Path, physical: &Path) -> Result<Descriptor> {
    let image = source(source_path, physical)?;
    let descriptor = encode(&image, None)?;
    if reusable(root, &descriptor)?.is_none() {
        let mut payload = tempfile::NamedTempFile::new_in(root.join("tmp"))?;
        ensure!(
            encode(&image, Some(payload.as_file_mut()))? == descriptor,
            "root source changed during admission"
        );
        install(root, payload.path(), &descriptor)?;
    }
    Ok(descriptor)
}
