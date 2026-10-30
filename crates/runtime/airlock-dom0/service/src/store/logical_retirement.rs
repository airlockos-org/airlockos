//! Logical cleanup derives every deletion permission from the original immutable protection trace.
//! Callers retain admission exclusion through discovery, request construction and filesystem execution.

use super::{fs::*, mounts, segments};
use airlock_deployment_core::retention::{
    logical::{DeleteRequest, ResourceIndex, Target},
    tracing::Trace,
};
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
};

/// Resolve only the physical namespace represented by the exact request category.
fn path(root: &Path, target: &Target) -> Result<PathBuf> {
    let path = match target {
        Target::ObjectMetadata(name) => root
            .join("objects/metadata")
            .join(format!("{name}.json", name = component(name)?)),
        Target::FragmentMetadata(name) => root
            .join("objects/blob-metadata")
            .join(format!("{name}.json", name = component(name)?)),
        Target::View(recorded) => {
            let path = PathBuf::from(recorded);
            ensure!(
                path.parent() == Some(root.join("views/by-closure").as_path()),
                "view cleanup target is outside its namespace"
            );
            component(
                path.file_name()
                    .and_then(|n| n.to_str())
                    .context("invalid view identity")?,
            )?;
            path
        }
        Target::Root(name) => root.join("root-artifacts").join(component(name)?),
    };
    pool_path(root, &path)?;
    Ok(path)
}

/// Validate kind and mounts before any cleanup begins, and again immediately before each removal.
fn preflight(root: &Path, target: &Target) -> Result<PathBuf> {
    let path = path(root, target)?;
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            let expected = match target {
                Target::ObjectMetadata(_) | Target::FragmentMetadata(_) => metadata.is_file(),
                Target::View(_) | Target::Root(_) => metadata.is_dir(),
            };
            ensure!(
                expected,
                "logical cleanup target has an unexpected file type: {path:?}"
            );
            mounts::ensure_unmounted(&fs::canonicalize(&path)?)?;
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    if let Target::FragmentMetadata(name) = target {
        let index = segments::file_index(root, name)?;
        if index.try_exists()? {
            ensure!(
                fs::symlink_metadata(&index)?.is_file(),
                "file index is not a regular file"
            );
            mounts::ensure_unmounted(&fs::canonicalize(&index)?)?;
        }
    }
    Ok(path)
}

/// Prepare every logical deletion before generation removal or other destructive GC effects.
pub(super) fn prepare<'a>(root: &Path, trace: &'a Trace) -> Result<Vec<DeleteRequest<'a>>> {
    let index = ResourceIndex::new(
        root.to_str().context("non-UTF-8 pool identity")?.to_owned(),
        trace,
    )
    .context("invalid logical protection index")?;
    let mut requests = Vec::new();
    for directory in [
        "objects/metadata",
        "objects/blob-metadata",
        "objects/file-indexes",
        "views/by-closure",
        "root-artifacts",
    ] {
        for candidate in children(&root.join(directory))? {
            let target = match directory {
                "objects/metadata" | "objects/blob-metadata" | "objects/file-indexes" => {
                    if candidate.extension().is_none_or(|ext| ext != "json") {
                        continue;
                    }
                    let name = candidate
                        .file_stem()
                        .and_then(|n| n.to_str())
                        .context("invalid metadata identity")?
                        .to_owned();
                    if directory == "objects/file-indexes"
                        && segments::object_metadata(root, &name)?.try_exists()?
                    {
                        continue;
                    }
                    if directory == "objects/metadata" {
                        Target::ObjectMetadata(name)
                    } else {
                        Target::FragmentMetadata(name)
                    }
                }
                "views/by-closure" => Target::View(
                    candidate
                        .to_str()
                        .context("non-UTF-8 view identity")?
                        .to_owned(),
                ),
                "root-artifacts" => Target::Root(
                    candidate
                        .file_name()
                        .and_then(|n| n.to_str())
                        .context("invalid root identity")?
                        .to_owned(),
                ),
                _ => unreachable!("fixed logical cleanup namespace"),
            };
            ensure!(
                if directory == "objects/file-indexes" {
                    matches!(&target, Target::FragmentMetadata(name) if segments::file_index(root, name).is_ok_and(|path| path == candidate))
                } else {
                    path(root, &target)? == candidate
                },
                "logical cleanup identity mismatch"
            );
            if let Some(request) = index.reclaim(target) {
                preflight(root, request.target())?;
                requests.push(request);
            }
        }
    }
    Ok(requests)
}

/// Consume the original permission; a caller cannot resupply its pool, path or resource category.
pub(super) fn execute(request: DeleteRequest<'_>) -> Result<()> {
    let root = Path::new(request.pool());
    let path = preflight(root, request.target())?;
    failpoint("gc-before-logical-delete")?;
    if let Target::FragmentMetadata(name) = request.target() {
        // The file-header cache has the same lifetime and protection as its
        // admitted fragment. Remove it first so interrupted cleanup is retryable.
        let index = segments::file_index(root, name)?;
        remove(&index)?;
        if let Some(parent) = index.parent().filter(|parent| parent.exists()) {
            sync_dir(parent)?;
        }
    }
    match request.target() {
        Target::ObjectMetadata(_) | Target::FragmentMetadata(_) => match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        },
        Target::View(_) | Target::Root(_) => remove(&path)?,
    }
    sync_dir(path.parent().context("logical target has no parent")?)?;
    match request.target() {
        Target::View(_) => failpoint("gc-after-view-delete")?,
        Target::Root(_) => failpoint("gc-after-root-delete")?,
        Target::ObjectMetadata(_) | Target::FragmentMetadata(_) => {}
    }
    failpoint("gc-after-logical-delete")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// Empty pool namespaces in ordinary disposable directories; no kernel devices are used.
    fn pool(root: &Path) -> Result<()> {
        for directory in [
            "objects/metadata",
            "objects/blob-metadata",
            "objects/file-indexes",
            "views/by-closure",
            "root-artifacts",
        ] {
            fs::create_dir_all(root.join(directory))?;
        }
        Ok(())
    }

    #[test]
    fn original_pool_category_and_target_are_the_only_coordinates_removed() -> Result<()> {
        let fixture = tempfile::tempdir()?;
        let root = fixture.path().join("pool");
        let other = fixture.path().join("other");
        for root in [&root, &other] {
            pool(root)?;
            for directory in ["objects/metadata", "objects/blob-metadata"] {
                fs::write(root.join(directory).join("same.json"), b"original")?;
                fs::write(root.join(directory).join("sibling.json"), b"sibling")?;
            }
            fs::write(segments::file_index(root, "same")?, b"build headers")?;
            fs::write(segments::file_index(root, "sibling")?, b"retained headers")?;
            fs::create_dir(root.join("views/by-closure/same"))?;
            fs::create_dir(root.join("root-artifacts/same"))?;
        }
        let trace = Trace::new();
        let index = ResourceIndex::new(root.to_str().unwrap().into(), &trace).unwrap();
        execute(
            index
                .reclaim(Target::ObjectMetadata("same".into()))
                .unwrap(),
        )?;
        assert!(!root.join("objects/metadata/same.json").exists());
        assert_eq!(
            fs::read(root.join("objects/blob-metadata/same.json"))?,
            b"original"
        );
        assert_eq!(
            fs::read(root.join("objects/metadata/sibling.json"))?,
            b"sibling"
        );
        assert_eq!(
            fs::read(other.join("objects/metadata/same.json"))?,
            b"original"
        );

        for _ in 0..2 {
            execute(
                index
                    .reclaim(Target::FragmentMetadata("same".into()))
                    .unwrap(),
            )?;
            execute(
                index
                    .reclaim(Target::View(
                        root.join("views/by-closure/same").to_str().unwrap().into(),
                    ))
                    .unwrap(),
            )?;
            execute(index.reclaim(Target::Root("same".into())).unwrap())?;
        }
        assert!(!segments::file_index(&root, "same")?.exists());
        assert_eq!(
            fs::read(segments::file_index(&root, "sibling")?)?,
            b"retained headers"
        );
        // Interrupted admission can leave headers without their fragment record.
        let orphan = segments::file_index(&root, "orphan")?;
        fs::write(&orphan, b"unpublished headers")?;
        let request = prepare(&root, &trace)?.into_iter().find(|request| {
            matches!(request.target(), Target::FragmentMetadata(name) if name == "orphan")
        }).expect("orphan cache shares fragment cleanup authority");
        execute(request)?;
        assert!(!orphan.exists());
        assert!(other.join("views/by-closure/same").is_dir());
        assert!(other.join("root-artifacts/same").is_dir());
        assert_eq!(
            fs::read(root.join("objects/blob-metadata/sibling.json"))?,
            b"sibling"
        );
        Ok(())
    }

    #[test]
    fn directories_symlinks_and_cross_namespace_view_targets_cannot_escape_the_adapter()
    -> Result<()> {
        let fixture = tempfile::tempdir()?;
        let root = fixture.path().join("pool");
        pool(&root)?;
        let outside = fixture.path().join("outside");
        fs::create_dir(&outside)?;
        fs::write(outside.join("keep"), b"preserve")?;
        let trace = Trace::new();
        let index = ResourceIndex::new(root.to_str().unwrap().into(), &trace).unwrap();
        let metadata = root.join("objects/metadata/changed.json");
        fs::write(&metadata, b"original")?;
        let request = index
            .reclaim(Target::ObjectMetadata("changed".into()))
            .unwrap();
        fs::remove_file(&metadata)?;
        fs::create_dir(&metadata)?;
        fs::write(metadata.join("keep"), b"preserve")?;
        assert!(execute(request).is_err());
        assert_eq!(fs::read(metadata.join("keep"))?, b"preserve");

        let fragment = segments::object_metadata(&root, "redirected")?;
        fs::write(&fragment, b"preserve fragment")?;
        symlink(
            outside.join("keep"),
            segments::file_index(&root, "redirected")?,
        )?;
        assert!(
            execute(
                index
                    .reclaim(Target::FragmentMetadata("redirected".into()))
                    .unwrap()
            )
            .is_err()
        );
        assert_eq!(fs::read(&fragment)?, b"preserve fragment");

        symlink(&outside, root.join("root-artifacts/redirected"))?;
        assert!(execute(index.reclaim(Target::Root("redirected".into())).unwrap()).is_err());
        assert!(
            execute(
                index
                    .reclaim(Target::View(outside.to_str().unwrap().into()))
                    .unwrap()
            )
            .is_err()
        );
        assert!(execute(index.reclaim(Target::Root("../outside".into())).unwrap()).is_err());
        let view = root.join("views/by-closure/nested");
        fs::create_dir(&view)?;
        symlink(&outside, view.join("link"))?;
        execute(
            index
                .reclaim(Target::View(view.to_str().unwrap().into()))
                .unwrap(),
        )?;
        assert_eq!(fs::read(outside.join("keep"))?, b"preserve");
        Ok(())
    }
}
