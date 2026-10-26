//! Isolate upstream boot-menu generation from dangling or already sealed profile history.
//! Prepared entries publish only after installation succeeds, preserving the current default.

use super::{boot_artifacts, fs::*};
use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
};

fn copy_profiles(
    source: &Path,
    target: &Path,
    sealed: &BTreeSet<PathBuf>,
    selected: &Path,
) -> Result<()> {
    mkdir_all(target)?;
    for path in children(source)? {
        let name = path.file_name().context("profile has no name")?;
        if path.is_symlink() && path.try_exists()? {
            let canonical = fs::canonicalize(&path)?;
            if name != "system" && sealed.contains(&canonical) && canonical != selected {
                continue;
            }
            let copied = target.join(name);
            symlink(fs::read_link(&path)?, &copied)?;
            let metadata = fs::symlink_metadata(&path)?;
            use std::os::unix::fs::MetadataExt;
            let timestamps = rustix::fs::Timestamps {
                last_access: rustix::time::Timespec {
                    tv_sec: metadata.atime(),
                    tv_nsec: metadata.atime_nsec(),
                },
                last_modification: rustix::time::Timespec {
                    tv_sec: metadata.mtime(),
                    tv_nsec: metadata.mtime_nsec(),
                },
            };
            rustix::fs::utimensat(
                rustix::fs::CWD,
                &copied,
                &timestamps,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )?;
        } else if path.is_dir() && name == "system-profiles" {
            copy_profiles(&path, &target.join(name), sealed, selected)?;
        }
    }
    Ok(())
}

/// Capture the selected profile and pin its private copy to the requested immutable system.
/// A concurrent profile change must not cause the approved installer to generate another host's boot entry.
fn prepare_profiles(
    source: &Path,
    target: &Path,
    sealed: &BTreeSet<PathBuf>,
    system: &Path,
) -> Result<()> {
    copy_profiles(source, target, sealed, system)?;
    let selected = target.join("system");
    ensure!(
        fs::canonicalize(&selected)? == system,
        "boot installation profile differs from requested host"
    );

    // Eliminate references through mutable global profile links before the namespace mount.
    fs::remove_file(&selected)?;
    symlink(system, selected)?;

    Ok(())
}

pub(super) fn publish_loader(staged: &Path, loader: &Path) -> Result<()> {
    let old = fs::read_to_string(loader.join("loader.conf"))?;
    let choices: Vec<_> = old
        .lines()
        .filter(|line| {
            matches!(
                line.split_whitespace().next(),
                Some("default" | "preferred")
            )
        })
        .collect();
    ensure!(
        choices
            .iter()
            .any(|line| line.split_whitespace().next() == Some("default")),
        "boot preparation requires existing default"
    );
    let protected: BTreeSet<_> = choices
        .iter()
        .filter_map(|line| line.split_whitespace().nth(1))
        .map(|name| name.trim_end_matches(".conf"))
        .collect();
    let entries = loader.join("entries");
    mkdir_all(&entries)?;
    for path in children(&staged.join("entries"))? {
        if path.extension().is_some_and(|s| s == "conf") {
            atomic(
                &entries.join(path.file_name().context("missing entry name")?),
                &fs::read(&path)?,
                0o644,
            )?;
        }
    }
    for path in children(&entries)? {
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .context("invalid entry name")?;
        if path.extension().is_some_and(|s| s == "conf")
            && !staged.join("entries").join(name).try_exists()?
            && !name.starts_with("airlock-")
            && !protected.contains(name.trim_end_matches(".conf"))
        {
            remove(&path)?;
        }
    }
    sync_dir(&entries)?;
    let text = fs::read_to_string(staged.join("loader.conf"))?;
    let lines = choices
        .into_iter()
        .chain(text.lines().filter(|line| {
            !matches!(
                line.split_whitespace().next(),
                Some("default" | "preferred")
            )
        }))
        .collect::<Vec<_>>()
        .join("\n");
    atomic(
        &loader.join("loader.conf"),
        format!("{lines}\n").as_bytes(),
        0o644,
    )
}

pub(super) fn install(system: &str, profiles: &Path, loader: &Path, pool: &Path) -> Result<()> {
    entry(system)?;
    let temporary = tempfile::tempdir()?;
    let copied = temporary.path().join("profiles");
    let mut sealed = BTreeSet::new();
    for path in children(&pool.join("host/boots"))? {
        let record: boot_artifacts::BootRecord = read(&path)?;
        if record.retired == Some(true)
            || !pool
                .join("host/artifacts")
                .join(path.file_name().context("missing boot record name")?)
                .try_exists()?
        {
            continue;
        }
        boot_artifacts::verify(
            pool,
            loader.parent().context("loader has no ESP")?,
            &record.system,
            record.generation,
        )?;
        sealed.insert(PathBuf::from(record.system.as_str()));
    }
    prepare_profiles(profiles, &copied, &sealed, Path::new(system))?;
    ensure!(
        copied.join("system").try_exists()?,
        "selected host profile unavailable"
    );
    let staged = temporary.path().join("loader");
    command(
        "cp",
        &["-a", &loader.to_string_lossy(), &staged.to_string_lossy()],
        None,
    )?;
    command(
        "mount",
        &[
            "--bind",
            &copied.to_string_lossy(),
            &profiles.to_string_lossy(),
        ],
        None,
    )?;
    let result = (|| -> Result<()> {
        command(
            "mount",
            &[
                "--bind",
                &staged.to_string_lossy(),
                &loader.to_string_lossy(),
            ],
            None,
        )?;
        let result = command(
            &format!("{system}/bin/switch-to-configuration"),
            &["boot"],
            None,
        );
        let unmount = command("umount", &[&loader.to_string_lossy()], None);
        result?;
        unmount?;
        Ok(())
    })();
    let unmount = command("umount", &[&profiles.to_string_lossy()], None);
    result?;
    unmount?;
    publish_loader(&staged, loader)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Private boot installation cannot follow a changed global system profile after its check.
    #[test]
    fn private_profile_retains_the_requested_system_and_rejects_substitution() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let system = directory.path().join("system-a");
        let other = directory.path().join("system-b");
        let profiles = directory.path().join("profiles");
        fs::create_dir(&system)?;
        fs::create_dir(&other)?;
        fs::create_dir(&profiles)?;
        symlink(&system, profiles.join("system-1-link"))?;
        symlink("system-1-link", profiles.join("system"))?;
        let copied = directory.path().join("copied");
        prepare_profiles(&profiles, &copied, &BTreeSet::new(), &system)?;
        assert_eq!(fs::read_link(copied.join("system"))?, system);
        fs::remove_file(profiles.join("system-1-link"))?;
        symlink(&other, profiles.join("system-1-link"))?;
        assert_eq!(fs::canonicalize(copied.join("system"))?, system);
        assert!(
            prepare_profiles(
                &profiles,
                &directory.path().join("rejected"),
                &BTreeSet::new(),
                &system
            )
            .is_err()
        );
        Ok(())
    }
}
