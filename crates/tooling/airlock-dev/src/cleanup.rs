//! Remove explicitly selected generated workstation artifacts without following output links into their targets.

use crate::{environment::Environment, gc};
use anyhow::{Context, Result, ensure};
use clap::ValueEnum;
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

/// Existing generated-artifact cleanup operations, kept separate from Nix garbage collection.
#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum Mode {
    /// Show the available generated-artifact categories without touching the filesystem.
    Usage,
    /// Report selected generated directories without deleting anything.
    DiskUsage,
    /// Remove generated disk overlays, monitor sockets, firmware state and output links.
    VmDisks,
    /// Remove generated VM work directories, including their test logs and overlays.
    VmWorkdirs,
    /// Remove only the generated result-link directory, leaving store objects untouched.
    ResultLinks,
    /// Remove the selected generated log directory.
    Logs,
    /// Remove the selected cache root, including cached RPM assets.
    Cache,
}

/// Enumerate children without following directory symlinks; an absent work directory is empty.
fn children(path: &Path) -> Result<Vec<fs::DirEntry>> {
    match fs::read_dir(path) {
        Ok(entries) => Ok(entries.collect::<std::io::Result<Vec<_>>>()?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error.into()),
    }
}

/// Delete one generated path, refusing broad roots and preserving symlink target contents.
fn remove(path: &Path, protected: &[PathBuf]) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let parent = gc::canonical(path.parent().context("cleanup target has no parent")?)?;
    let identity = parent.join(path.file_name().context("cleanup target has no filename")?);
    ensure!(
        identity != Path::new("/")
            && !protected
                .iter()
                .any(|protected| protected.starts_with(&identity)),
        "refusing cleanup of a protected root or its ancestor: {identity}",
        identity = identity.display()
    );
    println!("{path}", path = path.display());
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(())
}

/// Execute one existing cleanup mode against the same selected workstation environment.
pub(crate) fn execute(root: &Path, mode: Mode) -> Result<()> {
    if matches!(mode, Mode::Usage) {
        println!(
            "usage: airlock-dev clean MODE\nModes: disk-usage, vm-disks, vm-workdirs, result-links, logs, cache"
        );
        return Ok(());
    }
    let environment = Environment::load()?;
    let data = environment.path("AIRLOCK_DATA_ROOT", root.join(".airlock"));
    let vm = environment.path("AIRLOCK_VM_DIR", root.join(".airlock-vm"));
    let logs = environment.path("AIRLOCK_LOG_DIR", root.join(".airlock-logs"));
    let links = environment.path("AIRLOCK_RESULT_LINK_DIR", data.join("result-links"));
    let cache = environment.path("AIRLOCK_QUBES_CACHE_DIR", root.join(".airlock-cache/rpms"));
    let cache = if cache.file_name().is_some_and(|name| name == "rpms") {
        cache.parent().unwrap().to_owned()
    } else {
        cache
    };
    let nix = environment.path("AIRLOCK_NIX_ROOT", data.join("nix-root"));
    let protected = [
        root.to_owned(),
        data,
        nix.clone(),
        PathBuf::from("/nix"),
        PathBuf::from("/nix/store"),
        PathBuf::from("/home"),
        PathBuf::from("/run/media"),
        PathBuf::from("/etc"),
        PathBuf::from("/usr"),
        PathBuf::from("/var"),
        PathBuf::from("/run"),
        PathBuf::from("/tmp"),
        PathBuf::from("/dev"),
        PathBuf::from("/proc"),
        PathBuf::from("/sys"),
    ]
    .into_iter()
    .map(|path| gc::canonical(&path))
    .collect::<Result<Vec<_>>>()?;
    if matches!(mode, Mode::DiskUsage) {
        let mut paths = [vm, links, logs, cache, nix]
            .into_iter()
            .collect::<BTreeSet<_>>();
        for entry in children(root)? {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(".airlock-") || name == "result" || name.starts_with("result-") {
                paths.insert(entry.path());
            }
        }
        let output = airlock_nix_core::runtime::process::run(
            Command::new("du").args(["-sh", "--"]).args(paths),
            None,
            Some(std::time::Duration::from_secs(600)),
        )?;
        use std::io::Write;
        std::io::stdout().write_all(&output.stdout)?;
        return Ok(());
    }
    if matches!(mode, Mode::VmDisks | Mode::VmWorkdirs) {
        ensure!(
            !gc::vm_running(&vm)?,
            "refusing cleanup while an Airlock QEMU VM appears to be running"
        );
    }
    match mode {
        Mode::VmDisks => {
            for entry in children(&vm)? {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.ends_with("-result")
                    || name.ends_with(".qcow2")
                    || (name.contains(".qcow2.") && name.ends_with(".bak"))
                    || name.ends_with(".monitor")
                    || name.ends_with("-OVMF_VARS.fd")
                    || name == "serial.log"
                {
                    remove(&entry.path(), &protected)?;
                }
            }
        }
        Mode::VmWorkdirs => {
            let mut targets = BTreeSet::from([vm]);
            for entry in children(root)? {
                if entry.file_type()?.is_dir()
                    && entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".airlock-vm")
                {
                    targets.insert(entry.path());
                }
            }
            // Preflight every selected workdir before deleting any of them, including nondefault VMs.
            for target in &targets {
                ensure!(
                    !gc::vm_running(&gc::canonical(target)?)?,
                    "refusing cleanup while an Airlock QEMU VM appears to be running: {target}",
                    target = target.display()
                );
            }
            for target in targets {
                remove(&target, &protected)?;
            }
        }
        Mode::ResultLinks => remove(&links, &protected)?,
        Mode::Logs => remove(&logs, &protected)?,
        Mode::Cache => remove(&cache, &protected)?,
        Mode::DiskUsage | Mode::Usage => unreachable!(),
    }
    // No Nix command is needed to remove generated paths; store deletion remains guarded GC only.
    Ok(())
}
