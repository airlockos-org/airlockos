//! Refresh bootstrap-policy links while retaining the separate runtime-owned topology authority.

use airlock_machine_planning::ipc_policy::CheckedPolicy;
use anyhow::{Result, ensure};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
};

/// Read the existing single managed filename without allowing traversal into other policy files.
fn managed(value: String) -> Result<String> {
    let value = std::env::var("AIRLOCK_QUBES_MANAGED_POLICY_FILE")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or(value);
    ensure!(
        !value.is_empty() && value != "." && value != ".." && !value.contains('/'),
        "invalid managed policy filename"
    );
    Ok(value)
}

/// Remove an obsolete policy entry without following directory symlinks.
fn remove(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_dir() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(())
}

/// Refuse unmanaged authority before changing any runtime-policy entries.
pub(super) fn execute(
    static_dir: PathBuf,
    runtime_dir: PathBuf,
    managed_file: String,
) -> Result<()> {
    let static_dir = std::env::var_os("AIRLOCK_QUBES_STATIC_POLICY_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or(static_dir);
    let runtime_dir = std::env::var_os("AIRLOCK_QUBES_POLICY_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or(runtime_dir);
    let managed_file = managed(managed_file)?;
    let managed_path = runtime_dir.join(&managed_file);
    const MARKER: &str = "# Managed by Airlock setup-config.";
    let exists = managed_path.symlink_metadata().is_ok();
    if exists {
        ensure!(
            fs::read_to_string(&managed_path)?
                .lines()
                .any(|line| line == MARKER),
            "refusing unmanaged Airlock qrexec policy file: {path}",
            path = managed_path.display()
        );
    }
    // Resolve the complete static set before removing old links, so a broken source cannot leave a partial refresh.
    let mut sources = Vec::new();
    if static_dir.is_dir() {
        for entry in fs::read_dir(&static_dir)? {
            let entry = entry?;
            if entry.file_name() == managed_file.as_str() {
                continue;
            }
            sources.push((entry.file_name(), fs::canonicalize(entry.path())?));
        }
    }
    fs::create_dir_all(&runtime_dir)?;
    fs::set_permissions(&runtime_dir, fs::Permissions::from_mode(0o755))?;
    for entry in fs::read_dir(&runtime_dir)? {
        let entry = entry?;
        if entry.file_name() != managed_file.as_str() {
            remove(&entry.path())?;
        }
    }
    for (name, source) in sources {
        symlink(source, runtime_dir.join(name))?;
    }
    if !exists {
        // create_new refuses a dangling link or concurrent publication instead of following it.
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&managed_path)?;
        let empty = CheckedPolicy::new(Vec::new());
        file.write_all(empty.text().as_bytes())?;
        file.set_permissions(fs::Permissions::from_mode(0o644))?;
        file.sync_all()?;
        fs::File::open(&runtime_dir)?.sync_all()?;
    }
    Ok(())
}
