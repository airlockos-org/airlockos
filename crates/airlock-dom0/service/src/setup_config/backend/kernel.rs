//! Install or adopt exact kernel bundles without overwriting unrelated Qubes kernels.

use super::{Session, path, physical};
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path};

/// Compare immediate source files, matching upstream kernel adoption rules.
fn kernel_matches(source: &Path, target: &Path) -> Result<bool> {
    if !target.join("vmlinuz").is_file() {
        return Ok(false);
    }
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        if entry.file_type()?.is_file()
            && (!target.join(entry.file_name()).is_file()
                || fs::read(entry.path())? != fs::read(target.join(entry.file_name()))?)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Install or adopt an exact kernel source; refuse to overwrite unrelated Qubes kernels.
pub(in crate::setup_config) fn install(
    session: &mut Session,
    domain: &str,
    name: &str,
    source: &str,
) -> Result<()> {
    ensure!(
        !name.is_empty() && name != "." && name != ".." && !name.contains('/'),
        "invalid kernel name: {name}"
    );
    let source_path = physical(source);
    ensure!(
        source_path.is_dir() && source_path.join("vmlinuz").is_file(),
        "kernel source vmlinuz is missing: {source}"
    );
    let base = path("AIRLOCK_QUBES_KERNEL_BASE", "/var/lib/qubes/vm-kernels");
    let target = base.join(name);
    let marker = target.join("MANAGED_BY_AIRLOCK");
    let matches = kernel_matches(&source_path, &target)?;
    let source_line = format!("source={source}", source = source_path.display());
    if matches
        && fs::read_to_string(&marker)
            .is_ok_and(|text| text.lines().any(|line| line == source_line))
    {
        return Ok(());
    }
    let adopt = target.is_dir() && !marker.is_file();
    ensure!(
        !adopt || matches,
        "kernel exists but is not managed by Airlock: {target}",
        target = target.display()
    );
    if session.apply {
        if !adopt {
            fs::create_dir_all(&base)?;
            let temporary = tempfile::Builder::new()
                .prefix(".airlock-kernel-")
                .tempdir_in(&base)?;
            session.command(
                "cp",
                &[
                    "-a",
                    &format!("{source}/.", source = source_path.display()),
                    temporary.path().to_str().context("kernel temporary path")?,
                ],
            )?;
            fs::write(
                temporary.path().join("MANAGED_BY_AIRLOCK"),
                format!("{source_line}\nschema=airlock.qubes-kernel.v1\n"),
            )?;
            if target.try_exists()? {
                fs::remove_dir_all(&target)?;
            }
            fs::rename(temporary.path(), &target)?;
        } else {
            fs::write(
                marker,
                format!("{source_line}\nschema=airlock.qubes-kernel.v1\n"),
            )?;
        }
    }
    session.count("kernels_changed")?;
    session.action(
        "kernel",
        if adopt { "adopt" } else { "install" },
        domain,
        name,
        source,
    )?;
    Ok(())
}
