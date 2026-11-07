//! Explicit workstation builds prepare their generator and Cargo sources before collecting credentials.
//! Source preparation and quick tests only consume these inputs; neither installs tools.

use airlock_build::crate_graph;
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

/// Resolve and check the generator before starting any authenticated USB operation.
pub(crate) fn generator() -> Result<PathBuf> {
    let path = airlock_dev_paths::path("AIRLOCK_CRATE2NIX", "tools/crate2nix/bin/crate2nix")?;
    fs::canonicalize(&path).context("run make prepare-dependencies to prepare crate2nix")?;
    let version = crate::support::text(Command::new(&path).arg("--version"))?;
    ensure!(
        version == format!("crate2nix {expected}", expected = crate_graph::VERSION),
        "expected crate2nix {expected}, got {version}",
        expected = crate_graph::VERSION,
    );
    Ok(path)
}

/// Prepare both independent locked workspaces and the pinned upstream generator without using Nix.
/// Only the default disposable tool location is installed automatically; explicit executables are checked.
pub(crate) fn prepare(root: &Path) -> Result<()> {
    let tool_root = airlock_dev_paths::root()?.join("tools/crate2nix");
    let default = tool_root.join("bin/crate2nix");
    let selected = airlock_dev_paths::path("AIRLOCK_CRATE2NIX", "tools/crate2nix/bin/crate2nix")?;
    if selected == default && !selected.exists() {
        let status = Command::new("cargo")
            .args(["install", "--locked", "--version"])
            .arg(format!("={version}", version = crate_graph::VERSION))
            .arg("--root")
            .arg(&tool_root)
            .arg("crate2nix")
            .status()?;
        ensure!(status.success(), "crate2nix preparation failed: {status}");
    }
    let generator = generator()?;
    eprintln!("Prepared crate2nix: {path}", path = generator.display());

    for (manifest, variable, fallback) in [
        (
            "crates/Cargo.toml",
            "AIRLOCK_CARGO_VENDOR",
            "cache/authoring-vendor",
        ),
        (
            "crates/tooling/airlock-store-packer/Cargo.toml",
            "AIRLOCK_PACKER_CARGO_VENDOR",
            "cache/packer-vendor",
        ),
    ] {
        let vendor = airlock_dev_paths::path(variable, fallback)?;
        fs::create_dir_all(vendor.parent().context("vendor directory parent")?)?;
        let status = Command::new("cargo")
            .current_dir(root)
            .args(["vendor", "--locked", "--versioned-dirs", "--manifest-path"])
            .arg(root.join(manifest))
            .arg(&vendor)
            .stdout(Stdio::null())
            .status()?;
        ensure!(
            status.success(),
            "dependency preparation failed for {manifest}: {status}"
        );
    }
    Ok(())
}
