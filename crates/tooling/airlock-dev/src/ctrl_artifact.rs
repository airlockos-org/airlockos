//! Explicit controller test-artifact preparation binds the executable to the GUI and shared review sources.

use crate::support;
use anyhow::{Context, Result, ensure};
use clap::{Subcommand, ValueEnum};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

/// Choose an explicit build operation rather than provisioning during regression execution.
#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum Builder {
    /// Build using the already prepared local Cargo environment.
    Cargo,
    /// Build the standalone application package in the guarded Airlock store.
    Nix,
}

/// Prepare, record or verify the controller executable used by native process tests.
#[derive(Subcommand)]
pub(crate) enum Action {
    /// Explicitly build the GUI and record its complete source and executable digests.
    Build {
        // Build system selected by the workstation caller.
        #[arg(long, value_enum, default_value = "cargo")]
        builder: Builder,
    },
    /// Record a binary prepared by the enclosing Cargo build workflow.
    Record {
        // Executable produced by the explicit preparation step.
        #[arg(long)]
        binary: PathBuf,
    },
    /// Refuse stale source, changed bytes or a substituted executable before running tests.
    Verify {
        // Optional explicit executable must match the verified receipt.
        #[arg(long)]
        binary: Option<PathBuf>,
    },
}

/// Include every file under implementation and asset roots without following directory symlinks.
fn collect(root: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_name() == "__pycache__" {
            continue;
        }
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            collect(&path, files)?;
        } else if path.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

/// Hash file contents independently of timestamps or build output location.
fn digest(path: &Path) -> Result<String> {
    Ok(format!("{hash:x}", hash = Sha256::digest(fs::read(path)?)))
}

/// Bind the GUI implementation, assets, manifest/lock and shared review core to one stable digest.
fn sources(root: &Path) -> Result<String> {
    let mut files = [
        "crates/Cargo.toml",
        "crates/Cargo.lock",
        "crates/runtime/airlock-sys-ctrl/gui/Cargo.toml",
        "crates/airlock-common/nix/Cargo.toml",
        "crates/airlock-common/desktop/Cargo.toml",
    ]
    .into_iter()
    .map(|name| root.join(name))
    .collect::<Vec<_>>();
    for name in ["src", "assets", "examples"] {
        collect(
            &root.join("crates/runtime/airlock-sys-ctrl/gui").join(name),
            &mut files,
        )?;
    }
    collect(&root.join("crates/airlock-common/nix/src"), &mut files)?;
    for name in ["src", "assets"] {
        collect(
            &root.join("crates/airlock-common/desktop").join(name),
            &mut files,
        )?;
    }
    files.sort();
    let mut hash = Sha256::new();
    for path in files {
        hash.update(path.strip_prefix(root)?.as_os_str().as_encoded_bytes());
        hash.update([0]);
        hash.update(digest(&path)?.as_bytes());
        hash.update([0]);
    }
    Ok(format!("{hash:x}", hash = hash.finalize()))
}

/// Refuse an artifact whose source or executable changed after preparation.
fn verify(root: &Path, record: &Value, selected: Option<&Path>) -> Result<PathBuf> {
    let binary = PathBuf::from(record["binary"].as_str().context("controller binary")?);
    if let Some(selected) = selected {
        ensure!(
            fs::canonicalize(selected)? == fs::canonicalize(&binary)?,
            "AIRLOCK_CTRL_BIN differs from the verified build; run make ctrl-build"
        );
    }
    ensure!(
        record["source_sha256"] == sources(root)?,
        "GUI sources changed after the build; run make ctrl-build"
    );
    ensure!(
        record["binary_sha256"] == digest(&binary)?,
        "GUI binary changed after the build; run make ctrl-build"
    );
    Ok(fs::canonicalize(binary)?)
}

/// Persist a receipt only when the entire build retained the selected source identity.
fn record(root: &Path, binary: &Path, before: &str) -> Result<()> {
    ensure!(
        sources(root)? == before,
        "GUI sources changed during the build; rebuild before testing"
    );
    let binary = fs::canonicalize(binary)?;
    let receipt = root.join(".airlock-logs/ctrl-build.json");
    fs::create_dir_all(receipt.parent().unwrap())?;
    let record =
        json!({"binary": binary, "source_sha256": before, "binary_sha256": digest(&binary)?});
    support::record(&receipt, &record)?;
    support::print(&record)
}

/// Execute artifact preparation explicitly; verification never builds or fetches tools.
pub(crate) fn execute(root: &Path, action: Action) -> Result<()> {
    match action {
        Action::Verify { binary } => {
            let receipt = root.join(".airlock-logs/ctrl-build.json");
            let record = support::json(&receipt)
                .context("GUI build receipt missing; run make ctrl-build")?;
            support::print(&json!({"binary": verify(root, &record, binary.as_deref())?}))
        }
        Action::Record { binary } => record(root, &binary, &sources(root)?),
        Action::Build { builder } => {
            let before = sources(root)?;
            let binary = match builder {
                Builder::Cargo => {
                    ensure!(
                        Command::new("cargo")
                            .current_dir(root)
                            .args([
                                "build",
                                "--locked",
                                "--manifest-path",
                                "crates/Cargo.toml",
                                "-p",
                                "airlock-sys-ctrl-gui"
                            ])
                            .status()?
                            .success(),
                        "GUI Cargo build failed"
                    );
                    std::env::var_os("CARGO_TARGET_DIR")
                        .map(PathBuf::from)
                        .unwrap_or_else(|| root.join("crates/target"))
                        .join("debug/airlock-sys-ctrl-gui")
                }
                Builder::Nix => {
                    let output = support::output(
                        Command::new(std::env::current_exe()?)
                            .arg("--repository-root")
                            .arg(root)
                            .args(["with-environment", "--", "nix", "--"])
                            .current_dir(root)
                            .args([
                                "build",
                                "./crates#airlock-sys-ctrl-gui",
                                "--no-write-lock-file",
                                "--no-link",
                                "--json",
                            ]),
                    )?;
                    let output: Value = serde_json::from_slice(&output)?;
                    let logical = output[0]["outputs"]["out"]
                        .as_str()
                        .context("GUI package output")?;
                    let physical = if std::env::var("AIRLOCK_USE_HOST_NIX_STORE").as_deref()
                        == Ok("1")
                    {
                        PathBuf::from("/")
                    } else {
                        PathBuf::from(
                            std::env::var_os("AIRLOCK_NIX_ROOT").context("Airlock store root")?,
                        )
                    };
                    physical
                        .join(logical.trim_start_matches('/'))
                        .join("bin/airlock-sys-ctrl-gui")
                }
            };
            record(root, &binary, &before)
        }
    }
}

#[cfg(test)]
mod regression {
    use super::*;

    /// Changes to code, assets, manifests, shared review code or the binary invalidate an explicit build receipt.
    #[test]
    fn receipt_binds_all_review_inputs_and_binary_bytes() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path();
        let names = [
            "crates/Cargo.toml",
            "crates/Cargo.lock",
            "crates/runtime/airlock-sys-ctrl/gui/Cargo.toml",
            "crates/airlock-common/nix/Cargo.toml",
            "crates/airlock-common/desktop/Cargo.toml",
            "crates/airlock-common/desktop/src/lib.rs",
            "crates/airlock-common/nix/src/lib.rs",
            "crates/runtime/airlock-sys-ctrl/gui/src/main.rs",
            "crates/airlock-common/desktop/assets/airlock.svg",
            "crates/airlock-common/desktop/assets/airlock.png",
        ];
        for name in names {
            let path = root.join(name);
            fs::create_dir_all(path.parent().unwrap())?;
            fs::write(path, name)?;
        }
        let binary = root.join("controller");
        fs::write(&binary, "built binary")?;
        let receipt = json!({"binary": binary, "source_sha256": sources(root)?, "binary_sha256": digest(&binary)?});
        assert_eq!(verify(root, &receipt, None)?, binary);
        let other = root.join("other");
        fs::write(&other, "other binary")?;
        assert!(verify(root, &receipt, Some(&other)).is_err());
        for name in names {
            fs::write(root.join(name), "changed")?;
            assert!(
                verify(root, &receipt, None)
                    .unwrap_err()
                    .to_string()
                    .contains("sources changed")
            );
            fs::write(root.join(name), name)?;
        }
        fs::write(&binary, "changed binary")?;
        assert!(
            verify(root, &receipt, None)
                .unwrap_err()
                .to_string()
                .contains("binary changed")
        );
        Ok(())
    }
}
