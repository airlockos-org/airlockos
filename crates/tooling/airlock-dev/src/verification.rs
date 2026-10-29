//! Explicitly provision and run the pinned prover; ordinary Cargo never downloads it.

use crate::support;
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{fs, path::Path, process::Command};

#[derive(Deserialize)]
struct Pin {
    // Release identity checked against the executable before verification.
    version: String,
    // Upstream source identity, independent of the human-readable version.
    commit: String,
    // Exact rustup toolchain used by this Verus compiler.
    rust: String,
    // Immutable release asset, shared with the Rust-authored Nix package.
    url: String,
    // SHA-256 checked before any downloaded executable is unpacked or run.
    sha256: String,
}

/// Optionally prepare tools, then verify the production crates and their dependencies.
pub(crate) fn run(root: &Path, prepare: bool) -> Result<u8> {
    ensure!(
        std::env::consts::OS == "linux" && std::env::consts::ARCH == "x86_64",
        "the pinned Verus distribution currently supports x86_64 Linux"
    );
    let pin: Pin = serde_json::from_slice(&fs::read(root.join("crates/verus.json"))?)?;
    let cache = root.join(".airlock-cache/verus").join(&pin.version);
    let provisioned = std::env::var_os("AIRLOCK_VERUS_ROOT").map(std::path::PathBuf::from);
    let tools = provisioned
        .clone()
        .unwrap_or_else(|| cache.join("verus-x86-linux"));

    if prepare {
        if provisioned.is_none() && !tools.exists() {
            fs::create_dir_all(cache.parent().context("tool cache parent")?)?;
            let temporary = tempfile::tempdir_in(cache.parent().unwrap())?;
            let archive = temporary.path().join("release.zip");
            checked(
                Command::new("curl")
                    .args(["--fail", "--location", "--silent", "--show-error"])
                    .arg(&pin.url)
                    .arg("--output")
                    .arg(&archive),
            )?;
            ensure!(
                support::hash(&archive)? == pin.sha256,
                "Verus archive checksum differs"
            );
            checked(
                Command::new("unzip")
                    .arg("-q")
                    .arg(&archive)
                    .arg("-d")
                    .arg(temporary.path()),
            )?;
            fs::rename(temporary.path(), &cache)?;
        }
        checked(Command::new("rustup").args([
            "toolchain",
            "install",
            &pin.rust,
            "--profile",
            "minimal",
            "--component",
            "rustc-dev,llvm-tools",
        ]))?;
    }

    ensure!(
        tools.join("verus").is_file(),
        "run make verify-prepare or enter the verification Nix shell first"
    );
    let version: serde_json::Value = serde_json::from_slice(&support::output(
        Command::new(tools.join("verus")).args(["--version", "--output-json"]),
    )?)?;
    ensure!(
        version["verus"]["version"] == pin.version && version["verus"]["commit"] == pin.commit,
        "Verus executable does not match verus.json"
    );

    // Use a separate target directory so ordinary stable Cargo artifacts are unaffected.
    // `verify` (not `focus`) checks vstd as well as the production crates.
    let mut paths = vec![tools];
    paths.extend(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    ));
    let status = Command::new("cargo")
        .current_dir(root)
        .env("PATH", std::env::join_paths(paths)?)
        .env("RUSTUP_TOOLCHAIN", &pin.rust)
        .args([
            "verus",
            "verify",
            "--manifest-path",
            "crates/Cargo.toml",
            "-p",
            "airlock-machine-planning",
            "-p",
            "airlock-deployment-core",
            "-p",
            "airlock-diagnostics",
            "-p",
            "airlock-provisioning-core",
            "-p",
            "airlock-build-plan",
            "-p",
            "airlock-clipboard-core",
            "--features",
            "airlock-machine-planning/wire",
            "--locked",
        ])
        .arg("--target-dir")
        .arg(root.join("target/verus"))
        .status()
        .context("run pinned Verus")?;
    Ok(if status.success() { 0 } else { 1 })
}

/// Inherit diagnostic output and fail if an explicit provisioning step fails.
fn checked(command: &mut Command) -> Result<()> {
    ensure!(
        command.status()?.success(),
        "verification tool preparation failed"
    );
    Ok(())
}
