//! Generate upstream crate recipes inside captured source, without Nix evaluation or fetching.
//! Cargo supplies metadata; reviewed Git hashes prevent crate2nix's prefetch path.
//! Cargo, crate2nix and their filesystem observations remain trusted tool adapters.

use super::{Result, digest, output};
use airlock_build::{crate_graph, git_sources};
use serde::Deserialize;
use serde_json::json;
use std::{collections::BTreeMap, fs, path::Path, process::Command};

#[derive(Deserialize)]
struct Metadata {
    /// Cargo-resolved packages, including optional dependencies discovered with all features.
    packages: Vec<Package>,
}

#[derive(Deserialize)]
struct Package {
    /// Cargo's complete source-bound package identity, used by upstream's hash cache.
    id: String,
    /// Registry or Git source identity; absent for workspace/path packages.
    source: Option<String>,
}

/// Generate recipes for one captured workspace. Keep CLI paths relative so random staging
/// directories cannot invalidate otherwise identical output. Cargo itself enforces --locked;
/// its directory source supplies unpublished Git revisions without consulting a remote.
fn workspace(root: &Path, generator: &Path, vendor: &Path) -> Result<()> {
    let cargo = tempfile::tempdir()?;
    let mut configuration = format!(
        r#"
[net]
offline = true

[source.crates-io]
replace-with = "airlock-admitted"

[source.airlock-admitted]
directory = {vendor:?}
"#,
        vendor = vendor.to_str().ok_or("non-UTF-8 vendor directory")?,
    );
    for source in git_sources::SOURCES {
        configuration.push_str(&format!(
            r#"
[source.{alias:?}]
git = {repository:?}
rev = {revision:?}
replace-with = "airlock-admitted"
"#,
            repository = source.repository,
            alias = source.alias,
            revision = source.revision,
        ));
    }
    fs::write(cargo.path().join("config.toml"), &configuration)?;
    let locked = fs::read(root.join("Cargo.lock"))?;
    let metadata = output(
        Command::new("cargo")
            .current_dir(root)
            .env("CARGO_HOME", cargo.path())
            .env("CARGO_NET_OFFLINE", "true")
            .args([
                "metadata",
                "--locked",
                "--offline",
                "--all-features",
                "--format-version",
                "1",
            ]),
    )?;
    let metadata: Metadata = serde_json::from_slice(&metadata)?;
    let mut hashes = BTreeMap::new();
    for package in metadata.packages {
        if let Some(identity) = package.source
            && identity.starts_with("git+")
        {
            let source = git_sources::SOURCES
                .iter()
                .find(|source| {
                    identity
                        == format!(
                            "git+{repository}?rev={revision}#{revision}",
                            repository = source.repository,
                            revision = source.revision
                        )
                })
                .ok_or_else(|| format!("Git source requires a reviewed tree hash: {identity}"))?;
            hashes.insert(package.id, source.hash);
        }
    }
    fs::write(
        root.join("crate-hashes.json"),
        serde_json::to_vec_pretty(&hashes)?,
    )?;
    // All Git hashes are supplied, and registry hashes come from the Cargo lock.
    // With these upstream contracts generation never invokes Nix/prefetch helpers.
    output(
        Command::new(generator)
            .current_dir(root)
            .env("CARGO_HOME", cargo.path())
            .env("CARGO_NET_OFFLINE", "true")
            .args([
                "generate",
                "--all-features",
                "-f",
                "Cargo.toml",
                "-o",
                "Cargo.nix",
                "--crate-hashes",
                "crate-hashes.json",
            ]),
    )?;
    if fs::read(root.join("Cargo.lock"))? != locked {
        return Err("crate generation changed the captured Cargo lock".into());
    }
    Ok(())
}

/// Prepare independent workspace graphs without merging their locks or build identities.
/// Provision the generator explicitly before preparation; this function never installs tools.
pub(super) fn generate(applications: &Path) -> Result<()> {
    let generator = std::env::var_os("AIRLOCK_CRATE2NIX")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/run/current-system/sw/bin/crate2nix"));
    if !generator.is_absolute() {
        return Err("AIRLOCK_CRATE2NIX must name an absolute pinned executable".into());
    }
    let identity = fs::canonicalize(&generator).map_err(|error| {
        format!(
            "prepare crate2nix {version} explicitly and set AIRLOCK_CRATE2NIX: {error}",
            version = crate_graph::VERSION,
        )
    })?;
    let version = output(Command::new(&generator).arg("--version"))?;
    let version = std::str::from_utf8(&version)?.trim();
    if version != format!("crate2nix {expected}", expected = crate_graph::VERSION) {
        return Err(format!(
            "expected crate2nix {expected}, got {version}",
            expected = crate_graph::VERSION
        )
        .into());
    }
    let vendor = std::env::var_os("AIRLOCK_CARGO_VENDOR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "/etc/airlock/authoring/vendor".into());
    let vendor = fs::canonicalize(vendor)?;
    // Cargo reads ancestor configuration independently of --manifest-path. Generate
    // outside the machine checkout so its authoring patches cannot affect this
    // application's dependency graph. Relative recipes remain valid after copying.
    let scratch = tempfile::tempdir_in("/tmp")?;
    let captured = scratch.path().join("workspace");
    super::mirror(applications, &captured)?;
    workspace(&captured, &generator, &vendor)?;
    let packer_vendor = std::env::var_os("AIRLOCK_PACKER_CARGO_VENDOR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "/etc/airlock/authoring/packer-vendor".into());
    let packer_vendor = fs::canonicalize(packer_vendor)?;
    workspace(
        &captured.join("tooling/airlock-store-packer"),
        &generator,
        &packer_vendor,
    )?;
    for directory in ["", "tooling/airlock-store-packer"] {
        for name in ["Cargo.nix", "crate-hashes.json"] {
            fs::copy(
                captured.join(directory).join(name),
                applications.join(directory).join(name),
            )?;
        }
    }
    fs::write(
        applications.join("crate2nix-preparation.json"),
        serde_json::to_vec_pretty(&json!({
            "schema": "airlock.crate2nix-preparation.v1",
            "generator": version,
            "generator_sha256": digest(&identity)?,
            "workspace_lock": digest(&applications.join("Cargo.lock"))?,
            "packer_lock": digest(&applications.join("tooling/airlock-store-packer/Cargo.lock"))?,
            "discovery": "all-features; production builds select their own features",
        }))?,
    )?;
    Ok(())
}
