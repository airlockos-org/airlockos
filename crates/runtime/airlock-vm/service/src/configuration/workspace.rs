//! Seed and refresh editable configuration inputs without overwriting dirty user work.

use super::{Config, io};
use anyhow::{Context, Result, ensure};
use serde_json::json;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
    process::Command,
};

/// Machine-owned files copied into a newly initialized configuration repository.
const SEED: &[&str] = &[
    ".gitignore",
    ".cargo",
    "README.md",
    "Makefile",
    "Cargo.toml",
    "Cargo.lock",
    "config-inputs.json",
    "src",
];

/// Copy a trusted seed tree as editable files, preserving links without chmodding their targets.
fn copy(source: &Path, target: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() {
        symlink(fs::read_link(source)?, target)?;
    } else if metadata.is_dir() {
        fs::create_dir_all(target)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            copy(&entry.path(), &target.join(entry.file_name()))?;
        }
        fs::set_permissions(
            target,
            fs::Permissions::from_mode(metadata.permissions().mode() | 0o700),
        )?;
    } else {
        ensure!(metadata.is_file(), "seed contains a non-file object");
        fs::copy(source, target)?;
        fs::set_permissions(
            target,
            fs::Permissions::from_mode(metadata.permissions().mode() | 0o200),
        )?;
    }
    Ok(())
}

/// Populate only a newly selected candidate source tree with machine-owned initial files.
pub(super) fn seed(config: &Config, repo: &Path) -> Result<()> {
    fs::create_dir_all(repo)?;
    for name in SEED {
        copy(&config.seed.join(name), &repo.join(name))?;
    }
    Ok(())
}

/// All five input trees must exist before attempting an offline lock refresh.
pub(super) fn ready(root: &Path) -> bool {
    [
        "nixpkgs",
        "nixpkgs-libvirt_10_5",
        "nixos-qubes",
        "airlock-support",
        "airlock-apps",
    ]
    .iter()
    .all(|name| root.join(name).is_dir())
}

/// Relocate Cargo paths and source-input declarations to the installed admitted-input view.
pub(super) fn relocate(config: &Config, repo: &Path, root: &Path) -> Result<()> {
    ensure!(
        root.is_absolute(),
        "configuration input root must be absolute"
    );
    let inputs = io::read(&repo.join("config-inputs.json"))?;
    let applications = inputs["applications"]
        .as_str()
        .context("configuration applications input")?;
    let old = applications
        .strip_suffix("/airlock-apps")
        .unwrap_or(applications);
    let home = format!(
        "/rw/home/{user}/.local/share/airlock/config-inputs",
        user = config.user
    );
    let mut cargo = fs::read_to_string(repo.join(".cargo/config.toml"))?;
    for previous in [
        old,
        "/etc/airlock/config-inputs",
        "/rw/airlock/config-inputs",
        &home,
        config.inputs.to_str().context("configuration input path")?,
    ] {
        cargo = cargo.replace(
            &format!("{previous}/"),
            &format!("{root}/", root = root.display()),
        );
    }
    fs::write(repo.join(".cargo/config.toml"), cargo)?;
    io::save(
        &repo.join("config-inputs.json"),
        &json!({"nixpkgs":root.join("nixpkgs"),"libvirt":root.join("nixpkgs-libvirt_10_5"),"qubes":root.join("nixos-qubes"),"machine":root.join("airlock-support"),"applications":root.join("airlock-apps")}),
    )
}

/// Generate a disposable flake and retain only its lock in the editable repository.
pub(super) fn lock(config: &Config, repo: &Path) -> Result<()> {
    let temporary = tempfile::tempdir()?;
    fs::copy(
        repo.join("config-inputs.json"),
        temporary.path().join("config-inputs.json"),
    )?;
    io::run(
        Command::new("make")
            .current_dir(repo)
            .args(["--silent", "generate"])
            .arg(format!(
                "OUTPUT={output}",
                output = temporary.path().display()
            )),
    )?;
    io::run(
        Command::new(&config.nix)
            .args([
                "--extra-experimental-features",
                "nix-command",
                "--extra-experimental-features",
                "flakes",
                "flake",
                "lock",
                "--impure",
                "--offline",
            ])
            .arg(format!("path:{path}", path = temporary.path().display())),
    )?;
    fs::copy(temporary.path().join("flake.lock"), repo.join("flake.lock"))?;
    Ok(())
}

/// Detect the legacy persistent-root spellings that require explicit input relocation.
fn needs_refresh(config: &Config, repo: &Path) -> bool {
    let home = format!(
        "/rw/home/{user}/.local/share/airlock/config-inputs/",
        user = config.user
    );
    let configured = format!("{path}/", path = config.inputs.display());
    ["config-inputs.json", "flake.lock"]
        .into_iter()
        .any(|name| {
            fs::read_to_string(repo.join(name)).is_ok_and(|text| {
                [
                    "__AIRLOCK_NIXPKGS_URL__",
                    "/rw/airlock/config-inputs/",
                    &home,
                    &configured,
                ]
                .iter()
                .any(|pattern| text.contains(pattern))
            })
        })
}

/// Initialize staging, or refresh its input lock only under the existing clean-worktree rules.
pub(super) fn staging(config: &Config) -> Result<()> {
    let repo = io::path("AIRLOCK_CONFIG_REPO_PATH", &config.repo);
    let inputs = io::path("AIRLOCK_CONFIG_INPUTS_PATH", &config.public_inputs);
    if repo.join(".git").is_dir() {
        let refresh = std::env::var("AIRLOCK_CONFIG_REFRESH_INPUTS").as_deref() == Ok("1");
        if refresh {
            if !ready(&inputs) {
                eprintln!("config staging inputs are not present; refresh deferred");
                return Ok(());
            }
            if io::git(&repo, &["status", "--porcelain"])?.is_empty() {
                relocate(config, &repo, &inputs)?;
                lock(config, &repo)?;
                if !io::git(
                    &repo,
                    &[
                        "status",
                        "--porcelain",
                        ".cargo/config.toml",
                        "config-inputs.json",
                        "flake.lock",
                    ],
                )?
                .is_empty()
                {
                    io::git(
                        &repo,
                        &[
                            "add",
                            ".cargo/config.toml",
                            "config-inputs.json",
                            "flake.lock",
                        ],
                    )?;
                    io::commit(
                        &repo,
                        "refresh airlock config inputs",
                        "Airlock Config Staging",
                        "airlock-config-staging@localhost",
                    )?;
                } else {
                    ensure!(
                        !needs_refresh(config, &repo),
                        "config staging config input paths still need refresh after lock update"
                    );
                }
            } else {
                eprintln!("config staging input refresh deferred because worktree is dirty");
            }
        }
        if !repo.join("flake.lock").is_file() {
            ensure!(
                io::git(&repo, &["status", "--porcelain"])?.is_empty(),
                "config staging worktree is dirty; refusing to refresh config input paths"
            );
            if ready(&inputs) {
                relocate(config, &repo, &inputs)?;
                lock(config, &repo)?;
                io::git(
                    &repo,
                    &[
                        "add",
                        ".cargo/config.toml",
                        "config-inputs.json",
                        "flake.lock",
                    ],
                )?;
                io::commit(
                    &repo,
                    "lock airlock config candidate inputs",
                    "Airlock Config Staging",
                    "airlock-config-staging@localhost",
                )?;
            }
        }
        return Ok(());
    }
    fs::create_dir_all(&repo)?;
    if std::env::var("AIRLOCK_CONFIG_STAGING_INIT_FROM_INITIAL_CONFIG").as_deref() != Ok("1") {
        eprintln!("config staging repository awaits sys-config-vault current import");
        return Ok(());
    }
    io::run(Command::new("git").args(["init", "-b", "main"]).arg(&repo))?;
    seed(config, &repo)?;
    relocate(config, &repo, &inputs)?;
    let mut args = vec!["add"];
    args.extend(SEED);
    io::git(&repo, &args)?;
    if ready(&inputs) {
        lock(config, &repo)?;
        io::git(
            &repo,
            &[
                "add",
                ".cargo/config.toml",
                "config-inputs.json",
                "flake.lock",
            ],
        )?;
    }
    io::commit(
        &repo,
        "init airlock config candidate",
        "Airlock Config Staging",
        "airlock-config-staging@localhost",
    )?;
    Ok(())
}
