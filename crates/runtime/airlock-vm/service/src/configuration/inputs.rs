//! Import the fixed source-input archive as the configured user, then expose its existing public mounts.

use super::{Config, io};
use anyhow::{Context, Result, ensure};
use flate2::read::GzDecoder;
use serde_json::json;
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Read,
    path::{Component, Path, PathBuf},
    process::Command,
};

/// Fixed role-independent input names admitted by the existing configuration transport.
const NAMES: &[&str] = &[
    "airlock-apps",
    "airlock-support",
    "nixos-qubes",
    "nixpkgs",
    "nixpkgs-libvirt_10_5",
];

/// Validate a logical input path and return its containing Nix store object.
fn root(source: &str) -> Result<PathBuf> {
    ensure!(
        !source.contains("//")
            && !Path::new(source)
                .components()
                .any(|part| matches!(part, Component::ParentDir)),
        "invalid config input store path"
    );
    let object = source
        .strip_prefix("/nix/store/")
        .and_then(|suffix| suffix.split('/').next())
        .context("input is not a Nix store path")?;
    let (hash, name) = object
        .split_once('-')
        .context("invalid config input store object")?;
    ensure!(
        !hash.is_empty()
            && hash.bytes().all(|byte| byte.is_ascii_alphanumeric())
            && !name.is_empty(),
        "invalid config input store object"
    );
    Ok(PathBuf::from("/nix/store").join(object))
}

/// Keep path overrides beneath their existing private-volume boundary without traversal.
fn absolute(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && !path
                .components()
                .any(|part| matches!(part, Component::ParentDir)),
        "configuration path must be absolute without traversal"
    );
    Ok(())
}

/// Construct the existing user-switch boundary, retaining the configured home and cache environment.
fn user(config: &Config) -> Command {
    let mut command = Command::new("runuser");
    command.args(["-u", &config.user, "--", "env"]);
    for key in ["HOME", "USER", "LOGNAME", "XDG_CACHE_HOME"] {
        let value = match key {
            "HOME" => format!("/home/{user}", user = config.user),
            "XDG_CACHE_HOME" => format!("/home/{user}/.cache", user = config.user),
            _ => config.user.clone(),
        };
        command.arg(format!("{key}={value}"));
    }
    command
}

/// Import only validated source roots, retaining the original private-store and staging refresh boundaries.
pub(super) fn execute(config: &Config, contract: &Path) -> Result<()> {
    let target = io::path("AIRLOCK_CONFIG_INPUTS_PATH", &config.inputs);
    let store = io::path("AIRLOCK_CONFIG_NIX_STORE_ROOT", &config.store);
    absolute(&target)?;
    absolute(&store)?;
    ensure!(
        target.starts_with("/rw") && target != Path::new("/rw"),
        "AIRLOCK_CONFIG_INPUTS_PATH must live under /rw"
    );
    ensure!(
        store != Path::new("/"),
        "configuration store must be a private root"
    );
    fs::create_dir_all(&target)?;
    fs::create_dir_all(&store)?;
    let owner = format!("{user}:users", user = config.user);
    let _ = io::run(Command::new("chown").arg(&owner).arg(&target).arg(&store));
    let temporary = tempfile::Builder::new()
        .prefix(".config-inputs-import-")
        .tempdir_in(target.parent().context("input directory parent")?)?;
    let archive = io::receive(temporary.path())?;
    io::unpack(
        &archive,
        temporary.path(),
        &["manifest.json", "store-paths", "store-export.nar.gz"],
        &["manifest.json", "store-paths", "store-export.nar.gz"],
    )?;
    let manifest = io::read(&temporary.path().join("manifest.json"))?;
    ensure!(
        manifest["schema"] == "airlock.config-inputs.v1",
        "unsupported config input manifest schema"
    );
    let inputs = manifest["inputs"]
        .as_object()
        .context("config inputs must be an object")?;
    ensure!(
        inputs.keys().map(String::as_str).collect::<Vec<_>>() == NAMES,
        "config input manifest has unknown or missing names"
    );
    let mut roots = BTreeSet::new();
    for line in fs::read_to_string(temporary.path().join("store-paths"))?.lines() {
        let path = root(line)?;
        ensure!(
            path == Path::new(line),
            "config input store-paths must contain root objects"
        );
        roots.insert(path);
    }
    for source in inputs.values() {
        let source = source
            .as_str()
            .context("config input path must be a string")?;
        ensure!(
            roots.contains(&root(source)?),
            "config input manifest root is missing from store-paths"
        );
    }
    for path in &roots {
        if io::run(
            user(config)
                .arg("nix-store")
                .arg("--store")
                .arg(&store)
                .arg("--check-validity")
                .arg(path),
        )
        .is_err()
        {
            let physical = store.join(path.strip_prefix("/").unwrap());
            if physical.symlink_metadata().is_ok() {
                if physical.is_dir() && !physical.is_symlink() {
                    fs::remove_dir_all(&physical)?;
                } else {
                    fs::remove_file(&physical)?;
                }
            }
            let lock = physical.with_file_name(format!(
                "{name}.lock",
                name = physical.file_name().unwrap().to_string_lossy()
            ));
            if lock.is_file() {
                fs::remove_file(lock)?;
            }
        }
    }
    let nar = temporary.path().join("store-export.nar");
    let mut decoder = GzDecoder::new(File::open(temporary.path().join("store-export.nar.gz"))?);
    let size = std::io::copy(
        &mut decoder.by_ref().take(8 * 1024 * 1024 * 1024 + 1),
        &mut File::create(&nar)?,
    )?;
    ensure!(
        size <= 8 * 1024 * 1024 * 1024,
        "config input export exceeds its decoded size limit"
    );
    io::files(
        user(config)
            .arg("nix-store")
            .arg("--store")
            .arg(&store)
            .arg("--import"),
        &nar,
        &temporary.path().join("import.stdout"),
        &temporary.path().join("import.stderr"),
    )?;
    for path in &roots {
        io::run(
            user(config)
                .arg("nix-store")
                .arg("--store")
                .arg(&store)
                .arg("--check-validity")
                .arg(path),
        )?;
    }
    io::save(&target.join("manifest.json"), &manifest)?;
    let _ = io::run(
        Command::new("chown")
            .arg(&owner)
            .arg(target.join("manifest.json")),
    );
    fs::create_dir_all(&config.public_inputs)?;
    for (name, source) in inputs {
        let physical = store.join(source.as_str().unwrap().trim_start_matches('/'));
        ensure!(
            physical.is_dir(),
            "imported config input path is missing from private Nix store: {physical}",
            physical = physical.display()
        );
        let mount = config.public_inputs.join(name);
        if io::run(Command::new("mountpoint").args(["-q"]).arg(&mount)).is_ok() {
            io::run(Command::new("umount").arg(&mount))?;
        }
        if let Ok(metadata) = mount.symlink_metadata()
            && !metadata.is_dir()
        {
            fs::remove_file(&mount)?;
        }
        fs::create_dir_all(&mount)?;
        io::run(
            Command::new("mount")
                .arg("--bind")
                .arg(&physical)
                .arg(&mount),
        )?;
    }
    let mut locked = false;
    if config.role == "sys-config-staging" {
        io::run(
            user(config)
                .arg(format!(
                    "AIRLOCK_CONFIG_INPUTS_PATH={path}",
                    path = config.public_inputs.display()
                ))
                .arg("AIRLOCK_CONFIG_REFRESH_INPUTS=1")
                .arg(format!("PATH={path}", path = config.staging_path))
                .arg(std::env::current_exe()?)
                .args(["configuration", "--config"])
                .arg(contract)
                .arg("staging-init"),
        )?;
        locked = config.repo.join("flake.lock").is_file();
    }
    println!(
        "{receipt}",
        receipt = json!({"schema":"airlock.config-inputs-import.v1","status":"passed","path":target,"flake_lock":locked})
    );
    Ok(())
}
