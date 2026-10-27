//! Select workstation data/store paths without ever implicitly falling back to the host Nix store.

use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::Command,
};

/// Workstation environment overrides applied to child processes rather than global process state.
pub(crate) struct Environment {
    /// Selected variables, including explicit private-store Nix configuration.
    pub values: BTreeMap<OsString, OsString>,
}

/// Compatibility operations used by thin shell launchers while they are migrated.
#[derive(Subcommand)]
pub(crate) enum Action {
    /// Emit safely quoted exports for existing caller environments.
    Exports,
    /// Test whether logical store paths use the selected private root.
    UsesChroot,
    /// Translate one logical store path without resolving its contents.
    Physical {
        /// Logical source or executable path.
        path: PathBuf,
    },
    /// Translate a colon-separated executable/library path list.
    PhysicalList {
        /// Original path list, preserving empty components.
        paths: OsString,
    },
    /// Select the containing store object for an executable path.
    StoreRoot {
        /// Path within a logical store object.
        path: PathBuf,
    },
    /// Run an executable through Nix's existing private-store environment when necessary.
    RunStore {
        /// Exact executable and arguments; no shell evaluation occurs.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        arguments: Vec<OsString>,
    },
}

/// Read a nonempty override, matching the existing shell defaulting semantics.
fn value(key: &str) -> Option<OsString> {
    std::env::var_os(key).filter(|value| !value.is_empty())
}

impl Environment {
    /// Select defaults and create only the configured Airlock data directories.
    pub fn load() -> Result<Self> {
        let data = value("AIRLOCK_DATA_ROOT").map(PathBuf::from).or_else(|| {
            let media = Path::new("/run/media/user/data");
            (media.is_dir() && rustix::fs::access(media, rustix::fs::Access::WRITE_OK).is_ok())
                .then(|| media.join("airlock"))
        });
        let host = std::env::var("AIRLOCK_USE_HOST_NIX_STORE").as_deref() == Ok("1");
        ensure!(
            data.is_some() || host,
            "/run/media/user/data is not available; refusing to use the host Nix store by default; set AIRLOCK_DATA_ROOT or explicitly set AIRLOCK_USE_HOST_NIX_STORE=1"
        );
        let mut values = BTreeMap::new();
        if let Some(data) = data {
            let defaults = [
                ("AIRLOCK_DATA_ROOT", data.clone()),
                ("AIRLOCK_VM_DIR", data.join("vm")),
                ("AIRLOCK_LOG_DIR", data.join("logs")),
                ("AIRLOCK_QUBES_CACHE_DIR", data.join("cache/rpms")),
                ("AIRLOCK_RESULT_LINK_DIR", data.join("result-links")),
                ("AIRLOCK_NIX_ROOT", data.join("nix-root")),
                ("TMPDIR", data.join("tmp")),
                ("XDG_CACHE_HOME", data.join("cache/xdg")),
            ];
            for (key, fallback) in defaults {
                let path = value(key).map(PathBuf::from).unwrap_or(fallback);
                ensure!(path.is_absolute(), "{key} must be absolute");
                fs::create_dir_all(&path)?;
                values.insert(OsString::from(key), path.into_os_string());
            }
            let root = values.get(OsStr::new("AIRLOCK_NIX_ROOT")).unwrap().clone();
            values.insert(
                "AIRLOCK_NIX_STORE".into(),
                value("AIRLOCK_NIX_STORE").unwrap_or(root),
            );
            if !host && std::env::var("AIRLOCK_NIX_CONFIGURED").as_deref() != Ok("1") {
                let store = values.get(OsStr::new("AIRLOCK_NIX_STORE")).unwrap();
                let store = store
                    .to_str()
                    .context("private Nix store path is not UTF-8")?;
                ensure!(
                    !store.contains(['\n', '\r']),
                    "private Nix store path contains a line break"
                );
                let mut config = std::env::var("NIX_CONFIG").unwrap_or_default();
                if !config.is_empty() {
                    config.push('\n');
                }
                config.push_str(&format!("store = {store}"));
                values.insert("NIX_CONFIG".into(), config.into());
                values.insert("AIRLOCK_NIX_CONFIGURED".into(), "1".into());
            }
        }
        Ok(Self { values })
    }

    /// Read a selected path or inherit its existing explicit value before using a caller fallback.
    pub fn path(&self, key: &str, fallback: impl AsRef<Path>) -> PathBuf {
        self.values
            .get(OsStr::new(key))
            .cloned()
            .or_else(|| value(key))
            .map(PathBuf::from)
            .unwrap_or_else(|| fallback.as_ref().to_owned())
    }

    /// Execute another native operation with the selected environment and unchanged input/output streams.
    pub fn run(&self, root: &Path, arguments: &[OsString]) -> Result<u8> {
        let mut command = Command::new(std::env::current_exe()?);
        if !arguments.iter().any(|argument| {
            argument == "--repository-root"
                || argument
                    .to_str()
                    .is_some_and(|argument| argument.starts_with("--repository-root="))
        }) {
            command.arg("--repository-root").arg(root);
        }
        let status = command.args(arguments).envs(&self.values).status()?;
        Ok(status.code().unwrap_or(1).try_into()?)
    }
}

/// Return whether the current explicitly configured environment uses a private store root.
fn chroot() -> bool {
    std::env::var("AIRLOCK_USE_HOST_NIX_STORE").as_deref() != Ok("1")
        && value("AIRLOCK_NIX_ROOT").is_some_and(|root| root != OsStr::new("/"))
}

/// Translate a logical store path only when private-store selection explicitly requires it.
pub(crate) fn physical(path: &Path) -> PathBuf {
    if chroot() && path.starts_with("/nix/store") && path != Path::new("/nix/store") {
        return PathBuf::from(std::env::var_os("AIRLOCK_NIX_ROOT").unwrap())
            .join(path.strip_prefix("/").unwrap());
    }
    path.into()
}

/// Select exactly the containing logical store object, retaining non-store inputs unchanged.
fn store_root(path: &Path) -> PathBuf {
    if let Ok(relative) = path.strip_prefix("/nix/store")
        && let Some(name) = relative.components().next()
    {
        return PathBuf::from("/nix/store").join(name);
    }
    path.into()
}

/// Emit shell quotes only for trusted native exports; every embedded quote remains literal data.
fn quote(value: &OsStr) -> Result<String> {
    let value = value
        .to_str()
        .context("cannot export non-UTF-8 environment value to shell")?;
    Ok(format!("'{value}'", value = value.replace('\'', "'\\''")))
}

/// Dispatch compatibility helpers while keeping path/store decisions in Rust.
pub(crate) fn execute(action: Action) -> Result<u8> {
    match action {
        Action::Exports => {
            for (key, value) in Environment::load()?.values {
                println!(
                    "export {key}={value}",
                    key = key.to_str().context("environment variable name")?,
                    value = quote(&value)?
                );
            }
        }
        Action::UsesChroot => return Ok(u8::from(!chroot())),
        Action::Physical { path } => println!("{path}", path = physical(&path).display()),
        Action::PhysicalList { paths } => {
            let paths = paths
                .to_str()
                .context("path list is not UTF-8")?
                .split(':')
                .map(|path| physical(Path::new(path)))
                .collect::<Vec<_>>();
            println!(
                "{paths}",
                paths = std::env::join_paths(paths)?.to_string_lossy()
            );
        }
        Action::StoreRoot { path } => println!("{path}", path = store_root(&path).display()),
        Action::RunStore { arguments } => {
            let (program, args) = arguments.split_first().context("missing executable")?;
            let mut command = if chroot() && Path::new(program).starts_with("/nix/store") {
                let mut command = Command::new("nix");
                command
                    .arg("shell")
                    .arg(store_root(Path::new(program)))
                    .arg("-c")
                    .arg(program);
                command
            } else {
                Command::new(program)
            };
            return Err(command.args(args).exec().into());
        }
    }
    Ok(0)
}
