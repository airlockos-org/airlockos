//! Builder VMs combine an immutable package base with a private writable layer.
//! A saved base identity prevents persistent build outputs from silently moving
//! to an unrelated base; approved additive successors preserve those outputs.

mod identity;

use self::identity::Identity;
use airlock_nix_core::state::{OperationKind, OperationOwner, StateStore};
use anyhow::{Context, Result, anyhow, ensure};
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Component, Path, PathBuf},
    process::{Command, ExitCode},
    time::Duration,
};

#[derive(Clone, Copy, ValueEnum)]
enum Role {
    UsrAssistant,
    SysCtrl,
}

impl Role {
    fn name(self) -> &'static str {
        match self {
            Self::UsrAssistant => "usr-assistant",
            Self::SysCtrl => "sys-ctrl",
        }
    }
}

#[derive(Subcommand)]
enum Operation {
    /// Mount the authenticated base and persistent private upper layer.
    Start,
    /// Unmount this builder while preserving its base identity and build outputs.
    Stop,
}

#[derive(Parser)]
struct Request {
    // Lifecycle action; no builds are performed by this command.
    #[command(subcommand)]
    operation: Operation,
    // Root-owned persistent parent retaining both identity and writable output.
    #[arg(long, global = true, default_value = "/rw/airlock-builder")]
    state: PathBuf,
    // Root-owned volatile parent containing mounts and readiness records.
    #[arg(long, global = true, default_value = "/run/airlock-builder")]
    runtime: PathBuf,
    // Unprivileged account which owns private Nix state and build outputs.
    #[arg(long, global = true, default_value = "user")]
    user: String,
    // Builder role authenticated by the immutable metadata identity.
    #[arg(long, global = true, value_enum, default_value = "usr-assistant")]
    domain: Role,
    // Immutable metadata frontend installed by dom0.
    #[arg(long, global = true, default_value = "/dev/xvdg")]
    store_device: String,
    // Filtered external-data frontend installed by dom0.
    #[arg(long, global = true, default_value = "/dev/xvdh")]
    blob_device: String,
    // Nix database loader; it imports metadata without evaluating or building.
    #[arg(long, global = true, default_value = "nix-store")]
    nix_store: String,
}

#[derive(Deserialize, Serialize)]
struct Ready {
    // Authenticated base accepted before mounting writable state.
    identity: Identity,
    // Nix local-overlay URI consumed by unprivileged build processes.
    uri: String,
    // Mount order retained so shutdown can unmount in reverse dependency order.
    mounts: Vec<PathBuf>,
}

pub(crate) fn main_from(args: impl IntoIterator<Item = OsString>) -> ExitCode {
    let request = match Request::try_parse_from(args) {
        Ok(request) => request,
        Err(error) => {
            let code = error.exit_code();
            let _ = error.print();
            return ExitCode::from(code as u8);
        }
    };
    match execute(&request) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("airlock builder-store: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn execute(args: &Request) -> Result<()> {
    directory(&args.state)?;
    directory(&args.runtime)?;
    ensure!(
        args.state != args.runtime
            && !args.state.starts_with(&args.runtime)
            && !args.runtime.starts_with(&args.state),
        "builder state and runtime must be separate directories"
    );
    directory(&args.runtime.join("operations"))?;
    let store = StateStore::initialize(&args.runtime.join("operations"))?;
    let _lock = store.try_operation(
        &"mount".parse()?,
        OperationOwner::new(
            format!("{} builder store", args.domain.name()),
            match args.operation {
                Operation::Start => "Mount the authenticated base and writable output",
                Operation::Stop => "Unmount while preserving private build output",
            }
            .into(),
            OperationKind::Maintenance,
        )?,
    )?;

    // This sibling remains in place when a cloned builder's state is archived.
    // It also serializes callers that accidentally select different runtimes.
    let state_lock_root = args.state.with_file_name(format!(
        ".{}-operations",
        args.state
            .file_name()
            .context("state has no name")?
            .to_str()
            .context("invalid state name")?
    ));
    directory(&state_lock_root)?;
    let state_store = StateStore::initialize(&state_lock_root)?;
    let _state_lock = state_store.try_operation(
        &"mount".parse()?,
        OperationOwner::new(
            format!("{} builder state", args.domain.name()),
            "Protect the persistent upper layer across mount lifecycles".into(),
            OperationKind::Maintenance,
        )?,
    )?;

    match args.operation {
        Operation::Start => start(args),
        Operation::Stop => stop(args),
    }
}

fn directory(path: &Path) -> Result<()> {
    real_directory(path)?;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
        "builder state must be a root-owned directory without group or other write access"
    );
    Ok(())
}

fn real_directory(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && path != Path::new("/")
            && !path
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir)),
        "builder path must be absolute and normalized"
    );
    let text = path.to_str().context("builder path is not UTF-8")?;
    ensure!(
        !text.contains([',', ':', '\n', '\r', '\\']),
        "builder path contains an overlay option delimiter"
    );
    let mut ancestor = PathBuf::new();
    for part in path.components() {
        ancestor.push(part);
        match fs::symlink_metadata(&ancestor) {
            Ok(metadata) => ensure!(
                metadata.is_dir(),
                "symlink or non-directory in builder path: {}",
                ancestor.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&ancestor)?;
                File::open(&ancestor)?.sync_all()?;
                File::open(ancestor.parent().context("directory has no parent")?)?.sync_all()?;
            }
            Err(error) => return Err(error.into()),
        }
        if ancestor != path {
            let metadata = fs::symlink_metadata(&ancestor)?;
            ensure!(
                metadata.uid() == 0
                    && (metadata.mode() & 0o022 == 0 || metadata.mode() & 0o1000 != 0),
                "untrusted builder path ancestor: {}",
                ancestor.display()
            );
        }
    }
    Ok(())
}

fn atomic(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path.parent().context("record has no parent")?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o644))?;
    serde_json::to_writer(&mut file, value)?;
    file.write_all(b"\n")?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|error| error.error)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn bytes(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "builder metadata must be a regular file: {}",
        path.display()
    );
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "builder metadata exceeds its size limit"
    );
    Ok(bytes)
}

fn read<T: DeserializeOwned>(path: &Path) -> Result<T> {
    Ok(serde_json::from_slice(&bytes(path, 1024 * 1024)?)?)
}

fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn identity(metadata: &Path, role: Role) -> Result<(Identity, Vec<u8>)> {
    ensure!(
        fs::symlink_metadata(metadata)?.is_dir(),
        "invalid builder metadata directory"
    );
    let identity: Identity = read(&metadata.join("identity.json"))?;
    identity.validate()?;
    let registration = bytes(&metadata.join("registration"), 64 * 1024 * 1024)?;
    ensure!(
        identity.domain() == format!("{role}-build-store", role = role.name())
            && identity.registration_hash() == hash(&registration),
        "invalid pinned builder metadata"
    );
    if let Some(expected) = identity.inputs_hash() {
        ensure!(
            expected
                == hash(&bytes(
                    &metadata.join("flake-inputs.json"),
                    8 * 1024 * 1024
                )?),
            "invalid pinned builder flake inputs"
        );
    }
    Ok((identity, registration))
}

fn record_base(state: &Path, identity: &Identity) -> Result<()> {
    let path = state.join("base.json");
    if path.try_exists()? {
        let previous: Identity = read(&path)?;
        previous.validate()?;
        if previous == *identity {
            return Ok(());
        }
        ensure!(
            identity.accepts(&previous),
            "builder base changed; preserve the old base and upper, do not rebase automatically"
        );
    } else {
        for name in ["upper", "merged", "work"] {
            let directory = state.join(name);
            if directory.try_exists()? {
                ensure!(
                    fs::symlink_metadata(&directory)?.is_dir()
                        && fs::read_dir(&directory)?.next().is_none(),
                    "builder state exists without its base identity"
                );
            }
        }
    }
    atomic(&path, identity)
}

fn archive_foreign_base(state: &Path, identity: &Identity) -> Result<()> {
    let path = state.join("base.json");
    if !path.try_exists()? {
        return Ok(());
    }
    let previous: Identity = read(&path)?;
    previous.validate()?;
    if previous.domain() == identity.domain() {
        return Ok(());
    }
    let domain = previous.domain();
    let archive = state.with_file_name(format!(
        "{}-{domain}",
        state
            .file_name()
            .context("state has no name")?
            .to_str()
            .context("invalid state name")?
    ));
    ensure!(
        fs::symlink_metadata(&archive)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
        "inherited builder archive already exists; preserve both layers"
    );
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        state,
        rustix::fs::CWD,
        &archive,
        rustix::fs::RenameFlags::NOREPLACE,
    )?;
    File::open(state.parent().context("state has no parent")?)?.sync_all()?;
    fs::create_dir(state)?;
    File::open(state)?.sync_all()?;
    File::open(state.parent().context("state has no parent")?)?.sync_all()?;
    Ok(())
}

fn command(program: &str, args: &[&str], input: Option<Vec<u8>>) -> Result<String> {
    let output = airlock_nix_core::runtime::process::run(
        Command::new(program).args(args),
        input,
        Some(Duration::from_secs(90)),
    )?
    .checked(program)?;
    Ok(String::from_utf8(output)?)
}

fn text(path: &Path) -> Result<&str> {
    path.to_str().context("non-UTF-8 builder path")
}

fn mountpoints() -> Result<Vec<PathBuf>> {
    let mut mounts = Vec::new();
    for line in fs::read_to_string("/proc/self/mountinfo")?.lines() {
        let encoded = line
            .split_whitespace()
            .nth(4)
            .context("invalid kernel mount record")?;
        let mut decoded = Vec::new();
        let mut bytes = encoded.bytes();
        while let Some(byte) = bytes.next() {
            if byte == b'\\' {
                let octal = bytes.by_ref().take(3).collect::<Vec<_>>();
                ensure!(
                    octal.len() == 3 && octal.iter().all(|b| (b'0'..=b'7').contains(b)),
                    "invalid kernel mount escape"
                );
                let value = (octal[0] - b'0') as u16 * 64
                    + (octal[1] - b'0') as u16 * 8
                    + (octal[2] - b'0') as u16;
                decoded.push(u8::try_from(value)?);
            } else {
                decoded.push(byte);
            }
        }
        mounts.push(PathBuf::from(std::ffi::OsStr::from_bytes(&decoded)));
    }
    Ok(mounts)
}

fn mounted(path: &Path) -> Result<bool> {
    Ok(mountpoints()?.iter().any(|mount| mount == path))
}

fn ensure_unmounted(path: &Path) -> Result<()> {
    ensure!(
        !mountpoints()?.iter().any(|mount| mount.starts_with(path)),
        "builder path has existing mounts: {}",
        path.display()
    );
    Ok(())
}

fn mount(args: &Request, mounts: &mut Vec<PathBuf>, target: &Path, options: &[&str]) -> Result<()> {
    directory(target)?;
    ensure!(
        !mounted(target)?,
        "unsafe or already mounted builder path: {}",
        target.display()
    );
    // Record intent before mount so an interrupted start remains recoverable.
    mounts.push(target.to_path_buf());
    atomic(&args.runtime.join("mounts.json"), mounts)?;
    let mut command_args = options.to_vec();
    command_args.push(text(target)?);
    command("mount", &command_args, None)?;
    Ok(())
}

fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn start(args: &Request) -> Result<()> {
    ensure!(
        !args.runtime.join("ready.json").try_exists()?
            && !args.runtime.join("mounts.json").try_exists()?,
        "builder store is already mounted or needs cleanup; stop it first"
    );
    for path in [
        args.runtime.join("pool"),
        args.runtime.join("lower"),
        args.runtime.join("lower-scaffold"),
        args.state.join("merged"),
        args.state.join("upper"),
        args.state.join("work"),
    ] {
        ensure_unmounted(&path)?;
    }
    ensure!(
        !args.blob_device.contains([',', '\n', '\r']),
        "invalid builder blob device"
    );
    let uid = command("id", &["-u", "--", &args.user], None)?
        .trim()
        .parse::<u32>()?;
    let gid = command("id", &["-g", "--", &args.user], None)?
        .trim()
        .parse::<u32>()?;
    let mut mounts = Vec::new();
    let result = (|| {
        let pool = args.runtime.join("pool");
        mount(
            args,
            &mut mounts,
            &pool,
            &[
                "-t",
                "erofs",
                "-o",
                &format!("ro,nodev,nosuid,device={}", args.blob_device),
                &args.store_device,
            ],
        )?;
        let (identity, registration) = identity(&pool.join(".airlock-builder"), args.domain)?;
        archive_foreign_base(&args.state, &identity)?;
        record_base(&args.state, &identity)?;

        let lower = args.runtime.join("lower");
        // Re-import exactly the approved registrations on every start. A service
        // restart must not inherit stale rows from a previous base or clone.
        let database_parent = lower.join("nix/var/nix");
        directory(&database_parent)?;
        let database = database_parent.join("db");
        match fs::symlink_metadata(&database) {
            Ok(metadata) => {
                ensure!(metadata.is_dir(), "invalid lower Nix database directory");
                ensure_unmounted(&database)?;
                fs::remove_dir_all(&database)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let lower_store = lower.join("nix/store");
        let scaffold = args.runtime.join("lower-scaffold");
        directory(&scaffold.join(".links"))?;
        mount(
            args,
            &mut mounts,
            &lower_store,
            &[
                "-t",
                "overlay",
                "overlay",
                "-o",
                &format!(
                    "ro,nodev,nosuid,index=off,metacopy=off,redirect_dir=nofollow,lowerdir={}:{}",
                    text(&pool)?,
                    text(&scaffold)?
                ),
            ],
        )?;
        command(
            &args.nix_store,
            &[
                "--store",
                text(&lower)?,
                "--option",
                "build-users-group",
                "",
                "--load-db",
            ],
            Some(registration),
        )?;

        let db = lower.join("nix/var/nix/db");
        mount(args, &mut mounts, &db, &["--bind", text(&db)?])?;
        command("mount", &["-o", "remount,bind,ro", text(&db)?], None)?;
        for name in [
            "merged",
            "merged/nix",
            "merged/nix/store",
            "merged/nix/var",
            "upper",
            "work",
        ] {
            let path = args.state.join(name);
            if ["merged/nix/var", "upper", "work"].contains(&name) {
                real_directory(&path)?;
                ensure!(
                    [0, uid].contains(&fs::symlink_metadata(&path)?.uid()),
                    "unexpected builder directory owner"
                );
                rustix::fs::chown(
                    &path,
                    Some(rustix::process::Uid::from_raw(uid)),
                    Some(rustix::process::Gid::from_raw(gid)),
                )?;
            } else {
                // Intermediate mount parents must not remain writable by the
                // builder account, including directories from an earlier boot.
                real_directory(&path)?;
                ensure!(
                    [0, uid].contains(&fs::symlink_metadata(&path)?.uid()),
                    "unexpected builder mount directory owner"
                );
                rustix::fs::chown(
                    &path,
                    Some(rustix::process::Uid::ROOT),
                    Some(rustix::process::Gid::ROOT),
                )?;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
            }
        }
        let merged = args.state.join("merged");
        mount(
            args,
            &mut mounts,
            &merged.join("nix/store"),
            &[
                "-t",
                "overlay",
                "overlay",
                "-o",
                &format!(
                    "nodev,nosuid,index=off,metacopy=off,redirect_dir=nofollow,lowerdir={},upperdir={},workdir={}",
                    text(&lower_store)?,
                    text(&args.state.join("upper"))?,
                    text(&args.state.join("work"))?
                ),
            ],
        )?;

        let lower_uri = format!("local?root={}&read-only=true", text(&lower)?);
        let uri = format!(
            "local-overlay://?root={}&lower-store={}&upper-layer={}",
            encode(text(&merged)?),
            encode(&lower_uri),
            encode(text(&args.state.join("upper"))?)
        );
        atomic(
            &args.runtime.join("ready.json"),
            &Ready {
                identity,
                uri,
                mounts: mounts.clone(),
            },
        )
    })();
    if let Err(error) = result {
        return match cleanup(args, &mounts) {
            Ok(()) => Err(error),
            Err(cleanup) => Err(anyhow!(
                "{error:#}; builder cleanup also failed: {cleanup:#}"
            )),
        };
    }
    Ok(())
}

fn cleanup(args: &Request, mounts: &[PathBuf]) -> Result<()> {
    let expected = [
        args.runtime.join("pool"),
        args.runtime.join("lower/nix/store"),
        args.runtime.join("lower/nix/var/nix/db"),
        args.state.join("merged/nix/store"),
    ];
    ensure!(
        mounts.len() <= expected.len()
            && mounts
                .iter()
                .zip(&expected)
                .all(|(actual, expected)| actual == expected),
        "invalid builder mount journal"
    );
    revoke_ready(args)?;
    for path in mounts.iter().rev() {
        if mounted(path)? {
            command("umount", &[text(path)?], None)?;
        }
    }
    match fs::remove_file(args.runtime.join("mounts.json")) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    File::open(&args.runtime)?.sync_all()?;
    Ok(())
}

fn stop(args: &Request) -> Result<()> {
    revoke_ready(args)?;
    let journal = args.runtime.join("mounts.json");
    if !journal.try_exists()? {
        for path in [
            args.runtime.join("pool"),
            args.runtime.join("lower"),
            args.state.join("merged"),
        ] {
            ensure_unmounted(&path).context("builder mounts exist without their journal")?;
        }
        return Ok(());
    }
    let mounts: Vec<PathBuf> = read(&journal).context("invalid builder mount journal")?;
    cleanup(args, &mounts)
}

fn revoke_ready(args: &Request) -> Result<()> {
    match fs::remove_file(args.runtime.join("ready.json")) {
        Ok(()) => File::open(&args.runtime)?.sync_all()?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}
