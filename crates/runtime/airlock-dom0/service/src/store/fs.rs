//! Durable pool files and canonical object identities shared by store operations.
//! Publication uses rename followed by directory fsync so a committed name survives power loss.

use anyhow::{Context, Result, ensure};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

pub(super) const GENERATION_SCHEMA: &str = "airlock.closure-store.generation.v1";

pub(super) const ALIGNMENT: u64 = 4096;

pub(super) const SEGMENT_TARGET: u64 = 2 * 1024 * 1024 * 1024;

pub(super) fn read<T: DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_reader(File::open(path).with_context(|| format!("open {}", path.display()))?)
        .with_context(|| format!("read {}", path.display()))
}

pub(super) fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

/// Persist newly created ancestors as well as the directory's own contents.
pub(super) fn mkdir_all(path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref();
    let mut missing = Vec::new();
    let mut current = path;
    while !current.as_os_str().is_empty() && !current.try_exists()? {
        missing.push(current.to_path_buf());
        current = current.parent().context("directory has no ancestor")?;
    }
    fs::create_dir_all(path)?;

    // Sync from the leaves outward: a committed child needs a durable name in
    // its parent, even if a later file publication syncs that child directory.
    for directory in missing {
        sync_dir(&directory)?;
        let parent = directory.parent().context("directory has no parent")?;
        sync_dir(if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        })?;
    }
    Ok(())
}

/// Reserve a fresh directory without permitting an existing generation to be reused.
pub(super) fn mkdir(path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref();
    fs::create_dir(path)?;
    sync_dir(path)?;
    let parent = path.parent().context("directory has no parent")?;
    sync_dir(if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    })
}

pub(super) fn atomic(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().context("file has no parent")?;
    mkdir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    temporary.write_all(data)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    sync_dir(parent)
}

pub(super) fn write<T: Serialize>(path: &Path, value: &T, mode: u32) -> Result<()> {
    let mut data = serde_json::to_vec_pretty(value)?;
    data.push(b'\n');
    atomic(path, &data, mode)
}

pub(super) fn text(value: &Value, key: &str) -> Result<String> {
    Ok(value[key]
        .as_str()
        .with_context(|| format!("missing text field {key}"))?
        .to_owned())
}

pub(super) fn number(value: &Value, key: &str) -> Result<u64> {
    value[key]
        .as_u64()
        .with_context(|| format!("invalid unsigned field {key}"))
}

pub(super) fn component(value: &str) -> Result<&str> {
    ensure!(
        !value.is_empty() && value != "." && value != ".." && !value.contains(['/', '\0']),
        "invalid pool path component"
    );
    Ok(value)
}

pub(super) fn entry(value: &str) -> Result<&str> {
    component(
        value
            .strip_prefix("/nix/store/")
            .context("not a Nix store root")?,
    )
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(super) fn hash(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0; 1024 * 1024];
    loop {
        let size = file.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        digest.update(&buffer[..size]);
        super::progress::advance(size as u64);
    }
    Ok(hex(&digest.finalize()))
}

pub(super) fn children(path: &Path) -> Result<Vec<PathBuf>> {
    if !path.try_exists()? {
        return Ok(Vec::new());
    }
    ensure!(
        fs::symlink_metadata(path)?.is_dir(),
        "expected real directory: {}",
        path.display()
    );
    let mut paths = fs::read_dir(path)?
        .map(|item| item.map(|i| i.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.sort();
    Ok(paths)
}

pub(super) fn descendants(path: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for child in children(path)? {
        if fs::symlink_metadata(&child)?.is_dir() {
            paths.extend(descendants(&child)?);
        }
        paths.push(child);
    }
    paths.sort();
    Ok(paths)
}

pub(super) use airlock_nix_core::artifact::tree_hash;

pub(super) fn remove(path: &Path) -> Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !meta.is_symlink() {
        super::mounts::ensure_unmounted(&fs::canonicalize(path)?)?;
    }
    remove_tree(path, &meta)
}

fn remove_tree(path: &Path, meta: &fs::Metadata) -> Result<()> {
    if meta.is_dir() {
        fs::set_permissions(path, fs::Permissions::from_mode(meta.mode() | 0o700))?;
        for child in children(path)? {
            remove_tree(&child, &fs::symlink_metadata(&child)?)?;
        }
        fs::remove_dir(path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(())
}

pub(super) fn command(program: &str, args: &[&str], input: Option<&[u8]>) -> Result<String> {
    super::progress::command(program, || {
        let output = airlock_nix_core::runtime::process::run(
            Command::new(program).args(args),
            input.map(Vec::from),
            None,
        )
        .with_context(|| format!("run {program}"))?;
        Ok(String::from_utf8(output.checked(program)?)?)
    })
}

pub(super) fn tool(name: &str, override_name: &str) -> String {
    std::env::var(override_name).unwrap_or_else(|_| name.to_owned())
}

pub(super) fn failpoint(name: &str) -> Result<()> {
    ensure!(
        std::env::var("AIRLOCK_CLOSURE_STORE_FAILPOINT").as_deref() != Ok(name),
        "simulated failure at {name}"
    );
    Ok(())
}

pub(super) fn now() -> String {
    if image_build() {
        return "1970-01-01T00:00:01Z".to_owned();
    }
    // The same UTC representation is used in existing pool manifests.
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = seconds / 86400;
    let z = days as i64 + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds / 3600 % 24,
        seconds / 60 % 60,
        seconds % 60
    )
}

thread_local! {
    static IMAGE_BUILD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub(super) fn image_build() -> bool {
    IMAGE_BUILD.get()
}

pub(super) fn with_image_build(operation: impl FnOnce() -> Result<Value>) -> Result<Value> {
    struct Reset(
        // Previous reproducibility context restored on every exit path.
        bool,
    );

    impl Drop for Reset {
        fn drop(&mut self) {
            IMAGE_BUILD.set(self.0);
        }
    }

    let _reset = Reset(IMAGE_BUILD.replace(true));
    super::views::with_image_indexes(|| super::segments::with_verification(operation))
}

pub(super) fn transaction(identity: &str) -> Result<String> {
    if image_build() {
        let mut digest = sha1::Sha1::new();
        digest.update([
            0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4,
            0x30, 0xc8,
        ]);
        digest.update(format!("airlock-image-seed:{identity}"));
        let digest = digest.finalize();
        let mut bytes: [u8; 16] = digest[..16].try_into()?;
        bytes[6] = (bytes[6] & 0x0f) | 0x50;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        return Ok(hex(&bytes));
    }
    Ok(fs::read_to_string("/proc/sys/kernel/random/uuid")?
        .trim()
        .replace('-', ""))
}

pub(super) fn closure_hash(paths: &[String], system: &str, root: &str, kernel: &str) -> String {
    let mut hash = Sha256::new();
    for item in [
        GENERATION_SCHEMA.to_owned(),
        format!("system={system}"),
        format!("root={root}"),
        format!("kernel={kernel}"),
    ]
    .iter()
    .chain(paths)
    {
        hash.update(item.as_bytes());
        hash.update(b"\0");
    }
    hex(&hash.finalize())
}

pub(super) fn store_paths(source: &Path, system: &str) -> Result<Vec<String>> {
    let source = if source.is_dir() {
        let direct = source.join("store-paths");
        if direct.is_file() {
            direct
        } else {
            source.join("closure/store-paths")
        }
    } else {
        source.to_path_buf()
    };
    let mut paths = if source.is_file() {
        fs::read_to_string(source)?
            .lines()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect()
    } else {
        Vec::new()
    };
    if !system.is_empty() {
        paths.push(system.to_owned());
    }
    paths.sort();
    paths.dedup();
    ensure!(!paths.is_empty(), "closure source has no store paths");
    for path in &paths {
        entry(path)?;
    }
    Ok(paths)
}

/// Kernel-held exclusion; dropping the descriptor releases the lock on every exit path.
pub(super) struct PoolLock {
    // Open descriptor owns flock for the duration of a store transaction.
    _file: File,
}

impl PoolLock {
    pub(super) fn acquire(path: &Path) -> Result<Self> {
        mkdir_all(path.parent().context("lock has no parent")?)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .mode(0o600)
            .open(path)?;
        ensure!(
            file.metadata()?.is_file(),
            "pool lock is not a regular file"
        );
        rustix::fs::flock(&file, rustix::fs::FlockOperation::LockExclusive)?;
        Ok(Self { _file: file })
    }
}

pub(super) fn ensure_pool(root: &Path) -> Result<()> {
    // Validate every structural parent before creating any missing directory.
    // A corrupt pool must not redirect privileged writes outside its root.
    for part in [
        "MANIFEST.json",
        "objects/metadata",
        "objects/blob-metadata",
        "objects/segments",
        "domains",
        "views/by-closure",
        "runtime",
        "running",
        "transactions",
        "tmp",
        "root-artifacts",
        "builders",
        "host",
    ] {
        pool_path(root, &root.join(part))?;
    }
    ensure!(
        !root.join("objects/data.blob").try_exists()?,
        "unsupported single-blob closure pool"
    );
    let manifest = root.join("MANIFEST.json");
    if manifest.try_exists()? {
        let value: Value = read(&manifest)?;
        ensure!(
            value["schema"] == "airlock.closure-store.v1"
                && value["object_key"] == "nix-store-basename",
            "unsupported closure pool"
        );
        for (key, expected) in [
            ("schema", "airlock.closure-store.object-store.v1"),
            ("segments", "objects/segments"),
            ("metadata", "objects/blob-metadata"),
            ("object_key", "nix-store-basename"),
            ("format", "posix-tar-fragment-v1"),
        ] {
            ensure!(
                value["object_store"][key] == expected,
                "unsupported pool object store"
            );
        }
        ensure!(
            value["object_store"].get("data").is_none(),
            "unsupported pool data layout"
        );
    }
    for part in [
        "objects/metadata",
        "objects/blob-metadata",
        "objects/segments",
        "domains",
        "views/by-closure",
        "runtime",
        "running",
        "transactions",
        "tmp",
    ] {
        mkdir_all(root.join(part))?;
    }
    if !manifest.try_exists()? {
        write(
            &manifest,
            &json!({
                "schema": "airlock.closure-store.v1",
                "created_at": now(),
                "object_key": "nix-store-basename",
                "object_store": {"schema":"airlock.closure-store.object-store.v1","segments":"objects/segments","metadata":"objects/blob-metadata","object_key":"nix-store-basename","format":"posix-tar-fragment-v1","segment_target_bytes":SEGMENT_TARGET},
            }),
            0o644,
        )?;
    }
    Ok(())
}

pub(super) fn pool_path(root: &Path, path: &Path) -> Result<()> {
    ensure!(
        path.starts_with(root)
            && !root
                .components()
                .chain(path.components())
                .any(|c| c == std::path::Component::ParentDir),
        "metadata escapes pool"
    );
    let mut parent = path.to_path_buf();
    loop {
        ensure!(
            !parent.is_symlink(),
            "pool metadata is a symlink: {}",
            parent.display()
        );
        if parent == root {
            break;
        }
        ensure!(parent.pop(), "metadata has no pool ancestor");
    }
    Ok(())
}

pub(super) fn relative_path(source: &Path, directory: &Path) -> Result<PathBuf> {
    let source: Vec<_> = source.components().collect();
    let directory: Vec<_> = directory.components().collect();
    ensure!(
        source.first() == directory.first(),
        "relative link roots differ"
    );
    let common = source
        .iter()
        .zip(&directory)
        .take_while(|(a, b)| a == b)
        .count();
    let mut path = PathBuf::new();
    for _ in common..directory.len() {
        path.push("..");
    }
    for part in &source[common..] {
        path.push(part.as_os_str());
    }
    Ok(path)
}
