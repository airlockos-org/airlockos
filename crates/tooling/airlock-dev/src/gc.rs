//! Guarded collection of the external workstation's private Airlock store, retaining structured artifact roots.

use crate::{environment::Environment, support};
use airlock_nix_core::runtime::process;
use airlock_nix_core::store_path::StorePath;
use anyhow::{Context, Result, ensure};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Write,
    os::unix::fs::{MetadataExt, symlink},
    path::{Component, Path, PathBuf},
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Retain recently built fragments across automatic GC without keeping stale packer generations forever.
const FRAGMENT_CACHE_MAX_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Existing guarded store-maintenance entry modes.
#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum Mode {
    /// Refresh roots, list dead paths, and collect only above the configured size threshold.
    Auto,
    /// Refresh roots and list dead paths without requesting deletion.
    DryRun,
    /// Refresh roots and request collection of all unreachable objects in the private store.
    Run,
    /// Refresh managed roots without invoking Nix garbage collection.
    Roots,
}

/// Resolve existing symlinks and lexical parents even when the final path does not exist.
pub(crate) fn canonical(path: &Path) -> Result<PathBuf> {
    fn resolve(path: &Path, links: &mut usize) -> Result<PathBuf> {
        let absolute = if path.is_absolute() {
            path.to_owned()
        } else {
            std::env::current_dir()?.join(path)
        };
        let mut output = PathBuf::from("/");
        for component in absolute.components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::ParentDir => {
                    output.pop();
                }
                Component::Normal(name) => {
                    output.push(name);
                    match fs::symlink_metadata(&output) {
                        Ok(metadata) if metadata.file_type().is_symlink() => {
                            *links += 1;
                            ensure!(*links <= 40, "too many symlinks in maintenance path");
                            let target = fs::read_link(&output)?;
                            output.pop();
                            output = resolve(&output.join(target), links)?;
                        }
                        Ok(_) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                _ => anyhow::bail!("unsupported maintenance path"),
            }
        }
        Ok(output)
    }
    resolve(path, &mut 0)
}

/// Match the existing opt-in override spelling exactly.
fn enabled(name: &str) -> bool {
    std::env::var(name).as_deref() == Ok("1")
}

/// Detect a QEMU process using the selected VM directory without executing a process-name regex.
pub(crate) fn vm_running(vm: &Path) -> Result<bool> {
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        if !entry
            .file_name()
            .as_encoded_bytes()
            .iter()
            .all(u8::is_ascii_digit)
        {
            continue;
        }
        let Ok(command) = fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        let args = command.split(|byte| *byte == 0).collect::<Vec<_>>();
        let qemu = args.first().is_some_and(|program| {
            program
                .windows(b"qemu-system".len())
                .any(|window| window == b"qemu-system")
        });
        if qemu
            && args.iter().any(|argument| {
                argument
                    .windows(vm.as_os_str().as_encoded_bytes().len().max(1))
                    .any(|window| window == vm.as_os_str().as_encoded_bytes())
            })
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Add only known path-valued fields from decoded objects, never arbitrary log strings.
fn json_paths(value: &Value, output: &mut Vec<String>) {
    match value {
        Value::Object(values) => {
            for (key, value) in values {
                if [
                    "source",
                    "source_path",
                    "output_path",
                    "host_system_source",
                    "profile_source",
                ]
                .contains(&key.as_str())
                    && let Some(path) = value
                        .as_str()
                        .filter(|path| path.starts_with("/nix/store/"))
                {
                    output.push(path.into());
                }
                json_paths(value, output);
            }
        }
        Value::Array(values) => {
            for value in values {
                json_paths(value, output);
            }
        }
        _ => {}
    }
}

/// Normalize only existing objects in the selected physical store to their logical Nix identity.
fn logical(path: &Path, store: &Path) -> Option<PathBuf> {
    let relative = path
        .strip_prefix("/nix/store")
        .or_else(|_| path.strip_prefix(store))
        .ok()?;
    let Component::Normal(name) = relative.components().next()? else {
        return None;
    };
    fs::symlink_metadata(store.join(name))
        .is_ok()
        .then(|| PathBuf::from("/nix/store").join(name))
}

/// File entries in a possibly absent generated directory, ordered for stable root manifests.
fn entries(path: &Path) -> Result<Vec<fs::DirEntry>> {
    match fs::read_dir(path) {
        Ok(entries) => {
            let mut entries = entries.collect::<std::io::Result<Vec<_>>>()?;
            entries.sort_by_key(fs::DirEntry::file_name);
            Ok(entries)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error.into()),
    }
}

/// QEMU's structured identity for one image in an inspected backing chain.
#[derive(Deserialize)]
struct Image {
    /// Filename reported for this layer, including the final base image.
    filename: String,
    /// Resolved backing location when QEMU supplies one.
    #[serde(rename = "full-backing-filename")]
    full_backing: Option<String>,
    /// Header's backing location, relative to the named layer when not absolute.
    #[serde(rename = "backing-filename")]
    backing: Option<String>,
}

/// A referenced store object that was already absent before collection began.
#[derive(Serialize)]
struct MissingBacking {
    /// VM disk or retained backup whose chain cannot reach its base.
    image: PathBuf,
    /// Header's backing path, including any symlink alias used to reach the absent object.
    backing: PathBuf,
    /// Logical Nix object whose directory is absent from the selected physical store.
    missing_store_object: PathBuf,
}

/// Distinguish an absent store object from an unreadable or damaged existing image.
enum ImageLocation {
    /// A resolved path that can be inspected without host/private-store namespace ambiguity.
    File {
        /// Physical file or directory reached after resolving image symlinks.
        path: PathBuf,
    },
    /// An entire valid store object is already missing; this is not an inspection error.
    AbsentObject {
        /// Logical identity retained in the diagnostic even though no object remains to root.
        object: PathBuf,
    },
}

/// Resolve image symlinks in the selected store, retaining both aliases and their targets.
fn image_file(
    path: &Path,
    store: &Path,
    paths: &mut Vec<PathBuf>,
    links: &mut usize,
) -> Result<ImageLocation> {
    paths.push(path.to_owned());
    let mapped = match path.strip_prefix("/nix/store") {
        Ok(relative) => store.join(relative),
        Err(_) => path.to_owned(),
    };
    paths.push(mapped.clone());
    let mut output = PathBuf::from("/");
    for component in mapped.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                output.pop();
            }
            Component::Normal(name) => {
                output.push(name);
                let metadata = match fs::symlink_metadata(&output) {
                    Ok(metadata) => metadata,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::NotFound
                            && output.parent() == Some(store) =>
                    {
                        let object = Path::new("/nix/store").join(name);
                        let _: StorePath = object
                            .to_str()
                            .context("non-UTF-8 backing store object")?
                            .parse()?;
                        return Ok(ImageLocation::AbsentObject { object });
                    }
                    Err(error) => return Err(error.into()),
                };
                if metadata.file_type().is_symlink() {
                    *links += 1;
                    ensure!(*links <= 40, "too many symlinks in backing image path");
                    paths.push(output.clone());
                    let target = fs::read_link(&output)?;
                    output.pop();
                    match image_file(&output.join(target), store, paths, links)? {
                        ImageLocation::File { path } => output = path,
                        absent @ ImageLocation::AbsentObject { .. } => return Ok(absent),
                    }
                }
            }
            _ => anyhow::bail!("unsupported backing image path"),
        }
    }
    paths.push(output.clone());
    Ok(ImageLocation::File { path: output })
}

/// Inspect each layer without asking host QEMU to open private-store backing paths itself.
fn backing_paths(
    qemu: &std::ffi::OsStr,
    image: &Path,
    store: &Path,
    missing: &mut Vec<MissingBacking>,
) -> Result<Vec<PathBuf>> {
    let mut named = image.to_owned();
    let mut paths = Vec::new();
    let mut seen = BTreeSet::new();
    for layer in 0..64 {
        let location = image_file(&named, store, &mut paths, &mut 0).with_context(|| {
            format!(
                "cannot resolve backing image {image}",
                image = named.display()
            )
        })?;
        let physical = match location {
            ImageLocation::File { path } => path,
            ImageLocation::AbsentObject { object } => {
                ensure!(layer > 0, "VM image disappeared before backing inspection");
                missing.push(MissingBacking {
                    image: image.to_owned(),
                    backing: named,
                    missing_store_object: object,
                });
                return Ok(paths);
            }
        };
        ensure!(physical.is_file(), "backing image is not a regular file");
        ensure!(seen.insert(physical.clone()), "cyclic QEMU backing chain");
        let information = support::text(
            Command::new(qemu)
                .args(["info", "--output=json"])
                .arg(&physical),
        )
        .with_context(|| {
            format!(
                "cannot inspect backing image {image}",
                image = named.display()
            )
        })?;
        let image: Image =
            serde_json::from_str(&information).context("invalid QEMU backing-chain evidence")?;
        ensure!(
            !image.filename.is_empty(),
            "QEMU reported an empty image filename"
        );
        let Some(backing) = image.backing.or(image.full_backing) else {
            return Ok(paths);
        };
        ensure!(
            !backing.is_empty(),
            "QEMU reported an empty backing filename"
        );
        // Relative headers use the named layer's directory, even when it is a symlink.
        named = named
            .parent()
            .context("image has no parent directory")?
            .join(backing);
    }
    anyhow::bail!("QEMU backing chain exceeds 64 layers")
}

/// Collect all current root evidence before replacing the previous managed root set.
fn roots(
    root: &Path,
    vm: &Path,
    links: &Path,
    logs: &Path,
    store: &Path,
    missing: &mut Vec<MissingBacking>,
) -> Result<BTreeMap<PathBuf, (String, String)>> {
    let mut roots = BTreeMap::new();
    let mut add = |name: String, path: &Path, reason: String| {
        if let Some(logical) = logical(path, store) {
            roots.entry(logical).or_insert((name, reason));
        }
    };
    for (directory, kind) in [(root, 0), (vm, 1), (links, 2)] {
        for entry in entries(directory)? {
            let name = entry.file_name().to_string_lossy().into_owned();
            if (kind == 0 && name != "result" && !name.starts_with("result-"))
                || (kind == 1 && !name.ends_with("-result"))
                || !entry.file_type()?.is_symlink()
            {
                continue;
            }
            let target = fs::read_link(entry.path())?;
            let target = if target.is_absolute() {
                target
            } else {
                directory.join(target)
            };
            add(
                format!("outlink-{name}"),
                &target,
                format!("out-link:{path}", path = entry.path().display()),
            );
        }
    }
    let qemu = std::env::var_os("AIRLOCK_QEMU_IMG_BIN").unwrap_or_else(|| "qemu-img".into());
    for entry in entries(vm)? {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !entry.file_type()?.is_file()
            || !(name.ends_with(".qcow2") || (name.contains(".qcow2.") && name.ends_with(".bak")))
        {
            continue;
        }
        // Retain reachable layers even when a later store object was already removed.
        for path in backing_paths(&qemu, &entry.path(), store, missing)
            .context("cannot inspect qcow2 backing roots")?
        {
            add(
                format!(
                    "qcow-backing-{name}-{backing}",
                    name = entry.file_name().to_string_lossy(),
                    backing = path.file_name().unwrap_or_default().to_string_lossy()
                ),
                &path,
                format!("qcow2-backing:{image}", image = entry.path().display()),
            );
        }
    }
    for entry in entries(logs)? {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !entry.file_type()?.is_file()
            || !name.ends_with(".json")
            || !(name.contains("config")
                || name.contains("deployment")
                || name.ends_with("builds.json"))
        {
            continue;
        }
        let value = support::json(&entry.path())
            .with_context(|| format!("cannot inspect GC receipt roots: {name}"))?;
        let mut paths = Vec::new();
        json_paths(&value, &mut paths);
        for path in paths {
            add(
                format!(
                    "json-{name}-{base}",
                    base = Path::new(&path)
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                ),
                Path::new(&path),
                format!("json-artifact:{file}", file = entry.path().display()),
            );
        }
    }
    Ok(roots)
}

/// Keep complete, recent fragment outputs during routine GC; explicit full GC may reclaim them.
fn retain_recent_fragments(
    store: &Path,
    roots: &mut BTreeMap<PathBuf, (String, String)>,
    now: SystemTime,
) -> Result<usize> {
    let now = now.duration_since(UNIX_EPOCH)?.as_secs();
    let mut retained = 0;
    for entry in entries(store)? {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Ok(path) = format!("/nix/store/{name}").parse::<StorePath>() else {
            continue;
        };
        if !name
            .get(33..)
            .is_some_and(|suffix| suffix.starts_with("airlock-store-fragment-"))
            || !entry.file_type()?.is_dir()
            || !entry.path().join("metadata.json").is_file()
            || !entry.path().join("object.tar").is_file()
        {
            continue;
        }
        // Nix normalizes output mtimes to 1970. Filesystem change time records when
        // this private store received the completed output, including substitutes.
        let changed = entry.metadata()?.ctime();
        let Ok(changed) = u64::try_from(changed) else {
            continue;
        };
        if now.saturating_sub(changed) > FRAGMENT_CACHE_MAX_AGE.as_secs() {
            continue;
        }
        roots
            .entry(PathBuf::from(path.as_str()))
            .or_insert_with(|| {
                (
                    format!("fragment-cache-{name}"),
                    "recent-image-fragment-cache".into(),
                )
            });
        retained += 1;
    }
    Ok(retained)
}

/// Incomplete chains may add protection, but cannot revoke any previously known existing root.
fn retain_previous(
    directory: &Path,
    store: &Path,
    roots: &mut BTreeMap<PathBuf, (String, String)>,
) -> Result<()> {
    for entry in entries(directory)? {
        if !entry.file_type()?.is_symlink() {
            continue;
        }
        // Cache roots are expendable even when a VM backing chain is incomplete.
        // Carrying them forward would defeat explicit full GC and cache expiry.
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with("fragment-cache-")
        {
            continue;
        }
        let target = fs::read_link(entry.path())?;
        let _: StorePath = target
            .to_str()
            .context("non-UTF-8 previous GC root")?
            .parse()
            .context("invalid previous GC root")?;
        if let Some(path) = logical(&target, store) {
            roots.entry(path.clone()).or_insert_with(|| {
                (
                    format!(
                        "retained-{object}",
                        object = path.file_name().unwrap().to_string_lossy()
                    ),
                    "previous-root:incomplete-backing-chain".into(),
                )
            });
        }
    }
    Ok(())
}

/// Publish distinct roots before deleting stale links, so filename collisions cannot drop retention.
fn publish(directory: &Path, roots: &BTreeMap<PathBuf, (String, String)>) -> Result<()> {
    let mut names = BTreeSet::new();
    let mut manifest = Vec::new();
    for (logical, (name, reason)) in roots {
        let name = name
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || "_.-".contains(ch) {
                    ch
                } else {
                    '_'
                }
            })
            .collect::<String>();
        let digest = support::digest(logical.as_os_str().as_encoded_bytes());
        let name = format!("{name}-{hash}", hash = &digest[..16]);
        let temporary = tempfile::tempdir_in(directory)?;
        symlink(logical, temporary.path().join("root"))?;
        fs::rename(temporary.path().join("root"), directory.join(&name))?;
        names.insert(name.clone());
        writeln!(
            manifest,
            "{name}\t{logical}\t{reason}",
            logical = logical.display()
        )?;
    }
    for entry in entries(directory)? {
        if !names.contains(&entry.file_name().to_string_lossy().into_owned())
            && (entry.file_type()?.is_file() || entry.file_type()?.is_symlink())
        {
            fs::remove_file(entry.path())?;
        }
    }
    support::atomic(&directory.join("manifest.tsv"), &manifest)
}

/// Measure allocated storage using the existing system utility rather than traversing Nix objects in Rust.
fn size(root: &Path) -> Result<u64> {
    support::text(Command::new("du").args(["-s", "-B1"]).arg(root))?
        .split_whitespace()
        .next()
        .context("du did not report private-store size")?
        .parse()
        .map_err(Into::into)
}

/// Refresh guarded roots and invoke Nix only against the selected private root.
pub(crate) fn execute(root: &Path, mode: Mode) -> Result<()> {
    ensure!(
        !enabled("AIRLOCK_USE_HOST_NIX_STORE"),
        "refusing to GC while AIRLOCK_USE_HOST_NIX_STORE=1"
    );
    let env = Environment::load()?;
    let data = canonical(&env.path("AIRLOCK_DATA_ROOT", ""))?;
    let nix = canonical(&env.path("AIRLOCK_NIX_ROOT", ""))?;
    ensure!(
        data.starts_with("/run/media/user/data/airlock")
            || enabled("AIRLOCK_GC_ALLOW_NONSTANDARD_DATA_ROOT"),
        "refusing nonstandard data root: {data}",
        data = data.display()
    );
    ensure!(
        nix == data.join("nix-root")
            && ![Path::new("/"), Path::new("/nix"), Path::new("/nix/store")]
                .contains(&nix.as_path()),
        "refusing AIRLOCK_NIX_ROOT outside the expected Airlock store: {nix}",
        nix = nix.display()
    );
    let store = nix.join("nix/store");
    let managed = nix.join("nix/var/nix/gcroots/airlock");
    ensure!(
        canonical(&store)?.starts_with(&nix) && canonical(&managed)?.starts_with(&nix),
        "private store or managed roots escape the selected Nix root"
    );
    if !store.is_dir() && matches!(mode, Mode::Auto) {
        println!(
            "Airlock store directory is missing; auto GC skipped: {store}",
            store = store.display()
        );
        return Ok(());
    }
    ensure!(
        store.is_dir(),
        "Airlock store directory is missing: {store}",
        store = store.display()
    );
    let logs = env.path("AIRLOCK_LOG_DIR", root.join(".airlock-logs"));
    let vm = env.path("AIRLOCK_VM_DIR", root.join(".airlock-vm"));
    let links = env.path("AIRLOCK_RESULT_LINK_DIR", data.join("result-links"));
    ensure!(
        enabled("AIRLOCK_GC_ALLOW_RUNNING_VM") || !vm_running(&vm)?,
        "refusing to GC while an Airlock QEMU VM appears to be running"
    );
    let threshold: u64 = std::env::var("AIRLOCK_GC_AUTO_THRESHOLD_GIB")
        .unwrap_or_else(|_| "150".into())
        .parse()
        .context("AIRLOCK_GC_AUTO_THRESHOLD_GIB must be a non-negative integer")?;
    let threshold_bytes = threshold
        .checked_mul(1024 * 1024 * 1024)
        .context("GC threshold overflow")?;
    fs::create_dir_all(&logs)?;
    fs::create_dir_all(&managed)?;
    let lock = File::options()
        .create(true)
        .write(true)
        .truncate(false)
        .open(data.join("gc.lock"))?;
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .context("another Airlock GC operation is running")?;
    let mut missing = Vec::new();
    let mut roots = roots(root, &vm, &links, &logs, &store, &mut missing)?;
    let fragment_cache_roots = if matches!(mode, Mode::Run) {
        0
    } else {
        retain_recent_fragments(&store, &mut roots, SystemTime::now())?
    };
    if !missing.is_empty() {
        retain_previous(&managed, &store, &mut roots)?;
        for gap in &missing {
            eprintln!(
                "Warning: {image} references absent backing object {object}; retaining previous managed roots and collecting only unrelated outputs.",
                image = gap.image.display(),
                object = gap.missing_store_object.display()
            );
        }
    }
    publish(&managed, &roots)?;
    let before = size(&nix)?;
    let program = std::env::var_os("AIRLOCK_NIX_STORE_BIN").unwrap_or_else(|| "nix-store".into());
    let dead_log = logs.join("airlock-store-gc-dead-paths.log");
    let dead_errors = logs.join("airlock-store-gc-dead-paths.stderr.log");
    let gc_log = logs.join("airlock-store-gc.log");
    let mut dead = 0;
    let mut collected = false;
    if matches!(mode, Mode::Auto | Mode::DryRun) {
        let output = process::run(
            Command::new(&program)
                .args(["--gc", "--print-dead"])
                .envs(&env.values)
                .env("NIX_CONFIG", format!("store = {nix}", nix = nix.display())),
            None,
            Some(Duration::from_secs(3600)),
        )?;
        fs::write(&dead_log, &output.stdout)?;
        fs::write(&dead_errors, &output.stderr)?;
        output.checked("private-store dead-path query")?;
        dead = fs::read_to_string(&dead_log)?
            .lines()
            .filter(|line| line.starts_with("/nix/store/"))
            .count();
    }
    if matches!(mode, Mode::Run)
        || (matches!(mode, Mode::Auto) && dead > 0 && before >= threshold_bytes)
    {
        let output = process::run(
            Command::new(&program)
                .arg("--gc")
                .envs(&env.values)
                .env("NIX_CONFIG", format!("store = {nix}", nix = nix.display())),
            None,
            Some(Duration::from_secs(3600)),
        )?;
        let mut bytes = output.stdout.clone();
        bytes.extend_from_slice(&output.stderr);
        fs::write(&gc_log, bytes)?;
        output.checked("private-store garbage collection")?;
        collected = true;
    }
    let result = logs.join("airlock-store-gc.json");
    support::record(
        &result,
        &json!({"schema":"airlock.store-gc.v1","mode":match mode {Mode::Auto=>"auto",Mode::DryRun=>"dry-run",Mode::Run=>"run",Mode::Roots=>"roots"},"data_root":data,"nix_root":nix,"store_dir":store,"gcroots_dir":managed,"root_manifest":managed.join("manifest.tsv"),"root_count":roots.len(),"fragment_cache_roots":fragment_cache_roots,"missing_backing_images":missing,"auto_threshold_gib":threshold,"threshold_bytes":threshold_bytes,"store_bytes_before":before,"store_bytes_after":size(&nix)?,"dead_count":dead,"gc_ran":collected,"dead_log":dead_log,"dead_stderr_log":dead_errors,"gc_log":gc_log,"result_json":result}),
    )?;
    println!(
        "Airlock data root: {data}\nAirlock Nix root:  {nix}\nRooted paths:     {count}\nFragment cache:   {fragment_cache_roots} roots\nDead path count:  {dead}\nResult JSON:      {result}",
        data = data.display(),
        nix = nix.display(),
        count = roots.len(),
        result = result.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Routine GC retains complete recent fragments and lets an aged packer cache expire.
    #[test]
    fn fragment_cache_roots_expire_without_accepting_incomplete_outputs() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let store = temporary.path();
        let complete = "11111111111111111111111111111111-airlock-store-fragment-package";
        let incomplete = "22222222222222222222222222222222-airlock-store-fragment-incomplete";
        fs::create_dir(store.join(complete))?;
        fs::write(store.join(complete).join("metadata.json"), "{}")?;
        fs::write(store.join(complete).join("object.tar"), "tar")?;
        fs::create_dir(store.join(incomplete))?;
        let mut roots = BTreeMap::new();

        let now = SystemTime::now();
        assert_eq!(retain_recent_fragments(store, &mut roots, now)?, 1);
        assert!(roots.contains_key(&PathBuf::from(format!("/nix/store/{complete}"))));
        roots.clear();
        assert_eq!(
            retain_recent_fragments(
                store,
                &mut roots,
                now + FRAGMENT_CACHE_MAX_AGE + Duration::from_secs(2)
            )?,
            0
        );
        assert!(roots.is_empty());
        Ok(())
    }

    /// Existing symlink parents are resolved before a missing path's lexical parent components.
    #[test]
    fn canonical_paths_preserve_symlink_parent_semantics() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let nested = temporary.path().join("actual/nested");
        fs::create_dir_all(&nested)?;
        symlink(&nested, temporary.path().join("alias"))?;
        assert_eq!(
            canonical(&temporary.path().join("alias/../missing"))?,
            temporary.path().join("actual/missing")
        );
        Ok(())
    }

    /// Only selected structured fields retain objects; free-form diagnostic text does not create roots.
    #[test]
    fn structured_gc_roots_ignore_unclassified_strings() {
        let mut paths = Vec::new();
        json_paths(
            &json!({"source":"/nix/store/a-source","nested":[{"output_path":"/nix/store/b-output","log":"/nix/store/c-noise"}]}),
            &mut paths,
        );
        assert_eq!(
            paths.into_iter().collect::<BTreeSet<_>>(),
            [
                "/nix/store/a-source".to_owned(),
                "/nix/store/b-output".to_owned()
            ]
            .into_iter()
            .collect()
        );
    }
}
