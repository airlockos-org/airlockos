//! Snapshot machine source and emit a complete, inspectable Nix input in an ignored build directory.
//! Preparation never evaluates Nix or authorizes a build or deployment.

pub mod cache;

use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

/// Errors from source capture, Rust compilation or artifact publication.
type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// Run a source tool and retain its diagnostic output on failure.
fn output(command: &mut Command) -> Result<Vec<u8>> {
    let result = command.output()?;
    if !result.status.success() {
        return Err(format!(
            "source preparation failed: {command:?}\n{stderr}",
            stderr = String::from_utf8_lossy(&result.stderr),
        )
        .into());
    }

    Ok(result.stdout)
}

/// Read Git metadata without including ignored editor or build output in the artifact.
fn git(source: &Path, args: &[&str]) -> Result<Vec<u8>> {
    output(Command::new("git").arg("-C").arg(source).args(args))
}

/// Hash both file bytes and permissions so executable source remains distinguishable.
fn digest(path: &Path) -> Result<String> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::symlink_metadata(path)?;
    let mut hash = Sha256::new();
    hash.update(metadata.permissions().mode().to_le_bytes());
    if metadata.file_type().is_symlink() {
        hash.update(fs::read_link(path)?.as_os_str().as_encoded_bytes());
    } else {
        hash.update(fs::read(path)?);
    }

    Ok(format!("{hash:x}", hash = hash.finalize()))
}

/// Copy indexed source files and recursively capture initialized Git submodules.
/// Working edits to tracked files are included; deleted files and ignored output are omitted.
fn snapshot(source: &Path, destination: &Path) -> Result<BTreeMap<String, String>> {
    let entries = git(source, &["ls-files", "--stage", "-z", "--", "."])?;
    let mut files = BTreeMap::new();
    for entry in entries
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
    {
        let entry = std::str::from_utf8(entry)?;
        let (metadata, name) = entry.split_once('\t').ok_or("invalid Git index entry")?;
        let mode = metadata
            .split_whitespace()
            .next()
            .ok_or("missing Git file mode")?;
        let from = source.join(name);
        let to = destination.join(name);
        if mode == "160000" {
            fs::create_dir_all(&to)?;
            for (child, hash) in snapshot(&from, &to)? {
                files.insert(format!("{name}/{child}"), hash);
            }
            continue;
        }
        if !from.try_exists()? && fs::symlink_metadata(&from).is_err() {
            continue;
        }

        fs::create_dir_all(to.parent().ok_or("source file lacks parent")?)?;
        if fs::symlink_metadata(&from)?.file_type().is_symlink() {
            std::os::unix::fs::symlink(fs::read_link(&from)?, &to)?;
        } else {
            fs::copy(&from, &to)?;
        }
        files.insert(name.to_owned(), digest(&to)?);
    }

    let revision = String::from_utf8(git(source, &["rev-parse", "HEAD"])?)?;
    let timestamp = String::from_utf8(git(source, &["show", "-s", "--format=%ct", "HEAD"])?)?;
    fs::write(
        destination.join("airlock-source.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "revision": revision.trim(),
            "timestamp": timestamp.trim().parse::<u64>()?,
            "dirty": !git(source, &["status", "--porcelain", "--untracked-files=no"])?.is_empty(),
        }))?,
    )?;

    files.insert(
        "airlock-source.json".into(),
        digest(&destination.join("airlock-source.json"))?,
    );

    Ok(files)
}

/// Hash the complete prepared tree in stable path order, excluding its own receipt.
fn inventory(root: &Path, directory: &Path, files: &mut BTreeMap<String, String>) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if fs::symlink_metadata(&path)?.is_dir() {
            inventory(root, &path, files)?;
        } else {
            files.insert(
                path.strip_prefix(root)?.to_string_lossy().into_owned(),
                digest(&path)?,
            );
        }
    }

    Ok(())
}

/// Capture indexed source, emit its Nix interface, and publish a content-addressed build tree.
/// The output contains no Git metadata. Use the returned directory with an explicit `path:` URL.
/// The receipt records source revision, working source contents and every prepared file digest.
/// Source changes during preparation fail before publication; existing artifacts are never replaced.
/// Checkout-local caches must be ignored by Git; external caches are also accepted.
/// The callback may compile Rust, but must not run Nix.
/// Successful preparation attempts automatic cache cleanup unless
/// `AIRLOCK_PREPARED_AUTO_PRUNE=0`. Use `prepare_leased` for protection throughout subsequent use.
pub fn prepare(
    source: &Path,
    cache: &Path,
    emit: impl FnOnce(&Path) -> Result<()>,
) -> Result<PathBuf> {
    let (tree, _lease) = prepare_leased(source, cache, emit)?;
    Ok(tree)
}

/// Prepare source and protect its published tree until the returned lease is dropped.
/// Cleanup runs after publication, with the current tree protected. It retains three
/// recently used disposable trees plus anything used within 24 hours, pins and active leases.
/// A busy cache skips cleanup; cleanup failures are reported on stderr without failing preparation.
/// Set `AIRLOCK_PREPARED_AUTO_PRUNE=0` to disable automatic cleanup.
pub fn prepare_leased(
    source: &Path,
    cache: &Path,
    emit: impl FnOnce(&Path) -> Result<()>,
) -> Result<(PathBuf, cache::Lease)> {
    let source = fs::canonicalize(source)?;
    fs::create_dir_all(cache)?;
    let cache = fs::canonicalize(cache)?;
    if cache.starts_with(&source)
        && !Command::new("git")
            .arg("-C")
            .arg(&source)
            .args(["check-ignore", "--quiet", "--"])
            .arg(cache.strip_prefix(&source)?)
            .status()?
            .success()
    {
        return Err("checkout-local prepared source cache must be ignored by Git".into());
    }

    let coordination = cache::coordination(&cache, false)?;
    let staging = tempfile::Builder::new()
        .prefix(".preparing-")
        .tempdir_in(&cache)?;
    let files = snapshot(&source, staging.path())?;
    let revision = String::from_utf8(git(&source, &["rev-parse", "HEAD"])?)?
        .trim()
        .to_owned();
    let dirty = !git(&source, &["status", "--porcelain", "--untracked-files=no"])?.is_empty();
    emit(staging.path())?;

    let verification = tempfile::tempdir_in(&cache)?;
    if snapshot(&source, verification.path())? != files
        || String::from_utf8(git(&source, &["rev-parse", "HEAD"])?)?.trim() != revision
    {
        return Err("source changed during preparation; retry from a stable checkout".into());
    }

    let mut artifacts = BTreeMap::new();
    inventory(staging.path(), staging.path(), &mut artifacts)?;
    let artifact_hash = format!(
        "{hash:x}",
        hash = Sha256::digest(serde_json::to_vec(&artifacts)?)
    );
    let receipt = serde_json::json!({
        "schema": "airlock.prepared-source.v1",
        "compiler_sha256": digest(&std::env::current_exe()?)?,
        "revision": revision,
        "dirty": dirty,
        "source_files": files,
        "artifact_sha256": artifact_hash,
        "artifact_files": artifacts,
    });
    let receipt = serde_json::to_vec_pretty(&receipt)?;
    let identity = format!("{hash:x}", hash = Sha256::digest(&receipt));
    fs::write(staging.path().join("airlock-prepared.json"), &receipt)?;

    let destination = cache.join(identity);
    // Publish and check the identity under one lock, including concurrent identical preparations.
    let publication = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(cache.join(".publication.lock"))?;
    publication.lock()?;
    if destination.exists() {
        if fs::read(destination.join("airlock-prepared.json"))? != receipt {
            return Err("prepared source identity collision".into());
        }
        let mut existing = BTreeMap::new();
        inventory(&destination, &destination, &mut existing)?;
        existing.remove("airlock-prepared.json");
        if existing != artifacts {
            return Err("existing prepared source was modified".into());
        }
    } else {
        fs::rename(staging.path(), &destination)?;
    }

    let lease = cache::lease(&cache, &destination)?;
    drop(publication);
    drop(coordination);

    cache::automatic(&cache);
    Ok((destination, lease))
}

/// Emit the application flake consumed by builds into an already captured source tree.
pub fn applications(directory: &Path) -> Result<()> {
    fs::create_dir_all(directory)?;
    fs::write(
        directory.join("flake.nix"),
        crate::flake("applications")?.source,
    )?;
    Ok(())
}

/// Emit optional constructor catalogues for inspection and test fixtures.
/// Normal prepared build trees omit these exports because their flakes compose Rust constructors.
/// Use a separate directory or a test copy; adding files to a published tree invalidates its receipt.
pub fn inspection(directory: &Path) -> Result<()> {
    for (relative, generated) in [
        (
            "airlock-config/generated/packages.nix",
            crate::application_packages()?,
        ),
        (
            "airlock-config/generated/vm-builders.nix",
            crate::vm_builders()?,
        ),
        (
            "airlock-config/generated/modules.nix",
            crate::machine_modules()?,
        ),
        (
            "airlock-config/generated/displays.nix",
            crate::display_builders()?,
        ),
        (
            "runtime/airlock-sys-gui/service/generated/packages.nix",
            crate::gui_service_packages()?,
        ),
    ] {
        let path = directory.join(relative);
        fs::create_dir_all(path.parent().ok_or("artifact lacks parent")?)?;
        fs::write(path, generated.source)?;
    }

    Ok(())
}

/// Compile a machine-owned program against explicitly supplied application sources and vendor tree.
/// Cargo build output stays outside the prepared tree; its resulting program receives the export path.
/// A locked, stable source mirror preserves Cargo fingerprints across Nix-only edits and new snapshots.
/// Cargo still tracks real compiler inputs, including files explicitly embedded by Rust code.
pub fn compile(source: &Path, applications: &Path, destination: &Path) -> Result<()> {
    let vendor = std::env::var("AIRLOCK_CARGO_VENDOR").unwrap_or_else(|_| {
        applications
            .parent()
            .unwrap_or(applications)
            .join(".airlock-cache/authoring-vendor")
            .to_string_lossy()
            .into_owned()
    });
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| applications.join("target"));
    compile_in(source, applications, destination, &target, &vendor)
}

/// Mirror captured sources without touching unchanged files or following source symlinks.
/// Removing stale inputs lets Cargo observe deletions as well as additions and edits.
fn mirror(source: &Path, destination: &Path) -> Result<()> {
    if let Ok(existing) = fs::symlink_metadata(destination)
        && !existing.is_dir()
    {
        remove(destination)?;
    }
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(destination)? {
        let entry = entry?;
        match fs::symlink_metadata(source.join(entry.file_name())) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => remove(&entry.path())?,
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
    }

    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let from = entry.path();
        let to = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&from)?;
        if metadata.is_dir() {
            if let Ok(existing) = fs::symlink_metadata(&to)
                && !existing.is_dir()
            {
                remove(&to)?;
            }
            mirror(&from, &to)?;
        } else {
            if fs::symlink_metadata(&to).is_ok_and(|m| !m.is_dir())
                && digest(&from)? == digest(&to)?
            {
                continue;
            }
            if fs::symlink_metadata(&to).is_ok() {
                remove(&to)?;
            }
            if metadata.file_type().is_symlink() {
                std::os::unix::fs::symlink(fs::read_link(&from)?, &to)?;
            } else {
                fs::copy(&from, &to)?;
            }
        }
    }

    Ok(())
}

/// Delete one mirror entry without following a symlink to an external directory.
fn remove(path: &Path) -> Result<()> {
    if fs::symlink_metadata(path)?.is_dir() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(())
}

/// Serialize compiler mirror updates and execution while keeping emission tied to the fresh snapshot.
fn compile_in(
    source: &Path,
    applications: &Path,
    destination: &Path,
    target: &Path,
    vendor: &str,
) -> Result<()> {
    fs::create_dir_all(target)?;
    let target = fs::canonicalize(target)?;
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(target.join("airlock-machine-source.lock"))?;
    lock.lock()?;
    let compiler_source = target.join("airlock-machine-source");
    if compiler_source.starts_with(fs::canonicalize(source)?) {
        return Err("compiler mirror must be outside the captured source".into());
    }
    mirror(source, &compiler_source)?;

    let status = Command::new("cargo")
        .current_dir(source)
        .args([
            "--config",
            &format!(
                "patch.crates-io.airlock-config.path={path:?}",
                path = applications.join("airlock-config")
            ),
            "--config",
            &format!("source.airlock-admitted.directory={vendor:?}"),
            "--config",
            &format!(
                "build.rustflags=[{mapping:?}]",
                mapping = format!(
                    "--remap-path-prefix={apps}/=",
                    apps = applications.display()
                )
            ),
            "run",
            "--manifest-path",
        ])
        .arg(compiler_source.join("Cargo.toml"))
        .args(["--locked", "--offline", "--target-dir"])
        .arg(&target)
        .args(["--", "--emit"])
        .arg(destination)
        .stdout(Stdio::null())
        .status()?;
    if !status.success() {
        return Err("Rust source compilation failed during preparation".into());
    }

    Ok(())
}

/// Run a machine checkout's preparation adapter with its physical configuration and pinned apps.
/// Accept `--emit DIRECTORY` or `prepare CACHE` from the process arguments. The nested validation
/// machine comes from Airlock's shared profile; emission never evaluates Nix or deploys a system.
/// Invalid arguments, source changes during preparation, or filesystem failures return an error.
pub fn run_machine(
    snapshot: &crate::model::MachineSnapshot,
    application_revision: &str,
) -> Result<()> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let emit = |directory: &Path| {
        crate::export_machine(
            snapshot,
            &crate::profiles::bootstrap::machine()?,
            application_revision,
            directory,
        )
    };

    match arguments.as_slice() {
        [command, directory] if command == "--emit" => emit(&PathBuf::from(directory)),
        [command, cache] if command == "prepare" => {
            let tree = prepare(&std::env::current_dir()?, &PathBuf::from(cache), emit)?;
            println!("path:{path}", path = tree.display());
            Ok(())
        }
        _ => Err("usage: airlock-machine-config prepare CACHE | --emit DIRECTORY".into()),
    }
}

/// Prepare the development flake and its complete machine and application source inputs.
/// Builds the source-owned machine compiler before exposing any flake to Nix.
pub fn development(source: &Path, cache: &Path) -> Result<PathBuf> {
    let (tree, _lease) = development_leased(source, cache)?;
    Ok(tree)
}

/// Prepare development input and acquire its usage lease before pruning can intervene.
/// Keep the returned lease alive until every consuming process has finished.
pub fn development_leased(source: &Path, cache: &Path) -> Result<(PathBuf, cache::Lease)> {
    prepare_leased(source, cache, |tree| {
        applications(&tree.join("crates"))?;
        let applications = source.join("crates");
        compile(
            &tree.join("airlock-machine"),
            &applications,
            &tree.join("airlock-machine"),
        )?;
        fs::write(tree.join("flake.nix"), crate::flake("development")?.source)?;

        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirroring new snapshots preserves compiler input timestamps and tracks changed or deleted user files.
    #[test]
    fn mirror_preserves_unchanged_inputs_and_replaces_stale_entries() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let source = temporary.path().join("source");
        let destination = temporary.path().join("compiler");
        fs::create_dir_all(source.join("vms"))?;
        fs::write(source.join("main.rs"), "fn main() {}")?;
        fs::write(source.join("vms/home.nix"), "{}")?;
        mirror(&source, &destination)?;
        let modified = fs::metadata(destination.join("main.rs"))?.modified()?;

        fs::write(
            source.join("vms/home.nix"),
            "{ imports = [ ./shared.nix ]; }",
        )?;
        fs::write(source.join("vms/shared.nix"), "{}")?;
        fs::write(destination.join("stale.rs"), "old input")?;
        mirror(&source, &destination)?;
        assert_eq!(
            fs::metadata(destination.join("main.rs"))?.modified()?,
            modified
        );
        assert_eq!(
            fs::read(source.join("vms/home.nix"))?,
            fs::read(destination.join("vms/home.nix"))?
        );
        assert!(destination.join("vms/shared.nix").is_file());
        assert!(!destination.join("stale.rs").exists());

        // A cached directory must not redirect synchronization outside the mirror.
        fs::remove_dir_all(destination.join("vms"))?;
        let external = temporary.path().join("external");
        fs::create_dir(&external)?;
        std::os::unix::fs::symlink(&external, destination.join("vms"))?;
        mirror(&source, &destination)?;
        assert!(destination.join("vms/home.nix").is_file());
        assert!(!external.join("home.nix").exists());
        Ok(())
    }

    /// Real Cargo reuses the compiler across snapshot paths while emission sees fresh Nix files.
    #[test]
    #[ignore = "requires explicitly prepared Cargo"]
    fn external_tool_nix_only_snapshots_reuse_rust_compiler() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let first = temporary.path().join("first");
        let second = temporary.path().join("second");
        let apps = temporary.path().join("apps");
        let target = temporary.path().join("target");
        let vendor = temporary.path().join("vendor");
        fs::create_dir_all(first.join("src"))?;
        fs::create_dir_all(first.join("vms"))?;
        fs::create_dir_all(apps.join("airlock-config/src"))?;
        fs::create_dir(&vendor)?;
        fs::write(
            apps.join("airlock-config/Cargo.toml"),
            r#"
            [package]
            name = "airlock-config"
            version = "0.1.0"
            edition = "2024"
            publish = false
        "#,
        )?;
        fs::write(apps.join("airlock-config/src/lib.rs"), "")?;
        fs::write(
            first.join("Cargo.toml"),
            r#"
            [package]
            name = "compiler-fixture"
            version = "0.1.0"
            edition = "2024"
            publish = false
        "#,
        )?;
        let program = r#"
            /// Export the current snapshot's module, leaving its contents outside compiler inputs.
            fn main() -> std::io::Result<()> {
                let destination = std::env::args_os().nth(2).unwrap();
                std::fs::create_dir_all(&destination)?;

                std::fs::write(
                    std::path::Path::new(&destination).join("result"),
                    std::fs::read("vms/home.nix")?,
                )
            }
        "#;
        fs::write(first.join("src/main.rs"), program)?;
        fs::write(first.join("vms/home.nix"), "first module")?;
        let patch = format!(
            "patch.crates-io.airlock-config.path={path:?}",
            path = apps.join("airlock-config")
        );
        assert!(
            Command::new("cargo")
                .current_dir(&first)
                .args(["--config", &patch, "generate-lockfile", "--offline"])
                .status()?
                .success()
        );
        compile_in(
            &first,
            &apps,
            &temporary.path().join("out-first"),
            &target,
            vendor.to_str().unwrap(),
        )?;
        let executable = target.join("debug/compiler-fixture");
        let modified = fs::metadata(&executable)?.modified()?;
        let bytes = fs::read(&executable)?;

        mirror(&first, &second)?;
        fs::write(second.join("vms/home.nix"), "second module")?;
        compile_in(
            &second,
            &apps,
            &temporary.path().join("out-second"),
            &target,
            vendor.to_str().unwrap(),
        )?;
        assert_eq!(fs::metadata(&executable)?.modified()?, modified);
        assert_eq!(fs::read(&executable)?, bytes);
        assert_eq!(
            fs::read_to_string(temporary.path().join("out-second/result"))?,
            "second module"
        );

        fs::write(
            second.join("src/main.rs"),
            program.replace("\"result\"", "\"changed-result\""),
        )?;
        compile_in(
            &second,
            &apps,
            &temporary.path().join("out-third"),
            &target,
            vendor.to_str().unwrap(),
        )?;
        assert_ne!(fs::read(&executable)?, bytes);
        assert!(temporary.path().join("out-third/changed-result").is_file());
        Ok(())
    }
}
