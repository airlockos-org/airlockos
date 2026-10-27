//! Prepare reproducible VM boot filesystems and closure manifests inside the image builder.

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};
use std::{
    fs::{self, File, Permissions},
    io::Write,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Parser)]
struct Args {
    /// Explicit build artifact operation; no block-device provisioning is provided here.
    #[command(subcommand)]
    operation: Operation,
}

#[derive(Subcommand)]
enum Operation {
    /// Inspect installed entry points against the exact guest store view without executing them.
    Preflight(crate::preflight::Request),
    /// Build the fixed empty-store boot filesystem and its descriptor.
    Root {
        /// New derivation output holding the filesystem and manifest.
        #[arg(long)]
        out: PathBuf,
        /// Separate metadata output consumed without copying the filesystem.
        #[arg(long)]
        metadata: PathBuf,
        /// Requested logical filesystem capacity in MiB.
        #[arg(long)]
        size_mib: u64,
        /// Statically linked upstream BusyBox.
        #[arg(long)]
        busybox: PathBuf,
        /// Native early boot initializer.
        #[arg(long)]
        init: PathBuf,
        /// Native storage descriptor writer supplied as a build dependency.
        #[arg(long)]
        dom0: PathBuf,
    },
    /// Record an already computed Nix closure without copying its store objects.
    Manifest {
        /// New output directory for the closure inventory and metadata.
        #[arg(long)]
        out: PathBuf,
        /// Input store-path inventory from upstream closureInfo.
        #[arg(long)]
        paths: PathBuf,
        /// Serialized settings with name, device, mountpoint, and root_paths.
        #[arg(long)]
        settings: PathBuf,
        /// Reference native launcher; supplying it enables mandatory boot preflight before publication.
        #[arg(long)]
        launcher: Option<PathBuf>,
        /// ELF metadata inspector selected by the image recipe.
        #[arg(long, default_value = "readelf")]
        readelf: PathBuf,
    },
}

/// Execute one upstream image tool, propagating failure before metadata publication.
fn run(command: &mut Command) -> Result<()> {
    ensure!(
        command.status()?.success(),
        "image preparation helper failed: {program}",
        program = command.get_program().to_string_lossy()
    );
    Ok(())
}

/// Enumerate tree entries without following symlinks; return deterministic relative names.
fn inventory(root: &Path, directory: &Path, entries: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        entries.push(entry.path().strip_prefix(root)?.to_owned());
        if entry.file_type()?.is_dir() {
            inventory(root, &entry.path(), entries)?;
        }
    }
    Ok(())
}

/// Write structured metadata only after every preceding artifact operation succeeded.
fn write_json(path: &Path, value: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    fs::write(path, bytes)?;
    Ok(())
}

pub(crate) fn main() -> Result<()> {
    match Args::parse().operation {
        Operation::Preflight(request) => crate::preflight::run(request),
        Operation::Root {
            out,
            metadata,
            size_mib,
            busybox,
            init,
            dom0,
        } => {
            ensure!(size_mib > 0, "root filesystem capacity must be positive");
            let size = size_mib
                .checked_mul(1024 * 1024)
                .context("root filesystem capacity overflow")?;
            let temporary = tempfile::tempdir_in(std::env::current_dir()?)?;
            let root = temporary.path().join("root");
            for directory in [
                "bin",
                "dev",
                "etc",
                "home",
                "lib/modules",
                "nix/store",
                "nix/var/nix/profiles",
                "proc",
                "run/qubes",
                "rw",
                "sbin",
                "sys",
                "tmp",
                "usr/local",
                "var/log/qubes",
            ] {
                fs::create_dir_all(root.join(directory))?;
            }
            fs::create_dir_all(&out)?;
            symlink("/run", root.join("var/run"))?;
            fs::copy(busybox, root.join("bin/busybox"))?;
            fs::set_permissions(root.join("bin/busybox"), Permissions::from_mode(0o555))?;
            symlink("/bin/busybox", root.join("sbin/modprobe"))?;
            fs::set_permissions(root.join("nix/store"), Permissions::from_mode(0o555))?;
            fs::copy(init, root.join("sbin/init"))?;
            fs::set_permissions(root.join("sbin/init"), Permissions::from_mode(0o555))?;
            fs::write(
                out.join("MANAGED_BY_AIRLOCK"),
                r#"schema=airlock.nix-closure-root.v1
contains_store=false
init=/sbin/init
store_mountpoint=/nix/store
store_device_default=/dev/xvde
store_blob_device_default=/dev/xvdf
store_formats=erofs
"#,
            )?;
            let mut paths = Vec::new();
            inventory(&root, &root, &mut paths)?;
            paths.sort();
            let mut listing = File::create(out.join("root-files.txt"))?;
            for path in &paths {
                writeln!(listing, "./{path}", path = path.display())?;
            }
            // touch -h retains symlink identity; fakeroot retains root ownership in mkfs -d.
            for path in
                std::iter::once(root.clone()).chain(paths.iter().map(|path| root.join(path)))
            {
                run(Command::new("touch")
                    .args(["-h", "-d", "@1", "--"])
                    .arg(path))?;
            }
            let image = out.join("root.img");
            File::create(&image)?.set_len(size)?;
            run(Command::new("fakeroot")
                .args([
                    "mkfs.ext4",
                    "-q",
                    "-F",
                    "-L",
                    "nixroot",
                    "-U",
                    "00000000-0000-4000-8000-000000000001",
                    "-O",
                    "^has_journal",
                    "-E",
                    "hash_seed=00000000-0000-4000-8000-000000000001,lazy_itable_init=0",
                    "-d",
                ])
                .arg(&root)
                .arg(&image)
                .env("E2FSPROGS_FAKE_TIME", "1")
                .env("SOURCE_DATE_EPOCH", "1"))?;
            let times = temporary.path().join("root-times.debugfs");
            let mut script = File::create(&times)?;
            for path in [PathBuf::from("/"), PathBuf::from("/lost+found")]
                .into_iter()
                .chain(paths.iter().map(|path| Path::new("/").join(path)))
            {
                for field in ["atime", "ctime", "mtime", "crtime"] {
                    writeln!(
                        script,
                        "set_inode_field \"{path}\" {field} 1",
                        path = path.display()
                    )?;
                }
            }
            drop(script);
            run(Command::new("debugfs")
                .args(["-w", "-f"])
                .arg(times)
                .arg(&image)
                .env("E2FSPROGS_FAKE_TIME", "1")
                .env("SOURCE_DATE_EPOCH", "1"))?;
            fs::create_dir_all(&metadata)?;
            run(Command::new(dom0)
                .args(["storage", "image", "root-descriptor"])
                .arg(&image)
                .arg("--output")
                .arg(metadata.join("root.json")))?;
            write_json(
                &out.join("manifest.json"),
                &json!({
                    "schema": "airlock.nix-closure-root-image.v1", "image": "root.img", "contains_store": false,
                    "init": "/sbin/init", "store_mountpoint": "/nix/store", "store_device_default": "/dev/xvde",
                    "store_blob_device_default": "/dev/xvdf", "store_formats": ["erofs"],
                }),
            )
        }
        Operation::Manifest {
            out,
            paths,
            settings,
            launcher,
            readelf,
        } => {
            let settings: Value = serde_json::from_slice(&fs::read(settings)?)?;
            fs::create_dir_all(&out)?;
            if let Some(launcher) = launcher {
                ensure!(
                    settings["root_paths"]
                        .as_array()
                        .is_some_and(|roots| !roots.is_empty()),
                    "boot preflight requires at least one system root"
                );
                let mut reports = Vec::new();
                for system in settings["root_paths"]
                    .as_array()
                    .context("closure root paths")?
                {
                    let report = crate::preflight::check(
                        Path::new(system.as_str().context("system path")?),
                        &paths,
                        Path::new("/nix/store"),
                        &launcher,
                        &readelf,
                    )?;
                    reports.push(report);
                }
                write_json(
                    &out.join("boot-preflight.json"),
                    &serde_json::to_value(&reports)?,
                )?;
                for report in reports {
                    report.require_success()?;
                }
            }
            let bytes = fs::read(paths)?;
            let count = bytes.iter().filter(|byte| **byte == b'\n').count();
            fs::write(out.join("store-paths"), bytes)?;
            write_json(
                &out.join("manifest.json"),
                &json!({
                    "schema": "airlock.store-closure-manifest.v1", "name": settings["name"],
                    "root_paths": settings["root_paths"], "store_paths_file": "store-paths", "object_count": count,
                    "mountpoint": settings["mountpoint"], "device": settings["device"], "read_only": true,
                }),
            )
        }
    }
}
