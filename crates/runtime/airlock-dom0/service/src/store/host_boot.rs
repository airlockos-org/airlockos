//! Assemble only the host generation named by the boot entry, before stage two starts.
//! Its writable upper and Nix metadata stay independent of every other retained generation.

use super::{builder, database, fs::*, host, host_machine, prepared, records, views};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    ffi::CString,
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

fn overlay(target: &Path, options: &str, read_only: bool) -> Result<()> {
    let flags = if read_only {
        rustix::mount::MountFlags::RDONLY
    } else {
        rustix::mount::MountFlags::empty()
    };
    let options = CString::new(options)?;
    rustix::mount::mount("overlay", target, "overlay", flags, options.as_c_str())
        .with_context(|| format!("mount overlay at {}", target.display()))?;
    Ok(())
}

pub(super) fn mount_overlay(sysroot: &Path) -> Result<()> {
    let options = format!(
        "index=off,metacopy=off,redirect_dir=nofollow,lowerdir={}/lower/nix/store,upperdir={}/active/upper,workdir={}/active/work",
        host::HOST,
        host::HOST,
        host::HOST
    );
    rustix::process::chroot(sysroot)?;
    std::env::set_current_dir("/")?;
    overlay(Path::new("/nix/store"), &options, false)
}

pub(super) fn boot_system(cmdline: &str) -> Result<String> {
    let init: Vec<_> = cmdline
        .split_whitespace()
        .filter_map(|word| word.strip_prefix("init="))
        .collect();
    ensure!(init.len() == 1, "exactly one NixOS init path required");
    let system = init[0]
        .strip_suffix("/init")
        .context("invalid NixOS init path")?;
    let mut parts = system.split("/specialisation/");
    entry(parts.next().context("missing host store root")?)?;
    if let Some(name) = parts.next() {
        component(name)?;
    }
    ensure!(parts.next().is_none(), "invalid specialisation init path");
    Ok(system.to_owned())
}

pub(super) fn report_failure(sysroot: &Path, error: &anyhow::Error) {
    let report = (|| -> Result<()> {
        let mut value = json!({"error":format!("{error:#}")});
        for name in ["/proc/self/mountinfo", "/proc/filesystems", "/proc/cmdline"] {
            value[name] = json!(fs::read_to_string(name).unwrap_or_else(|error| error.to_string()));
        }
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        component(boot.trim())?;
        write(
            &sysroot
                .join("var/log/airlock-boot")
                .join(format!("{}-host-store-failure.json", boot.trim())),
            &value,
            0o600,
        )
    })();
    if let Err(error) = report {
        eprintln!("could not save host mount failure evidence: {error:#}");
    }
}

fn bind(source: &Path, target: &Path) -> Result<()> {
    command(
        "mount",
        &[
            "--bind",
            &source.to_string_lossy(),
            &target.to_string_lossy(),
        ],
        None,
    )?;
    Ok(())
}

pub(super) fn assemble(sysroot: &Path, cmdline: &str) -> Result<Value> {
    let root = sysroot.join(host::POOL.trim_start_matches('/'));
    let storage = sysroot.join(host::HOST.trim_start_matches('/'));
    mkdir_all(&storage)?;
    let physical = |path: &Path| -> Result<PathBuf> {
        ensure!(
            path.is_absolute()
                && !path
                    .components()
                    .any(|c| c == std::path::Component::ParentDir),
            "invalid absolute host path"
        );
        Ok(sysroot.join(path.strip_prefix("/")?))
    };

    let mut system = boot_system(cmdline)?;
    ensure_pool(&root)?;
    let _lock = PoolLock::acquire(&root.join("admission.lock"))?;
    if system.contains("/specialisation/") {
        system = text(&read(&root.join("host/aliases.json"))?, &system)?;
    }

    let record = host::validate(&root, Path::new(host::POOL), &system, false)?;
    let generation = record.generation.get();
    let generation_root = storage.join("generations").join(generation.to_string());
    let upper = generation_root.join("upper");
    mkdir_all(&upper)?;
    mkdir_all(generation_root.join("work"))?;

    let registration = fs::read_to_string(physical(&record.registration)?)?;
    let registered = builder::registration(&registration)?;
    database::recover(&generation_root)?;
    let old = if generation_root
        .join("nix/var/nix/db/db.sqlite")
        .try_exists()?
    {
        builder::registration(&database::dump(&generation_root)?)?
    } else {
        Default::default()
    };
    let saved: BTreeSet<_> = children(&upper)?
        .iter()
        .filter_map(|path| {
            path.file_name()
                .map(|name| format!("/nix/store/{}", name.to_string_lossy()))
        })
        .filter(|path| old.contains_key(path))
        .collect();
    let needed = builder::reference_closure(&old, &saved)?;
    ensure!(
        needed
            .iter()
            .all(|path| saved.contains(path) || registered.contains_key(path)),
        "host upper references objects outside fixed view"
    );
    let upper_registration: String = needed.iter().map(|path| old[path].text.as_str()).collect();
    let merged_registration = if needed.is_empty() {
        registration.clone()
    } else {
        builder::merge(&[&registration, &upper_registration])?
    };

    let mut mounts = Vec::new();
    let result = (|| -> Result<Value> {
        let target = storage.join("bases").join(generation.to_string());
        mkdir_all(&target)?;
        let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
        ensure!(
            !mountinfo
                .lines()
                .any(|line| line.split_whitespace().nth(4) == target.to_str()),
            "host base already mounted"
        );

        let map: Value = read(&physical(&record.blob_map)?)?;
        let mut mapped = map.clone();
        prepared::relocate(&mut mapped, host::POOL, &root.to_string_lossy());
        let device = views::attach_map(&root, &format!("airlock-host-{generation}"), &mapped)?;
        eprintln!("Airlock host store: mounting EROFS base {generation}");
        command(
            "mount",
            &[
                "-t",
                "erofs",
                "-o",
                &format!("ro,loop,device={}", text(&device, "device")?),
                &physical(&record.metadata_image)?.to_string_lossy(),
                &target.to_string_lossy(),
            ],
            None,
        )?;
        mounts.push(target.clone());

        let lower = storage.join("lower");
        let lower_store = lower.join("nix/store");
        mkdir_all(&lower_store)?;
        remove(&lower.join("nix/var/nix/db"))?;
        let scaffold = storage.join("lower-scaffold");
        mkdir_all(scaffold.join(".links"))?;
        overlay(
            &lower_store,
            &format!(
                "index=off,metacopy=off,redirect_dir=nofollow,lowerdir={}:{}",
                target.display(),
                scaffold.display()
            ),
            true,
        )?;
        mounts.push(lower_store);

        command(
            "nix-store",
            &[
                "--store",
                &format!("local?root={}", lower.display()),
                "--load-db",
            ],
            Some(registration.as_bytes()),
        )?;
        let db = lower.join("nix/var/nix/db");
        bind(&db, &db)?;
        mounts.push(db.clone());
        command(
            "mount",
            &["-o", "remount,bind,ro", &db.to_string_lossy()],
            None,
        )?;
        let active = storage.join("active");
        mkdir_all(&active)?;
        bind(&generation_root, &active)?;
        mounts.push(active);
        let trash = generation_root.join("published-copies");
        mkdir_all(&trash)?;
        for path in children(&upper)? {
            let name = path
                .file_name()
                .and_then(|s| s.to_str())
                .context("invalid upper object filename")?;
            if !registered.contains_key(&format!("/nix/store/{name}")) {
                continue;
            }
            let metadata: Value =
                read(&root.join("objects/metadata").join(format!("{name}.json")))?;
            ensure!(
                tree_hash(&path)? == text(&metadata, "tree_hash")?,
                "upper differs from immutable object: {name}"
            );
            let destination = trash.join(name);
            remove(&destination)?;
            fs::rename(&path, &destination)?;
            sync_dir(&upper)?;
        }
        let pin = records::running_path(&root, "dom0", generation, "host-upper")?;
        write(
            &pin,
            &json!({
                "schema": "airlock.closure-store.running-ref.v1",
                "status": "running",
                "domain": "dom0",
                "generation": generation,
                "manifest": record.manifest,
                "closure_hash": record.closure_hash,
                "volume": "host-upper",
                "physical_references": views::references(&map,"host-upper")?,
            }),
            0o644,
        )?;
        let merged = sysroot.join("nix/store");
        mkdir_all(&merged)?;
        command(
            std::env::current_exe()?
                .to_str()
                .context("invalid service path")?,
            &[
                "storage",
                "host",
                "mount-overlay",
                "--sysroot",
                &sysroot.to_string_lossy(),
            ],
            None,
        )?;
        mounts.push(merged);
        let own = generation_root.join("nix/var/nix/db/db.sqlite");
        let metadata_source = if own.try_exists()? {
            own
        } else {
            generation_root.join("seed-metadata.sqlite")
        };
        database::replace(
            sysroot,
            &merged_registration,
            &generation_root,
            &metadata_source,
        )?;
        let database = sysroot.join("nix/var/nix/db");
        mkdir_all(&database)?;
        bind(&generation_root.join("nix/var/nix/db"), &database)?;
        mounts.push(database);
        write(
            &storage.join("base.json"),
            &json!({"schema":"airlock.host-base.v2","systems":[system],"generation":generation,"closure_hash":record.closure_hash}),
            0o644,
        )?;
        remove(&trash)?;
        let links = upper.join(".links");
        if links.is_dir() && !links.is_symlink() {
            for link in children(&links)? {
                let meta = fs::symlink_metadata(&link)?;
                if meta.is_file() && meta.nlink() == 1 {
                    remove(&link)?;
                }
            }
            sync_dir(&links)?;
        }
        ensure!(
            physical(Path::new(&system))?.join("init").is_file(),
            "selected init missing from assembled view"
        );
        host_machine::restore(sysroot, &record)?;
        write(&root.join("host/running.json"), &record, 0o644)?;
        for directory in children(&root.join("running/dom0"))? {
            let old = directory
                .file_name()
                .and_then(|s| s.to_str())
                .context("invalid host pin generation")?
                .parse::<u64>()?;
            if old != generation && directory.join("host-upper.json").try_exists()? {
                records::running(&root, "dom0", old, "host-upper", false)?;
            }
        }
        Ok(json!({"assembled":system,"generation":generation}))
    })();
    if let Err(error) = &result {
        report_failure(sysroot, error);
        for path in mounts.iter().rev() {
            if let Err(error) = command("umount", &[&path.to_string_lossy()], None) {
                eprintln!("host mount cleanup failed: {error:#}");
            }
        }
    }
    result
}

#[cfg(test)]
mod tests;
