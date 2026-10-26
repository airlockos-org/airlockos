//! Host software views keep independent boot artifacts and generation-specific writable state.
//! Publication retains the view before a boot entry can refer to it; selection never reboots.

use super::{
    HostReceipt, boot_artifacts, builder, database,
    fs::*,
    generations::{self, Admission},
    records, views,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

pub(super) const POOL: &str = "/var/lib/airlock/closure-store";

/// Persistent host-store layout shared with the generated boot configuration.
pub(super) const HOST: &str = airlock_machine_core::host_store::ROOT;

pub(super) const MACHINE: &str = "/var/lib/airlock/machine";

/// Open the same selected overlay configured for the host's Nix daemon.
pub(super) fn overlay_uri() -> String {
    airlock_machine_core::host_store::URI.into()
}

pub(super) fn validate(
    root: &Path,
    logical: &Path,
    system: &str,
    allow_retired: bool,
) -> Result<HostReceipt> {
    let path = root
        .join("host/boots")
        .join(format!("{}.json", entry(system)?));
    pool_path(root, &path)?;
    let receipt: HostReceipt = read(&path)?;
    ensure!(
        receipt.system.as_str() == system && (allow_retired || receipt.retired != Some(true)),
        "host boot record identity mismatch or retired"
    );
    let physical = |path: &Path| -> Result<PathBuf> {
        ensure!(
            !path
                .components()
                .any(|c| c == std::path::Component::ParentDir),
            "host metadata escapes pool"
        );
        Ok(root.join(path.strip_prefix(logical)?))
    };

    let manifest: Value = read(&physical(&receipt.manifest)?)?;
    ensure!(
        records::committed(root, &manifest)?
            && manifest["domain"] == "dom0"
            && manifest["generation"] == receipt.generation.get()
            && manifest["store"]["closure_hash"] == receipt.closure_hash.as_str()
            && manifest["store"]["canonical_metadata_image"]
                == receipt
                    .metadata_image
                    .to_str()
                    .context("non-UTF-8 host metadata path")?
            && manifest["store"]["canonical_blob_map"]
                == receipt
                    .blob_map
                    .to_str()
                    .context("non-UTF-8 host map path")?,
        "host generation differs from boot record"
    );

    let paths: BTreeSet<String> = serde_json::from_value(manifest["store"]["paths"].clone())?;
    ensure!(
        paths.contains(system),
        "host system absent from admitted view"
    );
    for (key, path, expected) in [
        (
            "registration",
            &receipt.registration,
            &receipt.registration_sha256,
        ),
        (
            "metadata_image",
            &receipt.metadata_image,
            &receipt.metadata_image_sha256,
        ),
        ("blob_map", &receipt.blob_map, &receipt.blob_map_sha256),
    ] {
        let path = physical(path)?;
        pool_path(root, &path)?;
        ensure!(
            hash(&path)? == expected.as_str(),
            "host {key} checksum mismatch"
        );
    }

    let registered = builder::registration(&fs::read_to_string(physical(&receipt.registration)?)?)?;
    ensure!(
        registered.keys().cloned().collect::<BTreeSet<_>>() == paths,
        "host registration differs from view"
    );

    let generation = receipt.generation.get();
    let pin: Value = read(&records::running_path(
        root,
        "dom0",
        generation,
        "host-retained",
    )?)?;
    let map: Value = read(&physical(&receipt.blob_map)?)?;
    let refs = views::references(&map, &format!("running:dom0:{generation}:host-retained"))?;
    ensure!(
        pin["schema"] == "airlock.closure-store.running-ref.v1"
            && pin["status"] == "running"
            && pin["domain"] == "dom0"
            && pin["generation"] == generation
            && pin["manifest"]
                == receipt
                    .manifest
                    .to_str()
                    .context("non-UTF-8 host manifest path")?
            && pin["closure_hash"] == receipt.closure_hash.as_str()
            && pin["physical_references"] == json!(refs),
        "host retention pin mismatch"
    );
    Ok(receipt)
}

fn admit(
    root: &Path,
    domain: &str,
    system: &str,
    registration: &str,
    incremental: bool,
    previous: Option<&Value>,
) -> Result<generations::AdmittedGeneration> {
    let registered = builder::registration(registration)?;
    ensure!(
        registered.contains_key(system),
        "system missing from host/builder registration"
    );

    let temporary = tempfile::tempdir_in(root.join("tmp"))?;
    let paths = format!(
        "{}\n",
        registered.keys().cloned().collect::<Vec<_>>().join("\n")
    );
    atomic(
        &temporary.path().join("store-paths"),
        paths.as_bytes(),
        0o644,
    )?;
    write(&temporary.path().join("manifest.json"), &json!({}), 0o644)?;

    let result = generations::admit(&Admission {
        pool: root,
        domain,
        system,
        source: temporary.path(),
        source_identity: &temporary.path().to_string_lossy(),
        root_source: "",
        kernel: "",
        physical: Path::new("/nix/store"),
        segment_target: SEGMENT_TARGET,
        verification: if incremental { "incremental" } else { "tree" },
        approved_by: "dom0",
        approval_source: "host-publication",
        activate: false,
        retain: true,
        previous_index: previous,
        device: "/dev/xvde",
        blob_device: "/dev/xvdf",
        mountpoint: "/nix/store",
    })?;

    let manifest = &result.manifest;
    atomic(
        &manifest
            .parent()
            .context("missing generation parent")?
            .join("registration"),
        registration.as_bytes(),
        0o444,
    )?;
    Ok(result)
}

pub(super) fn publish(
    root: &Path,
    system: &str,
    registration: &str,
    systems: &[String],
    incremental: bool,
) -> Result<HostReceipt> {
    pool_path(root, &root.join("host/boots"))?;
    if root
        .join("host/boots")
        .join(format!("{}.json", entry(system)?))
        .try_exists()?
    {
        return validate(root, root, system, false);
    }

    let running = root.join("host/running.json");
    let previous = if running.try_exists()? {
        let running: Value = read(&running)?;
        let old = validate(root, root, &text(&running, "system")?, false)?;
        Some(read::<Value>(&old.manifest)?["store"].clone())
    } else {
        None
    };

    let result = admit(
        root,
        "dom0",
        system,
        registration,
        incremental,
        previous.as_ref(),
    )?;
    let manifest_path = &result.manifest;
    let manifest: Value = read(manifest_path)?;

    let registered = builder::registration(registration)?;
    ensure!(
        systems.iter().all(|system| registered.contains_key(system)),
        "host boot choice absent from admitted closure"
    );
    let store = &manifest["store"];
    let record = HostReceipt {
        schema: super::host_receipt::Schema::V1,
        system: system.parse()?,
        generation: result.identity.generation,
        manifest: manifest_path.clone(),
        registration: manifest_path
            .parent()
            .context("missing manifest parent")?
            .join("registration"),
        registration_sha256: hex(&Sha256::digest(registration)).parse()?,
        metadata_image: text(store, "canonical_metadata_image")?.into(),
        metadata_image_sha256: hash(Path::new(&text(store, "canonical_metadata_image")?))?
            .parse()?,
        blob_map: text(store, "canonical_blob_map")?.into(),
        blob_map_sha256: hash(Path::new(&text(store, "canonical_blob_map")?))?.parse()?,
        closure_hash: text(store, "closure_hash")?.parse()?,
        retired: None,
        timings: None,
        extensions: BTreeMap::new(),
    };

    records::running(
        root,
        "dom0",
        number(&manifest, "generation")?,
        "host-retained",
        true,
    )?;
    let map: Value = read(&record.blob_map)?;
    let mut durable: BTreeSet<PathBuf> = views::extents(&map)?
        .iter()
        .map(|e| e.segment_blob.clone())
        .collect();
    durable.extend([
        record.registration.clone(),
        record.metadata_image.clone(),
        record.blob_map.clone(),
    ]);
    for path in durable {
        File::open(path)?.sync_all()?;
    }
    failpoint("host-before-boot-record")?;
    for choice in systems
        .iter()
        .map(String::as_str)
        .chain(std::iter::once(system))
    {
        let mut selected = record.clone();
        selected.system = choice.parse()?;
        let path = root
            .join("host/boots")
            .join(format!("{}.json", entry(choice)?));
        pool_path(root, &path)?;
        write(&path, &selected, 0o644)?;
    }
    Ok(record)
}

pub(super) fn refresh_builder(
    root: &Path,
    role: &str,
    host_registration: &str,
    incremental: bool,
    seed_role: Option<&str>,
) -> Result<Value> {
    ensure!(
        ["sys-ctrl", "usr-assistant"].contains(&role),
        "invalid builder role"
    );
    let fresh = !root
        .join("builders")
        .join(format!("{role}.json"))
        .try_exists()?;
    let source = if fresh {
        seed_role.unwrap_or(role)
    } else {
        role
    };
    let previous: Value = read(&root.join("builders").join(format!("{source}.json")))?;
    let old_path = records::manifest_path(
        root,
        &format!("{source}-build-store"),
        number(&previous, "generation")?,
    )?;
    let directory = old_path.parent().context("missing old builder directory")?;
    let registration = builder::merge(&[
        &fs::read_to_string(directory.join("registration"))?,
        host_registration,
    ])?;
    if !fresh && previous["registration_sha256"] == hex(&Sha256::digest(&registration)) {
        return Ok(previous);
    }
    let old: Value = read(&old_path)?;

    let result = admit(
        root,
        &format!("{role}-build-store"),
        &text(&old, "system")?,
        &registration,
        incremental,
        Some(&old["store"]),
    )?;

    let manifest = &result.manifest;
    builder::prepare(
        root,
        &result.manifest,
        &manifest
            .parent()
            .context("missing new builder directory")?
            .join("registration"),
        Some(&directory.join("flake-inputs.json")),
        if fresh { None } else { Some(&previous) },
    )
}

fn publication_registration(system: &str) -> Result<String> {
    let live = command(
        "nix-store",
        &["--store", &overlay_uri(), "--gc", "--print-live"],
        None,
    )?;
    let records = builder::registration(&command(
        "nix-store",
        &["--store", &overlay_uri(), "--dump-db"],
        None,
    )?)?;
    let mut roots: BTreeSet<String> = live.lines().map(str::to_owned).collect();
    roots.insert(system.to_owned());
    for path in children(&Path::new(HOST).join("active/upper"))? {
        let logical = format!(
            "/nix/store/{}",
            path.file_name()
                .context("invalid upper object")?
                .to_string_lossy()
        );
        if records.contains_key(&logical) {
            roots.insert(logical);
        }
    }
    let needed = builder::reference_closure(&records, &roots)?;
    Ok(needed
        .iter()
        .map(|path| records[path].text.as_str())
        .collect())
}

pub(super) fn publish_live(system: &str) -> Result<HostReceipt> {
    let root = Path::new(POOL);
    ensure_pool(root)?;
    let temporary = Path::new(HOST).join("publishing");
    mkdir_all(&temporary)?;

    let temporary = tempfile::tempdir_in(temporary)?;
    command(
        "nix-store",
        &[
            "--add-root",
            &temporary.path().join("root").to_string_lossy(),
            "--realise",
            system,
        ],
        None,
    )?;
    let registration = publication_registration(system)?;
    let _lock = PoolLock::acquire(&root.join("admission.lock"))?;
    let record = publish(root, system, &registration, &[], true)?;
    let directory = Path::new(HOST)
        .join("generations")
        .join(record.generation.to_string());
    if !directory.join("nix/var/nix/db/db.sqlite").try_exists()? {
        database::seed(
            Path::new("/nix/var/nix/db/db.sqlite"),
            &directory.join("seed-metadata.sqlite"),
        )?;
    }
    refresh_builder(root, "sys-ctrl", &registration, true, None)?;
    refresh_builder(root, "usr-assistant", &registration, true, Some("sys-ctrl"))?;
    Ok(record)
}

pub(super) fn select(root: &Path, esp: &Path, system: &str, firmware: bool) -> Result<HostReceipt> {
    let record = validate(root, root, system, false)?;
    let entry = boot_artifacts::verify(root, esp, &record.system, record.generation)?;
    boot_artifacts::select_entry(esp, &entry, firmware)?;
    write(&root.join("host/selected.json"), &record, 0o644)?;
    Ok(record)
}

pub(super) fn retire(root: &Path, esp: &Path, system: &str) -> Result<Value> {
    for name in ["selected", "running"] {
        let path = root.join(format!("host/{name}.json"));
        if path.try_exists()? {
            ensure!(
                read::<Value>(&path)?["system"] != system,
                "cannot retire {name} host"
            );
        }
    }
    let path = root
        .join("host/boots")
        .join(format!("{}.json", entry(system)?));
    if path.try_exists()? {
        let mut record = validate(root, root, system, true)?;
        record.retired = Some(true);
        write(&path, &record, 0o644)?;
    }
    boot_artifacts::forget(root, esp, system)?;
    let mut groups: BTreeMap<u64, Vec<(PathBuf, Value)>> = BTreeMap::new();
    for path in children(&root.join("host/boots"))? {
        let value: Value = read(&path)?;
        groups
            .entry(number(&value, "generation")?)
            .or_default()
            .push((path, value));
    }
    for (generation, records) in groups {
        if !records.iter().all(|(_, v)| v["retired"] == true) {
            continue;
        }
        let refs = root.join("running/dom0").join(generation.to_string());
        if children(&refs)?
            .iter()
            .any(|p| p.file_name().is_none_or(|s| s != "host-retained.json"))
        {
            continue;
        }
        let path = records::manifest_path(root, "dom0", generation)?;
        let mut manifest: Value = read(&path)?;
        manifest["retention"]["retain"] = json!(false);
        write(&path, &manifest, 0o644)?;
        for (path, _) in records {
            remove(&path)?;
        }
        sync_dir(&root.join("host/boots"))?;
        records::running(root, "dom0", generation, "host-retained", false)?;
    }
    Ok(json!({"system":system,"retired":true}))
}

pub(super) fn allocated(path: &Path) -> Result<u64> {
    let mut seen = BTreeSet::new();
    let mut size = 0;
    for path in descendants(path)? {
        let stat = fs::symlink_metadata(path)?;
        if seen.insert((stat.dev(), stat.ino())) {
            size += stat.blocks() * 512;
        }
    }
    Ok(size)
}
