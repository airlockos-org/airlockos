//! Frozen builder bases share package payloads while retaining their own Nix metadata.
//! A successor must include its predecessor's registrations until stopped-VM handoff completes.

use super::{fs::*, records, views};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

/// Parsed registration record preserving Nix's exact dump/load representation.
#[derive(Clone)]
pub(super) struct Registration {
    // Exact record text, including informational deriver and hash encoding.
    pub(super) text: String,
    // Canonical hexadecimal NAR hash used to compare registrations.
    digest: String,
    // Uncompressed NAR size supplied to Nix's validity database.
    size: u64,
    // Complete set of referenced store roots, including self references.
    pub(super) references: BTreeSet<String>,
}

pub(super) fn registration(source: &str) -> Result<BTreeMap<String, Registration>> {
    let lines: Vec<_> = source.lines().collect();
    let mut offset = 0;
    let mut output = BTreeMap::new();
    while offset < lines.len() {
        ensure!(lines.len() - offset >= 5, "truncated Nix registration");
        let path = lines[offset];
        entry(path)?;
        let raw_hash = lines[offset + 1];
        let digest = if let Some(encoded) = raw_hash.strip_prefix("sha256:") {
            ensure!(encoded.len() == 52, "invalid Nix hash length");
            let alphabet = b"0123456789abcdfghijklmnpqrsvwxyz";
            let mut bytes = [0u8; 32];
            for character in encoded.bytes() {
                let mut carry = alphabet
                    .iter()
                    .position(|b| *b == character)
                    .context("invalid Nix base32 hash")? as u16;
                for byte in &mut bytes {
                    carry += *byte as u16 * 32;
                    *byte = carry as u8;
                    carry >>= 8;
                }
                ensure!(carry == 0, "Nix hash exceeds SHA256 width");
            }
            hex(&bytes)
        } else {
            ensure!(
                raw_hash.len() == 64
                    && raw_hash
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "invalid registration hash"
            );
            raw_hash.to_owned()
        };
        let size = lines[offset + 2].parse()?;
        let count: usize = lines[offset + 4].parse()?;
        let end = offset
            .checked_add(5)
            .and_then(|n| n.checked_add(count))
            .context("registration count overflow")?;
        ensure!(end <= lines.len(), "truncated registration references");
        let references = lines[offset + 5..end]
            .iter()
            .map(|path| {
                entry(path)?;
                Ok((*path).to_owned())
            })
            .collect::<Result<BTreeSet<_>>>()?;
        let record = Registration {
            text: format!("{}\n", lines[offset..end].join("\n")),
            digest,
            size,
            references,
        };
        ensure!(
            output.insert(path.to_owned(), record).is_none(),
            "duplicate registration path"
        );
        offset = end;
    }
    ensure!(!output.is_empty(), "empty Nix registration");
    ensure!(
        output
            .values()
            .all(|r| r.references.iter().all(|path| output.contains_key(path))),
        "registration is not reference-complete"
    );
    Ok(output)
}

pub(super) fn merge(inputs: &[&str]) -> Result<String> {
    let mut output: BTreeMap<String, Registration> = BTreeMap::new();
    for input in inputs {
        for (path, record) in registration(input)? {
            if let Some(old) = output.get(&path) {
                ensure!(
                    old.digest == record.digest
                        && old.size == record.size
                        && old.references == record.references,
                    "conflicting Nix registration: {path}"
                );
            } else {
                output.insert(path, record);
            }
        }
    }
    Ok(output.values().map(|r| r.text.as_str()).collect())
}

pub(super) fn reference_closure(
    records: &BTreeMap<String, Registration>,
    roots: &BTreeSet<String>,
) -> Result<BTreeSet<String>> {
    let mut needed = BTreeSet::new();
    let mut pending: Vec<_> = roots.iter().cloned().collect();
    while let Some(path) = pending.pop() {
        if needed.insert(path.clone()) {
            pending.extend(
                records
                    .get(&path)
                    .with_context(|| format!("unregistered upper reference: {path}"))?
                    .references
                    .iter()
                    .cloned(),
            );
        }
    }
    Ok(needed)
}

pub(super) fn prepare(
    root: &Path,
    path: &Path,
    registration_source: &Path,
    offline: Option<&Path>,
    predecessor: Option<&Value>,
) -> Result<Value> {
    pool_path(root, path)?;
    let mut manifest: Value = read(path)?;
    let domain = text(&manifest, "domain")?;
    ensure!(
        ["usr-assistant-build-store", "sys-ctrl-build-store"].contains(&domain.as_str()),
        "invalid builder domain"
    );
    let role = domain
        .strip_suffix("-build-store")
        .context("invalid builder role")?;
    let registration_bytes = fs::read(registration_source)?;
    let registration_text = std::str::from_utf8(&registration_bytes)?;
    let registered = registration(registration_text)?;
    let expected: BTreeSet<String> = serde_json::from_value(manifest["store"]["paths"].clone())?;
    ensure!(
        registered.keys().cloned().collect::<BTreeSet<_>>() == expected,
        "builder registration differs from frozen view"
    );
    let offline_bytes = match offline.filter(|path| path.exists()) {
        Some(path) => Some(fs::read(path)?),
        None => None,
    };
    if let Some(bytes) = &offline_bytes {
        let value: Value = serde_json::from_slice(bytes)?;
        ensure!(
            value["schema"] == "airlock.sys-agent-offline-inputs.v1",
            "unsupported offline flake inputs"
        );
        let inputs = value["inputs"]
            .as_object()
            .context("missing offline inputs")?;
        ensure!(!inputs.is_empty(), "empty offline inputs");
        for source in inputs.values() {
            let path = Path::new(source.as_str().context("invalid offline source path")?);
            ensure!(
                path.starts_with("/nix/store")
                    && !path.components().any(|c| matches!(
                        c,
                        std::path::Component::ParentDir | std::path::Component::CurDir
                    )),
                "invalid offline source"
            );
            let name = path
                .strip_prefix("/nix/store")?
                .components()
                .next()
                .context("missing source root")?;
            let logical = format!(
                "/nix/store/{}",
                name.as_os_str().to_str().context("non-UTF8 offline path")?
            );
            ensure!(
                expected.contains(&logical),
                "offline input absent from builder base"
            );
        }
    }
    let mut identity = json!({
        "schema": format!("airlock.{role}-build-store.v1"),
        "domain": domain,
        "generation": manifest["generation"],
        "closure_hash": manifest["store"]["closure_hash"],
        "registration_sha256": hex(&Sha256::digest(&registration_bytes)),
    });
    if let Some(bytes) = &offline_bytes {
        identity["flake_inputs_sha256"] = json!(hex(&Sha256::digest(bytes)));
    }
    if let Some(previous) = predecessor {
        let old = records::generation(root, &domain, number(previous, "generation")?)?;
        ensure!(
            old["builder"] == *previous,
            "builder predecessor differs from committed base"
        );
        let old_path = PathBuf::from(text(previous, "metadata_image")?);
        let old_registration = fs::read_to_string(
            old_path
                .parent()
                .context("missing builder parent")?
                .join("registration"),
        )?;
        ensure!(
            merge(&[&old_registration, registration_text])? == merge(&[registration_text])?,
            "builder successor drops previous registrations"
        );
        let mut history = previous["predecessors"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        history.push(json!({"generation":previous["generation"],"closure_hash":previous["closure_hash"],"registration_sha256":previous["registration_sha256"]}));
        identity["predecessors"] = json!(history);
    }
    let directory = path.parent().context("missing builder directory")?;
    let image = directory.join("builder-store.erofs");
    fs::copy(
        text(&manifest["store"], "canonical_metadata_image")?,
        &image,
    )?;
    fs::set_permissions(&image, fs::Permissions::from_mode(0o644))?;
    let temporary = tempfile::tempdir_in(root.join("tmp"))?;
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o755))?;
    let metadata = temporary.path().join(".airlock-builder");
    mkdir(&metadata)?;
    atomic(&metadata.join("registration"), &registration_bytes, 0o644)?;
    if let Some(bytes) = &offline_bytes {
        atomic(&metadata.join("flake-inputs.json"), bytes, 0o644)?;
    }
    write(&metadata.join("identity.json"), &identity, 0o644)?;
    mkdir(temporary.path().join(".links"))?;
    command(
        &tool("mkfs.erofs", "AIRLOCK_MKFS_EROFS"),
        &[
            "--quiet",
            "--incremental=data",
            "--all-root",
            "-T",
            "1",
            "-U",
            "00000000-0000-0000-0000-000000000001",
            image.to_str().context("invalid image path")?,
            temporary.path().to_str().context("invalid staging path")?,
        ],
        None,
    )?;
    fs::set_permissions(&image, fs::Permissions::from_mode(0o444))?;
    File::open(&image)?.sync_all()?;
    identity["metadata_image"] = json!(image);
    manifest["builder"] = identity.clone();
    atomic(&directory.join("registration"), &registration_bytes, 0o444)?;
    if let Some(bytes) = &offline_bytes {
        atomic(&directory.join("flake-inputs.json"), bytes, 0o444)?;
    }
    write(path, &manifest, 0o644)?;
    records::running(
        root,
        &domain,
        number(&manifest, "generation")?,
        "builder-persistent",
        true,
    )?;
    write(
        &root.join("builders").join(format!("{role}.json")),
        &identity,
        0o644,
    )?;
    Ok(identity)
}

pub(super) fn volume_configs(root: &Path, logical: &Path, pool: &str, role: &str) -> Result<Value> {
    ensure!(
        ["sys-ctrl", "usr-assistant"].contains(&role),
        "invalid builder role"
    );
    let descriptor_path = root.join("builders").join(format!("{role}.json"));
    if !descriptor_path.try_exists()? {
        return Ok(json!({}));
    }
    let descriptor: Value = read(&descriptor_path)?;
    let domain = format!("{role}-build-store");
    ensure!(
        descriptor["schema"] == format!("airlock.{role}-build-store.v1")
            && descriptor["domain"] == domain,
        "invalid builder descriptor"
    );
    let generation = number(&descriptor, "generation")?;
    let manifest = records::generation(root, &domain, generation)?;
    ensure!(
        manifest["builder"] == descriptor,
        "builder descriptor differs from committed generation"
    );
    let pin: Value = read(&records::running_path(
        root,
        &domain,
        generation,
        "builder-persistent",
    )?)?;
    let relocate_path =
        |path: &str| -> Result<PathBuf> { Ok(root.join(Path::new(path).strip_prefix(logical)?)) };
    let map_path = text(&manifest["store"], "canonical_blob_map")?;
    pool_path(root, &relocate_path(&map_path)?)?;
    let map: Value = read(&relocate_path(&map_path)?)?;
    ensure!(
        pin["physical_references"]
            == json!(views::references(
                &map,
                &format!("running:{domain}:{generation}:builder-persistent")
            )?)
            && pin["schema"] == "airlock.closure-store.running-ref.v1"
            && pin["status"] == "running"
            && pin["domain"] == domain
            && pin["generation"] == generation
            && pin["closure_hash"] == manifest["store"]["closure_hash"],
        "builder persistent pin mismatch"
    );
    configs_for_generation(root, logical, pool, &domain, &manifest)
}

/// Describe an authenticated retained builder base, including approved predecessors.
pub(super) fn configs_for_generation(
    root: &Path,
    logical: &Path,
    pool: &str,
    domain: &str,
    manifest: &Value,
) -> Result<Value> {
    let descriptor = &manifest["builder"];
    let generation = number(manifest, "generation")?;
    ensure!(
        generation > 0
            && descriptor["schema"]
                == format!(
                    "airlock.{role}-build-store.v1",
                    role = domain
                        .strip_suffix("-build-store")
                        .context("invalid builder namespace")?
                )
            && descriptor["domain"] == domain
            && descriptor["generation"] == generation
            && descriptor["closure_hash"] == manifest["store"]["closure_hash"],
        "builder manifest identity mismatch"
    );
    let map_path = text(&manifest["store"], "canonical_blob_map")?;
    let relocate_path =
        |path: &str| -> Result<PathBuf> { Ok(root.join(Path::new(path).strip_prefix(logical)?)) };
    pool_path(root, &relocate_path(&map_path)?)?;
    let mut result = json!({});
    for name in ["builder-store", "builder-data"] {
        let mut volume = json!({
            "pool": pool,
            "rw": false,
            "snap_on_start": false,
            "save_on_stop": true,
            "source": null,
            "revisions_to_keep": 0,
            "domain_name": domain,
            "generation": generation.to_string(),
            "closure_hash": manifest["store"]["closure_hash"],
            "manifest_path": records::manifest_path(logical,domain,generation)?,
            "name": name,
            "vid": format!("domains/{domain}/generations/{generation}/{name}"),
        });
        if name == "builder-data" {
            volume["view_kind"] = json!("erofs-blob-map");
            volume["blob_map_path"] = json!(map_path);
            volume["blob_logical_size"] = manifest["store"]["blob_logical_size"].clone();
            volume["size"] = manifest["store"]["blob_logical_size"].clone();
        } else {
            let path = text(descriptor, "metadata_image")?;
            let physical = relocate_path(&path)?;
            pool_path(root, &physical)?;
            ensure!(
                fs::metadata(&physical)?.permissions().mode() & 0o222 == 0,
                "builder metadata is writable"
            );
            volume["view_kind"] = json!("metadata-image");
            volume["view_path"] = json!(path);
            volume["size"] = json!(fs::metadata(physical)?.len());
        }
        result[name] = volume;
    }
    Ok(result)
}

fn predecessors_to_release(
    root: &Path,
    role: &str,
    descriptor: &Value,
) -> Result<Vec<(u64, PathBuf, Value)>> {
    ensure!(
        ["sys-ctrl", "usr-assistant"].contains(&role),
        "invalid builder role"
    );
    let domain = format!("{role}-build-store");
    let current = number(descriptor, "generation")?;
    let mut seen = BTreeSet::new();
    let mut pending = Vec::new();
    let history = descriptor
        .get("predecessors")
        .map(|value| {
            value
                .as_array()
                .context("invalid builder predecessor history")
        })
        .transpose()?;
    for previous in history.into_iter().flatten() {
        let generation = number(previous, "generation")?;
        ensure!(
            generation > 0 && generation < current && seen.insert(generation),
            "invalid builder predecessor history"
        );
        let path = records::manifest_path(root, &domain, generation)?;
        let pin = records::running_path(root, &domain, generation, "builder-persistent")?;
        pool_path(root, &path)?;
        pool_path(root, &pin)?;
        if !path.try_exists()? {
            ensure!(
                !pin.try_exists()?,
                "builder pin has no committed generation"
            );
            continue;
        }
        let manifest = records::generation(root, &domain, generation)?;
        ensure!(
            manifest["store"]["closure_hash"] == previous["closure_hash"]
                && manifest["builder"]["registration_sha256"] == previous["registration_sha256"],
            "builder predecessor identity mismatch"
        );
        if manifest["retention"]["retain"] != false || pin.try_exists()? {
            pending.push((generation, path, manifest));
        }
    }
    Ok(pending)
}

pub(super) fn release_predecessors(root: &Path, role: &str, descriptor: &Value) -> Result<Value> {
    let pending = predecessors_to_release(root, role, descriptor)?;
    ensure!(
        read::<Value>(&root.join("builders").join(format!("{role}.json")))? == *descriptor,
        "builder descriptor changed during attachment"
    );
    // Validate the whole history before releasing anything. A retry only needs
    // to finish entries whose retention flag or persistent pin still remains.
    for (generation, path, mut manifest) in pending {
        manifest["retention"]["retain"] = json!(false);
        write(&path, &manifest, 0o644)?;
        records::running(
            root,
            &format!("{role}-build-store"),
            generation,
            "builder-persistent",
            false,
        )?;
    }
    Ok(json!({"released":true}))
}
