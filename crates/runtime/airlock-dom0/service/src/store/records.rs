//! Committed generations select software views; running references pin physical storage.
//! A transaction must commit before its generation or current pointer becomes usable.

use super::{fs::*, root, views};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
};

pub(super) fn manifest_path(root: &Path, domain: &str, generation: u64) -> Result<PathBuf> {
    ensure!(generation > 0, "generation must be positive");
    Ok(root
        .join("domains")
        .join(component(domain)?)
        .join("generations")
        .join(generation.to_string())
        .join("manifest.json"))
}

pub(super) fn committed(root: &Path, manifest: &Value) -> Result<bool> {
    if manifest["schema"] != GENERATION_SCHEMA || manifest["status"] != "committed" {
        return Ok(false);
    }
    let id = text(manifest, "transaction")?;
    let path = root
        .join("transactions")
        .join(format!("{}.json", component(&id)?));
    pool_path(root, &path)?;
    if !path.try_exists()? {
        return Ok(false);
    }
    let tx: Value = read(&path)?;
    let expected = manifest_path(
        root,
        &text(manifest, "domain")?,
        number(manifest, "generation")?,
    )?;
    ensure!(
        tx["schema"] == "airlock.closure-store.transaction.v1"
            && tx["id"] == id
            && tx["domain"] == manifest["domain"]
            && tx["generation"] == manifest["generation"],
        "generation transaction identity mismatch"
    );
    if tx["status"] != "committed" {
        return Ok(false);
    }
    // Image seeds record installed paths even while validated in a build directory.
    // Their transaction and canonical view must agree on that installed pool.
    let declared = std::path::PathBuf::from(text(&tx, "manifest")?);
    let logical = declared
        .ancestors()
        .nth(5)
        .context("invalid transaction manifest path")?;
    ensure!(
        declared.is_absolute()
            && !declared
                .components()
                .any(|c| c == std::path::Component::ParentDir)
            && declared == logical.join(expected.strip_prefix(root)?)
            && Path::new(&text(&manifest["store"], "canonical_blob_map")?)
                .starts_with(logical.join("views/by-closure")),
        "transaction names another generation manifest"
    );
    Ok(true)
}

pub(super) fn generation(root: &Path, domain: &str, generation: u64) -> Result<Value> {
    let path = manifest_path(root, domain, generation)?;
    pool_path(root, &path)?;
    let manifest: Value = read(&path)?;
    ensure!(
        committed(root, &manifest)?
            && manifest["domain"] == domain
            && manifest["generation"] == generation,
        "generation identity is not committed"
    );
    Ok(manifest)
}

pub(super) fn current(root: &Path, domain: &str) -> Result<Option<u64>> {
    let path = root
        .join("domains")
        .join(component(domain)?)
        .join("current");
    pool_path(root, path.parent().context("missing domain directory")?)?;
    if !path.is_symlink() {
        ensure!(!path.try_exists()?, "current selection is not a symlink");
        return Ok(None);
    }
    let target = fs::read_link(path)?;
    let name = target
        .file_name()
        .and_then(|s| s.to_str())
        .context("invalid current generation link")?;
    let generation: u64 = name.parse()?;
    ensure!(
        generation > 0 && target == Path::new(&format!("generations/{generation}")),
        "invalid current generation link"
    );
    Ok(Some(generation))
}

pub(super) fn next(root: &Path, domain: &str) -> Result<u64> {
    let directory = root.join("domains").join(component(domain)?);
    pool_path(root, &directory)?;
    let mut maximum = 0;
    for subdir in ["generations", "retired-generations"] {
        for path in children(&directory.join(subdir))? {
            let name = if subdir == "generations" {
                path.file_name()
            } else {
                path.file_stem()
            };
            if let Some(number) = name
                .and_then(|s| s.to_str())
                .and_then(|s| s.parse::<u64>().ok())
            {
                maximum = maximum.max(number);
            }
        }
    }
    // A failed admission can lose its directory during recovery. Its durable
    // transaction still reserves the issued identity, including aborted work.
    for path in children(&root.join("transactions"))? {
        if path.extension().is_none_or(|s| s != "json") {
            continue;
        }
        pool_path(root, &path)?;
        let tx: Value = read(&path)?;
        if tx["domain"] == domain {
            maximum = maximum.max(number(&tx, "generation")?);
        }
    }
    maximum.checked_add(1).context("generation ids exhausted")
}

pub(super) fn forget(root: &Path, domain: &str, generation: u64, reason: &str) -> Result<()> {
    let directory = root.join("domains").join(component(domain)?);
    let receipt = directory
        .join("retired-generations")
        .join(format!("{generation}.json"));
    pool_path(root, &receipt)?;
    if !receipt.try_exists()? {
        write(
            &receipt,
            &json!({"schema":"airlock.closure-store.generation-retirement.v1",
            "status":"discarded","domain":domain,"generation":generation,"reason":reason,"discarded_at":now()}),
            0o644,
        )?;
    }

    let path = manifest_path(root, domain, generation)?;
    let parent = path.parent().context("missing generation directory")?;
    pool_path(root, parent)?;
    remove(parent)?;
    sync_dir(parent.parent().context("missing generations directory")?)
}

pub(super) fn select(root: &Path, domain: &str, selected: u64) -> Result<()> {
    generation(root, domain, selected)?;
    let directory = root.join("domains").join(component(domain)?);
    let temporary = directory.join(format!(".current.tmp-{}", transaction("switch")?));
    symlink(format!("generations/{selected}"), &temporary)?;
    failpoint("switch-before-current-replace")?;
    fs::rename(temporary, directory.join("current"))?;
    sync_dir(&directory)?;
    failpoint("switch-after-current-replace")
}

pub(super) fn root_image(root: &Path, manifest: &Value) -> Result<Option<PathBuf>> {
    if manifest["root"]["source"].as_str().unwrap_or("").is_empty()
        && manifest["root"]["artifact"].is_null()
    {
        return Ok(None);
    }
    let descriptor: root::Descriptor =
        serde_json::from_value(manifest["root"]["artifact"].clone())?;
    Ok(Some(
        root::reusable(root, &descriptor)?.context("generation root artifact missing")?,
    ))
}

pub(super) fn running_path(
    root: &Path,
    domain: &str,
    generation: u64,
    volume: &str,
) -> Result<PathBuf> {
    ensure!(generation > 0, "generation must be positive");
    Ok(root
        .join("running")
        .join(component(domain)?)
        .join(generation.to_string())
        .join(format!("{}.json", component(volume)?)))
}

pub(super) fn running(
    root: &Path,
    domain: &str,
    selected: u64,
    volume: &str,
    mark: bool,
) -> Result<Value> {
    let path = running_path(root, domain, selected, volume)?;
    pool_path(root, &path)?;
    let mut result = json!({"schema":"airlock.closure-store.running-ref.v1","status":if mark { "running" } else { "cleared" },"pool_root":root,"domain":domain,"generation":selected,"volume":volume});
    if !mark {
        let removed = path.try_exists()? || path.is_symlink();
        remove(&path)?;
        if removed {
            let parent = path.parent().context("missing reference parent")?;
            let _ = fs::remove_dir(parent);
            let _ = fs::remove_dir(parent.parent().context("missing domain parent")?);
        }
        result["removed"] = json!(removed);
        return Ok(result);
    }
    let manifest = generation(root, domain, selected)?;
    let store = &manifest["store"];
    views::verify(root, store)?;
    let map = text(store, "canonical_blob_map")?;
    let references = views::references(
        &read(Path::new(&map))?,
        &format!("running:{domain}:{selected}:{volume}"),
    )?;
    let manifest_path = manifest_path(root, domain, selected)?;
    write(
        &path,
        &json!({
            "schema": "airlock.closure-store.running-ref.v1",
            "status": "running",
            "domain": domain,
            "generation": selected,
            "volume": volume,
            "manifest": manifest_path,
            "closure_hash": text(store,"closure_hash")?,
            "blob_map": map,
            "physical_references": references,
            "started_at": now(),
        }),
        0o644,
    )?;
    result["manifest"] = json!(manifest_path);
    Ok(result)
}

pub(super) fn manifests(root: &Path) -> Result<Vec<PathBuf>> {
    let mut output = Vec::new();
    for domain in children(&root.join("domains"))? {
        pool_path(root, &domain.join("generations"))?;
        for generation in children(&domain.join("generations"))? {
            let path = generation.join("manifest.json");
            pool_path(root, &path)?;
            if path.try_exists()? {
                output.push(path);
            }
        }
    }
    Ok(output)
}

pub(super) fn running_refs(root: &Path) -> Result<Vec<(PathBuf, Value)>> {
    let mut output = Vec::new();
    for domain in children(&root.join("running"))? {
        pool_path(root, &domain)?;
        for generation in children(&domain)? {
            pool_path(root, &generation)?;
            for path in children(&generation)? {
                if path.extension().is_some_and(|s| s == "json") {
                    pool_path(root, &path)?;
                    let value: Value = read(&path)?;
                    ensure!(
                        value["schema"] == "airlock.closure-store.running-ref.v1"
                            && value["status"] == "running",
                        "invalid running reference"
                    );
                    ensure!(
                        path == running_path(
                            root,
                            &text(&value, "domain")?,
                            number(&value, "generation")?,
                            &text(&value, "volume")?
                        )?,
                        "running reference identity mismatch"
                    );
                    output.push((path, value));
                }
            }
        }
    }
    Ok(output)
}
