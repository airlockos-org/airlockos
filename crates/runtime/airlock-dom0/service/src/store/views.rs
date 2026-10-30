//! EROFS indexes describe a logical tar stream backed by immutable pool extents.
//! Device-mapper exposes that stream without copying package bytes into each VM.

use super::{fs::*, records, runtime, segments};
use airlock_deployment_core::retention::runtime::{Context as ReleaseContext, Phase, Presence};
use airlock_nix_core::artifact::cache::layout_hash;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
};

/// One contiguous part of the logical tar stream, bound to admitted object bytes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct MapExtent {
    /// Byte address in the virtual external-data device.
    pub(super) logical_offset: u64,
    /// Segment supplying this range.
    pub(super) segment_id: String,
    /// Pool-owned backing file, checked against the segment identity before use.
    pub(super) segment_blob: PathBuf,
    /// Starting byte address in the physical segment.
    pub(super) segment_offset: u64,
    /// Number of contiguous bytes exposed at the logical address.
    pub(super) length: u64,
    /// Nix basename, or the shared tar terminator marker.
    pub(super) object: String,
    /// Digest of this object's tar fragment.
    pub(super) object_sha256: String,
}

pub(super) fn extents(map: &Value) -> Result<Vec<MapExtent>> {
    ensure!(
        map.get("central_blob").is_none(),
        "unsupported single-blob map"
    );
    Ok(serde_json::from_value(map["extents"].clone())?)
}

pub(super) fn references(map: &Value, source: &str) -> Result<Vec<Value>> {
    extents(map)?.into_iter().map(|item| {
        segments::segment_id(&item.segment_id)?;
        Ok(json!({"segment_id":item.segment_id,"source":source,"entry":item.object,"offset":item.segment_offset,"length":item.length,"logical_offset":item.logical_offset}))
    }).collect()
}

pub(super) fn integrity(store: &Value) -> Result<Value> {
    let metadata = PathBuf::from(text(store, "canonical_metadata_image")?);
    let map: Value = read(&PathBuf::from(text(store, "canonical_blob_map")?))?;
    Ok(json!({"metadata_sha256":hash(&metadata)?,"layout_sha256":layout_hash(&map)?}))
}

/// One index produced during this image command, before VM-specific builder metadata is injected.
#[derive(Clone)]
struct ImageIndex {
    // Immutable metadata image; each consuming closure receives its own copy.
    path: PathBuf,
    // Expected contents, checked again before reusing the saved image.
    sha256: String,
}

thread_local! {
    static IMAGE_INDEXES: std::cell::RefCell<Option<BTreeMap<String, ImageIndex>>> = const { std::cell::RefCell::new(None) };
}

/// Share only indexes created inside one reproducible preparation command, never a previous invocation.
pub(super) fn with_image_indexes<T>(operation: impl FnOnce() -> Result<T>) -> Result<T> {
    struct Reset(
        // Restore a surrounding context on normal return, failure or unwinding.
        Option<BTreeMap<String, ImageIndex>>,
    );

    impl Drop for Reset {
        fn drop(&mut self) {
            IMAGE_INDEXES.set(self.0.take());
        }
    }

    let _reset = Reset(IMAGE_INDEXES.replace(Some(BTreeMap::new())));
    operation()
}

/// Reuse exact logical contents only after checking that the source index has not changed.
fn reuse_image_index(key: &str, destination: &Path) -> Result<bool> {
    let cached = IMAGE_INDEXES
        .with_borrow(|scope| scope.as_ref().and_then(|indexes| indexes.get(key)).cloned());
    let Some(cached) = cached else {
        return Ok(false);
    };
    ensure!(
        hash(&cached.path)? == cached.sha256,
        "shared image index checksum mismatch"
    );
    fs::copy(&cached.path, destination)?;
    ensure!(
        hash(destination)? == cached.sha256,
        "shared image index changed during reuse"
    );
    Ok(true)
}

/// Remember a completed common index; the logical-layout key also determines its reproducible UUID.
fn remember_image_index(key: String, path: &Path) -> Result<()> {
    let index = ImageIndex {
        path: path.to_owned(),
        sha256: hash(path)?,
    };
    IMAGE_INDEXES.with_borrow_mut(|scope| {
        if let Some(indexes) = scope {
            indexes.insert(key, index);
        }
    });
    Ok(())
}

/// Check a committed view's content binding and current backing without reopening
/// package admission records or build-only file indexes. Admission and relocation
/// validate those records before publishing the checksums recorded by the generation.
fn checked_map(root: &Path, store: &Value) -> Result<Value> {
    for key in ["canonical_metadata_image", "canonical_blob_map"] {
        pool_path(root, Path::new(&text(store, key)?))?;
    }
    let map: Value = read(Path::new(&text(store, "canonical_blob_map")?))?;
    ensure!(
        json!({"metadata_sha256":hash(Path::new(&text(store, "canonical_metadata_image")?))?,"layout_sha256":layout_hash(&map)?})
            == store["integrity"],
        "retained view checksum mismatch"
    );
    let mut backing = BTreeMap::new();
    let mut logical = 0;
    for item in extents(&map)? {
        let (path, size) = match backing.entry(item.segment_id.clone()) {
            std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::btree_map::Entry::Vacant(entry) => {
                let path = segments::blob(root, &item.segment_id)?;
                let metadata = fs::metadata(&path)?;
                ensure!(metadata.is_file(), "retained backing is not a regular file");
                entry.insert((path, metadata.len()))
            }
        };
        ensure!(
            *path == item.segment_blob,
            "retained backing identity mismatch"
        );
        ensure!(
            item.logical_offset == logical
                && item.length > 0
                && item
                    .segment_offset
                    .checked_add(item.length)
                    .is_some_and(|end| end <= *size),
            "retained backing is truncated or non-contiguous"
        );
        logical = logical
            .checked_add(item.length)
            .context("logical extent overflow")?;
    }
    ensure!(
        logical == number(&map, "logical_size")?,
        "view logical length mismatch"
    );
    Ok(map)
}

/// Bind placement independently of the physical pool mountpoint. Unlike the
/// logical layout hash, this includes segment identities and physical offsets.
fn placement_hash(map: &Value) -> Result<String> {
    use sha2::{Digest, Sha256};

    let rows: Vec<_> = extents(map)?
        .into_iter()
        .map(|item| {
            json!([
                item.object,
                item.object_sha256,
                item.logical_offset,
                item.length,
                item.segment_id,
                item.segment_offset
            ])
        })
        .collect();
    Ok(hex(&Sha256::digest(serde_json::to_vec(&rows)?)))
}

/// Root-owned admission evidence travels with its canonical view and is reclaimed with it.
pub(super) fn admission_path(map: &Path) -> PathBuf {
    map.with_extension("admission.json")
}

/// Publish only after object admission or checked relocation has validated every row.
/// Atomic publication fails closed after interruption: a changed map cannot use an old receipt.
pub(super) fn certify_map(path: &Path, map: &Value) -> Result<()> {
    let receipt = json!({
        "schema":"airlock.closure-store.view-admission.v1",
        "layout_sha256":layout_hash(map)?,
        "placement_sha256":placement_hash(map)?,
    });
    let path = admission_path(path);
    // Recovery and no-op maintenance preserve already published evidence.
    if !path.is_symlink()
        && path.try_exists()?
        && read::<Value>(&path).is_ok_and(|old| old == receipt)
    {
        return Ok(());
    }
    write(&path, &receipt, 0o444)
}

/// Reuse admission evidence while checking the selected generation and actual backing.
/// No package records, package payloads or build indexes are opened at VM startup.
pub(super) fn attachment_map(root: &Path, store: &Value) -> Result<Value> {
    let map = checked_map(root, store)?;
    let path = admission_path(Path::new(&text(store, "canonical_blob_map")?));
    pool_path(root, &path)?;
    let admitted: Value = read(&path)?;
    ensure!(
        admitted["schema"] == "airlock.closure-store.view-admission.v1"
            && admitted["layout_sha256"] == store["integrity"]["layout_sha256"]
            && admitted["placement_sha256"] == placement_hash(&map)?,
        "view admission does not match retained placement"
    );
    Ok(map)
}

/// Authenticate a newly assembled view against already admitted object identities.
/// Unchanged package payloads are reused; only their small extent records are read.
pub(super) fn verify(root: &Path, store: &Value) -> Result<()> {
    let map = checked_map(root, store)?;
    for item in extents(&map)? {
        let meta: Value = read(&segments::object_metadata(root, &item.object)?)?;
        ensure!(
            std::iter::once(&meta)
                .chain(meta["locations"].as_array().into_iter().flatten())
                .any(|location| location["segment_id"] == item.segment_id
                    && location["segment_offset"] == item.segment_offset
                    && location["size"] == item.length
                    && location["sha256"] == item.object_sha256),
            "view extent differs from admitted object"
        );
    }
    Ok(())
}

pub(super) fn reconstruct(root: &Path, map: &Value, target: &Path) -> Result<()> {
    let mut output = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(target)?;
    for item in extents(map)? {
        let path = segments::blob(root, &item.segment_id)?;
        ensure!(path == item.segment_blob, "backing identity mismatch");
        let mut source = File::open(path)?;
        source.seek(SeekFrom::Start(item.segment_offset))?;
        output.seek(SeekFrom::Start(item.logical_offset))?;
        ensure!(
            std::io::copy(&mut source.take(item.length), &mut output)? == item.length,
            "truncated view extent"
        );
    }
    output.set_len(number(map, "logical_size")?)?;
    output.sync_all()?;
    Ok(())
}

pub(super) fn dm_name(domain: &str, generation: u64, closure: &str) -> String {
    let name: String = domain
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "_.+-".contains(c) {
                c
            } else {
                '-'
            }
        })
        .take(48)
        .collect();
    format!(
        "airlock-{name}-{generation}-{}",
        &closure[..closure.len().min(16)]
    )
}

fn dm_presence(name: &str) -> Result<Presence> {
    let presence = runtime::observe(name).presence();
    ensure!(
        presence != Presence::Unknown,
        "unknown mapper presence: {name}"
    );
    Ok(presence)
}

pub(super) fn detach(name: &str, deferred: bool) -> Result<bool> {
    if dm_presence(name)? == Presence::Absent {
        return Ok(false);
    }
    let mut args = vec!["remove"];
    if deferred {
        args.push("--deferred");
    }
    args.push(name);
    command(&tool("dmsetup", "AIRLOCK_DMSETUP"), &args, None)?;
    Ok(true)
}

pub(super) fn attach_map(root: &Path, name: &str, map: &Value) -> Result<Value> {
    let items = extents(map)?;
    let mut backings = BTreeMap::new();
    for item in &items {
        let path = segments::blob(root, &item.segment_id)?;
        ensure!(path == item.segment_blob, "blob map backing escapes pool");
        backings.insert(item.segment_id.clone(), path);
    }

    let mut devices = BTreeMap::new();
    let mut results = Vec::new();
    let losetup = tool("losetup", "AIRLOCK_LOSETUP");
    for (id, path) in backings {
        pool_path(root, &path)?;
        let path_text = path.to_str().context("invalid backing path")?;
        let existing = command(
            &losetup,
            &["-j", path_text, "--output", "NAME", "--noheadings"],
            None,
        )?;
        let device = if let Some(device) = existing
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
        {
            command(&losetup, &["-c", device], None)?;
            device.to_owned()
        } else {
            command(
                &losetup,
                &["--find", "--show", "--read-only", path_text],
                None,
            )?
            .trim()
            .to_owned()
        };
        ensure!(device.starts_with("/dev/loop"), "invalid loop device");
        results.push(json!({"id":id,"blob":path,"loop":device}));
        devices.insert(id, device);
    }

    let mut table = String::new();
    let mut logical = 0;
    for item in &items {
        ensure!(
            item.logical_offset == logical
                && item.length > 0
                && [item.logical_offset, item.length, item.segment_offset]
                    .iter()
                    .all(|n| n % 512 == 0),
            "invalid device mapper extent"
        );
        table.push_str(&format!(
            "{} {} linear {} {}\n",
            logical / 512,
            item.length / 512,
            devices.get(&item.segment_id).context("missing device")?,
            item.segment_offset / 512
        ));
        logical = logical
            .checked_add(item.length)
            .context("logical size overflow")?;
    }
    ensure!(
        logical == number(map, "logical_size")?,
        "blob map size mismatch"
    );

    let dmsetup = tool("dmsetup", "AIRLOCK_DMSETUP");
    if dm_presence(name)? == Presence::Absent {
        atomic(
            &root.join("runtime").join(format!("{name}.table")),
            table.as_bytes(),
            0o400,
        )?;
        failpoint("mapper-before-create")?;
        command(&dmsetup, &["-r", "create", name], Some(table.as_bytes()))?;
        failpoint("mapper-after-create")?;
    }

    command(&dmsetup, &["mknodes", name], None)?;
    Ok(json!({
        "segments": results,
        "loops": results.iter().map(|v|v["loop"].clone()).collect::<Vec<_>>(),
        "backing_paths": results.iter().map(|v|v["blob"].clone()).collect::<Vec<_>>(),
        "dm_name": name,
        "device": format!("/dev/mapper/{name}"),
    }))
}

fn runtime_reference(
    root: &Path,
    name: &str,
    domain: &str,
    generation: u64,
    path: &str,
    map: &Value,
    status: Phase,
) -> Result<()> {
    write(
        &root
            .join("runtime")
            .join(format!("{}.json", component(name)?)),
        &json!({
            "schema": "airlock.closure-store.runtime-view-ref.v1",
            "status": status.status(),
            "domain": domain,
            "generation": generation,
            "dm_name": name,
            "device": format!("/dev/mapper/{name}"),
            "blob_map": path,
            "closure_hash": map["closure_hash"],
            "segments": map["segments"],
            "physical_references": references(map, &format!("runtime:{name}"))?,
            "updated_at": now(),
        }),
        0o644,
    )
}

pub(super) fn attach(root: &Path, domain: &str, generation: u64, attaching: bool) -> Result<Value> {
    let manifest = records::generation(root, domain, generation)?;
    let store = &manifest["store"];
    let path = text(store, "canonical_blob_map")?;
    let map: Value = if attaching {
        attachment_map(root, store)?
    } else {
        read(Path::new(&path))?
    };
    let name = dm_name(domain, generation, &text(store, "closure_hash")?);
    let reference = root.join("runtime").join(format!("{name}.json"));
    let mut result = json!({
        "schema": if attaching { "airlock.closure-store.attach.v1" } else { "airlock.closure-store.detach.v1" },
        "status": "passed",
        "pool_root": root,
        "domain": domain,
        "generation": generation,
        "dm_name": name,
        "device": format!("/dev/mapper/{name}"),
    });
    if attaching {
        runtime_reference(
            root,
            &name,
            domain,
            generation,
            &path,
            &map,
            Phase::Preparing,
        )?;
        let view = attach_map(root, &name, &map)?;
        runtime_reference(root, &name, domain, generation, &path, &map, Phase::Active)?;
        for key in ["segments", "loops", "backing_paths"] {
            result[key] = view[key].clone();
        }
        result["blob_map"] = json!(path);
        result["read_only"] = json!(true);
        result["view_backend"] = json!("erofs-objectmap");
    } else {
        let removed = detach(&name, true)?;
        let observation = runtime::observe(&name);
        ensure!(
            observation.presence() != Presence::Unknown,
            "unknown mapper removal outcome: {name}"
        );
        let request = observation.release(
            root.to_str().context("non-UTF-8 pool path")?.to_owned(),
            Phase::Retiring,
            ReleaseContext::Reconciliation,
        );
        let reference_removed = request.is_some() && reference.try_exists()?;
        if let Some(request) = request {
            runtime::release(request)?;
        } else {
            runtime_reference(
                root,
                &name,
                domain,
                generation,
                &path,
                &map,
                Phase::Retiring,
            )?;
        }
        result["removed"] = json!(removed);
        result["runtime_ref_removed"] = json!(reference_removed);
    }
    Ok(result)
}

/// A frozen closure and optional predecessor used to assemble one exact EROFS view.
pub(super) struct ViewRequest<'a> {
    /// Pool containing the canonical immutable fragments.
    pub(super) root: &'a Path,
    /// New generation directory receiving links to the canonical view.
    pub(super) generation_dir: &'a Path,
    /// Sorted complete set of logical Nix store roots.
    pub(super) paths: &'a [String],
    /// Digest binding system, root, kernel and store roots.
    pub(super) closure: &'a str,
    /// Admission transaction that owns newly appended bytes.
    pub(super) transaction: &'a str,
    /// Rollover limit for ordinary object segments.
    pub(super) target: u64,
    /// Previously admitted objects whose payload bytes need not be reread.
    pub(super) trusted: &'a BTreeSet<String>,
    /// Prior view to authenticate before replacing it; cached file metadata is independent of membership.
    pub(super) previous: Option<&'a Value>,
}

// A temporary kernel mapping also needs a durable pin: process termination can
// leave the mapping alive after the admission lock has been released.
struct IndexMapping<'a> {
    // Pool retaining all extents until the mapper has disappeared.
    root: &'a Path,
    // Unique build mapper identity shared with its runtime reference.
    name: &'a str,
    // Failed cleanup must leave the durable reference available for recovery.
    active: bool,
}

impl<'a> IndexMapping<'a> {
    fn new(root: &'a Path, name: &'a str, map_path: &Path, map: &Value) -> Result<Self> {
        runtime_reference(
            root,
            name,
            "index-build",
            0,
            map_path.to_str().context("invalid index map path")?,
            map,
            Phase::Preparing,
        )?;
        Ok(Self {
            root,
            name,
            active: true,
        })
    }

    fn release(&mut self) -> Result<()> {
        if self.active {
            detach(self.name, false)?;
            let request = runtime::observe(self.name)
                .release(
                    self.root
                        .to_str()
                        .context("non-UTF-8 pool path")?
                        .to_owned(),
                    Phase::Retiring,
                    ReleaseContext::Reconciliation,
                )
                .context("mapper disappearance is not confirmed")?;
            runtime::release(request)?;
            remove(
                &self
                    .root
                    .join("runtime")
                    .join(format!("{}.table", self.name)),
            )?;
            self.active = false;
        }
        Ok(())
    }
}

impl Drop for IndexMapping<'_> {
    fn drop(&mut self) {
        if let Err(error) = self.release() {
            eprintln!("index mapper cleanup failed; keeping physical pin: {error:#}");
        }
    }
}

pub(super) fn materialize(request: ViewRequest<'_>) -> Result<Value> {
    let ViewRequest {
        root,
        generation_dir,
        paths,
        closure,
        transaction,
        target,
        trusted,
        previous,
    } = request;
    let directory = root.join("views/by-closure").join(component(closure)?);
    mkdir_all(&directory)?;
    let metadata = directory.join("store.erofs");
    let blob_path = directory.join("store.blob-map.json");
    let object_refs = directory.join("object-refs");
    let view_manifest = directory.join("manifest.json");

    let mut created = false;
    let mut preparation =
        json!({"index_reused_objects":0,"index_new_objects":0,"index_build_seconds":0.0});
    if !metadata.is_file()
        || !blob_path.is_file()
        || !object_refs.is_file()
        || !view_manifest.is_file()
    {
        let depth = 0;
        if let Some(previous) = previous.filter(|_| !image_build()) {
            attachment_map(root, previous)?;
        }
        let order: Vec<_> = paths
            .iter()
            .map(|path| entry(path).map(str::to_owned))
            .collect::<Result<_>>()?;
        let mut reused = 0;
        let mut items = Vec::new();
        let mut segments = BTreeMap::new();
        let mut logical = 0u64;
        super::progress::detail("Assembling object map");
        for name in order
            .iter()
            .map(String::as_str)
            .chain(std::iter::once(".tar-eof"))
        {
            let value: Value = if name == ".tar-eof" {
                segments::eof(root, transaction, target)?
            } else {
                read(&segments::object_metadata(root, name)?)?
            };
            let extent = segments::extent(
                root,
                &value,
                !trusted.contains(&format!("/nix/store/{name}")),
            )?;
            ensure!(
                extent.size % 512 == 0 && extent.segment_offset % 512 == 0,
                "object extent not tar aligned"
            );
            let segment_meta: Value = read(&segments::metadata(root, &extent.segment_id)?)?;
            segments.insert(extent.segment_id.clone(), json!({"id":extent.segment_id,"blob":extent.segment_blob,"size":fs::metadata(&extent.segment_blob)?.len(),"status":segment_meta["status"]}));
            items.push(MapExtent {
                logical_offset: logical,
                segment_id: extent.segment_id,
                segment_blob: extent.segment_blob,
                segment_offset: extent.segment_offset,
                length: extent.size,
                object: name.to_owned(),
                object_sha256: extent.sha256,
            });
            logical = logical
                .checked_add(extent.size)
                .context("logical size overflow")?;
        }

        let map = json!({
            "schema": "airlock.closure-store.blob-map.v1",
            "closure_hash": closure,
            "filesystem": "erofs",
            "view_backend": "erofs-objectmap",
            "external_data_format": "posix-tar-index",
            "metadata_image": metadata,
            "segments": segments.values().collect::<Vec<_>>(),
            "segment_count": segments.len(),
            "logical_size": logical,
            "object_count": order.len(),
            "object_data_bytes": logical - 1024,
            "objects": order,
            "extents": items,
        });
        let source_map = map.clone();

        let temporary_metadata = tempfile::NamedTempFile::new_in(&directory)?;
        let started = std::time::Instant::now();
        // A VM's system/generation identify its manifest, but do not alter these EROFS bytes.
        let image_key = image_build().then(|| layout_hash(&map)).transpose()?;
        let shared = match &image_key {
            Some(key) => {
                super::image_cache::index(key, temporary_metadata.path())?
                    || reuse_image_index(key, temporary_metadata.path())?
            }
            None => false,
        };
        if shared {
            super::progress::detail("Reusing verified shared EROFS index");
        } else if !image_build() {
            // Reassemble only file metadata. The external data map contains
            // exactly this closure, including after replacements and removals.
            // Cached headers avoid rereading unchanged package fragments and
            // building temporary loop/device-mapper devices for index input.
            let mut source = tempfile::NamedTempFile::new_in(root.join("tmp"))?;
            {
                let mut archive = tar::Builder::new(std::io::BufWriter::new(source.as_file_mut()));
                for item in &items {
                    if item.object == ".tar-eof" {
                        continue;
                    }
                    let value: Value = read(&segments::object_metadata(root, &item.object)?)?;
                    reused += usize::from(value.get("index_sha256").is_some());
                    let entries = segments::index(root, &item.object, &value)?;
                    airlock_nix_core::artifact::fragment::append_index(
                        &mut archive,
                        &entries,
                        &item.object,
                        item.logical_offset,
                        item.length,
                    )?;
                }
                archive.into_inner()?.flush()?;
            }
            command(
                &tool("mkfs.erofs", "AIRLOCK_MKFS_EROFS"),
                &[
                    "--quiet",
                    "--tar=ddtaridx",
                    temporary_metadata
                        .path()
                        .to_str()
                        .context("invalid metadata path")?,
                    source
                        .path()
                        .to_str()
                        .context("invalid index source path")?,
                ],
                None,
            )?;
        } else {
            let mut temporary = tempfile::NamedTempFile::new_in(root.join("tmp"))?;
            let source_mode = std::env::var("AIRLOCK_CLOSURE_STORE_INDEX_SOURCE")
                .unwrap_or_else(|_| "auto".to_owned());
            ensure!(
                ["auto", "file", "dm"].contains(&source_mode.as_str()),
                "invalid index source mode"
            );

            let name = format!(
                "airlock-build-{closure}-{transaction}",
                closure = &closure[..16],
                transaction = &transaction[..8]
            );
            let use_dm = source_mode == "dm"
                || (source_mode == "auto" && rustix::process::geteuid().is_root());
            let mut mapping = if use_dm {
                Some(IndexMapping::new(root, &name, &blob_path, &source_map)?)
            } else {
                None
            };
            let dm_view = if use_dm {
                match attach_map(root, &name, &source_map) {
                    Ok(value) => Some(value),
                    Err(error) if source_mode == "dm" => return Err(error),
                    Err(error) => {
                        mapping
                            .as_mut()
                            .context("missing index pin")?
                            .release()
                            .with_context(|| format!("index mapper setup failed: {error:#}"))?;
                        None
                    }
                }
            } else {
                None
            };
            if dm_view.is_none() {
                reconstruct(root, &source_map, temporary.path())?;
                temporary.flush()?;
            }

            let source = dm_view
                .as_ref()
                .and_then(|v| v["device"].as_str())
                .map(str::to_owned)
                .unwrap_or_else(|| temporary.path().to_string_lossy().into_owned());
            let mut args = vec!["--quiet".to_owned(), "--tar=i".to_owned()];
            if let Some(key) = &image_key {
                args.extend([
                    "-T".into(),
                    "1".into(),
                    "-U".into(),
                    format!(
                        "{first}-{second}-{third}-{fourth}-{fifth}",
                        first = &key[..8],
                        second = &key[8..12],
                        third = &key[12..16],
                        fourth = &key[16..20],
                        fifth = &key[20..32]
                    ),
                ]);
            }
            args.extend([
                temporary_metadata.path().to_string_lossy().into_owned(),
                source,
            ]);

            super::progress::detail("Building EROFS metadata index");
            let result = command(
                &tool("mkfs.erofs", "AIRLOCK_MKFS_EROFS"),
                &args.iter().map(String::as_str).collect::<Vec<_>>(),
                None,
            );
            let cleanup = mapping.as_mut().map(IndexMapping::release).transpose();
            result?;
            cleanup?;
        }

        let reused = if shared { paths.len() } else { reused };

        preparation = json!({"index_reused_objects":reused,"index_new_objects":paths.len() - reused,"index_build_seconds":started.elapsed().as_secs_f64()});
        failpoint("view-after-metadata-build")?;
        temporary_metadata.as_file().sync_all()?;
        fs::set_permissions(temporary_metadata.path(), fs::Permissions::from_mode(0o444))?;
        temporary_metadata
            .persist(&metadata)
            .map_err(|error| error.error)?;
        write(&blob_path, &map, 0o444)?;
        atomic(
            &object_refs,
            format!("{}\n", order.join("\n")).as_bytes(),
            0o444,
        )?;
        failpoint("view-after-metadata-publish")?;
        write(
            &view_manifest,
            &json!({
                "schema": "airlock.closure-store.view-erofs-objectmap.v1",
                "closure_hash": closure,
                "filesystem": "erofs",
                "view_backend": "erofs-objectmap",
                "external_data_format": "posix-tar-index",
                "metadata_image": metadata,
                "blob_map": blob_path,
                "object_refs": object_refs,
                "object_count": order.len(),
                "object_data_bytes": logical - 1024,
                "read_only": true,
                "image_contains_materialized_store_copy": false,
                "index_depth": depth,
            }),
            0o644,
        )?;
        sync_dir(&directory)?;
        if let Some(key) = image_key {
            remember_image_index(key, &metadata)?;
        }
        created = true;
    }

    let map: Value = read(&blob_path)?;
    let view: Value = read(&view_manifest)?;
    mkdir_all(generation_dir)?;
    for (name, source) in [
        ("store.erofs", &metadata),
        ("store.blob-map.json", &blob_path),
        ("object-refs", &object_refs),
    ] {
        let target = generation_dir.join(name);
        remove(&target)?;
        symlink(relative_path(source, generation_dir)?, target)?;
    }
    sync_dir(generation_dir)?;
    let mut output = json!({
        "view_backend": "erofs-objectmap",
        "filesystem": "erofs",
        "view_dir": directory,
        "image": generation_dir.join("store.erofs"),
        "canonical_image": metadata,
        "metadata_image": generation_dir.join("store.erofs"),
        "canonical_metadata_image": metadata,
        "blob_map": generation_dir.join("store.blob-map.json"),
        "canonical_blob_map": blob_path,
        "object_refs": generation_dir.join("object-refs"),
        "canonical_object_refs": object_refs,
        "blob_device": "/dev/xvdf",
        "blob_volume": "store-data",
        "blob_logical_size": map["logical_size"],
        "object_data_bytes": map["object_data_bytes"],
        "object_extent_count": extents(&map)?.len(),
        "segment_count": map["segment_count"],
        "segments": map["segments"],
        "image_created": created,
        "image_contains_materialized_store_copy": false,
        "index_depth": number(&view,"index_depth")?,
        "preparation": preparation,
    });
    output["integrity"] = integrity(&output)?;
    verify(root, &output)?;
    certify_map(&blob_path, &map)?;
    Ok(output)
}

#[cfg(test)]
mod image_index_tests {
    use super::*;

    /// Build one admitted immutable view without kernel devices or external tools.
    fn admitted_view(root: &Path) -> Result<(Value, Value)> {
        ensure_pool(root)?;
        let backing = segments::blob(root, "000001")?;
        fs::write(&backing, vec![0u8; 1024])?;
        let directory = root.join("views/by-closure/example");
        fs::create_dir_all(&directory)?;
        let metadata = directory.join("store.erofs");
        fs::write(&metadata, "immutable filesystem metadata")?;
        let path = directory.join("store.blob-map.json");
        let map = json!({"logical_size":512,"extents":[{
            "logical_offset":0,"segment_id":"000001","segment_blob":backing,
            "segment_offset":0,"length":512,"object":"package","object_sha256":"a".repeat(64)
        }]});
        write(&path, &map, 0o644)?;
        write(
            &segments::object_metadata(root, "package")?,
            &json!({
                "segment_id":"000001","segment_offset":0,"size":512,"sha256":"a".repeat(64)
            }),
            0o644,
        )?;
        let mut store = json!({"canonical_metadata_image":metadata,"canonical_blob_map":path});
        store["integrity"] = integrity(&store)?;
        verify(root, &store)?;
        certify_map(&path, &map)?;
        Ok((store, map))
    }

    /// Boot reuses admission without opening package records, but rejects changed
    /// placement, missing/truncated backing, redirected paths and damaged metadata.
    #[test]
    fn retained_attachment_reuses_admission_and_checks_current_storage() -> Result<()> {
        let fixture = tempfile::tempdir()?;
        let root = fixture.path();
        let (store, map) = admitted_view(root)?;
        let path = PathBuf::from(text(&store, "canonical_blob_map")?);
        fs::write(
            segments::object_metadata(root, "package")?,
            "not parsed at startup",
        )?;
        assert!(verify(root, &store).is_err());
        assert_eq!(attachment_map(root, &store)?, map);

        let mut changed = map.clone();
        changed["extents"][0]["segment_offset"] = json!(512);
        write(&path, &changed, 0o644)?;
        assert!(attachment_map(root, &store).is_err());
        write(&path, &map, 0o644)?;
        assert!(attachment_map(root, &store).is_ok());

        let blob = segments::blob(root, "000001")?;
        fs::write(&blob, vec![0u8; 256])?;
        assert!(attachment_map(root, &store).is_err());
        fs::remove_file(&blob)?;
        assert!(attachment_map(root, &store).is_err());
        let outside = fixture.path().join("outside");
        fs::write(&outside, vec![0u8; 1024])?;
        symlink(&outside, &blob)?;
        assert!(attachment_map(root, &store).is_err());
        fs::remove_file(&blob)?;
        fs::write(&blob, vec![0u8; 1024])?;
        fs::write(text(&store, "canonical_metadata_image")?, "damaged")?;
        assert!(attachment_map(root, &store).is_err());
        Ok(())
    }

    /// A map changed by maintenance cannot use stale evidence. Only a checked
    /// replacement publication restores startup, independently of the pool mountpoint.
    #[test]
    fn admission_binds_placement_and_survives_pool_relocation() -> Result<()> {
        let fixture = tempfile::tempdir()?;
        let root = fixture.path().join("pool");
        let (store, mut map) = admitted_view(&root)?;
        let path = PathBuf::from(text(&store, "canonical_blob_map")?);
        fs::remove_file(admission_path(&path))?;
        assert!(attachment_map(&root, &store).is_err());
        map["extents"][0]["segment_offset"] = json!(512);
        write(&path, &map, 0o644)?;
        certify_map(&path, &map)?;
        assert!(attachment_map(&root, &store).is_ok());

        let relocated = fixture.path().join("relocated");
        fs::rename(&root, &relocated)?;
        super::super::prepared::relocate_pool(
            &relocated,
            &root.to_string_lossy(),
            &relocated.to_string_lossy(),
        )?;
        let mut store = store;
        super::super::prepared::relocate(
            &mut store,
            &root.to_string_lossy(),
            &relocated.to_string_lossy(),
        );
        assert!(attachment_map(&relocated, &store).is_ok());
        Ok(())
    }

    /// Common indexes remain content-bound, reject corruption and cannot escape their preparation scope.
    #[test]
    fn reuse_requires_the_same_layout_and_unchanged_index() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let original = temporary.path().join("index.erofs");
        let destination = temporary.path().join("copy.erofs");
        fs::write(&original, "verified index")?;
        let map = json!({"logical_size":512,"extents":[{"logical_offset":0,"segment_id":"000001","segment_blob":"/pool/one.blob","segment_offset":0,"length":512,"object":"package","object_sha256":"a".repeat(64)}]});
        let key = layout_hash(&map)?;

        with_image_indexes(|| {
            remember_image_index(key.clone(), &original)?;
            assert!(reuse_image_index(&key, &destination)?);
            assert_eq!(fs::read(&original)?, fs::read(&destination)?);
            let mut changed = map.clone();
            changed["extents"][0]["object_sha256"] = json!("b".repeat(64));
            assert!(!reuse_image_index(&layout_hash(&changed)?, &destination)?);

            fs::write(&original, "damaged index")?;
            assert!(reuse_image_index(&key, &destination).is_err());
            assert_eq!(fs::read(&destination)?, b"verified index");
            Ok(())
        })?;
        assert!(!reuse_image_index(&key, &destination)?);
        Ok(())
    }
}
