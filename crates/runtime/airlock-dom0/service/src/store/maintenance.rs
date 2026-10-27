//! Storage reclamation traces logical generations and physical pins before deleting bytes.
//! Relocation publishes verified replacement extents before refreshing unpinned views.

use super::{
    fs::*, logical_retirement, physical, records, relocation, runtime, segment_retirement,
    segments, tracing,
};
use airlock_deployment_core::retention::{
    Candidate, Generation, Protection, ReclaimRequest,
    inventory::{self as protection_inventory, PoolSources, ProtectionInventory, StoredGeneration},
    logical::Target,
    physical::PhysicalProtection,
    runtime::Context as ReleaseContext,
    tracing::{Sources, Trace},
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

/// Objects and generations protected by selection, retention, running guests or unfinished work.
struct Liveness {
    // Complete decoded sources; one verified constructor accounts for every source.
    sources: Sources,
    // Verified union of retained manifest references and unfinished object admissions.
    trace: Trace,
    // Committed domain/generation pairs which must survive maintenance.
    generations: BTreeSet<(String, u64)>,
    // Unfinished transactions whose newly appended objects remain protected.
    transactions: BTreeSet<String>,
    // Committed manifests indexed by their domain and generation.
    manifests: BTreeMap<(String, u64), (PathBuf, Value)>,
    // Incomplete generation records retained for recovery rather than activation.
    incomplete: Vec<Value>,
    // Running references lacking a committed generation, reported without discarding pins.
    stale_running: Vec<PathBuf>,
}

/// Extend the logical source collection before rebuilding its checked trace.
fn add_manifest(root: &Path, live: &mut Liveness, manifest: &Value) -> Result<()> {
    live.sources
        .manifests
        .push(tracing::manifest(root, manifest)?);
    Ok(())
}

/// Preserve the complete original logical trace without intermediate lookup-set projections.
fn index_trace(live: &mut Liveness) -> Result<()> {
    live.trace =
        Trace::from_sources(&live.sources).context("invalid retained resource references")?;
    Ok(())
}

fn liveness(root: &Path, keep: usize) -> Result<(Liveness, ProtectionInventory)> {
    let mut live = Liveness {
        sources: Sources {
            manifests: Vec::new(),
            pending_objects: Vec::new(),
        },
        trace: Trace::new(),
        generations: BTreeSet::new(),
        transactions: BTreeSet::new(),
        manifests: BTreeMap::new(),
        incomplete: Vec::new(),
        stale_running: Vec::new(),
    };
    for path in children(&root.join("transactions"))? {
        if path.extension().is_none_or(|s| s != "json") {
            continue;
        }
        let value: Value = read(&path)?;
        if value["status"] != "committed" && value["status"] != "aborted" {
            live.transactions.insert(text(&value, "id")?);
        }
    }

    let mut committed = Vec::new();
    let mut by_domain: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for path in records::manifests(root)? {
        let value: Value = read(&path)?;
        let domain = text(&value, "domain")?;
        component(&domain)?;
        let generation = number(&value, "generation")?;
        ensure!(
            path == records::manifest_path(root, &domain, generation)?,
            "generation record path identity mismatch"
        );
        if records::committed(root, &value)? {
            by_domain
                .entry(domain.clone())
                .or_default()
                .push(generation);
            committed.push(StoredGeneration {
                generation: Generation {
                    domain: domain.clone(),
                    number: generation,
                },
                retained: value["retention"]["retain"]
                    .as_bool()
                    .context("invalid generation retention pin")?,
            });
            ensure!(
                live.manifests
                    .insert((domain, generation), (path, value))
                    .is_none(),
                "duplicate committed generation identity"
            );
        } else if let Some(id) = value["transaction"].as_str() {
            let tx_path = root
                .join("transactions")
                .join(format!("{}.json", component(id)?));
            if tx_path.try_exists()? && read::<Value>(&tx_path)?["status"] != "aborted" {
                live.transactions.insert(id.to_owned());
                add_manifest(root, &mut live, &value)?;
                live.incomplete.push(json!({"domain":domain,"generation":generation,"transaction":id,"manifest":path}));
            }
        }
    }

    let mut recent = Vec::new();
    for (domain, mut generations) in by_domain {
        generations.sort_unstable_by(|a, b| b.cmp(a));
        recent.extend(generations.into_iter().take(keep).map(|number| Generation {
            domain: domain.clone(),
            number,
        }));
    }

    let mut selected = Vec::new();
    for directory in children(&root.join("domains"))? {
        let domain = directory
            .file_name()
            .and_then(|s| s.to_str())
            .context("invalid domain namespace")?;
        if let Some(number) = records::current(root, domain)? {
            selected.push(Generation {
                domain: domain.to_owned(),
                number,
            });
        }
    }

    let mut running = Vec::new();
    for (path, value) in records::running_refs(root)? {
        let g = Generation {
            domain: text(&value, "domain")?,
            number: number(&value, "generation")?,
        };
        if !protection_inventory::committed(&committed, &g) {
            live.stale_running.push(path);
        }
        running.push(g);
    }

    let sources = PoolSources {
        committed,
        selected,
        running,
        recent,
    };

    let protected = ProtectionInventory::pool(&sources)
        .context("invalid or missing selected pool generation")?;

    for reference in protected.references() {
        match reference {
            Protection::Exact(g) => {
                live.generations.insert((g.domain.clone(), g.number));
            }
            Protection::System { .. } => {
                anyhow::bail!("unexpected system reference in pool inventory")
            }
        }
    }

    for key in live.generations.clone() {
        let (_, value) = live
            .manifests
            .get(&key)
            .context("current or running generation missing")?;
        let value = value.clone();
        add_manifest(root, &mut live, &value)?;
    }

    for path in children(&root.join("objects/blob-metadata"))? {
        if path.extension().is_none_or(|s| s != "json") {
            continue;
        }
        let value: Value = read(&path)?;
        if live.transactions.contains(&text(&value, "transaction")?) {
            let name = tracing::pending_object(&value)?;
            component(&name)?;
            ensure!(
                path.file_stem().and_then(|s| s.to_str()) == Some(name.as_str()),
                "pending object path identity mismatch"
            );
            live.sources.pending_objects.push(name);
        }
    }
    index_trace(&mut live)?;
    Ok((live, protected))
}

fn inventory(
    root: &Path,
    locations: &BTreeMap<String, (Value, segments::Extent)>,
    references: &BTreeMap<String, Vec<Value>>,
) -> Result<Vec<Value>> {
    let mut output = Vec::new();
    for id in segments::ids(root)? {
        let path = segments::blob(root, &id)?;
        let metadata = segments::metadata(root, &id)?;
        let value: Value = read(&metadata)?;
        // Validate physical identity and lifecycle before GC can begin any deletion.
        segment_retirement::observe(root, &id)?;
        let used = segment_retirement::bytes(root, &id)?;
        let current: Vec<_> = locations
            .iter()
            .filter(|(_, (_, extent))| extent.segment_id == id)
            .collect();
        let live: u64 = current.iter().map(|(_, (_, extent))| extent.size).sum();
        let refs = references.get(&id).cloned().unwrap_or_default();
        output.push(json!({
            "id": id,
            "blob": path,
            "metadata": metadata,
            "status": value["status"],
            "sealed": value["sealed"],
            "oversized": value["oversized"],
            "target_bytes": value["target_bytes"],
            "used_bytes": used,
            "object_count": value["object_count"],
            "current_live_bytes": live,
            "current_live_entries": current.iter().map(|(name,_)|name).collect::<Vec<_>>(),
            "dead_bytes": used.saturating_sub(live),
            "utilization_percent": if used == 0 {100.0} else {live as f64 * 100.0 / used as f64},
            "physical_reference_count": refs.len(),
            "blocked_by_physical_refs": !refs.is_empty(),
            "references": refs.iter().take(50).collect::<Vec<_>>(),
            "reference_count": refs.len(),
        }));
    }
    Ok(output)
}

fn delete_segments(
    root: &Path,
    inventory: &[Value],
    protection: &PhysicalProtection<'_>,
) -> Result<Value> {
    ensure!(
        root == Path::new(protection.pool()),
        "physical protection pool mismatch"
    );
    let index = protection
        .index()
        .context("invalid segment protection index")?;
    let current = segment_retirement::current(root)?;
    // Decode and select every request before starting physical deletion. Report
    // flags and reference counts are diagnostics, never permission to unlink.
    let mut selected = Vec::new();
    let mut seen = BTreeSet::new();
    for value in inventory {
        let id = text(value, "id")?;
        ensure!(
            seen.insert(id.clone()),
            "duplicate segment deletion candidate"
        );
        let observed = segment_retirement::observe(root, &id)?;
        selected.push((value, index.reclaim(observed, &current)));
    }

    let mut removed = Vec::new();
    let mut retained = Vec::new();
    let mut partial = Vec::new();
    let mut blocked = Vec::new();
    let mut reclaimed = 0;
    for (value, request) in selected {
        if let Some(request) = request {
            let id = request.id().to_owned();
            reclaimed += segment_retirement::execute(request)?;
            removed.push(id);
        } else {
            let id = text(value, "id")?;
            if number(value, "current_live_bytes")? == 0
                && number(value, "physical_reference_count")? > 0
            {
                blocked.push(id.clone());
            }
            if number(value, "current_live_bytes")? > 0 && number(value, "dead_bytes")? > 0 {
                partial.push(id);
            }
            retained.push((*value).clone());
        }
    }
    Ok(
        json!({"removed_segments":removed,"retained_segments":retained,"partially_live_segments":partial,"blocked_segments":blocked,"bytes_reclaimed":reclaimed}),
    )
}

/// The only GC generation-forget adapter accepts an exact verified request.
fn reclaim(root: &Path, request: &ReclaimRequest) -> Result<()> {
    records::forget(
        root,
        request.domain(),
        request.generation(),
        "garbage-collected",
    )
}

pub(super) fn gc(root: &Path, keep: usize, references: Vec<Protection>) -> Result<Value> {
    let (mut live, pool_inventory) = liveness(root, keep)?;
    // A missing journal pin is uncertain authority, not an empty protection set.
    for reference in &references {
        if let Protection::Exact(g) = reference {
            ensure!(
                live.manifests.contains_key(&(g.domain.clone(), g.number)),
                "protected generation missing: {domain}:{number}",
                domain = g.domain,
                number = g.number
            );
        }
    }
    let protected = pool_inventory
        .with_references(references)
        .context("invalid collection protections")?;
    let previously_traced = live.generations.clone();
    let mut requests = Vec::new();
    for ((domain, number), (_, manifest)) in &live.manifests {
        let candidate = Candidate {
            generation: Generation {
                domain: domain.clone(),
                number: *number,
            },
            system: text(manifest, "system")?,
        };
        if let Some(request) = protected.reclaim(candidate) {
            requests.push(request);
        } else {
            live.generations.insert((domain.clone(), *number));
        }
    }
    // Explicit machine references retain objects and views as well as generation records.
    for key in live
        .generations
        .difference(&previously_traced)
        .cloned()
        .collect::<Vec<_>>()
    {
        let manifest = live
            .manifests
            .get(&key)
            .context("protected generation missing")?
            .1
            .clone();
        add_manifest(root, &mut live, &manifest)?;
    }
    // Decode every surviving root before any deletion, including inactive manifests
    // retained for recovery. Invalid roots must not be discovered after object removal.
    index_trace(&mut live)?;
    let retiring: BTreeSet<_> = requests
        .iter()
        .map(|r| (r.domain().to_owned(), r.generation()))
        .collect();
    for path in records::manifests(root)? {
        let value: Value = read(&path)?;
        let digest = tracing::root_digest(&value)?;
        let key = (text(&value, "domain")?, number(&value, "generation")?);
        if !retiring.contains(&key)
            && let Some(digest) = digest
        {
            ensure!(live.trace.include_root(digest), "invalid root reference");
        }
    }
    let logical_requests = logical_retirement::prepare(root, &live.trace)?;
    // Resolve every retained pin before the first deletion, so damaged metadata fails closed.
    let locations = physical::locations(root, &live.trace)?;
    let physical::References {
        by_segment: references,
        stale_runtime: stale,
        protection,
    } = physical::resolve(root, &live.trace, &locations)?;
    let inventory = inventory(root, &locations, &references)?;
    let mut removed_generations = Vec::new();
    for request in requests {
        reclaim(root, &request)?;
        removed_generations
            .push(json!({"domain":request.domain(),"generation":request.generation()}));
        failpoint("gc-after-generation-remove")?;
    }
    let mut removed_metadata = Vec::new();
    let mut removed_blobs = Vec::new();
    let mut removed_special = Vec::new();
    let mut removed_views = Vec::new();
    let mut removed_roots = Vec::new();
    for request in logical_requests {
        // These copies report successful effects only. Execution consumes the original permission.
        let reported = match request.target() {
            Target::ObjectMetadata(name) => Target::ObjectMetadata(name.clone()),
            Target::FragmentMetadata(name) => Target::FragmentMetadata(name.clone()),
            Target::View(path) => Target::View(path.clone()),
            Target::Root(name) => Target::Root(name.clone()),
        };
        logical_retirement::execute(request)?;
        match reported {
            Target::ObjectMetadata(name) | Target::FragmentMetadata(name) if name == ".tar-eof" => {
                removed_special.push(name);
            }
            Target::ObjectMetadata(name) => {
                removed_metadata.push(name);
                failpoint("gc-after-object-metadata-remove")?;
            }
            Target::FragmentMetadata(name) => {
                removed_blobs.push(name);
                failpoint("gc-after-object-metadata-remove")?;
            }
            Target::View(path) => removed_views.push(
                Path::new(&path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .context("invalid view identity")?
                    .to_owned(),
            ),
            Target::Root(name) => removed_roots.push(name),
        }
    }
    let mut result = delete_segments(root, &inventory, &protection)?;
    for (key,value) in json!({
        "schema": "airlock.closure-store.gc.v1",
        "status": "passed",
        "pool_root": root,
        "retained_generations": live.generations.iter().map(|(domain,generation)|json!({"domain":domain,"generation":generation})).collect::<Vec<_>>(),
        "stale_running_refs": live.stale_running,
        "stale_runtime_view_refs": stale,
        "in_progress_generations": live.incomplete,
        "active_transaction_ids": live.transactions,
        "removed_generations": removed_generations,
        "removed_object_metadata": removed_metadata,
        "removed_object_blobs": removed_blobs,
        "removed_special_extents": removed_special,
        "removed_views": removed_views,
        "removed_root_artifacts": removed_roots,
        "segments_dir": root.join("objects/segments"),
        "segment_store_append_only": true,
        "segment_compaction": "available",
    }).as_object().context("invalid GC receipt")? {
        result[key] = value.clone();
    }
    Ok(result)
}

/// Refresh immutable view placements through checked per-entry relocation requests.
pub(super) fn refresh_maps(root: &Path) -> Result<Vec<PathBuf>> {
    relocation::refresh_maps(root)
}

pub(super) fn compact(
    root: &Path,
    keep: usize,
    threshold: u64,
    maximum: usize,
    target: u64,
    dry_run: bool,
) -> Result<Value> {
    ensure!(
        (1..=100).contains(&threshold) && maximum > 0,
        "invalid compaction bounds"
    );
    let (live, _inventory) = liveness(root, keep)?;
    let live_locations = physical::locations(root, &live.trace)?;
    let physical::References {
        by_segment: references,
        ..
    } = physical::resolve(root, &live.trace, &live_locations)?;
    let plan_inventory = inventory(root, &live_locations, &references)?;
    let mut candidates: Vec<_> = plan_inventory
        .iter()
        .filter(|v| {
            v["sealed"] == true
                && v["oversized"] != true
                && v["current_live_bytes"].as_u64().is_some_and(|n| n > 0)
                && v["utilization_percent"]
                    .as_f64()
                    .is_some_and(|n| n <= threshold as f64)
        })
        .cloned()
        .collect();
    candidates.sort_by(|a, b| {
        a["utilization_percent"]
            .as_f64()
            .unwrap_or(100.0)
            .total_cmp(&b["utilization_percent"].as_f64().unwrap_or(100.0))
            .then_with(|| a["id"].as_str().cmp(&b["id"].as_str()))
    });
    candidates.truncate(maximum);
    let zero: Vec<_> = plan_inventory
        .iter()
        .filter(|v| {
            v["sealed"] == true
                && v["current_live_bytes"] == 0
                && v["physical_reference_count"] == 0
        })
        .collect();
    let mut result = json!({
        "schema": "airlock.closure-store.compaction.v1",
        "status": "passed",
        "dry_run": dry_run,
        "pool_root": root,
        "threshold_percent": threshold,
        "max_segments": maximum,
        "segment_target_bytes": target,
        "candidate_segments": candidates,
        "segment_compaction": "copy-and-switch",
    });
    if dry_run {
        result["segments"] = json!(plan_inventory);
        result["segment_count"] = json!(plan_inventory.len());
        result["directly_reclaimable_segments"] = json!(zero);
        result["objects_to_move"] = json!(
            candidates
                .iter()
                .map(|v| v["current_live_entries"].as_array().map_or(0, Vec::len))
                .sum::<usize>()
        );
        result["bytes_to_copy"] = json!(
            candidates
                .iter()
                .filter_map(|v| v["current_live_bytes"].as_u64())
                .sum::<u64>()
        );
        result["bytes_reclaimable_now"] = json!(
            zero.iter()
                .filter_map(|v| v["used_bytes"].as_u64())
                .sum::<u64>()
        );
        return Ok(result);
    }

    let tx = transaction("compaction")?;
    let tx_path = root.join("transactions").join(format!("{tx}.json"));
    let noop = candidates.is_empty() && zero.is_empty();
    if !noop {
        write(
            &tx_path,
            &json!({
                "schema": "airlock.closure-store.transaction.v1",
                "id": tx,
                "type": "compaction",
                "status": "preparing",
                "created_at": now(),
                "candidate_segments": candidates.iter().map(|v|v["id"].clone()).collect::<Vec<_>>(),
            }),
            0o644,
        )?;
    }
    failpoint("compact-after-tx-create")?;

    let current = root.join("objects/current-segment");
    if !candidates.is_empty() && current.try_exists()? {
        let _lock = PoolLock::acquire(&root.join("objects/segments.lock"))?;
        segments::seal(
            root,
            fs::read_to_string(&current)?.trim(),
            &tx,
            "pre-compaction-open-segment",
        )?;
    }

    let mut moved = Vec::new();
    let mut new_segments = BTreeSet::new();
    let mut copied = 0;
    for candidate in &candidates {
        let id = text(candidate, "id")?;
        for (name, (original, old)) in &live_locations {
            if old.segment_id != id {
                continue;
            }
            let plan = relocation::plan(root, name, original, old, &tx)?;
            let mut temporary = tempfile::NamedTempFile::new_in(root.join("tmp"))?;
            let mut source = File::open(&old.segment_blob)?;
            source.seek(SeekFrom::Start(old.segment_offset))?;
            ensure!(
                std::io::copy(&mut source.take(old.size), temporary.as_file_mut())? == old.size,
                "compaction source truncated"
            );
            temporary.flush()?;
            ensure!(
                hash(temporary.path())? == old.sha256,
                "compaction source checksum mismatch"
            );
            failpoint("compact-after-object-copy")?;
            let extent = segments::append(root, temporary.path(), name, &tx, target)?;
            let request = relocation::copied(plan, &extent)?;
            failpoint("compact-before-location-publish")?;
            relocation::publish(request)?;
            failpoint("compact-after-location-publish")?;
            copied += extent.size;
            new_segments.insert(extent.segment_id.clone());
            moved.push(json!({
                "entry": name,
                "old_segment_id": old.segment_id,
                "old_segment_offset": old.segment_offset,
                "new_segment_id": extent.segment_id,
                "new_segment_offset": extent.segment_offset,
                "size": extent.size,
                "sha256": extent.sha256,
            }));
        }
    }

    for id in new_segments {
        let _lock = PoolLock::acquire(&root.join("objects/segments.lock"))?;
        failpoint("compact-before-replacement-seal")?;
        segments::seal(root, &id, &tx, "compaction-replacement")?;
    }

    let refreshed = if moved.is_empty() {
        Vec::new()
    } else {
        refresh_maps(root)?
    };
    failpoint("compact-after-view-refresh")?;
    if !noop {
        write(
            &tx_path,
            &json!({"schema":"airlock.closure-store.transaction.v1","id":tx,"type":"compaction","status":"committed","committed_at":now(),"objects_moved":moved.len(),"bytes_copied":copied}),
            0o644,
        )?;
    }
    failpoint("compact-after-tx-commit")?;
    let (live, _inventory) = liveness(root, keep)?;
    let live_locations = physical::locations(root, &live.trace)?;
    let physical::References {
        by_segment: references,
        protection,
        ..
    } = physical::resolve(root, &live.trace, &live_locations)?;
    let retirement = delete_segments(
        root,
        &inventory(root, &live_locations, &references)?,
        &protection,
    )?;
    failpoint("compact-after-retirement")?;
    let dead: u64 = candidates
        .iter()
        .filter_map(|v| v["dead_bytes"].as_u64())
        .sum();
    for (key, value) in json!({
        "noop": noop,
        "transaction": if noop {Value::Null}else{json!(tx)},
        "objects_moved": moved,
        "objects_reused": [],
        "bytes_copied": copied,
        "bytes_reclaimed": retirement["bytes_reclaimed"],
        "segments_retired": retirement["removed_segments"],
        "segments_blocked_from_deletion": retirement["blocked_segments"],
        "views_refreshed": refreshed,
        "write_amplification": copied as f64/dead.max(1) as f64,
    })
    .as_object()
    .context("invalid compaction receipt")?
    {
        result[key] = value.clone();
    }
    Ok(result)
}

pub(super) fn recover(root: &Path) -> Result<Value> {
    let mut protected: BTreeSet<(String, u64)> = records::running_refs(root)?
        .iter()
        .map(|(_, value)| Ok((text(value, "domain")?, number(value, "generation")?)))
        .collect::<Result<_>>()?;
    for domain in children(&root.join("domains"))? {
        pool_path(root, &domain)?;
        let name = domain
            .file_name()
            .and_then(|s| s.to_str())
            .context("invalid domain directory")?;
        if let Some(generation) = records::current(root, name)? {
            protected.insert((name.to_owned(), generation));
        }
    }

    let mut transactions = Vec::new();
    for path in children(&root.join("transactions"))? {
        if path.extension().is_none_or(|s| s != "json") {
            continue;
        }
        pool_path(root, &path)?;
        let tx: Value = read(&path)?;
        ensure!(
            tx["schema"] == "airlock.closure-store.transaction.v1"
                && path.file_stem().and_then(|s| s.to_str()) == Some(text(&tx, "id")?.as_str())
                && matches!(
                    tx["status"].as_str(),
                    Some("preparing" | "committed" | "aborted")
                ),
            "invalid recovery transaction"
        );
        transactions.push((path, tx));
    }

    let mut aborted = Vec::new();
    let mut finalized = Vec::new();
    let mut aborted_ids = BTreeSet::new();
    for (path, mut tx) in transactions {
        if tx["status"] == "committed" {
            if let Some(path) = tx["manifest"].as_str() {
                let path = Path::new(path);
                pool_path(root, path)?;
                if path.try_exists()? {
                    let mut manifest: Value = read(path)?;
                    if manifest["schema"] == GENERATION_SCHEMA && manifest["status"] == "prepared" {
                        ensure!(
                            manifest["transaction"] == tx["id"],
                            "recovery transaction identity mismatch"
                        );
                        manifest["status"] = json!("committed");
                        ensure!(
                            records::committed(root, &manifest)?,
                            "recovery transaction is not committed"
                        );
                        manifest["recovered_at"] = json!(now());
                        write(path, &manifest, 0o644)?;
                        finalized.push(path.to_path_buf());
                    }
                }
            }
        } else {
            aborted_ids.insert(text(&tx, "id")?);
            if tx["status"] != "aborted" {
                tx["status"] = json!("aborted");
                tx["aborted_at"] = json!(now());
                write(&path, &tx, 0o644)?;
                aborted.push(path);
            }
        }
    }
    for path in children(&root.join("tmp"))? {
        remove(&path)?;
    }

    let mut removed_runtime = Vec::new();
    for path in children(&root.join("runtime"))? {
        if path.extension().is_none_or(|s| s != "json") {
            continue;
        }
        let reference = runtime::load(root, &path)?;
        if let Some(request) = runtime::observe(&reference.name).release(
            root.to_str().context("non-UTF-8 pool path")?.to_owned(),
            reference.phase,
            ReleaseContext::Reconciliation,
        ) {
            runtime::release(request)?;
            removed_runtime.push(path);
        }
    }

    let mut sealed = Vec::new();
    for id in segments::ids(root)? {
        let value: Value = read(&segments::metadata(root, &id)?)?;
        if value["sealed"] != true
            && value["created_by_transaction"]
                .as_str()
                .is_some_and(|tx| aborted_ids.contains(tx))
        {
            let _lock = PoolLock::acquire(&root.join("objects/segments.lock"))?;
            segments::seal(
                root,
                &id,
                &text(&value, "created_by_transaction")?,
                "recovery-after-aborted-transaction",
            )?;
            sealed.push(id);
        }
    }

    let mut removed = Vec::new();
    for domain in children(&root.join("domains"))? {
        pool_path(root, &domain.join("generations"))?;
        for path in children(&domain)? {
            if path
                .file_name()
                .is_some_and(|s| s.to_string_lossy().starts_with(".current.tmp-"))
            {
                remove(&path)?;
            }
        }
        for path in children(&domain.join("generations"))? {
            pool_path(root, &path)?;
            let manifest_path = path.join("manifest.json");
            let manifest: Option<Value> = if manifest_path.try_exists()? {
                Some(read(&manifest_path)?)
            } else {
                None
            };
            if manifest
                .as_ref()
                .is_none_or(|manifest| manifest["schema"] != GENERATION_SCHEMA)
                || !manifest
                    .as_ref()
                    .map(|manifest| records::committed(root, manifest))
                    .transpose()?
                    .unwrap_or(false)
            {
                let name = domain
                    .file_name()
                    .and_then(|s| s.to_str())
                    .context("invalid generation domain")?;
                let generation = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .context("invalid generation id")?
                    .parse()?;
                ensure!(
                    !protected.contains(&(name.to_owned(), generation)),
                    "recovery cannot discard a selected or running generation"
                );
                if let Some(manifest) = &manifest {
                    ensure!(
                        manifest["schema"] == GENERATION_SCHEMA
                            && manifest["status"] == "prepared"
                            && manifest["domain"] == name
                            && manifest["generation"] == generation
                            && manifest["transaction"]
                                .as_str()
                                .is_some_and(|id| aborted_ids.contains(id)),
                        "damaged generation is not an unfinished admission"
                    );
                }
                records::forget(root, name, generation, "incomplete-admission")?;
                removed.push(path);
            }
        }
    }
    let mut reconciled = Vec::new();
    for path in children(&root.join("objects/blob-metadata"))? {
        if path.extension().is_none_or(|s| s != "json")
            || path.file_stem().is_some_and(|s| s == ".tar-eof")
        {
            continue;
        }
        let value: Value = read(&path)?;
        let name = tracing::pending_object(&value)?;
        ensure!(
            path == segments::object_metadata(root, &name)?,
            "recovery object filename identity mismatch"
        );
        if relocation::reconcile(root, &name)? {
            reconciled.push(name);
        }
    }

    let refreshed = refresh_maps(root)?;
    Ok(json!({
        "schema": "airlock.closure-store.recovery.v1",
        "status": "passed",
        "pool_root": root,
        "aborted_transactions": aborted,
        "finalized_generations": finalized,
        "removed_incomplete_generations": removed,
        "removed_runtime_refs": removed_runtime,
        "sealed_aborted_segments": sealed,
        "reconciled_objects": reconciled,
        "refreshed_blob_maps": refreshed,
    }))
}

pub(super) fn status(root: &Path) -> Result<Value> {
    let (live, _inventory) = liveness(root, 2)?;
    let locations = physical::locations(root, &live.trace)?;
    let physical::References {
        by_segment: references,
        stale_runtime: stale,
        ..
    } = physical::resolve(root, &live.trace, &locations)?;
    let inventory = inventory(root, &locations, &references)?;

    let mut domains: BTreeMap<String, Value> = BTreeMap::new();
    for ((domain, generation), (path, manifest)) in &live.manifests {
        let entry = domains
            .entry(domain.clone())
            .or_insert(json!({"current":records::current(root,domain)?,"generations":[]}));
        entry["generations"]
            .as_array_mut()
            .context("invalid domain generations")?
            .push(json!({
                "generation": generation,
                "manifest": path,
                "system": manifest["system"],
                "closure_hash": manifest["store"]["closure_hash"],
                "object_count": manifest["store"]["object_count"],
                "filesystem": "erofs",
                "view_backend": "erofs-objectmap",
            }));
    }

    let objects = children(&root.join("objects/metadata"))?
        .iter()
        .filter(|p| p.extension().is_some_and(|s| s == "json"))
        .count();
    let blobs = children(&root.join("objects/blob-metadata"))?
        .iter()
        .filter(|p| {
            p.extension().is_some_and(|s| s == "json")
                && p.file_stem().is_some_and(|s| s != ".tar-eof")
        })
        .count();
    Ok(json!({
        "schema": "airlock.closure-store.status.v1",
        "status": "passed",
        "pool_root": root,
        "object_count": objects,
        "object_blob_count": blobs,
        "object_segment_count": blobs,
        "segments_dir": root.join("objects/segments"),
        "segment_count": inventory.len(),
        "sealed_segment_count": inventory.iter().filter(|v|v["sealed"]==true).count(),
        "open_segment_count": inventory.iter().filter(|v|v["sealed"]!=true).count(),
        "segment_bytes_total": inventory.iter().filter_map(|v|v["used_bytes"].as_u64()).sum::<u64>(),
        "segments": inventory,
        "domains": domains,
        "running": records::running_refs(root)?.iter().map(|(_,v)|v).collect::<Vec<_>>(),
        "stale_runtime_view_refs": stale,
        "segment_compaction": "available",
    }))
}
