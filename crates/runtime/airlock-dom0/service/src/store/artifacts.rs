//! Receive artifacts over a policy-controlled channel and publish inactive retained generations.
//! Negotiation pins reused extents until the validated manifest and its transaction commit.

use super::{fs::*, pool_cli, records, root, segments, views};
use airlock_nix_core::artifact::{
    self, ERROR_SCHEMA, FULL_SCHEMA, INCREMENTAL_SCHEMA, MAX_MESSAGE, PROBE_SCHEMA, REQUEST_SCHEMA,
    read_message, write_message,
};
use airlock_nix_core::{
    admission::ExpectedAdmission,
    identity::{GitRevision, GuestName, LockHash},
    store_path::{StoreArtifact, StoreFile, StorePath},
};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{BufRead, Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

/// Incoming fragment retained in a private staging directory until validation completes.
struct Fragment {
    // Locally chosen path; no archive pathname is extracted to disk.
    path: PathBuf,
    // Exact stream length checked against the tar header and manifest.
    size: u64,
    // SHA-256 of the bytes actually received.
    sha256: String,
}

fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    value[key]
        .as_array()
        .with_context(|| format!("missing array {key}"))
}

fn objects(manifest: &Value, domain: &str, inventory: bool) -> Result<BTreeMap<String, Value>> {
    ensure!(
        manifest["schema"] == FULL_SCHEMA || manifest["schema"] == INCREMENTAL_SCHEMA,
        "unsupported artifact schema"
    );
    ensure!(manifest["domain"] == domain, "artifact target mismatch");
    component(domain)?;
    artifact::validate_store_path(&text(manifest, "system")?)?;
    artifact::validate_provenance(
        &text(manifest, "source_revision")?,
        &text(manifest, "lock_hash")?,
    )?;
    let descriptor: Option<root::Descriptor> =
        serde_json::from_value(manifest["root_artifact"].clone())?;
    if let Some(descriptor) = &descriptor {
        descriptor.validate()?;
        ensure!(
            !text(manifest, "root_source")?.is_empty(),
            "root artifact has no source"
        );
    } else {
        ensure!(
            text(manifest, "root_source")?.is_empty(),
            "root source lacks artifact descriptor"
        );
    }
    let raw = array(manifest, "objects")?;
    ensure!(
        number(manifest, "object_count")? == raw.len() as u64,
        "artifact object count mismatch"
    );
    let mut objects = BTreeMap::new();
    for object in raw {
        let path = text(object, "path")?;
        artifact::validate_store_path(&path)?;
        let name = entry(&path)?;
        ensure!(
            object["entry"] == name && object["fragment"] == format!("objects/{name}.tar"),
            "artifact object identity mismatch"
        );
        if !(inventory
            && manifest["schema"] == INCREMENTAL_SCHEMA
            && object.get("tree_hash").is_none())
        {
            let hash = text(object, "tree_hash")?;
            ensure!(
                hash.len() == 64
                    && hash
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "invalid object tree hash"
            );
        }
        ensure!(!text(object, "nar_hash")?.is_empty(), "missing NAR hash");
        number(object, "nar_size")?;
        for reference in array(object, "references")? {
            artifact::validate_store_path(reference.as_str().context("invalid reference")?)?;
        }
        ensure!(
            objects.insert(path, object.clone()).is_none(),
            "duplicate artifact object"
        );
    }
    ensure!(
        objects.contains_key(&text(manifest, "system")?),
        "artifact lacks its system"
    );
    for object in objects.values() {
        ensure!(
            array(object, "references")?
                .iter()
                .all(|r| r.as_str().is_some_and(|r| objects.contains_key(r))),
            "artifact closure is incomplete"
        );
    }
    Ok(objects)
}

fn tar_tree_hash(fragment: &Path, name: &str) -> Result<String> {
    let input = File::open(fragment)?;
    let length = input.metadata()?.len();
    let mut archive = tar::Archive::new(input);
    let mut records = BTreeMap::new();
    let mut end = 0;
    for item in archive.entries()? {
        let mut item = item?;
        end = item
            .raw_file_position()
            .checked_add(
                item.size()
                    .div_ceil(512)
                    .checked_mul(512)
                    .context("tar member length overflow")?,
            )
            .context("tar extent overflow")?;
        let path = item.path()?.into_owned();
        ensure!(
            !path.is_absolute()
                && !path
                    .components()
                    .any(|c| c == std::path::Component::ParentDir),
            "unsafe object tar path"
        );
        let mut components = path.components();
        ensure!(
            components.next().is_some_and(|c| c.as_os_str() == name),
            "object tar path has wrong root"
        );
        let relative = components.collect::<PathBuf>();
        let kind = item.header().entry_type();
        let mode = item.header().mode()? & 0o7777;
        let (kind, value) = if kind.is_dir() {
            ('D', String::new())
        } else if kind.is_symlink() {
            (
                'L',
                item.link_name()?
                    .context("missing symlink target")?
                    .to_str()
                    .context("non-UTF8 symlink")?
                    .to_owned(),
            )
        } else {
            ensure!(kind.is_file(), "unsupported object tar member type");
            let mut digest = Sha256::new();
            let mut buffer = [0; 1024 * 1024];
            loop {
                let count = item.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                digest.update(&buffer[..count]);
            }
            ('F', hex(&digest.finalize()))
        };
        ensure!(
            records.insert(relative, (kind, mode, value)).is_none(),
            "duplicate object tar path"
        );
    }
    ensure!(
        length > 0 && end == length,
        "object fragment has an embedded terminator or trailing bytes"
    );

    let (kind, mode, value) = records
        .remove(Path::new(""))
        .context("object tar has no root")?;
    let mut digest = Sha256::new();
    match kind {
        'L' => {
            ensure!(records.is_empty(), "symlink tar root has children");
            digest.update(b"L\0");
            digest.update(value);
        }
        'F' => {
            ensure!(records.is_empty(), "file tar root has children");
            digest.update(format!("F\0{mode:o}\0"));
            digest.update(value);
        }
        'D' => {
            for path in records.keys() {
                let mut parent = path.parent();
                while let Some(path) = parent.filter(|path| !path.as_os_str().is_empty()) {
                    ensure!(
                        records.get(path).is_some_and(|(kind, _, _)| *kind == 'D'),
                        "object tar member has a missing or non-directory parent"
                    );
                    parent = path.parent();
                }
            }
            digest.update(b"D\0");
            for (path, (kind, mode, value)) in records {
                let path = path.to_str().context("non-UTF8 tar path")?;
                match kind {
                    'L' => digest.update(format!("L\0{path}\0{value}\0")),
                    'D' => digest.update(format!("D\0{path}\0{mode:o}\0")),
                    'F' => {
                        digest.update(format!("F\0{path}\0{mode:o}\0"));
                        digest.update(value);
                        digest.update(b"\0");
                    }
                    _ => unreachable!(),
                }
            }
        }
        _ => unreachable!(),
    }
    Ok(hex(&digest.finalize()))
}

fn receive_members(
    input: &mut dyn BufRead,
    staging: &Path,
    allowed: Option<&BTreeSet<String>>,
    descriptor: Option<&Value>,
) -> Result<(Value, BTreeMap<String, Fragment>)> {
    // A pipe read can return just one byte. Preserve the signature while sniffing
    // compression instead of assuming fill_buf supplies a complete magic number.
    let mut signature = [0; 2];
    input.read_exact(&mut signature)?;
    let reader = std::io::Cursor::new(signature).chain(input);
    let compressed = signature == [0x1f, 0x8b];
    let reader: Box<dyn Read + '_> = if compressed {
        Box::new(flate2::read::GzDecoder::new(reader))
    } else {
        Box::new(reader)
    };
    let mut archive = tar::Archive::new(reader);
    let mut manifest = None;
    let mut fragments = BTreeMap::new();
    for member in archive.entries()? {
        let mut member = member?;
        ensure!(
            member.header().entry_type().is_file(),
            "artifact member is not a regular file"
        );
        let name = member
            .path()?
            .to_str()
            .context("non-UTF8 artifact path")?
            .to_owned();
        let size = member.size();
        if name == "manifest.json" {
            ensure!(
                manifest.is_none() && size <= MAX_MESSAGE as u64,
                "invalid or duplicate manifest"
            );
            let mut bytes = Vec::new();
            member.read_to_end(&mut bytes)?;
            manifest = Some(serde_json::from_slice(&bytes)?);
            continue;
        }
        let basename = if name == "root.sparse" {
            ensure!(
                size <= descriptor
                    .map(|v| number(v, "payload_bytes"))
                    .transpose()?
                    .unwrap_or(64 * 1024u64.pow(3)),
                "root exceeds negotiated payload size"
            );
            "root.sparse".to_owned()
        } else {
            let name = name
                .strip_prefix("objects/")
                .and_then(|s| s.strip_suffix(".tar"))
                .context("unexpected artifact member")?;
            component(name)?;
            artifact::validate_store_path(&format!("/nix/store/{name}"))?;
            format!("{name}.tar")
        };
        ensure!(
            !fragments.contains_key(&name) && allowed.is_none_or(|a| a.contains(&name)),
            "duplicate or unrequested artifact fragment"
        );
        let target = staging.join(basename);
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)?;
        let available = rustix::fs::statvfs(staging)?;
        ensure!(
            size.checked_add(64 * 1024 * 1024).is_some_and(
                |required| required <= available.f_bavail.saturating_mul(available.f_frsize)
            ),
            "insufficient pool space for fragment"
        );
        let mut digest = Sha256::new();
        let mut received = 0;
        let mut buffer = [0; 1024 * 1024];
        loop {
            let count = member.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
            output.write_all(&buffer[..count])?;
            received += count as u64;
        }
        ensure!(received == size, "truncated artifact member");
        output.sync_all()?;
        fragments.insert(
            name,
            Fragment {
                path: target,
                size,
                sha256: hex(&digest.finalize()),
            },
        );
    }
    if compressed {
        // Tar stops at its first zero block, potentially before gzip checks its
        // CRC and trailer. Finish only the compressed member: plain duplex tar
        // intentionally leaves the sender's pipe open while awaiting our reply.
        let mut padding = Vec::new();
        archive.into_inner().take(32769).read_to_end(&mut padding)?;
        ensure!(
            padding.len() <= 32768 && padding.iter().all(|byte| *byte == 0),
            "unexpected compressed artifact trailer"
        );
    }
    Ok((manifest.context("artifact lacks manifest.json")?, fragments))
}

fn validate_payload(
    manifest: &Value,
    fragments: &BTreeMap<String, Fragment>,
    domain: &str,
    reused: &BTreeMap<String, Value>,
    root_reused: bool,
) -> Result<BTreeMap<String, Value>> {
    let objects = objects(manifest, domain, false)?;
    let mut expected = BTreeSet::new();
    for (path, object) in &objects {
        if let Some(old) = reused.get(path) {
            ensure!(
                old["tree_hash"] == object["tree_hash"],
                "existing object hash mismatch"
            );
            continue;
        }
        let member = text(object, "fragment")?;
        expected.insert(member.clone());
        let fragment = fragments
            .get(&member)
            .context("artifact fragment missing")?;
        ensure!(
            object["fragment_size"] == fragment.size
                && object["fragment_sha256"] == fragment.sha256,
            "artifact fragment checksum mismatch"
        );
        ensure!(
            tar_tree_hash(&fragment.path, entry(path)?)? == text(object, "tree_hash")?,
            "artifact tree checksum mismatch"
        );
    }
    if !manifest["root_artifact"].is_null() && !root_reused {
        expected.insert("root.sparse".into());
        let fragment = fragments
            .get("root.sparse")
            .context("missing root payload")?;
        ensure!(
            manifest["root_artifact"]["payload_bytes"] == fragment.size
                && manifest["root_artifact"]["sha256"] == fragment.sha256,
            "root payload checksum mismatch"
        );
    }
    ensure!(
        expected == fragments.keys().cloned().collect(),
        "artifact has unlisted fragments"
    );
    Ok(objects)
}

/// Required candidate coordinates from a probe or full inventory; transfer metrics remain separate.
#[derive(Deserialize)]
struct CandidateOffer {
    // Exact consuming guest from the incoming protocol message.
    domain: GuestName,
    // Exact built guest system.
    system: StorePath,
    // Original closure descriptor, including valid prepared child paths.
    closure_source: StoreArtifact,
    // Original root image source.
    root_source: StoreFile,
    // Paired boot kernel.
    kernel_name: String,
    // Submitted current source revision, independent of retained-generation provenance.
    source_revision: GitRevision,
    // Submitted dependency identity.
    lock_hash: LockHash,
    // A probe omits the root descriptor; full inventory must match it.
    #[serde(default)]
    root_artifact: Option<root::Descriptor>,
}

fn candidate(inventory: &Value, identity: Option<&ExpectedAdmission>, probe: bool) -> Result<()> {
    if let Some(expected) = identity {
        let offer: CandidateOffer = serde_json::from_value(inventory.clone())?;
        expected.root_artifact.validate()?;
        ensure!(
            offer.domain == expected.domain
                && offer.system == expected.system
                && offer.closure_source == expected.closure_source
                && offer.root_source == expected.root_source
                && offer.kernel_name == expected.kernel_name
                && offer.source_revision == expected.source_revision
                && offer.lock_hash == expected.lock_hash
                && (probe || offer.root_artifact.as_ref() == Some(&expected.root_artifact)),
            "artifact differs from prepared candidate"
        );
    }
    Ok(())
}

fn reuse(root: &Path, probe: &Value, domain: &str, approved_by: &str) -> Result<Option<Value>> {
    ensure!(probe["domain"] == domain, "artifact target mismatch");
    artifact::validate_store_path(&text(probe, "system")?)?;
    artifact::validate_provenance(&text(probe, "source_revision")?, &text(probe, "lock_hash")?)?;
    let namespace = super::runtime_namespace(domain);
    let mut paths = records::manifests(root)?;
    paths.sort_by_key(|p| {
        p.parent()
            .and_then(Path::file_name)
            .and_then(|s| s.to_str())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0)
    });
    for path in paths.into_iter().rev() {
        let manifest: Value = read(&path)?;
        if !records::committed(root, &manifest)?
            || manifest["domain"] != namespace
            || manifest["system"] != probe["system"]
            || manifest["store"]["source"] != probe["closure_source"]
            || manifest["root"]["source"] != probe["root_source"]
            || manifest["kernel"]["name"] != probe["kernel_name"]
            || manifest["provenance"]["source_revision"] != probe["source_revision"]
            || manifest["provenance"]["lock_hash"] != probe["lock_hash"]
            || manifest["approval"]
                != json!({"approved_by":approved_by,"source":probe["closure_source"],"transport":"qrexec"})
            || manifest["verification"]["status"] != "passed"
            || manifest["retention"]["retain"] != true
        {
            continue;
        }
        views::verify(root, &manifest["store"])?;
        let paths: Vec<String> = serde_json::from_value(manifest["store"]["paths"].clone())?;
        for path in &paths {
            ensure!(
                segments::reusable(root, path)?.is_some(),
                "retained guest object missing"
            );
        }
        let image = records::root_image(root, &manifest)?;
        let mut result = json!({
            "schema": "airlock.closure-store.admission.v1",
            "status": "passed",
            "transport": "qrexec",
            "domain": domain,
            "generation": manifest["generation"],
            "previous_generation": manifest["previous_generation"],
            "current_generation": records::current(root,&namespace)?,
            "activated": false,
            "retained": true,
            "manifest": path,
            "system": manifest["system"],
            "root_source": probe["root_source"],
            "kernel_name": probe["kernel_name"],
            "closure_hash": manifest["store"]["closure_hash"],
            "objects_total": paths.len(),
            "objects_reused": paths.len(),
            "objects_admitted": 0,
            "objects_transferred": 0,
            "payload_bytes_transferred": 0,
            "root_artifact": manifest["root"]["artifact"],
            "root_reused": image.is_some(),
            "root_payload_bytes_transferred": 0,
            "root_logical_bytes": manifest["root"]["artifact"]["logical_bytes"],
            "source_revision": manifest["provenance"]["source_revision"],
            "lock_hash": manifest["provenance"]["lock_hash"],
            "generation_reused": true,
        });
        if let Some(image) = image {
            result["root_allocated_bytes"] = json!(fs::metadata(image)?.blocks() * 512);
        }
        return Ok(Some(result));
    }
    Ok(None)
}

fn admit(
    root: &Path,
    manifest: &Value,
    fragments: &BTreeMap<String, Fragment>,
    domain: &str,
    approved_by: &str,
    reused: &BTreeMap<String, Value>,
    root_reused: bool,
) -> Result<Value> {
    let objects = validate_payload(manifest, fragments, domain, reused, root_reused)?;
    let descriptor: Option<root::Descriptor> =
        serde_json::from_value(manifest["root_artifact"].clone())?;
    let root_image = if let Some(descriptor) = &descriptor {
        Some(if root_reused {
            root::reusable(root, descriptor)?.context("negotiated root missing")?
        } else {
            root::install(
                root,
                &fragments
                    .get("root.sparse")
                    .context("missing root fragment")?
                    .path,
                descriptor,
            )?
        })
    } else {
        None
    };
    if let Some(mut receipt) = reuse(root, manifest, domain, approved_by)? {
        let old: Value = read(Path::new(&text(&receipt, "manifest")?))?;
        let paths: Vec<_> = objects.keys().cloned().collect();
        let matching_objects = objects.iter().all(|(path, object)| {
            segments::reusable(root, path).is_ok_and(|saved| {
                saved.is_some_and(|saved| saved["tree_hash"] == object["tree_hash"])
            })
        });
        if receipt["source_revision"] == manifest["source_revision"]
            && receipt["lock_hash"] == manifest["lock_hash"]
            && receipt["root_artifact"] == manifest["root_artifact"]
            && old["store"]["paths"] == json!(paths)
            && matching_objects
        {
            receipt["objects_transferred"] = json!(
                fragments
                    .keys()
                    .filter(|name| name.as_str() != "root.sparse")
                    .count()
            );
            receipt["payload_bytes_transferred"] = json!(
                fragments
                    .iter()
                    .filter(|(name, _)| name.as_str() != "root.sparse")
                    .map(|(_, fragment)| fragment.size)
                    .sum::<u64>()
            );
            receipt["root_reused"] = json!(root_reused);
            receipt["root_payload_bytes_transferred"] = json!(
                fragments
                    .get("root.sparse")
                    .map_or(0, |fragment| fragment.size)
            );
            receipt["timings"] = json!({});
            return Ok(receipt);
        }
    }
    let namespace = super::runtime_namespace(domain);
    let generation = records::next(root, &namespace)?;
    let previous = records::current(root, &namespace)?;
    let system = text(manifest, "system")?;
    let tx = transaction(&format!("artifact:{domain}:{generation}:{system}"))?;
    let tx_path = root.join("transactions").join(format!("{tx}.json"));
    let path = records::manifest_path(root, &namespace, generation)?;
    let directory = path.parent().context("missing generation directory")?;
    mkdir_all(
        directory
            .parent()
            .context("missing generations directory")?,
    )?;
    mkdir(directory)?;
    write(
        &tx_path,
        &json!({"schema":"airlock.closure-store.transaction.v1","id":tx,"domain":namespace,"generation":generation,"status":"preparing","kind":"transferred-artifact","created_at":now()}),
        0o644,
    )?;
    let publish = (|| -> Result<Value> {
        let target = pool_cli::target(None)?;
        let mut admitted = 0;
        let mut reused_count = 0;
        for (path, object) in &objects {
            if let Some(existing) = segments::reusable(root, path)? {
                ensure!(
                    existing["tree_hash"] == object["tree_hash"],
                    "existing object hash mismatch"
                );
                reused_count += 1;
            } else {
                let fragment = fragments
                    .get(&text(object, "fragment")?)
                    .context("missing requested object")?;
                segments::admit_fragment(
                    root,
                    path,
                    &fragment.path,
                    &text(object, "tree_hash")?,
                    &tx,
                    target,
                )?;
                admitted += 1;
            }
            failpoint("artifact-after-object-import")?;
        }
        let paths: Vec<_> = objects.keys().cloned().collect();
        let closure = closure_hash(
            &paths,
            &system,
            &text(manifest, "root_source")?,
            &text(manifest, "kernel_name")?,
        );
        let mut store = views::materialize(views::ViewRequest {
            root,
            generation_dir: directory,
            paths: &paths,
            closure: &closure,
            transaction: &tx,
            target,
            trusted: &paths.iter().cloned().collect(),
            previous: None,
        })?;
        for (key, value) in json!({
            "mode": "shared-closure",
            "closure_hash": closure,
            "source": manifest["closure_source"],
            "mountpoint": "/nix/store",
            "device": "/dev/xvde",
            "blob_device": "/dev/xvdf",
            "read_only": true,
            "paths": paths,
            "object_count": paths.len(),
            "segment_target_bytes": target,
        })
        .as_object()
        .context("invalid storage identity")?
        {
            store[key] = value.clone();
        }
        let mut generation_manifest = json!({
            "schema": GENERATION_SCHEMA,
            "status": "prepared",
            "domain": namespace,
            "generation": generation,
            "previous_generation": previous,
            "created_at": now(),
            "transaction": tx,
            "approval": {"approved_by":approved_by,"source":manifest["closure_source"],"transport":"qrexec"},
            "provenance": {"source_revision":manifest["source_revision"],"lock_hash":manifest["lock_hash"],"artifact_schema":manifest["schema"]},
            "system": system,
            "root": {"source":manifest["root_source"],"artifact":descriptor},
            "kernel": {"name":manifest["kernel_name"]},
            "store": store,
            "verification": {"mode":"transferred-artifact","status":"passed","verified_objects":paths.len()},
            "retention": {"retain":true},
        });
        failpoint("artifact-before-generation-commit")?;
        write(&path, &generation_manifest, 0o644)?;
        write(
            &tx_path,
            &json!({"schema":"airlock.closure-store.transaction.v1","id":tx,"domain":namespace,"generation":generation,"status":"committed","activated":false,"committed_at":now(),"manifest":path}),
            0o644,
        )?;
        generation_manifest["status"] = json!("committed");
        write(&path, &generation_manifest, 0o644)?;
        let package_fragments: Vec<_> = fragments
            .iter()
            .filter(|(name, _)| name.as_str() != "root.sparse")
            .collect();
        let mut result = json!({
            "schema": "airlock.closure-store.admission.v1",
            "status": "passed",
            "transport": "qrexec",
            "domain": domain,
            "generation": generation,
            "previous_generation": previous,
            "current_generation": previous,
            "activated": false,
            "retained": true,
            "manifest": path,
            "system": system,
            "root_source": manifest["root_source"],
            "kernel_name": manifest["kernel_name"],
            "closure_hash": closure,
            "objects_total": paths.len(),
            "objects_admitted": admitted,
            "objects_reused": reused_count,
            "objects_transferred": package_fragments.len(),
            "payload_bytes_transferred": package_fragments.iter().map(|(_,f)|f.size).sum::<u64>(),
            "root_artifact": descriptor,
            "root_reused": root_reused,
            "root_payload_bytes_transferred": fragments.get("root.sparse").map_or(0,|f|f.size),
            "root_logical_bytes": manifest["root_artifact"]["logical_bytes"],
            "timings": {},
            "source_revision": manifest["source_revision"],
            "lock_hash": manifest["lock_hash"],
        });
        if let Some(image) = &root_image {
            result["root_allocated_bytes"] = json!(fs::metadata(image)?.blocks() * 512);
        }
        Ok(result)
    })();
    if publish.is_err() {
        // Committed transactions remain recoverable if only the final manifest write failed.
        if read::<Value>(&tx_path)?["status"] != "committed" {
            write(
                &tx_path,
                &json!({"schema":"airlock.closure-store.transaction.v1","id":tx,"domain":namespace,"generation":generation,"status":"aborted","aborted_at":now()}),
                0o644,
            )?;
            remove(directory)?;
        }
    }
    publish
}

pub(super) fn receive(
    input: &mut dyn BufRead,
    output: &mut dyn Write,
    pool: &Path,
    domain: &str,
    approved_by: &str,
    incremental: bool,
    identity: Option<&ExpectedAdmission>,
) -> Result<Value> {
    component(domain)?;
    ensure_pool(pool)?;
    let _lock = PoolLock::acquire(&pool.join("admission.lock"))?;
    let mut inventory = if incremental {
        Some(read_message(input)?)
    } else {
        None
    };
    if inventory
        .as_ref()
        .is_some_and(|value| value["schema"] == PROBE_SCHEMA)
    {
        let probe = inventory.as_ref().context("missing probe")?;
        candidate(probe, identity, true)?;
        if let Some(receipt) = reuse(pool, probe, domain, approved_by)? {
            if let Some(identity) = identity {
                ensure!(
                    serde_json::from_value::<Option<root::Descriptor>>(
                        receipt["root_artifact"].clone()
                    )?
                    .as_ref()
                        == Some(&identity.root_artifact),
                    "reused root differs from candidate"
                );
            }
            return Ok(receipt);
        }
        write_message(output, &json!({"schema":PROBE_SCHEMA,"reuse":false}))?;
        inventory = Some(read_message(input)?);
    }
    let mut reused = BTreeMap::new();
    let mut allowed = None;
    let mut root_reused = false;
    if let Some(inventory) = &inventory {
        ensure!(
            inventory["schema"] == INCREMENTAL_SCHEMA,
            "unsupported incremental inventory"
        );
        candidate(inventory, identity, false)?;
        let objects = objects(inventory, domain, true)?;
        for (path, object) in &objects {
            if let Some(existing) = segments::reusable(pool, path)? {
                if let Some(hash) = object.get("tree_hash") {
                    ensure!(
                        existing["tree_hash"] == *hash,
                        "existing object hash mismatch"
                    );
                }
                reused.insert(path.clone(), existing);
            }
        }
        let descriptor: Option<root::Descriptor> =
            serde_json::from_value(inventory["root_artifact"].clone())?;
        if let Some(descriptor) = &descriptor {
            root_reused = root::reusable(pool, descriptor)?.is_some();
        }
        let mut requested: BTreeSet<String> = objects
            .iter()
            .filter(|(path, _)| !reused.contains_key(*path))
            .map(|(_, object)| text(object, "fragment"))
            .collect::<Result<_>>()?;
        if descriptor.is_some() && !root_reused {
            let bytes = number(&inventory["root_artifact"], "payload_bytes")?;
            let available = rustix::fs::statvfs(pool)?;
            let needed = bytes
                .checked_mul(2)
                .and_then(|bytes| bytes.checked_add(64 * 1024 * 1024))
                .context("root admission space overflow")?;
            ensure!(
                available.f_bavail.saturating_mul(available.f_frsize) >= needed,
                "insufficient pool space for root artifact admission"
            );
            requested.insert("root.sparse".into());
        }
        write_message(
            output,
            &json!({
                "schema": REQUEST_SCHEMA,
                "missing": objects.keys().filter(|path|!reused.contains_key(*path)).collect::<Vec<_>>(),
                "missing_root": descriptor.is_some()&&!root_reused,
                "reused_tree_hashes": reused.iter().map(|(path,value)|(path.clone(),value["tree_hash"].clone())).collect::<BTreeMap<_,
                _>>(),
            }),
        )?;
        allowed = Some(requested);
    }
    let temporary = tempfile::tempdir_in(pool.join("tmp"))?;
    let descriptor = inventory
        .as_ref()
        .map(|i| &i["root_artifact"])
        .filter(|v| !v.is_null());
    let (manifest, fragments) =
        receive_members(input, temporary.path(), allowed.as_ref(), descriptor)?;
    if let Some(inventory) = &inventory {
        let mut comparable = manifest.clone();
        let old = objects(inventory, domain, true)?;
        for object in comparable["objects"]
            .as_array_mut()
            .context("missing objects")?
        {
            let path = text(object, "path")?;
            let fields = object.as_object_mut().context("invalid object")?;
            fields.remove("fragment_size");
            fields.remove("fragment_sha256");
            if old
                .get(&path)
                .is_none_or(|value| value.get("tree_hash").is_none())
            {
                fields.remove("tree_hash");
            }
        }
        ensure!(
            comparable == *inventory,
            "artifact differs from negotiated inventory"
        );
    } else {
        ensure!(
            manifest["schema"] == FULL_SCHEMA,
            "incremental artifacts require negotiation"
        );
    }
    admit(
        pool,
        &manifest,
        &fragments,
        domain,
        approved_by,
        &reused,
        root_reused,
    )
}

pub(super) fn report_error(output: &mut dyn Write, error: &anyhow::Error) {
    let message = format!("{error:#}");
    let end = message
        .char_indices()
        .map(|(index, _)| index)
        .take_while(|index| *index <= 4096)
        .last()
        .unwrap_or(0);
    let error = if message.len() <= 4096 {
        message.as_str()
    } else {
        &message[..end]
    };
    let _ = write_message(output, &json!({"schema":ERROR_SCHEMA,"error":error}));
}
