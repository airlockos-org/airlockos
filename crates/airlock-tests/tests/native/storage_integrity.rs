//! Admission and compaction reject damaged data before publishing or reclaiming retained storage.

use crate::common::{self, store::Store};
use anyhow::Result;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

/// Read metadata only after the production command has completed its durable publication.
fn read(path: impl AsRef<Path>) -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

/// Snapshot contents and modification times so read-only operations cannot silently rewrite metadata.
pub(super) fn snapshot(root: &Path) -> Result<BTreeMap<PathBuf, (Vec<u8>, u128)>> {
    let mut result = BTreeMap::new();
    if !root.exists() {
        return Ok(result);
    }
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() && !path.is_symlink() {
            for (relative, value) in snapshot(&path)? {
                result.insert(path.strip_prefix(root)?.join(relative), value);
            }
        } else if path.is_file() {
            let changed = path
                .metadata()?
                .modified()?
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos();
            result.insert(
                path.strip_prefix(root)?.to_owned(),
                (fs::read(&path)?, changed),
            );
        }
    }
    Ok(result)
}

/// Collect only committed manifests, keeping expected rejection checks independent of staging layout.
fn manifests(root: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>> {
    Ok(snapshot(root)?
        .into_iter()
        .filter(|(path, _)| path.file_name().is_some_and(|name| name == "manifest.json"))
        .map(|(path, (bytes, _))| (path, bytes))
        .collect())
}

/// Rewrite an actual produced archive so corruption cases exercise the real admission stream parser.
fn archive(
    payload: Vec<u8>,
    mutate: impl FnOnce(&mut BTreeMap<String, Vec<u8>>) -> Result<()>,
) -> Result<Vec<u8>> {
    let mut contents = BTreeMap::new();
    for entry in tar::Archive::new(payload.as_slice()).entries()? {
        let mut entry = entry?;
        let name = entry.path()?.to_str().unwrap().to_owned();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        contents.insert(name, bytes);
    }
    mutate(&mut contents)?;
    let mut result = tar::Builder::new(Vec::new());
    for (name, bytes) in contents {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o444);
        header.set_cksum();
        result.append_data(&mut header, name, bytes.as_slice())?;
    }
    Ok(result.into_inner()?)
}

/// Invalid object identity, provenance or bounds cannot replace even an already committed generation.
#[test]
fn artifact_manifest_rejection_preserves_existing_generations() -> Result<()> {
    for damage in [
        "domain",
        "system",
        "revision",
        "lock",
        "count",
        "references",
        "duplicate",
        "entry",
        "fragment",
        "tree",
        "nar-size",
        "nar-hash",
    ] {
        let store = Store::new()?;
        let prior = store.admit(true)?;
        let before = manifests(&store.pool.join("domains"))?;
        let payload = archive(store.artifact()?, |members| {
            let mut manifest: Value = serde_json::from_slice(&members["manifest.json"])?;
            match damage {
                "domain" => manifest["domain"] = json!("other-vm"),
                "system" => {
                    manifest["system"] =
                        json!(format!("/nix/store/{hash}-missing", hash = "z".repeat(32)))
                }
                "revision" => manifest["source_revision"] = json!("dirty"),
                "lock" => manifest["lock_hash"] = json!("invalid"),
                "count" => {
                    manifest["object_count"] = json!(manifest["object_count"].as_u64().unwrap() + 1)
                }
                "references" => {
                    manifest["objects"][0]["references"] =
                        json!([format!("/nix/store/{hash}-missing", hash = "z".repeat(32))])
                }
                "duplicate" => {
                    let object = manifest["objects"][0].clone();
                    manifest["objects"].as_array_mut().unwrap().push(object);
                    manifest["object_count"] =
                        json!(manifest["object_count"].as_u64().unwrap() + 1);
                }
                "entry" => manifest["objects"][0]["entry"] = json!("../escape"),
                "fragment" => manifest["objects"][0]["fragment"] = json!("../escape.tar"),
                "tree" => manifest["objects"][0]["tree_hash"] = json!("0".repeat(64)),
                "nar-size" => manifest["objects"][0]["nar_size"] = json!(-1),
                "nar-hash" => manifest["objects"][0]["nar_hash"] = json!(""),
                _ => unreachable!(),
            }
            members.insert("manifest.json".into(), serde_json::to_vec(&manifest)?);
            Ok(())
        })?;
        // A rejected manifest can close stdin before the remaining archive is sent.
        // This runner retains the failing exit status and diagnostics in that case.
        let rejected = airlock_nix_core::runtime::process::run(
            &mut store.receiver(),
            Some(payload),
            Some(Duration::from_secs(30)),
        )?;
        assert!(!rejected.status.success(), "accepted {damage}");
        assert_eq!(manifests(&store.pool.join("domains"))?, before);
        assert_eq!(
            store.run(&[
                "pool",
                "describe-generation",
                "--pool-root",
                store.pool_text(),
                "--domain",
                "usr-home-runtime-store",
                "--generation",
                &prior["generation"].to_string()
            ])?["selected"],
            true
        );
        assert_eq!(fs::read_dir(store.pool.join("tmp"))?.count(), 0);
    }
    let store = Store::new()?;
    let payload = store.artifact()?;
    let first = common::json(&mut store.receiver(), Some(payload.clone()))?;
    let second = common::json(&mut store.receiver(), Some(payload))?;
    assert_eq!(first["generation"], second["generation"]);
    assert_eq!(second["objects_admitted"], 0);

    // Losing one half of an object record must not permit a different tree to
    // replace the surviving identity under the same store name.
    let before = manifests(&store.pool.join("domains"))?;
    let name = Path::new(&store.system)
        .file_name()
        .unwrap()
        .to_str()
        .unwrap();
    fs::remove_file(
        store
            .pool
            .join("objects/blob-metadata")
            .join(format!("{name}.json")),
    )?;
    fs::write(
        store.physical.join(name).join("init"),
        "substituted contents",
    )?;
    let rejected = common::run(&mut store.receiver(), Some(store.artifact()?))?;
    assert!(!rejected.status.success());
    assert_eq!(manifests(&store.pool.join("domains"))?, before);
    Ok(())
}

/// Negotiation rejects a substituted prepared identity before asking the sender for any object bytes.
#[test]
fn artifact_negotiation_rejects_changed_prepared_identity_and_bad_frames() -> Result<()> {
    let store = Store::new()?;
    let identity = store.temporary.path().join("identity.json");
    let inventory = json!({"schema": "airlock.pool-artifact.v4", "domain": "usr-home", "system": store.system,
        "closure_source":format!("/nix/store/{hash}-closure",hash="c".repeat(32)),
        "root_source":format!("/nix/store/{hash}-root/root.img",hash="d".repeat(32)), "kernel_name": "",
        "source_revision": "a".repeat(40), "lock_hash": "b".repeat(64),
        "root_artifact":{"schema":"airlock.root-artifact.v1", "sha256":"d".repeat(64),
            "logical_bytes":65536,"payload_bytes":64,"format":"ext4","boot_abi":"airlock.nix-closure-root.v1"}});
    let mut expected = inventory.clone();
    expected.as_object_mut().unwrap().remove("schema");
    let mut malformed = expected.clone();
    malformed["root_artifact"] = json!({"changed": true});
    let mut substituted = inventory.clone();
    substituted["kernel_name"] = json!("other-kernel");
    let receiver = || {
        let mut command = store.command(&["artifact", "receive-incremental", "--pool-root"]);
        command.arg(&store.pool).args([
            "--expected-domain",
            "usr-home",
            "--approved-by",
            "sys-ctrl",
        ]);
        command
    };
    // Both malformed protected records and well-formed substituted offers must fail before transfer.
    for (expected, offered) in [(malformed, inventory), (expected, substituted)] {
        fs::write(&identity, serde_json::to_vec(&expected)?)?;
        let mut wire = serde_json::to_vec(&offered)?;
        wire.push(b'\n');
        let output = common::run(
            receiver().arg("--expected-identity").arg(&identity),
            Some(wire),
        )?;
        assert!(!output.status.success());
        let error: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(error["schema"], "airlock.pool-artifact-error.v1");
        assert!(
            error["error"]
                .as_str()
                .unwrap()
                .contains("prepared candidate"),
            "{error}"
        );
        assert!(manifests(&store.pool.join("domains"))?.is_empty());
    }
    for message in [b"{}".as_slice(), b"{invalid}\n", b"[]\n"] {
        let output = common::run(&mut receiver(), Some(message.to_vec()))?;
        assert!(!output.status.success());
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout)?["schema"],
            "airlock.pool-artifact-error.v1"
        );
    }
    Ok(())
}

/// Sparse identity depends on disk contents rather than host allocation and remains independent of private edits.
#[test]
fn root_artifacts_preserve_sparse_disk_identity_and_private_copy_independence() -> Result<()> {
    let store = Store::new()?;
    let dense = store.temporary.path().join("dense.img");
    fs::write(&dense, fs::read(&store.root)?)?;
    let expected = common::json(
        store
            .command(&["image", "root-descriptor"])
            .arg(&store.root),
        None,
    )?;
    assert_eq!(
        common::json(
            store.command(&["image", "root-descriptor"]).arg(dense),
            None
        )?,
        expected
    );
    assert!(
        expected["payload_bytes"].as_u64().unwrap()
            < expected["logical_bytes"].as_u64().unwrap() / 10
    );
    let receipt = common::json(&mut store.receiver(), Some(store.artifact()?))?;
    let retained = store
        .pool
        .join("root-artifacts")
        .join(expected["sha256"].as_str().unwrap())
        .join("root.img");
    assert_eq!(receipt["root_artifact"], expected);
    assert_eq!(fs::read(&retained)?, fs::read(&store.root)?);
    assert!(retained.metadata()?.blocks() * 512 < retained.metadata()?.len() / 10);
    let private = store.temporary.path().join("private.img");
    fs::copy(&retained, &private)?;
    fs::set_permissions(&private, fs::Permissions::from_mode(0o600))?;
    let mut file = fs::OpenOptions::new().write(true).open(&private)?;
    file.seek(SeekFrom::Start(2 * 65536))?;
    file.write_all(b"private change")?;
    assert_eq!(
        common::json(
            store.command(&["image", "root-descriptor"]).arg(retained),
            None
        )?,
        expected
    );
    assert_ne!(
        common::json(
            store.command(&["image", "root-descriptor"]).arg(private),
            None
        )?,
        expected
    );
    Ok(())
}

/// Sparse stream corruption, overlap, unsupported formats and redirected retention roots cannot publish artifacts.
#[test]
fn damaged_or_redirected_root_artifacts_are_never_retained() -> Result<()> {
    for damage in [
        "checksum",
        "truncated",
        "overlap",
        "format",
        "abi",
        "zero-extent",
    ] {
        let store = Store::new()?;
        let payload = archive(store.artifact()?, |members| {
            let mut manifest: Value = serde_json::from_slice(&members["manifest.json"])?;
            match damage {
                "checksum" => manifest["root_artifact"]["sha256"] = json!("0".repeat(64)),
                "truncated" => {
                    members.get_mut("root.sparse").unwrap().pop();
                }
                "overlap" | "zero-extent" => {
                    let data = members.get_mut("root.sparse").unwrap();
                    let first = b"AIRLOCK-ROOT-SPARSE-1\n".len() + 8;
                    if damage == "overlap" {
                        let second = first + 12 + 65536;
                        data[second..second + 8].fill(0);
                    } else {
                        data[first + 12..first + 12 + 65536].fill(0);
                    }
                    manifest["root_artifact"]["sha256"] =
                        json!(format!("{hash:x}", hash = Sha256::digest(data)));
                }
                "format" => manifest["root_artifact"]["format"] = json!("unsupported"),
                "abi" => manifest["root_artifact"]["boot_abi"] = json!("unsupported"),
                _ => unreachable!(),
            }
            members.insert("manifest.json".into(), serde_json::to_vec(&manifest)?);
            Ok(())
        })?;
        assert!(
            !common::run_file(&mut store.receiver(), &payload)?
                .status
                .success(),
            "accepted {damage}"
        );
        assert!(manifests(&store.pool.join("domains"))?.is_empty());
        assert_eq!(fs::read_dir(store.pool.join("tmp"))?.count(), 0);
        let retained = store.pool.join("root-artifacts");
        if retained.is_dir() {
            for entry in fs::read_dir(retained)? {
                assert!(!entry?.path().join("root.img").exists());
            }
        }
    }
    let store = Store::new()?;
    store.run(&["pool", "status", "--pool-root", store.pool_text()])?;
    let outside = store.temporary.path().join("outside");
    fs::create_dir(&outside)?;
    symlink(&outside, store.pool.join("root-artifacts"))?;
    assert!(
        !common::run_file(&mut store.receiver(), &store.artifact()?)?
            .status
            .success()
    );
    assert_eq!(fs::read_dir(outside)?.count(), 0);
    Ok(())
}

/// Unsupported pool formats remain byte-for-byte intact, including their directory layout.
#[test]
fn unsupported_pool_formats_and_invalid_extents_fail_before_mutation() -> Result<()> {
    let store = Store::new()?;
    store.run(&["pool", "status", "--pool-root", store.pool_text()])?;
    let before = snapshot(&store.pool)?;
    store.run(&["pool", "status", "--pool-root", store.pool_text()])?;
    assert_eq!(snapshot(&store.pool)?, before);
    for layout in ["single-blob", "unsegmented-manifest", "wrong-schema"] {
        let store = Store::new()?;
        fs::create_dir(&store.pool)?;
        if layout == "single-blob" {
            fs::create_dir(store.pool.join("objects"))?;
            fs::write(store.pool.join("objects/data.blob"), b"retained data")?;
        } else {
            let value = if layout == "unsegmented-manifest" {
                json!({"schema": "airlock.closure-store.v1", "object_key": "nix-store-basename", "object_store": {"data": "objects/data.blob"}})
            } else {
                json!({"schema": "unknown"})
            };
            fs::write(
                store.pool.join("MANIFEST.json"),
                serde_json::to_vec(&value)?,
            )?;
        }
        let before = snapshot(&store.pool)?;
        let directories = fs::read_dir(&store.pool)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<BTreeSet<_>>>()?;
        assert!(
            !common::run(
                &mut store.command(&["pool", "status", "--pool-root", store.pool_text()]),
                None
            )?
            .status
            .success()
        );
        assert_eq!(snapshot(&store.pool)?, before);
        assert_eq!(
            fs::read_dir(&store.pool)?
                .map(|entry| entry.map(|entry| entry.path()))
                .collect::<std::io::Result<BTreeSet<_>>>()?,
            directories
        );
    }
    for (field, value) in [
        ("segment_id", json!("../escape")),
        ("segment_offset", json!(-1)),
        ("length", json!(u64::MAX)),
        ("logical_offset", json!(512)),
    ] {
        let store = Store::new()?;
        let receipt = store.admit(true)?;
        let path = Path::new(receipt["canonical_blob_map"].as_str().unwrap());
        let mut map = read(path)?;
        map["extents"][0][field] = value;
        fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;
        fs::write(path, serde_json::to_vec(&map)?)?;
        assert!(
            !common::run(
                &mut store.command(&[
                    "pool",
                    "attach-blob-view",
                    "--pool-root",
                    store.pool_text(),
                    "--domain",
                    "usr-home-runtime-store",
                    "--generation",
                    "1"
                ]),
                None
            )?
            .status
            .success()
        );
        assert_eq!(fs::read_dir(store.pool.join("runtime"))?.count(), 0);
    }
    Ok(())
}

/// Create a partially live segment by retaining one object from an earlier larger generation.
fn fragmented() -> Result<(Store, Value)> {
    let store = Store::new()?;
    let mut additions = Vec::new();
    for letter in ["b", "c", "d"] {
        let name = format!("{hash}-object", hash = letter.repeat(32));
        fs::write(store.physical.join(&name), letter.as_bytes().repeat(8192))?;
        additions.push(format!("/nix/store/{name}"));
    }
    fs::write(
        store.closure.join("store-paths"),
        format!(
            "{system}\n{objects}\n",
            system = store.system,
            objects = additions.join("\n")
        ),
    )?;
    let first = common::json(
        store.admission().args(["--segment-target-bytes", "32768"]),
        None,
    )?;
    fs::write(
        store.closure.join("store-paths"),
        format!(
            "{system}\n{object}\n",
            system = store.system,
            object = additions[0]
        ),
    )?;
    let second = common::json(
        store.admission().args(["--segment-target-bytes", "32768"]),
        None,
    )?;
    store.run(&[
        "pool",
        "gc",
        "--pool-root",
        store.pool_text(),
        "--keep-generations",
        "0",
    ])?;
    assert!(!Path::new(first["manifest"].as_str().unwrap()).exists());
    Ok((store, second))
}

/// Limit each relocation scenario to one small segment without changing production compaction policy.
fn compact(store: &Store) -> Command {
    store.command(&[
        "pool",
        "compact",
        "--pool-root",
        store.pool_text(),
        "--threshold-percent",
        "80",
        "--max-segments",
        "1",
        "--keep-generations",
        "0",
        "--segment-target-bytes",
        "32768",
    ])
}

/// A runtime-only physical pin survives failed kernel queries even after its generation is collected.
#[test]
fn runtime_pins_survive_uncertain_observations_and_release_only_after_confirmed_absence()
-> Result<()> {
    let store = Store::new()?;
    // Seal every fragment so the runtime pin is the only remaining deletion barrier.
    let admitted = common::json(
        store
            .admission()
            .args(["--segment-target-bytes", "512", "--activate", "false"]),
        None,
    )?;
    let map = read(admitted["canonical_blob_map"].as_str().unwrap())?;
    let pins: Vec<_> = map["extents"].as_array().unwrap().iter().map(|extent| json!({
        "segment_id": extent["segment_id"], "offset": extent["segment_offset"], "length": extent["length"],
    })).collect();
    let name = "airlock-runtime-test";
    let reference = store.pool.join("runtime").join(format!("{name}.json"));
    fs::write(
        &reference,
        serde_json::to_vec(&json!({
            "schema":"airlock.closure-store.runtime-view-ref.v1", "status":"active",
            "dm_name":name, "physical_references":pins,
        }))?,
    )?;
    let original_record = fs::read(&reference)?;
    let physical = snapshot(&store.pool.join("objects/segments"))?;
    let peer = common::peer_link(store.temporary.path(), "dmsetup")?;
    let report = store.temporary.path().join("mapper-report.json");
    let invoke = |action: &str| -> Result<Value> {
        let mut command = store.command(&["pool", action, "--pool-root", store.pool_text()]);
        if action == "gc" {
            command.args(["--keep-generations", "0"]);
        }
        common::json(
            command
                .env("AIRLOCK_DMSETUP", &peer)
                .env("AIRLOCK_TEST_MAPPER_REPORT", &report),
            None,
        )
    };

    for observation in [
        json!({"exit":1}),
        json!({"exit":1,"stdout":"unrelated|253|0\n"}),
        json!({"signal":true}),
        json!({"stdout":"unrelated|253|0\n","stderr":"query incomplete"}),
        json!({"stdout":"malformed\n"}),
        json!({"stdout":"unrelated|253|0"}),
        json!({"stdout":"unrelated|253|0\nunrelated|253|1\n"}),
        json!({"stdout":format!("{name}|253|0\n")}),
    ] {
        fs::write(&report, serde_json::to_vec(&observation)?)?;
        for _ in 0..2 {
            assert!(
                invoke("recover")?["removed_runtime_refs"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
            assert!(
                invoke("gc")?["removed_segments"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
            assert!(!Path::new(admitted["manifest"].as_str().unwrap()).exists());
            assert_eq!(fs::read(&reference)?, original_record);
            assert_eq!(snapshot(&store.pool.join("objects/segments"))?, physical);
        }
    }
    // Ordinary process creation failure also retains the same physical protection.
    for action in ["recover", "gc"] {
        let mut command = store.command(&["pool", action, "--pool-root", store.pool_text()]);
        if action == "gc" {
            command.args(["--keep-generations", "0"]);
        }
        common::json(
            command.env(
                "AIRLOCK_DMSETUP",
                store.temporary.path().join("missing-dmsetup"),
            ),
            None,
        )?;
        assert_eq!(fs::read(&reference)?, original_record);
        assert_eq!(snapshot(&store.pool.join("objects/segments"))?, physical);
    }

    // A successful inventory containing only another name proves this exact mapping absent.
    fs::write(
        &report,
        br#"{"stdout":"airlock-runtime-test-other|253|0\n"}"#,
    )?;
    assert_eq!(
        invoke("recover")?["removed_runtime_refs"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(!reference.exists());
    assert!(
        invoke("recover")?["removed_runtime_refs"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        !invoke("gc")?["removed_segments"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        invoke("gc")?["removed_segments"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    Ok(())
}

/// An interrupted prepare is retained by collection, then explicitly reconciled under attach exclusion.
#[test]
fn preparing_and_invalid_runtime_records_do_not_silently_lose_protection() -> Result<()> {
    let store = Store::new()?;
    let admitted = store.admit(false)?;
    let map = read(admitted["canonical_blob_map"].as_str().unwrap())?;
    let extent = &map["extents"][0];
    let record = json!({
        "schema":"airlock.closure-store.runtime-view-ref.v1", "status":"preparing", "dm_name":"airlock-preparing",
        "physical_references":[{"segment_id":extent["segment_id"], "offset":extent["segment_offset"], "length":extent["length"]}],
    });
    let path = store.pool.join("runtime/airlock-preparing.json");
    fs::write(&path, serde_json::to_vec(&record)?)?;
    let peer = common::peer_link(store.temporary.path(), "dmsetup")?;
    let report = store.temporary.path().join("mapper-report.json");
    fs::write(&report, br#"{"stdout":"No devices found\n"}"#)?;
    let invoke = |action: &str| {
        let mut command = store.command(&["pool", action, "--pool-root", store.pool_text()]);
        if action == "gc" {
            command.args(["--keep-generations", "0"]);
        }
        command
            .env("AIRLOCK_DMSETUP", &peer)
            .env("AIRLOCK_TEST_MAPPER_REPORT", &report);
        command
    };
    assert!(
        common::json(&mut invoke("gc"), None)?["removed_segments"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(path.is_file());
    for (field, invalid) in [
        ("schema", "unknown"),
        ("status", "unknown"),
        ("dm_name", "airlock-other"),
        ("dm_name", "airlock-escaped name"),
    ] {
        let mut broken = record.clone();
        broken[field] = json!(invalid);
        fs::write(&path, serde_json::to_vec(&broken)?)?;
        let before = snapshot(&store.pool)?;
        for action in ["recover", "gc"] {
            assert!(!common::run(&mut invoke(action), None)?.status.success());
            assert_eq!(snapshot(&store.pool)?, before);
        }
    }
    fs::write(&path, serde_json::to_vec(&record)?)?;
    assert_eq!(
        common::json(&mut invoke("recover"), None)?["removed_runtime_refs"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(!path.exists());
    Ok(())
}

/// Planning is read-only, and running disk maps retain old bytes until their owner explicitly releases them.
#[test]
fn compaction_preserves_running_segments_until_pin_release() -> Result<()> {
    let (store, receipt) = fragmented()?;
    let before = snapshot(&store.pool)?;
    let plan = common::json(compact(&store).args(["--dry-run", "true"]), None)?;
    assert!(!plan["candidate_segments"].as_array().unwrap().is_empty());
    assert_eq!(snapshot(&store.pool)?, before);
    let generation = receipt["generation"].to_string();
    store.run(&[
        "pool",
        "mark-running",
        "--pool-root",
        store.pool_text(),
        "--domain",
        "usr-home-runtime-store",
        "--generation",
        &generation,
        "--volume",
        "store-data",
    ])?;
    let running = store
        .pool
        .join("running/usr-home-runtime-store")
        .join(&generation)
        .join("store-data.json");
    let original_running = fs::read(&running)?;
    let candidates: BTreeSet<_> = plan["candidate_segments"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["id"].as_str().unwrap())
        .collect();
    let result = common::json(&mut compact(&store), None)?;
    assert_eq!(fs::read(&running)?, original_running);
    assert!(!result["objects_moved"].as_array().unwrap().is_empty());
    assert!(candidates.iter().all(|id| {
        result["segments_blocked_from_deletion"]
            .as_array()
            .unwrap()
            .contains(&json!(id))
    }));
    store.run(&[
        "pool",
        "clear-running",
        "--pool-root",
        store.pool_text(),
        "--domain",
        "usr-home-runtime-store",
        "--generation",
        &generation,
        "--volume",
        "store-data",
    ])?;
    let result = store.run(&[
        "pool",
        "gc",
        "--pool-root",
        store.pool_text(),
        "--keep-generations",
        "0",
    ])?;
    assert!(candidates.iter().all(|id| {
        result["removed_segments"]
            .as_array()
            .unwrap()
            .contains(&json!(id))
    }));
    assert_eq!(
        store.run(&[
            "pool",
            "describe-generation",
            "--pool-root",
            store.pool_text(),
            "--domain",
            "usr-home-runtime-store",
            "--generation",
            &generation
        ])?["selected"],
        true
    );
    Ok(())
}

/// Physical relocation must never change the logical tar stream exposed by a software view.
fn logical_map_identity(map: &Value) -> Vec<Value> {
    map["extents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            json!({
                "object":entry["object"], "logical_offset":entry["logical_offset"],
                "length":entry["length"], "digest":entry["object_sha256"],
            })
        })
        .collect()
}

/// Every durable relocation boundary can recover a usable selected view; damaged backing aborts reclamation.
#[test]
fn interrupted_or_corrupt_compaction_preserves_selected_data() -> Result<()> {
    for failure in [
        "compact-after-tx-create",
        "compact-after-object-copy",
        "compact-before-location-publish",
        "compact-between-location-records",
        "compact-after-location-publish",
        "compact-before-replacement-seal",
        "compact-after-view-refresh",
        "compact-after-tx-commit",
    ] {
        let (store, receipt) = fragmented()?;
        let map = Path::new(receipt["canonical_blob_map"].as_str().unwrap());
        let logical_identity = logical_map_identity(&read(map)?);
        assert!(
            !common::run(
                compact(&store).env("AIRLOCK_CLOSURE_STORE_FAILPOINT", failure),
                None
            )?
            .status
            .success()
        );
        for _ in 0..2 {
            store.run(&["pool", "recover", "--pool-root", store.pool_text()])?;
            assert_eq!(logical_map_identity(&read(map)?), logical_identity);
        }
        let result = store.run(&[
            "pool",
            "load-generation",
            "--pool-root",
            store.pool_text(),
            "--domain",
            "usr-home-runtime-store",
            "--generation",
            &receipt["generation"].to_string(),
        ])?;
        assert_eq!(result["system"], store.system);
        common::json(compact(&store).args(["--dry-run", "true"]), None)?;
    }
    let (store, _) = fragmented()?;
    let metadata = fs::read_dir(store.pool.join("objects/blob-metadata"))?
        .filter_map(std::result::Result::ok)
        .find(|entry| entry.file_name().as_encoded_bytes().starts_with(b"a"))
        .unwrap()
        .path();
    let value = read(metadata)?;
    let path = Path::new(value["segment_blob"].as_str().unwrap());
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    let mut file = fs::OpenOptions::new().write(true).open(path)?;
    file.seek(SeekFrom::Start(value["segment_offset"].as_u64().unwrap()))?;
    file.write_all(b"damaged")?;
    let before = snapshot(&store.pool)?;
    assert!(!common::run(&mut compact(&store), None)?.status.success());
    assert_eq!(snapshot(&store.pool)?, before);
    Ok(())
}

/// Reconstruct separately retained extents only for an explicitly prepared real EROFS index check.
pub(super) fn extract(store: &Store, receipt: &Value) -> Result<PathBuf> {
    let directory = store.temporary.path().join("extracted");
    let external = store.temporary.path().join("external.tar");
    let mut file = File::create(&external)?;
    for extent in read(receipt["canonical_blob_map"].as_str().unwrap())?["extents"]
        .as_array()
        .unwrap()
    {
        let mut source = File::open(extent["segment_blob"].as_str().unwrap())?;
        source.seek(SeekFrom::Start(extent["segment_offset"].as_u64().unwrap()))?;
        file.seek(SeekFrom::Start(extent["logical_offset"].as_u64().unwrap()))?;
        let length = extent["length"].as_u64().unwrap();
        assert_eq!(std::io::copy(&mut source.take(length), &mut file)?, length);
    }
    common::run(
        Command::new(common::tool("fsck.erofs")?)
            .arg(format!("--device={path}", path = external.display()))
            .arg(format!("--extract={path}", path = directory.display()))
            .arg(receipt["canonical_metadata_image"].as_str().unwrap()),
        None,
    )?
    .checked()?;
    Ok(directory)
}

/// Cached metadata indexes preserve exact closure membership across additions, replacements and removals.
#[test]
#[ignore = "requires explicitly prepared AIRLOCK_EROFS_MKFS with Airlock metadata-index support and fsck.erofs"]
fn packaged_erofs_indexes_preserve_predecessors_and_reject_corruption() -> Result<()> {
    let mkfs = std::env::var_os("AIRLOCK_EROFS_MKFS")
        .expect("prepare the patched EROFS package explicitly");
    let mut store = Store::new()?;
    let shared = format!("{hash}-shared", hash = "b".repeat(32));
    fs::write(store.physical.join(&shared), "shared payload")?;
    fs::write(
        store.closure.join("store-paths"),
        format!("{system}\n/nix/store/{shared}\n", system = store.system),
    )?;
    let first = common::json(store.admission().env("AIRLOCK_MKFS_EROFS", &mkfs), None)?;
    let before = fs::read(first["canonical_metadata_image"].as_str().unwrap())?;
    let addition = format!("{hash}-addition", hash = "0".repeat(32));
    let relative = Path::new(&addition)
        .join("long-name-")
        .join("x".repeat(160));
    fs::create_dir_all(store.physical.join(&relative).parent().unwrap())?;
    fs::write(store.physical.join(&relative), "new payload")?;
    fs::set_permissions(
        store.physical.join(&relative),
        fs::Permissions::from_mode(0o755),
    )?;
    let long_target = "long-target-".repeat(20);
    symlink(
        &long_target,
        store.physical.join(&addition).join("long-link"),
    )?;
    fs::write(store.physical.join(&addition).join("empty"), [])?;
    let mut paths = fs::OpenOptions::new()
        .append(true)
        .open(store.closure.join("store-paths"))?;
    writeln!(paths, "/nix/store/{addition}")?;
    let second = common::json(
        store
            .admission()
            .env("AIRLOCK_MKFS_EROFS", &mkfs)
            .args(["--previous-generation", &first["generation"].to_string()]),
        None,
    )?;
    assert_eq!(second["store"]["index_depth"], 0);
    assert_eq!(
        fs::read(first["canonical_metadata_image"].as_str().unwrap())?,
        before
    );
    let target = extract(&store, &second)?;
    assert_eq!(
        fs::read_to_string(
            target
                .join(Path::new(&store.system).file_name().unwrap())
                .join("init")
        )?,
        "system fixture"
    );
    assert_eq!(fs::read_to_string(target.join(&relative))?, "new payload");
    assert_eq!(
        fs::metadata(target.join(&relative))?.permissions().mode() & 0o777,
        0o755
    );
    assert_eq!(
        fs::read_link(target.join(&addition).join("long-link"))?,
        PathBuf::from(long_target)
    );
    assert_eq!(fs::metadata(target.join(&addition).join("empty"))?.len(), 0);
    fs::remove_dir_all(&target)?;

    let previous_image = fs::read(second["canonical_metadata_image"].as_str().unwrap())?;
    let replacement = format!("{hash}-system", hash = "c".repeat(32));
    fs::create_dir(store.physical.join(&replacement))?;
    fs::write(
        store.physical.join(&replacement).join("init"),
        "replacement system",
    )?;
    store.system = format!("/nix/store/{replacement}");
    fs::write(
        store.closure.join("store-paths"),
        format!("{system}\n/nix/store/{shared}\n", system = store.system),
    )?;
    let third = common::json(
        store
            .admission()
            .env("AIRLOCK_MKFS_EROFS", &mkfs)
            .args(["--previous-generation", &second["generation"].to_string()]),
        None,
    )?;
    let target = extract(&store, &third)?;
    assert_eq!(
        fs::read_to_string(target.join(&replacement).join("init"))?,
        "replacement system"
    );
    assert_eq!(fs::read_to_string(target.join(&shared))?, "shared payload");
    let names: BTreeSet<_> = fs::read_dir(&target)?
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(
        names,
        [
            std::ffi::OsString::from(&shared),
            std::ffi::OsString::from(&replacement)
        ]
        .into_iter()
        .collect()
    );
    let map = read(third["canonical_blob_map"].as_str().unwrap())?;
    assert_eq!(map["objects"].as_array().unwrap().len(), 2);
    assert!(
        !map["objects"]
            .as_array()
            .unwrap()
            .contains(&json!(addition))
    );
    assert_eq!(
        fs::read(second["canonical_metadata_image"].as_str().unwrap())?,
        previous_image
    );

    // Corrupt cached metadata must fail closed, even though its package bytes
    // are still valid and a previous generation can still read them.
    let cached = store
        .pool
        .join("objects/file-indexes")
        .join(format!("{shared}.json"));
    let mut metadata = read(&cached)?;
    metadata[0]["offset"] = json!(0);
    fs::set_permissions(&cached, fs::Permissions::from_mode(0o600))?;
    fs::write(&cached, serde_json::to_vec(&metadata)?)?;
    let extra = format!("{hash}-extra", hash = "d".repeat(32));
    fs::write(store.physical.join(&extra), "extra")?;
    writeln!(
        fs::OpenOptions::new()
            .append(true)
            .open(store.closure.join("store-paths"))?,
        "/nix/store/{extra}"
    )?;
    let rejected = common::run(store.admission().env("AIRLOCK_MKFS_EROFS", &mkfs), None)?;
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stdout).contains("cached file index checksum mismatch"),
        "{stdout}",
        stdout = String::from_utf8_lossy(&rejected.stdout)
    );

    let store = Store::new()?;
    let first = common::json(store.admission().env("AIRLOCK_MKFS_EROFS", &mkfs), None)?;
    let path = Path::new(first["canonical_metadata_image"].as_str().unwrap());
    fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;
    fs::write(path, b"corrupt metadata")?;
    let addition = format!("{hash}-addition", hash = "b".repeat(32));
    fs::write(store.physical.join(&addition), "new")?;
    let mut paths = fs::OpenOptions::new()
        .append(true)
        .open(store.closure.join("store-paths"))?;
    writeln!(paths, "/nix/store/{addition}")?;
    let output = common::run(
        store
            .admission()
            .env("AIRLOCK_MKFS_EROFS", mkfs)
            .args(["--previous-generation", &first["generation"].to_string()]),
        None,
    )?;
    assert!(!output.status.success());
    assert_eq!(
        store.run(&[
            "pool",
            "describe-generation",
            "--pool-root",
            store.pool_text(),
            "--domain",
            "usr-home-runtime-store",
            "--generation",
            &first["generation"].to_string()
        ])?["selected"],
        true
    );
    Ok(())
}

/// Normal admission invokes actual Nix verification before publication and keeps small objects in one open segment.
#[test]
fn pool_verification_and_segment_packing_preserve_admission_boundaries() -> Result<()> {
    let store = Store::new()?;
    common::peer_link(store.temporary.path(), "nix")?;
    let arguments = store.temporary.path().join("nix-verify.json");
    let path = format!(
        "{root}:{path}",
        root = store.temporary.path().display(),
        path = std::env::var("PATH")?
    );
    let receipt = common::json(
        store
            .admission_mode("nix-store")
            .env("PATH", &path)
            .env("AIRLOCK_TEST_NIX_ARGS", &arguments),
        None,
    )?;
    assert_eq!(receipt["verification"]["mode"], "nix-store");
    let command = read(&arguments)?;
    for option in ["--extra-experimental-features", "nix-command"] {
        assert!(command.as_array().unwrap().contains(&json!(option)));
    }
    let rejected_pool = store.temporary.path().join("rejected-pool");
    // Replace the destination argument without duplicating a clap option or weakening production verification.
    let mut command = store.admission_mode("nix-store");
    let args: Vec<_> = command
        .get_args()
        .map(|value| {
            if value == store.pool.as_os_str() {
                rejected_pool.clone().into_os_string()
            } else {
                value.to_owned()
            }
        })
        .collect();
    command = store.command(&[]);
    command
        .args(args.into_iter().skip(1))
        .env("PATH", path)
        .env("AIRLOCK_TEST_NIX_ARGS", arguments)
        .env("AIRLOCK_TEST_NIX_EXIT", "1");
    assert!(!common::run(&mut command, None)?.status.success());
    assert!(manifests(&rejected_pool.join("domains"))?.is_empty());

    let store = Store::new()?;
    let mut objects = vec![store.system.clone()];
    for letter in ["b", "c", "d"] {
        let name = format!("{hash}-small", hash = letter.repeat(32));
        fs::write(store.physical.join(&name), letter.repeat(1024))?;
        objects.push(format!("/nix/store/{name}"));
    }
    fs::write(
        store.closure.join("store-paths"),
        format!("{paths}\n", paths = objects.join("\n")),
    )?;
    common::json(
        store
            .admission()
            .args(["--segment-target-bytes", "1048576"]),
        None,
    )?;
    let mut segments = BTreeSet::new();
    for path in objects {
        let name = Path::new(&path).file_name().unwrap();
        let value = read(
            store
                .pool
                .join("objects/blob-metadata")
                .join(name)
                .with_extension("json"),
        )?;
        segments.insert(value["segment_id"].clone().as_str().unwrap().to_owned());
    }
    assert_eq!(segments.len(), 1);
    let status = store.run(&["pool", "status", "--pool-root", store.pool_text()])?;
    assert_eq!(status["segment_count"], 1);
    assert_eq!(status["open_segment_count"], 1);
    Ok(())
}

/// In-progress object metadata stays protected until recovery aborts it; committed generations finalize without activation.
#[test]
fn recovery_distinguishes_active_objects_from_committed_unselected_generations() -> Result<()> {
    let store = Store::new()?;
    let failed = common::run(
        store
            .admission()
            .env("AIRLOCK_CLOSURE_STORE_FAILPOINT", "object-after-metadata"),
        None,
    )?;
    assert!(!failed.status.success());
    let name = Path::new(&store.system)
        .file_name()
        .unwrap()
        .to_str()
        .unwrap();
    let gc = store.run(&[
        "pool",
        "gc",
        "--pool-root",
        store.pool_text(),
        "--keep-generations",
        "0",
    ])?;
    assert!(!gc["active_transaction_ids"].as_array().unwrap().is_empty());
    assert!(
        !gc["removed_object_blobs"]
            .as_array()
            .unwrap()
            .contains(&json!(name))
    );
    store.run(&["pool", "recover", "--pool-root", store.pool_text()])?;
    assert!(
        store.run(&["pool", "status", "--pool-root", store.pool_text()])?["domains"]
            .get("usr-home-runtime-store")
            .is_none()
    );
    let gc = store.run(&[
        "pool",
        "gc",
        "--pool-root",
        store.pool_text(),
        "--keep-generations",
        "0",
    ])?;
    assert!(
        gc["removed_object_blobs"]
            .as_array()
            .unwrap()
            .contains(&json!(name))
    );

    let store = Store::new()?;
    let failed = common::run(
        store.admission().args(["--activate", "false"]).env(
            "AIRLOCK_CLOSURE_STORE_FAILPOINT",
            "generation-after-tx-commit",
        ),
        None,
    )?;
    assert!(!failed.status.success());
    assert_eq!(
        read(
            store
                .pool
                .join("domains/usr-home-runtime-store/generations/1/manifest.json")
        )?["status"],
        "prepared"
    );
    let gc = store.run(&[
        "pool",
        "gc",
        "--pool-root",
        store.pool_text(),
        "--keep-generations",
        "0",
    ])?;
    assert!(
        gc["in_progress_generations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["domain"] == "usr-home-runtime-store" && entry["generation"] == 1)
    );
    let recovered = store.run(&["pool", "recover", "--pool-root", store.pool_text()])?;
    assert_eq!(
        recovered["finalized_generations"].as_array().unwrap().len(),
        1
    );
    let status = store.run(&["pool", "status", "--pool-root", store.pool_text()])?;
    assert!(status["domains"]["usr-home-runtime-store"]["current"].is_null());
    assert_eq!(
        status["domains"]["usr-home-runtime-store"]["generations"][0]["generation"],
        1
    );
    Ok(())
}

/// Switching honors its atomic publication boundary; interrupted GC retains the selected generation.
#[test]
fn interrupted_switch_and_gc_preserve_the_last_published_selection() -> Result<()> {
    let store = Store::new()?;
    let first = store.admit(true)?;
    let selected_view = Path::new(first["canonical_metadata_image"].as_str().unwrap())
        .parent()
        .unwrap();
    let selected_root = store
        .pool
        .join("root-artifacts")
        .join(first["root_artifact"]["sha256"].as_str().unwrap());
    // Recovery may refresh physical segment-size diagnostics in the location map.
    // Its original extents, immutable index and object list must remain intact.
    let selected_map = selected_view.join("store.blob-map.json");
    let extents_before = read(&selected_map)?["extents"].clone();
    let mut view_before = snapshot(selected_view)?;
    view_before.remove(Path::new("store.blob-map.json"));
    let root_before = snapshot(&selected_root)?;
    let addition = format!("{hash}-new", hash = "b".repeat(32));
    fs::write(store.physical.join(&addition), "new data")?;
    let mut paths = fs::OpenOptions::new()
        .append(true)
        .open(store.closure.join("store-paths"))?;
    writeln!(paths, "/nix/store/{addition}")?;
    // The second generation has both an extra object and a different immutable boot disk.
    let mut root = fs::OpenOptions::new().write(true).open(&store.root)?;
    root.seek(SeekFrom::Start(2 * 65536))?;
    root.write_all(b"second boot disk")?;
    let second = store.admit(false)?;
    let stale_view = Path::new(second["canonical_metadata_image"].as_str().unwrap())
        .parent()
        .unwrap();
    let stale_root = store
        .pool
        .join("root-artifacts")
        .join(second["root_artifact"]["sha256"].as_str().unwrap());
    for (failure, expected) in [
        ("switch-before-current-replace", 1),
        ("switch-after-current-replace", 2),
    ] {
        let output = common::run(
            store
                .command(&[
                    "pool",
                    "switch",
                    "--pool-root",
                    store.pool_text(),
                    "--domain",
                    "usr-home-runtime-store",
                    "--generation",
                    "2",
                ])
                .env("AIRLOCK_CLOSURE_STORE_FAILPOINT", failure),
            None,
        )?;
        assert!(!output.status.success());
        store.run(&["pool", "recover", "--pool-root", store.pool_text()])?;
        assert_eq!(
            store.run(&["pool", "status", "--pool-root", store.pool_text()])?["domains"]["usr-home-runtime-store"]
                ["current"],
            expected
        );
    }
    store.run(&[
        "pool",
        "rollback",
        "--pool-root",
        store.pool_text(),
        "--domain",
        "usr-home-runtime-store",
        "--generation",
        "1",
    ])?;
    for failure in [
        "gc-before-logical-delete",
        "gc-after-object-metadata-remove",
        "gc-after-view-delete",
        "gc-after-root-delete",
    ] {
        let output = common::run(
            store
                .command(&[
                    "pool",
                    "gc",
                    "--pool-root",
                    store.pool_text(),
                    "--keep-generations",
                    "0",
                ])
                .env("AIRLOCK_CLOSURE_STORE_FAILPOINT", failure),
            None,
        )?;
        assert!(
            !output.status.success(),
            "missing logical deletion boundary: {failure}"
        );
        store.run(&["pool", "recover", "--pool-root", store.pool_text()])?;
        let mut observed_view = snapshot(selected_view)?;
        observed_view.remove(Path::new("store.blob-map.json"));
        assert_eq!(observed_view, view_before);
        assert_eq!(read(&selected_map)?["extents"], extents_before);
        assert_eq!(snapshot(&selected_root)?, root_before);
        if failure == "gc-before-logical-delete" {
            assert!(stale_view.is_dir());
            assert!(stale_root.is_dir());
            // Model interrupted recursive removal: orphan directories need not remain complete.
            fs::remove_file(stale_view.join("manifest.json"))?;
            fs::remove_file(stale_root.join("root.img"))?;
        }
        if failure == "gc-after-view-delete" {
            assert!(!stale_view.exists());
        }
        if failure == "gc-after-root-delete" {
            assert!(!stale_root.exists());
        }
    }
    let status = store.run(&["pool", "status", "--pool-root", store.pool_text()])?;
    assert_eq!(status["domains"]["usr-home-runtime-store"]["current"], 1);
    assert_eq!(
        status["domains"]["usr-home-runtime-store"]["generations"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    // Repeated recovery also preserves an exact machine-journal pin with no live VM reference.
    assert_eq!(store.admit(false)?["generation"], 3);
    assert_eq!(store.admit(false)?["generation"], 4);
    let args = [
        "pool",
        "gc",
        "--pool-root",
        store.pool_text(),
        "--keep-generations",
        "0",
        "--protect-generation",
        "usr-home-runtime-store:3",
    ];
    let interrupted = common::run(
        store.command(&args).env(
            "AIRLOCK_CLOSURE_STORE_FAILPOINT",
            "gc-after-generation-remove",
        ),
        None,
    )?;
    assert!(!interrupted.status.success());
    for _ in 0..2 {
        store.run(&["pool", "recover", "--pool-root", store.pool_text()])?;
        let gc = store.run(&args)?;
        let retained = gc["retained_generations"].as_array().unwrap();
        assert!(retained.contains(&json!({"domain":"usr-home-runtime-store","generation":1})));
        assert!(retained.contains(&json!({"domain":"usr-home-runtime-store","generation":3})));
        assert_eq!(retained.len(), 2);
    }
    Ok(())
}

/// Invalid orphan targets refuse collection before even an unrelated generation is forgotten.
#[test]
fn logical_cleanup_preflights_every_target_before_destructive_effects() -> Result<()> {
    let store = Store::new()?;
    store.admit(true)?;
    let inactive = store.admit(false)?;
    let outside = store.temporary.path().join("outside");
    fs::create_dir(&outside)?;
    fs::write(outside.join("keep"), b"preserve")?;
    for (kind, target) in [
        ("directory", store.pool.join("objects/metadata/orphan.json")),
        ("file", store.pool.join("views/by-closure/orphan")),
        ("symlink", store.pool.join("root-artifacts/orphan")),
    ] {
        match kind {
            "directory" => fs::create_dir(&target)?,
            "file" => fs::write(&target, b"not a view")?,
            "symlink" => symlink(&outside, &target)?,
            _ => unreachable!(),
        }
        let before = snapshot(&store.pool)?;
        let failed = common::run(
            &mut store.command(&[
                "pool",
                "gc",
                "--pool-root",
                store.pool_text(),
                "--keep-generations",
                "0",
            ]),
            None,
        )?;
        assert!(
            !failed.status.success(),
            "accepted invalid logical target: {target:?}"
        );
        assert_eq!(snapshot(&store.pool)?, before);
        assert!(Path::new(inactive["manifest"].as_str().unwrap()).is_file());
        assert_eq!(fs::read(outside.join("keep"))?, b"preserve");
        if kind == "directory" {
            fs::remove_dir(&target)?;
        } else {
            fs::remove_file(&target)?;
        }
    }
    store.run(&[
        "pool",
        "gc",
        "--pool-root",
        store.pool_text(),
        "--keep-generations",
        "0",
    ])?;
    assert!(!Path::new(inactive["manifest"].as_str().unwrap()).exists());
    Ok(())
}

/// Segment unlinking can be interrupted before, between, or after its two files without losing selected bytes.
#[test]
fn interrupted_segment_retirement_reconciles_partial_files_without_replaying_authority()
-> Result<()> {
    for failure in [
        "gc-before-segment-delete",
        "gc-between-segment-files",
        "gc-after-segment-delete",
    ] {
        let (store, receipt) = fragmented()?;
        let output = common::run(
            compact(&store).env("AIRLOCK_CLOSURE_STORE_FAILPOINT", failure),
            None,
        )?;
        assert!(
            !output.status.success(),
            "missing retirement failure boundary: {failure}"
        );
        if failure == "gc-between-segment-files" {
            assert!(
                fs::read_dir(store.pool.join("objects/segments"))?
                    .filter_map(std::result::Result::ok)
                    .any(|entry| {
                        entry.path().extension().is_some_and(|e| e == "json")
                            && !entry.path().with_extension("blob").exists()
                    })
            );
        }
        store.run(&["pool", "recover", "--pool-root", store.pool_text()])?;
        for _ in 0..2 {
            store.run(&[
                "pool",
                "gc",
                "--pool-root",
                store.pool_text(),
                "--keep-generations",
                "0",
            ])?;
            let generation = receipt["generation"].to_string();
            let loaded = store.run(&[
                "pool",
                "load-generation",
                "--pool-root",
                store.pool_text(),
                "--domain",
                "usr-home-runtime-store",
                "--generation",
                &generation,
            ])?;
            assert_eq!(loaded["system"], store.system);
        }
        let again = store.run(&[
            "pool",
            "gc",
            "--pool-root",
            store.pool_text(),
            "--keep-generations",
            "0",
        ])?;
        assert!(again["removed_segments"].as_array().unwrap().is_empty());
        for entry in fs::read_dir(store.pool.join("objects/segments"))? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "json") {
                assert!(
                    path.with_extension("blob").is_file(),
                    "partial retirement did not reconcile"
                );
            }
        }
    }
    Ok(())
}

/// Corrupt physical identity or lifecycle is rejected before GC removes any logical or physical data.
#[test]
fn segment_retirement_refuses_malformed_observations_before_cleanup() -> Result<()> {
    let (store, _) = fragmented()?;
    let path = fs::read_dir(store.pool.join("objects/segments"))?
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.extension().is_some_and(|e| e == "json"))
        .unwrap();
    let original = read(&path)?;
    let permissions = fs::metadata(&path)?.permissions();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    for defect in ["schema", "id", "blob", "status", "sealed"] {
        let mut damaged = original.clone();
        match defect {
            "schema" => damaged["schema"] = json!("unsupported"),
            "id" => damaged["id"] = json!("999999"),
            "blob" => damaged["blob"] = json!(store.pool.join("objects/segments/999999.blob")),
            "status" => damaged["status"] = json!("unknown"),
            "sealed" => damaged["sealed"] = json!(!original["sealed"].as_bool().unwrap()),
            _ => unreachable!(),
        }
        fs::write(&path, serde_json::to_vec(&damaged)?)?;
        let before = snapshot(&store.pool)?;
        let output = common::run(
            &mut store.command(&[
                "pool",
                "gc",
                "--pool-root",
                store.pool_text(),
                "--keep-generations",
                "0",
            ]),
            None,
        )?;
        assert!(
            !output.status.success(),
            "accepted invalid segment {defect}"
        );
        assert_eq!(
            snapshot(&store.pool)?,
            before,
            "mutated pool before rejecting {defect}"
        );
    }
    fs::write(&path, serde_json::to_vec(&original)?)?;
    fs::set_permissions(&path, permissions)?;
    store.run(&[
        "pool",
        "gc",
        "--pool-root",
        store.pool_text(),
        "--keep-generations",
        "0",
    ])?;
    Ok(())
}
