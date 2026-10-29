//! Admission recovery and artifact protocols use real services on ordinary temporary files.

use crate::common::{self, store::Store};
use anyhow::{Context, Result};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};

/// Read one transaction or generation record without changing its representation.
fn read(path: impl AsRef<Path>) -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

/// Enumerate committed manifests while keeping assertions independent of directory order.
fn manifests(store: &Store) -> Result<Vec<std::path::PathBuf>> {
    let domains = store.pool.join("domains");
    let mut result = Vec::new();
    if !domains.exists() {
        return Ok(result);
    }
    for domain in fs::read_dir(domains)? {
        let generations = domain?.path().join("generations");
        if !generations.is_dir() {
            continue;
        }
        for entry in fs::read_dir(generations)? {
            let path = entry?.path().join("manifest.json");
            if path.exists() {
                result.push(path);
            }
        }
    }
    Ok(result)
}

/// Running references retain bytes until explicitly cleared; generation numbers remain monotonic.
#[test]
fn admission_selection_running_pins_and_gc() -> Result<()> {
    let store = Store::new()?;
    let first = store.admit(true)?;
    let second = store.admit(false)?;
    assert_eq!(
        (first["generation"].as_u64(), second["generation"].as_u64()),
        (Some(1), Some(2))
    );
    assert_eq!(first["objects_admitted"], 1);
    assert_eq!(second["objects_reused"], 1);
    assert_eq!(
        store.run(&[
            "pool",
            "describe-generation",
            "--pool-root",
            store.pool_text(),
            "--domain",
            "usr-home-runtime-store",
            "--generation",
            "1"
        ])?["selected"],
        true
    );

    store.run(&[
        "pool",
        "mark-running",
        "--pool-root",
        store.pool_text(),
        "--domain",
        "usr-home-runtime-store",
        "--generation",
        "2",
        "--volume",
        "store-data",
    ])?;
    let collected = store.run(&[
        "pool",
        "gc",
        "--pool-root",
        store.pool_text(),
        "--keep-generations",
        "0",
    ])?;
    assert!(
        collected["retained_generations"]
            .as_array()
            .unwrap()
            .contains(&json!({"domain":"usr-home-runtime-store","generation":2}))
    );
    // A stale logical running reference keeps its physical pins until explicit release.
    let manifest = store
        .pool
        .join("domains/usr-home-runtime-store/generations/2/manifest.json");
    let saved = fs::read(&manifest)?;
    let running = store
        .pool
        .join("running/usr-home-runtime-store/2/store-data.json");
    let physical_pin = fs::read(&running)?;
    fs::remove_file(&manifest)?;
    assert_eq!(
        store.run(&[
            "pool",
            "gc",
            "--pool-root",
            store.pool_text(),
            "--keep-generations",
            "0"
        ])?["stale_running_refs"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(fs::read(&running)?, physical_pin);
    fs::write(&manifest, saved)?;
    store.run(&[
        "pool",
        "clear-running",
        "--pool-root",
        store.pool_text(),
        "--domain",
        "usr-home-runtime-store",
        "--generation",
        "2",
        "--volume",
        "store-data",
    ])?;
    // Original journal pins protect a generation after it is neither selected nor running.
    for _ in 0..2 {
        let kept = store.run(&[
            "pool",
            "gc",
            "--pool-root",
            store.pool_text(),
            "--keep-generations",
            "0",
            "--protect-generation",
            "usr-home-runtime-store:2",
        ])?;
        assert!(kept["removed_generations"].as_array().unwrap().is_empty());
        assert!(
            kept["retained_generations"]
                .as_array()
                .unwrap()
                .contains(&json!({"domain":"usr-home-runtime-store","generation":2}))
        );
    }
    let source = format!("usr-home-runtime-store:{system}", system = store.system);
    assert!(
        store.run(&[
            "pool",
            "gc",
            "--pool-root",
            store.pool_text(),
            "--keep-generations",
            "0",
            "--protect-system",
            &source
        ])?["removed_generations"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    // A lost or malformed exact pin aborts before deleting even an otherwise reclaimable generation.
    let before = manifests(&store)?;
    for pin in [
        "usr-home-runtime-store:99",
        "other-runtime-store:2",
        "../escape:2",
        "usr-home-runtime-store:0",
    ] {
        let output = common::run(
            &mut store.command(&[
                "pool",
                "gc",
                "--pool-root",
                store.pool_text(),
                "--keep-generations",
                "0",
                "--protect-generation",
                pin,
            ]),
            None,
        )?;
        assert!(!output.status.success(), "{pin}");
        assert_eq!(manifests(&store)?, before);
    }
    assert_eq!(
        store.run(&[
            "pool",
            "gc",
            "--pool-root",
            store.pool_text(),
            "--keep-generations",
            "0"
        ])?["removed_generations"],
        json!([{"domain":"usr-home-runtime-store","generation":2}])
    );
    store.run(&[
        "pool",
        "retire-generation",
        "--pool-root",
        store.pool_text(),
        "--domain",
        "usr-home-runtime-store",
        "--generation",
        "1",
    ])?;
    assert_eq!(
        store.run(&[
            "pool",
            "gc",
            "--pool-root",
            store.pool_text(),
            "--keep-generations",
            "0"
        ])?["removed_root_artifacts"],
        json!([first["root_artifact"]["sha256"]])
    );
    assert!(store.admit(true)?["generation"].as_u64().unwrap() > 1);
    Ok(())
}

/// A selected namespace with no committed manifest must block all collection before deletion.
#[test]
fn gc_rejects_missing_selected_namespace_before_reclamation() -> Result<()> {
    let store = Store::new()?;
    store.admit(false)?;
    let lost = store.pool.join("domains/lost-runtime-store");
    fs::create_dir_all(lost.join("generations"))?;
    std::os::unix::fs::symlink("generations/99", lost.join("current"))?;
    let before = manifests(&store)?;
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
        "a selected namespace disappeared from the inventory"
    );
    let failure: Value = serde_json::from_slice(&output.stdout)?;
    assert!(
        failure["error"]
            .as_str()
            .unwrap()
            .contains("missing selected pool generation"),
        "{failure}"
    );
    assert_eq!(manifests(&store)?, before);
    fs::remove_file(lost.join("current"))?;
    assert_eq!(
        store.run(&[
            "pool",
            "gc",
            "--pool-root",
            store.pool_text(),
            "--keep-generations",
            "0"
        ])?["removed_generations"],
        json!([{"domain":"usr-home-runtime-store","generation":1}])
    );
    Ok(())
}

/// A later explicit retention decision wins over a delayed automatic release and its retries.
#[test]
fn automatic_retention_release_rechecks_manual_decisions_under_lock() -> Result<()> {
    let store = Store::new()?;
    store.admit(false)?;
    let path = store
        .pool
        .join("domains/usr-home-runtime-store/generations/1/manifest.json");
    // Represent the original admission pin before any explicit user retention update.
    let mut admitted = read(&path)?;
    admitted["retention"]["retain"] = json!(true);
    fs::write(&path, serde_json::to_vec(&admitted)?)?;
    let args = [
        "pool",
        "release-automatic",
        "--pool-root",
        store.pool_text(),
        "--domain",
        "usr-home-runtime-store",
        "--generation",
        "1",
    ];
    let mut protected = args.to_vec();
    protected.extend(["--protect-generation", "usr-home-runtime-store:1"]);
    assert_eq!(store.run(&protected)?["status"], "unchanged");
    assert_eq!(store.run(&args)?["retain"], false);
    assert_eq!(store.run(&args)?["status"], "unchanged");
    store.run(&[
        "pool",
        "set-retention",
        "--pool-root",
        store.pool_text(),
        "--domain",
        "usr-home-runtime-store",
        "--generation",
        "1",
        "--retain",
        "true",
    ])?;
    let before = fs::read(&path)?;
    for _ in 0..2 {
        assert_eq!(store.run(&args)?["status"], "unchanged");
        assert_eq!(fs::read(&path)?, before);
    }
    Ok(())
}

/// Every publication failpoint recovers without selecting a partially committed generation.
#[test]
fn interrupted_admissions_preserve_the_selected_committed_view() -> Result<()> {
    for failure in [
        "admit-after-tx-create",
        "object-after-append",
        "generation-before-manifest",
        "generation-after-manifest",
        "generation-after-tx-commit",
        "generation-after-manifest-commit",
        "switch-before-current-replace",
    ] {
        let store = Store::new()?;
        store.admit(true)?;
        let addition = format!("{hash}-addition", hash = "b".repeat(32));
        fs::write(store.physical.join(&addition), b"new object")?;
        writeln!(
            fs::OpenOptions::new()
                .append(true)
                .open(store.closure.join("store-paths"))?,
            "/nix/store/{addition}"
        )?;
        let output = common::run(
            store
                .admission()
                .env("AIRLOCK_CLOSURE_STORE_FAILPOINT", failure),
            None,
        )?;
        assert!(!output.status.success(), "{failure}");

        store.run(&["pool", "recover", "--pool-root", store.pool_text()])?;
        assert_eq!(
            store.run(&[
                "pool",
                "describe-generation",
                "--pool-root",
                store.pool_text(),
                "--domain",
                "usr-home-runtime-store",
                "--generation",
                "1"
            ])?["selected"],
            true,
            "{failure}"
        );
        for manifest in manifests(&store)? {
            let manifest = read(manifest)?;
            assert_eq!(manifest["status"], "committed", "{failure}");
            let transaction = manifest["transaction"].as_str().unwrap();
            assert_eq!(
                read(store.pool.join(format!("transactions/{transaction}.json")))?["status"],
                "committed"
            );
        }
    }
    Ok(())
}

/// Interrupted segment promotion cannot publish a generation or strand permanently protected bytes.
#[test]
fn interrupted_received_segments_recover_without_activation() -> Result<()> {
    for failure in [
        "artifact-after-segment-publish",
        "object-after-metadata",
        "artifact-before-generation-commit",
    ] {
        let store = Store::new()?;
        let output = common::run(
            store
                .receiver()
                .env("AIRLOCK_CLOSURE_STORE_FAILPOINT", failure),
            Some(store.artifact()?),
        )?;
        assert!(!output.status.success(), "{failure}");
        store.run(&["pool", "recover", "--pool-root", store.pool_text()])?;
        assert!(manifests(&store)?.is_empty());
        store.run(&[
            "pool",
            "gc",
            "--pool-root",
            store.pool_text(),
            "--keep-generations",
            "0",
        ])?;
        assert_eq!(
            fs::read_dir(store.pool.join("objects/segments"))?.count(),
            0
        );
        let receipt = common::json(&mut store.receiver(), Some(store.artifact()?))?;
        assert_eq!(receipt["status"], "passed");
        assert_eq!(receipt["activated"], false);
    }
    Ok(())
}

/// A full artifact is retained without changing the selected generation.
#[test]
fn full_artifact_is_retained_inactive() -> Result<()> {
    let store = Store::new()?;
    let small = format!(
        "{hash}-{name}",
        hash = "b".repeat(32),
        name = "long-name-".repeat(16)
    );
    let large = format!("{hash}-large", hash = "c".repeat(32));
    fs::write(store.physical.join(&small), b"small payload")?;
    fs::write(store.physical.join(&large), vec![7; 32768])?;
    let paths = [
        store.system.clone(),
        format!("/nix/store/{small}"),
        format!("/nix/store/{large}"),
    ];
    fs::write(
        store.closure.join("store-paths"),
        format!("{}\n", paths.join("\n")),
    )?;
    let metadata: serde_json::Map<String, Value> = paths
        .iter()
        .map(|path| {
            (
                path.clone(),
                json!({"narHash":"sha256:fixture", "narSize":32768, "references":[]}),
            )
        })
        .collect();
    fs::write(
        store.temporary.path().join("path-info.json"),
        serde_json::to_vec(&metadata)?,
    )?;
    let receipt = common::json(
        store
            .receiver()
            .env("AIRLOCK_CLOSURE_STORE_SEGMENT_TARGET_BYTES", "16384"),
        Some(store.artifact()?),
    )?;
    let fragments: Vec<_> = paths
        .iter()
        .map(|path| {
            read(
                store
                    .pool
                    .join("objects/blob-metadata")
                    .join(format!("{}.json", path.rsplit('/').next().unwrap())),
            )
        })
        .collect::<Result<_>>()?;
    assert_eq!(fragments[0]["segment_id"], fragments[1]["segment_id"]);
    assert_ne!(fragments[1]["segment_id"], fragments[2]["segment_id"]);
    assert_eq!(receipt["retained"], true);
    assert_eq!(receipt["activated"], false);
    assert_eq!(receipt["objects_admitted"], 3);
    assert_eq!(receipt["domain"], "usr-home");
    let manifest = read(receipt["manifest"].as_str().unwrap())?;
    assert_eq!(manifest["domain"], "usr-home-runtime-store");
    assert!(
        !store
            .pool
            .join("domains/usr-home-runtime-store/current")
            .exists()
    );
    Ok(())
}

/// Incremental reuse transfers no repeated payload and propagates receiver rejection.
#[test]
fn incremental_channel_reuses_bytes_and_propagates_rejection() -> Result<()> {
    let store = Store::new()?;
    let first = common::json(&mut store.sender()?, None)?;
    let second = common::json(store.sender()?.arg("--reuse-generation"), None)?;
    assert_eq!(second["generation_reused"], true);
    assert_eq!(second["generation"], first["generation"]);
    assert_eq!(second["objects_transferred"], 0);
    assert_eq!(second["root_payload_bytes_transferred"], 0);

    // A fresh command avoids duplicate CLI flags while changing the declared domain.
    let command = store.sender()?;
    let args: Vec<_> = command
        .get_args()
        .map(|arg| {
            if arg == "usr-home" {
                "other-vm".into()
            } else {
                arg.to_owned()
            }
        })
        .collect();
    let mut rejected = Command::new(&store.cli);
    store
        .environment(&mut rejected)
        .args(args)
        .env("AIRLOCK_TEST_RECEIVER", &store.service)
        .env("AIRLOCK_TEST_POOL", &store.pool);
    let output = common::run(&mut rejected, None)?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("pool receiver rejected admission"));
    Ok(())
}

/// Provenance changes require a new review generation even when bytes can be reused.
#[test]
fn changed_provenance_gets_a_new_generation() -> Result<()> {
    let store = Store::new()?;
    let first = common::json(&mut store.sender()?, None)?;
    let command = store.sender()?;
    let mut args: Vec<_> = command.get_args().map(|arg| arg.to_owned()).collect();
    for (flag, value) in [
        ("--source-revision", "c".repeat(40)),
        ("--lock-hash", "d".repeat(64)),
    ] {
        let index = args.iter().position(|arg| arg == flag).unwrap();
        args[index + 1] = value.into();
    }
    let mut command = Command::new(&store.cli);
    store
        .environment(&mut command)
        .args(args)
        .arg("--reuse-generation")
        .env("AIRLOCK_TEST_RECEIVER", &store.service)
        .env("AIRLOCK_TEST_POOL", &store.pool);
    let second = common::json(&mut command, None)?;
    assert!(second["generation"].as_u64() > first["generation"].as_u64());
    assert_eq!(second["source_revision"], "c".repeat(40));
    assert_eq!(second["lock_hash"], "d".repeat(64));
    assert_eq!(second["objects_transferred"], 0);
    Ok(())
}

/// A sender accepts only a receipt tied to its exact review identity.
#[test]
fn unrelated_receipts_are_rejected() -> Result<()> {
    for (field, value) in [
        ("schema", json!("unrelated")),
        ("generation", json!(0)),
        ("source_revision", json!("c".repeat(40))),
        ("lock_hash", json!("d".repeat(64))),
    ] {
        let store = Store::new()?;
        let mut receipt = json!({
            "schema": "airlock.closure-store.admission.v1",
            "generation": 1,
            "status": "passed",
            "domain": "usr-home",
            "system": store.system,
            "activated": false,
            "retained": true,
            "root_source": store.root,
            "kernel_name": "",
            "source_revision": "a".repeat(40),
            "lock_hash": "b".repeat(64),
            "generation_reused": true
        });
        receipt[field] = value;
        let peer = common::peer_link(store.temporary.path(), "receipt-peer")?;
        let output = common::run(
            store
                .artifact_command("send")
                .arg("--qrexec-client")
                .arg(peer)
                .arg("--reuse-generation")
                .env("AIRLOCK_TEST_RECEIPT", receipt.to_string()),
            None,
        )?;
        assert!(!output.status.success(), "{field}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("invalid pool admission receipt"),
            "{field}"
        );
    }
    Ok(())
}

/// A missing blob map cannot publish a misleading running pin.
#[test]
fn missing_map_cannot_create_an_empty_pin() -> Result<()> {
    let store = Store::new()?;
    let receipt = store.admit(true)?;
    fs::remove_file(receipt["canonical_blob_map"].as_str().unwrap())?;
    let output = common::run(
        &mut store.command(&[
            "pool",
            "mark-running",
            "--pool-root",
            store.pool_text(),
            "--domain",
            "usr-home-runtime-store",
            "--generation",
            "1",
            "--volume",
            "store-data",
        ]),
        None,
    )?;
    assert!(!output.status.success());
    assert_eq!(fs::read_dir(store.pool.join("running"))?.count(), 0);
    Ok(())
}

/// Committed transaction IDs and ownership must match their generation manifest.
#[test]
fn transaction_must_belong_to_its_generation() -> Result<()> {
    for (field, value) in [
        ("domain", json!("other")),
        ("generation", json!(99)),
        ("id", json!("other")),
    ] {
        let store = Store::new()?;
        let receipt = store.admit(true)?;
        let manifest = read(receipt["manifest"].as_str().unwrap())?;
        let transaction = manifest["transaction"].as_str().unwrap();
        let path = store.pool.join(format!("transactions/{transaction}.json"));
        let mut tx = read(&path)?;
        tx[field] = value;
        fs::write(path, serde_json::to_vec(&tx)?)?;

        let output = common::run(
            &mut store.command(&[
                "pool",
                "load-generation",
                "--pool-root",
                store.pool_text(),
                "--domain",
                "usr-home-runtime-store",
                "--generation",
                "1",
            ]),
            None,
        )?;
        assert!(!output.status.success(), "{field}");
    }
    Ok(())
}

/// Garbage collection and recovery cannot reuse a discarded generation number.
#[test]
fn discarded_generation_numbers_are_never_reissued() -> Result<()> {
    for cleanup in ["gc", "recover"] {
        let store = Store::new()?;
        store.admit(true)?;
        if cleanup == "gc" {
            assert_eq!(store.admit(false)?["generation"], 2);
        } else {
            assert!(
                !common::run(
                    store
                        .admission()
                        .env("AIRLOCK_CLOSURE_STORE_FAILPOINT", "admit-after-tx-create"),
                    None
                )?
                .status
                .success()
            );
        }
        store.run(
            &[
                "pool",
                cleanup,
                "--pool-root",
                store.pool_text(),
                "--keep-generations",
                "0",
            ]
            .into_iter()
            .take(if cleanup == "gc" { 6 } else { 4 })
            .collect::<Vec<_>>(),
        )?;
        assert!(
            !store
                .pool
                .join("domains/usr-home-runtime-store/generations/2")
                .exists()
        );
        assert!(store.admit(true)?["generation"].as_u64().unwrap() > 2);
    }
    Ok(())
}

/// Maintenance refuses redirected directories and leaves unrelated bytes intact.
#[test]
fn directory_symlinks_cannot_redirect_maintenance() -> Result<()> {
    for operation in ["gc", "recover"] {
        let store = Store::new()?;
        store.run(&["pool", "status", "--pool-root", store.pool_text()])?;
        let outside = store.temporary.path().join("outside");
        let generation = outside.join("generations/1");
        fs::create_dir_all(&generation)?;
        fs::write(generation.join("sentinel"), b"preserve outside bytes")?;
        std::os::unix::fs::symlink(&outside, store.pool.join("domains/redirect"))?;

        assert!(
            !common::run(
                &mut store.command(&["pool", operation, "--pool-root", store.pool_text()]),
                None
            )?
            .status
            .success()
        );
        assert_eq!(
            fs::read(generation.join("sentinel"))?,
            b"preserve outside bytes"
        );
    }
    Ok(())
}

/// Initialization validates existing paths before creating pool metadata or directories.
#[test]
fn initialization_rejects_symlinks_before_creating_directories() -> Result<()> {
    let store = Store::new()?;
    let outside = store.temporary.path().join("outside");
    fs::create_dir(&outside)?;
    fs::create_dir(&store.pool)?;
    std::os::unix::fs::symlink(&outside, store.pool.join("objects"))?;
    assert!(
        !common::run(
            &mut store.command(&["pool", "status", "--pool-root", store.pool_text()]),
            None
        )?
        .status
        .success()
    );
    assert_eq!(fs::read_dir(outside)?.count(), 0);
    assert!(!store.pool.join("MANIFEST.json").exists());
    Ok(())
}

/// Recovery preserves a damaged selected generation for explicit repair.
#[test]
fn damaged_selected_generation_is_kept() -> Result<()> {
    let store = Store::new()?;
    let receipt = store.admit(true)?;
    let path = Path::new(receipt["manifest"].as_str().unwrap());
    let mut manifest = read(path)?;
    manifest["schema"] = json!("damaged");
    fs::write(path, serde_json::to_vec(&manifest)?)?;
    assert!(
        !common::run(
            &mut store.command(&["pool", "recover", "--pool-root", store.pool_text()]),
            None
        )?
        .status
        .success()
    );
    assert_eq!(read(path)?["schema"], "damaged");
    assert!(
        store
            .pool
            .join("domains/usr-home-runtime-store/current")
            .is_symlink()
    );
    Ok(())
}

/// Archive names, including absolute paths and traversal, cannot escape receiver staging.
#[test]
fn unexpected_archive_members_cannot_escape_staging() -> Result<()> {
    for name in [
        "../escape",
        "/absolute",
        "objects/../escape.tar",
        "objects/a.tar",
    ] {
        let store = Store::new()?;
        // Raw header names are intentional: safe archive-builder APIs reject these before the receiver sees them.
        let mut header = tar::Header::new_gnu();
        header.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
        header.set_size(4);
        header.set_mode(0o644);
        header.set_cksum();
        let mut builder = tar::Builder::new(Vec::new());
        builder.append(&header, &b"evil"[..])?;
        let payload = builder.into_inner()?;
        assert!(
            !common::run(&mut store.receiver(), Some(payload))?
                .status
                .success(),
            "{name}"
        );
        assert!(!store.temporary.path().join("escape").exists());
        assert_eq!(fs::read_dir(store.pool.join("tmp"))?.count(), 0);
    }
    Ok(())
}

/// Split gzip signatures still require a valid trailer before an artifact is committed.
#[test]
fn gzip_trailer_is_checked_after_split_signature() -> Result<()> {
    for corrupt in [false, true] {
        let store = Store::new()?;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&store.artifact()?)?;
        let mut payload = encoder.finish()?;
        if corrupt {
            let index = payload.len() - 8;
            payload[index] ^= 1;
        }
        // Admission performs durable filesystem writes. Use the normal process
        // budget, not the three-second fixture-handshake budget, under image-build I/O.
        let logs = tempfile::tempdir()?;
        let mut job = airlock_tests::system::Job::spawn_input(
            &mut store.receiver(),
            logs.path(),
            Stdio::piped(),
        )?;
        let mut input = job.take_stdin().context("gzip receiver input")?;
        input.write_all(&payload[..1])?;
        input.flush()?;
        std::thread::sleep(Duration::from_millis(50));
        input.write_all(&payload[1..])?;
        drop(input);
        let status = job.wait(Duration::from_secs(30)).with_context(|| {
            format!(
                "gzip receiver did not finish: {error}",
                error = fs::read_to_string(logs.path().join("stderr.log")).unwrap_or_default()
            )
        })?;
        if corrupt {
            assert!(!status.success());
            assert!(manifests(&store)?.is_empty());
        } else {
            assert!(status.success());
            assert_eq!(
                serde_json::from_slice::<Value>(&fs::read(logs.path().join("stdout.log"))?)?["retained"],
                true
            );
        }
    }
    Ok(())
}

/// Rehashed fragments still cannot conceal nonzero bytes after the inner tar terminator.
#[test]
fn fragment_cannot_hide_bytes_after_tar_terminator() -> Result<()> {
    let store = Store::new()?;
    let payload = store.artifact()?;
    let mut source = tar::Archive::new(&payload[..]);
    let mut members = Vec::new();
    for entry in source.entries()? {
        let mut entry = entry?;
        let name = entry.path()?.to_string_lossy().into_owned();
        let header = entry.header().clone();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        if name.starts_with("objects/") {
            bytes.extend_from_slice(&[0; 1024]);
            let mut hidden = [0; 512];
            hidden[..6].copy_from_slice(b"hidden");
            bytes.extend_from_slice(&hidden);
        }
        members.push((name, header, bytes));
    }
    let mut manifest: Value =
        serde_json::from_slice(&members.iter().find(|m| m.0 == "manifest.json").unwrap().2)?;
    for object in manifest["objects"].as_array_mut().unwrap() {
        let fragment = &members
            .iter()
            .find(|m| Some(m.0.as_str()) == object["fragment"].as_str())
            .unwrap()
            .2;
        object["fragment_size"] = json!(fragment.len());
        object["fragment_sha256"] = json!(format!("{hash:x}", hash = Sha256::digest(fragment)));
    }

    let mut target = tar::Builder::new(Vec::new());
    for (name, mut header, bytes) in members {
        let bytes = if name == "manifest.json" {
            serde_json::to_vec(&manifest)?
        } else {
            bytes
        };
        header.set_size(bytes.len() as u64);
        header.set_cksum();
        target.append(&header, &bytes[..])?;
    }
    assert!(
        !common::run(&mut store.receiver(), Some(target.into_inner()?))?
            .status
            .success()
    );
    assert!(manifests(&store)?.is_empty());
    Ok(())
}

/// Damaged current pointers stop recovery without deleting retained manifests.
#[test]
fn bad_current_pointer_stops_recovery() -> Result<()> {
    for target in [
        None,
        Some("../elsewhere/1"),
        Some("/elsewhere/generations/1"),
        Some("generations/0"),
    ] {
        let store = Store::new()?;
        let receipt = store.admit(true)?;
        let pointer = store.pool.join("domains/usr-home-runtime-store/current");
        fs::remove_file(&pointer)?;
        if let Some(target) = target {
            std::os::unix::fs::symlink(target, pointer)?;
        } else {
            fs::write(pointer, b"damaged pointer")?;
        }
        assert!(
            !common::run(
                &mut store.command(&["pool", "recover", "--pool-root", store.pool_text()]),
                None
            )?
            .status
            .success()
        );
        assert!(Path::new(receipt["manifest"].as_str().unwrap()).exists());
    }
    Ok(())
}

/// Mounted temporary, view and root trees remain protected in an isolated user mount namespace.
#[test]
#[ignore = "requires unprivileged user/mount namespaces and mount tools"]
fn cleanup_refuses_bind_mounts() -> Result<()> {
    let store = Store::new()?;
    store.run(&["pool", "status", "--pool-root", store.pool_text()])?;
    let source = store.temporary.path().join("mounted-source");
    fs::create_dir(&source)?;
    fs::write(source.join("sentinel"), b"preserve mounted bytes")?;
    for (target, operation) in [
        ("tmp/interrupted-mount", "recover"),
        ("views/by-closure/mounted-view", "gc"),
        ("root-artifacts/mounted-root", "gc"),
    ] {
        let target = store.pool.join(target);
        fs::create_dir_all(&target)?;
        common::run(
            Command::new("unshare")
                .args([
                    "--user",
                    "--map-root-user",
                    "--mount",
                    "--propagation",
                    "private",
                ])
                .arg(common::peer())
                .arg("recover-mounted")
                .arg(&source)
                .arg(&target)
                .arg(&store.service)
                .arg(&store.pool)
                .arg(operation),
            None,
        )?
        .checked()?;
    }
    assert_eq!(
        fs::read(source.join("sentinel"))?,
        b"preserve mounted bytes"
    );
    Ok(())
}

/// Invalid retained references must stop GC before unrelated generations or objects disappear.
#[test]
fn gc_refuses_incomplete_manifest_references_before_any_deletion() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let store = Store::new()?;
    let extra = format!("{hash}-dependency", hash = "b".repeat(32));
    fs::write(store.physical.join(&extra), b"dependency")?;
    writeln!(
        fs::OpenOptions::new()
            .append(true)
            .open(store.closure.join("store-paths"))?,
        "/nix/store/{extra}"
    )?;
    store.admit(true)?;
    store.admit(false)?;
    store.run(&[
        "pool",
        "set-retention",
        "--pool-root",
        store.pool_text(),
        "--domain",
        "usr-home-runtime-store",
        "--generation",
        "2",
        "--retain",
        "false",
    ])?;
    let first = store
        .pool
        .join("domains/usr-home-runtime-store/generations/1/manifest.json");
    let second = store
        .pool
        .join("domains/usr-home-runtime-store/generations/2/manifest.json");
    let original = read(&first)?;
    let original_second = fs::read(&second)?;
    let map = std::path::PathBuf::from(original["store"]["canonical_blob_map"].as_str().unwrap());
    let original_map = fs::read(&map)?;
    let map_permissions = fs::metadata(&map)?.permissions();
    fs::set_permissions(&map, fs::Permissions::from_mode(0o644))?;
    let object = store.system.rsplit('/').next().unwrap();
    let metadata = store.pool.join(format!("objects/metadata/{object}.json"));
    let original_metadata = fs::read(&metadata)?;
    let root = store
        .pool
        .join("root-artifacts")
        .join(original["root"]["artifact"]["sha256"].as_str().unwrap());

    for defect in [
        "missing-paths",
        "wrong-paths-type",
        "empty-paths",
        "shortened-closure",
        "wrong-view",
        "missing-root",
        "missing-artifact",
        "invalid-root",
        "missing-map-extent",
    ] {
        let mut damaged = original.clone();
        match defect {
            "missing-paths" => {
                damaged["store"].as_object_mut().unwrap().remove("paths");
            }
            "wrong-paths-type" => damaged["store"]["paths"] = json!(false),
            "empty-paths" => damaged["store"]["paths"] = json!([]),
            "shortened-closure" => {
                damaged["store"]["paths"] = json!([store.system]);
                damaged["store"]["object_count"] = json!(1);
            }
            "wrong-view" => {
                damaged["store"]["canonical_blob_map"] = json!(
                    store
                        .pool
                        .join("views/by-closure/wrong/store.blob-map.json")
                )
            }
            "missing-root" => {
                damaged.as_object_mut().unwrap().remove("root");
            }
            "missing-artifact" => {
                damaged["root"].as_object_mut().unwrap().remove("artifact");
            }
            "invalid-root" => damaged["root"]["artifact"] = json!({"sha256":"invalid"}),
            "missing-map-extent" => {
                let mut value: Value = serde_json::from_slice(&original_map)?;
                value["extents"].as_array_mut().unwrap().remove(0);
                fs::write(&map, serde_json::to_vec(&value)?)?;
            }
            _ => unreachable!(),
        }
        fs::write(&first, serde_json::to_vec(&damaged)?)?;
        for _ in 0..2 {
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
            assert!(!output.status.success(), "GC accepted {defect}");
            assert_eq!(
                fs::read(&second)?,
                original_second,
                "GC deleted unrelated generation after {defect}"
            );
            assert_eq!(fs::read(&metadata)?, original_metadata);
            assert!(root.join("root.img").is_file());
        }
        fs::write(&map, &original_map)?;
    }
    fs::write(&first, serde_json::to_vec(&original)?)?;
    fs::set_permissions(&map, map_permissions)?;
    store.run(&[
        "pool",
        "gc",
        "--pool-root",
        store.pool_text(),
        "--keep-generations",
        "0",
    ])?;
    assert!(!second.exists());
    assert_eq!(fs::read(&metadata)?, original_metadata);
    assert!(root.join("root.img").is_file());
    Ok(())
}

/// Corrupted active physical pins refuse cleanup; their original segment remains intact.
#[test]
fn gc_refuses_invalid_physical_pins_before_any_deletion() -> Result<()> {
    let store = Store::new()?;
    store.admit(true)?;
    let inactive = store.admit(false)?;
    store.run(&[
        "pool",
        "mark-running",
        "--pool-root",
        store.pool_text(),
        "--domain",
        "usr-home-runtime-store",
        "--generation",
        "1",
        "--volume",
        "store-data",
    ])?;
    let path = store
        .pool
        .join("running/usr-home-runtime-store/1/store-data.json");
    let original = read(&path)?;
    let segment = original["physical_references"][0]["segment_id"]
        .as_str()
        .unwrap();
    let blob = store.pool.join(format!("objects/segments/{segment}.blob"));
    let original_bytes = fs::read(&blob)?;
    for defect in [
        "missing-length",
        "zero-length",
        "overflow",
        "truncated-segment",
        "empty-pins",
        "invalid-segment",
    ] {
        let mut damaged = original.clone();
        match defect {
            "missing-length" => {
                damaged["physical_references"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("length");
            }
            "zero-length" => damaged["physical_references"][0]["length"] = json!(0),
            "overflow" => damaged["physical_references"][0]["offset"] = json!(u64::MAX),
            "truncated-segment" => {
                damaged["physical_references"][0]["length"] = json!(original_bytes.len() as u64 + 1)
            }
            "empty-pins" => damaged["physical_references"] = json!([]),
            "invalid-segment" => {
                damaged["physical_references"][0]["segment_id"] = json!("../outside")
            }
            _ => unreachable!(),
        }
        fs::write(&path, serde_json::to_vec(&damaged)?)?;
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
        assert!(!output.status.success(), "GC accepted {defect}");
        assert_eq!(fs::read(&blob)?, original_bytes);
    }
    fs::write(&path, serde_json::to_vec(&original)?)?;
    // A valid range belonging to a different object must not resolve this logical requirement.
    // Conflicting current locations are also rejected rather than selecting the first record.
    let name = store.system.rsplit('/').next().unwrap();
    let location_path = store
        .pool
        .join(format!("objects/blob-metadata/{name}.json"));
    let location = read(&location_path)?;
    for defect in [
        "missing-entry",
        "wrong-entry",
        "schema",
        "two-current",
        "no-current",
    ] {
        let mut damaged = location.clone();
        match defect {
            "missing-entry" => {
                damaged.as_object_mut().unwrap().remove("entry");
            }
            "wrong-entry" => damaged["entry"] = json!("other-object"),
            "schema" => damaged["schema"] = json!("unknown-location"),
            "two-current" => damaged["locations"]
                .as_array_mut()
                .unwrap()
                .push(location["locations"][0].clone()),
            "no-current" => damaged["locations"][0]["status"] = json!("retired"),
            _ => unreachable!(),
        }
        fs::write(&location_path, serde_json::to_vec(&damaged)?)?;
        let before = super::storage_integrity::snapshot(&store.pool)?;
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
            "GC accepted canonical location defect: {defect}"
        );
        assert_eq!(super::storage_integrity::snapshot(&store.pool)?, before);
        assert!(Path::new(inactive["manifest"].as_str().unwrap()).is_file());
    }
    fs::write(&location_path, serde_json::to_vec(&location)?)?;
    store.run(&[
        "pool",
        "gc",
        "--pool-root",
        store.pool_text(),
        "--keep-generations",
        "0",
    ])?;
    assert_eq!(fs::read(&blob)?, original_bytes);
    Ok(())
}

/// Interrupted admissions keep their objects without a generation manifest; malformed owners refuse GC.
#[test]
fn gc_traces_pending_admission_objects_without_silently_omitting_bad_records() -> Result<()> {
    let store = Store::new()?;
    store.admit(true)?;
    let extra = format!("{hash}-pending", hash = "b".repeat(32));
    fs::write(store.physical.join(&extra), b"pending data")?;
    writeln!(
        fs::OpenOptions::new()
            .append(true)
            .open(store.closure.join("store-paths"))?,
        "/nix/store/{extra}"
    )?;
    let output = common::run(
        store
            .admission()
            .env("AIRLOCK_CLOSURE_STORE_FAILPOINT", "object-after-metadata"),
        None,
    )?;
    assert!(!output.status.success());
    let metadata = store
        .pool
        .join(format!("objects/blob-metadata/{extra}.json"));
    let original = read(&metadata)?;
    for field in ["entry", "transaction", "schema"] {
        let mut damaged = original.clone();
        damaged.as_object_mut().unwrap().remove(field);
        fs::write(&metadata, serde_json::to_vec(&damaged)?)?;
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
            "GC ignored a pending object without {field}"
        );
        assert!(metadata.is_file());
    }
    fs::write(&metadata, serde_json::to_vec(&original)?)?;
    for _ in 0..2 {
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
            output.status.success(),
            "pending-object GC failed: {reply}",
            reply = String::from_utf8_lossy(&output.stdout)
        );
        assert_eq!(read(&metadata)?, original);
    }
    // The first admission can publish the shared terminator before any manifest
    // exists. No selected view is needed to keep that unfinished object's bytes.
    let initial = Store::new()?;
    let output = common::run(
        initial.admission().env(
            "AIRLOCK_CLOSURE_STORE_FAILPOINT",
            "generation-before-manifest",
        ),
        None,
    )?;
    assert!(!output.status.success());
    let terminator = initial.pool.join("objects/blob-metadata/.tar-eof.json");
    let original_terminator = fs::read(&terminator)?;
    let output = common::run(
        &mut initial.command(&[
            "pool",
            "gc",
            "--pool-root",
            initial.pool_text(),
            "--keep-generations",
            "0",
        ]),
        None,
    )?;
    assert!(
        output.status.success(),
        "initial-admission GC failed: {reply}",
        reply = String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(fs::read(&terminator)?, original_terminator);
    Ok(())
}
