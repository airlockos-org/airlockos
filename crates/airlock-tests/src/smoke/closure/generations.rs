//! Apply explicit test declarations and switch retained generations through existing storage adapters.

use super::super::config;
use super::probes::feature;
use super::{Session, common, physical, text};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{fs, process::Command};

/// Stop only an existing running target, retaining the original upstream shutdown behavior.
pub(super) fn shutdown(session: &mut Session, guest: &str, output: &str) -> Result<()> {
    if session
        .command("qvm-check", &[guest], "nix-closure-domain-exists.log")
        .is_ok()
        && session
            .command(
                "qvm-check",
                &["--running", guest],
                "nix-closure-domain-power.log",
            )
            .is_ok()
    {
        session.command("qvm-shutdown", &["--wait", guest], output)?;
    }
    Ok(())
}

/// Build a native test declaration from an existing VM's immutable artifacts, without inventing sources.
pub(super) fn declaration(session: &mut Session, source: &str, label: &str) -> Result<Value> {
    let system = feature(session, source, "airlock-system-source")?;
    let root = feature(session, source, "airlock-root-source")?;
    let store = feature(session, source, "airlock-store-source")?;
    let role = feature(session, source, "airlock-role")?;
    let kernel = session.command(
        "qvm-prefs",
        &[source, "kernel"],
        "nix-closure-domain-source-kernel.log",
    )?;
    ensure!(
        !kernel.is_empty(),
        "source domain {source} has no kernel preference"
    );
    Ok(
        json!({"class":"StandaloneVM","label":label,"netvm":null,"template":null,"prefs":{"autostart":false,"default_user":common::setting("AIRLOCK_QUBE_USER","user"),"include_in_backups":false,"kernel":kernel,"memory":1024,"maxmem":1024,"qrexec_timeout":180,"vcpus":1,"virt_mode":"pvh"},"features":{"airlock-backend":"nix-closure","airlock-role":role,"airlock-test":"nix-closure-domain","os":"Linux","qrexec":"1"},"services":{"network-manager":false},"backend":{"type":"nix-closure","template":null,"system":{"source":system,"source_ref":null},"kernel":{"name":kernel,"source":null,"source_ref":null},"initrd":{"name":null,"source":null,"source_ref":null},"modules":{"name":null,"source":null,"source_ref":null},"root":{"mode":"qubes-root-image","source":root,"source_ref":null,"read_only":false},"store":{"mode":"shared-closure","source":store,"source_ref":null,"read_only":true,"device":"/dev/xvde","blob_device":"/dev/xvdf","blobDevice":"/dev/xvdf","mountpoint":"/nix/store","view_backend":"erofs-objectmap","viewBackend":"erofs-objectmap"},"state":{"persistent":null,"volatile":null}}}),
    )
}

/// Apply one of the existing direct/config-flow test generations and retain its compatible receipt.
pub(super) fn apply(
    session: &mut Session,
    domain: &str,
    peer: &str,
    second: bool,
    mode: &str,
    staging: &str,
    message: &str,
) -> Result<Value> {
    let output = if second {
        "nix-closure-domain-config-apply-gen2.json"
    } else {
        "nix-closure-domain-config-apply.json"
    };
    if mode == "direct" {
        let primary = common::setting(
            if second {
                "AIRLOCK_NIX_CLOSURE_DIRECT_GEN2_SOURCE_VM"
            } else {
                "AIRLOCK_NIX_CLOSURE_DIRECT_PRIMARY_SOURCE_VM"
            },
            if second {
                "sys-config-vault"
            } else {
                "sys-config-staging"
            },
        );
        let peer_source = common::setting(
            "AIRLOCK_NIX_CLOSURE_DIRECT_PEER_SOURCE_VM",
            "sys-config-validator",
        );
        let mut topology = json!({"schema":"airlock.qubes-topology.v1","prefs":{},"templates":{},"kernels":{},"domains":{},"qrexec_policy":{"rules":[]}});
        topology["domains"][domain] = declaration(session, &primary, "green")?;
        topology["domains"][peer] = declaration(session, &peer_source, "blue")?;
        topology["qrexec_policy"]["rules"] = json!([{"service":"airlock.NixStoreRuntimeCheck","argument":"*","source":"dom0","target":domain,"action":"allow"},{"service":"airlock.NixStoreRuntimeCheck","argument":"*","source":"dom0","target":peer,"action":"allow"},{"service":"airlock.NixStoreRuntimeCheck","argument":"*","source":"@anyvm","target":"@anyvm","action":"deny"}]);
        let path = session.file(if second {
            "nix-closure-domain-direct-topology-gen2.json"
        } else {
            "nix-closure-domain-direct-topology.json"
        });
        common::save(&path, &topology)?;
        let setup = common::setting("AIRLOCK_SETUP_CONFIG_COMMAND", "airlock-setup-config");
        session.run(
            Command::new(setup)
                .arg("--apply")
                .arg("--topology")
                .arg(&path),
            None,
            if second {
                "nix-closure-domain-apply-gen2.log"
            } else {
                "nix-closure-domain-apply.log"
            },
        )?;
        let setup: Value = serde_json::from_slice(&fs::read(session.file("setup-config.json"))?)?;
        ensure!(
            setup["status"] == "passed",
            "direct native setup did not pass"
        );
        let record = json!({"schema":"airlock.config-apply.v1","status":"passed","reason":"direct nix-closure topology setup","topology":path,"setup":setup,"nix_domain_materializations_result":{"domains":[{"domain":domain},{"domain":peer}]}});
        common::save(&session.file(output), &record)?;
        Ok(record)
    } else {
        let user = common::setting("AIRLOCK_QUBE_USER", "user");
        let repo = format!("/home/{user}/airlock-config");
        if second {
            let mut inputs: Value = serde_json::from_str(&session.remote(
                staging,
                "cat",
                &[&format!("{repo}/smoke-inputs.json")],
                None,
                "nix-closure-domain-gen2-inputs.log",
            )?)?;
            inputs["message"] = json!(message);
            session.remote(
                staging,
                "tee",
                &[&format!("{repo}/smoke-inputs.json")],
                Some(serde_json::to_vec(&inputs)?),
                "nix-closure-domain-staging-update-gen2.log",
            )?;
            session.remote(
                staging,
                "git",
                &["-C", &repo, "add", "src", "smoke-inputs.json"],
                None,
                "nix-closure-domain-gen2-add.log",
            )?;
            session.remote(
                staging,
                "git",
                &[
                    "-C",
                    &repo,
                    "-c",
                    "user.name=Airlock Closure Smoke",
                    "-c",
                    "user.email=airlock-closure-smoke@localhost",
                    "commit",
                    "-m",
                    "update nix closure smoke domain generation",
                ],
                None,
                "nix-closure-domain-staging-update-gen2.log",
            )?;
        } else {
            config::stage(
                session,
                staging,
                &json!({"created":domain,"peer":peer,"message":message,"peerMessage":message,"action":"switch"}),
                "add nix closure smoke domain",
            )?;
        }
        session.run(
            Command::new("airlock-config-apply").arg("--apply").env(
                "AIRLOCK_CONFIG_APPLY_NIX_OFFLINE",
                common::setting("AIRLOCK_CONFIG_APPLY_NIX_OFFLINE", "0"),
            ),
            None,
            if second {
                "nix-closure-domain-apply-gen2.log"
            } else {
                "nix-closure-domain-apply.log"
            },
        )?;
        let record: Value = serde_json::from_slice(&fs::read(session.file("config-apply.json"))?)?;
        common::save(&session.file(output), &record)?;
        Ok(record)
    }
}

/// Read one pool JSON result while retaining diagnostics separately from its parsed receipt.
pub(super) fn pool(session: &mut Session, args: &[&str], output: &str) -> Result<Value> {
    let stdout = session.run(
        Command::new("airlock-dom0-service")
            .args(["storage", "pool"])
            .args(args),
        None,
        &format!("{output}.log"),
    )?;
    let value = serde_json::from_str(&stdout)?;
    common::save(&session.file(output), &value)?;
    Ok(value)
}

/// Check exact generation membership in one pool report field.
pub(super) fn contains(value: &Value, key: &str, domain: &str, generation: u64) -> bool {
    value[key].as_array().is_some_and(|entries| {
        entries.iter().any(|entry| {
            entry["domain"] == format!("{domain}-runtime-store")
                && entry["generation"] == generation
        })
    })
}

/// Restore the boot metadata returned by the existing stopped-domain generation switch adapter.
pub(super) fn restore(session: &mut Session, domain: &str, generation: u64) -> Result<()> {
    let stdout = session.command(
        "airlock-dom0-service",
        &[
            "storage",
            "domain",
            "switch-store",
            domain,
            &generation.to_string(),
        ],
        "nix-closure-domain-rollback-switch.stdout",
    )?;
    fs::write(
        session.file("nix-closure-domain-rollback-switch.stdout"),
        stdout,
    )?;
    session.run(
        Command::new("airlock-test-report")
            .arg("extract")
            .arg("--any")
            .arg(session.file("nix-closure-domain-rollback-switch.stdout"))
            .arg(session.file("nix-closure-domain-rollback-switch.json")),
        None,
        "nix-closure-domain-rollback-extract.log",
    )?;
    let selected: Value = serde_json::from_slice(&fs::read(
        session.file("nix-closure-domain-rollback-switch.json"),
    )?)?;
    ensure!(
        selected["generation"] == generation,
        "switch selected a different retained generation"
    );
    let get = |key: &str, default: &str| selected[key].as_str().unwrap_or(default).to_owned();
    let system = text(&selected, "system")?;
    let root = get("root_source", "");
    if !root.is_empty() {
        let root = physical(&root);
        let root = if root.is_dir() {
            root.join("root.img")
        } else {
            root
        };
        ensure!(root.is_file(), "rollback root image is missing");
        session.run(
            Command::new("qvm-volume")
                .args(["import", &format!("{domain}:root")])
                .arg(root),
            None,
            "nix-closure-domain-rollback-root.log",
        )?;
    }
    let kernel = get("kernel_name", "");
    if !kernel.is_empty() {
        session.command(
            "qvm-prefs",
            &[domain, "kernel", &kernel],
            "nix-closure-domain-rollback-kernel.log",
        )?;
    }
    let filesystem = get("filesystem", "erofs");
    let blob = get("blob_device", "/dev/xvdf");
    let options = format!(
        "console=hvc0 init=/sbin/init airlock.system={system} airlock.storedev=/dev/xvde airlock.storefmt={filesystem}{suffix}",
        suffix = if filesystem == "erofs" {
            format!(" airlock.storeblobdev={blob}")
        } else {
            String::new()
        }
    );
    session.command(
        "qvm-prefs",
        &[domain, "kernelopts", &options],
        "nix-closure-domain-rollback-kernelopts.log",
    )?;
    let mut features = vec![
        ("system-source", system.into()),
        ("root-source", root),
        ("store-source", get("source", "")),
        ("store-mode", "shared-closure".into()),
        ("store-view-backend", get("view_backend", "erofs-objectmap")),
        ("store-filesystem", filesystem.clone()),
        ("store-generation", generation.to_string()),
        ("store-closure-hash", get("closure_hash", "")),
        (
            "store-view-image",
            get("view_image", &get("metadata_image", "")),
        ),
        ("store-mountpoint", "/nix/store".into()),
        ("store-device", "/dev/xvde".into()),
        ("store-read-only", "True".into()),
    ];
    if filesystem == "erofs" {
        features.extend([
            ("store-blob-device", blob),
            ("store-blob-volume", get("blob_volume", "")),
            ("store-blob-map", get("blob_map", "")),
        ]);
    }
    for (name, value) in features {
        session.command(
            "qvm-features",
            &[domain, &format!("airlock-{name}"), &value],
            "nix-closure-domain-rollback-identity.log",
        )?;
    }
    Ok(())
}
