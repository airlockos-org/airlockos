//! Retain the established smoke receipt, diagnostic files and final restored boot identity.

use super::probes::Boot;
use super::{Session, physical};
use anyhow::Result;
use serde_json::{Value, json};
use std::fs;

/// Retain useful machine observations even when the mutating scenario fails partway through.
pub(super) fn diagnostics(session: &mut Session, domain: &str, peer: &str) {
    for (program, args, name) in [
        (
            "qvm-ls",
            vec!["--raw-data", "--fields", "NAME,STATE,CLASS,LABEL,TEMPLATE"],
            "qvm-ls.log",
        ),
        ("qvm-prefs", vec![domain], "qvm-prefs.log"),
        ("qvm-features", vec![domain], "qvm-features.log"),
        ("qvm-features", vec![peer], "peer-qvm-features.log"),
        ("qvm-volume", vec!["list", domain], "qvm-volumes.log"),
        (
            "journalctl",
            vec![
                "-b",
                "--no-pager",
                "-u",
                "qubesd",
                "-u",
                "qubes-db-dom0",
                "-u",
                "qubes-qrexec-policy-daemon",
            ],
            "journal.log",
        ),
    ] {
        let _ = session.command(program, &args, &format!("nix-closure-domain-{name}"));
    }
    for (source, dest) in [
        ("/var/lib/qubes/qubes.xml", "qubes.xml"),
        ("/var/log/libvirt/libxl/libxl-driver.log", "libxl.log"),
        (
            "/var/lib/airlock/qubes-policy.d/90-airlock.policy",
            "policy.log",
        ),
    ] {
        let _ = fs::copy(source, session.file(&format!("nix-closure-domain-{dest}")));
    }
    for (source, dest) in [
        ("config-apply-topology.json", "applied-topology.json"),
        (
            "config-apply-nix-domain-materializations.json",
            "materializations.json",
        ),
        ("config-apply-nix-domain-builds.json", "builds.json"),
        ("setup-config.json", "setup.json"),
    ] {
        let _ = fs::copy(
            session.file(source),
            session.file(&format!("nix-closure-domain-{dest}")),
        );
    }
}

/// Assemble the established receipt schema from retained native scenario evidence.
pub(super) fn evidence(session: &Session, record: &mut Value) -> Result<()> {
    record["logs"] = json!({});
    record["logs"]["command"] = json!(session.file("nix-closure-domain-smoke.commands.log"));
    record["logs"]["staging_update"] = json!(session.file("nix-closure-domain-staging-update.log"));
    record["logs"]["apply"] = json!(session.file("nix-closure-domain-apply.log"));
    record["logs"]["apply_result"] = json!(session.file("nix-closure-domain-config-apply.json"));
    record["logs"]["gen2_staging_update"] =
        json!(session.file("nix-closure-domain-staging-update-gen2.log"));
    record["logs"]["gen2_apply"] = json!(session.file("nix-closure-domain-apply-gen2.log"));
    record["logs"]["gen2_apply_result"] =
        json!(session.file("nix-closure-domain-config-apply-gen2.json"));
    record["logs"]["qvm_ls"] = json!(session.file("nix-closure-domain-qvm-ls.log"));
    record["logs"]["qvm_prefs"] = json!(session.file("nix-closure-domain-qvm-prefs.log"));
    record["logs"]["qvm_features"] = json!(session.file("nix-closure-domain-qvm-features.log"));
    record["logs"]["qvm_volumes"] = json!(session.file("nix-closure-domain-qvm-volumes.log"));
    record["logs"]["root_volume"] = json!(session.file("nix-closure-domain-root-volume.log"));
    record["logs"]["store_volume"] = json!(session.file("nix-closure-domain-store-volume.log"));
    record["logs"]["peer_store_volume"] =
        json!(session.file("nix-closure-domain-peer-store-volume.log"));
    record["logs"]["kernelopts"] = json!(session.file("nix-closure-domain-kernelopts.log"));
    record["logs"]["root_image_check"] =
        json!(session.file("nix-closure-domain-root-image-check.log"));
    record["logs"]["store_view_check"] =
        json!(session.file("nix-closure-domain-store-view-check.log"));
    record["logs"]["runtime_service"] =
        json!(session.file("nix-closure-domain-runtime-service.log"));
    record["logs"]["peer_runtime_service"] =
        json!(session.file("nix-closure-domain-peer-runtime-service.log"));
    record["logs"]["guest_probe"] = json!(session.file("nix-closure-domain-guest-probe.log"));
    record["logs"]["peer_guest_probe"] =
        json!(session.file("nix-closure-domain-peer-guest-probe.log"));
    record["logs"]["visibility"] = json!(session.file("nix-closure-domain-visibility.log"));
    record["logs"]["peer_visibility"] =
        json!(session.file("nix-closure-domain-peer-visibility.log"));
    record["logs"]["sharing_proof"] = json!(session.file("nix-closure-domain-sharing-proof.json"));
    record["logs"]["gen2_sharing_proof"] =
        json!(session.file("nix-closure-domain-sharing-proof-gen2.json"));
    record["logs"]["running_status"] =
        json!(session.file("nix-closure-domain-running-status.json"));
    record["logs"]["gc_running"] = json!(session.file("nix-closure-domain-gc-running.json"));
    record["logs"]["rollback_switch"] =
        json!(session.file("nix-closure-domain-rollback-switch.json"));
    record["logs"]["rollback_identity"] =
        json!(session.file("nix-closure-domain-rollback-identity.log"));
    record["logs"]["guest_probe_after_rollback"] =
        json!(session.file("nix-closure-domain-guest-probe-after-rollback.log"));
    record["logs"]["retention"] = json!(session.file("nix-closure-domain-set-retention-gen2.json"));
    record["logs"]["gc_after_rollback"] =
        json!(session.file("nix-closure-domain-gc-after-rollback.json"));
    record["logs"]["guest_probe_after_reboot"] =
        json!(session.file("nix-closure-domain-guest-probe-after-reboot.log"));
    record["logs"]["guest_probe_after_restart"] =
        json!(session.file("nix-closure-domain-guest-probe-after-restart.log"));
    record["logs"]["persistence"] = json!(session.file("nix-closure-domain-persistence.log"));
    record["logs"]["console"] = json!(session.file("nix-closure-domain-console.log"));
    record["logs"]["journal"] = json!(session.file("nix-closure-domain-journal.log"));
    record["logs"]["libvirt_xml"] = json!(session.file("nix-closure-domain-libvirt.xml"));
    record["logs"]["peer_libvirt_xml"] = json!(session.file("nix-closure-domain-peer-libvirt.xml"));
    record["apply_result"] = fs::read(session.file("nix-closure-domain-config-apply.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or(Value::Null);
    record["setup_result"] = fs::read(session.file("nix-closure-domain-setup.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or(Value::Null);
    record["nix_domain_builds"] = fs::read(session.file("nix-closure-domain-builds.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or(Value::Null);
    record["nix_domain_materializations"] =
        fs::read(session.file("nix-closure-domain-materializations.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or(Value::Null);
    record["sharing_proof"] = fs::read(session.file("nix-closure-domain-sharing-proof.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or(Value::Null);
    record["gen2_apply_result"] =
        fs::read(session.file("nix-closure-domain-config-apply-gen2.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or(Value::Null);
    record["gen2_sharing_proof"] =
        fs::read(session.file("nix-closure-domain-sharing-proof-gen2.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or(Value::Null);
    record["running_status"] = fs::read(session.file("nix-closure-domain-running-status.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or(Value::Null);
    record["gc_running"] = fs::read(session.file("nix-closure-domain-gc-running.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or(Value::Null);
    record["rollback_switch"] = fs::read(session.file("nix-closure-domain-rollback-switch.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or(Value::Null);
    record["gc_after_rollback"] =
        fs::read(session.file("nix-closure-domain-gc-after-rollback.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or(Value::Null);
    record["runtime_service_output"] =
        fs::read_to_string(session.file("nix-closure-domain-runtime-service.log"))
            .map(Value::String)
            .unwrap_or(Value::Null);
    record["guest_probe_output"] =
        fs::read_to_string(session.file("nix-closure-domain-guest-probe.log"))
            .map(Value::String)
            .unwrap_or(Value::Null);
    Ok(())
}

/// Retain the final restored boot identity only after every selected scenario phase succeeds.
pub(super) fn boot_identity(record: &mut Value, restored: &Boot) {
    for (key, value) in [
        ("system_source", restored.system.as_str()),
        ("root_source", restored.root.as_str()),
        ("store_source", restored.store.as_str()),
        ("store_view_image", restored.view.as_str()),
        ("store_mode", "shared-closure"),
        ("store_device", restored.device.as_str()),
    ] {
        record[key] = json!(value);
    }
    for (key, value) in [
        ("root_source_physical", &restored.root),
        ("store_source_physical", &restored.store),
        ("store_view_image_physical", &restored.view),
    ] {
        record[key] = json!(physical(value));
    }
}
