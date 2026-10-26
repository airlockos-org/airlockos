//! Whole-machine transactions bind human review, pool identities and durable recovery state.

pub(super) mod fixture;

mod hermit;

use crate::common;
use anyhow::{Context, Result, ensure};
use fixture::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

/// Require a rejected action to expose the intended guard rather than a later incidental failure.
fn error(value: &Value, expected: &str) {
    assert!(
        value["error"].as_str().unwrap().contains(expected),
        "{value}"
    );
}

/// The foreground set includes the home VM's inherited network path while leaving the controller deferred.
#[test]
fn foreground_boot_includes_home_and_its_network_dependencies() -> Result<()> {
    let mut home = declaration("usr-home", 1);
    home["features"]["airlock-boot-foreground"] = json!("1");
    home.as_object_mut().unwrap().remove("netvm");
    home["prefs"]["guivm"] = json!("sys-gui");
    let mut firewall = declaration("sys-firewall", 1);
    firewall["netvm"] = json!("sys-net");
    let mut controller = declaration("sys-ctrl", 1);
    controller["prefs"]["autostart"] = json!(false);
    let raw = json!({"schema":"airlock.qubes-topology.v1", "prefs":{"default_netvm":"sys-firewall"}, "domains":{
        "sys-gui":declaration("sys-gui", 1), "usr-home":home,
        "sys-net":declaration("sys-net", 1), "sys-firewall":firewall, "sys-ctrl":controller
    }});
    let inputs = airlock_machine_core::boot::BootInputs::new(raw.clone())?;
    let names = airlock_machine_core::boot::foreground_guests(inputs.topology())?;
    let names = names.iter().map(|name| name.as_str()).collect::<Vec<_>>();
    assert_eq!(names.len(), 4);
    assert!(names.contains(&"sys-gui"));
    let position = |name| names.iter().position(|value| *value == name).unwrap();
    assert!(position("sys-net") < position("sys-firewall"));
    assert!(position("sys-firewall") < position("usr-home"));

    let mut malformed = raw;
    malformed["domains"]["usr-home"]["features"]["airlock-boot-foreground"] = json!(true);
    let malformed = airlock_machine_core::boot::BootInputs::new(malformed)?;
    assert!(airlock_machine_core::boot::foreground_guests(malformed.topology()).is_err());
    Ok(())
}

/// Review, preparation, activation and verification share one approval and do not repeat completed work.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_review_apply_and_verify_share_one_durable_approval() -> Result<()> {
    let machine = Machine::new()?;
    let identity = machine.approve(None)?;
    let prepared = machine.run(&["prepared-check", &machine.candidate], None, true)?;
    let result = machine.run(
        &[
            "apply",
            &machine.candidate,
            "--expected-state",
            prepared["state"].as_str().unwrap(),
        ],
        None,
        true,
    )?;
    assert_eq!(result["phase"], "complete");
    assert_eq!(
        result["observed"]["usr-home"]["running"],
        store("usr-home-system", 2)
    );
    assert_eq!(
        machine.run(
            &["review-control"],
            Some(json!({"op": "status", "request_id": identity})),
            true
        )?["status"],
        "deployment_started"
    );
    assert_eq!(machine.run(&["verify"], None, true)?["phase"], "complete");
    let shutdowns = |calls: Vec<Value>| {
        calls
            .iter()
            .filter(|call| call[0] == "qvm-shutdown")
            .count()
    };
    assert_eq!(shutdowns(machine.calls()?), 1);
    machine.run(&["apply", &machine.candidate], None, true)?;
    assert_eq!(shutdowns(machine.calls()?), 1);
    let transactions = fs::read_dir(machine.path("machine/transactions"))?;
    assert!(
        transactions
            .filter_map(std::result::Result::ok)
            .any(|entry| entry.path().join("commands").is_dir())
    );
    Ok(())
}

/// Missing approval and a changed prepared snapshot both fail before publishing an activation transaction.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_unapproved_or_stale_candidates_cannot_disrupt_vms() -> Result<()> {
    let mut machine = Machine::new()?;
    error(
        &machine.run(&["apply", &machine.candidate], None, false)?,
        "human-approved",
    );
    assert!(!machine.calls()?.iter().any(|call| {
        ["qvm-shutdown", "qvm-start", "nix-env"]
            .iter()
            .any(|command| call[0] == *command)
    }));
    machine.approve(None)?;
    let prepared = machine.run(&["prepared-check", &machine.candidate], None, true)?;
    machine.data["running"] = json!([]);
    machine.persist()?;
    error(
        &machine.run(
            &[
                "apply",
                &machine.candidate,
                "--expected-state",
                prepared["state"].as_str().unwrap(),
            ],
            None,
            false,
        )?,
        "stale",
    );
    assert!(!machine.path("machine/latest.json").exists());
    Ok(())
}

/// Failed setup remains audited; resume and rollback use the original approval without hiding the failure.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_failed_setup_has_durable_resume_and_rollback() -> Result<()> {
    for (recovery, native_v1) in [("resume", false), ("rollback", false), ("resume", true)] {
        let mut machine = Machine::new()?;
        let request = machine.approve(None)?;
        machine.data["fail"] = json!("airlock-setup-config");
        machine.persist()?;
        machine.run(&["apply", &machine.candidate], None, false)?;
        let mut failed = read(machine.path("machine/latest.json"))?;
        assert_eq!(failed["phase"], "failed");
        assert_eq!(failed["failed_phase"], "configuring");
        if native_v1 {
            // Historical V1 journals and approvals predate the stable operation field.
            failed.as_object_mut().unwrap().remove("operation");
            failed.as_object_mut().unwrap().remove("guest_generations");
            failed["native_coordinator"] = json!("airlock-dom0-service-v1");
            save(machine.path("machine/latest.json"), &failed)?;
            save(
                machine.path(&format!(
                    "machine/transactions/{id}/status.json",
                    id = failed["id"].as_str().unwrap()
                )),
                &failed,
            )?;
            let path = machine.path(&format!("machine/reviews/requests/{request}.json"));
            let mut approval = read(&path)?;
            approval
                .as_object_mut()
                .unwrap()
                .remove("deployment_operation");
            save(path, &approval)?;
        }
        error(
            &machine.run(&["boot-setup", SETUP, "--apply"], None, false)?,
            "interrupted",
        );
        save(
            machine.path("etc/generation-retention.json"),
            &json!({"enabled": true}),
        )?;
        save(
            machine.path("machine/maintenance/pending.json"),
            &json!({"key": "f".repeat(64)}),
        )?;
        error(
            &machine.run(&["generation-maintenance"], None, false)?,
            "verification",
        );
        let refused = machine.run(
            &["review-control"],
            Some(json!({"op": "context", "revision": "1".repeat(40),
            "lock_hash": lock_hash(), "family": "machine", "target": null})),
            false,
        )?;
        error(&refused, "older deployment");

        machine.reload()?;
        machine.data.as_object_mut().unwrap().remove("fail");
        machine.persist()?;
        let result = machine.run(&[recovery], None, true)?;
        assert_eq!(result["phase"], "complete");
        assert_eq!(result["recovery_of"], failed["id"]);
        if native_v1 {
            assert_eq!(result["operation"]["id"], failed["id"]);
        }
        let record = read(machine.path(&format!(
            "machine/transactions/{id}/status.json",
            id = failed["id"].as_str().unwrap()
        )))?;
        assert_eq!(record["recovered_by"], result["id"]);
        if recovery == "rollback" {
            assert_eq!(result["release"], machine.baseline);
            assert_eq!(
                result["observed"]["usr-home"]["running"],
                store("usr-home-system", 1)
            );
        }
    }
    Ok(())
}

/// A successful preflight cannot authorise boot work after the publication response changes.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_host_generation_handoff_rejects_changed_publication() -> Result<()> {
    for field in ["system", "generation", "metadata_image_sha256", "schema"] {
        let mut machine = Machine::new()?;
        machine.approve(None)?;
        let mut changed = machine.data["host_pool"].clone();
        changed[field] = match field {
            "system" => json!("/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-other-host"),
            "generation" => json!(2),
            "metadata_image_sha256" => json!("e".repeat(64)),
            "schema" => json!("unexpected.receipt"),
            _ => unreachable!(),
        };
        machine.data["host_response_after_preflight"] = changed;
        machine.data["host_validations"] = json!(0);
        machine.persist()?;

        let rejected = machine.run(&["apply", &machine.candidate], None, false)?;
        error(
            &rejected,
            if field == "schema" {
                "unknown variant"
            } else {
                "host generation differs"
            },
        );

        let calls = machine.calls()?;
        assert!(
            !calls.iter().any(|call| call[0] == "nix-env"
                || call[0] == "qvm-shutdown"
                || (call[0] == "storage-host" && call[1] == "install-boot")),
            "accepted {field}"
        );
    }
    Ok(())
}

/// Real coordinator crashes leave uncertain effects; recovery reobserves them under the original operation.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_crashes_reconcile_selected_and_observed_generations() -> Result<()> {
    let points = [
        (
            json!(["storage-host", "checkpoint-machine"]),
            "host-boot-preparation",
            "rollback",
        ),
        (json!("qvm-shutdown"), "stopping", "resume"),
        (json!("airlock-setup-config"), "configuring", "rollback"),
        (json!("qvm-start"), "starting", "resume"),
        (
            json!(["storage-host", "select", HOST]),
            "host-boot-selection",
            "resume",
        ),
    ];
    for (point, phase, recovery) in points {
        let mut machine = Machine::new()?;
        machine.approve(None)?;
        machine.data["crash_after"] = point;
        machine.persist()?;
        let output = common::run(&mut machine.command(&["apply", &machine.candidate])?, None)?;
        assert!(!output.status.success());
        let interrupted = read(machine.path("machine/latest.json"))?;
        assert_eq!(interrupted["phase"], phase);
        error(
            &machine.run(&["boot-setup", SETUP, "--apply"], None, false)?,
            "interrupted",
        );
        machine.reload()?;
        machine.data.as_object_mut().unwrap().remove("crash_after");
        machine.persist()?;
        let restored = machine.run(&[recovery], None, true)?;
        assert_eq!(restored["phase"], "complete");
        assert_eq!(restored["operation"], interrupted["operation"]);
        assert_eq!(restored["recovery_of"], interrupted["id"]);
        assert_eq!(
            restored["previous"],
            if recovery == "rollback" {
                machine.candidate.as_str()
            } else {
                machine.baseline.as_str()
            }
        );
        assert_eq!(
            restored["observed"]["usr-home"]["running"],
            store(
                "usr-home-system",
                if recovery == "rollback" { 1 } else { 2 }
            )
        );
    }
    Ok(())
}

/// Interrupted rollback keeps both endpoints even after the selection and Qubes generations change.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_repeated_recovery_preserves_rollback_pair() -> Result<()> {
    let mut machine = Machine::new()?;
    machine.approve(None)?;
    let mut original = None;
    for (command, point) in [
        ("apply", "qvm-start"),
        ("rollback", "airlock-setup-config"),
        ("resume", "qvm-start"),
    ] {
        machine.data["crash_after"] = json!(point);
        machine.persist()?;
        let arguments = if command == "apply" {
            vec![command, &machine.candidate]
        } else {
            vec![command]
        };
        let output = common::run(&mut machine.command(&arguments)?, None)?;
        assert!(!output.status.success());
        let record = read(machine.path("machine/latest.json"))?;
        if let Some(operation) = &original {
            assert_eq!(&record["operation"], operation);
        } else {
            original = Some(record["operation"].clone());
        }
        if command != "apply" {
            assert_eq!(record["release"], machine.baseline);
            assert_eq!(record["previous"], machine.candidate);
        }
        machine.reload()?;
    }
    machine.data.as_object_mut().unwrap().remove("crash_after");
    machine.persist()?;
    let record = machine.run(&["resume"], None, true)?;
    assert_eq!(record["phase"], "complete");
    assert_eq!(record["operation"], original.unwrap());
    assert_eq!(
        record["observed"]["usr-home"]["running"],
        store("usr-home-system", 1)
    );
    Ok(())
}

/// A target restarted after shutdown cannot slip through into VM configuration.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_runtime_races_and_uncertain_outcomes_require_reconciliation() -> Result<()> {
    let mut machine = Machine::new()?;
    machine.approve(None)?;
    machine.data["restart_after_shutdown"] = json!(true);
    machine.persist()?;
    error(
        &machine.run(&["apply", &machine.candidate], None, false)?,
        "shutdown is incomplete",
    );
    assert!(
        !machine
            .calls()?
            .iter()
            .any(|call| call[0] == "airlock-setup-config")
    );
    machine.reload()?;
    machine
        .data
        .as_object_mut()
        .unwrap()
        .remove("restart_after_shutdown");
    machine.data["fail_after"] = json!("airlock-setup-config");
    machine.persist()?;
    machine.run(&["resume"], None, false)?;
    machine.reload()?;
    assert_eq!(machine.data["selected"]["usr-home"], 2);
    let failed = read(machine.path("machine/latest.json"))?;
    assert_eq!(failed["failed_phase"], "configuring");
    machine.data.as_object_mut().unwrap().remove("fail_after");
    machine.data["power_states"] = json!({"usr-home": "Paused"});
    machine.persist()?;
    let calls = machine.calls()?.len();
    machine.run(&["resume"], None, false)?;
    assert!(!machine.calls()?[calls..].iter().any(|call| {
        [
            "qvm-shutdown",
            "qvm-start",
            "airlock-setup-config",
            "nix-env",
        ]
        .iter()
        .any(|name| call[0] == *name)
    }));
    machine.data.as_object_mut().unwrap().remove("power_states");
    machine.persist()?;
    assert_eq!(machine.run(&["resume"], None, true)?["phase"], "complete");
    Ok(())
}

/// Corrupt selection cannot redirect recovery or grant permission for any external deployment request.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_conflicting_recovery_records_fail_before_effects() -> Result<()> {
    let mut machine = Machine::new()?;
    machine.approve(None)?;
    machine.data["fail"] = json!("airlock-setup-config");
    machine.persist()?;
    machine.run(&["apply", &machine.candidate], None, false)?;
    let path = machine.path("machine/selection.json");
    let original = read(&path)?;
    let third = machine.release("candidates/third", 1)?;
    for (field, value) in [
        ("release", third),
        ("previous", machine.candidate.clone()),
        ("transaction", "999999".into()),
    ] {
        let mut invalid = original.clone();
        invalid[field] = json!(value);
        save(&path, &invalid)?;
        let before = machine.calls()?.len();
        machine.run(&["resume"], None, false)?;
        machine.run(&["rollback"], None, false)?;
        assert_eq!(machine.calls()?.len(), before);
    }
    fs::write(&path, b"{broken")?;
    let before = machine.calls()?.len();
    machine.run(&["resume"], None, false)?;
    assert_eq!(machine.calls()?.len(), before);
    save(&path, &original)?;
    // Missing initial selection is ambiguous about completion, but not about the two possible releases.
    fs::remove_file(&path)?;
    let before = machine.calls()?.len();
    error(
        &machine.run(&["verify"], None, false)?,
        "deployment history exists without a selection",
    );
    assert_eq!(machine.calls()?.len(), before);
    machine.reload()?;
    machine.data.as_object_mut().unwrap().remove("fail");
    machine.persist()?;
    let restored = machine.run(&["rollback"], None, true)?;
    assert_eq!(restored["previous"], machine.candidate);
    assert_eq!(restored["phase"], "complete");
    Ok(())
}

/// Lock contention reports its owner, but read-only review status remains available during validation.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_machine_lock_preserves_readable_review_status() -> Result<()> {
    let mut machine = Machine::new()?;
    let identity = machine.approve(None)?;
    machine.data["delay"] = json!("storage-host");
    machine.persist()?;
    let replies = common::json(
        &mut machine.program(
            Path::new("/var/lib/airlock/bin/machine-lock-race"),
            &[&machine.candidate, &identity],
        )?,
        None,
    )?;
    assert_eq!(replies[0]["lock"]["held"], true, "{replies}");
    assert_eq!(replies[0]["lock"]["owner"], "Candidate validation");
    assert_eq!(replies[1]["status"], "busy");
    assert!(
        replies[1]["lock"]["reason"]
            .as_str()
            .is_some_and(|reason| !reason.is_empty())
    );
    Ok(())
}

/// Reviews reject a changed baseline, source identity or authorized VM scope before candidate binding.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_source_reviews_are_bound_to_baseline_revision_and_scope() -> Result<()> {
    for change in ["host", "revision", "scope"] {
        let machine = Machine::new()?;
        let context = machine.context("machine", None)?;
        if change == "host" {
            let path = machine.physical(&machine.baseline).join("release.json");
            let mut value = read(&path)?;
            value["revision"] = json!("1".repeat(40));
            save(path, &value)?;
            let result = machine.run(&["review-control"], Some(json!({"op": "decide", "request_id": context["request_id"],
                "decision": "approve", "scope": context["scope"], "review_fingerprint": "f".repeat(64)})), false)?;
            error(&result, "stale_review");
            continue;
        }
        machine.decide(
            &context,
            if change == "scope" {
                Some(json!({"allowed_vms": ["sys-gui"], "allow_reboot": true}))
            } else {
                None
            },
        )?;
        if change == "revision" {
            let path = machine.physical(&machine.candidate).join("release.json");
            let mut value = read(&path)?;
            value["revision"] = json!("1".repeat(40));
            save(path, &value)?;
        }
        let result = machine.run(
            &[
                "review-bind",
                context["request_id"].as_str().unwrap(),
                &machine.candidate,
            ],
            None,
            false,
        )?;
        error(
            &result,
            if change == "revision" {
                "source differs"
            } else {
                "scope"
            },
        );
    }
    Ok(())
}

/// Admission binds the controller and exact candidate; its helper emits exactly one final protocol reply.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_pool_admission_checks_caller_binding_and_final_reply() -> Result<()> {
    let machine = Machine::new()?;
    error(
        &machine.run(
            &[
                "admission-prepare",
                &machine.candidate,
                "--caller",
                "usr-assistant",
            ],
            None,
            false,
        )?,
        "requires sys-ctrl",
    );
    let prepared = machine.run(
        &[
            "admission-prepare",
            &machine.candidate,
            "--caller",
            "sys-ctrl",
        ],
        None,
        true,
    )?;
    let path = machine.physical(&machine.candidate).join("release.json");
    let mut value = read(&path)?;
    value["revision"] = json!("1".repeat(40));
    save(path, &value)?;
    let admission = format!(
        "{identity}.usr-home",
        identity = prepared["admission"].as_str().unwrap()
    );
    let result = machine.run(
        &["admission-receive", &admission, "--caller", "sys-ctrl"],
        None,
        false,
    )?;
    assert_eq!(result["schema"], "airlock.pool-artifact-error.v1");
    error(&result, "changed");

    for failed in [false, true] {
        let mut machine = Machine::new()?;
        let prepared = machine.run(
            &[
                "admission-prepare",
                &machine.candidate,
                "--caller",
                "sys-ctrl",
            ],
            None,
            true,
        )?;
        machine.data["artifact_error"] = json!(failed);
        machine.persist()?;
        let admission = format!(
            "{identity}.usr-home",
            identity = prepared["admission"].as_str().unwrap()
        );
        let result = machine.run(
            &["admission-receive", &admission, "--caller", "sys-ctrl"],
            None,
            !failed,
        )?;
        assert_eq!(
            result["schema"],
            if failed {
                "airlock.pool-artifact-error.v1"
            } else {
                "airlock.closure-store.admission.v1"
            }
        );
    }
    Ok(())
}

/// Candidate materialization checks exact pool receipts and keeps the unchanged host while clearing copy intent.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_candidate_binding_checks_pool_identity_and_baseline() -> Result<()> {
    let machine = Machine::new()?;
    let mut receipt = machine.receipt();
    save(machine.path("receipts.json"), &json!({"usr-home": receipt}))?;
    for name in [
        "release.json",
        "topology.json",
        "staged.json",
        "root-artifacts.json",
    ] {
        fs::copy(
            machine.physical(&machine.candidate).join(name),
            machine.path("host").join(name),
        )?;
    }
    let result = machine.run(
        &["machine-bind", HOST, "/var/lib/airlock/receipts.json"],
        None,
        true,
    )?;
    let candidate = machine.physical(result["candidate"].as_str().unwrap());
    assert_eq!(read(candidate.join("staged.json"))?, json!({"usr-home": 2}));
    assert_eq!(
        read(candidate.join("release.json"))?["guestProvenance"]["usr-home"]["revision"],
        "e".repeat(40)
    );
    assert_eq!(
        machine.run(
            &["machine-bind", HOST, "/var/lib/airlock/receipts.json"],
            None,
            true
        )?["candidate"],
        result["candidate"]
    );
    receipt["manifest"] = json!(format!(
        "{path}-substituted",
        path = receipt["manifest"].as_str().unwrap()
    ));
    save(machine.path("receipts.json"), &json!({"usr-home": receipt}))?;
    error(
        &machine.run(
            &["machine-bind", HOST, "/var/lib/airlock/receipts.json"],
            None,
            false,
        )?,
        "identity mismatch",
    );

    let machine = Machine::new()?;
    let baseline_path = machine.physical(&machine.baseline).join("release.json");
    let mut baseline = read(&baseline_path)?;
    baseline["retireDomains"] = json!(["usr-old"]);
    baseline["privateVolumeCopies"] = json!({"usr-home": "usr-old"});
    save(baseline_path, &baseline)?;
    save(machine.path("receipt.json"), &machine.receipt())?;
    let result = machine.run(&["guest-plan", "/var/lib/airlock/receipt.json"], None, true)?;
    let manifest = read(
        machine
            .physical(result["candidate"].as_str().unwrap())
            .join("release.json"),
    )?;
    assert_eq!(manifest["host"], HOST);
    assert_eq!(manifest["retireDomains"], json!([]));
    assert_eq!(manifest["privateVolumeCopies"], json!({}));
    assert_eq!(result["plan"]["changed"], json!(["usr-home"]));
    Ok(())
}

/// Scoped boot overlaps home and assistant, joins readiness once and checks storage before cache reuse.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_boot_cache_checks_persistent_disks_before_reuse() -> Result<()> {
    let mut machine = Machine::new()?;
    let path = machine.physical(&machine.baseline).join("topology.json");
    let mut topology = read(&path)?;
    topology["domains"]["usr-home"]["features"]["airlock-boot-foreground"] = json!("1");
    let mut assistant = declaration("usr-assistant", 1);
    assistant["features"]["airlock-role"] = json!("usr-assistant");
    assistant["prefs"]["guivm"] = json!("sys-gui");
    topology["domains"]["usr-assistant"] = assistant;
    save(&path, &topology)?;
    machine.configure_boot(false)?;
    machine.data["boot_unit_states"] = json!({
        "usr-home":["inactive", "active"], "usr-assistant":["activating", "active"]
    });
    machine.persist()?;
    let first = machine.run(&["boot-setup", "--gui", SETUP, "--apply"], None, true)?;
    assert_eq!(first["scope"], "gui");
    assert_eq!(first["reused"], false);
    assert!(
        first["domains"]
            .as_array()
            .unwrap()
            .contains(&json!("usr-home"))
    );
    assert!(
        first["domains"]
            .as_array()
            .unwrap()
            .contains(&json!("usr-assistant"))
    );
    let calls = machine.calls()?;
    let starts = calls
        .iter()
        .filter(|call| call[0] == "systemctl" && call[1] == "start")
        .collect::<Vec<_>>();
    assert_eq!(
        starts,
        vec![
            &json!([
                "systemctl",
                "start",
                "--no-block",
                "airlock-boot-guest@usr-home.service"
            ]),
            &json!([
                "systemctl",
                "start",
                "--no-block",
                "airlock-boot-guest@usr-assistant.service"
            ])
        ]
    );
    // Home may finish while the assistant remains in progress. The foreground
    // command must neither join its readiness nor start it a second time.
    assert!(!calls.iter().any(|call| call[0] == "systemctl"
        && call[1] == "show"
        && call.as_array().unwrap().last()
            == Some(&json!("airlock-boot-guest@usr-assistant.service"))));
    assert_eq!(
        read(machine.path("data.json"))?["boot_unit_states"]["usr-assistant"],
        json!(["activating", "active"])
    );

    assert_eq!(
        machine.run(
            &["boot-setup", "--background", SETUP, "--apply"],
            None,
            true
        )?["status"],
        "passed"
    );

    machine.data = read(machine.path("data.json"))?;
    machine.data["boot_unit_states"]["usr-assistant"] = json!(["failed"]);
    machine.persist()?;
    error(
        &machine.run(&["boot-start"], None, false)?,
        "usr-assistant startup unit is failed",
    );

    machine.data = read(machine.path("data.json"))?;
    machine.data["boot_unit_states"]["usr-assistant"] = json!(["activating", "active"]);
    machine.persist()?;
    machine.run(&["boot-start"], None, true)?;
    assert!(
        !machine.calls()?.iter().any(|call| call[0] == "qvm-start"
            && call.as_array().unwrap().contains(&json!("usr-assistant"))),
        "background must join the submitted job"
    );

    assert_eq!(
        machine.run(&["boot-setup", "--gui", SETUP, "--apply"], None, true)?["reused"],
        true
    );
    fs::remove_file(machine.path("sys-gui-private.img"))?;
    let result = machine.run(&["boot-setup", "--gui", SETUP, "--apply"], None, false)?;
    let message = result["error"].as_str().unwrap();
    assert!(message.contains("No such file") || message.contains("missing"));

    let mut machine = Machine::new()?;
    machine.configure_boot(false)?;
    machine.run(&["boot-setup", "--gui", SETUP, "--apply"], None, true)?;
    machine.configure_boot(true)?;
    error(
        &machine.run(&["boot-setup", "--gui", SETUP, "--apply"], None, false)?,
        "persistent disk",
    );
    Ok(())
}

/// Pruning requires exact confirmation and rechecks selected and manually retained recovery references.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_release_pruning_protects_recovery_references() -> Result<()> {
    let machine = Machine::new()?;
    machine.approve(None)?;
    machine.run(&["apply", &machine.candidate], None, true)?;
    error(
        &machine.run(
            &["release-prune", &machine.candidate, "--confirm", "wrong"],
            None,
            false,
        )?,
        "confirmation",
    );
    assert!(
        machine.run(&["release-prune-plan", &machine.candidate], None, true)?["blockers"]
            .as_array()
            .unwrap()
            .contains(&json!("selected release"))
    );
    error(
        &machine.run(
            &["trash-purge", "123-usr-home", "--confirm", "other"],
            None,
            false,
        )?,
        "confirmation",
    );
    assert!(!machine.path("machine/pruned-releases").exists());

    let old = machine.release("candidates/obsolete", 1)?;
    let path = machine.physical(&old).join("release.json");
    let mut manifest = read(&path)?;
    manifest["host"] = json!(store("obsolete-host", 2));
    save(path, &manifest)?;
    let mut transaction = read(machine.path("machine/latest.json"))?;
    transaction["id"] = json!("123");
    transaction["release"] = json!(old);
    transaction["previous"] = json!(machine.baseline);
    save(
        machine.path("machine/transactions/123/status.json"),
        &transaction,
    )?;
    machine.run(&["release-retain", &old, "--retain", "true"], None, true)?;
    assert!(
        machine.run(&["release-prune-plan", &old], None, true)?["blockers"]
            .as_array()
            .unwrap()
            .contains(&json!("explicitly retained rollback choice"))
    );
    machine.run(&["release-retain", &old, "--retain", "false"], None, true)?;
    for _ in 0..2 {
        assert_eq!(
            machine.run(&["release-prune", &old, "--confirm", &old], None, true)?["status"],
            "pruned"
        );
    }
    Ok(())
}

/// Automatic collection runs only after selected generations pass verification and clears its durable pending marker.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_maintenance_follows_verification_and_detects_wrong_runtime() -> Result<()> {
    let mut machine = Machine::new()?;
    let manifest_path = machine.physical(&machine.candidate).join("release.json");
    let mut manifest = read(&manifest_path)?;
    manifest["staged_generations"] = json!({});
    save(&manifest_path, &manifest)?;
    machine.approve(None)?;
    machine.run(&["apply", &machine.candidate], None, true)?;
    save(
        machine.path("etc/generation-retention.json"),
        &json!({"enabled": true}),
    )?;
    fs::rename(
        machine.path("etc/generation-retention.json"),
        machine.path("host/etc/airlock/generation-retention.json"),
    )?;
    symlink(
        "/run/current-system/etc/airlock/generation-retention.json",
        machine.path("etc/generation-retention.json"),
    )?;
    machine.run(&["verify"], None, true)?;
    machine.run(&["release-list"], None, true)?;
    assert!(machine.path("machine/maintenance/pending.json").is_file());
    let result = machine.run(&["generation-maintenance"], None, true)?;
    assert_eq!(result["status"], "passed");
    assert_eq!(result["gc"]["status"], "passed");
    assert!(machine.calls()?.iter().any(|call| call[0] == "storage-pool"
        && call.as_array().unwrap().windows(2).any(|pair| pair
            == [
                json!("--protect-generation"),
                json!("usr-home-runtime-store:2")
            ])));
    assert!(!machine.path("machine/maintenance/pending.json").exists());
    assert_eq!(
        machine.run(&["generation-maintenance"], None, true)?["status"],
        "idle"
    );

    // Snapshot omissions cannot silently turn into an empty protection set on a later cleanup.
    machine.run(&["verify"], None, true)?;
    let last_cleaned = machine.path("machine/maintenance/last-cleaned-generation.json");
    fs::remove_file(&last_cleaned)?;
    machine.run(&["verify"], None, true)?;
    let journal_path = machine.path("machine/latest.json");
    let original = read(&journal_path)?;
    let history = machine.path(&format!(
        "machine/transactions/{id}/status.json",
        id = original["id"].as_str().unwrap()
    ));
    let mut omitted = original.clone();
    omitted["guest_generations"][0]["entries"] = json!([]);
    save(&journal_path, &omitted)?;
    save(&history, &omitted)?;
    let before = machine.calls()?.len();
    error(
        &machine.run(&["generation-maintenance"], None, false)?,
        "protected journal coordinates",
    );
    assert!(
        !machine.calls()?[before..]
            .iter()
            .any(|call| call[0] == "storage-pool" && call[1] == "gc")
    );
    assert!(machine.path("machine/maintenance/pending.json").exists());
    save(&journal_path, &original)?;
    save(&history, &original)?;
    assert_eq!(
        machine.run(&["generation-maintenance"], None, true)?["status"],
        "passed"
    );

    // A malformed saved candidate set is an error, rather than an absent list on restart.
    fs::remove_file(&last_cleaned)?;
    machine.run(&["verify"], None, true)?;
    let maintenance_path = machine.path("machine/maintenance/latest.json");
    let saved_maintenance = read(&maintenance_path)?;
    let mut malformed = saved_maintenance.clone();
    malformed["plan"]["prune"] = json!("not-a-list");
    save(&maintenance_path, &malformed)?;
    let before = machine.calls()?.len();
    error(
        &machine.run(&["generation-maintenance"], None, false)?,
        "invalid type",
    );
    assert!(
        !machine.calls()?[before..]
            .iter()
            .any(|call| call[0] == "storage-pool" && call[1] == "gc")
    );
    save(&maintenance_path, &saved_maintenance)?;
    assert_eq!(
        machine.run(&["generation-maintenance"], None, true)?["status"],
        "passed"
    );

    machine.reload()?;
    machine.data["generations"]["usr-home:2"]["system"] = json!(store("unexpected-system", 1));
    machine.persist()?;
    error(
        &machine.run(&["verify"], None, false)?,
        "differs from release",
    );
    Ok(())
}

/// Boot start follows declared autostart and verifies the selected pool without requiring an older transaction.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_boot_start_verifies_declared_autostart() -> Result<()> {
    let mut machine = Machine::new()?;
    let path = machine.physical(&machine.baseline).join("topology.json");
    let mut topology = read(&path)?;
    topology["domains"]["usr-home"]["features"]["airlock-role"] = json!("usr-assistant");
    save(&path, &topology)?;
    save(
        machine.path("etc/qubes-topology.json"),
        &read(machine.physical(&machine.baseline).join("topology.json"))?,
    )?;
    machine.data["running"] = json!([]);
    machine.data["health_failures"] = json!(1);
    machine.persist()?;
    let result = machine.run(&["boot-start"], None, true)?;
    assert_eq!(result["started"], json!(["usr-home"]));
    assert!(
        read(machine.path("data.json"))?["health_probes"]
            .as_u64()
            .unwrap()
            >= 3
    );
    assert_eq!(
        result["observed"]["usr-home"]["running"],
        store("usr-home-system", 1)
    );
    Ok(())
}

/// A completed private-volume copy is never repeated after failed start; existing destinations need a receipt.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_private_volume_copy_resumes_without_overwriting_new_work() -> Result<()> {
    let mut machine = Machine::new()?;
    let _volumes = Volumes::new(&machine)?;
    machine.replacement()?;
    machine.approve(Some(
        json!({"allowed_vms": ["usr-home", "usr-new"], "allow_reboot": true}),
    ))?;
    machine.data["fail"] = json!("qvm-start");
    machine.persist()?;
    let failure = machine.run(&["apply", &machine.candidate], None, false)?;
    assert_eq!(
        read(machine.path("data.json"))?["clone_count"],
        1,
        "{failure}"
    );
    fs::write(machine.path("private-data"), "new work after original copy")?;
    machine.reload()?;
    machine.data.as_object_mut().unwrap().remove("fail");
    machine.persist()?;
    assert_eq!(machine.run(&["resume"], None, true)?["phase"], "complete");
    assert_eq!(
        fs::read_to_string(machine.path("private-data"))?,
        "new work after original copy"
    );
    assert_eq!(read(machine.path("data.json"))?["clone_count"], 1);
    assert_eq!(
        machine.run(&["trash-list"], None, true)?["records"][0]["status"],
        "trashed"
    );

    // Before a per-copy receipt exists, the prior authorised journal still fixes the source UUID.
    {
        let mut interrupted = Machine::new()?;
        let _volumes = Volumes::new(&interrupted)?;
        interrupted.replacement()?;
        interrupted.approve(Some(
            json!({"allowed_vms": ["usr-home", "usr-new"], "allow_reboot": true}),
        ))?;
        interrupted.data["crash_after"] = json!("qvm-shutdown");
        interrupted.persist()?;
        let crash = common::run(
            &mut interrupted.command(&["apply", &interrupted.candidate])?,
            None,
        )?;
        assert!(!crash.status.success());
        interrupted.reload()?;
        interrupted
            .data
            .as_object_mut()
            .unwrap()
            .remove("crash_after");
        interrupted.data["uuids"] = json!({"usr-home":"123e4567-e89b-12d3-a456-426614174009"});
        interrupted.persist()?;
        for _ in 0..2 {
            error(
                &interrupted.run(&["resume"], None, false)?,
                "original authorised resources",
            );
            let data = read(interrupted.path("data.json"))?;
            assert_eq!(data["clone_from_count"].as_u64().unwrap_or(0), 0);
            assert_eq!(data["clone_count"].as_u64().unwrap_or(0), 0);
        }
    }

    // Successful external overwrite with a lost reply stays uncertain across repeated restarts.
    {
        let mut interrupted = Machine::new()?;
        let _volumes = Volumes::new(&interrupted)?;
        interrupted.replacement()?;
        interrupted.approve(Some(
            json!({"allowed_vms": ["usr-home", "usr-new"], "allow_reboot": true}),
        ))?;
        interrupted.data["clone_reply_lost"] = json!(true);
        interrupted.persist()?;
        interrupted.run(&["apply", &interrupted.candidate], None, false)?;
        assert_eq!(read(interrupted.path("data.json"))?["clone_count"], 1);
        fs::write(
            interrupted.path("private-data"),
            "preserve uncertain outcome",
        )?;
        for _ in 0..2 {
            let failed = interrupted.run(&["resume"], None, false)?;
            error(&failed, "Uncertain");
            assert_eq!(read(interrupted.path("data.json"))?["clone_count"], 1);
            assert_eq!(
                fs::read_to_string(interrupted.path("private-data"))?,
                "preserve uncertain outcome"
            );
        }
    }

    let mut machine = Machine::new()?;
    let _volumes = Volumes::new(&machine)?;
    machine.replacement()?;
    machine.data["selected"]["usr-new"] = json!(2);
    machine.persist()?;
    let context = machine.context("machine", None)?;
    machine.decide(
        &context,
        Some(json!({"allowed_vms": ["usr-home", "usr-new"], "allow_reboot": true})),
    )?;
    error(
        &machine.run(
            &[
                "review-bind",
                context["request_id"].as_str().unwrap(),
                &machine.candidate,
            ],
            None,
            false,
        )?,
        "existing VM",
    );
    assert!(!machine.path("private-data").exists());
    Ok(())
}

/// Trash purge respects retained topology and foreign disk references, then removes only the recorded VM once.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_trash_purge_rechecks_references_and_is_idempotent() -> Result<()> {
    let mut machine = Machine::new()?;
    let _volumes = Volumes::new(&machine)?;
    let topology = machine.replacement()?;
    // Exercise retirement recovery independently of private-copy receipts.
    let candidate = machine.physical(&machine.candidate);
    let mut manifest = read(candidate.join("release.json"))?;
    manifest["privateVolumeCopies"] = json!({});
    save(candidate.join("release.json"), &manifest)?;
    machine.approve(Some(
        json!({"allowed_vms": ["usr-home", "usr-new"], "allow_reboot": true}),
    ))?;
    machine.data["crash_after"] = json!("qvm-shutdown");
    machine.persist()?;
    let crash = common::run(&mut machine.command(&["apply", &machine.candidate])?, None)?;
    assert!(!crash.status.success());
    machine.reload()?;
    machine.data.as_object_mut().unwrap().remove("crash_after");
    machine.data["uuids"] = json!({"usr-home":"123e4567-e89b-12d3-a456-426614174009"});
    machine.persist()?;
    error(
        &machine.run(&["resume"], None, false)?,
        "retirement proposal differs",
    );
    machine.reload()?;
    machine.data.as_object_mut().unwrap().remove("uuids");
    machine.persist()?;
    machine.run(&["resume"], None, true)?;
    machine.reload()?;
    machine.data["uuids"] = json!({"usr-home":"123e4567-e89b-12d3-a456-426614174009"});
    machine.persist()?;
    error(
        &machine.run(&["verify"], None, false)?,
        "trash registration or storage changed",
    );
    machine.reload()?;
    machine.data.as_object_mut().unwrap().remove("uuids");
    machine.persist()?;
    let mut record = machine.run(&["trash-list"], None, true)?["records"][0].clone();
    let identity = record["id"].as_str().unwrap().to_owned();
    error(
        &machine.run(
            &[
                "trash-purge",
                &identity,
                "--confirm",
                &identity,
                "--before-expiry",
            ],
            None,
            false,
        )?,
        "references VM",
    );
    let mut selected = read(machine.path("machine/selection.json"))?;
    selected["previous"] = selected["release"].clone();
    save(machine.path("machine/selection.json"), &selected)?;
    let key = format!(
        "{hash:x}",
        hash = Sha256::digest(machine.baseline.as_bytes())
    );
    save(
        machine.path(&format!("machine/pruned-releases/{key}.json")),
        &json!({"schema": "airlock.machine-release-prune.v1", "status": "pruned", "release": machine.baseline}),
    )?;
    save(
        machine.path("host/etc/airlock/qubes-topology.json"),
        &topology,
    )?;
    record["purge_after"] = json!(1);
    save(
        machine.path(&format!("machine/trash/{identity}.json")),
        &record,
    )?;
    machine.reload()?;
    machine.data["alias"] = json!(["usr-new", "store"]);
    machine.persist()?;
    error(
        &machine.run(
            &["trash-purge", &identity, "--confirm", &identity],
            None,
            false,
        )?,
        "referenced by usr-new",
    );
    machine.data.as_object_mut().unwrap().remove("alias");
    machine.persist()?;
    machine.data["power_states"] = json!({"usr-home":"Paused"});
    machine.persist()?;
    error(
        &machine.run(
            &["trash-purge", &identity, "--confirm", &identity],
            None,
            false,
        )?,
        "halted",
    );
    machine.reload()?;
    assert!(machine.data["selected"].get("usr-home").is_some());
    machine.data.as_object_mut().unwrap().remove("power_states");
    machine.data["crash_after"] = json!("qvm-remove");
    machine.persist()?;
    let interrupted = common::run(
        &mut machine.command(&["trash-purge", &identity, "--confirm", &identity])?,
        None,
    )?;
    assert!(!interrupted.status.success());
    machine.reload()?;
    assert!(machine.data["selected"].get("usr-home").is_none());
    assert_eq!(
        read(machine.path(&format!("machine/trash/{identity}.json")))?["status"],
        "purging"
    );
    machine.data.as_object_mut().unwrap().remove("crash_after");
    machine.persist()?;
    for _ in 0..2 {
        assert_eq!(
            machine.run(
                &["trash-purge", &identity, "--confirm", &identity],
                None,
                true
            )?["status"],
            "purged"
        );
        assert!(
            read(machine.path("data.json"))?["selected"]
                .get("usr-home")
                .is_none()
        );
    }
    Ok(())
}

/// Fresh images derive their baseline from installed source identity and the actually applied topology.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_fresh_image_review_uses_installed_source() -> Result<()> {
    let mut machine = Machine::new()?;
    let topology = read(machine.physical(&machine.baseline).join("topology.json"))?;
    fs::remove_dir_all(machine.physical(&machine.baseline))?;
    save(
        machine.path("host/etc/airlock/machine-source.json"),
        &json!({"schema": "airlock.machine-source.v1", "revision": revision(), "lockHash": lock_hash()}),
    )?;
    save(machine.path("system/current-topology.json"), &topology)?;
    let status = machine.run(&["status"], None, true)?;
    assert_eq!(status["phase"], "image-baseline");
    assert_eq!(status["revision"], revision());
    assert_eq!(status["baseline"]["initialized"], false);
    assert!(status["host_matches_selection"].is_null());
    error(&machine.run(&["verify"], None, false)?, "finish startup");
    assert!(!machine.physical(&machine.baseline).exists());

    let result = machine.context("machine", None)?;
    assert_eq!(result["baseline"], revision());
    assert_eq!(
        read(machine.physical(&machine.baseline).join("release.json"))?["lockHash"],
        lock_hash()
    );
    let manifest = machine.physical(&machine.baseline).join("release.json");
    let before = fs::read(&manifest)?;
    let verified = machine.run(&["verify"], None, true)?;
    assert_eq!(verified["status"], "passed");
    assert_eq!(verified["phase"], "image-baseline");
    assert_eq!(
        verified["observed"]["usr-home"]["running"],
        store("usr-home-system", 1)
    );
    assert_eq!(fs::read(&manifest)?, before);
    assert!(!machine.path("machine/selection.json").exists());
    assert!(!machine.path("machine/latest.json").exists());
    let status = machine.run(&["status"], None, true)?;
    assert_eq!(status["baseline"]["initialized"], true);
    assert_eq!(status["host_matches_baseline"], true);
    assert_eq!(status["baseline"]["source_matches_image"], true);

    let original_manifest = read(&manifest)?;
    let mut changed_manifest = original_manifest.clone();
    changed_manifest["host"] = json!(store("wrong-host", 1));
    save(&manifest, &changed_manifest)?;
    assert_eq!(
        machine.run(&["status"], None, true)?["host_matches_baseline"],
        false
    );
    error(
        &machine.run(&["verify"], None, false)?,
        "running host or profile",
    );
    save(&manifest, &original_manifest)?;

    let mut changed = topology;
    changed["domains"]["usr-home"]["prefs"]["memory"] = json!(4096);
    save(machine.path("system/current-topology.json"), &changed)?;
    error(
        &machine.run(&["verify"], None, false)?,
        "applied topology differs",
    );
    save(
        machine.path("system/current-topology.json"),
        &read(machine.physical(&machine.baseline).join("topology.json"))?,
    )?;
    save(
        machine.path("host/etc/airlock/machine-source.json"),
        &json!({"schema":"airlock.machine-source.v1", "revision":"c".repeat(40), "lockHash":lock_hash()}),
    )?;
    assert_eq!(
        machine.run(&["status"], None, true)?["baseline"]["source_matches_image"],
        false
    );
    error(&machine.run(&["verify"], None, false)?, "source differs");
    save(
        machine.path("host/etc/airlock/machine-source.json"),
        &json!({"schema":"airlock.machine-source.v1", "revision":revision(), "lockHash":lock_hash()}),
    )?;
    machine.data["generations"]["usr-home:1"]["system"] = json!(store("wrong-system", 1));
    machine.data["features"]["usr-home"]["airlock-system-source"] =
        json!(store("usr-home-system", 1));
    machine.persist()?;
    error(
        &machine.run(&["verify"], None, false)?,
        "generation system differs",
    );
    Ok(())
}

/// Offline planning orders inherited providers before their clients and grants no activation authority.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_offline_plan_orders_inherited_network_dependencies() -> Result<()> {
    let machine = Machine::new()?;
    for release in [&machine.baseline, &machine.candidate] {
        let path = machine.physical(release).join("topology.json");
        let mut topology = read(&path)?;
        topology["prefs"]["default_netvm"] = json!("z-network");
        topology["domains"]["z-network"] = declaration("z-network", 1);
        topology["domains"]["usr-home"]
            .as_object_mut()
            .unwrap()
            .remove("netvm");
        save(path, &topology)?;
    }
    let result = machine.run(
        &[
            "plan",
            &machine.candidate,
            "--baseline",
            &machine.baseline,
            "--running",
            "usr-home",
            "--host",
            HOST,
        ],
        None,
        true,
    )?;
    assert_eq!(result["authority"], "local-inspection-only");
    let start = result["plan"]["start"].as_array().unwrap();
    assert!(
        start.iter().position(|name| name == "z-network").unwrap()
            < start.iter().position(|name| name == "usr-home").unwrap()
    );
    Ok(())
}

/// VM plan transfer binds an actual protected guest approval without starting a machine deployment.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_guest_plan_binds_the_protected_approval() -> Result<()> {
    let machine = Machine::new()?;
    let mut receipt = machine.receipt();
    let context = machine.context("guest", Some("usr-home"))?;
    machine.decide(&context, None)?;
    receipt["review_authorization"] = context["request_id"].clone();
    let result = machine.run(
        &[
            "rpc",
            "--engine",
            &format!("{HOST}/sw/bin/airlock-dom0-service"),
            "guest-receive",
            "plan",
        ],
        Some(receipt),
        true,
    )?;
    assert_eq!(result["plan"]["changed"], json!(["usr-home"]));
    let mut found = false;
    for entry in fs::read_dir(machine.path("machine/reviews/bindings"))? {
        let binding = read(entry?.path())?;
        found |= binding["request_id"] == context["request_id"]
            && binding["release"] == result["candidate"];
    }
    assert!(found);
    assert!(!machine.path("machine/latest.json").exists());
    Ok(())
}

/// Development observations fingerprint canonical Unicode topology and keep disposable admission tests isolated.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_development_snapshot_is_read_only_and_canonical() -> Result<()> {
    let machine = Machine::new()?;
    let topology = json!({"domains": {}, "description": "Unicode ☃"});
    save(machine.path("system/current-topology.json"), &topology)?;
    save(
        machine.path("etc/boot-source.json"),
        &json!({"revision": revision()}),
    )?;
    fs::write(machine.path("etc/dev-mode"), "enabled")?;
    let result = machine.run(&["development-snapshot"], None, true)?;
    assert_eq!(result["host"], HOST);
    assert!(result["manifest"].is_null());
    // Canonical persistence uses sorted keys, ASCII escapes and Python-compatible separators.
    let canonical = br#"{"description": "Unicode \u2603", "domains": {}}"#;
    assert_eq!(
        result["topologyHash"],
        format!("{hash:x}", hash = Sha256::digest(canonical))
    );
    assert_eq!(result["topology"], topology);
    assert!(!machine.path("machine/transaction.json").exists());
    error(
        &machine.run(&["pool-admission-smoke"], None, false)?,
        "disposable vm-pool-admission-test profile",
    );
    assert!(!machine.path("pool-admission-smoke").exists());
    Ok(())
}

/// The actual native planner/coordinator dispatches typed PCI requests and reconciles uncertain success.
#[test]
#[ignore = "requires explicitly prepared bubblewrap and unprivileged user namespaces"]
fn namespace_native_pci_assignment_rejects_foreign_ownership_and_reconciles_lost_reply()
-> Result<()> {
    let mut machine = Machine::new()?;
    let path = machine.physical(&machine.candidate).join("topology.json");
    let mut topology = read(&path)?;
    topology["domains"]["usr-home"]["devices"]["pci"] = json!([{
        "backend":"dom0", "id":"00_1c.0-00_00.0", "mode":"required", "match":"port", "options":{"no-strict-reset":"True"}
    }]);
    save(path, &topology)?;
    // Existing VM device declarations are immutable in an ordinary deployment.
    // This scenario reconciles a declared device whose observed assignment drifted.
    let baseline_path = machine.physical(&machine.baseline).join("topology.json");
    let mut baseline = read(&baseline_path)?;
    baseline["domains"]["usr-home"]["devices"] = topology["domains"]["usr-home"]["devices"].clone();
    save(baseline_path, &baseline)?;
    fs::create_dir_all(machine.path("sys-pci/0000:01:00.0"))?;
    fs::write(machine.path("sys-pci/0000:01:00.0/class"), "0x020000\n")?;
    machine.data["native_setup"] = json!(true);
    machine.data["pci_available"] = json!(
        "00_1c.0-00_00.0:8086:1234::p020000 device_id='8086:1234::p020000' port_id='00_1c.0-00_00.0' backend_domain='dom0' devclass='pci' _sbdf='0000:01:00.0'"
    );
    machine.data["pci_assigned"] = json!({"unmanaged-vm":"dom0+00_1c.0-00_00.0+_ device_id='*' port_id='00_1c.0-00_00.0' backend_domain='dom0' devclass='pci' mode='required'"});
    machine.persist()?;
    machine.approve(None)?;
    let _api = Volumes::new(&machine)?;
    error(
        &machine.run(&["apply", &machine.candidate], None, false)?,
        "ownership",
    );
    machine.reload()?;
    assert!(machine.data["pci_assign_count"].is_null());
    let journal = read(machine.path("machine/latest.json"))?;
    machine.data["pci_assigned"] = json!({});
    machine.data["pci_reply_lost"] = json!(true);
    machine.persist()?;
    error(
        &machine.run(&["resume"], None, false)?,
        "admin.vm.device.pci.Assign",
    );
    machine.reload()?;
    assert_eq!(machine.data["pci_assign_count"], 1);
    machine.data["pci_reply_lost"] = json!(false);
    machine.persist()?;
    assert_eq!(machine.run(&["resume"], None, true)?["phase"], "complete");
    machine.reload()?;
    assert_eq!(machine.data["pci_assign_count"], 1);
    assert!(machine.data["pci_unassign_count"].is_null());
    let complete = read(machine.path("machine/latest.json"))?;
    assert!(journal["operation"].is_object());
    assert_eq!(journal["operation"], complete["operation"]);
    Ok(())
}

/// Immutable root replay and capacity observation reconcile success before a lost external reply.
#[test]
#[ignore = "requires explicitly prepared native integration tools"]
fn namespace_native_backend_reconciles_lost_root_and_store_replies() -> Result<()> {
    let mut machine = Machine::new()?;
    for release in [&machine.baseline, &machine.candidate] {
        let path = machine.physical(release).join("topology.json");
        let mut topology = read(&path)?;
        topology["domains"]["usr-home"]["backend"]["state"]["persistent_size"] = json!(512);
        save(path, &topology)?;
    }
    // Exercise genuine unpinned retained lookup, rather than a manifest's fixed number.
    let manifest_path = machine.physical(&machine.candidate).join("release.json");
    let mut manifest = read(&manifest_path)?;
    manifest.as_object_mut().unwrap().remove("guestTransport");
    manifest["stagedGenerations"] = json!({});
    save(&manifest_path, &manifest)?;
    save(
        machine.physical(&machine.candidate).join("staged.json"),
        &json!({}),
    )?;
    machine.data["generations"]["usr-home:2"]["approval"]["approved_by"] = json!("usr-assistant");
    machine.data["native_setup"] = json!(true);
    machine.data["lose_root_reply"] = json!(true);
    machine.persist()?;
    machine.approve(None)?;
    error(
        &machine.run(&["apply", &machine.candidate], None, false)?,
        "root-import",
    );
    machine.reload()?;
    assert_eq!(machine.data["root_import_count"], 1);
    assert!(machine.data["resize_count"].is_null());
    let interrupted = read(machine.path("machine/latest.json"))?;
    assert_eq!(interrupted["native_coordinator"], "airlock-dom0-service-v3");
    let original = interrupted["guest_generations"].clone();
    assert_eq!(original[0]["entries"][0]["identity"]["generation"], 2);
    // A newer, otherwise identical committed generation would win a fresh lookup.
    let generation = machine.data["generations"]["usr-home:2"].clone();
    let mut newer = generation.clone();
    newer["generation"] = json!(3);
    newer["manifest"] = json!("/var/lib/airlock/pool/usr-home/3/manifest.json");
    machine.data["generations"]["usr-home:3"] = newer;
    machine.data["generations"]
        .as_object_mut()
        .unwrap()
        .remove("usr-home:2");
    machine.persist()?;
    assert!(machine.run(&["resume"], None, false)?["error"].is_string());
    assert_eq!(
        read(machine.path("machine/latest.json"))?["id"],
        interrupted["id"]
    );
    machine.reload()?;
    assert_eq!(machine.data["root_import_count"], 1);
    machine.data["generations"]["usr-home:2"] = generation;
    // History may lag in progress, but its immutable selection set must agree.
    let history = machine
        .path("machine/transactions")
        .join(interrupted["id"].as_str().unwrap())
        .join("status.json");
    let mut conflicting = read(&history)?;
    conflicting["guest_generations"][0]["entries"][0]["identity"]["generation"] = json!(3);
    save(&history, &conflicting)?;
    error(
        &machine.run(&["resume"], None, false)?,
        "journal identities disagree",
    );
    save(&history, &interrupted)?;
    // A historical record cannot invent an original unpinned selection during adoption.
    let mut historical = interrupted.clone();
    historical["native_coordinator"] = json!("airlock-dom0-service-v2");
    historical
        .as_object_mut()
        .unwrap()
        .remove("guest_generations");
    save(machine.path("machine/latest.json"), &historical)?;
    save(&history, &historical)?;
    error(
        &machine.run(&["resume"], None, false)?,
        "legacy recovery has no durable guest generation selection",
    );
    save(machine.path("machine/latest.json"), &interrupted)?;
    save(&history, &interrupted)?;

    machine.data["lose_root_reply"] = json!(false);
    machine.data["lose_store_reply"] = json!(true);
    machine.persist()?;
    error(&machine.run(&["resume"], None, false)?, "store-install");
    machine.reload()?;
    assert_eq!(machine.data["root_import_count"], 2);
    assert_eq!(machine.data["resize_count"], 1);
    assert_eq!(machine.data["private_sizes"]["usr-home"], 512);
    machine.data["lose_store_reply"] = json!(false);
    machine.data["wrong_store_receipt"] = json!(true);
    machine.persist()?;
    error(
        &machine.run(&["resume"], None, false)?,
        "store receipt differs",
    );
    machine.reload()?;
    assert!(machine.data["features"]["usr-home"]["airlock-system-source"].is_null());
    machine.data["wrong_store_receipt"] = json!(false);
    machine.data["store_restart_required"] = json!(true);
    for overrides in [
        json!({"run_id":"999"}),
        json!({"unsupported_domains_count":1}),
        json!({"restart_required":null}),
    ] {
        machine.data["setup_report_override"] = overrides;
        machine.persist()?;
        assert!(machine.run(&["resume"], None, false)?["error"].is_string());
        assert!(!machine.calls()?.iter().any(|call| call[0] == "qvm-start"));
        machine.reload()?;
    }
    // A replaced compatibility map cannot override the in-memory native selection on recovery.
    machine.data["staged_after_prepare"] = json!({"usr-home":999,"unexpected-vm":42});
    machine.data["setup_report_override"] = json!({});
    machine.persist()?;
    // Same software sources do not permit reporting completion with another original generation.
    machine.data["selected_after_setup"] = json!({"usr-home":3});
    machine.persist()?;
    error(
        &machine.run(&["resume"], None, false)?,
        "guest observations differ from journal selections",
    );
    let rejected = read(machine.path("machine/latest.json"))?;
    assert_eq!(rejected["phase"], "failed");
    assert_eq!(rejected["failed_phase"], "verifying");
    assert!(rejected["verified_at"].is_null());
    assert!(rejected["generation_verified_at"].is_null());
    machine.reload()?;
    machine
        .data
        .as_object_mut()
        .unwrap()
        .remove("selected_after_setup");
    machine.persist()?;
    assert_eq!(machine.run(&["resume"], None, true)?["phase"], "complete");
    machine.reload()?;
    assert_eq!(machine.data["resize_count"], 1);
    assert_eq!(machine.data["selected"]["usr-home"], 2);
    let completed = read(machine.path("machine/latest.json"))?;
    assert!(interrupted["operation"].is_object());
    assert_eq!(interrupted["operation"], completed["operation"]);
    assert_eq!(completed["guest_generations"], original);
    assert_eq!(
        machine
            .calls()?
            .iter()
            .filter(|call| call[0] == "storage-pool" && call[1] == "find-generation")
            .count(),
        1
    );

    assert_eq!(
        read(
            machine
                .path("machine/transactions")
                .join(completed["id"].as_str().unwrap())
                .join("staged.json")
        )?["usr-home"],
        999
    );

    // Post-reboot verification follows the same exact-generation decision.
    let mut previous_boot = completed.clone();
    previous_boot["boot_id"] = json!("00000000-0000-0000-0000-000000000001");
    let history = machine
        .path("machine/transactions")
        .join(completed["id"].as_str().unwrap())
        .join("status.json");
    save(machine.path("machine/latest.json"), &previous_boot)?;
    save(&history, &previous_boot)?;
    machine.data["selected"]["usr-home"] = json!(3);
    machine.data["features"]["usr-home"]["airlock-store-generation"] = json!("3");
    machine.persist()?;
    error(
        &machine.run(&["verify"], None, false)?,
        "guest observations differ from journal selections",
    );
    assert_eq!(read(machine.path("machine/latest.json"))?, previous_boot);
    machine.reload()?;
    machine.data["selected"]["usr-home"] = json!(2);
    machine.data["features"]["usr-home"]["airlock-store-generation"] = json!("2");
    machine.persist()?;
    assert_eq!(machine.run(&["verify"], None, true)?["phase"], "complete");
    Ok(())
}
