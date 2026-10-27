//! Verify host activation, selected generations and live-versus-boot semantics.

use super::{Session, common};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::fs;

/// Check the applied host contract, selected generation and live-versus-boot activation semantics.
pub(super) fn host(
    session: &mut Session,
    message: &str,
    action: &str,
    reason: &str,
) -> Result<(Value, Value)> {
    let state = common::path("AIRLOCK_SYSTEM_STATE_DIR", "/var/lib/airlock/system");
    let mut values = Vec::new();
    for (file, log) in [
        ("current-system.json", "config-vms-dom0-system.json"),
        ("current-plan.json", "config-vms-dom0-system-plan.json"),
        ("current-profile.json", "config-vms-dom0-profile.json"),
        ("last-apply.json", "config-vms-dom0-system-apply.json"),
        (
            "last-systemd-actions.json",
            "config-vms-dom0-systemd-actions.json",
        ),
    ] {
        let value = fs::read(state.join(file))?;
        fs::write(session.file(log), &value)?;
        values.push(serde_json::from_slice::<Value>(&value)?);
    }
    let system = &values[0];
    let plan = &values[1];
    let profile = &values[2];
    let apply = &values[3];
    let actions = &values[4];
    ensure!(
        system["schema"] == "airlock.system.v1"
            && system["dom0"]["profile"]["message"] == message
            && system["dom0"]["nixos"]["system"]["enable"] == true
            && system["dom0"]["nixos"]["system"]["source_ref"].is_null()
            && system["dom0"]["nixos"]["system"]["switch_action"] == action,
        "applied dom0 system JSON did not match expected value"
    );
    ensure!(
        profile["schema"] == "airlock.dom0-profile.v1"
            && profile["message"] == message
            && profile["built_by"] == "sys-config-staging",
        "applied dom0 profile JSON did not match expected value"
    );
    ensure!(
        apply["schema"] == "airlock.system-apply.v1"
            && apply["status"] == "passed"
            && apply["profile_status"] == "passed"
            && apply["host_system_status"] == "passed"
            && apply["host_system_switch_action"] == action,
        "dom0 system apply JSON did not pass"
    );
    for (label, value) in [
        ("system", &system["plan"]),
        ("plan", plan),
        ("apply", apply),
    ] {
        if action == "switch" {
            ensure!(
                value["reboot_required"] == false
                    && value["reboot_actions"]
                        .as_array()
                        .is_some_and(Vec::is_empty)
                    && value["reboot_reasons"]
                        .as_array()
                        .is_some_and(Vec::is_empty),
                "{label} unexpectedly requires reboot"
            );
        } else {
            ensure!(
                value["reboot_required"] == true
                    && value["reboot_actions"]
                        .as_array()
                        .is_some_and(|actions| actions.len() == 1)
                    && value["reboot_actions"][0]["type"] == "dom0-nixos-system"
                    && value["reboot_actions"][0]["switch_action"] == "boot"
                    && value["reboot_reasons"] == json!([reason]),
                "{label} did not preserve the staged boot requirement"
            );
        }
    }
    plan_actions(&system["plan"], message, action)?;
    plan_actions(plan, message, action)?;
    if action == "switch" {
        ensure!(
            system["dom0"]["systemd"]["services"]["airlock-local-extra-module"]["action"]
                == "restart",
            "host system omitted local service restart"
        );
    } else {
        ensure!(
            system["dom0"]["systemd"]["services"] == json!({}),
            "boot-only system declared live service changes"
        );
    }
    let source = apply["host_system_source"]
        .as_str()
        .filter(|source| source.starts_with("/nix/store/"))
        .context("host source is not a Nix store path")?;
    let selected = session.command(
        "readlink",
        &["-f", "/nix/var/nix/profiles/system"],
        "config-vms-dom0-host-system-profile-link.log",
    )?;
    ensure!(
        selected == source,
        "host system profile does not point at applied source"
    );
    let running = session.command(
        "readlink",
        &["/run/current-system"],
        "config-vms-dom0-current-system-link.log",
    )?;
    if action == "switch" {
        ensure!(
            running == source,
            "current system link does not point at applied source"
        );
        ensure!(
            apply["systemd_status"] == "passed"
                && actions["status"] == "passed"
                && actions["actions"]
                    .as_array()
                    .is_some_and(|actions| actions
                        .iter()
                        .any(|action| action["name"] == "airlock-local-extra-module"
                            && action["action"] == "restart"
                            && action["status"] == "passed")),
            "live service actions did not pass"
        );
        for (file, expected, log) in [
            (
                "/etc/airlock/inside-config-applied-message",
                message.to_owned(),
                "config-vms-dom0-host-config-message.log",
            ),
            (
                "/etc/airlock/local-dom0-extra-module",
                format!("{message}-extra"),
                "config-vms-dom0-extra-module-message.log",
            ),
            (
                "/etc/airlock/local-dom0-host-configuration",
                format!("{message}-configuration"),
                "config-vms-dom0-host-configuration-message.log",
            ),
            (
                "/var/lib/airlock/system/local-extra-module-restarted",
                message.to_owned(),
                "config-vms-dom0-extra-module-restarted.log",
            ),
        ] {
            let observed = session.command("cat", &[file], log)?;
            ensure!(
                observed == expected,
                "inside-config marker did not match expected value: {file}"
            );
        }
    } else {
        ensure!(
            apply["systemd_status"] == "skipped"
                && actions["status"] == "skipped"
                && actions["actions"].as_array().is_some_and(Vec::is_empty),
            "boot-only selection unexpectedly ran live service actions"
        );
    }
    let status: Value = serde_json::from_str(&session.command(
        "airlock-config-status",
        &[],
        "config-vms-config-status.json",
    )?)?;
    ensure!(
        status["schema"] == "airlock.config-status.v1"
            && status["status"] == "applied"
            && status["qvm"]["available"] == true
            && status["qvm"]["status"] == "ok"
            && status["apply"]["status"] == "passed"
            && status["system"]["last_apply"]["status"] == "passed",
        "config status JSON did not match applied state"
    );
    ensure!(
        status["pending_reboot"]["required"] == (action == "boot"),
        "config status pending reboot differs from activation mode"
    );
    Ok((apply.clone(), status))
}

/// Match live-action planning independently of the host adapter's success receipt.
fn plan_actions(plan: &Value, message: &str, action: &str) -> Result<()> {
    let actions = plan["live_actions"]
        .as_array()
        .context("host live actions")?;
    ensure!(
        actions
            .iter()
            .any(|item| item["type"] == "dom0-profile" && item["message"] == message),
        "host plan omitted profile activation"
    );
    ensure!(
        actions
            .iter()
            .any(|item| item["type"] == "dom0-nixos-system" && item["action"] == action),
        "host plan omitted selected NixOS activation"
    );
    if action == "switch" {
        ensure!(
            actions.iter().any(|item| item["type"] == "systemd-service"
                && item["name"] == "airlock-local-extra-module"
                && item["action"] == "restart"),
            "host plan omitted local service restart"
        );
    }
    Ok(())
}
