//! Apply declared host profiles and service actions through existing NixOS and systemd interfaces.

use super::{
    build::{activation_path, physical, safe},
    control,
    io::{self, Operation},
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

/// Require an existing executable activation entry point before changing its profile selection.
fn executable(path: &Path) -> bool {
    path.metadata()
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

/// Install through Nix's profile manager for the host store, or an exact link for other sources.
fn profile(
    operation: &mut Operation,
    source: &str,
    target: &Path,
    state: Option<&Path>,
) -> Result<()> {
    let physical = physical(Path::new(source));
    fs::create_dir_all(target.parent().context("profile directory")?)?;
    if let Some(state) = state
        && let Ok(current) = fs::canonicalize(target)
        && current != physical
    {
        fs::write(
            state.join("previous-host-system"),
            format!("{current}\n", current = current.display()),
        )?;
    }
    if source.starts_with("/nix/store/") && physical == Path::new(source) {
        operation.text(
            "nix-env",
            &[
                "-p",
                target.to_str().context("profile path")?,
                "--set",
                source,
            ],
        )?;
    } else {
        control::link(&physical, target)?;
    }
    Ok(())
}

/// Apply each explicitly declared service action and preserve a failed action before stopping.
fn services(operation: &mut Operation, system: &Value) -> Result<Value> {
    let mut receipt = json!({"schema":"airlock.systemd-actions.v1","status":"skipped","reason":"no systemd live actions declared","actions":[]});
    let summary = operation.file("config-system-systemd-actions.log");
    fs::write(&summary, [])?;
    let result: Result<()> = (|| {
        if let Some(services) = system["dom0"]["systemd"]["services"].as_object() {
            for (name, service) in services {
                let action = service["action"].as_str().unwrap_or("");
                if action == "none" {
                    continue;
                }
                let log = operation.file(&format!(
                    "config-system-systemd-{name}-{action}.log",
                    name = safe(name),
                    action = safe(action)
                ));
                let result: Result<()> = (|| {
                    ensure!(
                        matches!(action, "restart" | "reload"),
                        "unsupported systemd action for {name}: {action}"
                    );
                    operation.logged("systemctl", &[action.into(), name.into()], &log, &[])
                })();
                receipt["actions"].as_array_mut().unwrap().push(json!({"name":name,"action":action,"reason":service["reason"].as_str().unwrap_or("null"),"status":if result.is_ok() {"passed"} else {"failed"},"log":log}));
                if log.is_file() {
                    use std::io::Write;
                    fs::OpenOptions::new()
                        .append(true)
                        .open(&summary)?
                        .write_all(&fs::read(&log)?)?;
                }
                result?;
                receipt["status"] = json!("passed");
                receipt["reason"] = json!("systemd live actions applied");
            }
        }
        Ok(())
    })();
    if let Err(error) = &result {
        receipt["status"] = json!("failed");
        receipt["reason"] = json!(format!("{error:#}"));
    }
    io::save(
        &operation.file("config-system-systemd-actions.json"),
        &receipt,
    )?;
    result?;
    Ok(receipt)
}

/// Replace prior host evidence before setup or activation so an interrupted attempt cannot inherit success.
pub(super) fn pending(system_path: &Path, started: bool) -> Result<()> {
    let operation = Operation::new("config-system")?;
    let system: Value = crate::state::configuration(system_path)?;
    io::save(
        &operation.file("config-apply-system-plan.json"),
        &system["plan"],
    )?;
    let status = if started { "unknown" } else { "skipped" };
    let reason = if started {
        "host activation has not reported an outcome"
    } else {
        "host activation has not been attempted"
    };
    io::save(
        &operation.file("config-system-apply.json"),
        &json!({"schema":"airlock.system-apply.v1","status":status,"reason":reason}),
    )?;
    io::save(
        &operation.file("config-system-systemd-actions.json"),
        &json!({"schema":"airlock.systemd-actions.v1","status":"skipped","reason":"service actions have not been attempted","actions":[]}),
    )?;
    for name in [
        "config-system-apply.log",
        "config-system-profile-activation.log",
        "config-system-host-activation.log",
        "config-system-systemd-actions.log",
    ] {
        fs::write(operation.file(name), [])?;
    }
    Ok(())
}

/// Apply a host contract and persist a compatible result on both activation success and failure.
pub(super) fn execute(system_path: &Path) -> Result<()> {
    pending(system_path, true)?;
    let mut operation = Operation::new("config-system")?;
    let system: Value = crate::state::configuration(system_path)?;
    let plan = &system["plan"];
    let state = io::path("AIRLOCK_SYSTEM_STATE_DIR", "/var/lib/airlock/system");
    let etc = io::path("AIRLOCK_SYSTEM_ETC_DIR", "/etc/airlock");
    let profile_path = io::path(
        "AIRLOCK_SYSTEM_PROFILE",
        "/nix/var/nix/profiles/airlock-system",
    );
    let host_profile = io::path(
        "AIRLOCK_HOST_SYSTEM_PROFILE",
        "/nix/var/nix/profiles/system",
    );
    let current_link = io::path("AIRLOCK_HOST_CURRENT_SYSTEM_LINK", "/run/current-system");
    fs::create_dir_all(&state)?;
    fs::create_dir_all(&etc)?;
    io::save(&operation.file("config-apply-system-plan.json"), plan)?;
    io::save(&state.join("last-system.json"), &system)?;
    io::save(&state.join("last-plan.json"), plan)?;
    let source = system["dom0"]["profile"]["source"].as_str().unwrap_or("");
    let host = &system["dom0"]["nixos"]["system"];
    let host_source = host["source"].as_str().unwrap_or("");
    let action = host["switch_action"].as_str().unwrap_or("switch");
    let activation_log = operation.file("config-system-profile-activation.log");
    let host_log = operation.file("config-system-host-activation.log");
    let mut receipt = json!({"schema":"airlock.system-apply.v1", "status":"passed", "reason":"system plan applied", "profile_status":"skipped", "host_system_status":"skipped", "systemd_status":"skipped", "profile_source":source, "profile_source_physical":if source.is_empty() {std::path::PathBuf::new()} else {physical(Path::new(source))}, "profile":profile_path, "host_system_source":host_source, "host_system_source_physical":"", "host_system_profile":host_profile, "host_current_system_link":current_link, "host_current_system":"", "host_system_switch_action":action, "state_dir":state, "etc_dir":etc, "system":system_path, "plan":operation.file("config-apply-system-plan.json"), "build_log":operation.file("config-apply-system-builds.log"), "activation_log":activation_log, "host_system_activation_log":host_log, "systemd_actions":operation.file("config-system-systemd-actions.json"), "systemd_actions_log":operation.file("config-system-systemd-actions.log"), "reboot_actions":plan["reboot_actions"], "reboot_required":plan["reboot_required"], "reboot_reasons":plan["reboot_reasons"]});
    // Both skipped and failed activations retain an initialized service-action receipt.
    io::save(
        &operation.file("config-system-systemd-actions.json"),
        &json!({"schema":"airlock.systemd-actions.v1","status":"skipped","reason":"no systemd live actions declared","actions":[]}),
    )?;
    let result: Result<()> = (|| {
        if !source.is_empty() {
            let source_path = physical(Path::new(source));
            let activation = activation_path(&source_path, &system["dom0"]["profile"])?;
            ensure!(
                source_path.is_dir() && executable(&activation),
                "dom0 profile activation command is missing or not executable: {activation}",
                activation = activation.display()
            );
            profile(&mut operation, source, &profile_path, None)
                .context("installing dom0 profile failed")?;
            if system["dom0"]["profile"]["activation_action"]
                .as_str()
                .unwrap_or("run")
                == "run"
            {
                operation
                    .logged(
                        activation.to_str().context("profile activation path")?,
                        &[],
                        &activation_log,
                        &[
                            (
                                "AIRLOCK_SYSTEM_JSON".into(),
                                system_path.as_os_str().to_owned(),
                            ),
                            (
                                "AIRLOCK_SYSTEM_PLAN_JSON".into(),
                                operation
                                    .file("config-apply-system-plan.json")
                                    .into_os_string(),
                            ),
                            (
                                "AIRLOCK_SYSTEM_STATE_DIR".into(),
                                state.as_os_str().to_owned(),
                            ),
                            ("AIRLOCK_SYSTEM_ETC_DIR".into(), etc.as_os_str().to_owned()),
                            (
                                "AIRLOCK_SYSTEM_PROFILE".into(),
                                profile_path.as_os_str().to_owned(),
                            ),
                        ],
                    )
                    .context("dom0 profile activation failed")?;
            } else {
                fs::write(&activation_log, "profile activation not requested\n")?;
            }
            receipt["profile_status"] = json!("passed");
        } else {
            fs::write(&activation_log, "no dom0 profile source declared\n")?;
        }
        if host["enable"] == true {
            ensure!(
                !host_source.is_empty(),
                "dom0 NixOS system is enabled but source is empty"
            );
            ensure!(
                matches!(action, "switch" | "boot" | "test" | "dry-activate"),
                "unsupported dom0 NixOS switch action: {action}"
            );
            let source_path = physical(Path::new(host_source));
            let switch = source_path.join("bin/switch-to-configuration");
            ensure!(
                source_path.is_dir() && executable(&switch),
                "dom0 NixOS switch-to-configuration is missing or not executable"
            );
            receipt["host_system_source_physical"] = json!(source_path);
            profile(&mut operation, host_source, &host_profile, Some(&state))
                .context("installing dom0 NixOS system profile failed")?;
            operation
                .logged(
                    switch.to_str().context("host switch path")?,
                    &[action.into()],
                    &host_log,
                    &[],
                )
                .with_context(|| format!("dom0 NixOS switch-to-configuration {action} failed"))?;
            receipt["host_current_system"] =
                json!(fs::read_link(&current_link).unwrap_or_default());
            for (name, value) in [
                ("current-host-system", host_source.to_owned()),
                (
                    "current-host-system-profile",
                    host_profile.to_string_lossy().into_owned(),
                ),
                ("current-host-system-switch-action", action.to_owned()),
            ] {
                fs::write(state.join(name), format!("{value}\n"))?;
            }
            receipt["host_system_status"] = json!("passed");
        } else {
            fs::write(&host_log, "dom0 NixOS system generation is not enabled\n")?;
        }
        match services(&mut operation, &system) {
            Ok(actions) => {
                receipt["systemd_status"] = actions["status"].clone();
            }
            Err(error) => {
                receipt["systemd_status"] = json!("failed");
                return Err(error.context("systemd live actions failed"));
            }
        }
        Ok(())
    })();
    if let Err(error) = &result {
        receipt["status"] = json!("failed");
        receipt["reason"] = json!(error.to_string());
    }
    receipt["systemd_actions_result"] =
        io::optional(&operation.file("config-system-systemd-actions.json"));
    io::save(&operation.file("config-system-apply.json"), &receipt)?;
    io::save(&state.join("last-apply.json"), &receipt)?;
    io::save(&etc.join("system.json"), &system)?;
    io::save(&etc.join("system-plan.json"), plan)?;
    for (source, destination) in [
        ("config-apply-system-builds.json", "last-system-builds.json"),
        (
            "config-system-systemd-actions.json",
            "last-systemd-actions.json",
        ),
    ] {
        if operation.file(source).is_file() {
            fs::copy(operation.file(source), state.join(destination))?;
        }
    }
    fs::write(
        operation.file("config-system-apply.log"),
        format!("{receipt}\n"),
    )?;
    result
}
