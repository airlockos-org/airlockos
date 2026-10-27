//! Read-only compatibility status: intended configuration, persisted progress and runtime observations stay distinct.

use crate::{process::Runner, setup_config::report};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

/// Select the existing nonempty environment override without evaluating its contents.
fn path(key: &str, fallback: impl AsRef<Path>) -> PathBuf {
    std::env::var_os(key)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| fallback.as_ref().into())
}

/// Missing or invalid informational records remain null, never reconstructed authority.
fn read(path: &Path) -> Value {
    airlock_nix_core::state::read_json(path, 32 * 1024 * 1024).unwrap_or(Value::Null)
}

/// Report literal and resolved symlink identities independently.
fn links(path: &Path) -> Value {
    json!({"path":path,"target":fs::read_link(path).ok().unwrap_or_default(),"resolved_target":fs::canonicalize(path).ok().unwrap_or_default()})
}

/// Use only correctly typed fields, preferring the current plan over the last attempt.
fn array<'a>(current: &'a Value, last: &'a Value, key: &str) -> &'a [Value] {
    current[key]
        .as_array()
        .or_else(|| last[key].as_array())
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

/// Return stable unique nonempty reason/target strings from restart observations.
fn unique(actions: &[Value], key: &str) -> Vec<String> {
    actions
        .iter()
        .filter_map(|action| action[key].as_str())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Produce the existing status schema without using observations to grant control authority.
pub(super) fn observe() -> Result<Value> {
    let logs = path("AIRLOCK_LOG_DIR", "/var/log/airlock");
    let state = path("AIRLOCK_SYSTEM_STATE_DIR", "/var/lib/airlock/system");
    let boot_path = path(
        "AIRLOCK_CONFIG_STATUS_BOOT_TOPOLOGY_JSON",
        "/etc/airlock/qubes-topology.json",
    );
    let current_path = path(
        "AIRLOCK_CONFIG_STATUS_CURRENT_TOPOLOGY_JSON",
        state.join("current-topology.json"),
    );
    let boot = crate::state::configuration(&boot_path).unwrap_or(Value::Null);
    let current = read(&current_path);
    let (topology_path, topology_source, topology) = if let Some(override_path) =
        std::env::var_os("AIRLOCK_CONFIG_STATUS_TOPOLOGY_JSON").filter(|value| !value.is_empty())
    {
        let path = PathBuf::from(override_path);
        let value = crate::state::configuration(&path).unwrap_or(Value::Null);
        (path, "override", value)
    } else if !current.is_null() {
        (current_path.clone(), "current", current.clone())
    } else {
        (boot_path.clone(), "boot", boot.clone())
    };
    let setup_path = path(
        "AIRLOCK_CONFIG_STATUS_SETUP_JSON",
        logs.join("setup-config.json"),
    );
    let current_setup_path = path(
        "AIRLOCK_CONFIG_STATUS_CURRENT_SETUP_JSON",
        state.join("current-setup.json"),
    );
    let setup_log = read(&setup_path);
    let current_setup = read(&current_setup_path);
    let (setup_source, setup) = if !setup_log.is_null() {
        ("log", &setup_log)
    } else {
        ("current", &current_setup)
    };
    let apply_path = path(
        "AIRLOCK_CONFIG_STATUS_APPLY_JSON",
        logs.join("config-apply.json"),
    );
    let apply = read(&apply_path);
    let plan = read(&state.join("current-plan.json"));
    let last = read(&state.join("last-apply.json"));
    let profile = links(&path(
        "AIRLOCK_CONFIG_STATUS_SYSTEM_PROFILE",
        "/nix/var/nix/profiles/airlock-system",
    ));
    let host = links(&path(
        "AIRLOCK_CONFIG_STATUS_HOST_SYSTEM_PROFILE",
        "/nix/var/nix/profiles/system",
    ));
    let running = links(&path(
        "AIRLOCK_CONFIG_STATUS_RUN_CURRENT_SYSTEM",
        "/run/current-system",
    ));
    let active = host["resolved_target"]
        .as_str()
        .is_some_and(|value| !value.is_empty())
        && host["resolved_target"] == running["resolved_target"];
    let requested = array(&plan, &last, "reboot_actions");
    let actions = requested
        .iter()
        .filter(|action| {
            !(active
                && action["type"] == "dom0-nixos-system"
                && action["switch_action"]
                    .as_str()
                    .or_else(|| action["action"].as_str())
                    == Some("boot"))
        })
        .cloned()
        .collect::<Vec<_>>();
    let required_flag = plan["reboot_required"]
        .as_bool()
        .or_else(|| last["reboot_required"].as_bool())
        .unwrap_or(false);
    let reasons = if !actions.is_empty() {
        actions
            .iter()
            .filter_map(|action| {
                action
                    .get("reason")
                    .filter(|value| !value.is_null())
                    .cloned()
            })
            .collect::<Vec<_>>()
    } else if required_flag && requested.is_empty() {
        array(&plan, &last, "reboot_reasons").to_vec()
    } else {
        Vec::new()
    };
    let required = !actions.is_empty()
        || (required_flag
            && requested.is_empty()
            && !array(&plan, &last, "reboot_reasons").is_empty());
    let pending = json!({"required":required,"actions":actions,"reasons":reasons});
    let restarts = setup["restart_actions"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let pending_restarts = json!({"required":setup["restart_required"].as_bool().unwrap_or(false)||!restarts.is_empty(),"actions":restarts,"domains":unique(&restarts,"domain"),"reasons":unique(&restarts,"reason")});
    let staged = if required {
        last["host_system_source"]
            .as_str()
            .unwrap_or(host["resolved_target"].as_str().unwrap_or(""))
    } else {
        ""
    };
    let generation = json!({"active":active,"current_source":running["resolved_target"],"staged_source":staged,"profile":host,"running":running,"last_apply":{"status":last["status"],"host_system_status":last["host_system_status"],"source":last["host_system_source"].as_str().unwrap_or(""),"source_physical":last["host_system_source_physical"].as_str().unwrap_or(""),"switch_action":last["host_system_switch_action"].as_str().unwrap_or(""),"reboot_required":last["reboot_required"].as_bool().unwrap_or(false)},"pending_reboot":pending});
    let qvm = path("AIRLOCK_QVM_LS_BIN", "qvm-ls");
    let exists = if qvm.components().count() > 1 {
        qvm.is_file()
    } else {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .any(|directory| directory.join(&qvm).is_file())
    };
    let (qvm_status, domains) = if exists {
        match Runner::default().capture(
            &qvm,
            &[
                "--raw-data".into(),
                "--fields".into(),
                "NAME,CLASS,STATE,TEMPLATE,LABEL".into(),
                "--no-spinner".into(),
            ],
            Duration::from_secs(60),
            &[],
        ) {
            Ok(output) if output.status.success() && !output.limited => {
                let domains=String::from_utf8(output.stdout)?.lines().filter(|line|!line.is_empty()).map(|line|{let cols=line.split('|').collect::<Vec<_>>();json!({"name":cols[0],"class":cols.get(1).copied().unwrap_or(""),"state":cols.get(2).copied().unwrap_or(""),"template":cols.get(3).copied().unwrap_or(""),"label":cols.get(4).copied().unwrap_or("")})}).collect::<Vec<_>>();
                ("ok", domains)
            }
            _ => ("failed", Vec::new()),
        }
    } else {
        ("missing", Vec::new())
    };
    let managed = domains
        .iter()
        .filter(|domain| {
            domain["name"]
                .as_str()
                .is_some_and(|name| topology["domains"].get(name).is_some())
        })
        .cloned()
        .collect::<Vec<_>>();
    let keys = |key: &str| {
        topology[key]
            .as_object()
            .map(|values| values.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default()
    };
    let policy = path(
        "AIRLOCK_QUBES_POLICY_DIR",
        "/var/lib/airlock/qubes-policy.d",
    )
    .join(path(
        "AIRLOCK_QUBES_MANAGED_POLICY_FILE",
        "90-airlock.policy",
    ));
    let policy_text = fs::read_to_string(&policy).ok();
    let rule_count = policy_text
        .as_deref()
        .unwrap_or("")
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('#')
        })
        .count();
    let status = if apply["status"] == "passed" {
        "applied"
    } else if setup["status"] == "passed" {
        "setup"
    } else if !topology.is_null() {
        "declared"
    } else {
        "unknown"
    };
    Ok(
        json!({"schema":"airlock.config-status.v1","status":status,"host_generation":generation,"paths":{"topology":topology_path,"boot_topology":boot_path,"current_topology":current_path,"setup":setup_path,"current_setup":current_setup_path,"apply":apply_path,"system_state_dir":state,"qrexec_policy_file":policy},"topology":{"source":topology_source,"present":!topology.is_null(),"boot_present":!boot.is_null(),"current_present":!current.is_null(),"domain_names":keys("domains"),"template_names":keys("templates"),"kernel_names":keys("kernels"),"qrexec_policy_rule_count":topology["qrexec_policy"]["rules"].as_array().map(Vec::len).unwrap_or(0)},"qvm":{"available":qvm_status=="ok","status":qvm_status,"domains":domains,"managed_domains":managed},"qrexec_policy":{"file":policy,"exists":policy_text.is_some(),"rule_count":rule_count},"pending_reboot":pending,"pending_vm_restarts":pending_restarts,"deployment":{"current":read(&state.join("current-deployment.json")),"last_attempt":read(&state.join("last-deployment.json")),"current_apply":read(&state.join("current-config-apply.json")),"last_apply_result":read(&state.join("last-config-apply.json"))},"setup":setup,"setup_source":setup_source,"setup_log":setup_log,"current_setup":current_setup,"apply":apply,"system":{"state_dir":state,"current_system":read(&state.join("current-system.json")),"current_plan":plan,"pending_reboot":pending,"host_generation":generation,"last_apply":last,"profile":profile["path"],"profile_target":profile["target"],"profile_resolved_target":profile["resolved_target"],"host_system_profile":host["path"],"host_system_profile_target":host["target"],"host_system_profile_resolved_target":host["resolved_target"],"run_current_system":running["path"],"run_current_system_target":running["target"],"run_current_system_resolved_target":running["resolved_target"]}}),
    )
}

/// Check selected, running and pending-reboot state without mutating the machine.
pub(super) fn boot_verify() -> Result<()> {
    let logs = path("AIRLOCK_LOG_DIR", "/var/log/airlock");
    fs::create_dir_all(&logs)?;
    let mut status = Value::Null;
    let mut expected = std::env::var("AIRLOCK_EXPECTED_HOST_SYSTEM_SOURCE").unwrap_or_default();
    let marker = fs::read_to_string("/etc/airlock/inside-config-applied-message").ok();
    if let Some(marker) = &marker {
        fs::write(logs.join("config-boot-verify-marker.log"), marker)?;
    }
    let result: Result<()> = (|| {
        status = observe()?;
        report::save(&logs.join("config-boot-verify-status.json"), &status)?;
        ensure!(
            status["schema"] == "airlock.config-status.v1",
            "invalid config status schema"
        );
        if expected.is_empty() {
            expected = status["system"]["last_apply"]["host_system_source"]
                .as_str()
                .unwrap_or("")
                .into();
        }
        ensure!(!expected.is_empty(), "expected host system source is empty");
        ensure!(
            status["system"]["host_system_profile_resolved_target"] == expected,
            "host system profile does not point at expected generation"
        );
        ensure!(
            status["system"]["run_current_system_resolved_target"] == expected,
            "running system does not point at expected generation"
        );
        ensure!(
            status["pending_reboot"]["required"] == false,
            "config status still reports a pending reboot"
        );
        let message = std::env::var("AIRLOCK_EXPECTED_APPLIED_MESSAGE").unwrap_or_default();
        ensure!(
            message.is_empty()
                || marker
                    .as_deref()
                    .is_some_and(|marker| marker.lines().any(|line| line == message)),
            "inside-config marker did not match expected message"
        );
        Ok(())
    })();
    let record = json!({"schema":"airlock.config-boot-verify.v1","status":if result.is_ok(){"passed"}else{"failed"},"reason":result.as_ref().map(|()|"running dom0 booted into the staged NixOS generation".to_owned()).unwrap_or_else(|error|format!("{error:#}")),"expected_host_system_source":expected,"last_apply_host_system_source":status["system"]["last_apply"]["host_system_source"].as_str().unwrap_or(""),"host_system_profile_resolved_target":status["system"]["host_system_profile_resolved_target"].as_str().unwrap_or(""),"run_current_system_resolved_target":status["system"]["run_current_system_resolved_target"].as_str().unwrap_or(""),"pending_reboot":status["pending_reboot"],"status_json":status,"marker":marker});
    report::save(&logs.join("config-boot-verify.json"), &record)?;
    println!("{record}");
    result
}
