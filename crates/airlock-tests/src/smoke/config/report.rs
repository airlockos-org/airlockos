//! Collect best-effort command diagnostics and project the established receipt fields.

use super::{Session, settings::Scenario};
use anyhow::Result;
use serde_json::{Value, json};
use std::fs;

/// Representation retained by the existing smoke-report field.
enum Evidence {
    /// Captured command output retained as text.
    Text,
    /// Decoded structured result, or null when no valid result exists.
    Json,
    /// Evidence filename rather than its contents.
    Path,
}

/// Existing report fields, kept as data rather than repeated shell serialization.
const EVIDENCE: &[(&str, &str, Evidence)] = &[
    (
        "staging_uname",
        "config-vms-config-staging-uname.log",
        Evidence::Text,
    ),
    (
        "vault_uname",
        "config-vms-config-vault-uname.log",
        Evidence::Text,
    ),
    (
        "validator_uname",
        "config-vms-config-validator-uname.log",
        Evidence::Text,
    ),
    (
        "created_qube_uname",
        "config-vms-created-qube-uname.log",
        Evidence::Text,
    ),
    (
        "staging_user",
        "config-vms-config-staging-user.log",
        Evidence::Text,
    ),
    (
        "vault_user",
        "config-vms-config-vault-user.log",
        Evidence::Text,
    ),
    (
        "validator_user",
        "config-vms-config-validator-user.log",
        Evidence::Text,
    ),
    (
        "created_qube_user",
        "config-vms-created-qube-user.log",
        Evidence::Text,
    ),
    (
        "staging_backend",
        "config-vms-config-staging-backend.log",
        Evidence::Text,
    ),
    (
        "vault_backend",
        "config-vms-config-vault-backend.log",
        Evidence::Text,
    ),
    (
        "validator_backend",
        "config-vms-config-validator-backend.log",
        Evidence::Text,
    ),
    (
        "created_qube_backend",
        "config-vms-created-qube-backend.log",
        Evidence::Text,
    ),
    (
        "staging_store_volume",
        "config-vms-config-staging-store-volume.log",
        Evidence::Text,
    ),
    (
        "vault_store_volume",
        "config-vms-config-vault-store-volume.log",
        Evidence::Text,
    ),
    (
        "validator_store_volume",
        "config-vms-config-validator-store-volume.log",
        Evidence::Text,
    ),
    (
        "created_qube_store_volume",
        "config-vms-created-qube-store-volume.log",
        Evidence::Text,
    ),
    (
        "staging_store_mount",
        "config-vms-config-staging-store-mount.log",
        Evidence::Text,
    ),
    (
        "vault_store_mount",
        "config-vms-config-vault-store-mount.log",
        Evidence::Text,
    ),
    (
        "validator_store_mount",
        "config-vms-config-validator-store-mount.log",
        Evidence::Text,
    ),
    (
        "created_qube_store_mount",
        "config-vms-created-qube-store-mount.log",
        Evidence::Text,
    ),
    (
        "staging_persistence",
        "config-vms-config-staging-persistence.log",
        Evidence::Text,
    ),
    (
        "vault_persistence",
        "config-vms-config-vault-persistence.log",
        Evidence::Text,
    ),
    (
        "validator_persistence",
        "config-vms-config-validator-persistence.log",
        Evidence::Text,
    ),
    (
        "created_qube_persistence",
        "config-vms-created-qube-persistence.log",
        Evidence::Text,
    ),
    (
        "staging_appmenus_log",
        "config-vms-config-staging-appmenus.log",
        Evidence::Text,
    ),
    (
        "vault_appmenus_log",
        "config-vms-config-vault-appmenus.log",
        Evidence::Text,
    ),
    (
        "validator_appmenus_log",
        "config-vms-config-validator-appmenus.log",
        Evidence::Text,
    ),
    (
        "staging_init_log",
        "config-vms-config-staging-init.log",
        Evidence::Text,
    ),
    (
        "validator_init_log",
        "config-vms-config-validator-init.log",
        Evidence::Text,
    ),
    (
        "current_config_bootstrap",
        "config-vms-config-current-bootstrap.log",
        Evidence::Json,
    ),
    (
        "staging_update_log",
        "config-vms-config-staging-update.log",
        Evidence::Text,
    ),
    (
        "staging_update_script",
        "config-vms-config-staging-update.json",
        Evidence::Path,
    ),
    (
        "staging_repo_status",
        "config-vms-config-staging-repo-status.log",
        Evidence::Text,
    ),
    (
        "vault_repo_status",
        "config-vms-config-vault-repo-status.log",
        Evidence::Text,
    ),
    ("dom0_system", "config-vms-dom0-system.json", Evidence::Json),
    (
        "dom0_system_plan",
        "config-vms-dom0-system-plan.json",
        Evidence::Json,
    ),
    (
        "dom0_system_profile",
        "config-vms-dom0-profile.json",
        Evidence::Json,
    ),
    (
        "dom0_system_apply",
        "config-vms-dom0-system-apply.json",
        Evidence::Json,
    ),
    (
        "dom0_system_profile_link",
        "config-vms-dom0-system-profile-link.log",
        Evidence::Text,
    ),
    (
        "dom0_host_config_message",
        "config-vms-dom0-host-config-message.log",
        Evidence::Text,
    ),
    (
        "dom0_extra_module_message",
        "config-vms-dom0-extra-module-message.log",
        Evidence::Text,
    ),
    (
        "dom0_host_configuration_message",
        "config-vms-dom0-host-configuration-message.log",
        Evidence::Text,
    ),
    (
        "dom0_extra_module_restarted",
        "config-vms-dom0-extra-module-restarted.log",
        Evidence::Text,
    ),
    (
        "dom0_systemd_actions",
        "config-vms-dom0-systemd-actions.json",
        Evidence::Json,
    ),
    (
        "dom0_host_system_profile_link",
        "config-vms-dom0-host-system-profile-link.log",
        Evidence::Text,
    ),
    (
        "dom0_current_system_link",
        "config-vms-dom0-current-system-link.log",
        Evidence::Text,
    ),
    (
        "config_status",
        "config-vms-config-status.json",
        Evidence::Json,
    ),
    ("archive", "config-archive.json", Evidence::Json),
    ("archive_log", "config-vms-archive.log", Evidence::Text),
    ("apply", "config-apply.json", Evidence::Json),
    ("apply_log", "config-vms-apply.log", Evidence::Text),
    (
        "applied_topology",
        "config-vms-applied-topology.json",
        Evidence::Json,
    ),
    (
        "qrexec_policy_file",
        "config-vms-qrexec-policy.log",
        Evidence::Text,
    ),
    (
        "qrexec_policy_probe",
        "config-vms-qrexec-policy-probe.log",
        Evidence::Text,
    ),
    (
        "applied_feature",
        "config-vms-applied-feature.log",
        Evidence::Text,
    ),
    (
        "created_qube_feature",
        "config-vms-created-qube-feature.log",
        Evidence::Text,
    ),
    (
        "vault_archive_tree",
        "config-vms-config-vault-archive-tree.log",
        Evidence::Text,
    ),
    (
        "vault_deployment_tree",
        "config-vms-config-vault-deployment-tree.log",
        Evidence::Text,
    ),
    (
        "command_log",
        "config-vms-smoke.commands.log",
        Evidence::Path,
    ),
    ("qvm_ls_log", "config-vms-qvm-ls.log", Evidence::Path),
    ("journal_log", "config-vms-journal.log", Evidence::Path),
    ("libxl_log", "config-vms-libxl.log", Evidence::Path),
    ("qvm_prefs_log", "config-vms-qvm-prefs.log", Evidence::Path),
    (
        "staging_console_log",
        "config-vms-$STAGING-console.log",
        Evidence::Path,
    ),
    (
        "vault_console_log",
        "config-vms-$VAULT-console.log",
        Evidence::Path,
    ),
    (
        "validator_console_log",
        "config-vms-$VALIDATOR-console.log",
        Evidence::Path,
    ),
    (
        "created_qube_console_log",
        "config-vms-$CREATED_QUBE-console.log",
        Evidence::Path,
    ),
];

/// Collect diagnostics after every mode, including failed validation or apply.
pub(super) fn diagnostics(session: &mut Session, scenario: &Scenario) -> Result<()> {
    let _ = session.command("qvm-ls", &[], "config-vms-qvm-ls.log");
    let _ = session.command(
        "journalctl",
        &[
            "-b",
            "--no-pager",
            "-n",
            "260",
            "-u",
            "qubesd",
            "-u",
            "libvirtd",
            "-u",
            "qubes-db-dom0",
            "-u",
            "qubes-qrexec-policy-daemon",
        ],
        "config-vms-journal.log",
    );
    let mut observations = String::new();
    for guest in [
        &scenario.vault,
        &scenario.staging,
        &scenario.validator,
        &scenario.created,
    ] {
        for program in ["qvm-prefs", "qvm-features"] {
            if let Ok(text) = session.command(
                program,
                &[guest],
                &format!("config-vms-{guest}-{program}.log"),
            ) {
                observations.push_str(&format!("== {guest} {program} ==\n{text}\n"));
            }
        }
        if let Ok(console) =
            fs::read_to_string(format!("/var/log/airlock-xen-console/guest-{guest}.log"))
        {
            let lines = console
                .lines()
                .rev()
                .take(500)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join("\n");
            fs::write(
                session.file(&format!("config-vms-{guest}-console.log")),
                lines,
            )?;
        }
    }
    fs::write(session.file("config-vms-qvm-prefs.log"), observations)?;
    if let Ok(log) = fs::read_to_string("/var/log/libvirt/libxl/libxl-driver.log") {
        let lines = log
            .lines()
            .rev()
            .take(260)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(session.file("config-vms-libxl.log"), lines)?;
    }
    Ok(())
}

/// Preserve evidence representations, filenames and nulls for unavailable results.
pub(super) fn evidence(session: &Session, scenario: &Scenario, record: &mut Value) {
    for (key, file, kind) in EVIDENCE {
        let file = file
            .replace("$STAGING", &scenario.staging)
            .replace("$VAULT", &scenario.vault)
            .replace("$VALIDATOR", &scenario.validator)
            .replace("$CREATED_QUBE", &scenario.created);
        let path = session.file(&file);
        record[*key] = match kind {
            Evidence::Path => json!(path),
            Evidence::Text => fs::read_to_string(path)
                .map(|text| json!(text.trim_end_matches('\n')))
                .unwrap_or(Value::Null),
            Evidence::Json => fs::read(path)
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .unwrap_or(Value::Null),
        };
    }
}
