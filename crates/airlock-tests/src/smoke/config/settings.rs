//! Resolve scenario inputs while retaining mode-specific defaults and receipt fields.

use super::common;
use serde_json::{Value, json};

/// Inputs shared by the explicitly selected configuration smoke phases.
pub(super) struct Scenario {
    /// VM holding the editable candidate repository.
    pub(super) staging: String,
    /// VM independently validating the staged candidate.
    pub(super) validator: String,
    /// VM retaining candidate and deployment archives.
    pub(super) vault: String,
    /// VM expected to be created by the applied candidate.
    pub(super) created: String,
    /// Expected user for guest commands and repository paths.
    pub(super) user: String,
    /// Marker tying the staged source to observed results.
    pub(super) message: String,
    /// Selected preflight, staging, apply or complete workflow.
    pub(super) mode: String,
    /// Apply stage forwarded unchanged to the configuration command.
    pub(super) stage_name: String,
    /// Host generation activation mode: switch now or select next boot.
    pub(super) action: String,
    /// Expected explanation when the host requires a reboot.
    pub(super) reason: String,
}

impl Scenario {
    /// Read defaults without validating early, so invalid inputs still receive diagnostics.
    pub(super) fn from_environment() -> Self {
        let staging = common::setting("AIRLOCK_CONFIG_STAGING_VM", "sys-config-staging");
        let validator = common::setting("AIRLOCK_CONFIG_VALIDATOR_VM", "sys-config-validator");
        let vault = common::setting("AIRLOCK_CONFIG_VAULT_VM", "sys-config-vault");
        let created = common::setting("AIRLOCK_CONFIG_CREATED_QUBE", "airlock-work-from-config");
        let user = common::setting("AIRLOCK_QUBE_USER", "user");
        let message = common::setting(
            "AIRLOCK_CONFIG_APPLY_MESSAGE",
            &format!("smoke-applied-{id}", id = std::process::id()),
        );
        let mode = common::setting("AIRLOCK_CONFIG_VMS_SMOKE_MODE", "full");
        let stage_name = common::setting("AIRLOCK_CONFIG_APPLY_STAGE", "full");
        let action = common::setting("AIRLOCK_CONFIG_DOM0_SYSTEM_SWITCH_ACTION", "switch");
        let reason = common::setting(
            "AIRLOCK_CONFIG_DOM0_SYSTEM_REASON",
            if action == "boot" {
                "install next dom0 boot generation"
            } else {
                "staged dom0 NixOS system generation"
            },
        );

        Self {
            staging,
            validator,
            vault,
            created,
            user,
            message,
            mode,
            stage_name,
            action,
            reason,
        }
    }

    /// Start the existing informational receipt before any mutating phase.
    pub(super) fn record(&self) -> Value {
        json!({"schema":"airlock.config-vms-smoke.v1","reason":"staged Rust created a new qrexec-capable nix-closure VM","mode":self.mode,"config_apply_stage":self.stage_name,"staging":self.staging,"vault":self.vault,"validator":self.validator,"created_qube":self.created,"dom0_system_switch_action":self.action,"dom0_system_reason":self.reason})
    }
}
