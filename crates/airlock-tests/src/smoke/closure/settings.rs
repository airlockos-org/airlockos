//! Parse explicit scenario settings before opening evidence files or invoking any VM operation.

use super::common;
use anyhow::{Result, ensure};
use serde_json::{Value, json};

/// Immutable inputs shared by the ordered generation and isolation phases.
pub(super) struct Scenario {
    /// Primary test VM whose generation is changed and restored.
    pub(super) domain: String,
    /// Independent VM whose running store must survive changes to the primary.
    pub(super) peer: String,
    /// Validated direct or config-flow application mode.
    pub(super) mode: String,
    /// Whether to run the explicitly requested guest reboot probe.
    pub(super) reboot: bool,
    /// Whether to run the optional installed graphical probe.
    pub(super) gui: bool,
    /// Configuration source VM used by config-flow application.
    pub(super) staging: String,
    /// Configuration validation VM whose readiness is checked before application.
    pub(super) validator: String,
    /// Configuration vault VM or the default second-generation source.
    pub(super) vault: String,
    /// Initial guest configuration message and persistent marker contents.
    pub(super) message: String,
    /// Changed configuration message expected in the second generation.
    pub(super) second_message: String,
    /// Expected config-flow guest role, empty for direct source reuse.
    pub(super) role: String,
}

impl Scenario {
    /// Validate invocation settings without inspecting or changing any VM.
    pub(super) fn from_environment() -> Result<Self> {
        let domain = common::setting("AIRLOCK_NIX_CLOSURE_DOMAIN", "airlock-closure-smoke");
        let peer = common::setting("AIRLOCK_NIX_CLOSURE_PEER_DOMAIN", &format!("{domain}-peer"));
        common::vm(&domain)?;
        common::vm(&peer)?;
        ensure!(domain != peer, "primary and peer must differ");
        let mode = common::setting("AIRLOCK_NIX_CLOSURE_APPLY_MODE", "direct");
        ensure!(
            ["direct", "config-flow"].contains(&mode.as_str()),
            "unsupported closure apply mode"
        );
        let reboot = enabled("AIRLOCK_NIX_CLOSURE_REBOOT_PROBE")?;
        let gui = enabled("AIRLOCK_NIX_CLOSURE_GUI_PROBE")?;
        let staging = common::setting("AIRLOCK_CONFIG_STAGING_VM", "sys-config-staging");
        let validator = common::setting("AIRLOCK_CONFIG_VALIDATOR_VM", "sys-config-validator");
        let vault = common::setting("AIRLOCK_CONFIG_VAULT_VM", "sys-config-vault");
        let message = common::setting(
            "AIRLOCK_NIX_CLOSURE_APPLY_MESSAGE",
            &format!(
                "nix-closure-smoke-{timestamp}",
                timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs()
            ),
        );
        let second_message = common::setting(
            "AIRLOCK_NIX_CLOSURE_APPLY_MESSAGE_GEN2",
            &format!("{message}-gen2"),
        );
        let role = if mode == "direct" {
            String::new()
        } else {
            common::setting("AIRLOCK_NIX_CLOSURE_EXPECTED_ROLE", "nix-closure-smoke")
        };

        Ok(Self {
            domain,
            peer,
            mode,
            reboot,
            gui,
            staging,
            validator,
            vault,
            message,
            second_message,
            role,
        })
    }

    /// Start the existing receipt with probes pending until their phase succeeds.
    pub(super) fn record(&self) -> Value {
        json!({
            "schema": "airlock.nix-closure-domain-smoke.v1",
            "domain": self.domain,
            "peer_domain": self.peer,
            "staging": self.staging,
            "validator": self.validator,
            "vault": self.vault,
            "apply_message": self.message,
            "apply_message_gen2": self.second_message,
            "apply_mode": self.mode,
            "reboot_status": "not-run",
            "shutdown_start_status": "not-run",
            "gui_status": "skipped",
        })
    }
}

/// Parse explicit optional probes before any live changes occur.
fn enabled(key: &str) -> Result<bool> {
    match common::setting(key, "0").as_str() {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        _ => anyhow::bail!("invalid boolean {key}"),
    }
}
