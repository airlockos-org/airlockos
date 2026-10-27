//! Typed setup protocol; extension fields are diagnostics, never completion evidence.

use crate::model::{CheckStatus, TransactionId};
use airlock_deployment_core::setup::Evidence;
use airlock_nix_core::identity::LockHash;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Setup protocol version, independent of the helper command-line protocol.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum Schema {
    /// Native and legacy setup result envelope.
    #[serde(rename = "airlock.setup-config.v1")]
    V1,
}

/// A prediction is never evidence of applied configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Mode {
    /// Apply the requested changes.
    Apply,
    /// Describe proposed changes only.
    Plan,
}

/// Scope of one invocation, independent of its phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Scope {
    /// All VMs in the supplied topology.
    All,
    /// Network-provider bootstrap scope.
    BootCritical,
    /// Complement of the bootstrap scope.
    Deferred,
    /// One backend or device helper.
    Single,
}

impl Scope {
    /// Stable scope identity shared with verified completion evidence.
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::BootCritical => "boot-critical",
            Self::Deferred => "deferred",
            Self::Single => "single",
        }
    }
}

/// Global finalization cannot be supplied by a preparation or per-VM result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Phase {
    /// Entire requested scope.
    All,
    /// Global preparation before VM reconciliation.
    PrepareOnly,
    /// Finish after global preparation and VM reconciliation.
    FinishOnly,
    /// One VM's storage and boot metadata.
    BackendOnly,
    /// One VM's devices.
    DevicesOnly,
}

/// Strict counters; missing or malformed values cannot be interpreted as zero.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct Counts {
    /// Template definitions reconciled by this invocation.
    pub templates_changed: u64,
    /// Kernel bundles installed by this invocation.
    pub kernels_changed: u64,
    /// VM registrations created or reconciled.
    pub domains_changed: u64,
    /// VM or global properties changed.
    pub prefs_changed: u64,
    /// VM feature settings changed.
    pub features_changed: u64,
    /// VM service settings changed.
    pub services_changed: u64,
    /// VM device assignments changed.
    pub devices_changed: u64,
    /// Managed Qubes policy publications.
    pub qrexec_policy_changed: u64,
    /// Immutable root images imported.
    pub root_images_changed: u64,
    /// Immutable software-volume definitions changed.
    pub store_volumes_changed: u64,
    /// Private-volume capacities changed.
    pub state_volumes_changed: u64,
    /// Immutable software views materialized.
    pub store_views_changed: u64,
    /// Qubes daemon restorations requested or observed.
    pub qubesd_restarts: u64,
    /// Declared VMs that setup could not reconcile.
    pub unsupported_domains_count: u64,
}

impl Counts {
    /// Select a supported diagnostic counter, refusing unknown names.
    pub(crate) fn counter(&mut self, name: &str) -> Result<&mut u64> {
        Ok(match name {
            "templates_changed" => &mut self.templates_changed,
            "kernels_changed" => &mut self.kernels_changed,
            "domains_changed" => &mut self.domains_changed,
            "prefs_changed" => &mut self.prefs_changed,
            "features_changed" => &mut self.features_changed,
            "services_changed" => &mut self.services_changed,
            "devices_changed" => &mut self.devices_changed,
            "qrexec_policy_changed" => &mut self.qrexec_policy_changed,
            "root_images_changed" => &mut self.root_images_changed,
            "store_volumes_changed" => &mut self.store_volumes_changed,
            "state_volumes_changed" => &mut self.state_volumes_changed,
            "store_views_changed" => &mut self.store_views_changed,
            "qubesd_restarts" => &mut self.qubesd_restarts,
            "unsupported_domains_count" => &mut self.unsupported_domains_count,
            _ => anyhow::bail!("unknown setup count"),
        })
    }

    /// Add informational counts with checked arithmetic. Security aggregation is separately verified.
    pub(super) fn add(&mut self, other: &Self) -> Result<()> {
        self.templates_changed = self
            .templates_changed
            .checked_add(other.templates_changed)
            .context("setup count overflow")?;
        self.kernels_changed = self
            .kernels_changed
            .checked_add(other.kernels_changed)
            .context("setup count overflow")?;
        self.domains_changed = self
            .domains_changed
            .checked_add(other.domains_changed)
            .context("setup count overflow")?;
        self.prefs_changed = self
            .prefs_changed
            .checked_add(other.prefs_changed)
            .context("setup count overflow")?;
        self.features_changed = self
            .features_changed
            .checked_add(other.features_changed)
            .context("setup count overflow")?;
        self.services_changed = self
            .services_changed
            .checked_add(other.services_changed)
            .context("setup count overflow")?;
        self.devices_changed = self
            .devices_changed
            .checked_add(other.devices_changed)
            .context("setup count overflow")?;
        self.qrexec_policy_changed = self
            .qrexec_policy_changed
            .checked_add(other.qrexec_policy_changed)
            .context("setup count overflow")?;
        self.root_images_changed = self
            .root_images_changed
            .checked_add(other.root_images_changed)
            .context("setup count overflow")?;
        self.store_volumes_changed = self
            .store_volumes_changed
            .checked_add(other.store_volumes_changed)
            .context("setup count overflow")?;
        self.state_volumes_changed = self
            .state_volumes_changed
            .checked_add(other.state_volumes_changed)
            .context("setup count overflow")?;
        self.store_views_changed = self
            .store_views_changed
            .checked_add(other.store_views_changed)
            .context("setup count overflow")?;
        self.qubesd_restarts = self
            .qubesd_restarts
            .checked_add(other.qubesd_restarts)
            .context("setup count overflow")?;
        self.unsupported_domains_count = self
            .unsupported_domains_count
            .checked_add(other.unsupported_domains_count)
            .context("setup count overflow")?;
        Ok(())
    }
}

/// Native report shared by producers, aggregation and completion consumers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SetupReport {
    /// Closed envelope version.
    pub schema: Schema,
    /// Observable helper outcome.
    pub status: CheckStatus,
    /// Applied work versus a prediction.
    pub mode: Mode,
    /// Requested VM scope.
    pub scope: Scope,
    /// Requested stage of setup.
    pub phase: Phase,
    /// Exact invocation, propagated to every helper.
    pub run_id: TransactionId,
    /// Canonical fingerprint of the effective input, not its filename.
    pub topology_hash: LockHash,
    /// Required diagnostic and unsupported-work counters.
    #[serde(flatten)]
    pub counts: Counts,
    /// Actual requests, retained for diagnostic consumers.
    pub live_actions: Vec<Value>,
    /// Required restart/deferred-work evidence.
    pub restart_actions: Vec<Value>,
    /// Required unsupported-work evidence.
    pub unsupported_domains: Vec<Value>,
    /// Explicit remaining-work flag; missing never means false.
    pub restart_required: bool,
    /// Run for which helper aggregation has already completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rust_reconciled: Option<TransactionId>,
    /// Helper-owned task identity, absent for root preparation/finalization reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<super::tasks::Task>,
    /// Complete task outcomes, checked independently against the caller's configuration.
    #[serde(default)]
    pub task_results: Vec<super::tasks::Outcome>,
    /// Human-readable outcome, independent of success classification.
    pub reason: String,
    /// Paths and informational extensions retained for external diagnostic consumers.
    #[serde(flatten)]
    pub diagnostics: BTreeMap<String, Value>,
}

impl SetupReport {
    /// Project every completion blocker, even when a counter and its list disagree.
    pub(super) fn evidence(&self) -> Evidence {
        Evidence {
            run: self.run_id.as_str().into(),
            topology: self.topology_hash.to_string(),
            scope: self.scope.as_str().into(),
            passed: self.status == CheckStatus::Passed,
            applied: self.mode == Mode::Apply,
            final_phase: matches!(self.phase, Phase::All | Phase::FinishOnly),
            pending: self.restart_required
                || !self.restart_actions.is_empty()
                || self
                    .live_actions
                    .iter()
                    .any(|a| matches!(a["action"].as_str(), Some("defer"))),
            unsupported: self
                .counts
                .unsupported_domains_count
                .max(self.unsupported_domains.len() as u64),
        }
    }
}
