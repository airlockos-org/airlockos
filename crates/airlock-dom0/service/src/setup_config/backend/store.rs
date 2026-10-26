//! Materialize a shared store and validate its receipt before deriving boot-setting authority.

use super::{NativeConfig, Requests, Session, feature, install_store, restart_daemon};
use crate::{model::InstalledStorageReceipt, setup_config::selection};
use airlock_deployment_core::storage as verified;
use anyhow::{Context, Result, ensure};
use std::path::Path;

/// Store observations retained separately from the opaque requests that authorize their effects.
pub(super) struct StoreState {
    /// Installed generation and the actual changes reported by the storage adapter.
    pub(super) receipt: Option<InstalledStorageReceipt>,
    /// Deployment receipt projected for the original checked store request.
    pub(super) evidence: Option<verified::StoreEvidence>,
    /// A running VM must keep its existing store and boot identity until it stops.
    pub(super) deferred: bool,
}

/// Materialize the store through the deployment, selected-boot or manual adapter in that order.
pub(super) fn reconcile(
    session: &mut Session,
    config: &NativeConfig<'_>,
    artifact: &Path,
    requests: &Requests<'_>,
) -> Result<StoreState> {
    let NativeConfig {
        domain,
        system,
        root,
        store,
        kernel: kernel_name,
        mode,
        view,
        mount,
        device,
        blob_device,
        ..
    } = *config;
    let authority = requests.backend;
    let store_request = requests.store;
    let checked = requests.setup;
    let selected = requests.selected;

    let current_mode = feature(session, domain, "airlock-store-mode")
        .filter(|mode| !mode.is_empty())
        .unwrap_or_else(|| "shared-closure".into());
    let store_current = feature(session, domain, "airlock-store-source").as_deref() == Some(store)
        && current_mode == mode;
    let store_deferred = !store_current && session.running(domain)?;
    let mut store_result: Option<InstalledStorageReceipt> = None;
    let mut observed_store = None;
    if store_deferred {
        session.defer(domain, "domain-store", "source", store)?;
    } else if session.apply {
        let output = if authority.is_some() {
            install_store(
                session,
                store_request.context("missing checked native store")?,
            )?
        } else if let Some(request) = checked {
            let args = selection::arguments(request.store_arguments());
            session.service(&args.iter().map(String::as_str).collect::<Vec<_>>())?
        } else {
            session.service(&[
                "storage",
                "domain",
                "ensure-store",
                domain,
                artifact.to_str().context("store artifact path")?,
                store,
                "--mode",
                mode,
                "--system",
                system,
                "--root",
                root,
                "--kernel",
                kernel_name,
                "--device",
                device,
                "--blob-device",
                blob_device,
                "--mountpoint",
                mount,
                "--view-backend",
                view,
            ])?
        };
        let result: InstalledStorageReceipt = airlock_nix_core::state::parse_json(
            output.as_bytes(),
            Path::new("<storage-installation>"),
        )?;

        if authority.is_some() {
            let evidence = evidence(&result);
            store_request
                .context("missing checked store request")?
                .outcome(&evidence)
                .context("store receipt differs from approved boot identity or generation")?;
            observed_store = Some(evidence);
        }
        if let Some(request) = checked {
            let observed = crate::store::handoff::installed(&result);
            ensure!(
                selected
                    .context("missing selected generation")?
                    .setup(&observed)
                    .is_some(),
                "storage outcome differs from checked setup selection"
            );
            ensure!(
                request.selection().generation == observed.generation,
                "storage selected another generation"
            );
        }
        let volumes = result
            .volumes_created
            .as_ref()
            .map(|v| v.iter().map(String::as_str).collect::<Vec<_>>())
            .unwrap_or_else(|| {
                if result.volume_created {
                    vec!["store"]
                } else {
                    vec![]
                }
            });
        for volume in volumes {
            session.count("store_volumes_changed")?;
            session.action("domain-store-volume", "create", domain, "volume", volume)?;
        }
        if result.view_created {
            session.count("store_views_changed")?;
            session.action("domain-store-view", "materialize", domain, "source", store)?;
        }
        if result.qubesd_restarted || result.qubesd_restart_required {
            if !result.qubesd_restarted {
                if let Some(request) = store_request {
                    let outcome = request
                        .outcome(observed_store.as_ref().context("missing storage outcome")?)
                        .context("storage outcome changed")?;
                    restart_daemon(
                        session,
                        outcome
                            .restart()
                            .context("storage outcome does not require daemon restoration")?,
                    )?;
                } else {
                    session.change("systemctl", &["try-restart", "qubesd.service"])?;
                }
            }
            session.count("qubesd_restarts")?;
            session.action("systemd", "restart", "", "service", "qubesd.service")?;
        }
        store_result = Some(result);
    } else {
        for volume in ["store", "store-data"] {
            session.count("store_volumes_changed")?;
            session.action("domain-store-volume", "create", domain, "volume", volume)?;
        }
        session.count("store_views_changed")?;
        session.action("domain-store-view", "materialize", domain, "source", store)?;
    }

    Ok(StoreState {
        receipt: store_result,
        evidence: observed_store,
        deferred: store_deferred,
    })
}

/// Project storage's typed boot identity for comparison in verified executable Rust.
fn evidence(value: &InstalledStorageReceipt) -> verified::StoreEvidence {
    verified::StoreEvidence {
        name: value.domain.to_string(),
        system: value.identity.system.clone(),
        root: value.identity.root_source.clone(),
        source: value.identity.source.clone(),
        kernel: value.identity.kernel_name.clone(),
        generation: value.identity.generation.get(),
        generation_text: value.identity.generation.to_string(),
        closure_hash: value.closure_hash.clone().unwrap_or_default(),
        view_image: value
            .view_image
            .clone()
            .or_else(|| value.image.clone())
            .unwrap_or_default(),
        blob_map: value.blob_map.clone().unwrap_or_default(),
        blob_volume: value.blob_volume.clone().unwrap_or_default(),
        restart_required: value.qubesd_restart_required,
        restarted: value.qubesd_restarted,
    }
}
