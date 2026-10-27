//! Reconcile root imports and private capacity while retaining running-VM deferral.

use super::{
    NativeConfig, Requests, Session, feature, import_root, import_selected_root, path, physical,
    power, resize,
};
use crate::{setup_config::selection, store::ResolvedRoot};
use airlock_deployment_core::storage as verified;
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::path::{Path, PathBuf};

/// Root observations retained until shared-store reconciliation and boot metadata publication finish.
pub(super) struct RootState {
    /// Local root image, resolved from the selected generation or direct source.
    pub(super) image: PathBuf,
    /// Admitted root digest, empty when the legacy direct source supplies no digest.
    pub(super) hash: String,
    /// A running VM must keep its old root and boot identity until it stops.
    pub(super) deferred: bool,
}

/// Resolve and import only this VM's root, preserving the checked request at dispatch.
pub(super) fn reconcile(
    session: &mut Session,
    config: &NativeConfig<'_>,
    generation: Option<&str>,
    requests: &Requests<'_>,
) -> Result<RootState> {
    let domain = config.domain;
    let root = config.root;
    let authority = requests.backend;
    let checked = requests.setup;

    let mut root_image = PathBuf::new();
    let mut root_hash = String::new();
    let mut resolved = None;
    if generation.is_some() || !Path::new(root).exists() {
        let namespace = crate::store::runtime_namespace(domain);
        let selected_args = checked.map(|request| selection::arguments(request.root_arguments()));
        let mut args = vec![
            "storage",
            "pool",
            "resolve-root",
            "--domain",
            &namespace,
            "--root-source",
            root,
        ];
        if let Some(generation) = generation {
            args.extend(["--generation", generation]);
        }
        let record: ResolvedRoot = airlock_nix_core::state::parse_json(
            (if let Some(args) = selected_args {
                session.service(&args.iter().map(String::as_str).collect::<Vec<_>>())?
            } else {
                session.service(&args)?
            })
            .as_bytes(),
            Path::new("<resolved-root>"),
        )?;
        ensure!(
            record.domain.as_str() == namespace && record.root_source == root,
            "resolved root differs from requested namespace or source"
        );
        ensure!(
            record.image.is_absolute()
                && !record
                    .image
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir)),
            "invalid resolved root image path"
        );
        record.artifact.validate()?;
        root_image = record.image.clone();
        root_hash = record.artifact.sha256.clone();
        resolved = Some(record);
    }

    let root_current = feature(session, domain, "airlock-root-source").as_deref() == Some(root)
        && (root_hash.is_empty()
            || feature(session, domain, "airlock-root-artifact").as_deref() == Some(&root_hash));
    let root_deferred = !root_current && session.running(domain)?;
    if root_deferred {
        session.defer(domain, "domain-root", "source", root)?;
    } else if !root_current {
        if root_hash.is_empty() {
            root_image = physical(root);
            if root_image.is_dir() {
                root_image = root_image.join("root.img");
            }
            ensure!(
                root_image.is_file(),
                "Nix-native root image source is not a file: {root}"
            );
        }
        let service = path("AIRLOCK_DOM0_SERVICE", "airlock-dom0-service");
        session.change(
            service.to_str().context("service path")?,
            &["storage", "domain", "verify-native-volumes", domain],
        )?;
        if let Some(authority) = authority {
            let artifact = verified::RootArtifact {
                name: domain.into(),
                source: resolved
                    .as_ref()
                    .map_or(root, |r| r.root_source.as_str())
                    .into(),
                image: root_image.to_str().context("root image path")?.into(),
                hash: root_hash.clone(),
            };
            let observed = power(session, domain)?;
            import_root(
                session,
                authority
                    .root(&artifact, &observed)
                    .context("root import differs from checked source or halted target")?,
            )?;
        } else if let Some(request) = checked {
            let artifact = verified::RootArtifact {
                name: domain.into(),
                source: root.into(),
                image: root_image.to_str().context("root image path")?.into(),
                hash: root_hash.clone(),
            };
            let observed = power(session, domain)?;
            let request = request
                .root(&artifact, &observed)
                .context("root import differs from selected generation or halted VM")?;
            import_selected_root(session, request)?;
        } else {
            session.change(
                "qvm-volume",
                &[
                    "import",
                    &format!("{domain}:root"),
                    root_image.to_str().context("root image path")?,
                ],
            )?;
        }
        session.count("root_images_changed")?;
        session.action("domain-root", "import", domain, "source", root)?;
    }

    Ok(RootState {
        image: root_image,
        hash: root_hash,
        deferred: root_deferred,
    })
}

/// Enlarge private state only; never shrink it or resize a running VM's volume.
pub(super) fn private(
    session: &mut Session,
    domain: &str,
    desired: &Value,
    authority: Option<&verified::Backend<'_>>,
) -> Result<()> {
    if desired.is_null() {
        return Ok(());
    }
    let desired = desired
        .as_u64()
        .context("invalid persistent state volume size")?;
    let mut current_size = None;
    if session.apply {
        let current = session.command("qvm-volume", &["info", &format!("{domain}:private")]);
        current_size = current.as_ref().ok().and_then(|current| {
            current.lines().find_map(|line| {
                let mut words = line.split_whitespace();
                (words.next() == Some("size"))
                    .then(|| words.next().and_then(|value| value.parse::<u64>().ok()))
                    .flatten()
            })
        });
        if current_size.is_some_and(|current| current >= desired) {
            return Ok(());
        }
        if session.running(domain)? {
            return session.defer(
                domain,
                "domain-state-volume",
                "private",
                &desired.to_string(),
            );
        }
        // Missing capacity can justify deferring a known active VM, never resizing it.
        current_size.context("private capacity is missing or invalid")?;
    }
    if let Some(authority) = authority {
        let observed = power(session, domain)?;
        let request = authority
            .resize(&observed, current_size.context("missing private capacity")?)
            .context("private resize differs from checked capacity or halted target")?;
        resize(session, request)?;
    } else {
        session.change(
            "qvm-volume",
            &["resize", &format!("{domain}:private"), &desired.to_string()],
        )?;
    }
    session.count("state_volumes_changed")?;
    session.action(
        "domain-state-volume",
        "resize",
        domain,
        "private",
        &desired.to_string(),
    )?;
    Ok(())
}
