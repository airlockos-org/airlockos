//! Publish boot metadata only after root and store reconciliation permit the same identity.

use super::{NativeConfig, Requests, Session, feature, field, power, root, store};
use airlock_deployment_core::storage as verified;
use anyhow::{Context, Result, ensure};
use serde_json::Value;

/// Preserve deferred boot identities and derive every deployment setting from its checked request.
pub(super) fn publish(
    session: &mut Session,
    config: &NativeConfig<'_>,
    definition: &Value,
    exists: bool,
    root_state: &root::RootState,
    store_state: &store::StoreState,
    requests: &Requests<'_>,
) -> Result<()> {
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

    let accepted = match (requests.store, store_state.evidence.as_ref()) {
        (Some(request), Some(evidence)) => Some(
            request
                .outcome(evidence)
                .context("storage outcome changed")?,
        ),
        _ => None,
    };
    let root_evidence = verified::RootArtifact {
        name: domain.into(),
        source: root.into(),
        image: root_state.image.to_str().context("root image path")?.into(),
        hash: root_state.hash.clone(),
    };

    if session.apply || exists {
        let deferred = root_state.deferred || store_state.deferred;
        if deferred {
            if feature(session, domain, "airlock-system-source").as_deref() != Some(system) {
                session.defer(domain, "domain-system", "source", system)?;
            }
        } else {
            setting(
                session,
                authority,
                accepted.as_ref(),
                &root_evidence,
                requests.setup,
                ("qvm-prefs", domain, "kernel", kernel_name),
            )?;
            let mut options = field(&definition["prefs"], "kernelopts", "")?.to_owned();
            if options.is_empty() || options == "null" {
                options = "console=hvc0 init=/sbin/init".into();
            }
            for (key, value) in [
                ("init", "/sbin/init"),
                ("airlock.system", system),
                ("airlock.storedev", device),
                ("airlock.storefmt", "erofs"),
                ("airlock.storeblobdev", blob_device),
            ] {
                option(&mut options, key, value)?;
            }
            setting(
                session,
                authority,
                accepted.as_ref(),
                &root_evidence,
                requests.setup,
                ("qvm-prefs", domain, "kernelopts", &options),
            )?;
        }
        setting(
            session,
            authority,
            accepted.as_ref(),
            &root_evidence,
            requests.setup,
            ("qvm-features", domain, "airlock-backend", "nix-closure"),
        )?;
        if !deferred {
            for (key, value) in [
                ("airlock-system-source", system),
                ("airlock-root-source", root),
                ("airlock-root-artifact", root_state.hash.as_str()),
                ("airlock-store-source", store),
                ("airlock-store-mode", mode),
                ("airlock-store-view-backend", view),
                ("airlock-store-filesystem", "erofs"),
                ("airlock-store-mountpoint", mount),
                ("airlock-store-device", device),
                ("airlock-store-blob-device", blob_device),
                ("airlock-store-read-only", "True"),
            ] {
                setting(
                    session,
                    authority,
                    accepted.as_ref(),
                    &root_evidence,
                    requests.setup,
                    ("qvm-features", domain, key, value),
                )?;
            }
            if let Some(result) = &store_state.receipt {
                for (key, value) in [
                    (
                        "airlock-store-generation",
                        Some(result.identity.generation.to_string()),
                    ),
                    ("airlock-store-closure-hash", result.closure_hash.clone()),
                    (
                        "airlock-store-view-image",
                        result.view_image.clone().or_else(|| result.image.clone()),
                    ),
                    ("airlock-store-blob-map", result.blob_map.clone()),
                    ("airlock-store-blob-volume", result.blob_volume.clone()),
                ] {
                    if let Some(value) = value.filter(|value| !value.is_empty()) {
                        setting(
                            session,
                            authority,
                            accepted.as_ref(),
                            &root_evidence,
                            requests.setup,
                            ("qvm-features", domain, key, &value),
                        )?;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Select derived settings by typed fields; unknown keys cannot fall back to a raw mutation.
fn setting(
    session: &mut Session,
    authority: Option<&verified::Backend<'_>>,
    outcome: Option<&verified::StoreOutcome<'_>>,
    root: &verified::RootArtifact,
    selected: Option<&airlock_deployment_core::boot::SetupRequest<'_>>,
    proposed: (&str, &str, &str, &str),
) -> Result<()> {
    let (program, domain, key, value) = proposed;
    if let Some(selected) = selected {
        use airlock_deployment_core::boot::BootField;
        let field = match (program, key) {
            ("qvm-prefs", "kernel") => Some(BootField::Kernel),
            ("qvm-features", "airlock-system-source") => Some(BootField::System),
            ("qvm-features", "airlock-root-source") => Some(BootField::Root),
            ("qvm-features", "airlock-store-source") => Some(BootField::Store),
            _ => None,
        };
        if let Some(field) = field {
            return selected_setting(session, selected, field);
        }
    }
    let Some(authority) = authority else {
        return session.setting(program, domain, key, value);
    };
    if session
        .command(program, &[domain, key])
        .is_ok_and(|current| {
            airlock_deployment_core::configuration::value_matches(value, Some(&current))
        })
    {
        return Ok(());
    }
    let observed = power(session, domain)?;
    let request = if key == "airlock-root-artifact" {
        authority.root_setting(root, &observed)
    } else if let Some(field) = match key {
        "airlock-store-generation" => Some(verified::ReceiptField::Generation),
        "airlock-store-closure-hash" => Some(verified::ReceiptField::ClosureHash),
        "airlock-store-view-image" => Some(verified::ReceiptField::ViewImage),
        "airlock-store-blob-map" => Some(verified::ReceiptField::BlobMap),
        "airlock-store-blob-volume" => Some(verified::ReceiptField::BlobVolume),
        _ => None,
    } {
        outcome
            .context("missing accepted generation receipt")?
            .setting(field, &observed)
    } else {
        let field = match key {
            "kernel" => verified::BootField::Kernel,
            "kernelopts" => verified::BootField::Kernelopts,
            "airlock-backend" => verified::BootField::Backend,
            "airlock-system-source" => verified::BootField::System,
            "airlock-root-source" => verified::BootField::Root,
            "airlock-store-source" => verified::BootField::Source,
            "airlock-store-mode" => verified::BootField::Mode,
            "airlock-store-view-backend" => verified::BootField::ViewBackend,
            "airlock-store-filesystem" => verified::BootField::Filesystem,
            "airlock-store-mountpoint" => verified::BootField::Mountpoint,
            "airlock-store-device" => verified::BootField::Device,
            "airlock-store-blob-device" => verified::BootField::BlobDevice,
            "airlock-store-read-only" => verified::BootField::ReadOnly,
            _ => anyhow::bail!("unclassified native boot setting: {key}"),
        };
        authority.setting(field, &observed)
    }
    .context("boot setting requires original identity and named halted state")?;
    let args = request.arguments();
    ensure!(
        request.program() == program && args == [domain, key, value],
        "derived boot setting differs from checked backend"
    );
    apply_setting(session, request)
}

/// Consume a checked setting without separate VM, feature or value parameters.
fn apply_setting(session: &mut Session, request: verified::BootRequest<'_>) -> Result<()> {
    let args = request.arguments();
    session.setting(request.program(), &args[0], &args[1], &args[2])
}

/// Keep the fixed property/feature key and value selected by the verified request.
fn selected_setting(
    session: &mut Session,
    request: &airlock_deployment_core::boot::SetupRequest<'_>,
    field: airlock_deployment_core::boot::BootField,
) -> Result<()> {
    let program = request.setting_program(field);
    let args = request.setting_arguments(field);
    session.setting(program, &args[0], &args[1], &args[2])
}

/// Append a required boot option or reject a conflicting user-specified value.
pub(super) fn option(options: &mut String, key: &str, value: &str) -> Result<()> {
    let prefix = format!("{key}=");
    let declared = options
        .split(' ')
        .filter_map(|word| word.strip_prefix(&prefix))
        .collect::<Vec<_>>();
    if !declared.is_empty() {
        ensure!(
            declared.iter().all(|current| *current == value),
            "nix-closure kernelopts {key} conflicts with expected {value}"
        );
    } else {
        if !options.is_empty() {
            options.push(' ');
        }
        options.push_str(&format!("{key}={value}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Required boot identities cannot be replaced by conflicting command-line options.
    #[test]
    fn boot_options_preserve_declared_values() -> Result<()> {
        let mut options = "console=hvc0".into();
        option(&mut options, "init", "/sbin/init")?;
        let original = options.clone();
        option(&mut options, "init", "/sbin/init")?;
        assert_eq!(options, original);
        assert!(option(&mut options, "init", "/wrong").is_err());
        let mut duplicate = "init=/sbin/init init=/wrong".into();
        assert!(option(&mut duplicate, "init", "/sbin/init").is_err());
        let mut duplicate = "init=/sbin/init init=/sbin/init".into();
        option(&mut duplicate, "init", "/sbin/init")?;
        Ok(())
    }
}
