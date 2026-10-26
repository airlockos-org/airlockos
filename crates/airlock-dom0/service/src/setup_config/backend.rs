//! Native closure boot metadata and private/root/store volume reconciliation through existing adapters.

mod boot;

mod configuration;

mod kernel;

mod root;

mod store;

use super::runtime::{Session, path};
use airlock_deployment_core::storage as verified;
use anyhow::{Context, Result, ensure};
use configuration::NativeConfig;
use serde_json::Value;
use std::path::{Path, PathBuf};

pub(super) use kernel::install as kernel;

/// Borrowed opaque requests keep deployment and selected-boot dispatch tied to their original gates.
/// Configuration and observations alone cannot construct any of these requests.
struct Requests<'a> {
    /// Durable deployment authority, absent for boot and manual reconciliation.
    backend: Option<&'a verified::Backend<'a>>,
    /// Topology-bound selected generation, also retained during native deployment.
    setup: Option<&'a airlock_deployment_core::boot::SetupRequest<'a>>,
    /// Exact staged store request, required for deployment materialization and receipt acceptance.
    store: Option<&'a verified::StoreRequest<'a>>,
    /// Authenticated generation used to recheck the returned installation identity.
    selected: Option<&'a airlock_deployment_core::boot::SelectedGeneration>,
}

/// Translate logical store paths only for the explicitly selected private Nix root.
fn physical(source: &str) -> PathBuf {
    let root = std::env::var_os("AIRLOCK_NIX_ROOT").map(PathBuf::from);
    if std::env::var("AIRLOCK_USE_HOST_NIX_STORE").as_deref() != Ok("1")
        && source.starts_with("/nix/store/")
        && let Some(root) = root
        && root != Path::new("/")
        && !root.as_os_str().is_empty()
    {
        return root.join(source.trim_start_matches('/'));
    }
    source.into()
}

/// Return a backend string default without accepting malformed object/array values.
fn field<'a>(value: &'a Value, key: &str, default: &'a str) -> Result<&'a str> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(value) => value
            .as_str()
            .with_context(|| format!("backend {key} must be a string")),
    }
}

/// Read a declared source and reject an empty identity before any volume mutation.
fn source<'a>(backend: &'a Value, component: &str) -> Result<&'a str> {
    backend[component]["source"]
        .as_str()
        .filter(|source| !source.is_empty())
        .with_context(|| format!("Nix-native domain {component} source is missing"))
}

/// Read one observed feature only in apply mode, keeping plan mode independent of mutable metadata.
fn feature(session: &mut Session, domain: &str, key: &str) -> Option<String> {
    if session.apply {
        session.command("qvm-features", &[domain, key]).ok()
    } else {
        None
    }
}

/// Reconcile the native backend without changing a running VM's recorded boot identity prematurely.
pub(super) fn reconcile(session: &mut Session, domain: &str) -> Result<()> {
    reconcile_with(session, domain, None, None)
}

/// Execute a selected backend after rechecking its topology, including explicit backend-only invocations.
pub(super) fn reconcile_selected(
    session: &mut Session,
    domain: &str,
    selected: &airlock_deployment_core::boot::SelectedGeneration,
) -> Result<()> {
    reconcile_with(session, domain, None, Some(selected))
}

/// Share reconciliation observations while deployment mutation consumes opaque requests.
fn reconcile_with(
    session: &mut Session,
    domain: &str,
    staged_authority: Option<&verified::staging::StagedBackend<'_>>,
    selected: Option<&airlock_deployment_core::boot::SelectedGeneration>,
) -> Result<()> {
    let authority = staged_authority.map(|staged| staged.backend());
    let definition = session.topology["domains"][domain].clone();
    if definition["backend"]["type"] != "nix-closure" {
        ensure!(
            selected.is_none(),
            "selected boot backend is missing or unsupported"
        );
        return Ok(());
    }
    ensure!(
        field(&definition, "class", "StandaloneVM")? == "StandaloneVM",
        "nix-closure backend requires StandaloneVM class for {domain}"
    );
    let backend = &definition["backend"];
    let checked = selected
        .map(|selected| -> Result<_> {
            let backend: crate::model::Backend = serde_json::from_value(backend.clone())?;
            let generation = selected.selection().generation.to_string().parse()?;
            let wanted = crate::store::handoff::expected(&domain.parse()?, &backend, generation)?;
            selected
                .setup(&wanted)
                .context("backend differs from checked boot selection")
        })
        .transpose()?;
    let default_kernel = format!("airlock-{domain}");
    let config = configuration::decode(domain, &definition, checked.as_ref(), &default_kernel)?;
    let generation = configuration::generation(session, domain, staged_authority, selected)?;

    if !config.kernel_source.is_empty() {
        if let Some(authority) = authority {
            let request = authority
                .kernel()
                .context("kernel absent from checked backend")?;
            install_kernel(session, request)?;
        } else {
            kernel(session, domain, config.kernel, config.kernel_source)?;
        }
    }

    if let Some(authority) = authority {
        let native = authority
            .definition()
            .native
            .as_ref()
            .context("missing native backend")?;
        if let Some(expected) = native.generation {
            ensure!(
                generation.as_ref().and_then(|g| g.parse::<u64>().ok()) == Some(expected),
                "staged generation differs from original release"
            );
        }
    }
    let store_request = staged_authority
        .map(|a| {
            a.store()
                .context("store selection differs from checked staging")
        })
        .transpose()?;
    let artifact = if generation.is_some() {
        PathBuf::from(config.store)
    } else {
        let artifact = physical(config.store);
        ensure!(
            artifact.is_dir()
                && artifact.join("store-paths").is_file()
                && artifact.join("manifest.json").is_file(),
            "Nix-native shared closure source is missing store-paths or manifest.json: {store}",
            store = config.store
        );
        artifact
    };
    let names = session.command(
        "qvm-ls",
        &["--raw-data", "--fields", "NAME", "--no-spinner"],
    )?;
    let exists = names.lines().any(|name| name == domain);
    if session.apply || exists {
        ensure!(exists, "Rust configuration has not created {domain}");
        let classes = session.command(
            "qvm-ls",
            &["--raw-data", "--fields", "NAME,CLASS", "--no-spinner"],
        )?;
        ensure!(
            classes
                .lines()
                .any(|line| line == format!("{domain}|StandaloneVM")),
            "nix-closure domain class is not StandaloneVM: {domain}"
        );
    }

    let requests = Requests {
        backend: authority,
        setup: checked.as_ref(),
        store: store_request.as_ref(),
        selected,
    };
    let root_state = root::reconcile(session, &config, generation.as_deref(), &requests)?;
    root::private(
        session,
        domain,
        &backend["state"]["persistent_size"],
        authority,
    )?;
    let store_state = store::reconcile(session, &config, &artifact, &requests)?;

    boot::publish(
        session,
        &config,
        &definition,
        exists,
        &root_state,
        &store_state,
        &requests,
    )
}

/// Decode every native backend from the admitted topology before authority publication.
pub(crate) fn definitions(
    topology: &Value,
    service: &str,
    generations: &std::collections::BTreeMap<
        airlock_nix_core::identity::GuestName,
        crate::model::GenerationId,
    >,
) -> Result<Vec<verified::Definition>> {
    topology["domains"]
        .as_object()
        .context("missing topology domains")?
        .iter()
        .map(|(name, d)| {
            let native = if d["backend"]["type"] == "nix-closure" {
                let b = &d["backend"];
                ensure!(
                    field(d, "class", "StandaloneVM")? == "StandaloneVM",
                    "native backend requires StandaloneVM"
                );
                let system = source(b, "system")?;
                let root = source(b, "root")?;
                let store = source(b, "store")?;
                ensure!(
                    field(&b["store"], "mode", "shared-closure")? == "shared-closure"
                        && field(&b["store"], "view_backend", "erofs-objectmap")?
                            == "erofs-objectmap"
                        && field(&b["store"], "mountpoint", "/nix/store")? == "/nix/store"
                        && field(&b["store"], "device", "/dev/xvde")? == "/dev/xvde"
                        && field(&b["store"], "blob_device", "/dev/xvdf")? == "/dev/xvdf",
                    "unsupported native store layout"
                );
                let declared = field(&b["kernel"], "name", "")?;
                let kernel = if declared.is_empty() || declared == "null" {
                    format!("airlock-{name}")
                } else {
                    declared.into()
                };
                ensure!(
                    !kernel.is_empty() && kernel != "." && kernel != ".." && !kernel.contains('/'),
                    "invalid native kernel name"
                );
                let private_size = match &b["state"]["persistent_size"] {
                    Value::Null => None,
                    value => Some(value.as_u64().context("invalid private capacity")?),
                };
                let generation = generations
                    .get(&name.parse()?)
                    .map(|g| g.to_string().parse())
                    .transpose()?;
                let mut kernelopts = field(&d["prefs"], "kernelopts", "")?.to_owned();
                if kernelopts.is_empty() || kernelopts == "null" {
                    kernelopts = "console=hvc0 init=/sbin/init".into();
                }
                for (key, value) in [
                    ("init", "/sbin/init"),
                    ("airlock.system", system),
                    ("airlock.storedev", "/dev/xvde"),
                    ("airlock.storefmt", "erofs"),
                    ("airlock.storeblobdev", "/dev/xvdf"),
                ] {
                    boot::option(&mut kernelopts, key, value)?;
                }
                Some(verified::Native {
                    system: system.into(),
                    root: root.into(),
                    source: store.into(),
                    artifact: physical(store)
                        .to_str()
                        .context("invalid artifact path")?
                        .into(),
                    kernel,
                    kernel_source: field(&b["kernel"], "source", "")?.into(),
                    kernelopts,
                    private_size,
                    generation,
                })
            } else {
                None
            };
            Ok(verified::Definition {
                name: name.clone(),
                native,
                service: service.into(),
            })
        })
        .collect()
}

/// Restore only qubesd when a validated storage outcome requires it.
fn restart_daemon(session: &mut Session, request: verified::RestartRequest<'_>) -> Result<()> {
    let args = request.arguments();
    session.change(
        "systemctl",
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
    )
}

/// Query the exact named state again immediately before a destructive volume request.
fn power(session: &mut Session, name: &str) -> Result<verified::Power> {
    Ok(verified::Power {
        name: name.into(),
        state: airlock_deployment_core::inventory::PowerState::classify(&session.state(name)?),
    })
}

/// Consume the checked kernel identity at the filesystem installation boundary.
fn install_kernel(session: &mut Session, request: verified::KernelRequest<'_>) -> Result<()> {
    let (domain, name, source) = request.parameters();
    kernel(session, domain, name, source)
}

/// Forward only the verified root-volume target and admitted image.
fn import_root(session: &mut Session, request: verified::RootRequest<'_>) -> Result<()> {
    let args = request.arguments();
    session.change(
        "qvm-volume",
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
    )
}

/// Consume the checked root request without accepting an independent VM or image path.
fn import_selected_root(
    session: &mut Session,
    request: airlock_deployment_core::boot::RootRequest<'_>,
) -> Result<()> {
    let args = request.arguments();
    session.change(
        "qvm-volume",
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
    )
}

/// Decimal rendering cannot substitute a different capacity or volume selector.
fn resize(session: &mut Session, request: verified::ResizeRequest<'_>) -> Result<()> {
    session.change(
        "qvm-volume",
        &["resize", &request.volume(), &request.size().to_string()],
    )
}

/// The storage service retains admission, locking and offline-attachment safeguards.
fn install_store(session: &mut Session, request: &verified::StoreRequest<'_>) -> Result<String> {
    let args = super::selection::arguments(request.dispatch_arguments());
    session.command(
        request.program(),
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
    )
}

/// Reconcile a selected boot generation in-process and retain a run-specific helper receipt.
pub(crate) fn apply_boot(
    selected: &airlock_deployment_core::boot::SelectedGeneration,
    definition: &airlock_deployment_core::configuration::Definition,
    log: &Path,
    apply: bool,
) -> Result<Option<super::report::SetupReport>> {
    let helper = definition
        .helper
        .as_ref()
        .context("missing setup topology")?;
    let directory = super::report::helper_directory(log, &definition.name, "--backend-only")?;
    let mut session = Session::at(
        Path::new(&helper.topology),
        apply,
        "single",
        "backend-only",
        directory,
    )?;
    session.result.task = Some(super::report::tasks::Task::Vm {
        domain: definition.name.parse()?,
        kind: super::report::tasks::Kind::Backend,
    });
    let result = reconcile_with(&mut session, &definition.name, None, Some(selected));
    session.finish(&result)?;
    result?;
    Ok(Some(session.result))
}

/// Run native deployment backend reconciliation inside the coordinator, with typed effect gates.
pub(crate) fn apply_deployment(
    authority: &crate::coordinator::approval::DurableAuthorization,
    record: &crate::model::Record,
    staged: &verified::staging::StagedGenerations,
    index: usize,
    definition: &airlock_deployment_core::configuration::Definition,
    log: &Path,
) -> Result<Option<super::report::SetupReport>> {
    let Some(staged_backend) = authority.staged_storage(record, index, staged)? else {
        return Ok(None);
    };
    let backend = staged_backend.backend();
    ensure!(
        backend.definition().name == definition.name,
        "backend/configuration index differs"
    );
    let helper = definition
        .helper
        .as_ref()
        .context("missing admitted topology")?;
    let directory =
        super::report::helper_directory_for(log, &definition.name, "--backend-only", &record.id)?;
    let mut session = Session::at(
        Path::new(&helper.topology),
        true,
        "single",
        "backend-only",
        directory,
    )?;
    // Native deployment carries its checked selection in memory, without ambient staging input.
    session.staged = None;
    session.result.run_id = record.id.clone();
    session.result.task = Some(super::report::tasks::Task::Vm {
        domain: definition.name.parse()?,
        kind: super::report::tasks::Kind::Backend,
    });
    let result = reconcile_with(
        &mut session,
        &definition.name,
        Some(&staged_backend),
        staged_backend.selected(),
    );
    session.finish(&result)?;
    result?;
    Ok(Some(session.result))
}
