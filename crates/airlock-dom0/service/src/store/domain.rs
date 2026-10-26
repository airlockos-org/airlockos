//! Attach committed immutable generations using upstream Qubes storage objects.
//! A running VM keeps its existing boot identity; additive builder handoffs wait
//! until it stops, and qubesd is restored even when an offline update fails.

mod attachment;

mod snapshot;

use self::snapshot::Snapshot;
use super::{
    builder,
    domain_cli::{Ensure, Target},
    fs::*,
    generations::{self, Admission},
    pool_cli, prepared, records, runtime_namespace,
};
use crate::model::{GenerationReceipt, InstallationSchema, InstalledStorageReceipt};
use airlock_nix_core::identity::GuestName;
use anyhow::{Context, Result, anyhow, ensure};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

fn bridge(request: &Value) -> Result<Snapshot> {
    let program = std::env::var_os("AIRLOCK_QUBES_OBJECTS_BIN")
        .map(PathBuf::from)
        .map(Ok)
        .unwrap_or_else(std::env::current_exe)?;
    let output = airlock_nix_core::runtime::process::run(
        Command::new(&program).args(["storage", "qubes-objects"]),
        Some(serde_json::to_vec(request)?),
        Some(Duration::from_secs(120)),
    )?
    .checked(&program.to_string_lossy())?;
    let snapshot: Snapshot = serde_json::from_slice(&output)?;
    let domain: GuestName = serde_json::from_value(request["domain"].clone())?;
    snapshot.validate(&domain)?;
    Ok(snapshot)
}

fn snapshot(domain: &GuestName) -> Result<Snapshot> {
    bridge(&json!({"operation":"snapshot","domain":domain}))
}

/// Reject shared or derived writable state before importing a root image.
pub(super) fn verify_native(domain: &GuestName) -> Result<()> {
    snapshot(domain)?.verify_isolation()
}

/// Check the image constructor's reloaded Qubes objects without contacting a daemon.
pub(super) fn verify_snapshot(domain: &GuestName, request: &Value) -> Result<()> {
    let snapshot: Snapshot = serde_json::from_value(request["snapshot"].clone())?;
    snapshot.validate(domain)?;
    snapshot.verify_isolation()?;
    let configs: Vec<Value> = serde_json::from_value(request["volumes"].clone())?;
    let metadata = configs
        .iter()
        .find(|config| config["name"] == "store")
        .context("missing expected metadata volume")?;
    let data = configs
        .iter()
        .find(|config| config["name"] == "store-data")
        .context("missing expected external-data volume")?;
    for (feature, value) in [
        ("airlock-store-generation", &metadata["generation"]),
        ("airlock-store-closure-hash", &metadata["closure_hash"]),
        ("airlock-store-view-image", &metadata["view_path"]),
        ("airlock-store-blob-map", &data["blob_map_path"]),
    ] {
        ensure!(
            value.as_str() == Some(snapshot.feature(feature)),
            "prepared store feature binding mismatch: {feature}"
        );
    }

    ensure!(
        snapshot.matches(&configs),
        "prepared store would require boot-time mutation: {domain}"
    );
    ensure!(
        snapshot.feature("airlock-store-source")
            == request["source"]
                .as_str()
                .context("missing source binding")?
            && snapshot.feature("airlock-store-mode") == "shared-closure"
            && snapshot.feature("airlock-store-view-backend") == "erofs-objectmap",
        "prepared store feature mismatch"
    );
    let mut expected = vec![("store", "xvde"), ("store-data", "xvdf")];
    if ["usr-assistant", "sys-ctrl"].contains(&domain.as_str()) {
        expected.extend([("builder-store", "xvdg"), ("builder-data", "xvdh")]);
    }
    snapshot.frontends(&[], &expected)
}

fn load(target: &Target, generation: u64) -> Result<GenerationReceipt> {
    let _lock = PoolLock::acquire(&target.pool_root.join("admission.lock"))?;
    generations::load(
        &target.pool_root,
        &target.pool_root,
        &runtime_namespace(target.domain.as_str()),
        generation,
    )
}

/// Describe the immutable volume pair; offline callers supply its physical image size.
pub(super) fn shared_configs(
    target: &Target,
    admission: &GenerationReceipt,
    metadata_size: Option<u64>,
) -> Result<Vec<Value>> {
    attachment::project(target, admission, metadata_size)
}

fn check_features(target: &Target, vm: &Snapshot) -> Result<Option<GenerationReceipt>> {
    let generation = vm.feature("airlock-store-generation");
    if generation.is_empty() {
        return Ok(None);
    }
    let admission = load(target, generation.parse()?)?;
    let source = vm.feature("airlock-store-source");
    ensure!(
        source.is_empty()
            || admission.identity.source == source
            || admission.approval_source.as_deref() == Some(source),
        "Nix-native store feature/source mismatch"
    );
    for (feature, actual) in [
        (
            "airlock-store-closure-hash",
            admission.closure_hash.as_str(),
        ),
        (
            "airlock-store-view-image",
            admission
                .metadata_image
                .to_str()
                .context("metadata image path")?,
        ),
        (
            "airlock-store-blob-map",
            admission.blob_map.to_str().context("blob map path")?,
        ),
    ] {
        let expected = vm.feature(feature);
        ensure!(
            expected.is_empty() || actual == expected,
            "Nix-native store feature/{feature} mismatch"
        );
    }
    Ok(Some(admission))
}

fn boot_matches(admission: &GenerationReceipt, args: &Ensure) -> bool {
    admission.identity.system == args.system
        && admission.identity.root_source == args.root
        && admission.identity.kernel_name == args.kernel
}

/// A retained request keeps its authenticated receipt and original target until dispatch.
struct Retained<'a> {
    // Exact target whose committed records were validated.
    target: &'a Target,
    // Private receipt cannot be replaced by an independently supplied generation.
    receipt: GenerationReceipt,
    // Verus-checked complete boot identity.
    selected: airlock_deployment_core::boot::SelectedGeneration,
}

impl Retained<'_> {
    fn install(&self, observed: &Snapshot, source: &str) -> Result<InstalledStorageReceipt> {
        let actual = super::handoff::observed(&self.receipt)?;
        ensure!(
            self.selected.setup(&actual).is_some(),
            "retained receipt changed before attachment"
        );
        install_shared(self.target, &self.receipt, observed, source)
    }
}

fn staged(args: &Ensure) -> Result<Option<Retained<'_>>> {
    let supplied = match std::env::var_os("AIRLOCK_STAGED_GENERATIONS") {
        Some(path) => {
            let mapping: Value = read(Path::new(&path))?;
            mapping
                .get(args.target.domain.as_str())
                .map(|g| {
                    g.as_u64()
                        .or_else(|| g.as_str()?.parse().ok())
                        .context("invalid staged generation")
                })
                .transpose()?
        }
        None => None,
    };
    if let (Some(expected), Some(supplied)) = (args.generation, supplied) {
        ensure!(
            expected == supplied,
            "staged generation differs from request"
        );
    }
    let Some(generation) = args.generation.or(supplied) else {
        return Ok(None);
    };
    ensure!(generation > 0, "invalid requested generation");
    let admission = load(&args.target, generation)?;
    let wanted = airlock_deployment_core::boot::Selection {
        domain: args.target.domain.to_string(),
        generation,
        system: args.system.clone(),
        root: args.root.clone(),
        source: args
            .artifact
            .to_str()
            .context("non-UTF-8 store source")?
            .into(),
        kernel: args.kernel.clone(),
        mode: args.mode.clone(),
        device: args.target.device.clone(),
        blob_device: args.target.blob_device.clone(),
        mountpoint: args.target.mountpoint.clone(),
        backend: args.view_backend.clone(),
    };
    let observed = super::handoff::observed(&admission)?;
    let selected = airlock_deployment_core::boot::SelectedGeneration::check(wanted, &observed)
        .context("staged generation identity mismatch")?;
    ensure!(
        admission.approval_source.as_deref() == Some(args.source.as_str()),
        "staged generation approval source mismatch"
    );
    Ok(Some(Retained {
        target: &args.target,
        receipt: admission,
        selected,
    }))
}

fn admit(args: &Ensure) -> Result<GenerationReceipt> {
    let target = &args.target;
    let _lock = PoolLock::acquire(&target.pool_root.join("admission.lock"))?;
    if args.artifact.join("prepared.json").try_exists()? {
        let generation = prepared::verify_prepared(&serde_json::to_value(args)?)?;
        return generations::load(
            &target.pool_root,
            &target.pool_root,
            &runtime_namespace(target.domain.as_str()),
            generation.as_u64().context("invalid prepared generation")?,
        );
    }

    let physical = pool_cli::physical_store();
    let source_identity = args.artifact.to_str().context("non-UTF-8 closure source")?;
    let source = if source_identity.starts_with("/nix/store/") {
        physical.join(entry(source_identity)?)
    } else {
        args.artifact.clone()
    };
    ensure!(
        !args.require_retained,
        "reviewed deployment requires a retained or prepared generation; refusing implicit admission"
    );
    let value = generations::admit(&Admission {
        pool: &target.pool_root,
        domain: &runtime_namespace(target.domain.as_str()),
        system: &args.system,
        source: &source,
        source_identity,
        root_source: &args.root,
        kernel: &args.kernel,
        physical: &physical,
        segment_target: pool_cli::target(None)?,
        verification: &args.verify_mode,
        approved_by: "dom0",
        approval_source: &args.source,
        activate: false,
        retain: true,
        previous_index: None,
        device: &target.device,
        blob_device: &target.blob_device,
        mountpoint: &target.mountpoint,
    })?;
    Ok(serde_json::from_value(value)?)
}

/// Reuse the exact current boot identity or attach an approved successor to a stopped VM.
pub(super) fn ensure(args: &Ensure) -> Result<InstalledStorageReceipt> {
    let target = &args.target;
    // An explicit retained selection must validate before any Qubes observation or fallback decision.
    let staged = staged(args)?;
    let vm = snapshot(&target.domain)?;
    vm.verify_isolation()?;
    vm.verify_pool(target)?;
    let mut projected = vec![json!({"name":"store"}), json!({"name":"store-data"})];
    let mut frontends = vec![
        ("store", target.device.as_str()),
        ("store-data", target.blob_device.as_str()),
    ];
    if ["usr-assistant", "sys-ctrl"].contains(&target.domain.as_str()) {
        let (configs, descriptor) = builder_configs(target)?;
        if configs.is_empty() {
            ensure!(
                !vm.volumes
                    .iter()
                    .any(|volume| volume.name.starts_with("builder-")),
                "attached builder volumes have no authenticated descriptor"
            );
        } else {
            check_builder(target, &vm, &configs, &descriptor)?;
            projected.extend(configs);
            frontends.extend([("builder-store", "xvdg"), ("builder-data", "xvdh")]);
        }
    }
    vm.frontends(&projected, &frontends)?;

    let source_current = vm.feature("airlock-store-source") == args.source
        && vm.feature("airlock-store-mode") == "shared-closure"
        && vm.feature("airlock-store-view-backend") == args.view_backend;
    let current = if source_current {
        check_features(target, &vm)?
    } else {
        None
    };
    let reusable = current.as_ref().filter(|admission| {
        boot_matches(admission, args)
            && staged.as_ref().is_none_or(|requested| {
                requested.receipt.identity.generation == admission.identity.generation
            })
    });
    let unchanged = if let Some(admission) = reusable {
        vm.matches(&shared_configs(target, admission, None)?)
    } else {
        false
    };

    let mut result = if unchanged {
        vm.frontends(
            &[],
            &[
                ("store", &target.device),
                ("store-data", &target.blob_device),
            ],
        )?;
        let admission = reusable.context("missing reusable generation")?;
        let admission = staged
            .as_ref()
            .map_or(admission, |retained| &retained.receipt);
        receipt(target, admission, &args.source, Attachment::default())
    } else {
        ensure!(
            !vm.running,
            "shared store source changed but domain is running: {}",
            target.domain
        );
        match staged {
            Some(retained) => retained.install(&vm, &args.source)?,
            None => {
                // Only the separately selected manual policy can reach admission.
                let admission = match reusable {
                    Some(admission) => admission.clone(),
                    None => admit(args)?,
                };
                install_shared(target, &admission, &vm, &args.source)?
            }
        }
    };

    if ["usr-assistant", "sys-ctrl"].contains(&target.domain.as_str()) {
        let builder = ensure_builder(target)?;
        result.qubesd_restarted |= builder.restarted;
        result.qubesd_restart_required =
            (result.qubesd_restart_required || builder.changed) && !result.qubesd_restarted;
        for (key, changed) in [
            ("metadata_changed", builder.changed),
            ("qubesd_was_active", builder.was_active),
        ] {
            let previous = result
                .diagnostics
                .get(key)
                .and_then(Value::as_bool)
                .unwrap_or(false);
            result
                .diagnostics
                .insert(key.into(), json!(previous || changed));
        }
        result.volume_created |= !builder.created.is_empty();
        result
            .volumes_created
            .get_or_insert_default()
            .extend(builder.created);
    }
    Ok(result)
}

/// Select and attach an existing committed generation without admitting new package bytes.
pub(super) fn switch(target: &Target, generation: u64) -> Result<InstalledStorageReceipt> {
    let admission = load(target, generation)?;
    let vm = snapshot(&target.domain)?;
    ensure!(
        !vm.running,
        "shared store generation switch requested but domain is running: {}",
        target.domain
    );
    install_shared(target, &admission, &vm, &admission.identity.source)
}

fn install(target: &Target, before: &Snapshot, configs: &[Value]) -> Result<Snapshot> {
    before.verify_pool(target)?;
    let pool = json!({"name":target.pool_name,"driver":"airlock-closure","root_dir":target.pool_root,"revisions_to_keep":0});
    let request = attachment::Installation::new(&target.domain, before, &pool, configs)?;
    let result = bridge(&request.wire())?;
    request.check_after(&result)?;

    // Reload after save: the in-memory objects alone do not establish persistence.
    let persisted = snapshot(&target.domain)?;
    persisted.verify_pool(target)?;
    request.check_after(&persisted)?;
    Ok(persisted)
}

/// Decode serialized worker declarations once; this never creates installation authority.
#[cfg(feature = "qubes")]
pub(crate) fn objects_request(value: Value) -> Result<airlock_qubes::storage::Request> {
    use airlock_qubes::storage::{InstallInput, Request};
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
    enum Wire {
        Snapshot {
            /// Explicit inspected VM; dom0 and invalid guest names are rejected.
            domain: GuestName,
        },
        Install {
            /// Consuming VM whose identity is checked again against the locked snapshot.
            domain: GuestName,
            /// Closed pool declaration, decoded below into the semantic pool type.
            pool: Value,
            /// Closed wire definitions, decoded once before entering the adapter.
            volumes: Vec<Value>,
            /// Complete prior observation used only for locked comparison.
            expected: Value,
        },
    }
    Ok(match serde_json::from_value(value)? {
        Wire::Snapshot { domain } => Request::Snapshot {
            target: domain.to_string(),
        },
        Wire::Install {
            domain,
            pool,
            volumes,
            expected,
        } => Request::Install(InstallInput {
            target: domain.to_string(),
            pool: attachment::pool(&pool)?,
            definitions: volumes
                .iter()
                .map(attachment::WireDefinition::decode)
                .collect::<Result<_>>()?,
            expected,
        }),
    })
}

/// Installed policy supplied directly to the Qubes adapter; the plugin JSON dispatcher is separate.
#[cfg(feature = "qubes")]
pub(crate) struct ObjectsPolicy;

#[cfg(feature = "qubes")]
impl airlock_qubes::storage::Policy for ObjectsPolicy {
    fn authorize(
        &self,
        input: airlock_qubes::storage::InstallInput,
        observed: &Value,
    ) -> Result<airlock_deployment_core::attachment::CheckedInstallation> {
        ensure!(
            *observed == input.expected,
            "Qubes storage changed since it was inspected"
        );
        let before: Snapshot = serde_json::from_value(observed.clone())?;
        attachment::checked(
            &input.target.parse()?,
            &before,
            input.pool,
            input.definitions,
        )
    }

    fn verify(
        &self,
        installation: &airlock_deployment_core::attachment::CheckedInstallation,
        observed: &Value,
    ) -> Result<()> {
        let after: Snapshot = serde_json::from_value(observed.clone())?;
        attachment::check_after(installation, &after)
    }
}

/// Repeat semantic checks while Qubes holds its database lock and return only checked fields.
pub(super) fn authorize_install(
    domain: &GuestName,
    pool: &Value,
    volumes: &[Value],
    observed: &Value,
    expected: &Value,
) -> Result<Value> {
    ensure!(
        observed == expected,
        "Qubes storage changed since it was inspected"
    );
    let snapshot: Snapshot = serde_json::from_value(observed.clone())?;
    Ok(attachment::Installation::new(domain, &snapshot, pool, volumes)?.wire())
}

/// Refuse database publication if the adapter changed either writable volume or its isolation.
pub(super) fn verify_installed(
    domain: &GuestName,
    pool: &Value,
    volumes: &[Value],
    before: &Value,
    after: &Value,
) -> Result<()> {
    let before: Snapshot = serde_json::from_value(before.clone())?;
    let after: Snapshot = serde_json::from_value(after.clone())?;
    attachment::Installation::new(domain, &before, pool, volumes)?.check_after(&after)
}

fn install_shared(
    target: &Target,
    admission: &GenerationReceipt,
    inspected: &Snapshot,
    source: &str,
) -> Result<InstalledStorageReceipt> {
    let configs = shared_configs(target, admission, None)?;
    let frontends = [
        ("store", target.device.as_str()),
        ("store-data", target.blob_device.as_str()),
    ];
    inspected.frontends(&configs, &frontends)?;
    let created = configs
        .iter()
        .filter_map(|c| c["name"].as_str())
        .filter(|name| inspected.volume(name).is_none())
        .map(str::to_owned)
        .collect();
    let pool_created = !inspected.pools.contains_key(&target.pool_name);
    let ((), restarted, was_active) = with_qubesd_stopped(&integration_root(), || {
        let _lock = PoolLock::acquire(&target.pool_root.join("admission.lock"))?;
        let retained =
            attachment::CommittedGeneration::load(target, admission.identity.generation.get())?;
        ensure!(
            retained.definitions(target)? == configs,
            "generation changed before attachment"
        );
        let before = snapshot(&target.domain)?;
        ensure!(
            serde_json::to_value(&before)? == serde_json::to_value(inspected)?,
            "Qubes storage changed before installation"
        );
        ensure!(
            !before.running,
            "domain started before storage installation"
        );
        let persisted = install(target, &before, &configs)?;
        persisted.frontends(&[], &frontends)?;

        generations::switch(
            &target.pool_root,
            &runtime_namespace(target.domain.as_str()),
            admission.identity.generation.get(),
            false,
        )?;
        Ok(())
    })?;
    Ok(receipt(
        target,
        admission,
        source,
        Attachment {
            changed: true,
            pool_created,
            created,
            restarted,
            was_active,
        },
    ))
}

#[derive(Default)]
struct Attachment {
    // Whether the Qubes definition changed during this invocation.
    changed: bool,
    // Whether this invocation registered the immutable closure pool.
    pool_created: bool,
    // Volume keys absent before the update; replacements are not creations.
    created: Vec<String>,
    // Whether qubesd was restored after an offline configuration update.
    restarted: bool,
    // Whether the daemon was active before this invocation stopped it.
    was_active: bool,
}

fn receipt(
    target: &Target,
    admission: &GenerationReceipt,
    source: &str,
    outcome: Attachment,
) -> InstalledStorageReceipt {
    let mut identity = admission.identity.clone();
    identity.source = source.into();
    // Diagnostic fields are preserved for existing wire consumers, never used to construct identity.
    let mut diagnostics = admission.diagnostics.clone();
    for key in [
        "schema",
        "volume_created",
        "volumes_created",
        "qubesd_restart_required",
        "qubesd_restarted",
    ] {
        diagnostics.remove(key);
    }
    for (key, value) in json!({
        "volume":"store", "read_only":true, "metadata_changed":outcome.changed,
        "qubesd_was_active":outcome.was_active, "pool":target.pool_name,
        "pool_created":outcome.pool_created, "pool_root":target.pool_root,
        "manifest":admission.manifest, "metadata_image":admission.metadata_image,
        "blob_logical_size":admission.blob_logical_size, "approval_source":admission.approval_source,
    }).as_object().expect("diagnostic object") {
        diagnostics.insert(key.clone(), value.clone());
    }
    if outcome.changed {
        diagnostics.insert(
            "engine_current_generation".into(),
            json!(identity.generation),
        );
    }
    InstalledStorageReceipt {
        schema: InstallationSchema::V1,
        domain: target.domain.clone(),
        identity,
        qubesd_restart_required: outcome.changed && !outcome.restarted,
        qubesd_restarted: outcome.restarted,
        volume_created: !outcome.created.is_empty(),
        volumes_created: Some(outcome.created),
        view_created: admission.view_created,
        closure_hash: Some(admission.closure_hash.clone()),
        view_image: admission.view_image.clone(),
        image: admission.image.clone(),
        blob_map: Some(admission.blob_map.to_string_lossy().into_owned()),
        blob_volume: admission.blob_volume.clone(),
        diagnostics,
    }
}

fn builder_configs(target: &Target) -> Result<(Vec<Value>, Value)> {
    let _lock = PoolLock::acquire(&target.pool_root.join("admission.lock"))?;
    let configs = builder::volume_configs(
        &target.pool_root,
        &target.pool_root,
        &target.pool_name,
        target.domain.as_str(),
    )?;
    if configs
        .as_object()
        .context("invalid builder volumes")?
        .is_empty()
    {
        return Ok((Vec::new(), Value::Null));
    }
    let descriptor = read(
        &target
            .pool_root
            .join("builders")
            .join(format!("{}.json", target.domain)),
    )?;
    // Metadata must precede external data regardless of JSON map key ordering.
    Ok((
        ["builder-store", "builder-data"]
            .iter()
            .map(|name| configs[name].clone())
            .collect(),
        descriptor,
    ))
}

fn check_builder(
    target: &Target,
    vm: &Snapshot,
    configs: &[Value],
    descriptor: &Value,
) -> Result<bool> {
    for volume in &vm.volumes {
        ensure!(
            !volume.name.starts_with("builder-")
                || ["builder-store", "builder-data"].contains(&volume.name.as_str()),
            "unsupported builder volume: {}",
            volume.name
        );
    }
    let attached = configs
        .iter()
        .filter(|c| vm.volume(c["name"].as_str().unwrap_or("")).is_some())
        .count();
    ensure!(
        attached == 0 || attached == configs.len(),
        "incomplete persistent builder volume configuration"
    );
    if attached == 0 || vm.matches(configs) {
        return Ok(attached != 0);
    }

    // A changed pair must be one complete, authenticated predecessor. Matching
    // its generation/digest alone must not excuse writable or redirected volumes.
    let current = &vm
        .volume("builder-store")
        .context("missing builder metadata")?
        .config;
    let generation = current["generation"]
        .as_str()
        .context("invalid builder generation")?
        .parse::<u64>()?;
    ensure!(
        descriptor["predecessors"]
            .as_array()
            .is_some_and(|old| old.iter().any(|old| old["generation"] == generation
                && old["closure_hash"] == current["closure_hash"])),
        "unapproved persistent builder base transition"
    );
    let _lock = PoolLock::acquire(&target.pool_root.join("admission.lock"))?;
    let domain = format!("{domain}-build-store", domain = target.domain);
    let manifest = records::generation(&target.pool_root, &domain, generation)?;
    ensure!(
        descriptor["predecessors"]
            .as_array()
            .is_some_and(|old| old.iter().any(|old| old["generation"] == generation
                && old["closure_hash"] == manifest["builder"]["closure_hash"]
                && old["registration_sha256"] == manifest["builder"]["registration_sha256"])),
        "builder predecessor registration binding mismatch"
    );
    let previous = builder::configs_for_generation(
        &target.pool_root,
        &target.pool_root,
        &target.pool_name,
        &domain,
        &manifest,
    )?;
    let expected = ["builder-store", "builder-data"]
        .iter()
        .map(|name| previous[name].clone())
        .collect::<Vec<_>>();
    ensure!(
        vm.matches(&expected),
        "builder volumes do not match one complete immutable predecessor"
    );
    Ok(true)
}

fn ensure_builder(target: &Target) -> Result<Attachment> {
    let (configs, descriptor) = builder_configs(target)?;
    let vm = snapshot(&target.domain)?;
    if configs.is_empty() {
        ensure!(
            !vm.volumes
                .iter()
                .any(|volume| volume.name.starts_with("builder-")),
            "attached builder volumes have no authenticated descriptor"
        );
        return Ok(Attachment::default());
    }
    let attached = check_builder(target, &vm, &configs, &descriptor)?;
    let frontends = [("builder-store", "xvdg"), ("builder-data", "xvdh")];
    vm.frontends(&configs, &frontends)?;
    let unchanged = vm.matches(&configs);
    if attached && vm.running {
        return Ok(Attachment::default());
    }
    if unchanged {
        let _lock = PoolLock::acquire(&target.pool_root.join("admission.lock"))?;
        // The image already attached this exact successor. Releasing old pool pins
        // changes no Qubes configuration and must not interrupt unrelated RPCs.
        let current = snapshot(&target.domain)?;
        ensure!(
            current.matches(&configs),
            "builder volumes changed before completing handoff"
        );
        current.frontends(&[], &frontends)?;
        if !current.running {
            builder::release_predecessors(&target.pool_root, target.domain.as_str(), &descriptor)?;
        }
        return Ok(Attachment::default());
    }
    ensure!(
        !vm.running,
        "stop {} before attaching its persistent builder base",
        target.domain
    );

    let created = configs
        .iter()
        .filter_map(|config| {
            let name = config["name"].as_str()?;
            vm.volume(name).is_none().then(|| name.to_owned())
        })
        .collect();
    let ((), restarted, was_active) = with_qubesd_stopped(&integration_root(), || {
        let _lock = PoolLock::acquire(&target.pool_root.join("admission.lock"))?;
        let current = builder::volume_configs(
            &target.pool_root,
            &target.pool_root,
            &target.pool_name,
            target.domain.as_str(),
        )?;
        ensure!(
            ["builder-store", "builder-data"]
                .iter()
                .map(|name| current[name].clone())
                .collect::<Vec<_>>()
                == configs,
            "builder base changed before attachment"
        );
        ensure!(
            read::<Value>(
                &target
                    .pool_root
                    .join("builders")
                    .join(format!("{}.json", target.domain))
            )? == descriptor,
            "builder descriptor changed before attachment"
        );
        let before = snapshot(&target.domain)?;
        ensure!(
            serde_json::to_value(&before)? == serde_json::to_value(&vm)?,
            "Qubes storage changed before builder installation"
        );
        ensure!(
            !before.running,
            "builder started before completing its handoff"
        );
        let persisted = install(target, &before, &configs)?;
        persisted.frontends(&[], &frontends)?;

        builder::release_predecessors(&target.pool_root, target.domain.as_str(), &descriptor)?;
        Ok(())
    })?;
    Ok(Attachment {
        changed: true,
        created,
        restarted,
        was_active,
        ..Default::default()
    })
}

/// One host-wide namespace serializes qubesd updates across every closure pool.
pub(super) fn integration_root() -> PathBuf {
    std::env::var_os("AIRLOCK_QUBES_STORAGE_STATE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/airlock/qubes-storage"))
}

#[derive(PartialEq, Eq)]
enum DaemonState {
    // Neither an inactive nor a failed service is serving the Qubes database.
    Offline,
    // Startup completed and the daemon is available to its clients.
    Active,
    // A start, stop, reload or maintenance transition has not completed.
    Changing,
}

fn daemon_state() -> Result<DaemonState> {
    let output = airlock_nix_core::runtime::process::run(
        Command::new("systemctl").args([
            "show",
            "--property=ActiveState",
            "--value",
            "qubesd.service",
        ]),
        None,
        Some(Duration::from_secs(60)),
    )?
    .checked("inspect qubesd state")?;
    match std::str::from_utf8(&output)?.trim() {
        "inactive" | "failed" => Ok(DaemonState::Offline),
        "active" => Ok(DaemonState::Active),
        "activating" | "deactivating" | "reloading" | "maintenance" | "refreshing" => {
            Ok(DaemonState::Changing)
        }
        state => Err(anyhow!("unknown qubesd service state: {state:?}")),
    }
}

fn active() -> Result<bool> {
    if let Ok(forced) = std::env::var("AIRLOCK_NIX_DOMAIN_STORAGE_QUBESD_ACTIVE") {
        return match forced.as_str() {
            "1" | "true" | "yes" => Ok(true),
            "0" | "false" | "no" => Ok(false),
            _ => Err(anyhow!("invalid qubesd state override")),
        };
    }
    Ok(daemon_state()? != DaemonState::Offline)
}

fn systemctl(action: &str) -> Result<()> {
    eprintln!(
        "{}",
        json!({"event":"service-command-start","service":"qubesd.service","action":action})
    );
    let result = crate::process::Runner::default().text("systemctl", &[action, "qubesd.service"]);
    eprintln!(
        "{}",
        json!({"event":if result.is_ok(){"service-command-finish"}else{"service-command-error"},"service":"qubesd.service","action":action})
    );
    result?;
    let expected = if action == "stop" {
        DaemonState::Offline
    } else {
        DaemonState::Active
    };
    ensure!(
        daemon_state()? == expected,
        "qubesd did not reach its requested {action} state"
    );
    Ok(())
}

/// Restore a daemon left stopped by an interrupted storage update, even on a no-op retry.
pub(super) fn restore_daemon(state_root: &Path) -> Result<()> {
    let pending = state_root.join("qubesd-restart.json");
    if !pending.try_exists()? {
        return Ok(());
    }
    let intent: Value = crate::state::read(&pending)?;
    ensure!(
        intent == json!({"service":"qubesd.service","restore":true}),
        "invalid qubesd restart intent"
    );
    systemctl("start")?;
    fs::remove_file(&pending)?;
    sync_dir(pending.parent().context("restart record has no parent")?)
}

fn with_qubesd_stopped<T>(
    state_root: &Path,
    operation: impl FnOnce() -> Result<T>,
) -> Result<(T, bool, bool)> {
    let pending = state_root.join("qubesd-restart.json");
    let was_active = active()?;
    let interrupted = pending.try_exists()?;
    if !was_active && !interrupted {
        return operation().map(|result| (result, false, false));
    }
    // Persist restart intent before stopping the daemon, so a retried operation
    // also restores it after a previous process was interrupted.
    write(
        &pending,
        &json!({"service":"qubesd.service","restore":true}),
        0o600,
    )?;
    let stopped = if was_active {
        systemctl("stop")
    } else {
        Ok(())
    };
    // Even a failed or timed-out stop may have taken effect. Always request start.
    let result = stopped.and_then(|()| operation());
    let restarted = systemctl("start").and_then(|()| {
        fs::remove_file(&pending)?;
        sync_dir(pending.parent().context("restart record has no parent")?)
    });
    match (result, restarted) {
        (Ok(value), Ok(())) => Ok((value, true, true)),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => {
            Err(error.context("storage updated but qubesd could not be restored"))
        }
        (Err(error), Err(restart)) => Err(anyhow!(
            "{error:#}; additionally could not restore qubesd: {restart:#}"
        )),
    }
}
