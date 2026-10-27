//! Build-time seeds contain already admitted views, so first boot need not retain source packages.
//! Descriptor checks bind every required metadata file to the selected configuration.

use super::{
    builder,
    fs::*,
    generations::{self, Admission},
    host, progress, records, runtime_namespace, segments,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

pub(super) fn relocate(value: &mut Value, old: &str, new: &str) {
    match value {
        Value::String(text) => {
            if text == old || text.strip_prefix(old).is_some_and(|s| s.starts_with('/')) {
                *text = format!("{new}{}", &text[old.len()..]);
            }
        }
        Value::Array(values) => {
            for value in values {
                relocate(value, old, new);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                relocate(value, old, new);
            }
        }
        _ => {}
    }
}

fn json_files(root: &Path) -> Result<Vec<PathBuf>> {
    Ok(descendants(root)?
        .into_iter()
        .filter(|p| p.extension().is_some_and(|s| s == "json") && !p.is_symlink())
        .collect())
}

pub(super) fn relocate_pool(root: &Path, old: &str, new: &str) -> Result<()> {
    for path in json_files(root)? {
        let mut value: Value = read(&path)?;
        relocate(&mut value, old, new);
        write(&path, &value, 0o644)?;
    }
    Ok(())
}

pub(super) fn seal(root: &Path) -> Result<()> {
    for id in segments::ids(root)? {
        segments::seal(root, &id, "image-build", "image-seed")?;
    }
    remove(&root.join("objects/current-segment"))
}

pub(super) fn verify_files(root: &Path, files: &Value, trust_payload: bool) -> Result<usize> {
    progress::phase("Verifying prepared file checksums", || {
        let root_canonical = fs::canonicalize(root)?;
        let files = files
            .as_object()
            .context("missing prepared file fingerprints")?;
        let total = files.iter().try_fold(0u64, |total, (relative, expected)| {
            let path = Path::new(relative);
            if trust_payload
                && path.parent() == Some(Path::new("objects/segments"))
                && path.extension().is_some_and(|s| s == "blob")
            {
                return Ok(total);
            }
            total
                .checked_add(number(expected, "size")?)
                .context("verification byte total overflow")
        })?;
        progress::bytes(total);

        for (index, (relative, expected)) in files.iter().enumerate() {
            progress::detail(&format!(
                "{index}/{total} files | {relative}",
                total = files.len()
            ));
            let relative_path = Path::new(relative);
            ensure!(
                !relative_path.is_absolute()
                    && !relative_path
                        .components()
                        .any(|c| c == std::path::Component::ParentDir),
                "prepared checksum path escapes pool"
            );
            let path = root.join(relative);
            ensure!(
                fs::canonicalize(&path)?.starts_with(&root_canonical),
                "prepared checksum symlink escapes pool"
            );
            ensure!(
                fs::metadata(&path)?.len() == number(expected, "size")?,
                "prepared file missing or size mismatch: {relative}"
            );
            if !(trust_payload
                && relative_path.parent() == Some(Path::new("objects/segments"))
                && relative_path.extension().is_some_and(|s| s == "blob"))
            {
                ensure!(
                    hash(&path)? == text(expected, "sha256")?,
                    "prepared integrity check failed: {relative}"
                );
            }
        }

        progress::detail(&format!("{total}/{total} files", total = files.len()));
        Ok(files.len())
    })
}

fn fingerprint(root: &Path, relative: &str) -> Result<Value> {
    let path = root.join(relative);
    Ok(json!({"size":fs::metadata(&path)?.len(),"sha256":hash(&path)?}))
}

pub(super) fn prepare_pool(
    root: &Path,
    descriptors: &Path,
    specs: &Value,
    runtime: &Path,
) -> Result<Value> {
    ensure!(
        !root.try_exists()? && !descriptors.try_exists()?,
        "prepared outputs must not already exist"
    );

    mkdir_all(root)?;
    mkdir_all(descriptors)?;
    ensure_pool(root)?;

    let mut prepared = Vec::new();
    for spec in specs
        .as_array()
        .context("prepared specs must be an array")?
    {
        let name = text(spec, "name")?;
        component(&name)?;
        let target = descriptors.join(&name);
        mkdir(&target)?;
        let source = PathBuf::from(text(spec, "closure_source")?);
        for name in ["store-paths", "manifest.json"] {
            fs::copy(source.join(name), target.join(name))?;
        }

        let preflight = source.join("boot-preflight.json");
        if preflight.is_file() {
            fs::copy(preflight, target.join("boot-preflight.json"))?;
        }

        eprintln!("Preparing guest configuration: {name}");
        let domain = text(spec, "domain")?;
        let system = text(spec, "system")?;
        let root_source = text(spec, "root_source")?;
        let kernel = text(spec, "kernel_name")?;
        let physical = PathBuf::from(spec["physical_store_root"].as_str().unwrap_or("/nix/store"));

        let result = generations::admit(&Admission {
            pool: root,
            domain: &domain,
            system: &system,
            source: &target,
            source_identity: &target.to_string_lossy(),
            root_source: &root_source,
            kernel: &kernel,
            physical: &physical,
            segment_target: SEGMENT_TARGET,
            verification: "tree",
            approved_by: "image-build",
            approval_source: &target.to_string_lossy(),
            activate: false,
            retain: true,
            previous_index: None,
            device: "/dev/xvde",
            blob_device: "/dev/xvdf",
            mountpoint: "/nix/store",
        })?;

        if spec["builder"] == true {
            builder::prepare(
                root,
                &result.manifest,
                &source.join("registration"),
                Some(&source.join("flake-inputs.json")),
                None,
            )?;
        }
        prepared.push((target, result));
    }
    seal(root)?;
    relocate_pool(root, &root.to_string_lossy(), &runtime.to_string_lossy())?;
    let mut fingerprints = BTreeMap::new();
    for (target, result) in prepared {
        let path = result.manifest;
        let manifest: Value = read(&path)?;
        let store = &manifest["store"];
        let relative = path
            .strip_prefix(root)?
            .to_str()
            .context("invalid manifest path")?
            .to_owned();
        let mut files = BTreeSet::from([
            relative,
            format!("transactions/{}.json", text(&manifest, "transaction")?),
        ]);
        if let Some(digest) = manifest["root"]["artifact"]["sha256"].as_str() {
            files.insert(format!("root-artifacts/{digest}/artifact.json"));
        }
        for key in [
            "canonical_metadata_image",
            "canonical_blob_map",
            "canonical_object_refs",
        ] {
            files.insert(
                Path::new(&text(store, key)?)
                    .strip_prefix(runtime)?
                    .to_str()
                    .context("invalid view path")?
                    .to_owned(),
            );
        }
        if !manifest["builder"].is_null() {
            files.insert(
                Path::new(&text(&manifest["builder"], "metadata_image")?)
                    .strip_prefix(runtime)?
                    .to_str()
                    .context("invalid builder path")?
                    .to_owned(),
            );
            let domain = text(&manifest, "domain")?;
            let role = domain
                .strip_suffix("-build-store")
                .context("invalid builder domain")?;
            files.insert(format!("builders/{role}.json"));
            files.insert(format!(
                "running/{domain}/{}/builder-persistent.json",
                number(&manifest, "generation")?
            ));
        }
        let map: Value = read(
            &root.join(Path::new(&text(store, "canonical_blob_map")?).strip_prefix(runtime)?),
        )?;
        for segment in map["segments"].as_array().context("missing segments")? {
            let id = text(segment, "id")?;
            files.insert(format!("objects/segments/{id}.blob"));
            files.insert(format!("objects/segments/{id}.json"));
        }
        for name in map["objects"]
            .as_array()
            .context("missing map objects")?
            .iter()
            .filter_map(Value::as_str)
            .chain(std::iter::once(".tar-eof"))
        {
            component(name)?;
            files.insert(format!("objects/blob-metadata/{name}.json"));
            if name != ".tar-eof" {
                files.insert(format!("objects/metadata/{name}.json"));
            }
        }
        let mut selected = json!({});
        for relative in files {
            if !fingerprints.contains_key(&relative) {
                fingerprints.insert(relative.clone(), fingerprint(root, &relative)?);
            }
            selected[&relative] = fingerprints[&relative].clone();
        }
        write(
            &target.join("prepared.json"),
            &json!({
                "schema": "airlock.closure-store.prepared.v1",
                "pool_root": runtime,
                "domain": manifest["domain"],
                "generation": manifest["generation"],
                "system": manifest["system"],
                "root_source": manifest["root"]["source"],
                "kernel_name": manifest["kernel"]["name"],
                "closure_hash": store["closure_hash"],
                "files": selected,
            }),
            0o644,
        )?;
    }
    Ok(json!({"status":"prepared"}))
}

/// Authenticate each file once across descriptors of the same immutable pool, within this call only.
pub(super) fn verify_outputs(root: &Path, descriptors: &Path) -> Result<Value> {
    let mut manifests = Vec::new();
    let mut files = serde_json::Map::new();
    for directory in children(descriptors)? {
        if !fs::symlink_metadata(&directory)?.is_dir() {
            continue;
        }
        let path = directory.join("prepared.json");
        if !path.try_exists()? {
            continue;
        }
        let descriptor: Value = read(&path)?;
        ensure!(
            descriptor["schema"] == "airlock.closure-store.prepared.v1",
            "unsupported prepared descriptor"
        );
        let domain = text(&descriptor, "domain")?;
        let generation = number(&descriptor, "generation")?;
        let manifest = records::manifest_path(root, &domain, generation)?;
        let relative = manifest
            .strip_prefix(root)?
            .to_str()
            .context("invalid manifest relative path")?;
        ensure!(
            descriptor["files"].get(relative).is_some(),
            "prepared manifest checksum missing"
        );
        for (relative, expected) in descriptor["files"]
            .as_object()
            .context("invalid fingerprints")?
        {
            if let Some(previous) = files.get(relative) {
                ensure!(
                    number(previous, "size")? == number(expected, "size")?
                        && text(previous, "sha256")? == text(expected, "sha256")?,
                    "conflicting prepared fingerprints: {relative}"
                );
            } else {
                files.insert(relative.clone(), expected.clone());
            }
        }
        manifests.push(manifest);
    }
    ensure!(!manifests.is_empty(), "prepared store has no descriptors");

    // Check agreement before reading shared bytes; retain every variant's root-artifact validation.
    let files = verify_files(root, &Value::Object(files), false)?;
    for manifest in &manifests {
        records::root_image(root, &read(manifest)?)?;
    }

    Ok(json!({"status":"passed","variants":manifests.len(),"files":files}))
}

/// Software identity supplied independently of a prepared descriptor.
/// JSON decoding belongs to the image CLI; native setup constructs this value directly.
#[derive(serde::Deserialize)]
pub(super) struct Verification {
    /// Directory containing the frozen closure and its prepared descriptor.
    artifact: PathBuf,
    /// Installed pool whose files must authenticate the descriptor.
    pool_root: PathBuf,
    /// Consuming VM; its storage namespace is derived by verified code.
    domain: airlock_nix_core::identity::GuestName,
    /// Logical guest system, including manual local-artifact compatibility.
    system: String,
    /// Approved immutable root source.
    root: String,
    /// Approved kernel selection.
    kernel: String,
    /// Original closure source, distinct from the resolved artifact directory.
    source: String,
    /// Required metadata frontend.
    device: String,
    /// Required external-data frontend.
    blob_device: String,
    /// Required guest mountpoint.
    mountpoint: String,
    /// Required immutable view implementation.
    view_backend: String,
    /// Optional exact generation from the authorised plan.
    #[serde(default)]
    generation: Option<crate::model::GenerationId>,
}

impl TryFrom<&super::domain_cli::Ensure> for Verification {
    type Error = anyhow::Error;

    fn try_from(args: &super::domain_cli::Ensure) -> Result<Self> {
        Ok(Self {
            artifact: args.artifact.clone(),
            pool_root: args.target.pool_root.clone(),
            domain: args.target.domain.clone(),
            system: args.system.clone(),
            root: args.root.clone(),
            kernel: args.kernel.clone(),
            source: args.source.clone(),
            device: args.target.device.clone(),
            blob_device: args.target.blob_device.clone(),
            mountpoint: args.target.mountpoint.clone(),
            view_backend: args.view_backend.clone(),
            generation: args.generation.map(TryInto::try_into).transpose()?,
        })
    }
}

pub(super) fn verify_prepared(
    request: &Verification,
) -> Result<Option<airlock_deployment_core::attachment::prepared::CheckedGeneration>> {
    use airlock_deployment_core::attachment::prepared::{
        Boot, CheckedGeneration, Descriptor, Expected, Layout, Manifest,
    };

    let artifact = &request.artifact;
    let path = artifact.join("prepared.json");
    if !path.try_exists()? {
        return Ok(None);
    }
    let root = &request.pool_root;
    let pool = root.to_str().context("non-UTF-8 prepared pool path")?;
    let descriptor: Value = read(&path)?;
    ensure!(
        descriptor["schema"] == "airlock.closure-store.prepared.v1",
        "unsupported prepared descriptor"
    );
    let namespace = runtime_namespace(request.domain.as_str());
    let generation = number(&descriptor, "generation")?;
    let paths = store_paths(artifact, &request.system)?;
    let closure = closure_hash(&paths, &request.system, &request.root, &request.kernel);
    let manifest_path = records::manifest_path(root, &namespace, generation)?;
    ensure!(
        descriptor["files"]
            .get(
                manifest_path
                    .strip_prefix(root)?
                    .to_str()
                    .context("invalid manifest path")?
            )
            .is_some(),
        "prepared manifest checksum missing"
    );
    verify_files(root, &descriptor["files"], true)?;
    let manifest = records::generation(root, &namespace, generation)?;
    records::root_image(root, &manifest)?;
    let store = &manifest["store"];
    ensure!(store["paths"] == json!(paths), "prepared paths mismatch");

    // Record decoding and authenticated-byte hashing are external to this verified decision.
    let expected = Expected {
        boot: Boot {
            pool: pool.into(),
            namespace,
            system: request.system.clone(),
            root: request.root.clone(),
            kernel: request.kernel.clone(),
            closure,
        },
        layout: Layout {
            source: request.source.clone(),
            device: request.device.clone(),
            blob_device: request.blob_device.clone(),
            mountpoint: request.mountpoint.clone(),
            backend: request.view_backend.clone(),
        },
        number: request.generation.map(|g| g.get()),
    };
    let described = Descriptor {
        boot: Boot {
            pool: text(&descriptor, "pool_root")?,
            namespace: text(&descriptor, "domain")?,
            system: text(&descriptor, "system")?,
            root: text(&descriptor, "root_source")?,
            kernel: text(&descriptor, "kernel_name")?,
            closure: text(&descriptor, "closure_hash")?,
        },
        number: generation,
    };
    let loaded = Manifest {
        boot: Boot {
            pool: pool.into(),
            namespace: text(&manifest, "domain")?,
            system: text(&manifest, "system")?,
            root: text(&manifest["root"], "source")?,
            kernel: text(&manifest["kernel"], "name")?,
            closure: text(store, "closure_hash")?,
        },
        layout: Layout {
            source: text(store, "source")?,
            device: text(store, "device")?,
            blob_device: text(store, "blob_device")?,
            mountpoint: text(store, "mountpoint")?,
            backend: text(store, "view_backend")?,
        },
        number: number(&manifest, "generation")?,
    };
    Ok(Some(
        CheckedGeneration::check(&expected, &described, loaded)
            .context("prepared generation identity mismatch")?,
    ))
}

pub(super) fn prepare_host(
    seed: &Path,
    output: &Path,
    registration: &Path,
    system: &str,
    choices: &Value,
) -> Result<Value> {
    mkdir(output)?;
    let root = output.join("pool");
    progress::phase("Copying prepared guest pool", || {
        command(
            "cp",
            &[
                "-a",
                "--sparse=always",
                &seed.join("pool").to_string_lossy(),
                &root.to_string_lossy(),
            ],
            None,
        )
    })?;

    progress::phase("Preparing pool metadata", || {
        for path in std::iter::once(root.clone()).chain(descendants(&root)?) {
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.is_dir() {
                fs::set_permissions(
                    path,
                    fs::Permissions::from_mode(metadata.permissions().mode() | 0o200),
                )?;
            }
        }
        for path in [
            root.join("admission.lock"),
            root.join("objects/segments.lock"),
        ] {
            ensure!(!path.is_symlink(), "seed coordination lock is a symlink");
            if path.try_exists()? {
                fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
            }
        }
        relocate_pool(&root, host::POOL, &root.to_string_lossy())?;
        Ok(())
    })?;

    let registration_text = fs::read_to_string(registration)?;
    let mut systems = vec![system.to_owned()];
    systems.extend(
        choices
            .as_object()
            .context("invalid host choices")?
            .values()
            .map(|v| v.as_str().map(str::to_owned).context("invalid host choice"))
            .collect::<Result<Vec<_>>>()?,
    );
    systems.sort();
    systems.dedup();

    progress::phase("Publishing dom0 runtime store", || {
        host::publish(&root, system, &registration_text, &systems, false)
    })?;

    for role in ["sys-ctrl", "usr-assistant"] {
        if root
            .join("builders")
            .join(format!("{role}.json"))
            .try_exists()?
        {
            progress::phase(&format!("Preparing {role}-build-store"), || {
                host::refresh_builder(&root, role, &registration_text, false, None)
            })?;
        }
    }

    progress::phase("Sealing unified store", || {
        write(&root.join("host/aliases.json"), choices, 0o644)?;
        seal(&root)?;
        relocate_pool(&root, &root.to_string_lossy(), host::POOL)?;
        for path in children(&root.join("host/boots"))? {
            let mut value: Value = read(&path)?;
            let blob = root.join(Path::new(&text(&value, "blob_map")?).strip_prefix(host::POOL)?);
            value["blob_map_sha256"] = json!(hash(&blob)?);
            write(&path, &value, 0o644)?;
        }
        Ok(())
    })?;

    let fingerprints = progress::phase("Calculating unified-store checksums", || {
        let paths: Vec<_> = descendants(&root)?
            .into_iter()
            .filter(|path| {
                !path.is_symlink()
                    && path.is_file()
                    && path.file_name().is_some_and(|s| s != "root.img")
            })
            .collect();
        let total = paths.iter().try_fold(0u64, |total, path| {
            total
                .checked_add(fs::metadata(path)?.len())
                .context("checksum byte total overflow")
        })?;
        progress::bytes(total);
        let mut fingerprints = json!({});

        for path in paths {
            let relative = path
                .strip_prefix(&root)?
                .to_str()
                .context("invalid seed file path")?;
            progress::detail(relative);
            fingerprints[relative] = fingerprint(&root, relative)?;
        }

        Ok(fingerprints)
    })?;
    write(&output.join("pool-fingerprints.json"), &fingerprints, 0o644)?;

    progress::phase("Writing unified-store receipt", || {
        let receipt = json!({"schema":"airlock.unified-seed.v1","systems":systems,"pool_allocated_bytes":host::allocated(&root)?,"registration_sha256":hash(registration)?});
        write(&output.join("receipt.json"), &receipt, 0o644)?;
        Ok(receipt)
    })
}

/// Require diskless guest executables in the packaged host view, not merely the builder's store.
fn host_artifacts(topology: &crate::model::Topology, paths: &BTreeSet<String>) -> Result<()> {
    for (name, domain) in &topology.domains {
        if let Some(image) = domain.backend.hermit() {
            ensure!(
                paths.contains(domain.backend.system.source.as_str()),
                "{name}: Hermit executable is absent from the packaged host store: {path}",
                path = image.executable.as_str()
            );
        }
    }

    Ok(())
}

pub(super) fn verify_host(seed: &Path, topology: &crate::model::Topology) -> Result<Value> {
    let root = seed.join("pool");
    verify_files(&root, &read(&seed.join("pool-fingerprints.json"))?, false)?;

    progress::phase("Checking root artifacts and host boot records", || {
        for path in records::manifests(&root)? {
            records::root_image(&root, &read(&path)?)?;
        }
        for path in children(&root.join("host/boots"))? {
            let record: Value = read(&path)?;
            let receipt = host::validate(
                &root,
                Path::new(host::POOL),
                &text(&record, "system")?,
                false,
            )?;
            let manifest = root.join(receipt.manifest.strip_prefix(host::POOL)?);
            let manifest: Value = read(&manifest)?;
            host_artifacts(
                topology,
                &serde_json::from_value(manifest["store"]["paths"].clone())?,
            )?;
        }
        for role in ["usr-assistant", "sys-ctrl"] {
            builder::volume_configs(&root, Path::new(host::POOL), "airlock-closure", role)?;
        }
        Ok(())
    })?;

    Ok(json!({"schema":"airlock.unified-seed-check.v1","status":"passed"}))
}

pub(super) fn install_host(
    root: &Path,
    recovery_paths: &Path,
    recovery_system: &str,
) -> Result<Value> {
    let pool = root.join(host::POOL.trim_start_matches('/'));
    let recovery: BTreeSet<String> = fs::read_to_string(recovery_paths)?
        .lines()
        .map(str::to_owned)
        .collect();
    let mut admitted = BTreeSet::new();
    let records = children(&pool.join("host/boots"))?;
    ensure!(
        !records.is_empty() && !recovery.is_empty(),
        "missing host publication or recovery closure"
    );
    for path in records {
        let record: Value = read(&path)?;
        let manifest = pool.join(Path::new(&text(&record, "manifest")?).strip_prefix(host::POOL)?);
        let manifest: Value = read(&manifest)?;
        admitted.extend(serde_json::from_value::<BTreeSet<String>>(
            manifest["store"]["paths"].clone(),
        )?);
    }

    let store = root.join("nix/store");
    let ordinary: BTreeSet<_> = children(&store)?
        .iter()
        .filter_map(|path| {
            path.file_name()
                .and_then(|s| s.to_str())
                .filter(|s| !s.starts_with('.'))
                .map(|name| format!("/nix/store/{name}"))
        })
        .collect();
    ensure!(
        recovery.is_subset(&ordinary) && ordinary.is_subset(&admitted),
        "image store differs from published host/recovery inventory"
    );
    ensure!(
        recovery.contains(recovery_system),
        "recovery system absent from its closure"
    );
    ensure!(
        !super::boot_artifacts::inventory(&root.join("boot"), recovery_system)?.is_empty(),
        "independent recovery boot entry not installed"
    );

    let staging_bytes = host::allocated(&store)?;
    let pool_bytes = host::allocated(&pool)?;
    super::boot_artifacts::seal(&pool, &root.join("boot"), false, false)?;

    let destination = root.join("var/lib/airlock/recovery-store");
    mkdir_all(
        destination
            .parent()
            .context("missing recovery store parent")?,
    )?;
    mkdir(&destination)?;
    for path in children(&store)? {
        let name = path.file_name().context("missing store filename")?;
        if recovery.contains(&format!("/nix/store/{}", name.to_string_lossy())) {
            fs::rename(&path, destination.join(name))?;
        } else {
            remove(&path)?;
        }
    }

    let receipt = json!({
        "schema": "airlock.host-store.install.v1",
        "recovery_objects": recovery.len(),
        "recovery_allocated_bytes": host::allocated(&destination)?,
        "ordinary_host_objects_remaining": 0,
        "pool_allocated_bytes": pool_bytes,
        "installation_pool_plus_store_allocated_bytes": pool_bytes+staging_bytes,
    });
    write(
        &root.join("var/lib/airlock/host-store-install.json"),
        &receipt,
        0o644,
    )?;
    rustix::fs::syncfs(&std::fs::File::open(root)?)?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid guest declaration cannot substitute for retaining its executable in dom0's image.
    #[test]
    fn host_manifest_must_retain_diskless_guest_executables() -> Result<()> {
        let hermit = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-clipboard";
        let linux = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-linux";
        let inputs = airlock_machine_core::boot::BootInputs::new(json!({
            "schema":"airlock.qubes-topology.v1", "domains":{
                "sys-clipboard":{
                    "class":"HermitVM", "netvm":null, "template":null,
                    "features":{"qrexec":"","gui":""},
                    "prefs":{"memory":32,"maxmem":32,"vcpus":1,"guivm":null,"audiovm":null,"kernel":"","virt_mode":"pvh"},
                    "backend":{"type":"hermit", "system":{"source":hermit}, "artifact":{
                        "schema":"airlock.hermit-pvh.v1", "executable":format!("{hermit}/kernel.elf"),
                        "sha256":"a".repeat(64), "bytes":1024, "source_revision":"b".repeat(40),
                        "integration_revision":"c".repeat(40), "build_lock":"d".repeat(64), "authority":"disconnected"
                    }}
                },
                "usr-home":{
                    "class":"StandaloneVM", "netvm":null, "template":null,
                    "backend":{"type":"nix-closure", "system":{"source":linux},
                        "root":{"source":format!("{linux}/root.img")}, "kernel":{"name":"test"},
                        "store":{"source":linux,"mode":"shared-closure","mountpoint":"/nix/store",
                            "device":"/dev/xvde","blobDevice":"/dev/xvdf","viewBackend":"erofs-objectmap"}}
                }
            }
        }))?;
        let mut paths = BTreeSet::new();
        let error = host_artifacts(inputs.topology(), &paths).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("sys-clipboard: Hermit executable is absent")
        );
        assert!(error.to_string().contains(&format!("{hermit}/kernel.elf")));

        // Linux payloads remain in the guest pool; only Hermit needs its system in dom0.
        paths.insert(hermit.into());
        host_artifacts(inputs.topology(), &paths)
    }
}
