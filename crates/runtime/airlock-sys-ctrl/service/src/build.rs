//! Nix and pool adapters. This module cannot create an approval grant; all
//! evaluation/build entry points require the controller's checked grant.
use super::{
    Error, Result,
    controller::Grant,
    decode,
    process::{self, OwnedChild},
    protocol::{Action, identity},
    records, require,
};
use airlock_nix_core::{
    admission::{AdmissionReceipt, ExpectedAdmission},
    identity::*,
    review::{DeploymentPlan, PreparedPlan},
    root_artifact::RootDescriptor,
    state::{OperationLock, StateStore},
    store_path::{StoreFile, StorePath},
};
use flate2::{Compression, write::GzEncoder};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Instant,
};

const MACHINE_SCHEMA: &str = "airlock.sys-ctrl-machine-release.v2";

/// Installed controller configuration selects a release family; wire requests cannot change it.
fn profile() -> Result<&'static str> {
    let name = match fs::read_to_string("/etc/airlock/machine-build-profile") {
        Ok(name) => name,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok("usb-lab"),
        Err(error) => return Err(error.into()),
    };
    checked_profile(name.trim())
}

/// Admit only the physical machine and the explicit local development machine.
fn checked_profile(name: &str) -> Result<&'static str> {
    match name {
        "usb-lab" => Ok("usb-lab"),
        "local-lab" => Ok("local-lab"),
        _ => Err(Error::Message(
            "unsupported installed machine build profile".into(),
        )),
    }
}

#[cfg(test)]
mod profile_tests {
    use super::checked_profile;

    /// Installed profile selection cannot turn a release attribute into an arbitrary Nix expression.
    #[test]
    fn build_profiles_are_explicit() {
        assert_eq!(checked_profile("usb-lab").unwrap(), "usb-lab");
        assert_eq!(checked_profile("local-lab").unwrap(), "local-lab");
        for invalid in [
            "",
            "usb-gui-lab",
            "../../local-lab",
            "local-lab;builtins.abort",
        ] {
            assert!(checked_profile(invalid).is_err());
        }
    }
}

// The builder's store is mounted separately from this process's own Nix store.
// This mapping belongs to sys-ctrl, not the shared store-path identity.
fn physical(path: &StorePath) -> PathBuf {
    Path::new("/rw/airlock-builder/merged").join(path.as_str().trim_start_matches('/'))
}

#[derive(Deserialize)]
struct Manifest {
    /// Wire format identifier used to reject unsupported record versions.
    schema: String,
    /// Machine configuration name selected when building the release.
    profile: String,
    /// Git commit identifying the candidate source tree.
    revision: GitRevision,
    /// SHA-256 of flake.lock, binding the source to its dependency versions.
    #[serde(rename = "lockHash")]
    lock_hash: LockHash,
}

fn manifest(release: &StorePath, grant: &Grant) -> Result<()> {
    let raw = records::read_file(&physical(release).join("release.json"))?;
    let m: Manifest = decode(&serde_json::to_vec(&raw)?)?;
    require(
        m.schema == "airlock.machine-release.v1"
            && m.profile == profile()?
            && m.revision == grant.header.revision
            && m.lock_hash == grant.header.lock_hash,
        "built release provenance differs from submitted source",
    )?;

    Ok(())
}

fn name(grant: &Grant, kind: &str) -> String {
    format!("{kind}-{}", grant.header.revision)
}

fn build_release(store: &StateStore, grant: &Grant, lock: &OperationLock) -> Result<StorePath> {
    grant.check(lock)?;

    let start = Instant::now();
    let build_name = name(grant, "build");
    let path = records::record_path(&build_name)?;
    if path.try_exists()? {
        let mut saved: Value = records::read_owned(&build_name)?;
        let release: StorePath = decode(&serde_json::to_vec(&saved["release"])?)?;
        let link = records::root()?.join(format!("{build_name}-release"));
        if saved.get("revision") == Some(&json!(grant.header.revision))
            && saved.get("lock_hash") == Some(&json!(grant.header.lock_hash))
            && physical(&release).join("release.json").is_file()
            && fs::read_link(&link).ok().as_deref() == Some(Path::new(release.as_str()))
        {
            manifest(&release, grant)?;
            grant.check(lock)?;
            saved["build_seconds"] = json!(start.elapsed().as_secs_f64());
            saved["build_reused"] = json!(true);
            records::save(store, &build_name, &saved)?;
            return Ok(release);
        }
    }

    let release = StorePath::try_from(process::text(
        "airlock-usr-assistant-machine-build",
        &[
            "build",
            &format!(".#airlock-machine-release-{profile}", profile = profile()?),
        ],
    )?)?;
    manifest(&release, grant)?;
    require(
        identity(Path::new("/home/user/dev/airlockos-machine"))? == grant.header.source(),
        "controller checkout changed during release build",
    )?;
    lock.check_path()?;

    let link = records::root()?.join(format!("{build_name}-release"));
    process::output(
        "airlock-config-nix",
        &[
            "build",
            release.as_str(),
            "--out-link",
            link.to_str()
                .ok_or_else(|| Error::Message("non-UTF-8 state path".into()))?,
        ],
    )?;

    records::save(
        store,
        &build_name,
        &json!({"schema":MACHINE_SCHEMA,"release":release,"revision":grant.header.revision,"lock_hash":grant.header.lock_hash,"build_seconds":start.elapsed().as_secs_f64()}),
    )?;

    Ok(release)
}

pub(super) fn execute(store: &StateStore, grant: &Grant, lock: &OperationLock) -> Result<Value> {
    grant.check(lock)?;
    if grant.header.action.is_machine() {
        let release = build_release(store, grant, lock)?;
        if grant.header.action == Action::MachineBuild {
            return Ok(
                json!({"schema":MACHINE_SCHEMA,"release":release,"revision":grant.header.revision,"lock_hash":grant.header.lock_hash}),
            );
        }
        return send_release(store, grant, lock, &release);
    }

    let target = grant
        .header
        .target
        .as_ref()
        .ok_or_else(|| Error::Message("guest request has no target".into()))?;
    let configuration = if profile()? == "local-lab" {
        format!("airlock-local-lab-domain-{target}")
    } else if target.as_str() == "sys-gui" {
        "airlock-domain-sys-gui-usb-lab".into()
    } else {
        format!("airlock-domain-{target}")
    };
    let mut receipt: AdmissionReceipt = decode(&process::output(
        "airlock-usr-assistant-machine-build",
        &[
            "admit",
            target.as_str(),
            &format!(".#nixosConfigurations.{configuration}.config.system.build.toplevel"),
        ],
    )?)?;
    receipt.check_transfer(target, &grant.header.source())?;
    grant.check(lock)?;
    receipt
        .diagnostics
        .insert("review_authorization".into(), json!(grant.id));
    let service = if grant.header.action.is_plan() {
        "airlock.Ctrl.GuestPlan"
    } else {
        "airlock.Ctrl.GuestApply"
    };
    let result = process::rpc(service, &serde_json::to_value(&receipt)?, None)?;
    check_plan(&result, grant)?;

    records::save(
        store,
        &name(
            grant,
            &format!("guest-{target}-{}", grant.header.action.as_str()),
        ),
        &result,
    )?;

    Ok(result)
}

fn check_plan(result: &Value, grant: &Grant) -> Result<()> {
    if let Some(plan) = result.get("plan") {
        let plan: DeploymentPlan = decode(&serde_json::to_vec(plan)?)?;
        let prepared = PreparedPlan::new(grant.header.candidate()?, plan)?;
        grant.approval.scope().check(prepared.plan())?;
    }
    Ok(())
}

#[derive(Deserialize)]
struct Topology {
    /// Declared guest names and their intended configuration.
    domains: BTreeMap<GuestName, Domain>,
}

#[derive(Deserialize)]
struct Domain {
    /// Guest boot artifacts and the storage arrangement that supplies them.
    backend: Backend,
}

#[derive(Deserialize)]
struct Backend {
    /// Supported backend protocol, checked before using its artifacts.
    #[serde(rename = "type")]
    kind: String,
    /// System closure supplying the guest configuration.
    system: Option<Source>,
    /// Shared Nix closure and its guest-facing storage settings.
    store: Option<Source>,
    /// Root filesystem image from which the guest starts.
    root: Option<Source<StoreFile>>,
    /// Kernel configuration paired with the guest root.
    kernel: Option<Kernel>,
}

#[derive(Deserialize)]
struct Source<T = StorePath> {
    /// Immutable store location supplying the enclosing artifact.
    source: T,
}

#[derive(Deserialize)]
struct Kernel {
    /// Qubes kernel directory name used for this guest.
    name: String,
}

impl Backend {
    fn sources(&self) -> Result<(&StorePath, &StorePath, &StoreFile, &str)> {
        let system = self
            .system
            .as_ref()
            .ok_or_else(|| Error::Message("guest system source missing".into()))?;
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| Error::Message("guest closure source missing".into()))?;
        let root = self
            .root
            .as_ref()
            .ok_or_else(|| Error::Message("guest root source missing".into()))?;
        let kernel = self
            .kernel
            .as_ref()
            .ok_or_else(|| Error::Message("guest kernel missing".into()))?;
        require(
            !kernel.name.starts_with('-') && !kernel.name.is_empty() && !kernel.name.contains('/'),
            "invalid guest kernel name",
        )?;
        Ok((&system.source, &store.source, &root.source, &kernel.name))
    }
}

fn metadata(paths: &[String], recursive: bool) -> Result<BTreeMap<StorePath, Value>> {
    let mut command = Command::new("airlock-config-nix");
    command.args(["path-info", "--json"]);
    if recursive {
        command.arg("--recursive");
    }
    command.args(paths);
    let raw: Value =
        decode(&process::run(&mut command, None, None)?.checked("query Nix metadata")?)?;
    let mut metadata = BTreeMap::new();
    match raw {
        Value::Array(entries) => {
            for entry in entries {
                let path: StorePath = decode(&serde_json::to_vec(&entry["path"])?)?;
                require(
                    metadata.insert(path, entry).is_none(),
                    "duplicate store path metadata",
                )?;
            }
        }
        Value::Object(entries) => {
            for (path, entry) in entries {
                require(
                    metadata.insert(StorePath::try_from(path)?, entry).is_none(),
                    "duplicate store path metadata",
                )?;
            }
        }
        _ => return Err(Error::Message("invalid Nix metadata response".into())),
    }
    Ok(metadata)
}

fn machine_metadata(topology: &Topology) -> Result<BTreeMap<StorePath, Value>> {
    let mut paths = BTreeSet::new();
    for domain in topology
        .domains
        .values()
        .filter(|d| d.backend.kind == "nix-closure")
    {
        let (system, closure, _, _) = domain.backend.sources()?;
        let physical = physical(closure);
        let file = if physical.is_dir() {
            [
                physical.join("store-paths"),
                physical.join("closure/store-paths"),
            ]
            .into_iter()
            .find(|p| p.is_file())
            .ok_or_else(|| Error::Message("machine closure is missing store-paths".into()))?
        } else {
            physical
        };

        let bytes = fs::read(file)?;
        require(
            bytes.len() <= 32 * 1024 * 1024,
            "closure inventory exceeds limit",
        )?;
        let lines = String::from_utf8(bytes)
            .map_err(|_| Error::Message("non-UTF-8 closure inventory".into()))?;
        for line in lines.lines().map(str::trim).filter(|s| !s.is_empty()) {
            paths.insert(StorePath::try_from(line.to_owned())?);
        }
        paths.insert(system.clone());
    }

    let mut result = BTreeMap::new();
    let ordered = paths
        .iter()
        .map(|p| p.as_str().to_owned())
        .collect::<Vec<_>>();
    for chunk in ordered.chunks(512) {
        result.extend(metadata(chunk, false)?);
    }

    require(
        result.keys().cloned().collect::<BTreeSet<_>>() == paths,
        "machine package metadata differs from requested paths",
    )?;

    Ok(result)
}

/// Use the shared candidate contract; dom0 still independently authenticates committed storage.
fn check_guest_admission(
    receipt: &AdmissionReceipt,
    guest: &GuestName,
    backend: &Backend,
    grant: &Grant,
    root: &RootDescriptor,
) -> Result<()> {
    let (system, closure, source, kernel) = backend.sources()?;
    let expected = ExpectedAdmission {
        domain: guest.clone(),
        system: system.clone(),
        closure_source: closure.as_str().parse()?,
        root_source: source.clone(),
        kernel_name: kernel.to_owned(),
        source_revision: grant.header.revision.clone(),
        lock_hash: grant.header.lock_hash.clone(),
        root_artifact: root.clone(),
    };
    receipt.check_expected(&expected)?;
    Ok(())
}

fn send_release(
    store: &StateStore,
    grant: &Grant,
    lock: &OperationLock,
    release: &StorePath,
) -> Result<Value> {
    grant.check(lock)?;
    manifest(release, grant)?;

    let physical = physical(release);
    let topology: Topology = decode(&serde_json::to_vec(&records::read_file(
        &physical.join("topology.json"),
    )?)?)?;
    let roots: BTreeMap<GuestName, RootDescriptor> =
        serde_json::from_value(records::read_file(&physical.join("root-artifacts.json"))?)?;
    let transport = StorePath::try_from(
        fs::read_link(physical.join("transport"))?
            .to_str()
            .ok_or_else(|| Error::Message("invalid release transport link".into()))?
            .to_owned(),
    )?;

    let plan_name = name(grant, "plan");
    if grant.header.action.is_apply() && records::record_path(&plan_name)?.try_exists()? {
        let saved: Value = records::read_owned(&plan_name)?;
        if saved.get("source_release") == Some(&json!(transport)) && saved.get("prepared").is_some()
        {
            let prepared: ReviewId = decode(&serde_json::to_vec(&saved["prepared"])?)?;
            grant.check(lock)?;
            check_plan(&saved, grant)?;
            let mut result = process::rpc(
                "airlock.Ctrl.MachineApply",
                &json!({"schema":MACHINE_SCHEMA,"release":transport,"revision":grant.header.revision,"lock_hash":grant.header.lock_hash,"profile":profile()?,"prepared":prepared,"review_authorization":grant.id}),
                None,
            )?;
            result["build_seconds"] = json!(0);
            records::save(store, &name(grant, "apply"), &result)?;
            return Ok(result);
        }
    }

    let start = Instant::now();
    let authorization = send_transport("prepare", &transport, grant, lock, &json!({}))?;
    #[derive(Deserialize)]
    struct Admission {
        /// Wire format identifier used to reject unsupported record versions.
        schema: String,
        /// Candidate release location containing its manifest and topology.
        release: StorePath,
        /// Whether the admission reply claims activation; staging expects false.
        activated: bool,
        /// Guests whose artifacts were admitted by the storage helper.
        domains: Vec<GuestName>,
        /// Protected source-review identity returned by release admission.
        admission: ReviewId,
    }
    let admission: Admission = decode(&serde_json::to_vec(&authorization)?)?;
    require(
        admission.schema == "airlock.machine-admission.v1"
            && admission.release == transport
            && !admission.activated
            && admission.domains.iter().cloned().collect::<BTreeSet<_>>()
                == topology
                    .domains
                    .iter()
                    .filter(|(_, d)| d.backend.kind == "nix-closure")
                    .map(|(name, _)| name.clone())
                    .collect()
            && admission.domains.len()
                == topology
                    .domains
                    .values()
                    .filter(|d| d.backend.kind == "nix-closure")
                    .count(),
        "invalid candidate admission authorization",
    )?;
    records::save(store, &name(grant, "admission-prepare"), &authorization)?;

    let metadata_start = Instant::now();
    let metadata = machine_metadata(&topology)?;
    let metadata_seconds = metadata_start.elapsed().as_secs_f64();
    let mut metadata_file = tempfile::NamedTempFile::new()?;
    serde_json::to_writer(&mut metadata_file, &metadata)?;
    metadata_file.flush()?;

    let mut receipts = BTreeMap::new();
    for (name, domain) in &topology.domains {
        if domain.backend.kind != "nix-closure" {
            continue;
        }

        lock.check_path()?;
        let (system, closure, root, kernel) = domain.backend.sources()?;
        let receipt: AdmissionReceipt = decode(&process::output(
            "airlock",
            &[
                "artifact",
                "send",
                "--reuse-generation",
                "--candidate-admission",
                admission.admission.as_str(),
                "--path-info-file",
                metadata_file
                    .path()
                    .to_str()
                    .ok_or_else(|| Error::Message("invalid metadata path".into()))?,
                "--domain",
                name.as_str(),
                "--system",
                system.as_str(),
                "--closure-source",
                closure.as_str(),
                "--root-source",
                root.as_str(),
                "--kernel-name",
                kernel,
                "--source-revision",
                grant.header.revision.as_str(),
                "--lock-hash",
                grant.header.lock_hash.as_str(),
            ],
        )?)?;
        let root = roots
            .get(name)
            .ok_or_else(|| Error::Message("built release has no guest root".into()))?;
        check_guest_admission(&receipt, name, &domain.backend, grant, root)?;
        receipts.insert(name.clone(), receipt);
        records::save(store, &super::build::name(grant, "admissions"), &receipts)?;
    }

    let action = if grant.header.action.is_plan() {
        "plan"
    } else {
        "apply"
    };
    let mut result = send_transport(
        action,
        &transport,
        grant,
        lock,
        &serde_json::to_value(&receipts)?,
    )?;
    check_plan(&result, grant)?;
    for key in ["paths_transferred", "nar_bytes", "compressed_bytes"] {
        let first = result
            .get(key)
            .and_then(Value::as_u64)
            .ok_or_else(|| Error::Message(format!("transport metric missing: {key}")))?;
        let prep = authorization
            .get(key)
            .and_then(Value::as_u64)
            .ok_or_else(|| Error::Message(format!("preparation metric missing: {key}")))?;
        result[key] = json!(
            first
                .checked_add(prep)
                .ok_or_else(|| Error::Message("transport metric overflow".into()))?
        );
    }

    result["candidate_preparation"] = authorization;
    result["elapsed_seconds"] = json!(start.elapsed().as_secs_f64());
    if !result.get("timings").is_some_and(Value::is_object) {
        result["timings"] = json!({});
    }
    result["timings"]["machine_metadata_seconds"] = json!(metadata_seconds);
    let build: Value = records::read_owned(&name(grant, "build"))?;
    result["build_seconds"] = build["build_seconds"].clone();

    let mut guest_transfer = serde_json::Map::new();
    let mut root_inventory = serde_json::Map::new();
    for (name, receipt) in receipts {
        let mut metrics = serde_json::Map::new();
        for key in [
            "generation_reused",
            "objects_total",
            "objects_reused",
            "objects_transferred",
            "payload_bytes_transferred",
            "root_artifact",
            "root_reused",
            "root_payload_bytes_transferred",
            "root_logical_bytes",
            "root_allocated_bytes",
            "timings",
        ] {
            let value = match key {
                "generation_reused" => json!(receipt.generation_reused),
                "root_artifact" => serde_json::to_value(&receipt.root_artifact)?,
                _ => receipt.diagnostics.get(key).cloned().unwrap_or(Value::Null),
            };
            metrics.insert(key.into(), value);
        }
        guest_transfer.insert(name.to_string(), Value::Object(metrics));
        if let Some(root) = &receipt.root_artifact {
            root_inventory.insert(root.sha256.clone(),json!({"logical_bytes":receipt.diagnostics.get("root_logical_bytes"),"allocated_bytes":receipt.diagnostics.get("root_allocated_bytes")}));
        }
    }

    result["guest_transfer"] = Value::Object(guest_transfer);
    result["root_inventory"] = Value::Object(root_inventory);
    records::save(store, &name(grant, action), &result)?;

    Ok(result)
}

fn response(bytes: &[u8]) -> Result<Value> {
    let result: Value = decode(bytes)?;
    require(result.is_object(), "invalid dom0 machine response")?;
    if let Some(error) = result.get("error") {
        return Err(Error::Remote {
            operation: "machine transport".into(),
            message: error.to_string(),
            details: Box::new(result),
        });
    }

    Ok(result)
}

fn send_transport(
    action: &str,
    transport: &StorePath,
    grant: &Grant,
    lock: &OperationLock,
    receipts: &Value,
) -> Result<Value> {
    grant.check(lock)?;
    let metadata = metadata(&[transport.as_str().to_owned()], true)?;
    let mut paths = BTreeMap::new();
    for (path, entry) in &metadata {
        let size = entry
            .get("narSize")
            .and_then(Value::as_u64)
            .ok_or_else(|| Error::Message("Nix metadata lacks narSize".into()))?;
        paths.insert(path, size);
    }

    let service = match action {
        "prepare" => "airlock.Ctrl.MachinePrepare",
        "plan" => "airlock.Ctrl.MachinePlan",
        "apply" => "airlock.Ctrl.MachineApply",
        _ => return Err(Error::Message("unsupported transport action".into())),
    };
    let mut child = OwnedChild(
        Command::new("qrexec-client-vm")
            .args(["dom0", service])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?,
    );

    let mut input = child.0.stdin.take().expect("piped stdin");
    let mut output = BufReader::new(child.0.stdout.take().expect("piped stdout"));
    serde_json::to_writer(
        &mut input,
        &json!({"schema":MACHINE_SCHEMA,"release":transport,"revision":grant.header.revision,"lock_hash":grant.header.lock_hash,"profile":profile()?,"receipts":receipts,"paths":paths,"review_authorization":grant.id}),
    )?;
    input.write_all(b"\n")?;
    input.flush()?;

    let mut line = Vec::new();
    output
        .by_ref()
        .take(16 * 1024 * 1024 + 1)
        .read_until(b'\n', &mut line)?;
    require(
        line.len() <= 16 * 1024 * 1024 && line.last() == Some(&b'\n'),
        "invalid or oversized dom0 inventory response",
    )?;
    let inventory = response(&line)?;
    require(
        inventory.get("schema") == Some(&json!(MACHINE_SCHEMA)),
        "unsupported inventory response schema",
    )?;
    let missing: Vec<StorePath> = decode(&serde_json::to_vec(&inventory["missing"])?)?;
    require(
        missing.iter().cloned().collect::<BTreeSet<_>>().len() == missing.len()
            && missing.iter().all(|p| metadata.contains_key(p)),
        "invalid dom0 missing-object inventory",
    )?;

    let mut gzip = GzEncoder::new(input, Compression::fast());
    if !missing.is_empty() {
        let mut exporter = OwnedChild(
            Command::new("airlock-config-nix-store")
                .arg("--export")
                .args(missing.iter().map(StorePath::as_str))
                .stdout(Stdio::piped())
                .spawn()?,
        );
        io::copy(
            &mut exporter.0.stdout.take().expect("export stdout"),
            &mut gzip,
        )?;
        require(
            exporter.0.wait()?.success(),
            "machine release export failed",
        )?;
    } else {
        gzip.write_all(&[0; 8])?;
    }
    drop(gzip.finish()?);

    let mut bytes = Vec::new();
    output
        .take(process::LIMIT as u64 + 1)
        .read_to_end(&mut bytes)?;
    require(
        bytes.len() <= process::LIMIT,
        "dom0 planning response exceeds limit",
    )?;
    let result = response(&bytes)?;
    require(
        child.0.wait()?.success(),
        "machine transfer or validation failed",
    )?;

    Ok(result)
}
