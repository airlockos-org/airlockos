//! Capture evaluation inputs after source approval, separately from Nix-free source emission.
//! Nix owns locking, store identities and GC roots. These inputs grant no build or
//! deployment authority. The caller must retain `Prepared` throughout their use.
//!
//! The existing prepared-source inventory binds bytes, file presence and symlink
//! targets to the approved artifact. Serde, SHA-256, filesystem capture and Nix's
//! lock validity/store semantics remain trusted adapters. The verified lock guard
//! accepts only unchanged root bindings and unchanged retained dependency nodes.
//! The candidate compiler exports native compilation's explicit source catalogue;
//! arbitrary Nix modules retain the full source rather than guessing their imports.

use super::{Result, cache, inventory, mirror, output};
use crate::model::{GuestBackend, HermitApplication, MachineSnapshot};
use airlock_nix_core::{identity::GuestName, store_path::StorePath};
use rusix::{Config, interop::raw::NixValue, nix_record, nix_text};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
};

/// Why an evaluation can use a narrower source projection, or requires the complete snapshot.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Scope {
    /// Ordinary Nix modules can observe arbitrary captured files, including their absence.
    FullSnapshot,
    /// Native compilation reads an explicit crate projection and never imports user VM modules.
    Hermit {
        /// Supported native capability profile; the existing Hermit catalogue owns its files.
        application: String,
    },
}

/// A stable evaluation root and the remaining context required when consuming it.
#[derive(Debug, Serialize)]
pub struct Root {
    /// Immutable store object supplied as the flake root to Nix.
    pub source: StorePath,
    /// Captured source boundary; broad fallback is explicit rather than inferred independence.
    pub scope: Scope,
    /// Target supported by the current machine compiler.
    pub platform: String,
    /// Canonical executable, prefix arguments and version; include these in reuse checks.
    pub evaluator: String,
    /// Machine profile selected by the existing controller, part of the reuse context.
    pub profile: String,
    /// Human-readable explanation of the capture boundary or fallback.
    pub reason: String,
    /// Host assembly must consume the resulting descriptors of these guests.
    pub dependencies: Vec<GuestName>,
}

/// Owned source lease and Nix roots protecting every returned input through evaluation.
pub struct Prepared {
    /// Host and guest inputs, keyed by their declared machine identity.
    roots: BTreeMap<String, Root>,
    /// Private captured source, scoped staging directories and Nix's indirect GC roots.
    _capture: tempfile::TempDir,
    /// Prevent the original approved source artifact from being pruned during this operation.
    _source_lease: cache::Lease,
}

/// Source-owned component declaration, emitted with the complete reviewed source.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    /// Distinguishes a native input projection from unrestricted Nix configuration.
    scope: Scope,
    /// Host's descriptor dependencies; guest compilation has no dependency on running peers.
    dependencies: Vec<GuestName>,
    /// Candidate compiler's explicit native workspace and overlay directories.
    /// An older running controller must not substitute its own crate catalogue.
    #[serde(default)]
    members: Vec<String>,
}

/// Emit capture declarations without evaluating Nix or granting approval.
pub(crate) fn export(machine: &MachineSnapshot, directory: &Path, profile: &str) -> Result<()> {
    let mut specs = BTreeMap::new();
    for vm in machine.vms() {
        let scope = match vm.backend {
            GuestBackend::Nixos => Scope::FullSnapshot,
            GuestBackend::Hermit { application, .. } => Scope::Hermit {
                application: match application {
                    HermitApplication::Clipboard => "clipboard",
                    HermitApplication::Firewall => "firewall",
                }
                .into(),
            },
        };
        let members = match &scope {
            Scope::FullSnapshot => Vec::new(),
            Scope::Hermit { application } => airlock_build::hermit::APPLICATIONS
                .into_iter()
                .find(|source| source.profile == application)
                .ok_or("unsupported native application")?
                .members
                .iter()
                .copied()
                .chain(["patches", "vendor/nixos-qubes"])
                .map(str::to_owned)
                .collect(),
        };
        specs.insert(
            vm.name.to_string(),
            Spec {
                scope,
                dependencies: Vec::new(),
                members,
            },
        );
    }
    specs.insert(
        "dom0".into(),
        Spec {
            scope: Scope::FullSnapshot,
            dependencies: machine.vms().map(|vm| vm.name.clone()).collect(),
            members: Vec::new(),
        },
    );
    fs::write(
        directory.join(format!("generated/component-inputs-{profile}.json")),
        serde_json::to_vec_pretty(&specs)?,
    )?;
    fs::write(
        directory.join("generated/component-builders.nix"),
        crate::vm_builders()?.source,
    )?;
    Ok(())
}

/// Render literal fetcher attributes from Nix's JSON lock schema, using serde and Rusix.
/// Nested declarations are deliberately unsupported here and use the broad source boundary.
fn declaration(value: &Value) -> Result<NixValue> {
    let fields = value
        .as_object()
        .ok_or("missing original flake input declaration")?;
    let mut result = Vec::new();
    for (key, value) in fields {
        let literal = match value {
            Value::String(value) => NixValue::from(value.clone()),
            Value::Bool(value) => NixValue::from(*value),
            Value::Number(value) => {
                NixValue::from(value.as_i64().ok_or("unsupported input integer")?)
            }
            _ => return Err("component input requires a broader lock context".into()),
        };
        result.push((key.clone(), literal));
    }
    Ok(NixValue::record(result))
}

/// Describe only native compilation; no synthetic release revision or boot descriptor is created.
fn native_flake(lock: &Value, application: &str) -> Result<String> {
    let root = lock["root"].as_str().ok_or("dependency lock lacks root")?;
    let mut inputs = Vec::new();
    for name in ["nixpkgs", "nixpkgs-libvirt_10_5", "hermit-xen"] {
        let node = lock["nodes"][root]["inputs"][name]
            .as_str()
            .ok_or("native inputs require a broader follows context")?;
        inputs.push((name, declaration(&lock["nodes"][node]["original"])?));
    }
    let outputs = NixValue::function_attrs(
        ["self", "nixpkgs", "nixpkgs-libvirt_10_5", "hermit-xen"],
        |args| {
            let source = args.clone().select("self");
            let builders = NixValue::builtin("import").call(
                nix_text!("{source}/builders.nix", source = source.clone()),
            ).select("builders").call(nix_record! {
                "nixpkgs": args.clone().select("nixpkgs"),
                "nixpkgsLibvirt105Source": args.clone().select("nixpkgs-libvirt_10_5").to_text(),
                "nixosQubesSource": nix_text!("{source}/apps/vendor/nixos-qubes", source = source.clone()),
                "airlockSupport": source.clone(),
                "airlockAppsSource": nix_text!("{source}/apps", source = source),
                "hermitXen": args.select("hermit-xen"),
            });
            (
                Vec::<(&str, NixValue)>::new(),
                nix_record! {
                    "packages": nix_record! { "x86_64-linux": nix_record! {
                        "default": builders.select("mkHermitApplication").call(application),
                    } },
                },
            )
        },
    );
    Ok(crate::compile(
        Config::new()
            .set_dynamic("inputs", NixValue::record(inputs))
            .set_dynamic("outputs", outputs),
    )
    .map_err(|error| error.render(Path::new(".")))?
    .source)
}

/// Copy the explicitly bounded native source projection from the verified private capture.
fn native_source(machine: &Path, destination: &Path, members: &[String]) -> Result<()> {
    if members.is_empty() {
        return Err("candidate lacks an explicit native source boundary".into());
    }
    fs::create_dir_all(destination)?;
    fs::copy(
        captured_path(machine, Path::new("generated/component-builders.nix"))?,
        destination.join("builders.nix"),
    )?;
    // These package overlays form the same Nixpkgs fixed point as production.
    // Unused application recipes remain lazy; do not substitute a different package set.
    for member in members {
        let from = captured_path(machine, &Path::new("generated/crate2nix").join(member))?;
        mirror(&from, &destination.join("apps").join(member))?;
    }
    Ok(())
}

/// Read only through actual directories in the private capture. Mirroring preserves
/// nested symlinks as data, but its source directory must never itself resolve outside
/// the capture. Scoped inputs with such aliases use the broad, unchanged snapshot.
fn captured_path(root: &Path, relative: &Path) -> Result<PathBuf> {
    let mut path = root.to_owned();
    for part in relative.components() {
        if !matches!(part, std::path::Component::Normal(_)) {
            return Err("component input path must be relative and normalized".into());
        }
        path.push(part);
        if fs::symlink_metadata(&path)?.file_type().is_symlink() {
            return Err("component input requires a broader symlink context".into());
        }
    }
    Ok(path)
}

/// Prepare store-backed component roots from a published source artifact after approval.
/// `nix` supplies the caller's existing configured private-store command. Lock projection
/// is delegated to upstream Nix; new locked source identities force a broad fallback.
/// A complete verified private copy is consumed, never a subsequently reread checkout.
/// Keep the result alive until all consumers have finished. No systems are built here.
pub fn prepare(
    source: &Path,
    state: &Path,
    profile: &str,
    nix: &impl Fn() -> Command,
) -> Result<Prepared> {
    if !matches!(profile, "usb-lab" | "qemu-lab") {
        return Err("unsupported component profile".into());
    }
    let source = fs::canonicalize(source)?;
    let lease = cache::lease(source.parent().ok_or("source lacks cache parent")?, &source)?;
    fs::create_dir_all(state)?;
    let capture = tempfile::Builder::new()
        .prefix("component-inputs-")
        .tempdir_in(state)?;
    let captured = capture.path().join("snapshot");
    mirror(&source, &captured)?;
    let receipt_bytes = fs::read(captured_path(
        &captured,
        Path::new("airlock-prepared.json"),
    )?)?;
    let identity = format!("{hash:x}", hash = Sha256::digest(&receipt_bytes));
    if source.file_name().and_then(|name| name.to_str()) != Some(identity.as_str()) {
        return Err("captured source receipt differs from its published identity".into());
    }
    let receipt: Value = serde_json::from_slice(&receipt_bytes)?;
    let mut files = BTreeMap::new();
    let mut directories = BTreeSet::new();
    inventory(&captured, &captured, &mut files, &mut directories)?;
    files.remove("airlock-prepared.json");
    if serde_json::to_value(&files)? != receipt["artifact_files"] {
        return Err("captured component source differs from the prepared receipt".into());
    }
    if serde_json::to_value(&directories)? != receipt["artifact_directories"] {
        return Err(
            "captured directories differ from the receipt; prepare source with directory inventory"
                .into(),
        );
    }
    let candidate = captured.join("airlock-machine");
    let machine = match fs::symlink_metadata(&candidate) {
        Ok(metadata) if metadata.is_dir() => candidate,
        Ok(_) => return Err("captured machine source must be an actual directory".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => captured.clone(),
        Err(error) => return Err(error.into()),
    };
    let specs: BTreeMap<String, Spec> = serde_json::from_slice(&fs::read(captured_path(
        &machine,
        Path::new(&format!("generated/component-inputs-{profile}.json")),
    )?)?)?;
    let lock_path = captured_path(&machine, Path::new("flake.lock"))?;
    let lock: Value = serde_json::from_slice(&fs::read(&lock_path)?)?;
    let invocation = nix();
    let program = Path::new(invocation.get_program());
    if !program.is_absolute() {
        return Err("component preparation requires an absolute Nix executable".into());
    }
    let version = String::from_utf8(output(nix().arg("--version"))?)?;
    let evaluator = format!(
        "{program} {arguments:?}: {version}",
        program = fs::canonicalize(program)?.display(),
        arguments = invocation.get_args().collect::<Vec<_>>(),
        version = version.trim()
    );
    let mut roots = BTreeMap::new();
    let mut stored_paths: BTreeMap<PathBuf, StorePath> = BTreeMap::new();
    for (name, spec) in specs {
        if name != "dom0" {
            let _: GuestName = name.parse()?;
        }
        let mut scope = spec.scope;
        let mut path = machine.clone();
        let mut reason = "Full captured source: arbitrary Nix imports, absence checks and authoring/recovery inputs are preserved".to_owned();
        if let Scope::Hermit { application } = &scope {
            let native = capture.path().join(format!("native-{name}"));
            let attempt = || -> Result<()> {
                native_source(&machine, &native, &spec.members)?;
                fs::write(native.join("flake.nix"), native_flake(&lock, application)?)?;
                // Nix retains matching locked entries and prunes unused inputs itself.
                output(
                    nix()
                        .args(["flake", "lock", "--offline", "--reference-lock-file"])
                        .arg(&lock_path)
                        .arg("--output-lock-file")
                        .arg(native.join("flake.lock"))
                        .arg(format!("path:{path}", path = native.display())),
                )?;
                let projected: Value =
                    serde_json::from_slice(&fs::read(native.join("flake.lock"))?)?;
                let original = lock["nodes"]
                    .as_object()
                    .ok_or("dependency lock lacks nodes")?;
                let root = lock["root"].as_str().ok_or("dependency lock lacks root")?;
                let observed_root = projected["root"]
                    .as_str()
                    .ok_or("projected lock lacks root")?;
                let expected_inputs: serde_json::Map<String, Value> =
                    ["nixpkgs", "nixpkgs-libvirt_10_5", "hermit-xen"]
                        .into_iter()
                        .map(|name| (name.into(), lock["nodes"][root]["inputs"][name].clone()))
                        .collect();
                let mut expected_root_node = lock["nodes"][root].clone();
                expected_root_node["inputs"] = Value::Object(expected_inputs);
                // Compare complete retained nodes, including their dependency edges and
                // follows paths. A mere set of allowed source hashes would miss rewiring.
                let observed = projected["nodes"]
                    .as_object()
                    .ok_or("projected lock lacks nodes")?;
                let observed_root_node = observed
                    .get(observed_root)
                    .ok_or("projected root node missing")?;
                let encode =
                    |nodes: &serde_json::Map<String, Value>, root: &str| -> Result<Vec<String>> {
                        nodes
                            .iter()
                            .filter(|(name, _)| name.as_str() != root)
                            .map(|entry| Ok(serde_json::to_string(&entry)?))
                            .collect()
                    };
                let expected_nodes = encode(original, root)?;
                let observed_nodes = encode(observed, observed_root)?;
                if !airlock_machine_planning::lock_projection::matches(
                    &serde_json::to_string(&(root, expected_root_node))?,
                    &serde_json::to_string(&(observed_root, observed_root_node))?,
                    &expected_nodes
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                    &observed_nodes
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                ) {
                    return Err("Nix changed reviewed lock bindings or dependency nodes".into());
                }
                Ok(())
            };
            match attempt() {
                Ok(()) => {
                    path = native;
                    reason = "Explicit native crate, lock and overlay projection; release provenance remains outside compilation".into();
                }
                Err(error) => {
                    reason = format!("Full snapshot fallback: {error}");
                    scope = Scope::FullSnapshot;
                }
            }
        }
        let stored = if let Some(stored) = stored_paths.get(&path) {
            stored.clone()
        } else {
            let stored: StorePath = String::from_utf8(output(
                nix()
                    .args(["store", "add-path", "--name", "airlock-component-inputs"])
                    .arg(&path),
            )?)?
            .trim()
            .parse()?;
            output(
                nix()
                    // A bare directory installable would evaluate its default package.
                    // Root the already-added source object itself, without loading a flake.
                    .args(["build", "--impure", "--expr"])
                    .arg(
                        rusix::compile_value(NixValue::builtin("storePath").call(stored.as_str()))
                            .map_err(|error| error.render(Path::new(".")))?
                            .source,
                    )
                    .arg("--out-link")
                    .arg(capture.path().join(format!("root-{name}"))),
            )?;
            stored_paths.insert(path, stored.clone());
            stored
        };
        roots.insert(
            name,
            Root {
                source: stored,
                scope,
                platform: "x86_64-linux".into(),
                evaluator: evaluator.clone(),
                profile: profile.into(),
                reason,
                dependencies: spec.dependencies,
            },
        );
    }
    // The manifest is an observation for the caller, never an authorization receipt.
    fs::write(
        capture.path().join("inputs.json"),
        serde_json::to_vec_pretty(&json!({
            "schema": "airlock.component-inputs.v1", "roots": roots,
        }))?,
    )?;
    Ok(Prepared {
        roots,
        _capture: capture,
        _source_lease: lease,
    })
}

impl Prepared {
    /// Borrow captured identities while their source lease and Nix roots remain owned here.
    pub fn roots(&self) -> &BTreeMap<String, Root> {
        &self.roots
    }

    /// Return the manifest retained alongside the operation's source and Nix roots.
    pub fn manifest(&self) -> PathBuf {
        self._capture.path().join("inputs.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Republish a disposable changed capture with an accurate inventory and receipt identity.
    fn publish(staging: &Path) -> Result<PathBuf> {
        let mut files = BTreeMap::new();
        let mut directories = BTreeSet::new();
        inventory(staging, staging, &mut files, &mut directories)?;
        files.remove("airlock-prepared.json");
        let mut receipt: Value =
            serde_json::from_slice(&fs::read(staging.join("airlock-prepared.json"))?)?;
        receipt["artifact_files"] = serde_json::to_value(files)?;
        receipt["artifact_directories"] = serde_json::to_value(directories)?;
        let bytes = serde_json::to_vec(&receipt)?;
        fs::write(staging.join("airlock-prepared.json"), &bytes)?;
        let published = staging.with_file_name(format!("{hash:x}", hash = Sha256::digest(bytes)));
        fs::rename(staging, &published)?;
        Ok(published)
    }

    /// Exercise actual immutable store identities; tools and reviewed fixture are caller prepared.
    #[test]
    #[ignore = "explicit Nix/private-store evaluation with AIRLOCK_COMPONENT_SOURCE and AIRLOCK_COMPONENT_NIX"]
    fn component_boundaries_follow_captured_inputs() -> Result<()> {
        let source =
            PathBuf::from(std::env::var_os("AIRLOCK_COMPONENT_SOURCE").ok_or("missing source")?);
        let executable = std::env::var_os("AIRLOCK_COMPONENT_NIX").ok_or("missing Nix")?;
        let state =
            PathBuf::from(std::env::var_os("AIRLOCK_LOG_DIR").ok_or("missing log directory")?);
        let directory = tempfile::Builder::new()
            .prefix("component-validation-")
            .tempdir_in(&state)?;
        let staging = directory.path().join("staging");
        mirror(&source, &staging)?;
        let machine_relative = if staging.join("airlock-machine").is_dir() {
            "airlock-machine"
        } else {
            "."
        };
        let nix = || {
            let mut command = Command::new(&executable);
            command.args(["--extra-experimental-features", "nix-command flakes"]);
            command
        };
        let baseline = prepare(&source, directory.path(), "usb-lab", &nix)?;
        let physical = |root: &StorePath| -> PathBuf {
            let path = Path::new(root.as_str());
            match std::env::var_os("AIRLOCK_NIX_ROOT") {
                Some(prefix) => {
                    PathBuf::from(prefix).join(path.strip_prefix("/").expect("absolute store path"))
                }
                None => path.to_owned(),
            }
        };
        for name in ["sys-clipboard", "sys-firewall"] {
            assert!(
                matches!(baseline.roots[name].scope, Scope::Hermit { .. }),
                "{name}: {reason}",
                reason = baseline.roots[name].reason
            );
            // The flake is pure and its default package is the real production compiler output.
            let path = format!(
                "path:{source}#packages.x86_64-linux.default.drvPath",
                source = physical(&baseline.roots[name].source).display()
            );
            let drv = String::from_utf8(output(nix().args(["eval", "--raw", &path]))?)?;
            assert!(drv.trim().ends_with(".drv"));
            let inputs = NixValue::builtin("getFlake")
                .call(format!(
                    "path:{path}",
                    path = physical(&baseline.roots[name].source).display()
                ))
                .select("inputs");
            let full = physical(&baseline.roots["dom0"].source)
                .display()
                .to_string();
            let application = if name == "sys-firewall" {
                "firewall"
            } else {
                "clipboard"
            };
            let production = NixValue::builtin("import")
                .call(format!("{full}/generated/component-builders.nix"))
                .select("builders").call(nix_record! {
                    "nixpkgs": inputs.clone().select("nixpkgs"),
                    "nixpkgsLibvirt105Source": inputs.clone().select("nixpkgs-libvirt_10_5").to_text(),
                    "hermitXen": inputs.select("hermit-xen"),
                    "nixosQubesSource": format!("{full}/generated/crate2nix/vendor/nixos-qubes"),
                    "airlockAppsSource": format!("{full}/generated/crate2nix"),
                    "airlockSupport": full,
                    "applicationRevision": "a".repeat(40),
                })
                .select("mkHermitDomain").call(nix_record! {
                    "name": name, "application": application,
                    "upstream": if application == "firewall" { NixValue::from("sys-net") } else { NixValue::null() },
                    "memory": 256_i64, "vcpus": 1_i64,
                }).select("compiledApplication.drvPath");
            let expression = rusix::compile_value(production)
                .map_err(|error| error.render(Path::new(".")))?
                .source;
            let full_drv = String::from_utf8(output(nix().args([
                "eval",
                "--impure",
                "--raw",
                "--expr",
                &expression,
            ]))?)?;
            assert_eq!(
                drv, full_drv,
                "{name}: projection changed the production compilation"
            );
        }
        let machine = staging.join(machine_relative);
        let module = machine.join("vms/usr-home.nix");
        let original = fs::read(&module)?;
        for mutation in [
            "private-module",
            "shared-import",
            "deleted-import",
            "symlink",
            "empty-directory",
            "revision",
            "firewall-source",
            "native-source",
            "builder-settings",
            "dependency-lock",
        ] {
            mirror(&source.join(machine_relative), &machine)?;
            match mutation {
                "private-module" => fs::write(
                    &module,
                    [original.as_slice(), b"\n# private input edit\n"].concat(),
                )?,
                "shared-import" => {
                    fs::write(machine.join("vms/shared-input.nix"), "{}")?;
                    for name in ["usr-home", "sys-net"] {
                        fs::write(
                            machine.join(format!("vms/{name}.nix")),
                            "{ ... }: { imports = [ ./shared-input.nix ]; }",
                        )?;
                    }
                }
                "deleted-import" => fs::remove_file(&module)?,
                "symlink" => {
                    std::os::unix::fs::symlink("usr-home.nix", machine.join("vms/input-alias.nix"))?
                }
                "empty-directory" => fs::create_dir(machine.join("vms/new-empty-directory"))?,
                "revision" => {
                    let path = machine.join("airlock-source.json");
                    let mut identity: Value = serde_json::from_slice(&fs::read(&path)?)?;
                    identity["revision"] = Value::String("e".repeat(40));
                    fs::write(path, serde_json::to_vec(&identity)?)?;
                }
                "firewall-source" | "native-source" | "builder-settings" => {
                    let relative = match mutation {
                        "firewall-source" => {
                            "generated/crate2nix/runtime/airlock-sys-firewall/src/bin/hermit.rs"
                        }
                        "native-source" => "generated/crate2nix/airlock-common/boot/src/lib.rs",
                        _ => "generated/component-builders.nix",
                    };
                    let path = machine.join(relative);
                    let bytes = fs::read(&path)?;
                    let comment: &[u8] = if mutation == "builder-settings" {
                        b"\n# changed compiler input\n"
                    } else {
                        b"\n// changed compiler input\n"
                    };
                    fs::write(path, [bytes.as_slice(), comment].concat())?;
                }
                "dependency-lock" => {
                    let path = machine.join("flake.lock");
                    let mut lock: Value = serde_json::from_slice(&fs::read(&path)?)?;
                    let root = lock["root"].as_str().ok_or("missing root")?;
                    let node = lock["nodes"][root]["inputs"]["nixpkgs"]
                        .as_str()
                        .ok_or("missing nixpkgs")?
                        .to_owned();
                    lock["nodes"][&node]["locked"]["lastModified"] = json!(1);
                    fs::write(path, serde_json::to_vec(&lock)?)?;
                }
                _ => unreachable!(),
            }
            let published = publish(&staging)?;
            {
                let changed = prepare(&published, directory.path(), "usb-lab", &nix)?;
                for (name, root) in &baseline.roots {
                    let independent = matches!(root.scope, Scope::Hermit { .. })
                        && !matches!(
                            mutation,
                            "native-source" | "builder-settings" | "dependency-lock"
                        )
                        && !(mutation == "firewall-source" && name == "sys-firewall");
                    assert_eq!(
                        root.source == changed.roots[name].source,
                        independent,
                        "{mutation}: {name}"
                    );
                }
                assert!(changed.manifest().is_file());
                eprintln!("{mutation}: component identities match the declared boundary");
            }
            fs::rename(published, &staging)?;
        }
        let qemu = prepare(&source, directory.path(), "qemu-lab", &nix)?;
        assert!(qemu.roots.len() > baseline.roots.len());
        assert_eq!(qemu.roots["dom0"].dependencies.len(), qemu.roots.len() - 1);
        let retained = baseline._capture.path().to_owned();
        assert!(
            retained
                .join("root-sys-clipboard")
                .symlink_metadata()?
                .file_type()
                .is_symlink()
        );
        drop(baseline);
        assert!(!retained.exists());
        Ok(())
    }

    /// An approved alias is preserved by broad capture, never dereferenced by projection.
    #[test]
    fn native_projection_rejects_aliased_source_directories() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let machine = directory.path().join("machine");
        let generated = machine.join("generated");
        let external = directory.path().join("external");
        fs::create_dir_all(&generated)?;
        fs::create_dir(&external)?;
        fs::write(generated.join("component-builders.nix"), "{}")?;
        fs::write(external.join("private"), "must not be copied")?;
        std::os::unix::fs::symlink(&external, generated.join("crate2nix"))?;

        let destination = directory.path().join("native");
        assert!(
            native_source(
                &machine,
                &destination,
                &["airlock-common/bounded-heap".into()]
            )
            .is_err()
        );
        assert!(!destination.join("apps").exists());
        assert!(captured_path(&machine, Path::new("../external")).is_err());
        Ok(())
    }

    /// The approved candidate's member declaration governs capture across controller versions.
    #[test]
    fn native_projection_uses_candidate_members() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let machine = directory.path().join("machine");
        let generated = machine.join("generated");
        let member = generated.join("crate2nix/candidate-member");
        fs::create_dir_all(&member)?;
        fs::write(generated.join("component-builders.nix"), "{}")?;
        fs::write(member.join("source"), "candidate-owned input")?;
        let destination = directory.path().join("native");

        native_source(&machine, &destination, &["candidate-member".into()])?;
        assert_eq!(
            fs::read(destination.join("apps/candidate-member/source"))?,
            b"candidate-owned input"
        );
        assert!(
            native_source(
                &machine,
                &directory.path().join("escape"),
                &["../outside".into()]
            )
            .is_err()
        );
        assert!(native_source(&machine, &directory.path().join("unspecified"), &[]).is_err());
        Ok(())
    }

    /// Publish the minimal receipt boundary without invoking Git or Nix.
    fn fixture(directory: &Path) -> Result<PathBuf> {
        let staging = directory.join("staging");
        fs::create_dir(&staging)?;
        fs::create_dir(staging.join("empty"))?;
        fs::write(staging.join("input"), "approved bytes")?;
        let mut files = BTreeMap::new();
        let mut directories = BTreeSet::new();
        inventory(&staging, &staging, &mut files, &mut directories)?;
        let receipt = serde_json::to_vec(&json!({
            "schema":"airlock.prepared-source.v1", "artifact_files":files,
            "artifact_directories":directories,
        }))?;
        fs::write(staging.join("airlock-prepared.json"), &receipt)?;
        let destination = directory.join(format!("{hash:x}", hash = Sha256::digest(&receipt)));
        fs::rename(staging, &destination)?;
        Ok(destination)
    }

    /// Changes to bytes, presence or link identity fail before any evaluator is started.
    #[test]
    fn changed_prepared_source_cannot_reach_nix() -> Result<()> {
        for mutation in [
            "edit",
            "delete",
            "add",
            "symlink",
            "receipt",
            "add-directory",
            "delete-directory",
        ] {
            let directory = tempfile::tempdir()?;
            let source = fixture(directory.path())?;
            match mutation {
                "edit" => fs::write(source.join("input"), "different bytes")?,
                "delete" => fs::remove_file(source.join("input"))?,
                "add" => fs::write(source.join("extra"), "new input")?,
                "symlink" => {
                    fs::remove_file(source.join("input"))?;
                    std::os::unix::fs::symlink("../external", source.join("input"))?;
                }
                "receipt" => fs::write(source.join("airlock-prepared.json"), "{}")?,
                "add-directory" => fs::create_dir(source.join("extra"))?,
                "delete-directory" => fs::remove_dir(source.join("empty"))?,
                _ => unreachable!(),
            }
            let nix = || -> Command { panic!("changed source reached the evaluator") };
            assert!(
                prepare(&source, &directory.path().join("state"), "usb-lab", &nix).is_err(),
                "{mutation}"
            );
        }
        Ok(())
    }
}
