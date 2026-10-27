//! Resolve only the declared configuration outputs and retain relative sources beyond checkout cleanup.

use super::io::{self, Operation};
use crate::process::Files;
use airlock_nix_core::{
    configuration::{ResolvedConfiguration, ValidatedConfiguration},
    identity::GitRevision,
};
use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Component, Path, PathBuf},
};

/// Source resolution inputs supplied by the existing validated-candidate pipeline.
#[derive(Args)]
pub(crate) struct Request {
    /// Evaluated topology whose declared references may be built.
    #[arg(long)]
    pub(super) topology: PathBuf,
    /// Evaluated host contract containing declared host source references.
    #[arg(long)]
    pub(super) system: PathBuf,
    /// Exact checked-out or prepared candidate source directory.
    #[arg(long)]
    pub(super) worktree: PathBuf,
    /// Validated source revision used to retain direct source artifacts.
    #[arg(long)]
    pub(super) commit: GitRevision,
}

/// Keep logical Nix identities distinct from paths inside the explicitly selected private store.
pub(super) fn physical(source: &Path) -> PathBuf {
    let root = std::env::var_os("AIRLOCK_NIX_ROOT").map(PathBuf::from);
    if std::env::var("AIRLOCK_USE_HOST_NIX_STORE").as_deref() != Ok("1")
        && source.starts_with("/nix/store")
        && let Some(root) = root
        && root != Path::new("/")
        && !root.as_os_str().is_empty()
    {
        return root.join(source.strip_prefix("/").unwrap());
    }
    source.to_owned()
}

/// Replace only unsafe filename characters in informational artifact names.
pub(super) fn safe(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || "_.-".contains(ch) {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

/// Resolve the declared executable within its profile without letting absolute or parent paths replace that profile.
pub(super) fn activation_path(source: &Path, contract: &Value) -> Result<PathBuf> {
    let command = match contract.get("activation_command") {
        None | Some(Value::Null) => "bin/airlock-dom0-profile-activate",
        Some(value) => value
            .as_str()
            .context("profile activation command must be a string")?,
    };
    ensure!(
        !command.is_empty()
            && command.split('/').all(|part| {
                !part.is_empty()
                    && part != "."
                    && part != ".."
                    && part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"_.+-".contains(&byte))
            }),
        "profile activation command must be a relative executable path within the profile"
    );
    Ok(source.join(command))
}

/// Match candidate-relative source semantics while refusing parent traversal and empty components.
fn direct(worktree: &Path, source: &str) -> Result<PathBuf> {
    ensure!(!source.is_empty(), "empty direct system source");
    let path = Path::new(source);
    if path.is_absolute() {
        return Ok(path.into());
    }
    ensure!(
        source != "."
            && source != "./"
            && !source.contains("//")
            && !path
                .components()
                .any(|part| matches!(part, Component::ParentDir)),
        "unsafe relative system source: {source}"
    );
    Ok(worktree.join(path))
}

/// Validate the kind-specific files required by existing setup and activation adapters.
fn validate(kind: &str, source: &Path, contract: &Value) -> Result<()> {
    ensure!(
        source.exists(),
        "source is missing: {source}",
        source = source.display()
    );
    let executable = |name: &str| {
        source
            .join(name)
            .metadata()
            .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
    };
    match kind {
        "template" => ensure!(
            source.is_dir()
                && source.join("root.img").is_file()
                && source.join("template.conf").is_file(),
            "built template source is missing root.img or template.conf"
        ),
        "system" => ensure!(
            source.is_dir() && source.join("init").exists(),
            "Nix-native domain system source is missing init"
        ),
        "kernel" => ensure!(
            source.is_dir() && source.join("vmlinuz").is_file(),
            "Nix-native domain kernel source is missing vmlinuz"
        ),
        "initrd" | "modules" => {}
        "root" => ensure!(
            source.is_file() || (source.is_dir() && source.join("root.img").is_file()),
            "Nix-native domain root image directory is missing root.img"
        ),
        "store" => {
            ensure!(
                contract["mode"].as_str().unwrap_or("shared-closure") == "shared-closure",
                "unsupported Nix-native domain store mode"
            );
            ensure!(
                source.is_dir()
                    && source.join("store-paths").is_file()
                    && source.join("manifest.json").is_file(),
                "Nix-native domain shared closure source is missing store-paths or manifest.json"
            );
        }
        "dom0.profile" => {
            let activation = activation_path(source, contract)?;
            ensure!(
                source.is_dir()
                    && activation
                        .metadata()
                        .is_ok_and(|metadata| metadata.is_file()
                            && metadata.permissions().mode() & 0o111 != 0),
                "direct dom0 profile activation command is missing or not executable"
            );
        }
        "dom0.nixos.system" => ensure!(
            source.is_dir() && executable("bin/switch-to-configuration"),
            "dom0 NixOS system source is missing bin/switch-to-configuration"
        ),
        "dom0.nixos.kernel" | "dom0.nixos.xen" | "dom0.nixos.bootloader" | "dom0.nixos.qubes" => {}
        _ => bail!("unsupported source component: {kind}"),
    }
    Ok(())
}

/// Resolve one selected source; failed builds leave explicit evidence before propagating failure.
struct Resolver<'a> {
    /// Shared command evidence for source-resolution helpers.
    operation: &'a mut Operation,
    /// Selected candidate checkout or generated prepared tree.
    worktree: &'a Path,
    /// Retention namespace fixed to the validated source revision.
    retained: PathBuf,
}

impl Resolver<'_> {
    /// Resolve a build reference or retain a direct source, updating only that descriptor.
    fn resolve(
        &mut self,
        descriptor: &mut Value,
        kind: &str,
        owner: &str,
        family: &str,
    ) -> Result<()> {
        let reference = descriptor
            .get("source_ref")
            .filter(|value| !value.is_null())
            .cloned();
        if reference.is_none() && descriptor["source"].is_null() {
            return Ok(());
        }
        let retained_name = if family == "nix-domain" {
            format!("nix-domain-{owner}-{kind}")
        } else {
            kind.into()
        };
        let source = if let Some(reference) = reference {
            let attr = reference["attr"]
                .as_str()
                .context("source reference attr")?;
            let subpath = reference["subpath"].as_str().unwrap_or("");
            ensure!(
                !Path::new(subpath).is_absolute()
                    && !Path::new(subpath)
                        .components()
                        .any(|part| matches!(part, Component::ParentDir)),
                "unsafe source reference subpath"
            );
            let label = if family == "template" {
                owner.to_owned()
            } else if family == "nix-domain" {
                format!("{owner}-{kind}")
            } else {
                kind.to_owned()
            };
            let stem = format!("config-apply-{family}-build-{label}", label = safe(&label));
            let log = self.operation.file(&format!("{stem}.log"));
            let output = self.operation.file(&format!("{stem}.stdout"));
            let mut args = [
                "--extra-experimental-features",
                "nix-command",
                "--extra-experimental-features",
                "flakes",
                "build",
                "--impure",
                "--no-write-lock-file",
                "--no-link",
                "--print-out-paths",
                "--show-trace",
            ]
            .map(Into::into)
            .to_vec();
            match io::setting("AIRLOCK_CONFIG_APPLY_NIX_OFFLINE", "1").as_str() {
                "1" | "true" | "yes" => args.push("--offline".into()),
                "0" | "false" | "no" => {}
                _ => bail!("unsupported AIRLOCK_CONFIG_APPLY_NIX_OFFLINE value"),
            }
            args.push(format!("path:{worktree}#{attr}", worktree = self.worktree.display()).into());
            let result = self.operation.transfer(
                "nix",
                &args,
                Files {
                    input: None,
                    output: &output,
                    errors: &log,
                    limit: 16 * 1024 * 1024,
                },
                &[],
            );
            let output_path = fs::read_to_string(&output)
                .unwrap_or_default()
                .lines()
                .rfind(|line| !line.trim().is_empty())
                .unwrap_or("")
                .to_owned();
            let source = if subpath.is_empty() {
                PathBuf::from(&output_path)
            } else {
                PathBuf::from(&output_path).join(subpath)
            };
            let result = result.and_then(|()| {
                ensure!(
                    !output_path.is_empty(),
                    "build did not print an output path for {kind}"
                );
                validate(kind, &physical(&source), descriptor)
            });
            let mut record = json!({"attr":attr,"subpath":subpath,"status":if result.is_ok() {"passed"} else {"failed"},"output_path":output_path,"source_path":source,"log":log});
            match family {
                "template" => record["template"] = json!(owner),
                "nix-domain" => {
                    record["domain"] = json!(owner);
                    record["component"] = json!(kind);
                }
                _ => record["component"] = json!(kind),
            }
            let receipt = self
                .operation
                .file(&format!("config-apply-{family}-builds.json"));
            let mut builds: Value = crate::state::read(&receipt)?;
            builds["builds"]
                .as_array_mut()
                .context("source build inventory")?
                .push(record);
            io::save(&receipt, &builds)?;
            let mut combined = fs::OpenOptions::new().append(true).open(
                self.operation
                    .file(&format!("config-apply-{family}-builds.log")),
            )?;
            use std::io::Write;
            combined.write_all(&fs::read(&log)?)?;
            combined.write_all(output_path.as_bytes())?;
            result?;
            source
        } else {
            let declared = descriptor["source"]
                .as_str()
                .context("direct source must be a string")?;
            let source = direct(self.worktree, declared)?;
            let source_path = physical(&source);
            ensure!(
                source_path.exists(),
                "direct source is missing for {owner}.{kind}: {declared}"
            );
            let resolved = if Path::new(declared).is_absolute() {
                source
            } else {
                let retained = self.retained.join(safe(&retained_name));
                if retained.symlink_metadata().is_ok() {
                    if retained.is_dir() && !retained.is_symlink() {
                        fs::remove_dir_all(&retained)?;
                    } else {
                        fs::remove_file(&retained)?;
                    }
                }
                fs::create_dir_all(&self.retained)?;
                self.operation.text(
                    "cp",
                    &[
                        "-a",
                        source_path.to_str().context("direct source path")?,
                        retained.to_str().context("retained source path")?,
                    ],
                )?;
                retained
            };
            validate(kind, &physical(&resolved), descriptor)?;
            resolved
        };
        descriptor["source"] = json!(source);
        descriptor["source_ref"] = Value::Null;
        Ok(())
    }
}

/// Resolve template, native VM and host descriptors while preserving their independent contracts.
pub(super) fn execute(request: Request) -> Result<()> {
    let topology = crate::state::configuration(&request.topology)?;
    let system = crate::state::configuration(&request.system)?;
    resolve(&request.worktree, &request.commit, topology, system)?;
    Ok(())
}

/// Resolve immutable checked documents directly, without reopening their diagnostic JSON files.
pub(super) fn validated(
    candidate: ValidatedConfiguration,
    worktree: &Path,
) -> Result<ResolvedConfiguration> {
    let (topology, system) = resolve(
        worktree,
        &candidate.identity().source.commit,
        candidate.topology().clone(),
        candidate.system().clone(),
    )?;
    let operation = Operation::new("config-resolution-binding")?;
    fs::write(
        operation.file("config-apply-topology-validated.json"),
        candidate.topology_bytes(),
    )?;
    fs::write(
        operation.file("config-apply-system-validated.json"),
        candidate.system_bytes(),
    )?;
    let resolved = candidate.resolved(&topology, &system)?;
    fs::write(
        operation.file("config-apply-topology.json"),
        resolved.topology_bytes(),
    )?;
    fs::write(
        operation.file("config-apply-system.json"),
        resolved.system_bytes(),
    )?;
    io::save(
        &operation.file("config-apply-resolution.json"),
        &serde_json::to_value(resolved.record())?,
    )?;
    Ok(resolved)
}

/// Run the existing source resolver; the administrative CLI retains its separate explicit unvalidated entry point.
fn resolve(
    worktree: &Path,
    commit: &GitRevision,
    mut topology: Value,
    mut system: Value,
) -> Result<(Value, Value)> {
    let mut operation = Operation::new("config-resolve")?;
    io::save(
        &operation.file("config-apply-topology-validated.json"),
        &topology,
    )?;
    io::save(
        &operation.file("config-apply-system-validated.json"),
        &system,
    )?;
    for (family, schema) in [
        ("template", "airlock.template-builds.v1"),
        ("nix-domain", "airlock.nix-domain-builds.v1"),
        ("system", "airlock.system-builds.v1"),
    ] {
        io::save(
            &operation.file(&format!("config-apply-{family}-builds.json")),
            &json!({"schema":schema,"builds":[]}),
        )?;
        fs::write(
            operation.file(&format!("config-apply-{family}-builds.log")),
            [],
        )?;
    }
    let state = io::path("AIRLOCK_SYSTEM_STATE_DIR", "/var/lib/airlock/system");
    let mut resolver = Resolver {
        operation: &mut operation,
        worktree,
        retained: state.join("sources").join(commit.as_str()),
    };
    for (name, template) in topology["templates"]
        .as_object_mut()
        .context("templates must be an object")?
    {
        if !template["source_ref"].is_null() {
            resolver.resolve(template, "template", name, "template")?;
        }
    }
    for (name, domain) in topology["domains"]
        .as_object_mut()
        .context("domains must be an object")?
    {
        if domain["backend"]["type"] == "nix-closure" {
            for component in ["system", "kernel", "initrd", "modules", "root", "store"] {
                if let Some(descriptor) = domain
                    .get_mut("backend")
                    .and_then(|b| b.get_mut(component))
                    .filter(|d| !d.is_null())
                {
                    resolver.resolve(descriptor, component, name, "nix-domain")?;
                }
            }
        }
    }
    for component in ["profile", "system", "kernel", "xen", "bootloader", "qubes"] {
        let dom0 = system.get_mut("dom0");
        let descriptor = if component == "profile" {
            dom0.and_then(|d| d.get_mut("profile"))
        } else {
            dom0.and_then(|d| d.get_mut("nixos"))
                .and_then(|n| n.get_mut(component))
        };
        if let Some(descriptor) = descriptor.filter(|d| !d.is_null()) {
            resolver.resolve(
                descriptor,
                &if component == "profile" {
                    "dom0.profile".into()
                } else {
                    format!("dom0.nixos.{component}")
                },
                "dom0",
                "system",
            )?;
        }
    }
    io::save(&operation.file("config-apply-topology.json"), &topology)?;
    io::save(&operation.file("config-apply-system.json"), &system)?;
    let mut domains = Vec::new();
    for (name, domain) in topology["domains"].as_object().unwrap() {
        if domain["backend"]["type"] == "nix-closure" {
            let mut value = json!({"domain":name});
            for key in [
                "class", "label", "netvm", "prefs", "features", "services", "devices",
            ] {
                value[key] = if domain[key].is_null()
                    && ["prefs", "features", "services", "devices"].contains(&key)
                {
                    json!({})
                } else {
                    domain[key].clone()
                };
            }
            for key in [
                "system", "kernel", "initrd", "modules", "root", "store", "state",
            ] {
                value[key] = domain["backend"][key].clone();
            }
            domains.push(value);
        }
    }
    io::save(
        &operation.file("config-apply-nix-domain-materializations.json"),
        &json!({"schema":"airlock.nix-domain-materializations.v1","domains":domains}),
    )?;
    super::references::validate(
        &operation.file("config-apply-topology.json"),
        &operation.file("config-apply-domain-references.json"),
    )?;
    Ok((topology, system))
}
