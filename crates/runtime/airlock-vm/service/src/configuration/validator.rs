//! Evaluate source only in the existing validator role and return checked contracts as inert artifacts.

use super::{Config, io};
use airlock_nix_core::{
    admission::CheckStatus,
    configuration::{
        ArtifactHashes, PreparedArchive, PreparedSource, ValidationRecord, ValidationSchema,
        ValidatorRole, file_hash,
    },
    runtime::process,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    os::unix::fs::PermissionsExt,
    path::{Component, Path, PathBuf},
    process::Command,
    time::Duration,
};

/// Captured validation evidence and first failure, kept distinct from the archive payload.
struct Validation {
    /// Candidate source identity checked against the Git bundle and checkout.
    commit: String,
    /// Overall status becomes failed at the first failed check and never returns to passed.
    status: &'static str,
    /// First meaningful failure; subsequent checks still retain their individual results.
    reason: String,
    /// Existing check records consumed by dom0 and local staging validation.
    checks: Vec<Value>,
}

impl Validation {
    /// Publish the shared receipt shape; only successful evaluation can supply complete content hashes.
    fn record(&self, directory: &Path, prepared: bool) -> Result<ValidationRecord> {
        Ok(ValidationRecord {
            schema: ValidationSchema::V2,
            status: if self.status == "passed" {
                CheckStatus::Passed
            } else {
                CheckStatus::Failed
            },
            reason: self.reason.clone(),
            validator_role: ValidatorRole::Validator,
            commit: self.commit.parse()?,
            artifacts: if self.status == "passed" {
                Some(ArtifactHashes::read(directory)?)
            } else {
                None
            },
            prepared_source: if prepared {
                Some(PreparedSource {
                    archive: PreparedArchive::Source,
                    sha256: file_hash(&directory.join("prepared-source.tar"))?,
                })
            } else {
                None
            },
            checks: self
                .checks
                .iter()
                .cloned()
                .map(serde_json::from_value)
                .collect::<Result<_, _>>()?,
        })
    }

    /// Add one check and preserve the first failed reason while continuing independent checks.
    fn check(&mut self, name: &str, result: Result<()>, reason: &str, mut evidence: Value) -> bool {
        let passed = result.is_ok();
        evidence["name"] = json!(name);
        evidence["status"] = json!(if passed { "passed" } else { "failed" });
        if let Err(error) = result {
            evidence["error"] = json!(format!("{error:#}"));
            if self.status == "passed" {
                self.status = "failed";
                self.reason = reason.into();
            }
        }
        self.checks.push(evidence);
        passed
    }

    /// Record a deliberately skipped dependent check without granting it success.
    fn skip(&mut self, name: &str, log: &Path) {
        self.checks
            .push(json!({"name":name,"status":"skipped","log":log}));
    }
}

/// Run the existing private-store Nix command with fixed offline/evaluation flags.
fn nix(
    config: &Config,
    worktree: &Path,
    args: &[String],
    output: Option<&Path>,
    log: &Path,
) -> Result<()> {
    let result = process::run(
        Command::new(&config.nix)
            .current_dir(worktree)
            .args([
                "--extra-experimental-features",
                "nix-command",
                "--extra-experimental-features",
                "flakes",
            ])
            .args(args),
        None,
        Some(Duration::from_secs(3600)),
    )?;
    fs::write(log, &result.stderr)?;
    if let Some(output) = output {
        fs::write(output, &result.stdout)?;
    } else {
        use std::io::Write;
        fs::OpenOptions::new()
            .append(true)
            .open(log)?
            .write_all(&result.stdout)?;
    }
    result.checked("configuration Nix validation")?;
    Ok(())
}

/// Select only declared source references; native VM dependencies and host components retain distinct sets.
fn references(value: &Value, system: bool) -> Result<Vec<String>> {
    let mut output = Vec::new();
    let mut add = |descriptor: &Value| -> Result<()> {
        if !descriptor["source_ref"].is_null() {
            output.push(
                descriptor["source_ref"]["attr"]
                    .as_str()
                    .context("source reference has no attr")?
                    .into(),
            );
        }
        Ok(())
    };
    if system {
        add(&value["dom0"]["profile"])?;
        for name in ["system", "kernel", "xen", "bootloader", "qubes"] {
            add(&value["dom0"]["nixos"][name])?;
        }
    } else {
        if let Some(templates) = value["templates"].as_object() {
            for template in templates.values() {
                add(template)?;
            }
        }
        if let Some(domains) = value["domains"].as_object() {
            for domain in domains
                .values()
                .filter(|domain| domain["backend"]["type"] == "nix-closure")
            {
                for name in ["system", "kernel", "initrd", "modules", "root", "store"] {
                    add(&domain["backend"][name])?;
                }
            }
        }
    }
    Ok(output)
}

/// Reject unsafe/missing direct host sources without executing their activation programs.
fn direct_sources(value: &Value, worktree: &Path) -> Result<()> {
    let mut components = vec![("dom0.profile", &value["dom0"]["profile"])];
    for name in ["system", "kernel", "xen", "bootloader", "qubes"] {
        components.push((
            if name == "system" {
                "dom0.nixos.system"
            } else {
                name
            },
            &value["dom0"]["nixos"][name],
        ));
    }
    for (component, descriptor) in components {
        if descriptor["source"].is_null() {
            continue;
        }
        let source = descriptor["source"]
            .as_str()
            .context("direct source must be a string")?;
        ensure!(
            !source.is_empty(),
            "empty direct system source for {component}"
        );
        let source_path = Path::new(source);
        ensure!(
            source_path.is_absolute()
                || (source != "."
                    && source != "./"
                    && !source.contains("//")
                    && !source_path
                        .components()
                        .any(|part| matches!(part, Component::ParentDir))),
            "unsafe relative system source for {component}: {source}"
        );
        let resolved = worktree.join(source_path);
        ensure!(
            resolved.exists(),
            "direct system source is missing for {component}: {source}"
        );
        let activation = match component {
            "dom0.profile" => Some(
                descriptor["activation_command"]
                    .as_str()
                    .unwrap_or("bin/airlock-dom0-profile-activate"),
            ),
            "dom0.nixos.system" => Some("bin/switch-to-configuration"),
            _ => None,
        };
        if let Some(activation) = activation {
            ensure!(
                resolved.is_dir()
                    && resolved
                        .join(activation)
                        .metadata()
                        .is_ok_and(|metadata| metadata.is_file()
                            && metadata.permissions().mode() & 0o111 != 0),
                "direct system activation command is missing or not executable for {component}"
            );
        }
    }
    Ok(())
}

/// Dry-run every declared source build using the selected generated flake.
fn source_checks(
    config: &Config,
    worktree: &Path,
    value: &Value,
    system: bool,
    log: &Path,
) -> Result<()> {
    fs::write(log, [])?;
    let temporary = tempfile::tempdir()?;
    for (index, attr) in references(value, system)?.iter().enumerate() {
        let action_log = temporary.path().join(format!("ref-{index}.log"));
        let result = nix(
            config,
            worktree,
            &[
                "build".into(),
                "--impure".into(),
                "--offline".into(),
                "--no-write-lock-file".into(),
                "--dry-run".into(),
                "--no-link".into(),
                "--show-trace".into(),
                format!("path:{worktree}#{attr}", worktree = worktree.display()),
            ],
            None,
            &action_log,
        );
        use std::io::Write;
        fs::OpenOptions::new()
            .append(true)
            .open(log)?
            .write_all(&fs::read(&action_log)?)?;
        result?;
    }
    if system {
        direct_sources(value, worktree)?;
    }
    Ok(())
}

/// Validate a staged bundle, retain each check, and export only a completely passing result.
pub(super) fn execute(config: &Config) -> Result<()> {
    let full = std::env::var("AIRLOCK_CONFIG_VALIDATION_BUILD").unwrap_or_else(|_| "0".into());
    ensure!(
        matches!(full.as_str(), "0" | "1"),
        "AIRLOCK_CONFIG_VALIDATION_BUILD must be 0 or 1"
    );
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path();
    let input = io::receive(directory)?;
    io::unpack(
        &input,
        directory,
        &["config.bundle", "manifest.json"],
        &["config.bundle", "manifest.json"],
    )?;
    let (revision, _) = io::bundle(directory)?;
    let mut worktree = directory.join("worktree");
    io::clone(directory, &worktree, &revision)?;
    ensure!(
        io::git(&worktree, &["rev-parse", "HEAD"])? == revision.as_str(),
        "cloned commit does not match candidate commit"
    );
    let dirty = io::git(&worktree, &["status", "--porcelain"])?;
    let validation_dir = io::path("AIRLOCK_CONFIG_VALIDATION_DIR", &config.validation);
    let logs = validation_dir.join("logs");
    fs::create_dir_all(&logs)?;
    let mut validation = Validation {
        commit: revision.to_string(),
        status: "passed",
        reason: "validation passed".into(),
        checks: vec![
            json!({"name":"candidate-manifest","status":"passed","manifest":directory.join("manifest.json")}),
            json!({"name":"git-bundle-verify","status":"passed","log":directory.join("bundle-verify.log")}),
            json!({"name":"git-clone","status":"passed","log":directory.join("snapshot-git-clone.log")}),
        ],
    };
    validation.check(
        "git-clean",
        if dirty.is_empty() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("validated candidate worktree is dirty"))
        },
        "validated candidate worktree is dirty",
        json!({"details":dirty}),
    );
    if !dirty.is_empty() {
        let record = serde_json::to_value(validation.record(directory, false)?)?;
        io::save(&validation_dir.join(format!("{revision}.json")), &record)?;
        anyhow::bail!("validated candidate worktree is dirty");
    }
    let mut prepared_source = false;
    if validation.status == "passed" && worktree.join("Cargo.toml").is_file() {
        let prepared = io::run(
            Command::new("make")
                .current_dir(&worktree)
                .args(["--silent", "prepare"])
                .arg(format!(
                    "AIRLOCK_PREPARED_CACHE={cache}",
                    cache = validation_dir.join("sources").display()
                )),
        )?;
        let prepared = String::from_utf8(prepared)?;
        worktree = PathBuf::from(
            prepared
                .trim()
                .strip_prefix("path:")
                .unwrap_or(prepared.trim()),
        );
        ensure!(
            worktree.is_absolute() && worktree.is_dir(),
            "candidate prepare did not return an existing absolute source path"
        );
        let archive = directory.join("prepared-source.tar");
        let mut tar = tar::Builder::new(File::create(&archive)?);
        tar.append_dir_all(".", &worktree)?;
        tar.finish()?;
        drop(tar);
        prepared_source = true;
    }
    let flake = format!("path:{path}", path = worktree.display());
    let flake_log = logs.join(format!("flake-check-{revision}.log"));
    let flake_result = if worktree.join("flake.nix").is_file() {
        nix(
            config,
            &worktree,
            &[
                "flake".into(),
                "check".into(),
                "--impure".into(),
                "--offline".into(),
                "--no-write-lock-file".into(),
                "--no-build".into(),
                flake.clone(),
            ],
            None,
            &flake_log,
        )
    } else {
        fs::write(&flake_log, "flake.nix is missing\n")?;
        Err(anyhow::anyhow!("flake.nix is missing"))
    };
    let flake_ok = validation.check(
        "nix-flake-check-no-build",
        flake_result,
        "nix flake check --no-build failed",
        json!({"log":flake_log}),
    );
    let full_log = logs.join(format!("flake-check-build-{revision}.log"));
    if flake_ok && full == "1" {
        let result = nix(
            config,
            &worktree,
            &[
                "flake".into(),
                "check".into(),
                "--impure".into(),
                "--offline".into(),
                "--no-write-lock-file".into(),
                flake.clone(),
            ],
            None,
            &full_log,
        );
        validation.check(
            "nix-flake-check",
            result,
            "nix flake check failed",
            json!({"log":full_log}),
        );
    } else {
        fs::write(&full_log, "full flake build skipped\n")?;
        validation.skip("nix-flake-check", &full_log);
    }
    for (component, eval_name, schema_name, refs_name) in [
        (
            "topology",
            "nix-eval-airlock-topology",
            "airlock-topology-json",
            "nix-template-source-refs-dry-run",
        ),
        (
            "system",
            "nix-eval-airlock-system",
            "airlock-system-json",
            "nix-system-source-refs-dry-run",
        ),
    ] {
        let output = directory.join(format!("{component}.json"));
        let log = logs.join(format!("nix-eval-{component}-{revision}.log"));
        let result = nix(
            config,
            &worktree,
            &[
                "eval".into(),
                "--impure".into(),
                "--offline".into(),
                "--no-write-lock-file".into(),
                format!("{flake}#airlock.{component}"),
                "--json".into(),
            ],
            Some(&output),
            &log,
        );
        let passed = validation.check(eval_name, result, &format!("nix eval .#airlock.{component} failed"), json!({"attr":format!("airlock.{component}"),"output":format!("{component}.json"),"log":log}));
        let schema_log = logs.join(format!("{component}-json-{revision}.log"));
        let refs_log = logs.join(format!("{component}-source-refs-{revision}.log"));
        if passed {
            let value = io::read(&output);
            let schema = value
                .as_ref()
                .map_err(|error| anyhow::anyhow!("{error:#}"))
                .and_then(|value| {
                    if component == "topology" {
                        ensure!(
                            value["schema"] == "airlock.qubes-topology.v1"
                                && ["templates", "kernels", "prefs", "domains", "qrexec_policy"]
                                    .iter()
                                    .all(|key| value[*key].is_object())
                                && value["qrexec_policy"]["rules"].is_array(),
                            "invalid evaluated topology schema"
                        );
                    } else {
                        ensure!(
                            value["schema"] == "airlock.system.v1"
                                && value["dom0"].is_object()
                                && value["plan"].is_object()
                                && ["live_actions", "reboot_actions", "reboot_reasons"]
                                    .iter()
                                    .all(|key| value["plan"][*key].is_array())
                                && value["plan"]["reboot_required"].is_boolean(),
                            "invalid evaluated system schema"
                        );
                    }
                    Ok(())
                });
            fs::write(
                &schema_log,
                match &schema {
                    Ok(()) => "schema accepted".into(),
                    Err(error) => format!("{error:#}"),
                },
            )?;
            validation.check(
                schema_name,
                schema,
                &format!("evaluated airlock.{component} JSON validation failed"),
                json!({"path":format!("{component}.json"),"log":schema_log}),
            );
            let refs = value.and_then(|value| {
                source_checks(config, &worktree, &value, component == "system", &refs_log)
            });
            validation.check(
                refs_name,
                refs,
                if component == "system" {
                    "system source reference dry-run failed"
                } else {
                    "template source reference dry-run failed"
                },
                json!({"log":refs_log}),
            );
        } else {
            validation.skip(schema_name, &schema_log);
            validation.skip(refs_name, &refs_log);
        }
    }
    let record = serde_json::to_value(validation.record(directory, prepared_source)?)?;
    io::save(&validation_dir.join(format!("{revision}.json")), &record)?;
    io::save(&directory.join("validation.json"), &record)?;
    ensure!(
        validation.status == "passed",
        "candidate validation failed: {record}"
    );
    let mut members = vec![
        "config.bundle",
        "validation.json",
        "manifest.json",
        "topology.json",
        "system.json",
    ];
    if prepared_source {
        members.push("prepared-source.tar");
    }
    io::export(directory, &members)
}
