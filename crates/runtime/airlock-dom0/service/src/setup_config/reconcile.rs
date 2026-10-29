//! Reconcile common VM configuration in Rust for deployment and explicit setup.
//! The installed setup launcher dispatches global, storage and device adapters to
//! native Rust; common VM requests retain their existing deployment gates.

use super::*;
use crate::{model::Record, process::Runner};
use airlock_deployment_core::configuration::{self, Definition, Helper, Kind, Setting};
use serde_json::Value;
use std::{ffi::OsString, path::Path, time::Duration};

/// Normalize values exactly as the setup wire protocol: booleans use Qubes spelling.
fn value(v: &Value) -> Result<String> {
    Ok(match v {
        Value::Null => "none".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => anyhow::bail!("Qubes setting must be a scalar"),
    })
}

/// Decode one named settings map, refusing malformed containers and service values.
fn settings(domain: &Value, name: &str) -> Result<Vec<Setting>> {
    let Some(values) = domain.get(name) else {
        return Ok(Vec::new());
    };
    let values = values
        .as_object()
        .context("Qubes settings must be an object")?;
    values
        .iter()
        .map(|(key, v)| {
            ensure!(
                !key.is_empty()
                    && key
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
                "invalid Qubes setting name"
            );
            Ok(Setting {
                name: key.clone(),
                value: if name == "services" {
                    match v.as_bool().context("service setting must be boolean")? {
                        true => "on".into(),
                        false => "off".into(),
                    }
                } else {
                    value(v)?
                },
            })
        })
        .collect()
}

/// Decode the complete definition set from the same immutable release as plan binding.
/// This is a trusted wire adapter; request selection and argv construction are verified.
pub(crate) fn definitions(topology: &Value, program: &str, path: &Path) -> Result<Vec<Definition>> {
    let domains = topology["domains"]
        .as_object()
        .context("topology domains must be an object")?;
    domains
        .iter()
        .map(|(name, domain)| {
            let _: GuestName = name.parse()?;
            ensure!(domain.is_object(), "VM definition must be an object");
            let native = domain["backend"]["type"].as_str() == Some("nix-closure");
            let class = domain
                .get("class")
                .filter(|v| !v.is_null())
                .map(|v| v.as_str().context("VM class must be a string"))
                .transpose()?
                .unwrap_or(if native { "StandaloneVM" } else { "AppVM" });
            let label = domain
                .get("label")
                .filter(|v| !v.is_null())
                .map(|v| v.as_str().context("VM label must be a string"))
                .transpose()?
                .unwrap_or(if native { "green" } else { "red" });
            ensure!(
                !native || class == "StandaloneVM",
                "nix-closure requires StandaloneVM"
            );
            let mut features = settings(domain, "features")?;
            if domain["backend"]["type"] == "hermit" {
                let backend: crate::model::Backend =
                    serde_json::from_value(domain["backend"].clone())?;
                let artifact = backend.hermit().context("missing Hermit image")?;
                artifact.validate(false)?;
                ensure!(
                    class == "HermitVM",
                    "Hermit backend requires HermitVM class"
                );
                ensure!(
                    !features.iter().any(|setting| matches!(
                        setting.name.as_str(),
                        "airlock-hermit-artifact"
                            | "airlock-hermit-generation"
                            | "airlock-system-source"
                            | "airlock-hermit-scratch"
                    )),
                    "Hermit artifact feature is derived from the admitted backend"
                );
                features.push(Setting {
                    name: "airlock-hermit-generation".into(),
                    value: path.to_str().context("invalid generation path")?.into(),
                });
                features.push(Setting {
                    name: "airlock-system-source".into(),
                    value: backend.system.source.to_string(),
                });
                features.push(Setting {
                    name: "airlock-hermit-scratch".into(),
                    value: backend
                        .hermit_scratch()
                        .map(serde_json::to_string)
                        .transpose()?
                        .unwrap_or_default(),
                });
                features.push(Setting {
                    name: "airlock-hermit-artifact".into(),
                    value: serde_json::to_string(artifact)?,
                });
            }
            let mut properties = vec![Setting {
                name: "label".into(),
                value: label.into(),
            }];
            let mut prefs = settings(domain, "prefs")?;
            let order = [
                "virt_mode",
                "kernel",
                "kernelopts",
                "memory",
                "maxmem",
                "qrexec_timeout",
                "default_user",
            ];
            prefs.sort_by_key(|s| {
                order
                    .iter()
                    .position(|key| *key == s.name)
                    .unwrap_or(order.len())
            });
            properties.extend(
                prefs
                    .into_iter()
                    .filter(|s| !native || !matches!(s.name.as_str(), "kernel" | "kernelopts")),
            );
            if let Some(reference) = domain.get("netvm") {
                let reference = value(reference)?;
                properties.push(Setting {
                    name: "netvm".into(),
                    value: if ["", "none", "None", "null"].contains(&reference.as_str()) {
                        "none".into()
                    } else {
                        reference
                    },
                });
            }
            let template = domain
                .get("template")
                .filter(|v| !v.is_null())
                .map(value)
                .transpose()?
                .filter(|s| !s.is_empty() && s != "none");
            Ok(Definition {
                name: name.clone(),
                class: class.into(),
                label: label.into(),
                template,
                properties,
                features,
                services: settings(domain, "services")?,
                helper: Some(Helper {
                    program: program.into(),
                    topology: path.to_str().context("non-UTF8 topology path")?.into(),
                }),
            })
        })
        .collect()
}

/// Retained authority is absent only for explicit local boot/manual setup.
type Deployment<'a> = Option<(
    &'a crate::coordinator::approval::DurableAuthorization,
    &'a Record,
    &'a airlock_deployment_core::storage::staging::StagedGenerations,
)>;

/// Normal observation/iteration shared by deployment and boot/manual callers.
/// `only` restricts boot scopes without discarding the other declared identities.
pub(crate) fn apply(
    runner: &Runner,
    definitions: &[Definition],
    deployment: Deployment<'_>,
    apply: bool,
    only: Option<&str>,
) -> Result<()> {
    apply_inner(runner, definitions, deployment, apply, only, None)
}

/// A checked boot backend is consumed directly, without invoking an optional-selection helper.
pub(crate) fn apply_boot(
    runner: &Runner,
    definitions: &[Definition],
    apply: bool,
    domain: &str,
    selected: &airlock_deployment_core::boot::SelectedGeneration,
) -> Result<()> {
    ensure!(
        selected.selection().domain == domain,
        "checked setup names another VM"
    );
    apply_inner(
        runner,
        definitions,
        None,
        apply,
        Some(domain),
        Some(selected),
    )
}

fn apply_inner(
    runner: &Runner,
    definitions: &[Definition],
    deployment: Deployment<'_>,
    apply: bool,
    only: Option<&str>,
    selected: Option<&airlock_deployment_core::boot::SelectedGeneration>,
) -> Result<()> {
    let log = if deployment.is_some() {
        runner.configuration_log_directory()?
    } else {
        std::env::var_os("AIRLOCK_LOG_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| "/var/log/airlock".into())
    };
    let run: crate::model::TransactionId = deployment
        .map(|(_, record, _)| record.id.clone())
        .map_or_else(
            || {
                std::env::var("AIRLOCK_SETUP_RUN_ID")
                    .unwrap_or_else(|_| std::process::id().to_string())
                    .try_into()
            },
            Ok,
        )?;
    for definition in definitions {
        if only.is_none_or(|name| definition.name == name) {
            super::report::tasks::clear(&log, &definition.name)?;
        }
    }
    for (index, definition) in definitions.iter().enumerate() {
        if only.is_some_and(|name| definition.name != name) {
            continue;
        }
        let registered = runner.text(
            "qvm-ls",
            &["--raw-data", "--fields", "NAME", "--no-spinner"],
        )?;
        let exists = registered.lines().any(|name| name == definition.name);
        if let Some((authority, record, _)) = deployment {
            if let Some(request) = authority.configuration_create(record, index, exists)? {
                runner.create_deployment(request)?;
                event(
                    &log,
                    "domain",
                    "create",
                    definition,
                    "class",
                    &definition.class,
                    false,
                )?;
            }
        } else if !exists {
            manual(
                runner,
                "qvm-create",
                &configuration::create_arguments(definition),
                apply,
            )?;
            event(
                &log,
                "domain",
                "create",
                definition,
                "class",
                &definition.class,
                false,
            )?;
        }
    }

    // Creation precedes relationship configuration during deployment. Boot scopes
    // retain their existing provider-first orchestration in the setup adapter.
    for (index, definition) in definitions.iter().enumerate() {
        if only.is_some_and(|name| definition.name != name) {
            continue;
        }
        let backend = if let Some((authority, record, staged)) = deployment {
            super::backend::apply_deployment(authority, record, staged, index, definition, &log)?
        } else if let Some(selected) = selected {
            super::backend::apply_boot(selected, definition, &log, apply)?
        } else {
            helper(
                runner,
                definition,
                index,
                deployment,
                apply,
                Adapter::Backend,
                &log,
            )?
        };
        if backend.is_none() && deployment.is_some() {
            task_completed(
                &log,
                definition,
                &run,
                apply,
                super::report::tasks::Kind::Backend,
            )?;
        }
        let deferred = backend.as_ref().is_some_and(|report| {
            report.restart_actions.iter().any(|action| {
                matches!(
                    action["type"].as_str(),
                    Some("domain-root" | "domain-store" | "domain-system")
                )
            })
        });
        ensure!(
            deployment.is_none() || !deferred,
            "deployment backend update requires a stopped VM"
        );
        let root_provider = definition
            .properties
            .iter()
            .any(|s| s.name == "provides_network" && s.value == "True")
            && definition
                .properties
                .iter()
                .filter(|s| s.name == "netvm")
                .all(|s| configuration::value_matches("none", Some(&s.value)));
        for (kind, values) in [
            (Kind::Property, &definition.properties),
            (Kind::Feature, &definition.features),
            (Kind::Service, &definition.services),
        ] {
            for (setting_index, setting) in values.iter().enumerate() {
                if matches!(kind, Kind::Property) && setting.name == "netvm" && !root_provider {
                    continue;
                }
                if matches!(kind, Kind::Feature) && deferred && boot_feature(&setting.name) {
                    continue;
                }
                reconcile_setting(
                    runner,
                    definitions,
                    configuration::Selection {
                        domain: index,
                        kind,
                        setting: setting_index,
                    },
                    deployment,
                    apply,
                    &log,
                )?;
            }
        }
        if let Some((authority, record, _)) = deployment {
            ensure!(
                authority
                    .device_definitions()
                    .get(index)
                    .is_some_and(|d| d.name == definition.name),
                "device/configuration index identity differs"
            );
            super::devices::apply_deployment(runner, authority, record, index, &log)?;
            task_completed(
                &log,
                definition,
                &run,
                apply,
                super::report::tasks::Kind::Devices,
            )?;
        } else {
            helper(
                runner,
                definition,
                index,
                deployment,
                apply,
                Adapter::Devices,
                &log,
            )?;
        }
        if !root_provider {
            for (setting_index, _) in definition
                .properties
                .iter()
                .enumerate()
                .filter(|(_, setting)| setting.name == "netvm")
            {
                reconcile_setting(
                    runner,
                    definitions,
                    configuration::Selection {
                        domain: index,
                        kind: Kind::Property,
                        setting: setting_index,
                    },
                    deployment,
                    apply,
                    &log,
                )?;
            }
        }
        task_completed(
            &log,
            definition,
            &run,
            apply,
            super::report::tasks::Kind::Configuration,
        )?;
    }
    Ok(())
}

/// Record completion after all in-process work for this responsibility returned successfully.
fn task_completed(
    log: &Path,
    definition: &Definition,
    run: &crate::model::TransactionId,
    apply: bool,
    kind: super::report::tasks::Kind,
) -> Result<()> {
    let helper = definition
        .helper
        .as_ref()
        .context("missing task topology")?;
    super::report::tasks::completed(
        log,
        Path::new(&helper.topology),
        run,
        apply,
        super::report::tasks::Task::Vm {
            domain: definition.name.parse()?,
            kind,
        },
    )
}

/// Backend-selected boot identities must change together with root/store state.
fn boot_feature(name: &str) -> bool {
    matches!(
        name,
        "airlock-system-source"
            | "airlock-root-source"
            | "airlock-root-artifact"
            | "airlock-store-source"
            | "airlock-store-mode"
            | "airlock-store-generation"
            | "airlock-store-closure-hash"
            | "airlock-store-view-image"
            | "airlock-store-view-backend"
            | "airlock-store-blob-device"
            | "airlock-store-blob-volume"
            | "airlock-store-blob-map"
            | "airlock-store-filesystem"
            | "airlock-store-mountpoint"
            | "airlock-store-device"
            | "airlock-store-read-only"
    )
}

/// Native device reconciliation cannot be delegated under deployment authority.
#[derive(Clone, Copy)]
enum Adapter {
    /// Storage/backend compatibility boundary.
    Backend,
    /// Device helper for boot/manual setup only.
    Devices,
}

/// Invoke a single-VM adapter and read its informational, run-specific receipt.
fn helper(
    runner: &Runner,
    definition: &Definition,
    _index: usize,
    deployment: Deployment<'_>,
    apply: bool,
    kind: Adapter,
    log: &Path,
) -> Result<Option<super::report::SetupReport>> {
    let mode = match kind {
        Adapter::Backend => "--backend-only",
        Adapter::Devices => "--devices-only",
    };
    ensure!(
        deployment.is_none(),
        "deployment backend and devices require typed requests"
    );
    if let Some(helper) = &definition.helper {
        manual(
            runner,
            &helper.program,
            &[
                if apply {
                    "--apply".into()
                } else {
                    "--plan".into()
                },
                "--topology".into(),
                helper.topology.clone(),
                mode.into(),
                definition.name.clone(),
            ],
            true,
        )?;
    }
    let list = log.join("rust-setup-helpers.jsonl");
    if !list.try_exists()? {
        return Ok(None);
    }
    let text = std::fs::read_to_string(list)?;
    let name: String =
        serde_json::from_str(text.lines().last().context("missing helper receipt name")?)?;
    ensure!(
        !name.contains('/') && name != "." && name != "..",
        "invalid helper receipt path"
    );
    Ok(Some(crate::state::read(
        &log.join(name).join("setup-config.json"),
    )?))
}

/// Observe one setting, then dispatch only the immutable setting selected by the gate.
fn reconcile_setting(
    runner: &Runner,
    definitions: &[Definition],
    selection: configuration::Selection,
    deployment: Deployment<'_>,
    apply: bool,
    log: &Path,
) -> Result<()> {
    let definition = &definitions[selection.domain];
    let values = match selection.kind {
        Kind::Property => &definition.properties,
        Kind::Feature => &definition.features,
        Kind::Service => &definition.services,
    };
    let setting = &values[selection.setting];
    let program = match selection.kind {
        Kind::Property => "qvm-prefs",
        Kind::Feature => "qvm-features",
        Kind::Service => "qvm-service",
    };
    if matches!(selection.kind, Kind::Property)
        && setting.name == "netvm"
        && !["none", "None", ""].contains(&setting.value.as_str())
        && apply
    {
        let registered = runner.text(
            "qvm-ls",
            &["--raw-data", "--fields", "NAME", "--no-spinner"],
        )?;
        if !registered.lines().any(|name| name == setting.value) {
            ensure!(
                !definitions.iter().any(|d| d.name == setting.value),
                "declared NetVM is missing"
            );
            super::report::append(
                log,
                "rust-vm-actions.jsonl",
                &serde_json::json!({"type":"domain-pref","action":"defer","domain":definition.name,"field":"netvm","value":setting.value,
                "reason":"external NetVM does not exist yet; create the stock Qubes domain and rerun setup-config"}),
            )?;
            return Ok(());
        }
    }
    let current = if apply {
        runner
            .text(program, &[&definition.name, &setting.name])
            .ok()
    } else {
        None
    };
    let property = matches!(selection.kind, Kind::Property)
        && matches!(setting.name.as_str(), "netvm" | "guivm");
    let explicit = !property || (apply && explicit_property(&definition.name, &setting.name)?);
    if let Some((authority, record, _)) = deployment {
        let raw = runner.text(
            "qvm-ls",
            &["--raw-data", "--fields", "NAME,STATE", "--no-spinner"],
        )?;
        let rows = raw
            .lines()
            .map(|row| row.split_once('|').context("invalid VM power observation"))
            .collect::<Result<Vec<_>>>()?;
        let mut matching = rows.iter().filter(|(name, _)| *name == definition.name);
        let (name, power) = *matching.next().context("missing VM power observation")?;
        ensure!(matching.next().is_none(), "duplicate VM power observation");
        let kind = selection.kind;
        if let Some(request) = authority.configuration_setting(
            record,
            selection,
            &configuration::SettingObservation {
                name,
                current: current.as_deref(),
                explicit,
                power: airlock_deployment_core::inventory::PowerState::classify(power),
            },
        )? {
            runner.setting_deployment(request)?;
            event(
                log,
                event_kind(kind),
                "set",
                definition,
                &setting.name,
                &setting.value,
                false,
            )?;
        }
    } else if !configuration::value_matches(&setting.value, current.as_deref()) || !explicit {
        manual(
            runner,
            program,
            &[
                definition.name.clone(),
                setting.name.clone(),
                setting.value.clone(),
            ],
            apply,
        )?;
        let restart = apply
            && runner
                .text(
                    "qvm-ls",
                    &["--raw-data", "--fields", "NAME,STATE", "--no-spinner"],
                )?
                .lines()
                .any(|line| line == format!("{name}|Running", name = definition.name));
        event(
            log,
            event_kind(selection.kind),
            "set",
            definition,
            &setting.name,
            &setting.value,
            restart,
        )?;
    }
    Ok(())
}

/// Missing XML does not establish that a matching connection override is explicit.
fn explicit_property(name: &str, property: &str) -> Result<bool> {
    let path = std::env::var_os("AIRLOCK_QUBES_XML")
        .map(PathBuf::from)
        .unwrap_or_else(|| "/var/lib/qubes/qubes.xml".into());
    if !path.try_exists()? {
        return Ok(false);
    }
    super::xml::explicit(&path, Some(&name.parse()?), property)
}

/// Manual/boot setup must never reuse a runner that is executing a deployment.
fn manual(runner: &Runner, program: &str, args: &[String], apply: bool) -> Result<()> {
    runner.require_manual_setup()?;
    println!("+ {program} {arguments}", arguments = args.join(" "));
    if apply {
        let mut env = vec![(
            "AIRLOCK_SETUP_RUN_ID".into(),
            std::env::var("AIRLOCK_SETUP_RUN_ID")
                .unwrap_or_else(|_| std::process::id().to_string())
                .into(),
        )];
        if let (Some(mode), Some(domain)) = (args.get(3), args.get(4))
            && matches!(mode.as_str(), "--backend-only" | "--devices-only")
        {
            let root = std::env::var_os("AIRLOCK_LOG_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| "/var/log/airlock".into());
            env.push((
                "AIRLOCK_LOG_DIR".into(),
                super::report::helper_directory(&root, domain, mode)?.into_os_string(),
            ));
            // Preserve legacy/manual staging for compatibility helpers. Checked boot
            // selections use the in-process typed backend path instead of this environment.
            // This remains a manual/boot path, not deployment authorization.
            if mode == "--backend-only"
                && let Some(staged) = std::env::var_os("AIRLOCK_STAGED_GENERATIONS")
            {
                env.push(("AIRLOCK_STAGED_GENERATIONS".into(), staged));
            }
        }
        let output = runner.run(
            program,
            &args.iter().map(OsString::from).collect::<Vec<_>>(),
            Duration::from_secs(600),
            &env,
        )?;
        if !output.is_empty() {
            println!("{output}");
        }
    }
    Ok(())
}

/// Match the existing public setup action families.
fn event_kind(kind: Kind) -> &'static str {
    match kind {
        Kind::Property => "domain-pref",
        Kind::Feature => "domain-feature",
        Kind::Service => "domain-service",
    }
}

/// Record observed/predicted configuration changes separately from durable authority.
fn event(
    directory: &Path,
    kind: &str,
    action: &str,
    definition: &Definition,
    field: &str,
    value: &str,
    restart: bool,
) -> Result<()> {
    let mut action = serde_json::json!({"type":kind,"action":action,"domain":definition.name,"field":field,"value":value,"restart":restart});
    if restart {
        action["state"] = serde_json::json!("Running");
        action["reason"] = serde_json::json!(
            "domain is running; restart required for this change to fully take effect"
        );
    }
    super::report::append(directory, "rust-vm-actions.jsonl", &action)
}
