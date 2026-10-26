//! Coordinate explicit setup phases while Qubes and the existing storage service retain control.

use super::{
    backend, devices, policy,
    runtime::{Session, path, text},
};
use anyhow::{Context, Result, ensure};
use clap::Args;
use serde_json::Value;
use std::{collections::BTreeSet, fs, path::PathBuf};

/// Compatibility command line used by installed setup units and durable deployment helpers.
#[derive(Args)]
pub(crate) struct Request {
    /// Installed launcher retained as the child-helper identity in common VM reconciliation.
    #[arg(long)]
    script: PathBuf,
    /// Read-only capability negotiation, before initializing logs or state.
    #[arg(long)]
    protocol: bool,
    /// Execute the declared changes through existing adapters.
    #[arg(long, conflicts_with = "plan")]
    apply: bool,
    /// Describe changes without executing mutating adapters.
    #[arg(long)]
    plan: bool,
    /// Decoded topology belonging to the selected machine generation.
    #[arg(long, default_value = "/etc/airlock/qubes-topology.json")]
    topology: PathBuf,
    /// Checked retained-generation selections for this exact topology; no environment fallback.
    #[arg(long, requires = "boot_selection_hash")]
    boot_selection: Option<PathBuf>,
    /// Digest from the invoking coordinator; modified records cannot downgrade to manual admission.
    #[arg(long, requires = "boot_selection")]
    boot_selection_hash: Option<airlock_nix_core::identity::LockHash>,
    /// Configure autostart VMs and their local NetVM dependencies.
    #[arg(long, conflicts_with = "deferred")]
    boot_critical: bool,
    /// Configure the remaining declared VMs after critical boot setup.
    #[arg(long)]
    deferred: bool,
    /// Prepare global policy, kernels, templates and labels only.
    #[arg(long, conflicts_with_all = ["finish_only", "backend_only", "devices_only"])]
    prepare_only: bool,
    /// Finish global connections and persist the combined receipts.
    #[arg(long, conflicts_with_all = ["backend_only", "devices_only"])]
    finish_only: bool,
    /// Reconcile only this VM's native backend under its caller's selected phase.
    #[arg(long, conflicts_with = "devices_only")]
    backend_only: Option<airlock_nix_core::identity::GuestName>,
    /// Reconcile only this VM's declared or automatic device assignments.
    #[arg(long)]
    devices_only: Option<airlock_nix_core::identity::GuestName>,
}

/// Resolve only declared local NetVM relationships; omitted/external/disabled references add no edge.
fn dependency<'a>(topology: &'a Value, name: &str) -> Option<&'a str> {
    topology["domains"][name]["netvm"]
        .as_str()
        .filter(|target| {
            !target.is_empty()
                && !target.eq_ignore_ascii_case("none")
                && topology["domains"].get(*target).is_some()
        })
}

/// Retain setup's provider-first NetVM ordering and boot-scope selection, independently of deployment planning.
pub(super) fn selected(topology: &Value, scope: &str) -> Result<Vec<String>> {
    let domains = topology["domains"]
        .as_object()
        .context("topology domains must be an object")?;
    let mut pending = domains.keys().cloned().collect::<Vec<_>>();
    for name in &pending {
        let _: airlock_nix_core::identity::GuestName = name.parse()?;
    }
    let mut ordered = Vec::<String>::new();
    if domains.contains_key("sys-net") && dependency(topology, "sys-net").is_none() {
        ordered.push("sys-net".into());
        pending.retain(|name| name != "sys-net");
    }
    while !pending.is_empty() {
        let before = pending.len();
        let mut next = Vec::new();
        for name in pending {
            if dependency(topology, &name)
                .is_none_or(|parent| ordered.iter().any(|name| name == parent))
            {
                ordered.push(name);
            } else {
                next.push(name);
            }
        }
        ensure!(
            next.len() < before,
            "declared domain NetVM dependency cycle: {next:?}"
        );
        pending = next;
    }
    if scope == "all" {
        return Ok(ordered);
    }
    let mut critical = domains
        .iter()
        .filter(|(_, definition)| definition["prefs"]["autostart"] == true)
        .map(|(name, _)| name.clone())
        .collect::<BTreeSet<_>>();
    loop {
        let before = critical.len();
        let parents = critical
            .iter()
            .filter_map(|name| dependency(topology, name).map(str::to_owned))
            .collect::<Vec<_>>();
        critical.extend(parents);
        if critical.len() == before {
            break;
        }
    }
    Ok(ordered
        .into_iter()
        .filter(|name| critical.contains(name) == (scope == "boot-critical"))
        .collect())
}

/// Domain-backed defaults must be assigned only after the declared VMs exist.
fn domain_default(name: &str) -> bool {
    matches!(
        name,
        "default_dispvm" | "default_guivm" | "default_netvm" | "updatevm"
    )
}

/// Reconcile one class of global settings, including explicit empty overrides.
fn globals(session: &mut Session, domain_backed: bool) -> Result<()> {
    let prefs = session.topology["prefs"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    for (key, value) in prefs {
        if domain_default(&key) != domain_backed {
            continue;
        }
        let value = text(&value)?;
        if session.apply
            && session
                .command("qubes-prefs", &[&key])
                .is_ok_and(|current| {
                    airlock_deployment_core::configuration::value_matches(&value, Some(&current))
                })
        {
            let xml = path("AIRLOCK_QUBES_XML", "/var/lib/qubes/qubes.xml");
            if !value.is_empty() || (xml.is_file() && super::xml::explicit(&xml, None, &key)?) {
                continue;
            }
        }
        session.change("qubes-prefs", &[&key, &value])?;
        session.count("prefs_changed")?;
        session.action("global-pref", "set", "", &key, &value)?;
    }
    Ok(())
}

/// Reject unresolved source descriptors before any policy, VM or storage mutations.
fn preflight(session: &Session) -> Result<()> {
    ensure!(
        session.topology["schema"] == "airlock.qubes-topology.v1",
        "unsupported topology schema"
    );
    let domains = session.topology["domains"]
        .as_object()
        .context("topology domains must be an object")?;
    let mut unresolved = Vec::new();
    for (name, domain) in domains {
        if domain["backend"]["type"] == "nix-closure" {
            for component in ["system", "kernel", "initrd", "modules", "root", "store"] {
                if !domain["backend"][component]["source_ref"].is_null() {
                    unresolved.push(format!("{name}.{component}"));
                }
            }
        }
    }
    ensure!(
        unresolved.is_empty(),
        "Nix-native domain source reference was not resolved before setup-config: {unresolved:?}"
    );
    Ok(())
}

/// Publish selected policy paths directly; the compatibility report is output, never execution input.
fn prepare_policy(
    session: &mut Session,
    reconcile: impl FnOnce(&Value, &policy::Paths, bool) -> Result<bool>,
) -> Result<()> {
    if reconcile(&session.topology, &session.policy_paths, session.apply)? {
        let target = session.policy_paths.target().to_owned();
        session.count("qrexec_policy_changed")?;
        session.action(
            "qrexec-policy",
            "reload",
            "",
            target
                .file_name()
                .and_then(|name| name.to_str())
                .context("policy filename")?,
            target.to_str().context("policy path")?,
        )?;
    }
    Ok(())
}

/// Prepare the reusable global resources and labels used by the selected VM scope.
fn prepare(session: &mut Session, domains: &[String]) -> Result<()> {
    preflight(session)?;
    prepare_policy(session, policy::reconcile)?;
    globals(session, false)?;
    let kernels = session.topology["kernels"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    for (name, kernel) in kernels {
        backend::kernel(
            session,
            "",
            &name,
            kernel["source"]
                .as_str()
                .context("kernel source is empty")?,
        )?;
    }
    let templates = session.topology["templates"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    for (name, template) in templates {
        ensure!(
            template["source_ref"]["type"]
                .as_str()
                .is_none_or(str::is_empty),
            "template source reference was not resolved before setup-config: {name}"
        );
        let names = session.command(
            "qvm-ls",
            &["--raw-data", "--fields", "NAME", "--no-spinner"],
        )?;
        if names.lines().any(|current| current == name) {
            continue;
        }
        ensure!(
            template["import"] == true,
            "template is missing and import is disabled: {name}"
        );
        let source = template["source"]
            .as_str()
            .filter(|source| !source.is_empty())
            .context("template source is empty")?;
        ensure!(
            PathBuf::from(source).join("root.img").is_file(),
            "template source root.img is missing: {source}"
        );
        let mut args = vec!["--really", "--keep-source", "--no-installed-by-rpm"];
        if template["skip_start"] != false {
            args.push("--skip-start");
        }
        args.extend(["post-install", &name, source]);
        session.change("qvm-template-postprocess", &args)?;
        session.count("templates_changed")?;
        session.action("template", "import", &name, "source", source)?;
    }
    for domain in domains {
        let definition = session.topology["domains"][domain].clone();
        if let Some(color) = definition["features"]["airlock-label-color"]
            .as_str()
            .filter(|value| !value.is_empty())
        {
            let label = definition["label"]
                .as_str()
                .context("missing custom label name")?;
            let service = path("AIRLOCK_DOM0_SERVICE", "airlock-dom0-service");
            session.change(
                service.to_str().context("service path")?,
                &["setup-config", "ensure-label", label, color],
            )?;
        }
    }
    Ok(())
}

/// Preserve the installed setup CLI while every decision and loop runs in native Rust.
pub(super) fn execute(request: Request) -> Result<()> {
    if request.protocol {
        ensure!(
            !request.apply
                && !request.plan
                && !request.prepare_only
                && !request.finish_only
                && request.backend_only.is_none()
                && request.devices_only.is_none(),
            "protocol query cannot execute setup"
        );
        println!("airlock.setup.v4");
        return Ok(());
    }
    ensure!(
        request.apply || request.plan,
        "setup requires --apply or --plan"
    );
    let scope = if request.boot_critical {
        "boot-critical"
    } else if request.deferred {
        "deferred"
    } else {
        "all"
    };
    let phase = if request.prepare_only {
        "prepare-only"
    } else if request.finish_only {
        "finish-only"
    } else if request.backend_only.is_some() {
        "backend-only"
    } else if request.devices_only.is_some() {
        "devices-only"
    } else {
        "all"
    };
    let persist = match std::env::var("AIRLOCK_SETUP_CONFIG_PERSIST_STATE")
        .as_deref()
        .unwrap_or("1")
    {
        "1" | "true" | "yes" => true,
        "0" | "false" | "no" => false,
        _ => anyhow::bail!("unsupported AIRLOCK_SETUP_CONFIG_PERSIST_STATE value"),
    };
    let mut session = Session::new(&request.topology, request.apply, scope, phase)?;
    let boot = request
        .boot_selection
        .as_ref()
        .map(|path| {
            super::selection::BootSetup::read(
                path,
                request
                    .boot_selection_hash
                    .as_ref()
                    .context("checked selection digest is missing")?,
                &session.topology,
            )
        })
        .transpose();
    let boot = match boot {
        Ok(boot) => boot,
        Err(error) => {
            // A rejected handoff must not leave an earlier successful setup receipt looking current.
            let failure = Err(error);
            session.finish(&failure)?;
            return failure;
        }
    };
    session.result.task = request
        .backend_only
        .as_ref()
        .map(|domain| super::report::tasks::Task::Vm {
            domain: domain.clone(),
            kind: super::report::tasks::Kind::Backend,
        })
        .or_else(|| {
            request
                .devices_only
                .as_ref()
                .map(|domain| super::report::tasks::Task::Vm {
                    domain: domain.clone(),
                    kind: super::report::tasks::Kind::Devices,
                })
        });
    let mut status =
        super::status::Display::new(scope, session.directory.join("setup-config.commands.log"));
    let result = (|| {
        status.show(
            1,
            "Checking the system",
            "Checking Xen, Qubes services, and the declared VMs.",
        );
        let capabilities =
            fs::read_to_string(path("AIRLOCK_XEN_CAPABILITIES", "/proc/xen/capabilities"))
                .unwrap_or_default();
        ensure!(
            capabilities
                .split_whitespace()
                .any(|value| value == "control_d"),
            "host is not a Xen control domain"
        );
        for service in [
            "qubes-db-dom0.service",
            "qubesd.service",
            "qubes-qrexec-policy-daemon.service",
        ] {
            session.command("systemctl", &["is-active", "--quiet", service])?;
        }
        ensure!(
            session.topology["schema"] == "airlock.qubes-topology.v1",
            "unsupported topology schema"
        );
        if PathBuf::from("/etc/airlock/gui-gpu.json").exists() {
            let topology = path(
                "AIRLOCK_GUI_GPU_CHECK_TOPOLOGY",
                request.topology.to_str().context("topology path")?,
            );
            let output = session.service(&[
                "gpu",
                "check",
                "--topology",
                topology.to_str().context("GPU topology path")?,
                "--phase",
                "bootstrap",
            ])?;
            fs::write(session.directory.join("gui-gpu-check.json"), output)?;
        }
        if let Some(domain) = &request.backend_only {
            ensure!(
                session.topology["domains"].get(domain.as_str()).is_some(),
                "requested VM is not declared: {domain}"
            );
            return match boot
                .as_ref()
                .map(|boot| boot.get(domain.as_str()))
                .transpose()?
                .flatten()
            {
                Some(selected) => {
                    backend::reconcile_selected(&mut session, domain.as_str(), selected)
                }
                None => backend::reconcile(&mut session, domain.as_str()),
            };
        }
        if let Some(domain) = &request.devices_only {
            return devices::reconcile(&mut session, domain.as_str());
        }
        let domains = selected(&session.topology, scope)?;
        if !request.finish_only {
            status.show(
                2,
                "Preparing system images",
                "Checking reusable boot files and VM templates.",
            );
            prepare(&mut session, &domains)?;
            super::report::tasks::prepared(&session.directory, &session.result)?;
        }
        if request.prepare_only {
            return Ok(());
        }
        if !request.finish_only {
            for (index, domain) in domains.iter().enumerate() {
                status.show(
                    3,
                    &format!(
                        "VM {index} of {total}: {domain}",
                        index = index + 1,
                        total = domains.len()
                    ),
                    "Checking the VM and applying its configuration.",
                );
                if let Some(selected) = boot
                    .as_ref()
                    .map(|boot| boot.get(domain))
                    .transpose()?
                    .flatten()
                {
                    // Checked boot backends stay in Rust; helper selection cannot be lost in an environment hop.
                    let definitions = super::reconcile::definitions(
                        &session.topology,
                        request.script.to_str().context("setup script path")?,
                        &request.topology,
                    )?;
                    super::reconcile::apply_boot(
                        &crate::process::Runner::default(),
                        &definitions,
                        request.apply,
                        domain,
                        selected,
                    )?;
                } else {
                    session.service(&[
                        "setup-config",
                        "configure-domain",
                        "--topology",
                        request.topology.to_str().context("topology path")?,
                        "--script",
                        request.script.to_str().context("setup script path")?,
                        domain,
                        if request.apply { "--apply" } else { "--plan" },
                    ])?;
                }
            }
        }
        status.show(
            4,
            "Saving settings",
            "Applying default VM connections and saving setup state.",
        );
        globals(&mut session, true)
    })();
    if let Err(error) = &result {
        status.failed(&format!("{error:#}"));
    }
    session.finish(&result)?;
    if result.is_ok() {
        if request.apply
            && !request.prepare_only
            && request.backend_only.is_none()
            && request.devices_only.is_none()
            && scope != "boot-critical"
            && persist
        {
            let state = path("AIRLOCK_SYSTEM_STATE_DIR", "/var/lib/airlock/system");
            fs::create_dir_all(&state)?;
            fs::copy(&request.topology, state.join("current-topology.json"))?;
            fs::copy(
                session.directory.join("setup-config.json"),
                state.join("current-setup.json"),
            )?;
        }
        status.complete();
        println!("{result}", result = serde_json::to_value(&session.result)?);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Missing, redirected or malformed policy diagnostics cannot change execution destinations.
    #[test]
    fn policy_preparation_uses_selected_paths_instead_of_diagnostics() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let topology = temporary.path().join("topology.json");
        fs::write(
            &topology,
            serde_json::to_vec(&json!({"schema":"airlock.qubes-topology.v1","domains":{}}))?,
        )?;
        let logs = temporary.path().join("logs");
        let mut session = Session::at(&topology, false, "all", "all", logs.clone())?;
        let target = temporary.path().join("selected.policy");
        let rendered = logs.join("selected.rendered");
        session.policy_paths = policy::Paths::new(&target, &rendered)?;
        for (file, preview) in [
            (None, None),
            (
                Some(json!("/wrong/redirect.policy")),
                Some(json!("/wrong/preview")),
            ),
            (Some(json!(false)), Some(json!({"malformed":true}))),
        ] {
            session.result.diagnostics.remove("qrexec_policy_file");
            session.result.diagnostics.remove("qrexec_policy_rendered");
            if let Some(file) = file {
                session
                    .result
                    .diagnostics
                    .insert("qrexec_policy_file".into(), file);
            }
            if let Some(preview) = preview {
                session
                    .result
                    .diagnostics
                    .insert("qrexec_policy_rendered".into(), preview);
            }
            let mut dispatched = false;
            prepare_policy(&mut session, |_, paths, apply| {
                assert_eq!(paths.target(), target);
                assert_eq!(paths.rendered(), rendered);
                assert!(!apply);
                dispatched = true;
                Ok(true)
            })?;
            assert!(dispatched);
            assert_eq!(
                session.result.live_actions.last().unwrap()["value"],
                json!(target)
            );
        }
        assert!(!target.exists());
        Ok(())
    }

    /// Boot-critical setup closes only local NetVM dependencies; deferred setup is its complement.
    #[test]
    fn setup_scopes_partition_provider_order() -> Result<()> {
        let topology = json!({"domains":{
            "app":{"prefs":{"autostart":true},"netvm":"sys-firewall"},
            "idle":{"prefs":{"autostart":false}},
            "sys-firewall":{"netvm":"sys-net"},
            "sys-net":{"netvm":null}
        }});
        let critical = super::super::report::tasks::required(
            &topology,
            super::super::report::Scope::BootCritical,
        )?;
        let deferred = super::super::report::tasks::required(
            &topology,
            super::super::report::Scope::Deferred,
        )?;
        // Both phases need their own global preparation; each selected VM contributes three tasks.
        assert_eq!(critical.len(), 10);
        assert_eq!(deferred.len(), 4);
        assert!(matches!(
            critical[0],
            super::super::report::tasks::Task::Preparation
        ));
        assert_eq!(
            selected(&topology, "all")?,
            ["sys-net", "idle", "sys-firewall", "app"]
        );
        assert_eq!(
            selected(&topology, "boot-critical")?,
            ["sys-net", "sys-firewall", "app"]
        );
        assert_eq!(selected(&topology, "deferred")?, ["idle"]);
        Ok(())
    }

    /// A local cycle is rejected even when none of its members is autostarted.
    #[test]
    fn setup_rejects_netvm_cycles() {
        assert!(
            selected(
                &json!({"domains":{"a":{"netvm":"b"},"b":{"netvm":"a"}}}),
                "all"
            )
            .is_err()
        );
    }
}
