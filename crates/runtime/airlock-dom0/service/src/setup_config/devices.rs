//! Reconcile declared PCI assignments and retain dom0's active recovery network route.

use super::runtime::Session;
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs};

/// Split human-supplied device lists while preserving first occurrence order.
fn words(value: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    value
        .split(|ch: char| ch.is_ascii_whitespace() || ch == ',')
        .filter(|word| !word.is_empty() && seen.insert((*word).to_owned()))
        .map(str::to_owned)
        .collect()
}

/// Identify PCI interfaces supporting dom0's current default route, or an explicit test override.
fn recovery_ports(mut command: impl FnMut(&str, &[&str]) -> Result<String>) -> Result<Vec<String>> {
    if let Ok(value) = std::env::var("AIRLOCK_DOM0_DEFAULT_ROUTE_PCI_DEVICES")
        && !value.is_empty()
    {
        return Ok(words(&value));
    }
    let routes = command("ip", &["-o", "route", "show", "default"])?;
    let mut ports = BTreeSet::new();
    for line in routes.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        for pair in fields.windows(2) {
            if pair[0] == "dev" && pair[1] != "lo" {
                let device = fs::canonicalize(format!(
                    "/sys/class/net/{interface}/device",
                    interface = pair[1]
                ));
                if let Ok(device) = device
                    && let Some(name) = device
                        .file_name()
                        .and_then(|name| name.to_str())
                        .and_then(|name| crate::qubes::pci::address(name).ok())
                {
                    ports.insert(name);
                }
            }
        }
    }
    crate::qubes::pci::recovery_ports(&ports.into_iter().collect::<Vec<_>>())
}

/// The conventional root provider, or an explicit opt-in provider, receives automatic network PCI.
fn automatic(domain: &str, definition: &Value) -> bool {
    definition["devices"]["pci"]
        .as_array()
        .is_none_or(Vec::is_empty)
        && (domain == "sys-net" || definition["features"]["airlock-auto-network-pci"] == "1")
        && definition["prefs"]["provides_network"] == true
        && definition["netvm"]
            .as_str()
            .is_none_or(|target| target.is_empty() || target.eq_ignore_ascii_case("none"))
}

/// Issue one exact upstream assignment, retaining the original mode and match semantics.
fn assign(session: &mut Session, domain: &str, assignment: &Value) -> Result<()> {
    let field = |key: &str| {
        assignment[key]
            .as_str()
            .with_context(|| format!("missing PCI {key} for {domain}"))
    };
    let backend = field("backend")?;
    let device = field("id")?;
    let mode = field("mode")?;
    let matching = field("match")?;
    let target = format!("{backend}:{device}");
    let options = match assignment.get("options") {
        None | Some(Value::Null) => Vec::new(),
        Some(value) => value
            .as_object()
            .context("PCI options must be an object")?
            .iter()
            .map(|(key, value)| {
                Ok(format!(
                    "{key}={value}",
                    value = match value {
                        Value::String(value) => value.clone(),
                        _ => value.to_string(),
                    }
                ))
            })
            .collect::<Result<Vec<_>>>()?,
    };
    if session.apply && matching == "port" {
        let current = session
            .command("qvm-device", &["pci", "list", "--assignments", backend])
            .unwrap_or_default();
        if current.lines().any(|line| {
            line.split_whitespace().next() == Some(&target)
                && line.contains(&format!("*{domain} ({mode}"))
                && options.iter().all(|option| line.contains(option))
        }) {
            return Ok(());
        }
    }
    let mut args = vec!["pci", "assign"];
    match mode {
        "auto-attach" => {}
        "ask-to-attach" => args.push("--ask"),
        "required" => args.push("--required"),
        _ => bail!("unsupported PCI assignment mode for {domain}: {mode}"),
    }
    match matching {
        "port-and-device" => {}
        "port" => args.push("--port"),
        "device" => args.push("--device"),
        _ => bail!("unsupported PCI assignment match mode for {domain}: {matching}"),
    }
    for option in &options {
        args.extend(["--option", option]);
    }
    args.extend([domain, &target]);
    session.change("qvm-device", &args)?;
    session.count("devices_changed")?;
    let value = format!("{target} mode={mode} match={matching}");
    session.action("domain-device", "assign", domain, "pci", &value)?;
    if session.apply && session.state(domain).is_ok_and(|state| state == "Running") {
        session.defer(domain, "domain-device", "pci", &value)?;
    }
    Ok(())
}

/// Apply explicit assignments or automatic network discovery; never silently replace an empty result.
pub(super) fn reconcile(session: &mut Session, domain: &str) -> Result<()> {
    let definition = session.topology["domains"][domain].clone();
    ensure!(
        definition.is_object(),
        "requested VM is not declared: {domain}"
    );
    let explicit = match definition["devices"].get("pci") {
        None | Some(Value::Null) => &[][..],
        Some(value) => value
            .as_array()
            .context("PCI devices must be an array")?
            .as_slice(),
    };
    let auto = automatic(domain, &definition);
    if session.apply && (!explicit.is_empty() || auto) {
        let names = session.command(
            "qvm-ls",
            &["--raw-data", "--fields", "NAME", "--no-spinner"],
        )?;
        ensure!(
            names.lines().any(|name| name == domain),
            "domain is missing before PCI assignment: {domain}"
        );
    }
    for assignment in explicit {
        assign(session, domain, assignment)?;
    }
    if auto {
        let devices = match std::env::var("AIRLOCK_DOM0_NETWORK_PCI_DEVICES") {
            Ok(value) if !value.is_empty() => words(&value),
            _ => words(&session.service(&["setup-config", "network-pci"])?),
        };
        let mut excluded = words(&std::env::var("AIRLOCK_SYS_NET_PCI_EXCLUDE").unwrap_or_default())
            .into_iter()
            .collect::<BTreeSet<_>>();
        if domain == "sys-net" {
            excluded.extend(recovery_ports(|program, args| {
                session.command(program, args)
            })?);
        }
        let devices = devices
            .into_iter()
            .filter(|device| !excluded.contains(device))
            .collect::<Vec<_>>();
        ensure!(
            !devices.is_empty(),
            "automatic network PCI assignment found no available dom0 network PCI devices"
        );
        for device in devices {
            assign(
                session,
                domain,
                &json!({"backend":"dom0","id":device,"mode":"required","match":"port","options":{}}),
            )?;
        }
    }
    Ok(())
}

/// Decode exact desired PCI rules before the deployment's intent is published.
pub(crate) fn definitions(
    topology: &Value,
) -> Result<Vec<airlock_deployment_core::devices::Definition>> {
    use airlock_deployment_core::devices::{Assignment, Definition, Matching, Mode, OptionValue};
    let domains = topology["domains"]
        .as_object()
        .context("topology domains must be an object")?;
    domains
        .iter()
        .map(|(name, domain)| {
            let _: airlock_nix_core::identity::GuestName = name.parse()?;
            let assignments = match domain["devices"].get("pci") {
                None | Some(Value::Null) => &[][..],
                Some(value) => value
                    .as_array()
                    .context("PCI declarations must be an array")?
                    .as_slice(),
            };
            let assignments = assignments
                .iter()
                .map(|a| {
                    let field = |key: &str| a[key].as_str().context("missing PCI assignment field");
                    let backend = field("backend")?;
                    ensure!(
                        backend == "dom0",
                        "reviewed PCI assignments require the physical dom0 backend"
                    );
                    let id = field("id")?;
                    let (port, identity) = id
                        .split_once(':')
                        .map_or((id, None), |(port, identity)| (port, Some(identity)));
                    crate::qubes::pci::validate_port(port)?;
                    let options = match a.get("options") {
                        None | Some(Value::Null) => Vec::new(),
                        Some(options) => options
                            .as_object()
                            .context("PCI options must be an object")?
                            .iter()
                            .map(|(key, value)| {
                                ensure!(
                                    !key.is_empty()
                                        && key.bytes().all(
                                            |b| b.is_ascii_alphanumeric() || b"_-".contains(&b)
                                        ),
                                    "invalid PCI option key"
                                );
                                let value = match value {
                                    Value::String(value) => value.clone(),
                                    _ => value.to_string(),
                                };
                                ensure!(
                                    value.is_ascii()
                                        && !value.bytes().any(|b| b.is_ascii_control()),
                                    "invalid PCI option value"
                                );
                                Ok(OptionValue {
                                    name: key.clone(),
                                    value,
                                })
                            })
                            .collect::<Result<Vec<_>>>()?,
                    };
                    // Match qvm-device's legacy ro option normalization before retaining the definition.
                    let mut options = options
                        .into_iter()
                        .map(|option| (option.name, option.value))
                        .collect::<std::collections::BTreeMap<_, _>>();
                    if let Some(ro) = options.remove("ro") {
                        let value = match ro.to_ascii_lowercase().as_str() {
                            "1" | "true" | "yes" => "yes",
                            "0" | "false" | "no" => "no",
                            _ => bail!("invalid read-only assignment option"),
                        };
                        options.insert("read-only".into(), value.into());
                    }
                    let options = options
                        .into_iter()
                        .map(|(name, value)| OptionValue { name, value })
                        .collect();
                    Ok(Assignment {
                        backend: backend.into(),
                        port: port.into(),
                        identity: identity.map(str::to_owned),
                        mode: match field("mode")? {
                            "auto-attach" => Mode::Auto,
                            "ask-to-attach" => Mode::Ask,
                            "required" => Mode::Required,
                            _ => bail!("unsupported PCI mode"),
                        },
                        matching: match field("match")? {
                            "port-and-device" => Matching::Exact,
                            "port" => Matching::Port,
                            "device" => Matching::Device,
                            _ => bail!("unsupported PCI matching rule"),
                        },
                        options,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let netvm = match domain.get("netvm") {
                None | Some(Value::Null) => String::new(),
                Some(value) => value
                    .as_str()
                    .context("NetVM must be a string")?
                    .to_lowercase(),
            };
            Ok(Definition {
                name: name.clone(),
                assignments,
                provides_network: domain["prefs"]["provides_network"] == true,
                auto_feature: domain["features"]["airlock-auto-network-pci"]
                    .as_str()
                    .unwrap_or("")
                    .into(),
                netvm,
                excludes: words(&std::env::var("AIRLOCK_SYS_NET_PCI_EXCLUDE").unwrap_or_default()),
            })
        })
        .collect()
}

/// Replace the reviewed deployment helper with typed, directly dispatched assignment requests.
/// Boot/manual setup keeps its existing compatibility policy and report format.
pub(crate) fn apply_deployment(
    runner: &crate::process::Runner,
    authority: &crate::coordinator::approval::DurableAuthorization,
    record: &crate::model::Record,
    index: usize,
    log: &std::path::Path,
) -> Result<()> {
    use airlock_deployment_core::{devices, inventory::PowerState};
    let definition = authority
        .device_definitions()
        .get(index)
        .context("missing checked device definition")?;
    if definition.assignments.is_empty() && !devices::is_automatic(definition) {
        return Ok(());
    }
    let snapshot = crate::qubes::pci::observe()?;
    let raw = runner.text(
        "qvm-ls",
        &["--raw-data", "--fields", "NAME,STATE", "--no-spinner"],
    )?;
    let mut rows = raw
        .lines()
        .map(|line| {
            line.split_once('|')
                .context("invalid device power inventory")
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|(name, _)| *name == definition.name);
    let (name, state) = rows.next().context("missing device power observation")?;
    ensure!(rows.next().is_none(), "duplicate device power observation");
    let routes = if definition.name == "sys-net" && devices::is_automatic(definition) {
        recovery_ports(|program, args| runner.text(program, args))?
    } else {
        Vec::new()
    };
    let observed = devices::Observation {
        name: name.into(),
        power: PowerState::classify(state),
        hardware: snapshot.devices,
        uses: snapshot.uses,
        recovery_routes: routes,
    };
    let mut selections = Vec::new();
    for (assignment, declaration) in definition.assignments.iter().enumerate() {
        let hardware = observed
            .hardware
            .iter()
            .find(|h| h.port == declaration.port)
            .context("declared PCI port missing from physical inventory")?;
        selections.push(authority.device_explicit(record, index, assignment, hardware, &observed)?);
    }
    if devices::is_automatic(definition) {
        for hardware in &observed.hardware {
            if devices::is_eligible(definition, hardware, &observed.recovery_routes) {
                selections.push(authority.device_automatic(record, index, hardware, &observed)?);
            }
        }
        ensure!(
            !selections.is_empty(),
            "automatic network PCI assignment found no eligible devices"
        );
    }

    // Complete ownership/eligibility and power checks precede this VM's first mutation.
    let mut requests = Vec::new();
    for selection in selections {
        if !crate::qubes::pci::assignment_current(&selection, &observed.uses) {
            requests.push(selection.permit(&observed).context(
                "PCI configuration change requires a halted VM with unchanged ownership",
            )?);
        }
    }
    for request in requests {
        let owner = request.owner().to_owned();
        let (backend, port, identity) = request.resource();
        let target = format!("{backend}:{port}:{identity}");
        crate::qubes::pci::assign(request, &observed.uses)?;
        super::report::append(
            log,
            "rust-vm-actions.jsonl",
            &json!({"type":"domain-device", "action":"assign", "domain":owner, "field":"pci", "value":target, "restart":false}),
        )?;
    }
    Ok(())
}
