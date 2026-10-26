//! Collect fresh read-only observations; only verified evidence can reach readiness publication.
//! External probes and topology/policy decoding remain trusted adapters, not formal health oracles.

use crate::{model::Topology, process::Runner};
use airlock_deployment_core::boot::acceptance::{
    AcceptedBoot, GenerationReady, GuestReady, Instance, Requirement, Scope, Service, ServiceReady,
};
use airlock_nix_core::identity::GuestName;
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{collections::BTreeSet, path::PathBuf, time::Duration};

/// Closed installed policy; missing or unrecognised policy cannot weaken readiness requirements.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Policy {
    // Closed wire version installed by the boot-supervisor module.
    schema: Schema,
    // Whether successful critical startup requires a usable graphical desktop.
    desktop: bool,
    // Explicit null disables input; omission is a damaged policy, not an exemption.
    #[serde(deserialize_with = "input_target")]
    input_target: Option<GuestName>,
}

#[derive(Deserialize)]
enum Schema {
    // Only the installed boot-readiness policy format is supported.
    #[serde(rename = "airlock.boot-readiness.v1")]
    V1,
}

/// Require this nullable field to be present; serde's default Option handling permits omission.
fn input_target<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> std::result::Result<Option<GuestName>, D::Error> {
    Option::deserialize(decoder)
}

impl Policy {
    /// Read the installed contract rather than accepting caller-provided exemption flags.
    pub(crate) fn read() -> Result<Self> {
        let path = std::env::var_os("AIRLOCK_BOOT_READINESS_POLICY")
            .map(PathBuf::from)
            .unwrap_or_else(|| "/etc/airlock/boot-readiness.json".into());
        // This is immutable NixOS configuration, whose /etc entry is a
        // generation symlink, rather than a mutable supervisor record.
        let value: Self = crate::state::configuration(&path)?;
        let Schema::V1 = value.schema;
        Ok(value)
    }
}

/// Acceptance resamples existing readiness; it does not spend another full startup polling budget.
fn probe(runner: &Runner, program: &str, args: &[&str]) -> Result<String> {
    runner.run(
        program,
        &args
            .iter()
            .map(std::ffi::OsString::from)
            .collect::<Vec<_>>(),
        Duration::from_secs(10),
        &[],
    )
}

/// Read a running guest's Xen identity without requesting startup or repair.
fn instance(runner: &Runner, boot: &str, name: &str) -> Result<Instance> {
    probe(runner, "qvm-check", &["--running", name])?;
    let xid = probe(runner, "qvm-ls", &["--raw-data", "--fields", "XID", name])?;
    ensure!(
        !xid.is_empty() && xid.bytes().all(|byte| byte.is_ascii_digit()),
        "invalid Xen identity for {name}"
    );
    let xid = xid.parse()?;
    ensure!(xid > 0, "guest {name} has the dom0 Xen identity");
    Ok(Instance {
        boot: boot.into(),
        domain: name.into(),
        xid,
    })
}

/// Invoke only fixed read-only health commands through the existing Qubes transport.
fn service(runner: &Runner, name: &str, kind: Service) -> Result<()> {
    match kind {
        Service::Input => crate::input::connect::check(runner, &name.parse()?)?,
        kind => {
            let command = match kind {
                Service::Desktop => {
                    "root:/run/current-system/sw/bin/airlock-vm-service boot-health desktop".into()
                }
                Service::Worker => crate::readiness::worker_probe(Some(name))
                    .context("unsupported worker identity")?,
                Service::Network => crate::readiness::PROVIDER_HEALTH.into(),
                Service::Input => unreachable!(),
            };
            runner.run(
                "qrexec-client",
                &["-d".into(), name.into(), command.into()],
                Duration::from_secs(15),
                &[],
            )?;
        }
    }
    Ok(())
}

/// Project effective requirements for a declared guest; worker roles cannot silently name another VM.
fn requirement(topology: &Topology, policy: &Policy, name: &GuestName) -> Result<Requirement> {
    let domain = topology
        .domains
        .get(name)
        .context("required readiness guest is undeclared")?;
    let role = domain
        .features
        .get("airlock-role")
        .and_then(serde_json::Value::as_str);
    Requirement::new(
        name.to_string(),
        domain.backend.system.source.to_string(),
        policy.desktop,
        policy.input_target.as_ref().map(GuestName::as_str),
        role,
        domain.prefs.get("provides_network") == Some(&serde_json::Value::Bool(true)),
    )
    .context("invalid boot requirement or worker role differs from guest identity")
}

/// Collect every required capability and then resample all instances before verified acceptance.
/// The ordered name set comes from the existing dependency planner, with installed desktop/input requirements.
pub(crate) fn observe(
    topology: &Topology,
    policy: &Policy,
    boot: &str,
    scope: Scope,
) -> Result<AcceptedBoot> {
    ensure!(
        scope != Scope::Desktop || policy.desktop,
        "this host has no guarded desktop"
    );
    // These dynamic fields feed selection/capability projection. Malformed values must
    // not fall through as disabled autostart, absent worker role or non-provider status.
    for domain in topology.domains.values() {
        for key in ["autostart", "provides_network"] {
            ensure!(
                domain
                    .prefs
                    .get(key)
                    .is_none_or(serde_json::Value::is_boolean),
                "invalid boot preference: {key}"
            );
        }
        ensure!(
            domain
                .features
                .get("airlock-role")
                .is_none_or(serde_json::Value::is_string),
            "invalid boot worker role"
        );
    }

    let mut names: BTreeSet<_> = if scope == Scope::Complete {
        crate::planning::plan(topology, topology, &BTreeSet::new(), &[], false)?
            .start
            .into_iter()
            .collect()
    } else {
        airlock_machine_core::boot::foreground_guests(topology)?
            .into_iter()
            .collect()
    };
    if policy.desktop {
        names.insert("sys-gui".parse()?);
    }
    if let Some(target) = &policy.input_target {
        names.insert(target.clone());
    }
    let requirements: Vec<_> = names
        .iter()
        .map(|name| requirement(topology, policy, name))
        .collect::<Result<_>>()?;
    let runner = Runner::default();
    let mut guests = Vec::new();
    for name in &names {
        let wanted = requirement(topology, policy, name)?;
        let before = instance(&runner, boot, name.as_str())?;
        let actual = if let Some(artifact) = topology.domains[name].backend.hermit() {
            crate::hermit::ready(name.as_str(), artifact, before.xid)?;
            topology.domains[name].backend.system.source.to_string()
        } else {
            probe(
                &runner,
                "qrexec-client",
                &["-d", name.as_str(), "user:readlink -f /run/current-system"],
            )?
        };
        let mut checked_services = Vec::new();
        for (required, kind) in [
            (wanted.desktop, Service::Desktop),
            (wanted.input, Service::Input),
            (wanted.worker, Service::Worker),
            (wanted.network, Service::Network),
        ] {
            if required {
                service(&runner, name.as_str(), kind)?;
                checked_services.push(kind);
            }
        }
        // One common observation window brackets generation and every successful service
        // probe. Reusing that immutable snapshot avoids extra Qubes calls per capability.
        let after = instance(&runner, boot, name.as_str())?;
        let generation = GenerationReady::check(&wanted.system, actual, before.snapshot(), &after)
            .context("guest generation or instance changed during boot acceptance")?;
        let services = checked_services
            .into_iter()
            .map(|kind| {
                ServiceReady::check(kind, before.snapshot(), &after)
                    .context("guest restarted during service probe")
            })
            .collect::<Result<Vec<_>>>()?;
        guests.push(
            GuestReady::check(wanted, generation, services)
                .context("missing or stale required guest capability")?,
        );
    }
    let current = names
        .iter()
        .map(|name| instance(&runner, boot, name.as_str()))
        .collect::<Result<Vec<_>>>()?;
    AcceptedBoot::check(boot.into(), scope, &requirements, &guests, &current)
        .context("boot readiness evidence is incomplete or stale")
}
