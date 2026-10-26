//! Compare intended VM configurations and observed running state without activation.

use crate::model::*;
use crate::relationships::{Relationships, guests, strings};
use airlock_machine_planning::deployment::{Change, Configuration, SeedPlan};
use airlock_nix_core::identity::GuestName;
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// VM identities appearing in a dependency or observed-running set.
type Names = BTreeSet<GuestName>;

/// Match serde_json number equality: positive and negative floating zero compare equal.
struct EqualityFormatter;

impl serde_json::ser::Formatter for EqualityFormatter {
    fn write_f64<W: std::io::Write + ?Sized>(
        &mut self,
        writer: &mut W,
        value: f64,
    ) -> std::io::Result<()> {
        let value = if value == 0.0 { 0.0 } else { value };
        serde_json::ser::CompactFormatter.write_f64(writer, value)
    }
}

/// Encode complete typed values for verified equality without hashing or flattening them again.
/// Ordered maps retain all fields; the formatter preserves JSON's signed-zero equality.
fn configuration_value(value: &impl Serialize) -> Result<String> {
    let mut bytes = Vec::new();
    value.serialize(&mut serde_json::Serializer::with_formatter(
        &mut bytes,
        EqualityFormatter,
    ))?;
    Ok(String::from_utf8(bytes)?)
}

/// Resolve runtime dependencies using the same reference rules as machine authoring.
pub fn dependencies(t: &Topology, omit_display: bool) -> Result<BTreeMap<GuestName, Names>> {
    crate::relationships::Relationships::from(t).dependencies(omit_display)
}

/// Return dependency-first startup order, rejecting cycles among declared VMs.
pub fn ordered(t: &Topology) -> Result<Vec<GuestName>> {
    crate::relationships::Relationships::from(t).ordered()
}

fn pci_owner(t: &Topology) -> Result<Option<GuestName>> {
    let names: Vec<_> = t
        .domains
        .iter()
        .filter(|(n, d)| {
            ["usr-assistant", "sys-net"].contains(&n.as_str())
                && d.prefs.get("provides_network") == Some(&Value::Bool(true))
                && d.netvm.as_deref().is_none_or(str::is_empty)
                && (n.as_str() == "sys-net"
                    || d.features
                        .get("airlock-auto-network-pci")
                        .and_then(Value::as_str)
                        == Some("1"))
                && d.devices
                    .get("pci")
                    .and_then(Value::as_array)
                    .is_none_or(Vec::is_empty)
        })
        .map(|(n, _)| n.clone())
        .collect();
    ensure!(names.len() <= 1, "multiple automatic network PCI owners");
    Ok(names.into_iter().next())
}

/// Compute changed guests, ordered lifecycle effects, private-data transfers and reboot impact.
pub fn plan(
    old: &Topology,
    new: &Topology,
    running: &Names,
    retire: &[GuestName],
    retain_removed: bool,
) -> Result<Plan> {
    old.validate()?;
    new.validate()?;

    let removed: Names = old
        .domains
        .keys()
        .filter(|n| !new.domains.contains_key(*n))
        .cloned()
        .collect();
    let authorized: Names = retire.iter().cloned().collect();
    ensure!(
        authorized.is_subset(&removed),
        "retirement does not match removed VMs"
    );
    ensure!(
        retain_removed || removed.is_subset(&authorized),
        "VM removal requires explicit retirement"
    );

    let refs = dependencies(new, false)?;
    for (name, deps) in &refs {
        ensure!(
            deps.is_disjoint(&removed),
            "{name}: still depends on a removed VM"
        );
    }

    for v in new.prefs.values() {
        if let Some(s) = v.as_str() {
            ensure!(
                !removed.iter().any(|n| n.as_str() == s),
                "topology still references a removed VM"
            );
        }
    }

    if let Some(rules) = new.qrexec_policy.get("rules").and_then(Value::as_array) {
        for r in rules {
            for key in ["source", "target"] {
                if let Some(s) = r.get(key).and_then(Value::as_str) {
                    ensure!(
                        !removed.iter().any(|n| n.as_str() == s),
                        "policy references a removed VM"
                    );
                }
            }
        }
    }

    for (name, d) in &new.domains {
        if let Some(before) = old.domains.get(name) {
            ensure!(
                d.class_name == before.class_name
                    && d.template == before.template
                    && d.devices == before.devices
                    && d.backend.kind() == before.backend.kind()
                    && d.backend.state() == before.backend.state(),
                "{name}: domain class, devices or state changes require migration"
            );
            for (a, b) in [
                (&before.prefs, &d.prefs),
                (&before.features, &d.features),
                (&before.services, &d.services),
            ] {
                ensure!(
                    a.keys().all(|k| b.contains_key(k)),
                    "{name}: removing properties requires explicit reset values"
                );
            }
        }
    }

    for (a, b) in [
        (&old.prefs, &new.prefs),
        (&old.kernels, &new.kernels),
        (&old.templates, &new.templates),
    ] {
        ensure!(
            a.keys().all(|k| b.contains_key(k)),
            "removing topology defaults requires migration"
        );
    }

    // Serializing the complete values makes equality part of the verified decision,
    // rather than supplying unchecked changed/eligible flags. serde_json's default
    // ordered maps and the typed BTreeMaps provide stable field ordering.
    let universe: Names = old
        .domains
        .keys()
        .chain(new.domains.keys())
        .cloned()
        .collect();
    let rows = universe
        .iter()
        .map(|name| {
            Ok(Change {
                name: name.to_string(),
                before: old.domains.get(name).map(configuration_value).transpose()?,
                after: new.domains.get(name).map(configuration_value).transpose()?,
                autostart: new
                    .domains
                    .get(name)
                    .and_then(|d| d.prefs.get("autostart"))
                    .and_then(Value::as_bool),
                reconnect: old
                    .domains
                    .get(name)
                    .and_then(|d| d.features.get("airlock-gui-reconnect"))
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let before = Relationships::from(old);
    let after = Relationships::from(new);
    let planner = SeedPlan::new(
        Configuration {
            names: strings(&old.domains.keys().cloned().collect()),
            domains: before.declarations(&Names::new()),
            defaults: before.defaults(),
            globals: configuration_value(&(&old.kernels, &old.prefs))?,
        },
        Configuration {
            names: strings(&new.domains.keys().cloned().collect()),
            domains: after.declarations(&Names::new()),
            defaults: after.defaults(),
            globals: configuration_value(&(&new.kernels, &new.prefs))?,
        },
        strings(&universe),
        &rows,
        strings(running),
    )
    .map_err(|error| anyhow::anyhow!("invalid deployment planning inputs: {error:?}"))?;
    let changed: Names = guests(planner.changed().to_vec())?.into_iter().collect();
    let affected: Names = guests(planner.affected().to_vec())?.into_iter().collect();

    let mut result = Plan {
        configure: new.domains.keys().cloned().collect(),
        stage: changed
            .iter()
            .filter(|n| old.domains.get(*n).map(|d| &d.backend) != Some(&new.domains[*n].backend))
            .cloned()
            .collect(),
        stop: guests(planner.stop().context("VM dependency cycle")?)?,
        start: guests(planner.start().context("VM dependency cycle")?)?,
        changed: changed.into_iter().collect(),
        affected: affected.iter().cloned().collect(),
        retire: guests(planner.removed().to_vec())?,
        retained_undeclared: guests(planner.removed().to_vec())?,
        ..Plan::default()
    };

    let reconnect = guests(planner.reconnect())?;
    if !reconnect.is_empty() {
        result.gui_reconnect.insert("sys-gui".parse()?, reconnect);
    }

    if let (Some(a), Some(b)) = (pci_owner(old)?, pci_owner(new)?)
        && a != b
    {
        result.pci_handoff = Some(serde_json::json!({"from":a,"to":b}));
    }

    Ok(result)
}

/// Include domain declarations, dependency edges, defaults and RPC policy when protecting recovery data.
pub fn references_domain(topology: &Topology, name: &GuestName) -> Result<bool> {
    Ok(topology.domains.contains_key(name)
        || dependencies(topology, false)?
            .values()
            .any(|refs| refs.contains(name))
        || topology
            .prefs
            .values()
            .any(|v| v.as_str() == Some(name.as_str()))
        || topology
            .qrexec_policy
            .get("rules")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|r| {
                ["source", "target"]
                    .iter()
                    .any(|key| r.get(key).and_then(Value::as_str) == Some(name.as_str()))
            }))
}
