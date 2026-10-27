//! Validate every topology reference before configuration apply, including external NetVM capability.

use crate::process::Runner;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::Path};

/// Add a concrete reference while excluding the existing disabled and special endpoint spellings.
fn reference(
    references: &mut Vec<Value>,
    kind: &str,
    domain: Option<&str>,
    field: &str,
    value: &Value,
) {
    let target = match value {
        Value::Null => return,
        Value::String(value) => value.clone(),
        _ => value.to_string(),
    };
    if !["", "none", "None", "dom0", "@anyvm"].contains(&target.as_str()) {
        references.push(json!({"kind":kind,"domain":domain,"field":field,"target":target}));
    }
}

/// Collect the reference semantics shared by candidate admission and application.
fn collect(topology: &Value) -> Result<Vec<Value>> {
    let mut references = Vec::new();
    let domains = topology["domains"]
        .as_object()
        .context("topology domains must be an object")?;
    for (name, domain) in domains {
        reference(
            &mut references,
            "netvm",
            Some(name),
            "netvm",
            &domain["netvm"],
        );
        reference(
            &mut references,
            "guivm",
            Some(name),
            "prefs.guivm",
            &domain["prefs"]["guivm"],
        );
        if domain["backend"]["type"]
            .as_str()
            .unwrap_or("qubes-template")
            == "qubes-template"
        {
            reference(
                &mut references,
                "template",
                Some(name),
                "template",
                domain
                    .get("template")
                    .filter(|value| !value.is_null())
                    .unwrap_or(&domain["backend"]["template"]),
            );
        }
        if let Some(assignments) = domain["devices"]
            .get("pci")
            .filter(|value| !value.is_null())
        {
            for (index, assignment) in assignments
                .as_array()
                .context("PCI assignments must be an array")?
                .iter()
                .enumerate()
            {
                reference(
                    &mut references,
                    "device-backend",
                    Some(name),
                    &format!("devices.pci[{index}].backend"),
                    &assignment["backend"],
                );
            }
        }
    }
    if let Some(prefs) = topology["prefs"].as_object() {
        for (name, value) in prefs {
            if [
                "clockvm",
                "default_dispvm",
                "default_netvm",
                "default_guivm",
                "default_template",
                "management_dispvm",
                "updatevm",
            ]
            .contains(&name.as_str())
            {
                reference(&mut references, "global-pref", None, name, value);
            }
        }
    }
    if let Some(rules) = topology["qrexec_policy"]
        .get("rules")
        .filter(|value| !value.is_null())
    {
        for (index, rule) in rules
            .as_array()
            .context("policy rules must be an array")?
            .iter()
            .enumerate()
        {
            reference(
                &mut references,
                "qrexec-source",
                None,
                &format!("qrexec_policy.rules[{index}].source"),
                &rule["source"],
            );
            reference(
                &mut references,
                "qrexec-target",
                None,
                &format!("qrexec_policy.rules[{index}].target"),
                &rule["target"],
            );
        }
    }
    Ok(references)
}

/// Save a compatibility observation report, never treating it as deployment authority.
fn report(
    output: &Path,
    topology: &Path,
    references: &[Value],
    existing: &[String],
    missing: &[Value],
    reason: &str,
) -> Result<()> {
    crate::setup_config::report::save(
        output,
        &json!({"schema":"airlock.domain-references.v1", "status":if missing.is_empty() {"passed"} else {"failed"}, "reason":reason, "topology":topology, "references":references, "existing_domains":existing, "missing":missing}),
    )
}

/// Record one unusable external-network observation with its expected value.
fn problem(
    missing: &mut Vec<Value>,
    kind: &str,
    domain: Option<&str>,
    field: &str,
    target: &str,
    observation: (&str, &str),
    reason: &str,
) {
    let (value, expected) = observation;
    missing.push(json!({"kind":kind,"domain":domain,"field":field,"target":target,"value":value,"expected":expected,"reason":reason}));
}

/// Check declared and external identities, then check external providers' forwarding capability.
pub(super) fn validate(topology_path: &Path, output: &Path) -> Result<()> {
    let topology: Value = crate::state::configuration(topology_path)?;
    let references = collect(&topology)?;
    if references.is_empty() {
        return report(
            output,
            topology_path,
            &references,
            &[],
            &[],
            "topology has no domain references",
        );
    }
    let runner = Runner::default();
    let observed = runner.text(
        "qvm-ls",
        &["--raw-data", "--fields", "NAME", "--no-spinner"],
    );
    let observed = match observed {
        Ok(value) => value,
        Err(error) => {
            report(
                output,
                topology_path,
                &references,
                &[],
                &references,
                "cannot query existing Qubes domains",
            )?;
            return Err(
                error.context("cannot query existing Qubes domains for reference validation")
            );
        }
    };
    let existing = observed
        .lines()
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let mut candidate = topology["domains"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    if let Some(templates) = topology["templates"].as_object() {
        candidate.extend(templates.keys().cloned());
    }
    let mut known = candidate.clone();
    known.extend(existing.iter().cloned());
    let mut missing = references
        .iter()
        .filter(|reference| !known.contains(reference["target"].as_str().unwrap()))
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        report(
            output,
            topology_path,
            &references,
            &existing,
            &missing,
            "topology references missing domains",
        )?;
        anyhow::bail!("topology references missing domains");
    }
    let external = references
        .iter()
        .filter(|reference| {
            reference["kind"] == "netvm"
                || (reference["kind"] == "global-pref" && reference["field"] == "default_netvm")
        })
        .map(|reference| reference["target"].as_str().unwrap())
        .filter(|name| !candidate.contains(*name))
        .collect::<BTreeSet<_>>();
    for name in external {
        let provides = runner
            .text("qvm-prefs", &[name, "provides_network"])
            .unwrap_or_default();
        if !["True", "true", "1"].contains(&provides.as_str()) {
            problem(
                &mut missing,
                "network-capability",
                None,
                "provides_network",
                name,
                (&provides, "true"),
                "external NetVM does not provide network",
            );
        }
        if name == "sys-firewall" {
            let upstream = runner
                .text("qvm-prefs", &[name, "netvm"])
                .unwrap_or_default();
            if upstream != "sys-net" {
                problem(
                    &mut missing,
                    "stock-network-chain",
                    Some(name),
                    "netvm",
                    "sys-net",
                    (&upstream, "sys-net"),
                    "stock sys-firewall is not routed through sys-net",
                );
            }
            if !existing.iter().any(|name| name == "sys-net") {
                missing.push(json!({"kind":"stock-network-chain","domain":"sys-firewall","field":"netvm","target":"sys-net","reason":"stock sys-firewall upstream sys-net is missing"}));
                continue;
            }
            let provides = runner
                .text("qvm-prefs", &["sys-net", "provides_network"])
                .unwrap_or_default();
            if !["True", "true", "1"].contains(&provides.as_str()) {
                problem(
                    &mut missing,
                    "stock-network-chain",
                    Some("sys-net"),
                    "provides_network",
                    "sys-net",
                    (&provides, "true"),
                    "stock sys-net does not provide network",
                );
            }
            let upstream = runner
                .text("qvm-prefs", &["sys-net", "netvm"])
                .unwrap_or_default();
            if !["", "none", "None"].contains(&upstream.as_str()) {
                problem(
                    &mut missing,
                    "stock-network-chain",
                    Some("sys-net"),
                    "netvm",
                    "none",
                    (&upstream, "none"),
                    "stock sys-net should not be routed through another NetVM",
                );
            }
        }
    }
    report(
        output,
        topology_path,
        &references,
        &existing,
        &missing,
        if missing.is_empty() {
            "all referenced domains are declared by the candidate or exist in Qubes"
        } else {
            "topology references unusable network domains"
        },
    )?;
    ensure!(
        missing.is_empty(),
        "topology references unusable network domains"
    );
    Ok(())
}
