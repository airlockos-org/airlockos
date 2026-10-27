//! Inspect explicit Qubes properties and perform the narrow admin calls needed during machine setup.
//! Qubes continues to own PCI inventory, labels and database writes.

mod policy;

pub(crate) mod backend;

pub(crate) mod devices;

mod run;

mod runtime;

pub(crate) mod selection;

mod status;

pub(crate) mod xml;

pub(crate) mod reconcile;

pub(crate) mod report;

use crate::qubes::{self, properties};
use airlock_nix_core::identity::GuestName;
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use std::path::PathBuf;

/// Operations used by the local dom0 setup script; none is exposed as a new RPC.
#[derive(Args)]
pub(crate) struct Request {
    // The exact read or label reconciliation requested by the setup program.
    #[command(subcommand)]
    action: Action,
}

/// Keep setup inspection separate from the welcome window's completion state.
#[derive(Subcommand)]
enum Action {
    /// Reconcile the complete declared setup or one explicitly selected compatibility phase.
    Run(run::Request),
    /// Validate and reconcile the topology-managed policy independently of bootstrap transport.
    Policy {
        /// Full topology whose rules must all validate before installation.
        #[arg(long)]
        topology: PathBuf,
        /// Informational rendered preview produced in either mode.
        #[arg(long)]
        rendered: PathBuf,
        /// Exact Airlock-owned policy path; unrelated existing policies are refused.
        #[arg(long)]
        target: PathBuf,
        /// Install changes and reload the existing policy daemon.
        #[arg(long)]
        apply: bool,
    },
    /// Combine transaction-local setup receipts without invoking privileged helpers.
    Finalize {
        // Fixed setup result produced by the current helper invocation.
        #[arg(long)]
        result: PathBuf,
    },
    /// Reconcile one declared VM under the explicit boot/manual setup policy.
    ConfigureDomain {
        // Full admitted topology used for reference interpretation and backend helpers.
        #[arg(long)]
        topology: PathBuf,
        // Existing setup script, restricted to per-VM backend and device entry modes.
        #[arg(long)]
        script: PathBuf,
        // Exact declared VM; no arbitrary command arguments are accepted here.
        domain: GuestName,
        // Apply changes; otherwise print the same intended operations without mutation.
        #[arg(long, conflicts_with = "plan")]
        apply: bool,
        // Explicit observation-only/manual planning mode.
        #[arg(long, conflicts_with = "apply")]
        plan: bool,
    },
    /// Print whether a property is explicitly present rather than inherited or defaulted.
    PropertyExplicit {
        // Existing Qubes database inspected without editing or initializing it.
        #[arg(long)]
        xml: PathBuf,
        // Restrict inspection to one VM; omit for global properties.
        #[arg(long)]
        domain: Option<GuestName>,
        // Exact upstream property name to look up.
        property: String,
    },
    /// List dom0 PCI ports whose first upstream interface is a network controller.
    NetworkPci,
    /// Create a declared custom label or verify its existing colour without changing it.
    EnsureLabel {
        // Supported Airlock label identity, independent of Qubes' numeric index.
        name: String,
        // Six hexadecimal RGB digits with the configuration's 0x prefix.
        color: String,
    },
}

/// Dispatch local setup operations without introducing control authority in any VM.
pub(crate) fn execute(request: Request) -> Result<()> {
    let mut call =
        |method, argument: &str, payload: &[u8]| qubes::setup_dom0(method, argument, payload);
    match request.action {
        Action::Run(request) => run::execute(request)?,
        Action::Policy {
            topology,
            rendered,
            target,
            apply,
        } => {
            let raw: serde_json::Value = crate::state::configuration(&topology)?;
            let paths = policy::Paths::new(&target, &rendered)?;
            let changed = policy::reconcile(&raw, &paths, apply)?;
            println!("{changed}");
        }
        Action::Finalize { result } => report::finalize(&result)?,
        Action::ConfigureDomain {
            topology,
            script,
            domain,
            apply,
            plan,
        } => {
            ensure!(apply || plan, "setup requires --apply or --plan");
            let raw: serde_json::Value = crate::state::configuration(&topology)?;
            let definitions = reconcile::definitions(
                &raw,
                script.to_str().context("invalid setup path")?,
                &topology,
            )?;
            ensure!(
                definitions
                    .iter()
                    .any(|definition| definition.name == domain.as_str()),
                "VM is not declared by the topology"
            );
            reconcile::apply(
                &crate::process::Runner::default(),
                &definitions,
                None,
                apply,
                Some(domain.as_str()),
            )?;
        }
        Action::PropertyExplicit {
            xml,
            domain,
            property,
        } => {
            let explicit = xml::explicit(&xml, domain.as_ref(), &property)?;
            println!("{explicit}");
        }
        Action::NetworkPci => {
            let reply = call("admin.vm.device.pci.Available", "", &[])?;
            for port in network_ports(std::str::from_utf8(&reply)?)? {
                println!("{port}");
            }
        }
        Action::EnsureLabel { name, color } => ensure_label(&name, &color, &mut call)?,
    }
    Ok(())
}

/// Select network ports from authoritative inventory without parsing translated descriptions.
fn network_ports(reply: &str) -> Result<Vec<String>> {
    let mut ports = Vec::new();
    for line in reply.lines().filter(|line| !line.is_empty()) {
        let (identity, text) = line
            .split_once(' ')
            .context("invalid Qubes PCI inventory")?;
        // Available identifies a port plus device identity; assignments use only the port.
        let port = identity
            .split(':')
            .next()
            .context("missing Qubes PCI port")?;
        qubes::pci::validate_port(port)?;
        let fields = properties(text)?;
        for (field, expected) in [
            ("port_id", port),
            ("backend_domain", "dom0"),
            ("devclass", "pci"),
        ] {
            ensure!(
                fields.get(field).is_none_or(|actual| actual == expected),
                "inconsistent Qubes PCI identity"
            );
        }
        let interfaces = fields.get("interfaces").map(String::as_str).unwrap_or("");
        ensure!(
            interfaces.len().is_multiple_of(7),
            "invalid Qubes interface encoding"
        );
        if interfaces.starts_with("p02") {
            ensure!(
                !ports.iter().any(|seen| seen == port),
                "duplicate network PCI port"
            );
            ports.push(port.to_owned());
        }
    }
    Ok(ports)
}

/// Refuse undeclared labels and colour changes before any mutating admin call.
fn ensure_label(
    name: &str,
    color: &str,
    call: &mut impl FnMut(&'static str, &str, &[u8]) -> Result<Vec<u8>>,
) -> Result<()> {
    let digits = color
        .strip_prefix("0x")
        .context("invalid managed label colour")?;
    ensure!(
        matches!(name, "khaki" | "light-gray")
            && digits.len() == 6
            && digits.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid managed custom label"
    );

    let labels = call("admin.label.List", "", &[])?;
    if std::str::from_utf8(&labels)?
        .lines()
        .any(|label| label == name)
    {
        let current = call("admin.label.Get", name, &[])?;
        let current = std::str::from_utf8(&current)?.trim();
        let current = current
            .strip_prefix('#')
            .or_else(|| current.strip_prefix("0x"));
        ensure!(
            current.is_some_and(|current| current.eq_ignore_ascii_case(digits)),
            "existing custom label colour differs; explicit reconciliation required"
        );
    } else {
        call("admin.label.Create", name, color.as_bytes())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
