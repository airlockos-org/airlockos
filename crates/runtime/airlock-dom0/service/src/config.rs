//! Configuration transport and administrative compatibility commands through existing Qubes services.

mod references;

mod io;

mod archive;

mod candidate;

mod control;

mod build;

mod host;

mod apply;

mod inputs;

mod bootstrap;

mod assets;

mod status;

mod policy_paths;

use anyhow::Result;
use clap::{Args, Subcommand};
use std::path::PathBuf;

/// Local configuration entry points; existing RPC policy remains responsible for caller admission.
#[derive(Args)]
pub(crate) struct Request {
    /// Selected configuration protocol operation.
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Refresh static Qubes policy links while preserving the Airlock-owned rule file.
    PolicyPaths {
        /// Immutable bootstrap policy directory selected at installation.
        #[arg(long, default_value = "/etc/qubes/policy.d")]
        static_dir: PathBuf,
        /// Runtime policy directory owned by dom0.
        #[arg(long, default_value = "/var/lib/airlock/qubes-policy.d")]
        runtime_dir: PathBuf,
        /// Single managed policy filename preserved during refresh.
        #[arg(long, default_value = "90-airlock.policy")]
        managed_file: String,
    },
    /// Observe configuration, durable records and Qubes state without granting control authority.
    Status,
    /// Check that the selected host generation is running after reboot.
    BootVerify,
    /// Install Qubes kernel/template assets through the existing upstream installers.
    BootstrapAssets,
    /// Export the fixed configuration input set to staging and validator.
    ImportInputs,
    /// Initialize staging through the existing vault-current protocol.
    BootstrapCurrent,
    /// Apply the validated configuration through the existing staged administrative protocol.
    Apply(apply::Request),
    /// Apply the resolved host profile and explicitly declared service actions.
    Host {
        /// Resolved host contract selected by the existing apply pipeline.
        #[arg(long)]
        system: PathBuf,
    },
    /// Resolve only candidate-declared template, VM and host source descriptors.
    Resolve(build::Request),
    /// Dispatch one fixed configuration RPC operation under existing Qubes policy.
    Control {
        /// Selected read, validation, apply or administrative rollback operation.
        #[arg(value_enum)]
        operation: control::Action,
    },
    /// Validate a staged candidate through the offline validator and optionally archive it.
    Archive(archive::Request),
    /// Validate all concrete topology references before applying the candidate.
    References {
        /// Full evaluated topology supplied by the existing validator.
        #[arg(long)]
        topology: PathBuf,
        /// Structured observation report consumed by existing apply/archive results.
        #[arg(long)]
        output: PathBuf,
    },
}

/// Dispatch compatibility operations without introducing new transport or VM authority.
pub(crate) fn execute(request: Request) -> Result<()> {
    match request.action {
        Action::PolicyPaths {
            static_dir,
            runtime_dir,
            managed_file,
        } => policy_paths::execute(static_dir, runtime_dir, managed_file),
        Action::Status => {
            println!("{status}", status = status::observe()?);
            Ok(())
        }
        Action::BootVerify => status::boot_verify(),
        Action::BootstrapAssets => assets::execute(),
        Action::ImportInputs => inputs::execute(),
        Action::BootstrapCurrent => bootstrap::execute(),
        Action::Apply(request) => apply::execute(request),
        Action::Host { system } => host::execute(&system),
        Action::Resolve(request) => build::execute(request),
        Action::Control { operation } => control::execute(operation),
        Action::Archive(request) => archive::execute(request),
        Action::References { topology, output } => references::validate(&topology, &output),
    }
}
