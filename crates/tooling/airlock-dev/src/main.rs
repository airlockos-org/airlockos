//! Developer operations run on the external workstation, outside deployed VMs.

#![forbid(unsafe_code)]
mod deploy;

mod ctrl_artifact;

mod repository;

mod source;

mod transport;

mod support;

mod verification;

mod environment;

mod gc;

mod cleanup;

mod build_budget;

mod build_log;

mod usb_build_provision;

mod nested;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::{ffi::OsString, path::PathBuf, process::ExitCode};

#[derive(Parser)]
#[command(version, about)]
struct Args {
    // Parent checkout containing the separately committed machine repository.
    #[arg(long, global = true)]
    repository_root: Option<PathBuf>,
    // Explicit workstation operation; no command runs at installation or boot.
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Run a workstation build with one physical core excluded from its CPU affinity.
    BuildBudget {
        /// Build command and literal arguments, inherited by all its child processes.
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        arguments: Vec<OsString>,
    },
    /// Manage explicitly requested disposable nested VMs on this workstation.
    Nested {
        /// Live test operation; never runs as part of installation.
        #[command(subcommand)]
        command: nested::Action,
    },
    /// Run a native operation with the existing data-backed workstation environment.
    WithEnvironment {
        /// Native arguments forwarded unchanged after environment selection.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        arguments: Vec<OsString>,
    },
    /// Inspect or adapt the existing workstation environment without shell-owned policy.
    Environment {
        /// Requested environment compatibility helper.
        #[command(subcommand)]
        command: environment::Action,
    },
    /// Maintain only the guarded private Airlock store.
    Gc {
        /// Collection or root-refresh mode; deletion remains an explicit choice.
        #[arg(value_enum, default_value = "dry-run")]
        mode: gc::Mode,
    },
    /// Remove one explicit class of generated artifacts without invoking Nix GC.
    Clean {
        /// Generated artifact class or read-only size report.
        #[arg(value_enum, default_value = "usage")]
        mode: cleanup::Mode,
    },
    /// Verify the production durable-operation crate with the pinned Verus toolchain.
    Verify {
        // Tool provisioning is opt-in and never runs during quick tests or ordinary builds.
        #[arg(long)]
        prepare: bool,
    },
    /// Run Nix with the exact committed local machine submodule available.
    Nix {
        // Nix arguments forwarded unchanged after source selection.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        arguments: Vec<OsString>,
    },
    /// Check that the machine gitlink is reachable from the declared upstream main.
    CheckPublish,
    /// Reject USB image builds whose application pin differs from the committed workspace.
    CheckImageSource,
    /// Collect USB credentials, build as the current user, then provision without further prompts.
    UsbBuildProvision(usb_build_provision::Args),
    /// Explicitly prepare and verify the controller executable used by native tests.
    CtrlArtifact {
        // Build/record are explicit preparation; verify only inspects the existing artifact.
        #[command(subcommand)]
        command: ctrl_artifact::Action,
    },
    /// Prepare or transfer committed machine configuration and offline inputs.
    Source {
        // Source preparation never evaluates configuration or builds a system.
        #[command(subcommand)]
        command: source::Action,
    },
    /// Build or submit a reviewed deployment, or use explicit development repair.
    Deploy(deploy::Args),
    /// Plan or reload committed GUI styling without restarting a VM.
    GuiStyle(deploy::Style),
    /// Run the explicit admission/apply/rollback test in a disposable nested VM.
    PoolSmoke,
}

fn execute(args: Args) -> Result<u8> {
    let root = repository::root(args.repository_root.as_deref())?;
    match args.command {
        Action::BuildBudget { arguments } => build_budget::run(&root, &arguments),
        Action::Nested { command } => nested::execute(&root, command),
        Action::WithEnvironment { arguments } => {
            environment::Environment::load()?.run(&root, &arguments)
        }
        Action::Environment { command } => environment::execute(command),
        Action::Gc { mode } => {
            gc::execute(&root, mode)?;
            Ok(0)
        }
        Action::Clean { mode } => {
            cleanup::execute(&root, mode)?;
            Ok(0)
        }
        Action::Verify { prepare } => verification::run(&root, prepare),
        Action::Nix { arguments } => repository::nix(&root, &arguments),
        Action::CtrlArtifact { command } => {
            ctrl_artifact::execute(&root, command)?;
            Ok(0)
        }
        Action::CheckPublish => {
            repository::check_publish(&root)?;
            Ok(0)
        }
        Action::CheckImageSource => {
            repository::check_image_source(&root)?;
            Ok(0)
        }
        Action::UsbBuildProvision(args) => usb_build_provision::run(&root, args),
        Action::Source { command } => {
            source::execute(&root, command)?;
            Ok(0)
        }
        Action::Deploy(args) => deploy::execute(&root, args),
        Action::GuiStyle(args) => {
            deploy::style(&root, args)?;
            Ok(0)
        }
        Action::PoolSmoke => {
            deploy::pool_smoke(&root)?;
            Ok(0)
        }
    }
}

fn main() -> ExitCode {
    match execute(Args::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("airlock-dev: {error:#}");
            ExitCode::FAILURE
        }
    }
}
