//! Store commands share one native implementation across deployment and image construction.
//! Qubes-specific adapters translate upstream API calls at the boundary.

use anyhow::Result;
use clap::Subcommand;

/// Native storage operations, grouped by the resources and protocols they own.
#[derive(Subcommand)]
pub(crate) enum Command {
    /// Observe a build-time subprocess while preserving its standard streams.
    BuildProgress(
        /// Phase label and literal executable arguments.
        super::progress::Request,
    ),
    /// Read view definitions and filesystem accounting for upstream Qubes objects.
    QubesInspect,
    /// Access upstream Qubes objects in a supervised, short-lived native worker.
    #[cfg(feature = "qubes")]
    #[command(hide = true)]
    QubesObjects,
    /// Attach immutable store and builder volumes through upstream Qubes APIs.
    Domain(
        /// VM lifecycle request with explicit pool and boot-device bindings.
        Box<super::domain_cli::Request>,
    ),
    /// Inspect frozen builder bases or release predecessor pins after attachment.
    Builder(
        /// Builder-specific metadata and physical retention operation.
        super::builder_cli::Request,
    ),
    /// Prepare or authenticate image-seeded store metadata.
    Image(
        /// Validated image-store operation and its selected inputs.
        super::image_cli::Request,
    ),
    /// Manage immutable guest generations and their attached storage views.
    Pool(
        /// Validated generation, retention or physical-view operation.
        Box<super::pool_cli::Request>,
    ),
    /// Publish host views and maintain their independently bootable artifacts.
    Host(
        /// Validated host operation, including offline image targets.
        super::host_cli::Request,
    ),
    /// Receive built software over the policy-controlled artifact protocol.
    Artifact(
        /// Authenticated target and protected candidate identity supplied by the RPC handler.
        super::artifact_cli::Request,
    ),
}

/// Execute one operation while keeping artifact protocol output owned by its receiver.
pub(crate) fn execute(command: Command) -> Result<()> {
    let result = match command {
        Command::BuildProgress(request) => return super::progress::execute(request),
        #[cfg(feature = "qubes")]
        Command::QubesObjects => airlock_qubes::storage::execute(
            super::objects_request(crate::input_value("-")?)?,
            super::ObjectsPolicy,
        )?,
        Command::QubesInspect => super::qubes_inspect::run()?,
        Command::Domain(request) => super::domain_cli::run(*request)?,
        Command::Builder(request) => super::builder_cli::run(request)?,
        Command::Image(request) => super::image_cli::run(request)?,
        Command::Pool(request) => super::pool_cli::run(*request)?,
        Command::Host(request) => super::host_cli::run(request)?,
        Command::Artifact(request) => return super::artifact_cli::run(request),
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
