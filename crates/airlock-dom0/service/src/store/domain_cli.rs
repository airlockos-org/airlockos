//! Qubes attaches a metadata image and an external-data view to each guest.
//! These commands keep selection and attachment policy in Rust; a narrow bridge
//! translates the final configuration into upstream Qubes storage objects.

use super::{domain, fs::*};
use airlock_nix_core::{
    identity::GuestName,
    state::{OperationKind, OperationOwner, StateStore},
};
use anyhow::{Result, ensure};
use clap::{Args, Subcommand};
use serde_json::{Value, json};
use std::path::PathBuf;

/// Guest storage lifecycle operation, independent of deployment admission.
#[derive(Args)]
pub(crate) struct Request {
    // Selection, attachment or isolation check requested by the coordinator.
    #[command(subcommand)]
    operation: Operation,
}

/// One guest and its installed pool/device bindings; parsing does not open Qubes.
#[derive(Args)]
pub(super) struct Target {
    /// Existing Qubes VM whose boot volumes are being inspected.
    pub(super) domain: GuestName,
    /// Qubes pool receiving immutable metadata and external-data views.
    #[arg(
        long,
        env = "AIRLOCK_CLOSURE_STORE_POOL",
        default_value = "airlock-closure"
    )]
    pub(super) pool_name: String,
    /// Physical store root; this is also the installed pool path.
    #[arg(
        long,
        env = "AIRLOCK_CLOSURE_STORE_ROOT",
        default_value = "/var/lib/airlock/closure-store"
    )]
    pub(super) pool_root: PathBuf,
    /// Guest-visible metadata frontend; checked against upstream volume order.
    #[arg(long, default_value = "/dev/xvde")]
    pub(super) device: String,
    /// Guest-visible external-data frontend.
    #[arg(long, default_value = "/dev/xvdf")]
    pub(super) blob_device: String,
    /// Only the guest's canonical store mountpoint is supported.
    #[arg(long, default_value = "/nix/store", value_parser = ["/nix/store"])]
    pub(super) mountpoint: String,
}

/// Exact software and boot identity to reuse or admit before attaching volumes.
#[derive(Args)]
pub(super) struct Ensure {
    /// VM, pool and frontend binding shared with generation switching.
    #[command(flatten)]
    pub(super) target: Target,
    /// Frozen closure or prepared descriptor supplying the requested packages.
    pub(super) artifact: PathBuf,
    /// Source identity authenticated by the approved deployment.
    pub(super) source: String,
    // Only immutable shared closure views are supported.
    #[arg(long, default_value = "shared-closure", value_parser = ["shared-closure"])]
    pub(super) mode: String,
    /// Exact NixOS system whose root/kernel must match any reusable generation.
    #[arg(long)]
    pub(super) system: String,
    /// Immutable guest boot-disk source identity.
    #[arg(long)]
    pub(super) root: String,
    /// Qubes kernel installed with this generation.
    #[arg(long)]
    pub(super) kernel: String,
    /// Exact retained generation requested by a checked deployment, when present.
    #[arg(long)]
    pub(super) generation: Option<u64>,
    /// Reviewed activation may attach retained or prepared generations without admitting bytes.
    #[arg(long)]
    pub(super) require_retained: bool,
    /// Object verification policy used only when admission is necessary.
    #[arg(long, env = "AIRLOCK_CLOSURE_STORE_VERIFY", default_value = "nix-store", value_parser = ["none", "tree", "nix-store", "nix-store-trust", "incremental"])]
    pub(super) verify_mode: String,
    /// Metadata/external-data layout understood by this runtime.
    #[arg(long, default_value = "erofs-objectmap", value_parser = ["erofs-objectmap"])]
    pub(super) view_backend: String,
}

#[derive(Subcommand)]
enum Operation {
    /// Describe image-time volumes without opening a Qubes database.
    ImageVolumes {
        // Installed VM and pool identity embedded in the image.
        #[command(flatten)]
        target: Target,
        // Authenticated image receipt, or '-' to read it from standard input.
        #[arg(long)]
        admission: PathBuf,
        // Physical image size when installed paths do not exist on the builder.
        #[arg(long)]
        metadata_size: u64,
    },
    /// Validate an offline Qubes snapshot and exact expected volume definitions.
    VerifySnapshot {
        // Image VM whose storage is being checked without contacting a daemon.
        domain: GuestName,
        // Snapshot, desired volumes and source identity from the image constructor.
        #[arg(long)]
        request: PathBuf,
    },
    /// Admit or reuse the exact boot identity, then attach it to a stopped VM.
    EnsureStore(
        /// Approved closure and complete boot identity to attach.
        Ensure,
    ),
    /// Attach an already committed generation without rebuilding it.
    SwitchStore {
        // VM and pool whose selected generation changes.
        #[command(flatten)]
        target: Target,
        // Positive retained generation; never inferred from a newer pointer.
        generation: u64,
    },
    /// Reject writable root/private volumes shared with another Qubes VM.
    VerifyNativeVolumes {
        // Existing StandaloneVM whose writable state must be independent.
        domain: GuestName,
    },
}

/// Execute a validated lifecycle request and return its machine-readable result.
pub(super) fn run(request: Request) -> Result<Value> {
    match request.operation {
        Operation::VerifyNativeVolumes { domain: name } => {
            domain::verify_native(&name)?;
            Ok(json!({"domain":name,"native_volume_isolation":"passed"}))
        }
        Operation::ImageVolumes {
            target,
            admission,
            metadata_size,
        } => Ok(serde_json::to_value(domain::shared_configs(
            &target,
            &serde_json::from_value(request_value(&admission)?)?,
            Some(metadata_size),
        )?)?),
        Operation::VerifySnapshot { domain, request } => {
            domain::verify_snapshot(&domain, &request_value(&request)?)?;
            Ok(json!({"domain":domain,"status":"passed"}))
        }
        Operation::EnsureStore(args) => {
            validate(&args.target)?;
            let root = domain::integration_root();
            ensure!(
                root.is_absolute(),
                "Qubes storage state root must be absolute"
            );
            mkdir_all(&root)?;
            let store = StateStore::initialize(&root)?;
            let _lock = store.try_operation(
                &"attachment".parse()?,
                OperationOwner::new(
                    format!("Storage setup for {}", args.target.domain),
                    "Attach the approved software and builder volumes".into(),
                    OperationKind::Maintenance,
                )?,
            )?;
            domain::restore_daemon(&root)?;
            Ok(serde_json::to_value(domain::ensure(&args)?)?)
        }
        Operation::SwitchStore { target, generation } => {
            validate(&target)?;
            ensure!(generation > 0, "invalid generation");
            let root = domain::integration_root();
            ensure!(
                root.is_absolute(),
                "Qubes storage state root must be absolute"
            );
            mkdir_all(&root)?;
            let store = StateStore::initialize(&root)?;
            let _lock = store.try_operation(
                &"attachment".parse()?,
                OperationOwner::new(
                    format!("Storage switch for {}", target.domain),
                    "Attach a retained immutable generation".into(),
                    OperationKind::Maintenance,
                )?,
            )?;
            domain::restore_daemon(&root)?;
            Ok(serde_json::to_value(domain::switch(&target, generation)?)?)
        }
    }
}

fn request_value(path: &std::path::Path) -> Result<Value> {
    if path == std::path::Path::new("-") {
        Ok(serde_json::from_reader(std::io::stdin().lock())?)
    } else {
        read(path)
    }
}

fn validate(target: &Target) -> Result<()> {
    component(&target.pool_name)?;
    ensure!(target.pool_root.is_absolute(), "pool root must be absolute");
    ensure_pool(&target.pool_root)
}
