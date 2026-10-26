//! Administrative pool commands expose native store operations with validated inputs.
//! Every mutation shares one admission lock, including attachment and reference changes.

use super::{
    fs::*,
    generations::{self, Admission},
    maintenance, records, views,
};
use anyhow::{Result, ensure};
use clap::{Args, Subcommand};
use serde_json::Value;
use std::path::PathBuf;

/// Parsed store request, validated by the application's single command parser.
#[derive(Args)]
pub(crate) struct Request {
    // Exact pool operation; parsing never evaluates or builds a Nix configuration.
    #[command(subcommand)]
    operation: Operation,
}

#[derive(Args)]
struct Pool {
    // Persistent pool whose manifests and segment files are being accessed.
    #[arg(long, default_value = "/var/lib/airlock/closure-store")]
    pool_root: PathBuf,
}

#[derive(Args)]
struct Generation {
    // Pool location shared by the requested domain and its generation.
    #[command(flatten)]
    pool: Pool,
    // Domain namespace, checked before constructing filesystem paths.
    #[arg(long)]
    domain: String,
    // Positive, never reused generation identity.
    #[arg(long)]
    generation: u64,
}

/// Validated machine references shared by collection and conditional automatic-pin release.
#[derive(Args)]
struct Protections {
    // Exact machine-journal or manifest references retained even when not selected or running.
    #[arg(long)]
    protect_generation: Vec<super::protection::GenerationPin>,
    // Effective unpinned sources retained independently of numeric generation freshness.
    #[arg(long)]
    protect_system: Vec<super::protection::SystemPin>,
}

impl Protections {
    /// Preserve every parsed coordinate when crossing into verified decisions.
    fn decode(self) -> Vec<airlock_deployment_core::retention::Protection> {
        super::protection::decode(self.protect_generation, self.protect_system)
    }
}

#[derive(Args)]
struct Identity {
    // Pool containing the candidate or retained view.
    #[command(flatten)]
    pool: Pool,
    // VM or builder namespace receiving the software view.
    #[arg(long)]
    domain: String,
    // Logical NixOS system store root.
    #[arg(long)]
    system: String,
    // Path to frozen closure metadata.
    #[arg(long)]
    closure_source: String,
    // Optional immutable boot-disk source identity.
    #[arg(long, default_value = "")]
    root_source: String,
    // Qubes kernel associated with this configuration.
    #[arg(long, default_value = "")]
    kernel_name: String,
    // Entity whose approval binds the incoming configuration.
    #[arg(long, default_value = "dom0")]
    approved_by: String,
    // Only the external-data EROFS format is supported.
    #[arg(long,default_value="erofs-objectmap",value_parser=["erofs-objectmap"])]
    view_backend: String,
}

#[derive(Args)]
struct Admit {
    // Optional committed predecessor whose authenticated additive index may be extended.
    #[arg(long)]
    previous_generation: Option<u64>,
    // Fixed configuration and approval identities.
    #[command(flatten)]
    identity: Identity,
    // Source of package bytes; defaults to the configured local Nix store.
    #[arg(long)]
    physical_store_root: Option<PathBuf>,
    // Rollover limit for append-only object segments.
    #[arg(long)]
    segment_target_bytes: Option<u64>,
    // Whether to trust admitted objects and verify only newly supplied roots.
    #[arg(long,default_value="nix-store",value_parser=["none","tree","nix-store","nix-store-trust","incremental"])]
    verify_mode: String,
    // Review source recorded beside the authenticated approver.
    #[arg(long, default_value = "")]
    approval_source: String,
    // Replace the current pointer only after the new generation commits.
    #[arg(long,default_value="true",action=clap::ArgAction::Set)]
    activate: bool,
    // Retain inactive generations until explicitly released.
    #[arg(long,default_value="true",action=clap::ArgAction::Set)]
    retain: bool,
    // Guest-visible metadata device.
    #[arg(long, default_value = "/dev/xvde")]
    store_device: String,
    // Guest-visible external-data device.
    #[arg(long, default_value = "/dev/xvdf")]
    store_blob_device: String,
    // Guest mountpoint served by the read-only view.
    #[arg(long, default_value = "/nix/store")]
    store_mountpoint: String,
}

#[derive(Subcommand)]
enum Operation {
    Admit(Admit),
    FindGeneration(Identity),
    DescribeGeneration(Generation),
    LoadGeneration(Generation),
    Switch(Generation),
    Rollback(Generation),
    AttachBlobView(Generation),
    DetachBlobView(Generation),
    RetireGeneration(Generation),
    ReleaseAutomatic {
        // Original generation whose admission pin may be released.
        #[command(flatten)]
        generation: Generation,
        // Original immutable protection set, rechecked under the pool lock.
        #[command(flatten)]
        protections: Protections,
    },
    SetRetention {
        // Generation whose explicit GC protection is being changed.
        #[command(flatten)]
        generation: Generation,
        // New retention policy, independent of current selection.
        #[arg(long,action=clap::ArgAction::Set)]
        retain: bool,
    },
    MarkRunning {
        // Generation attached to the running consumer.
        #[command(flatten)]
        generation: Generation,
        // Independent volume name holding a physical pin.
        #[arg(long)]
        volume: String,
    },
    ClearRunning {
        // Generation detached from the consumer.
        #[command(flatten)]
        generation: Generation,
        // Independent volume whose physical pin is released.
        #[arg(long)]
        volume: String,
    },
    ResolveRoot {
        // Pool retaining the immutable boot image.
        #[command(flatten)]
        pool: Pool,
        // Domain which admitted this root source.
        #[arg(long)]
        domain: String,
        // Exact logical root source bound by a committed generation.
        #[arg(long)]
        root_source: String,
        // Optional exact generation to disambiguate retained roots.
        #[arg(long)]
        generation: Option<u64>,
    },
    Status(Pool),
    Recover(Pool),
    Gc {
        // Pool whose unreferenced files can be reclaimed.
        #[command(flatten)]
        pool: Pool,
        // Most recent generations retained in addition to explicit pins.
        #[arg(long, default_value_t = 2)]
        keep_generations: usize,
        // Complete machine references transported from the checked collection pass.
        #[command(flatten)]
        protections: Protections,
    },
    Compact {
        // Pool in which verified fragments may be relocated.
        #[command(flatten)]
        pool: Pool,
        // Report a bounded plan without copying or deleting payloads.
        #[arg(long,default_value="false",action=clap::ArgAction::Set)]
        dry_run: bool,
        // Maximum live-byte utilization eligible for compaction.
        #[arg(long, default_value_t = 50)]
        threshold_percent: u64,
        // Maximum sealed segments processed in this invocation.
        #[arg(long, default_value_t = 1)]
        max_segments: usize,
        // Latest unpinned generations retained during liveness tracing.
        #[arg(long, default_value_t = 2)]
        keep_generations: usize,
        // Replacement segment rollover limit.
        #[arg(long)]
        segment_target_bytes: Option<u64>,
    },
}

pub(super) fn physical_store() -> PathBuf {
    std::env::var_os("AIRLOCK_NIX_ROOT")
        .filter(|root| root != "/")
        .map(|root| PathBuf::from(root).join("nix/store"))
        .unwrap_or_else(|| PathBuf::from("/nix/store"))
}

pub(super) fn target(value: Option<u64>) -> Result<u64> {
    let value = value
        .or(std::env::var("AIRLOCK_CLOSURE_STORE_SEGMENT_TARGET_BYTES")
            .ok()
            .filter(|s| !s.is_empty())
            .map(|s| s.parse())
            .transpose()?)
        .unwrap_or(SEGMENT_TARGET);
    ensure!(value >= 512, "segment target must be at least 512");
    Ok(value)
}

pub(super) fn run(command: Request) -> Result<Value> {
    let pool = match &command.operation {
        Operation::Admit(a) => &a.identity.pool,
        Operation::FindGeneration(a) => &a.pool,
        Operation::DescribeGeneration(g)
        | Operation::LoadGeneration(g)
        | Operation::Switch(g)
        | Operation::Rollback(g)
        | Operation::AttachBlobView(g)
        | Operation::DetachBlobView(g)
        | Operation::RetireGeneration(g) => &g.pool,
        Operation::ReleaseAutomatic { generation, .. }
        | Operation::SetRetention { generation, .. }
        | Operation::MarkRunning { generation, .. }
        | Operation::ClearRunning { generation, .. } => &generation.pool,
        Operation::ResolveRoot { pool, .. }
        | Operation::Gc { pool, .. }
        | Operation::Compact { pool, .. } => pool,
        Operation::Status(p) | Operation::Recover(p) => p,
    };
    let root = pool.pool_root.clone();
    ensure_pool(&root)?;
    let _lock = PoolLock::acquire(&root.join("admission.lock"))?;
    match command.operation {
        Operation::Admit(args) => {
            let id = args.identity;
            let previous = args
                .previous_generation
                .map(|generation| records::generation(&root, &id.domain, generation))
                .transpose()?;
            let physical = args.physical_store_root.unwrap_or_else(physical_store);
            let source = if id.closure_source.starts_with("/nix/store/") {
                physical.join(entry(&id.closure_source)?)
            } else {
                PathBuf::from(&id.closure_source)
            };
            Ok(serde_json::to_value(generations::admit(&Admission {
                pool: &root,
                domain: &id.domain,
                system: &id.system,
                source: &source,
                source_identity: &id.closure_source,
                root_source: &id.root_source,
                kernel: &id.kernel_name,
                physical: &physical,
                segment_target: target(args.segment_target_bytes)?,
                verification: &args.verify_mode,
                approved_by: &id.approved_by,
                approval_source: &args.approval_source,
                activate: args.activate,
                retain: args.retain,
                previous_index: previous.as_ref().map(|manifest| &manifest["store"]),
                device: &args.store_device,
                blob_device: &args.store_blob_device,
                mountpoint: &args.store_mountpoint,
            })?)?)
        }
        Operation::FindGeneration(id) => Ok(serde_json::to_value(generations::find(
            &root,
            &id.domain,
            &id.system,
            &id.closure_source,
            &id.root_source,
            &id.kernel_name,
            &id.approved_by,
        )?)?),
        Operation::LoadGeneration(g) => Ok(serde_json::to_value(generations::load(
            &root,
            &root,
            &g.domain,
            g.generation,
        )?)?),
        Operation::DescribeGeneration(g) => generations::describe(&root, &g.domain, g.generation),
        Operation::Switch(g) => generations::switch(&root, &g.domain, g.generation, false),
        Operation::Rollback(g) => generations::switch(&root, &g.domain, g.generation, true),
        Operation::AttachBlobView(g) => views::attach(&root, &g.domain, g.generation, true),
        Operation::DetachBlobView(g) => views::attach(&root, &g.domain, g.generation, false),
        Operation::RetireGeneration(g) => generations::retire(&root, &g.domain, g.generation),
        Operation::ReleaseAutomatic {
            generation: g,
            protections,
        } => generations::release_automatic(&root, &g.domain, g.generation, protections.decode()),
        Operation::SetRetention {
            generation: g,
            retain,
        } => generations::retention(&root, &g.domain, g.generation, retain),
        Operation::MarkRunning {
            generation: g,
            volume,
        } => records::running(&root, &g.domain, g.generation, &volume, true),
        Operation::ClearRunning {
            generation: g,
            volume,
        } => records::running(&root, &g.domain, g.generation, &volume, false),
        Operation::ResolveRoot {
            domain,
            root_source,
            generation,
            ..
        } => Ok(serde_json::to_value(generations::resolve_root(
            &root,
            &domain,
            &root_source,
            generation,
        )?)?),
        Operation::Status(_) => maintenance::status(&root),
        Operation::Recover(_) => super::segments::with_verification(|| maintenance::recover(&root)),
        Operation::Gc {
            keep_generations,
            protections,
            ..
        } => super::segments::with_verification(|| {
            maintenance::gc(&root, keep_generations, protections.decode())
        }),
        Operation::Compact {
            dry_run,
            threshold_percent,
            max_segments,
            keep_generations,
            segment_target_bytes,
            ..
        } => super::segments::with_verification(|| {
            maintenance::compact(
                &root,
                keep_generations,
                threshold_percent,
                max_segments,
                target(segment_target_bytes)?,
                dry_run,
            )
        }),
    }
}
