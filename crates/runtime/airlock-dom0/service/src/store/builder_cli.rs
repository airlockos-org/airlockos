//! Frozen builder attachments retain dependencies of persistent writable outputs.
//! Physical predecessor pins are released only after a stopped-VM handoff confirms the exact successor.

use super::{builder, fs::*};
use anyhow::Result;
use clap::{Args, Subcommand};
use serde_json::Value;
use std::path::{Path, PathBuf};

/// Authenticated builder-base inspection or completed attachment handoff.
#[derive(Args)]
pub(crate) struct Request {
    // Exact base operation selected by the Qubes adapter or offline image constructor.
    #[command(subcommand)]
    operation: Operation,
}

#[derive(Subcommand)]
enum Operation {
    Volumes {
        // Physical pool used during image construction or runtime attachment.
        #[arg(long)]
        pool_root: PathBuf,
        // Installed pool location; omitted when physical and installed paths coincide.
        #[arg(long)]
        logical_root: Option<PathBuf>,
        // Qubes pool name assigned to the returned volumes.
        #[arg(long)]
        pool_name: String,
        // Builder role whose authenticated base is being attached.
        #[arg(long)]
        domain: String,
    },
    ReleasePredecessors {
        // Runtime pool whose predecessor pins are being handed off.
        #[arg(long)]
        pool_root: PathBuf,
        // Builder role which completed the stopped-VM attachment.
        #[arg(long)]
        domain: String,
        // Exact descriptor observed by the adapter before saving volume configuration.
        #[arg(long)]
        descriptor: PathBuf,
    },
}

pub(super) fn run(command: Request) -> Result<Value> {
    match command.operation {
        Operation::Volumes {
            pool_root,
            logical_root,
            pool_name,
            domain,
        } => builder::volume_configs(
            &pool_root,
            logical_root.as_deref().unwrap_or(&pool_root),
            &pool_name,
            &domain,
        ),
        Operation::ReleasePredecessors {
            pool_root,
            domain,
            descriptor,
        } => {
            ensure_pool(&pool_root)?;
            let _lock = PoolLock::acquire(&pool_root.join("admission.lock"))?;
            builder::release_predecessors(&pool_root, &domain, &request(&descriptor)?)
        }
    }
}

fn request(path: &Path) -> Result<Value> {
    if path == Path::new("-") {
        Ok(serde_json::from_reader(std::io::stdin().lock())?)
    } else {
        read(path)
    }
}
