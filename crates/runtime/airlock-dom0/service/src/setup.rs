//! Record first-run completion in dom0; the welcome window accesses it only through restricted RPCs.

use crate::state;
use airlock_nix_core::state::{OperationKind, OperationOwner, StateStore};
use anyhow::{Context, Result, ensure};
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Subcommand)]
pub(crate) enum Action {
    /// Report whether first-run setup was completed without creating state.
    Status,
    /// Persist completion once, rejecting damaged or unsupported prior records.
    Complete,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Completion {
    // Exact version of the small persistent first-run record.
    schema: u8,
    // This file exists only after successful completion; false is invalid state.
    completed: bool,
}

fn status(path: &std::path::Path) -> Result<bool> {
    match state::optional::<Completion>(path)? {
        None => Ok(false),
        Some(value) => {
            ensure!(
                value.schema == 1 && value.completed,
                "invalid first-run setup state"
            );
            Ok(true)
        }
    }
}

pub(crate) fn execute(action: Action) -> Result<()> {
    let path = std::env::var_os("AIRLOCK_SETUP_STATE")
        .map(PathBuf::from)
        .unwrap_or_else(|| "/var/lib/airlock/setup/state.json".into());
    let complete = match action {
        Action::Status => status(&path)?,
        Action::Complete => {
            let parent = path.parent().context("setup state has no parent")?;
            state::directory(parent)?;
            let store = StateStore::initialize(parent)?;
            let _guard = store.try_operation(
                &"setup-completion".parse()?,
                OperationOwner::new(
                    "Airlock first-run setup".into(),
                    "persist the user's completed first-run setup".into(),
                    OperationKind::Maintenance,
                )?,
            )?;
            if !status(&path)? {
                state::save(
                    &path,
                    &Completion {
                        schema: 1,
                        completed: true,
                    },
                )?;
            }
            true
        }
    };
    println!("{}", if complete { "complete" } else { "incomplete" });
    Ok(())
}
