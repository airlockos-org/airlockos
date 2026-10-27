//! Local configuration-role commands; existing Qubes policy and Unix permissions retain their boundaries.

mod io;

mod staging;

mod workspace;

mod vault;

mod inputs;

mod validator;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde::Deserialize;
use std::path::PathBuf;

/// Installed paths and tools shared by the existing configuration-role commands.
#[derive(Deserialize)]
struct Config {
    /// Unprivileged owner of the editable staging workspace and private-store imports.
    user: String,
    /// Editable repository populated only by staging operations.
    repo: PathBuf,
    /// Vault's independent archive repository.
    archive: PathBuf,
    /// Validation receipts and diagnostic logs within this VM.
    validation: PathBuf,
    /// Persistent import manifest directory within the writable private volume.
    inputs: PathBuf,
    /// Existing private Nix store root used for input imports.
    store: PathBuf,
    /// Mounted input directories exposed to configuration users.
    public_inputs: PathBuf,
    /// Initial machine-owned Rust candidate source tree.
    seed: PathBuf,
    /// Existing wrapper selecting this VM's private Nix evaluation environment.
    nix: PathBuf,
    /// VM's existing role, used only to select local staging refresh after import.
    role: String,
    /// Existing search path used for Rust authoring and input locking in configuration roles.
    staging_path: String,
}

/// Configuration operations available only with the local process's existing VM permissions.
#[derive(Args)]
pub(super) struct Request {
    /// Installed runtime paths; qrexec wrappers supply this immutable contract.
    #[arg(long)]
    config: PathBuf,
    /// Exact role operation selected by the existing installed command.
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Validate the editable worktree through the shared native validator implementation.
    StagingValidate,
    /// Prepare the validator receipt directory without evaluating any source.
    ValidatorInit,
    /// Import admitted source inputs into the existing private Nix store.
    InputsImport,
    /// Evaluate an inert candidate only within the existing validator role.
    Validate,
    /// Initialize or refresh a clean staging workspace.
    StagingInit,
    /// Initialize or repair the vault and its machine-owned initial baseline.
    VaultInit,
    /// Export the current archived source candidate.
    VaultExport,
    /// Archive a validated source candidate without evaluating its code.
    VaultCandidate,
    /// Archive one deployment evidence bundle with matching document identities.
    VaultDeployment,
    /// Export a clean staging commit as an inert bundle and manifest.
    StagingExport,
    /// Import vault-current without overwriting dirty or divergent work.
    StagingImport,
}

/// Read the installed contract and preserve the existing protocol-specific output stream.
pub(super) fn execute(request: Request) -> Result<()> {
    let config: Config = airlock_nix_core::state::read_json(&request.config, 1024 * 1024)
        .context("read configuration runtime paths")?;
    match request.action {
        Action::StagingValidate => staging::validate(&config, &request.config),
        Action::ValidatorInit => {
            std::fs::create_dir_all(
                io::path("AIRLOCK_CONFIG_VALIDATION_DIR", &config.validation).join("logs"),
            )?;
            Ok(())
        }
        Action::InputsImport => inputs::execute(&config, &request.config),
        Action::Validate => validator::execute(&config),
        Action::StagingInit => workspace::staging(&config),
        Action::VaultInit => vault::init(&config),
        Action::VaultExport => vault::export(&config),
        Action::VaultCandidate => vault::candidate(&config),
        Action::VaultDeployment => vault::deployment(&config),
        Action::StagingExport => staging::export(&config),
        Action::StagingImport => staging::import(&config),
    }
}
