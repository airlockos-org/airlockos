//! Transfer built configurations through the existing dom0 admission policy.
//! Preparation reads a frozen closure; it never builds software or changes local pool state.

use airlock_nix_core::artifact::Source;
use clap::{Args, Parser, Subcommand};
use std::{ffi::OsString, path::PathBuf, process::ExitCode};

#[derive(Parser)]
struct Command {
    // Preparation or policy-controlled sending of one immutable configuration.
    #[command(subcommand)]
    operation: Operation,
}

#[derive(Subcommand)]
enum Operation {
    /// Receive generated source as data; never execute its Rust authoring program.
    UnpackSource {
        // Exact archive returned by the configuration validator.
        #[arg(long)]
        archive: PathBuf,
        // New directory published after every file has been verified.
        #[arg(long)]
        destination: PathBuf,
        // Source commit bound by the authenticated validation result.
        #[arg(long)]
        revision: airlock_nix_core::identity::GitRevision,
        // SHA-256 of the archive recorded by the validator.
        #[arg(long)]
        sha256: String,
    },
    Prepare(Input),
    Send {
        // Frozen configuration and review provenance to send.
        #[command(flatten)]
        source: Input,
        // Existing Qubes client providing the authenticated inter-VM channel.
        #[arg(long, default_value = "qrexec-client-vm")]
        qrexec_client: String,
        // Probe for an exact retained generation before sending inventory.
        #[arg(long)]
        reuse_generation: bool,
        // Protected candidate admission identifier issued by dom0.
        #[arg(long)]
        candidate_admission: Option<String>,
        // Cached union of path-info metadata for a whole-machine submission.
        #[arg(long)]
        path_info_file: Option<PathBuf>,
    },
}

#[derive(Args)]
struct Input {
    // VM whose configured software closure is being transferred.
    #[arg(long)]
    domain: String,
    // Logical NixOS system root included in the frozen closure.
    #[arg(long)]
    system: String,
    // Closure metadata containing complete logical store roots.
    #[arg(long)]
    closure_source: String,
    // Immutable guest boot-disk source associated with the software closure.
    #[arg(long, default_value = "")]
    root_source: String,
    // Qubes kernel associated with this configuration.
    #[arg(long, default_value = "")]
    kernel_name: String,
    // Reviewed committed source revision.
    #[arg(long)]
    source_revision: String,
    // Reviewed dependency-lock digest.
    #[arg(long)]
    lock_hash: String,
    // Physical location of package bytes on this builder.
    #[arg(long)]
    physical_store_root: Option<PathBuf>,
    // Nix executable used to query path metadata.
    #[arg(long)]
    nix: Option<String>,
    // Optional store URI containing the frozen closure.
    #[arg(long)]
    nix_store: Option<String>,
    // Cached metadata for exactly this artifact's store roots.
    #[arg(long)]
    path_info_json: Option<PathBuf>,
}

impl Input {
    fn source(
        self,
        path_info: Option<PathBuf>,
    ) -> Result<Source, Box<dyn std::error::Error + Send + Sync>> {
        let path = path_info.or(self.path_info_json);
        let info = path
            .map(std::fs::read)
            .transpose()?
            .map(|bytes| serde_json::from_slice(&bytes))
            .transpose()?;
        let physical = self
            .physical_store_root
            .or_else(|| std::env::var_os("AIRLOCK_ARTIFACT_PHYSICAL_STORE").map(PathBuf::from))
            .unwrap_or_else(|| {
                std::env::var_os("AIRLOCK_NIX_ROOT")
                    .filter(|p| p != "/")
                    .map(|p| PathBuf::from(p).join("nix/store"))
                    .unwrap_or_else(|| PathBuf::from("/nix/store"))
            });
        Ok(Source {
            domain: self.domain,
            system: self.system,
            closure_source: self.closure_source,
            root_source: self.root_source,
            kernel_name: self.kernel_name,
            source_revision: self.source_revision,
            lock_hash: self.lock_hash,
            physical_store_root: physical,
            nix: self
                .nix
                .or_else(|| std::env::var("AIRLOCK_ARTIFACT_NIX").ok())
                .unwrap_or_else(|| "nix".to_owned()),
            nix_store: self
                .nix_store
                .or_else(|| std::env::var("AIRLOCK_POOL_NIX_STORE").ok())
                .filter(|v| !v.is_empty()),
            path_info: info,
        })
    }
}

pub(crate) fn main_from(args: impl IntoIterator<Item = OsString>) -> ExitCode {
    let command = match Command::try_parse_from(args) {
        Ok(value) => value,
        Err(error) => {
            let _ = error.print();
            return ExitCode::from(if error.use_stderr() { 2 } else { 0 });
        }
    };
    let run = || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match command.operation {
            Operation::UnpackSource {
                archive,
                destination,
                revision,
                sha256,
            } => {
                airlock_nix_core::artifact::prepared::unpack(
                    &archive,
                    &destination,
                    &revision,
                    &sha256,
                )
                .map_err(|error| error.into_boxed_dyn_error())?;
            }
            Operation::Prepare(input) => {
                input
                    .source(None)?
                    .write(&mut std::io::stdout().lock())
                    .map_err(|e| e.into_boxed_dyn_error())?;
            }
            Operation::Send {
                source,
                qrexec_client,
                reuse_generation,
                candidate_admission,
                path_info_file,
            } => {
                let receipt = source
                    .source(path_info_file)?
                    .send(
                        &qrexec_client,
                        candidate_admission.as_deref(),
                        reuse_generation,
                    )
                    .map_err(|e| e.into_boxed_dyn_error())?;
                println!("{}", serde_json::to_string(&receipt)?);
            }
        }
        Ok(())
    };
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("airlock artifact: {error}");
            ExitCode::FAILURE
        }
    }
}
