//! Read-only local inspection of saved jobs, reviews, deployment plans and locks.

use airlock_nix_core::{
    Error, Result,
    identity::JobId,
    job::JobSnapshot,
    review::{DeploymentPlan, ReviewRequest, ReviewResponse},
    state::{ResourceKey, StateStore, read_json},
};
use clap::{Parser, Subcommand};
use serde::Serialize;
use serde_json::json;
use std::{
    ffi::OsString,
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
};

#[derive(Parser)]
#[command(
    name = "airlock inspect",
    version,
    about = "Inspect Airlock Nix records locally. No build, approval grant, or deployment is performed."
)]
struct Args {
    // Requested subcommand and its validated command-line arguments.
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Inspect a controller snapshot; preserve approval separately from work status.
    Job {
        // Saved controller job JSON to validate and summarize.
        file: PathBuf,
        /// Check that this is the requested job, rather than a different record.
        #[arg(long)]
        request_id: Option<JobId>,
    },
    /// Validate the existing GUI request schema, source identities and scope.
    Review {
        // Source-bound review request JSON to inspect.
        file: PathBuf,
    },
    /// Validate a GUI response as data. This grants no approval authority.
    Response {
        // Human review response JSON to validate.
        file: PathBuf,
    },
    /// Inspect a bare deployment plan and its complete known VM impact.
    Plan {
        // Deployment-plan JSON whose effects should be summarized.
        file: PathBuf,
    },
    /// Observe a reserved store lock and verify its owner without acquiring it.
    Lock {
        // Existing state-store root to observe without acquiring exclusion.
        store: PathBuf,
        // Named operation whose current lock holder should be inspected.
        resource: ResourceKey,
        /// Inspect a record writer instead of a long-running operation.
        #[arg(long)]
        record: bool,
    },
}

fn inspect(command: Command) -> Result<serde_json::Value> {
    match command {
        Command::Job { file, request_id } => {
            let job: JobSnapshot = read_json(&file, 4 * 1024 * 1024)?;
            if request_id
                .as_ref()
                .is_some_and(|expected| expected != job.request_id())
            {
                return Err(Error::BindingMismatch {
                    field: "controller job ID",
                });
            }

            let feedback = job.submission_feedback();
            Ok(
                json!({"kind": "job", "record": job, "submission_feedback": feedback,
                "submission_exit_code": feedback.exit_code()}),
            )
        }
        Command::Review { file } => {
            let record: ReviewRequest = read_json(&file, 65536)?;
            Ok(json!({"kind": "review_request", "record": record}))
        }
        Command::Response { file } => {
            let record: ReviewResponse = read_json(&file, 65536)?;
            Ok(json!({"kind": "review_response", "record": record}))
        }
        Command::Plan { file } => {
            let record: DeploymentPlan = read_json(&file, 4 * 1024 * 1024)?;
            Ok(json!({"kind": "plan", "record": record,
                "affected_vms": record.affected_vms(), "reboot": record.reboot_requirement()}))
        }
        Command::Lock {
            store,
            resource,
            record,
        } => {
            let store = StateStore::open(&store)?;
            let observation = if record {
                store
                    .record::<serde_json::Value>(resource, 4 * 1024 * 1024)?
                    .lock_status()?
            } else {
                store.operation_status(&resource)?
            };

            Ok(json!({"kind": "lock", "observation": observation}))
        }
    }
}

fn print_json(value: &impl Serialize) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, value)?;
    stdout.write_all(b"\n")
}

fn respond(output: impl Serialize, code: ExitCode) -> ExitCode {
    if let Err(error) = print_json(&output) {
        if error.kind() == io::ErrorKind::BrokenPipe {
            return code;
        }

        eprintln!("airlock inspect: could not write response: {error}");
        return ExitCode::FAILURE;
    }
    code
}

pub(crate) fn main_from(args: impl IntoIterator<Item = OsString>) -> ExitCode {
    match inspect(Args::parse_from(args).command) {
        Ok(value) => respond(
            json!({"schema": "airlock.nix-inspection.v1", "authority": "local-inspection-only", "inspection": value}),
            ExitCode::SUCCESS,
        ),
        Err(error) => respond(error.report(), ExitCode::FAILURE),
    }
}
