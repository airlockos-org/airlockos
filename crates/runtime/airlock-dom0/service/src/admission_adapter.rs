//! Keep unprivileged qrexec admission and the sudo receiver as separately checked boundaries.

use anyhow::{Result, ensure};
use clap::{Args, Subcommand};
use std::{env, os::unix::process::CommandExt, path::PathBuf, process::Command};

#[derive(Args)]
pub(crate) struct Request {
    /// Explicit installed side of the admission boundary.
    #[command(subcommand)]
    operation: Operation,
}

#[derive(Subcommand)]
enum Operation {
    /// Check authenticated RPC identity before invoking the exact sudo-authorized receiver.
    Handler {
        /// Controller fixed by the installed policy.
        #[arg(long)]
        caller: String,
        /// Permitted target names fixed by the installed policy.
        #[arg(long)]
        target: Vec<String>,
        /// Exact store-owned receiver authorized in sudoers.
        #[arg(long)]
        receiver: PathBuf,
    },
    /// Independently check the unprivileged arguments before accessing root-owned storage.
    Receive {
        /// Controller fixed by the privileged receiver's installed contract.
        #[arg(long)]
        caller: String,
        /// Allowed target names from the same declared admission policy.
        #[arg(long)]
        target: Vec<String>,
        /// Native storage service supplied as an immutable executable dependency.
        #[arg(long)]
        service: PathBuf,
        /// Select the existing incremental protocol rather than full artifact transfer.
        #[arg(long)]
        incremental: bool,
        /// Target and claimed controller, both checked against installed settings.
        #[arg(last = true, num_args = 2)]
        arguments: Vec<String>,
    },
}

pub(crate) fn execute(request: Request) -> Result<()> {
    match request.operation {
        Operation::Handler {
            caller,
            target,
            receiver,
        } => {
            let remote = env::var("QREXEC_REMOTE_DOMAIN").unwrap_or_default();
            let selected = env::var("QREXEC_SERVICE_ARGUMENT").unwrap_or_default();
            ensure!(
                !remote.is_empty() && remote == caller,
                "admission RPC caller is not authorized"
            );
            ensure!(
                !selected.is_empty() && target.contains(&selected),
                "admission RPC target is not permitted"
            );
            Err(Command::new("/run/wrappers/bin/sudo")
                .arg("-n")
                .arg(receiver)
                .arg(selected)
                .arg(remote)
                .exec()
                .into())
        }
        Operation::Receive {
            caller,
            target,
            service,
            incremental,
            arguments,
        } => {
            ensure!(
                arguments.len() == 2,
                "admission receiver requires target and caller"
            );
            ensure!(
                !caller.is_empty() && arguments[1] == caller,
                "admission receiver rejected caller"
            );
            ensure!(
                target.contains(&arguments[0]),
                "admission receiver rejected target"
            );
            Err(Command::new(service)
                .args([
                    "storage",
                    "artifact",
                    if incremental {
                        "receive-incremental"
                    } else {
                        "receive"
                    },
                    "--expected-domain",
                    &arguments[0],
                    "--approved-by",
                    &arguments[1],
                ])
                .exec()
                .into())
        }
    }
}
