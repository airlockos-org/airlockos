//! Restricted artifact receiver entry points for existing Qubes admission channels.
//! Every rejection is reported over the duplex protocol as well as local stderr.

use super::{artifacts, fs::*};
use airlock_nix_core::admission::ExpectedAdmission;
use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use std::path::PathBuf;

/// Parsed store request, validated by the application's single command parser.
#[derive(Args)]
pub(crate) struct Request {
    // Whether the incoming stream begins with an inventory negotiation.
    #[command(subcommand)]
    operation: Operation,
}

#[derive(Subcommand)]
enum Operation {
    Receive(Receiver),
    ReceiveIncremental {
        // Authenticated target and approval identity supplied by the RPC handler.
        #[command(flatten)]
        receiver: Receiver,
        // Dom0-owned identity restricting admission to an already reviewed candidate.
        #[arg(long)]
        expected_identity: Option<PathBuf>,
    },
}

#[derive(Args)]
struct Receiver {
    // Persistent pool holding incoming fragments and committed views.
    #[arg(long, default_value = "/var/lib/airlock/closure-store")]
    pool_root: PathBuf,
    // VM namespace named by the authenticated RPC argument.
    #[arg(long)]
    expected_domain: String,
    // Authenticated caller or protected approval owner.
    #[arg(long)]
    approved_by: String,
}

pub(super) fn run(command: Request) -> Result<()> {
    let result = (|| -> Result<super::AdmissionReceipt> {
        let (receiver, incremental, identity) = match command.operation {
            Operation::Receive(receiver) => (receiver, false, None),
            Operation::ReceiveIncremental {
                receiver,
                expected_identity,
            } => (
                receiver,
                true,
                expected_identity
                    .map(|path| {
                        read::<ExpectedAdmission>(&path)
                            .context("invalid prepared candidate identity")
                    })
                    .transpose()?,
            ),
        };
        let value = artifacts::receive(
            &mut std::io::stdin().lock(),
            &mut std::io::stdout().lock(),
            &receiver.pool_root,
            &receiver.expected_domain,
            &receiver.approved_by,
            incremental,
            identity.as_ref(),
        )?;
        let receipt: super::AdmissionReceipt = serde_json::from_value(value)?;
        if let Some(root) = &receipt.root_artifact {
            root.validate()?;
        }
        Ok(receipt)
    })();
    match result {
        Ok(value) => {
            println!("{}", serde_json::to_string(&value)?);
            Ok(())
        }
        Err(error) => {
            eprintln!("airlock store admission: {error:#}");
            artifacts::report_error(&mut std::io::stdout().lock(), &error);
            Err(crate::process::ProtocolFailed.into())
        }
    }
}
