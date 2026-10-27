//! Machine commands submit reviewed source to sys-ctrl or send bounded control
//! requests to dom0. The CLI never builds locally or opens a dom0 shell.

use crate::submit;
use airlock_nix_core::{
    identity::{GuestName, JobId},
    runtime::{Result, process::OwnedChild, protocol::Action, report, require},
    store_path::StorePath,
};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use std::{
    ffi::OsString,
    io::Write,
    path::PathBuf,
    process::{Command, ExitCode, Stdio},
    str::FromStr,
};

#[derive(Parser)]
#[command(
    name = "airlock machine",
    about = "Review, deploy and maintain machine configuration"
)]
struct Arguments {
    /// Operation exposed through existing Qubes controller services.
    #[command(subcommand)]
    command: MachineCommand,
}

#[derive(Subcommand)]
enum MachineCommand {
    /// Submit committed source for approval and build without activation.
    Build(Source),
    /// Submit committed source for approval and compute a whole-machine plan.
    Plan(Source),
    /// Submit committed source for approval and deployment.
    Apply(Source),
    /// Review and plan a change to one guest.
    GuestPlan(Guest),
    /// Review and deploy a change to one guest.
    GuestApply(Guest),
    /// Read the recorded human decision and current worker status.
    ReviewStatus {
        /// Controller job to observe, as returned by source submission.
        #[arg(long)]
        request_id: JobId,
    },
    /// Observe deployed source, current transaction and pending reboot state.
    Status,
    /// Verify selected and running systems through dom0.
    Verify,
    /// Ask dom0 to resume an interrupted deployment.
    Resume,
    /// Ask dom0 to roll back the current deployment.
    Rollback,
    /// List retired VM data that remains recoverable.
    TrashList,
    /// Permanently purge one exact retired-data identity.
    TrashPurge {
        /// Retired-data record whose contents will be removed.
        #[arg(long)]
        identity: TrashIdentity,
        /// Must equal the entire identity, including its retirement timestamp.
        #[arg(long)]
        confirm: TrashIdentity,
        /// Explicitly permit purging before the record's normal expiry.
        #[arg(long)]
        before_expiry: bool,
    },
    /// Inspect blockers to removing one recorded release.
    ReleasePrunePlan(Prune),
    /// List recorded releases and retention state.
    ReleaseList,
    /// Remove one exact release, subject to dom0's retention blockers.
    ReleasePrune {
        /// Release and explicit early-purge exceptions to check.
        #[command(flatten)]
        plan: Prune,
        /// Must equal the complete release path being removed.
        #[arg(long)]
        confirm: RecordedRelease,
    },
    /// Change the retention marker for one recorded release.
    ReleaseRetain {
        /// Recorded release whose retention marker will change.
        #[arg(long)]
        release: RecordedRelease,
        /// Whether the release must be protected from pruning.
        #[arg(long)]
        retain: Retention,
    },
}

#[derive(Args)]
struct Source {
    /// Clean committed checkout; defaults to $HOME/airlockos-machine.
    #[arg(long)]
    repo: Option<PathBuf>,
}

#[derive(Args)]
struct Guest {
    /// Guest VM whose configuration is under review; dom0 is excluded.
    #[arg(long)]
    target: GuestName,
    /// Source checkout to submit through the normal review route.
    #[command(flatten)]
    source: Source,
}

#[derive(Args)]
struct Prune {
    /// Exact remote release location; never interpreted as a local path to read.
    #[arg(long)]
    release: RecordedRelease,
    /// Retired-data identities permitted to be purged before expiry, at most 100.
    #[arg(long)]
    allow_unexpired_trash: Vec<TrashIdentity>,
}

/// Retention is a string on the existing dom0 protocol, rather than a JSON boolean.
#[derive(Clone, Copy, Debug, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
enum Retention {
    True,
    False,
}

fn record_name(value: &str) -> bool {
    !value.is_empty()
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
struct TrashIdentity(
    /// One opaque record name, excluding path separators and shell syntax.
    String,
);

impl FromStr for TrashIdentity {
    type Err = &'static str;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        if !record_name(value) {
            return Err("expected an exact retired-data identity without path separators");
        }

        Ok(Self(value.to_owned()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
struct RecordedRelease(
    /// Exact absolute location understood by dom0; no normalization or local resolution.
    String,
);

impl FromStr for RecordedRelease {
    type Err = &'static str;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let candidate = value.strip_prefix("/var/lib/airlock/machine/candidates/");
        if value == "/var/lib/airlock/machine/baseline"
            || value.parse::<StorePath>().is_ok()
            || candidate.is_some_and(record_name)
        {
            return Ok(Self(value.to_owned()));
        }

        Err("expected an exact Nix store release, machine candidate, or machine baseline path")
    }
}

#[derive(Serialize)]
#[serde(tag = "action", rename_all = "kebab-case")]
enum Control {
    Status,
    Verify,
    Resume,
    Rollback,
    TrashList,
    TrashPurge {
        /// Record selected for permanent removal.
        identity: TrashIdentity,
        /// Exact record identity repeated by the caller.
        confirm: TrashIdentity,
        /// Whether the request explicitly permits early removal.
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        before_expiry: bool,
    },
    ReleasePrunePlan {
        /// Recorded release to inspect for removal blockers.
        release: RecordedRelease,
        /// Explicit exceptions; omitted when the normal expiry policy applies.
        #[serde(skip_serializing_if = "Vec::is_empty")]
        allow_unexpired_trash: Vec<TrashIdentity>,
    },
    ReleaseList,
    ReleasePrune {
        /// Exact recorded release selected for removal.
        release: RecordedRelease,
        /// Complete release path repeated by the caller.
        confirm: RecordedRelease,
        /// Explicit early-removal exceptions to dom0's retention checks.
        #[serde(skip_serializing_if = "Vec::is_empty")]
        allow_unexpired_trash: Vec<TrashIdentity>,
    },
    ReleaseRetain {
        /// Release whose retention marker is being changed.
        release: RecordedRelease,
        /// String-valued retention choice expected by the existing wire protocol.
        retain: Retention,
    },
}

#[derive(Serialize)]
struct Request {
    /// Existing dom0 control protocol; this record grants no authority by itself.
    schema: &'static str,
    /// Operation with only the fields valid for that operation.
    #[serde(flatten)]
    action: Control,
}

fn invalid(message: &str) -> ! {
    Arguments::command()
        .error(clap::error::ErrorKind::ValueValidation, message)
        .exit()
}

fn prune_limit(plan: &Prune) {
    if plan.allow_unexpired_trash.len() > 100 {
        invalid("at most 100 --allow-unexpired-trash identities are permitted");
    }
}

fn run(command: MachineCommand) -> Result<u8> {
    let action = match command {
        MachineCommand::Build(source) => {
            return submit::source(Action::MachineBuild, None, source.repo);
        }
        MachineCommand::Plan(source) => {
            return submit::source(Action::MachinePlan, None, source.repo);
        }
        MachineCommand::Apply(source) => {
            return submit::source(Action::MachineApply, None, source.repo);
        }
        MachineCommand::GuestPlan(guest) => {
            return submit::source(Action::GuestPlan, Some(guest.target), guest.source.repo);
        }
        MachineCommand::GuestApply(guest) => {
            return submit::source(Action::GuestApply, Some(guest.target), guest.source.repo);
        }
        MachineCommand::ReviewStatus { request_id } => return submit::review_status(request_id),
        MachineCommand::Status => Control::Status,
        MachineCommand::Verify => Control::Verify,
        MachineCommand::Resume => Control::Resume,
        MachineCommand::Rollback => Control::Rollback,
        MachineCommand::TrashList => Control::TrashList,
        MachineCommand::TrashPurge {
            identity,
            confirm,
            before_expiry,
        } => {
            if identity != confirm {
                invalid("--confirm must match the exact --identity");
            }
            Control::TrashPurge {
                identity,
                confirm,
                before_expiry,
            }
        }
        MachineCommand::ReleasePrunePlan(plan) => {
            prune_limit(&plan);
            Control::ReleasePrunePlan {
                release: plan.release,
                allow_unexpired_trash: plan.allow_unexpired_trash,
            }
        }
        MachineCommand::ReleaseList => Control::ReleaseList,
        MachineCommand::ReleasePrune { plan, confirm } => {
            prune_limit(&plan);
            if plan.release != confirm {
                invalid("--confirm must match the exact --release path");
            }
            Control::ReleasePrune {
                release: plan.release,
                confirm,
                allow_unexpired_trash: plan.allow_unexpired_trash,
            }
        }
        MachineCommand::ReleaseRetain { release, retain } => {
            Control::ReleaseRetain { release, retain }
        }
    };

    let mut request = serde_json::to_vec(&Request {
        schema: "airlock.machine-control.v1",
        action,
    })?;
    request.push(b'\n');
    require(
        request.len() <= 65536,
        "machine control request exceeds 64 KiB",
    )?;

    // Stream the peer's output directly, including progress and failed-deployment
    // observations. An `error` field is data, not a transport failure here.
    let mut child = OwnedChild(
        Command::new("qrexec-client-vm")
            .args(["dom0", "airlock.Ctrl.MachineControl"])
            .stdin(Stdio::piped())
            .spawn()?,
    );
    let sent = child
        .0
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(&request);
    let status = child.0.wait()?;
    if status.success() {
        sent?;
    }

    Ok(status.code().unwrap_or(1) as u8)
}

/// Parse the public machine namespace and dispatch directly to its Rust adapters.
pub(crate) fn main_from(args: impl IntoIterator<Item = OsString>) -> ExitCode {
    report(run(Arguments::parse_from(args).command))
}
