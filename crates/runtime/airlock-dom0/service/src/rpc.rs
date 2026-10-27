//! A qrexec channel carries a request, not authority to run an arbitrary command.
//! These receivers validate bounded messages, consult protected source approval,
//! and detach activation into systemd so restarting the caller cannot cancel it.

mod control;

mod machine;

mod transfer;

use crate::{model::ReleasePath, process::ProtocolFailed};
use airlock_nix_core::{
    identity::{GitRevision, GuestName, LockHash, ReviewId},
    runtime::process,
    state::{LockHolder, OperationKind, OperationLock, OperationOwner, StateStore},
};
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand, ValueEnum};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::{
    fs,
    io::{self, BufRead, Write},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Local selection of one policy-restricted request protocol and installed engine.
#[derive(Args)]
pub(crate) struct Request {
    // Installed coordinator fixed by the local wrapper, never by a wire request.
    #[arg(long)]
    engine: Option<PathBuf>,
    // Policy-specific protocol; qrexec wrappers fix this before reading input.
    #[command(subcommand)]
    operation: Operation,
}

#[derive(Subcommand)]
enum Operation {
    /// Receive a transport release and prepare, plan or start machine activation.
    MachineReceive {
        // Whether to admit guest artifacts, compute effects or start activation.
        #[arg(value_enum)]
        action: MachineAction,
    },
    /// Bind an inactive guest admission and optionally start its activation.
    GuestReceive {
        // Planning stays synchronous; activation runs in a detached systemd unit.
        #[arg(value_enum)]
        action: GuestAction,
    },
    /// Read state or invoke an allowlisted maintenance/recovery operation.
    MachineControl,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum MachineAction {
    Prepare,
    Plan,
    Apply,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum GuestAction {
    Plan,
    Apply,
}

/// Failed coordinator reply retained so callers receive busy/lock diagnostics.
#[derive(Debug)]
struct RemoteFailure {
    // Human-readable reason, bounded when emitted over the qrexec channel.
    detail: String,
    // Structured reply from the helper, including optional status and lock owner.
    response: Value,
    // Process exit code, absent when the helper was terminated by a signal.
    code: Option<i32>,
}

impl std::fmt::Display for RemoteFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for RemoteFailure {}

struct Receiver {
    // Protected state namespace; prepared tokens are always resolved beneath it.
    state: PathBuf,
    // Installed coordinator whose path is selected locally rather than over RPC.
    engine: PathBuf,
    // Capture admission policy at entry so a long request cannot downgrade it.
    review_required: bool,
}

/// Own the response stream, preserving structured failures without a second reply.
pub(crate) fn execute(state: &Path, request: Request) -> Result<()> {
    let guest = matches!(request.operation, Operation::GuestReceive { .. });
    let schema = match request.operation {
        Operation::MachineReceive { .. } => machine::SCHEMA,
        Operation::GuestReceive { .. } => "airlock.guest-deploy-error.v1",
        Operation::MachineControl => control::SCHEMA,
    };
    let action = match request.operation {
        Operation::GuestReceive {
            action: GuestAction::Plan,
        } => Some("guest-plan"),
        Operation::GuestReceive {
            action: GuestAction::Apply,
        } => Some("guest-apply"),
        _ => None,
    };
    let result = (|| {
        let engine = request
            .engine
            .or_else(|| std::env::var_os("AIRLOCK_DOM0_SERVICE").map(PathBuf::from))
            .map(Ok)
            .unwrap_or_else(std::env::current_exe)?;
        ensure!(
            engine.is_absolute(),
            "installed coordinator must be an absolute path"
        );
        let receiver = Receiver {
            state: state.to_owned(),
            engine,
            review_required: review_required()?,
        };
        let mut input = transfer::input()?;
        match request.operation {
            Operation::MachineReceive { action } => receiver.machine(action, &mut input),
            Operation::GuestReceive { action } => receiver.guest(action, &mut input),
            Operation::MachineControl => receiver.control(&mut input),
        }
    })();

    match result {
        Ok(value) => emit(&value).map_err(|_| ProtocolFailed.into()),
        Err(error) => {
            let remote = error.downcast_ref::<RemoteFailure>();
            let detail: String = format!("{error:#}").chars().take(4096).collect();
            let mut response = json!({"schema":schema,"status":"failed","error":detail});
            if let Some(remote) = remote {
                for key in ["status", "lock"] {
                    if let Some(value) = remote.response.get(key) {
                        response[key] = value.clone();
                    }
                }
            }
            if let Some(airlock_nix_core::Error::Busy { path, holder }) =
                error.downcast_ref::<airlock_nix_core::Error>()
            {
                response["status"] = json!("busy");
                response["lock"] = match holder {
                    LockHolder::Verified(details) => json!({
                        "held":true,"verified":true,"path":path,"holder":holder,
                        "owner":details.owner().name(),"reason":details.owner().reason(),
                        "pid":details.pid(),
                    }),
                    LockHolder::Unknown => json!({"held":true,"verified":false,"path":path,
                        "owner":"Unknown operation","reason":"Current owner details could not be verified"}),
                };
            }
            if guest {
                response["operation"] = json!(action);
                response["exit_code"] = json!(remote.and_then(|r| r.code));
                response
                    .as_object_mut()
                    .expect("object")
                    .entry("lock")
                    .or_insert(Value::Null);
            }
            eprintln!("airlock-dom0-service RPC: {detail}");
            let _ = emit(&response);
            Err(ProtocolFailed.into())
        }
    }
}

fn emit(value: &Value) -> Result<()> {
    let mut output = io::stdout().lock();
    serde_json::to_writer(&mut output, value)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}

fn message<T: DeserializeOwned>(input: &mut impl BufRead, limit: u64) -> Result<T> {
    use std::io::Read;
    let mut bytes = Vec::new();
    input.take(limit + 1).read_until(b'\n', &mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit && bytes.last() == Some(&b'\n'),
        "invalid or oversized RPC request"
    );
    Ok(airlock_nix_core::state::parse_json(
        &bytes,
        Path::new("<qrexec>"),
    )?)
}

fn review_required() -> Result<bool> {
    match fs::symlink_metadata("/etc/airlock/review-required") {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

impl Receiver {
    fn transfer_lock(&self, approval: Option<&ReviewId>) -> Result<OperationLock> {
        let root = self.state.join("rpc");
        crate::state::directory(&root)?;
        let store = StateStore::initialize(&root)?;
        let mut owner = OperationOwner::new(
            "Machine transfer from sys-ctrl".into(),
            "Serialize Nix imports and free-space budgeting before candidate preparation".into(),
            OperationKind::Deployment,
        )?;
        if let Some(id) = approval {
            owner = owner.with_review(id.clone());
        }
        Ok(store.try_operation(&"machine-transfer".parse()?, owner)?)
    }

    fn candidate_path(&self, candidate: &ReleasePath) -> Result<()> {
        let path = candidate.as_path();
        ensure!(
            path.parent() == Some(self.state.join("candidates").as_path())
                && fs::canonicalize(path)?.as_os_str() == path.as_os_str(),
            "coordinator returned a noncanonical candidate outside the protected namespace"
        );
        crate::state::trusted(path)
    }

    fn approval(
        &self,
        id: Option<&ReviewId>,
        revision: &GitRevision,
        lock_hash: &LockHash,
    ) -> Result<Option<Value>> {
        if !self.review_required {
            return Ok(None);
        }
        let id = id.context("source approval is required")?;
        Ok(Some(self.engine(
            &self.engine,
            &["review-control"],
            Some(&json!({"op":"check","request_id":id,"revision":revision,"lock_hash":lock_hash})),
        )?))
    }

    fn engine(&self, program: &Path, args: &[&str], input: Option<&Value>) -> Result<Value> {
        let bytes = input
            .map(|value| -> Result<Vec<u8>> {
                let mut bytes = serde_json::to_vec(value)?;
                bytes.push(b'\n');
                Ok(bytes)
            })
            .transpose()?;
        let output = process::run(
            Command::new(program)
                .arg("--state")
                .arg(&self.state)
                .args(args),
            bytes,
            Some(Duration::from_secs(600)),
        )?;
        if !output.status.success() {
            let response: Value =
                airlock_nix_core::state::parse_json(&output.stdout, Path::new("<coordinator>"))
                    .unwrap_or(Value::Null);
            let detail = response["error"]
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| String::from_utf8_lossy(&output.stderr).trim().to_owned());
            return Err(RemoteFailure {
                detail: if detail.is_empty() {
                    format!("coordinator failed ({})", output.status)
                } else {
                    detail
                },
                response,
                code: output.status.code(),
            }
            .into());
        }
        Ok(airlock_nix_core::state::parse_json(
            &output.stdout,
            Path::new("<coordinator>"),
        )?)
    }

    fn bind(&self, approval: Option<&ReviewId>, candidate: &ReleasePath) -> Result<()> {
        if self.review_required {
            let id = approval.context("source approval is required")?;
            self.engine(
                &self.engine,
                &["review-bind", id.as_str(), candidate.as_str()],
                None,
            )?;
        }
        Ok(())
    }

    fn detach(&self, engine: &Path, args: &[&str]) -> Result<String> {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let unit = format!("airlock-machine-deploy-{}-{stamp}", std::process::id());
        process::run(
            Command::new("systemd-run")
                .args(["--collect", "--property=Type=exec", "--unit", &unit, "--"])
                .arg(engine)
                .arg("--state")
                .arg(&self.state)
                .args(args),
            None,
            Some(Duration::from_secs(60)),
        )?
        .checked("start detached deployment")?;
        Ok(unit)
    }

    fn guest(&self, action: GuestAction, input: &mut impl BufRead) -> Result<Value> {
        let mut receipt: Value = message(input, 65536)?;
        let object = receipt
            .as_object_mut()
            .context("invalid guest admission receipt")?;
        let approval: Option<ReviewId> = object
            .remove("review_authorization")
            .map(serde_json::from_value)
            .transpose()?;
        if self.review_required {
            let revision: GitRevision = serde_json::from_value(receipt["source_revision"].clone())?;
            let lock_hash: LockHash = serde_json::from_value(receipt["lock_hash"].clone())?;
            let domain: GuestName = serde_json::from_value(receipt["domain"].clone())?;
            let checked = self
                .approval(approval.as_ref(), &revision, &lock_hash)?
                .context("source approval is required")?;
            ensure!(
                checked["binding"]["family"] == "machine"
                    || (checked["binding"]["family"] == "guest"
                        && checked["binding"]["target"] == domain.as_str()),
                "source approval targets a different guest"
            );
        }
        let mut result = self.engine(&self.engine, &["guest-plan", "-"], Some(&receipt))?;
        let candidate: ReleasePath = serde_json::from_value(result["candidate"].clone())?;
        self.candidate_path(&candidate)?;

        self.bind(approval.as_ref(), &candidate)?;
        if action == GuestAction::Apply {
            let unit = self.detach(&self.engine, &["apply", candidate.as_str()])?;
            result["unit"] = json!(unit);
        }
        Ok(result)
    }
}
