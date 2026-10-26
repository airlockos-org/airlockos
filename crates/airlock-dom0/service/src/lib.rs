//! Native dom0 operations shared by the command service and upstream Qubes plugins.
//! Qubes remains responsible for VM lifecycle, RPC policy and privileged control.

#![warn(missing_docs)]
#![forbid(unsafe_code)]
/// Immutable Hermit executable validation at privileged boundaries.
pub mod hermit;

mod boot;

mod admission_adapter;

mod development;

mod coordinator;

mod config;

mod gpu;

mod input;

mod lock;

mod model;

mod planning;

mod process;

mod qubes;

mod retention;

mod readiness;

mod rpc;

mod setup;

mod setup_config;

mod state;

mod store;

use airlock_nix_core::identity::{GuestName, ReviewId};
use anyhow::{Result, ensure};
use clap::{Parser, Subcommand};
use coordinator::Coordinator;
use model::{ApplyMode, Record, StorePath};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
};

#[derive(Parser)]
#[command(version, about)]
struct Args {
    // Dom0 state directory containing journal and selection records.
    #[arg(long, default_value = "/var/lib/airlock/machine")]
    state: PathBuf,
    // Requested subcommand and its validated command-line arguments.
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Enforce the installed admission RPC and privileged receiver contracts.
    AdmissionAdapter(admission_adapter::Request),
    /// Run configuration transport and administrative compatibility operations.
    Config(config::Request),
    /// Inspect or reversibly quarantine authenticated duplicate EFI cache files.
    BootCache(store::boot_cache::Request),
    /// Read the recorded host and source baseline for explicit development repair.
    DevelopmentSnapshot,
    /// Exercise admission and rollback only in the disposable nested test profile.
    PoolAdmissionSmoke,
    /// Validate GPU ownership and prepare firmware for the existing Qubes lifecycle.
    Gpu(gpu::Request),
    /// Discover physical input, coordinate forwarding and guard keyboard startup.
    Input(input::Request),
    /// Persist or observe first-run completion through restricted desktop RPCs.
    Setup {
        // Fixed first-run state operation authorized by the dom0 RPC wrapper.
        #[command(subcommand)]
        action: setup::Action,
    },
    /// Read setup properties and reconcile declared labels through existing Qubes APIs.
    SetupConfig(setup_config::Request),
    /// Start one VM and require its exact declared generation and provider readiness.
    StartQubeReady(readiness::Ready),
    /// Start the declared autostart network providers in local NetVM order.
    StartNetworkProviders,
    /// Wait for an active graphical login on the selected GUI generation.
    WaitDesktopReady(readiness::Desktop),
    /// Record boot readiness, recover interrupted attempts and collect diagnostics.
    BootSupervisor(boot::Request),
    /// Handle restricted dom0 requests received over existing Qubes RPC channels.
    Rpc(rpc::Request),
    /// Access storage operations used by Qubes, image preparation and boot tools.
    Storage {
        // Storage subsystem entry point; its protocol owns stdin/stdout.
        #[command(subcommand)]
        command: store::Command,
    },
    /// Configure VMs for startup from the selected machine generation.
    BootSetup {
        // Configure desktop dependencies before GPU handoff.
        #[arg(long, conflicts_with = "background")]
        gui: bool,
        // Configure remaining guests after the guarded desktop is ready.
        #[arg(long)]
        background: bool,
        // Default setup program supplied by the booted image.
        setup: model::StoreFile,
        // Exact setup arguments supplied by the service unit.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<std::ffi::OsString>,
    },
    /// Start declared autostart VMs after setup and hardware guards.
    BootStart {
        // Default topology used only without a selected deployment.
        #[arg(long, default_value = "/etc/airlock/qubes-topology.json")]
        topology: PathBuf,
        // Guests that must already be running after hardware guards.
        #[arg(long)]
        require_running: Vec<GuestName>,
    },
    /// List retained machine release choices and deletion blockers.
    ReleaseList,
    /// Report blockers to removing a particular retained release.
    ReleasePrunePlan {
        // Absolute release identity to inspect.
        release: PathBuf,
        // Trash-expiry blockers explicitly waived for this release.
        #[arg(long = "allow-unexpired-trash")]
        overrides: Vec<String>,
    },
    /// Remove a confirmed obsolete release through a resumable journal.
    ReleasePrune {
        // Exact absolute release identity to delete.
        release: PathBuf,
        // Must equal the complete release path.
        #[arg(long)]
        confirm: String,
        // Trash-expiry blockers explicitly waived for this release.
        #[arg(long = "allow-unexpired-trash")]
        overrides: Vec<String>,
    },
    /// Explicitly retain or release a recorded rollback choice.
    ReleaseRetain {
        // Recorded release whose manual retention changes.
        release: PathBuf,
        // Whether to protect this release from automatic pruning.
        #[arg(long, action = clap::ArgAction::Set)]
        retain: bool,
    },
    /// List retired VM storage records without deleting data.
    TrashList,
    /// Permanently remove a confirmed retired VM after reference checks.
    TrashPurge {
        // Transaction-and-VM identity of the trash record.
        identity: String,
        // Must equal the full trash identity.
        #[arg(long)]
        confirm: String,
        // Explicitly waive the minimum retention period.
        #[arg(long)]
        before_expiry: bool,
    },
    /// Run queued generation pruning and pool GC for a verified selection.
    GenerationMaintenance,
    /// Authorize inactive artifact imports for an inspected release.
    AdmissionPrepare {
        // Immutable imported release whose guest inventory is authorized.
        release: PathBuf,
        // Caller fixed by the restricted qrexec wrapper.
        #[arg(long)]
        caller: String,
    },
    /// Receive one exact candidate's guest artifacts through the storage protocol.
    AdmissionReceive {
        // Protected admission token followed by a dot and guest name.
        argument: String,
        // Caller fixed by the restricted qrexec wrapper.
        #[arg(long)]
        caller: String,
    },
    /// Create, decide, validate or observe a protected source review from stdin.
    ReviewControl,
    /// Bind a prepared release to an existing protected source review.
    ReviewBind {
        // Human authorization whose source and scope must cover the release.
        request_id: ReviewId,
        // Already admitted local candidate to bind.
        release: PathBuf,
    },
    /// Assemble a machine candidate from exact pool admission receipts.
    MachineBind {
        // Transport release imported by the restricted controller receiver.
        release: PathBuf,
        // Receipt JSON file, or a dash to read stdin.
        receipts: String,
    },
    /// Validate prepared artifacts and produce a mutable-state fingerprint.
    PreparedCheck {
        // Local candidate to revalidate without activation.
        release: PathBuf,
    },
    /// Prepare a single-guest candidate and describe its effects.
    GuestPlan {
        // Admission receipt file, or a dash to read stdin.
        receipt: String,
    },
    /// Prepare and activate an approved single-guest candidate.
    GuestApply {
        // Admission receipt file, or a dash to read stdin.
        receipt: String,
    },
    /// Observe the selected release, current transaction and machine lock.
    Status,
    /// Validate a release and compute a whole-machine lifecycle plan.
    Plan {
        // Release directory to inspect without activation.
        release: PathBuf,
        // Optional prior release used for a side-effect-free offline plan.
        #[arg(long)]
        baseline: Option<PathBuf>,
        // Guest names to treat as running when planning against an offline baseline.
        #[arg(long, requires = "baseline")]
        running: Vec<GuestName>,
        // Host system identity supplied for offline reboot planning.
        #[arg(long, requires = "baseline")]
        host: Option<StorePath>,
    },
    /// Activate an already admitted and source-approved direct-pool candidate.
    Apply {
        // Admitted candidate release directory to activate.
        release: PathBuf,
        // Mutable-state fingerprint returned by prepared-check.
        #[arg(long)]
        expected_state: Option<String>,
        // Explicit root-only development repair, recorded in the deployment journal.
        #[arg(long)]
        administrative: bool,
    },
    /// Verify selected pool artifacts, running guests and the host generation.
    Verify,
    /// Retry the exact recorded native transaction after a failure.
    Resume,
    /// Activate the exact previous release recorded by a native transaction.
    Rollback,
    /// Inspect weekly retention choices; does not prune releases or run GC.
    GenerationRetentionPlan,
    /// Validate release data locally without executing Qubes or Nix commands.
    InspectRelease {
        // Release directory whose manifest and topology should be validated.
        release: PathBuf,
    },
    /// Validate a transaction snapshot locally without changing it.
    InspectRecord {
        // Saved transaction JSON to validate without changing state.
        file: PathBuf,
    },
}

fn run(args: Args) -> Result<Value> {
    model::absolute(
        args.state
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("non-UTF-8 state path"))?,
    )?;

    let c = Coordinator::new(args.state);
    Ok(match args.command {
        Action::AdmissionAdapter(request) => {
            admission_adapter::execute(request)?;
            Value::Null
        }
        Action::Config(request) => {
            config::execute(request)?;
            Value::Null
        }
        Action::BootCache(request) => store::boot_cache::execute(&c.state, request)?,
        Action::DevelopmentSnapshot => development::snapshot()?,
        Action::PoolAdmissionSmoke => development::pool_smoke()?,
        Action::Gpu(request) => {
            gpu::execute(request)?;
            Value::Null
        }
        Action::Input(request) => {
            input::execute(request)?;
            Value::Null
        }
        Action::Setup { action } => {
            setup::execute(action)?;
            Value::Null
        }
        Action::SetupConfig(request) => {
            setup_config::execute(request)?;
            Value::Null
        }
        Action::StartQubeReady(request) => {
            readiness::start(request)?;
            Value::Null
        }
        Action::StartNetworkProviders => {
            readiness::start_providers()?;
            Value::Null
        }
        Action::WaitDesktopReady(request) => {
            readiness::desktop(request)?;
            Value::Null
        }
        Action::BootSupervisor(request) => boot::execute(request, &c)?,
        Action::Rpc(request) => {
            rpc::execute(&c.state, request)?;
            Value::Null
        }
        Action::Storage { command } => {
            store::execute(command)?;
            Value::Null
        }
        Action::BootSetup {
            setup,
            args,
            gui,
            background,
        } => c.boot_setup(setup, args, gui, background)?,
        Action::BootStart {
            topology,
            require_running,
        } => c.boot_start(&topology, &require_running)?,
        Action::ReleaseList => c.release_list()?,
        Action::ReleasePrunePlan { release, overrides } => {
            c.release_prune(&release, None, &overrides)?
        }
        Action::ReleasePrune {
            release,
            confirm,
            overrides,
        } => c.release_prune(&release, Some(&confirm), &overrides)?,
        Action::ReleaseRetain { release, retain } => c.release_retain(&release, retain)?,
        Action::TrashList => c.trash_list()?,
        Action::TrashPurge {
            identity,
            confirm,
            before_expiry,
        } => c.trash_purge(&identity, &confirm, before_expiry)?,
        Action::GenerationMaintenance => c.generation_maintenance()?,
        Action::AdmissionPrepare { release, caller } => c.admission_prepare(&release, &caller)?,
        Action::AdmissionReceive { argument, caller } => {
            c.admission_receive(&argument, &caller)?;
            Value::Null
        }
        Action::Status => c.status()?,
        Action::Plan {
            release,
            baseline,
            running,
            host,
        } => {
            let r = state::Release::load(&release)?;
            if let Some(path) = baseline {
                let old = state::Release::load(&path)?;
                let running: BTreeSet<_> = running.into_iter().collect();
                let host = host.map(Ok).unwrap_or_else(state::host)?;
                serde_json::to_value(airlock_machine_core::inspection::inspect(
                    airlock_machine_core::inspection::MachineView {
                        manifest: &old.manifest,
                        topology: &old.topology,
                    },
                    airlock_machine_core::inspection::MachineView {
                        manifest: &r.manifest,
                        topology: &r.topology,
                    },
                    &running,
                    &host,
                )?)?
            } else {
                serde_json::to_value(c.inspect(&r.path)?)?
            }
        }
        Action::ReviewControl => c.review_control()?,
        Action::ReviewBind {
            request_id,
            release,
        } => c.review_bind(&request_id, &release)?,
        Action::MachineBind { release, receipts } => {
            c.machine_bind(&release, serde_json::from_value(input_value(&receipts)?)?)?
        }
        Action::PreparedCheck { release } => c.prepared_check(&release)?,
        Action::GuestPlan { receipt } => {
            let path = c.guest_candidate(serde_json::from_value(input_value(&receipt)?)?)?;
            json!({"candidate":path,"plan":c.inspect(&path)?})
        }
        Action::GuestApply { receipt } => {
            let path = c.guest_candidate(serde_json::from_value(input_value(&receipt)?)?)?;
            json!(c.apply(&path, ApplyMode::New, None, false)?)
        }
        Action::Apply {
            release,
            expected_state,
            administrative,
        } => serde_json::to_value(c.apply(
            &release,
            ApplyMode::New,
            expected_state.as_deref(),
            administrative,
        )?)?,
        Action::Verify => serde_json::to_value(c.verify()?)?,
        Action::Resume => serde_json::to_value(c.recover(ApplyMode::Resume)?)?,
        Action::Rollback => serde_json::to_value(c.recover(ApplyMode::Rollback)?)?,
        Action::GenerationRetentionPlan => c.generation_plan()?,
        Action::InspectRelease { release } => {
            let r = state::Release::load(&release)?;
            json!({"authority":"local-inspection-only","release":r.path,"manifest":r.manifest,"domains":r.topology.domains.keys().collect::<Vec<_>>()})
        }
        Action::InspectRecord { file } => {
            let record: Record = state::read(&file)?;
            json!({"authority":"local-inspection-only","record":record})
        }
    })
}

fn input_value(path: &str) -> Result<Value> {
    use std::io::Read;
    if path != "-" {
        return state::read(std::path::Path::new(path));
    }

    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take(state::LIMIT + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= state::LIMIT,
        "input exceeds size limit"
    );
    Ok(airlock_nix_core::state::parse_json(
        &bytes,
        std::path::Path::new("<stdin>"),
    )?)
}

/// Parse command arguments and report a native dom0 operation.
pub fn main() -> ExitCode {
    let args = Args::parse();
    let direct = matches!(
        args.command,
        Action::AdmissionAdapter(_)
            | Action::Storage {
                command: store::Command::BuildProgress(_),
            }
            | Action::Config(_)
            | Action::Input(_)
            | Action::Gpu(_)
            | Action::SetupConfig(_)
            | Action::StartQubeReady(_)
            | Action::StartNetworkProviders
    );
    let stream = matches!(
        args.command,
        Action::Setup { .. }
            | Action::AdmissionReceive { .. }
            | Action::Storage { .. }
            | Action::Rpc(_)
    );
    let review = matches!(
        args.command,
        Action::ReviewControl | Action::ReviewBind { .. }
    );
    let result = run(args);
    if direct {
        return match result {
            Ok(_) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("airlock-dom0-service: {error:#}");
                ExitCode::FAILURE
            }
        };
    }
    if stream
        && result
            .as_ref()
            .is_err_and(|e| e.downcast_ref::<process::ProtocolFailed>().is_some())
    {
        return ExitCode::FAILURE;
    }
    if stream && result.is_ok() {
        return ExitCode::SUCCESS;
    }
    let (value, code) = match result {
        Ok(v) => (v, ExitCode::SUCCESS),
        Err(error) => {
            let busy = error.downcast_ref::<lock::Busy>();
            let mut v = json!({"schema":if stream { "airlock.pool-artifact-error.v1" } else if review { "airlock.review-control-error.v1" } else { "airlock.machine-error.v1" },"status":if busy.is_some(){"busy"}else{"failed"},"error":format!("{error:#}")});
            if let Some(b) = busy {
                match serde_json::to_value(&b.0) {
                    Ok(owner) => v["lock"] = owner,
                    Err(error) => v["lock_error"] = json!(error.to_string()),
                }
            }
            (v, ExitCode::FAILURE)
        }
    };

    let mut out = io::stdout().lock();
    if let Err(error) = serde_json::to_writer_pretty(&mut out, &value)
        .map_err(io::Error::other)
        .and_then(|_| out.write_all(b"\n"))
    {
        if error.kind() != io::ErrorKind::BrokenPipe {
            eprintln!("airlock-dom0-service: {error}");
        }
        return ExitCode::FAILURE;
    }

    code
}

/// Execute a storage plugin operation using the same validation and engine as the CLI.
pub fn storage_request(request: Value) -> Result<Value> {
    store::qubes_request(request)
}

/// Execute a GPU lifecycle operation without spawning another process or granting RPC authority.
pub fn gpu_request(request: Value) -> Result<Value> {
    gpu::qubes_request(request)
}

/// Decode the isolated worker's serialized storage declarations without granting installation permission.
#[cfg(feature = "qubes")]
pub fn storage_objects_request(request: Value) -> Result<airlock_qubes::storage::Request> {
    store::objects_request(request)
}

/// Supply the installed locked-observation and post-installation checks to upstream Qubes adapters.
#[cfg(feature = "qubes")]
pub fn storage_objects_policy() -> impl airlock_qubes::storage::Policy {
    store::ObjectsPolicy
}

/// Typed in-process interface used by Qubes storage callbacks.
pub mod storage_plugin;
