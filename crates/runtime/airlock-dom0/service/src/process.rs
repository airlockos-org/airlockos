//! Run bounded helper processes and clean up their owned descendants.

use anyhow::{Context, Result, ensure};
use rustix::process::{Pid, Signal, WaitId, WaitIdOptions, WaitOptions};
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::Read,
    os::unix::process::CommandExt,
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

const OUTPUT_LIMIT: u64 = 4 * 1024 * 1024;

const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Negotiated setup capabilities; old admitted helpers keep an explicit weaker report contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SetupProtocol {
    /// Bound reports plus independently required, exact per-VM task coverage.
    Covered,
    /// Typed reports bound to run, configuration and finalization.
    Bound,
    /// Earlier Rust helper supporting split phases without bound reports.
    UnboundNative,
    /// Admitted shell-era batch helper with its recognized usage response.
    Legacy,
}

impl SetupProtocol {
    /// Native configuration uses narrow prepare, per-VM and finish stages.
    pub(crate) fn native(self) -> bool {
        self != Self::Legacy
    }

    /// Only v4 promises complete task accounting; v3 retains its original bound reports.
    pub(crate) fn covered(self) -> bool {
        self == Self::Covered
    }

    /// Only the negotiated new protocol can produce typed completion evidence.
    pub(crate) fn bound(self) -> bool {
        matches!(self, Self::Bound | Self::Covered)
    }
}

/// A duplex helper has already owned the response stream and exited unsuccessfully.
/// Its protocol error must not be followed by a second coordinator JSON reply.
#[derive(Debug)]
pub struct ProtocolFailed;

impl std::fmt::Display for ProtocolFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("artifact protocol helper failed")
    }
}

impl std::error::Error for ProtocolFailed {}

struct OwnedChild {
    /// Child process owned until its leader and descendants have been reaped.
    child: Option<Child>,
    /// Process-group identity retained for cancelling all owned helpers.
    group: Pid,
    /// A batch delays orphan cleanup until every sibling process group has stopped.
    reap_orphans: bool,
}

/// Own all concurrent helpers before allowing process-wide orphan cleanup.
#[derive(Default)]
struct ChildBatch {
    /// Process groups whose leaders remain owned until completion or cancellation.
    children: Vec<OwnedChild>,
}

impl Drop for ChildBatch {
    fn drop(&mut self) {
        self.children.clear();
        let _ = reap_descendants(Instant::now() + CLEANUP_TIMEOUT);
    }
}

fn exited(pid: Pid) -> Result<bool> {
    loop {
        match rustix::process::waitid(
            WaitId::Pid(pid),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        ) {
            Ok(status) => return Ok(status.is_some()),
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

fn reap_descendants(deadline: Instant) -> Result<()> {
    // Runner owns all helpers in this single-threaded executable. A
    // subreaper adopts orphaned grandchildren, including ones that called
    // setsid() and escaped the original process group.
    let path = format!("/proc/self/task/{}/children", std::process::id());
    loop {
        let mut bytes = String::new();
        File::open(&path)?
            .take(128 * 1024 + 1)
            .read_to_string(&mut bytes)?;
        ensure!(bytes.len() <= 128 * 1024, "too many helper descendants");
        if bytes.trim().is_empty() {
            return Ok(());
        }

        for child in bytes.split_whitespace() {
            let pid = Pid::from_raw(child.parse()?).context("invalid helper PID")?;
            // A child PID remains ours, even after exit, until we reap it.
            match rustix::process::kill_process(pid, Signal::KILL) {
                Ok(()) | Err(rustix::io::Errno::SRCH) => {}
                Err(error) => return Err(error.into()),
            }
            match rustix::process::waitpid(Some(pid), WaitOptions::NOHANG) {
                Ok(_) | Err(rustix::io::Errno::INTR) => {}
                Err(error) => return Err(error.into()),
            }
        }

        ensure!(
            Instant::now() < deadline,
            "helper descendant cleanup timed out"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

impl OwnedChild {
    fn finish(&mut self) -> Result<ExitStatus> {
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        let child = self.child.as_mut().context("helper already reaped")?;
        // Keep the leader unreaped until signalling its group. Otherwise its
        // PID could be reused and a late cleanup could kill an unrelated group.
        match rustix::process::kill_process_group(self.group, Signal::KILL) {
            Ok(()) | Err(rustix::io::Errno::SRCH) => {}
            Err(error) => return Err(error.into()),
        }
        let _ = child.kill();
        while !exited(self.group)? {
            ensure!(Instant::now() < deadline, "helper cleanup timed out");
            thread::sleep(Duration::from_millis(10));
        }

        let status = child.wait()?;
        self.child = None;

        if self.reap_orphans {
            reap_descendants(deadline)?;
        }
        Ok(status)
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.child.is_some() {
            let _ = self.finish();
        } else if self.reap_orphans {
            let _ = reap_descendants(Instant::now() + CLEANUP_TIMEOUT);
        }
    }
}

/// Read a bounded capture file after its process group has stopped writing.
fn contents(mut file: File) -> Result<Vec<u8>> {
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.take(OUTPUT_LIMIT).read_to_end(&mut bytes)?;

    Ok(bytes)
}

/// Bounded helper runner owning each process group through exit and descendant cleanup.
#[derive(Default)]
pub struct Runner {
    // Optional transaction directory for durable helper stdout, stderr and timing evidence.
    log: std::cell::RefCell<Option<std::path::PathBuf>>,
}

/// Output from a helper whose exit, deadline and descendants have all been handled.
pub struct Captured {
    /// Bounded standard output retained as bytes, including non-UTF-8 diagnostics.
    pub stdout: Vec<u8>,
    /// Bounded standard error, including evidence from unsuccessful helpers.
    pub stderr: Vec<u8>,
    /// Reaped exit status; a killed helper may have no numeric exit code.
    pub status: ExitStatus,
    /// Whether execution was cancelled for exceeding its deadline or output budget.
    pub limited: bool,
}

/// File-backed protocol streams with an explicit payload budget, independent of small text capture.
pub(crate) struct Files<'a> {
    /// Optional regular input file; absence supplies an immediate EOF.
    pub input: Option<&'a std::path::Path>,
    /// Payload or command output retained without buffering it all in memory.
    pub output: &'a std::path::Path,
    /// Separate diagnostics retained on success, failure and timeout.
    pub errors: &'a std::path::Path,
    /// Maximum bytes allowed in the payload output; diagnostics retain the text capture budget.
    pub limit: u64,
}

impl Runner {
    /// Run independent boot helpers together, bounding output and cleaning every group before return.
    /// Each helper is a separate process so its own Runner can retain sequential descendant ownership.
    pub(crate) fn boot_workers(
        &self,
        program: &std::path::Path,
        arguments: &[Vec<OsString>],
        timeout: Duration,
        environment: &[(OsString, OsString)],
    ) -> Result<Vec<Captured>> {
        self.require_separate_host_policy()?;
        for args in arguments {
            self.check_raw(program.as_os_str(), args)?;
        }
        rustix::process::set_child_subreaper(Some(rustix::process::getpid()))?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .context("boot worker timeout too large")?;
        let mut batch = ChildBatch::default();
        let mut files = Vec::new();
        for args in arguments {
            let output = tempfile::tempfile()?;
            let errors = tempfile::tempfile()?;
            let child = Command::new(program)
                .args(args)
                .env_remove("AIRLOCK_STAGED_GENERATIONS")
                .envs(environment.iter().cloned())
                .stdin(Stdio::null())
                .stdout(Stdio::from(output.try_clone()?))
                .stderr(Stdio::from(errors.try_clone()?))
                .process_group(0)
                .spawn()
                .with_context(|| {
                    format!("start boot helper {program}", program = program.display())
                })?;
            let group = Pid::from_child(&child);
            batch.children.push(OwnedChild {
                child: Some(child),
                group,
                reap_orphans: false,
            });
            files.push((output, errors));
        }

        let mut statuses = vec![None; arguments.len()];
        while statuses.iter().any(Option::is_none) {
            for (index, child) in batch.children.iter_mut().enumerate() {
                if statuses[index].is_some() {
                    continue;
                }
                let (output, errors) = &files[index];
                let limited = Instant::now() >= deadline
                    || output.metadata()?.len() > OUTPUT_LIMIT
                    || errors.metadata()?.len() > OUTPUT_LIMIT;
                if limited || exited(child.group)? {
                    statuses[index] = Some((child.finish()?, limited));
                }
            }
            if statuses.iter().any(Option::is_none) {
                thread::sleep(Duration::from_millis(20));
            }
        }
        // No sibling is still running when adopted descendants are inspected and killed.
        reap_descendants(Instant::now() + CLEANUP_TIMEOUT)?;

        files
            .into_iter()
            .zip(statuses)
            .map(|((output, errors), status)| {
                let (status, limited) = status.context("missing boot worker status")?;
                let limited = limited
                    || output.metadata()?.len() > OUTPUT_LIMIT
                    || errors.metadata()?.len() > OUTPUT_LIMIT;
                Ok(Captured {
                    stdout: contents(output)?,
                    stderr: contents(errors)?,
                    status,
                    limited,
                })
            })
            .collect()
    }

    /// Enter deployment execution and record subsequent helper evidence.
    /// Direct lifecycle commands require checked requests, including through capture/stream.
    pub fn record_to(&self, path: std::path::PathBuf) -> Result<()> {
        crate::state::directory(&path)?;
        *self.log.borrow_mut() = Some(path);
        Ok(())
    }

    /// Refuse raw deployment lifecycle commands; boot and maintenance retain separate policies.
    fn check_raw(&self, program: &OsStr, args: &[OsString]) -> Result<()> {
        ensure!(
            self.log.borrow().is_none()
                || ![
                    "qvm-start",
                    "qvm-shutdown",
                    "qvm-kill",
                    "qvm-create",
                    "qvm-remove"
                ]
                .iter()
                .any(|name| std::path::Path::new(program).file_name() == Some(OsStr::new(name))),
            "deployment lifecycle command requires a verified request"
        );
        let name = std::path::Path::new(program).file_name();
        if self.log.borrow().is_some()
            && (name == Some(OsStr::new("qvm-device")) || name == Some(OsStr::new("qvm-pci")))
        {
            ensure!(
                name == Some(OsStr::new("qvm-device"))
                    && args.get(1).is_some_and(|action| ["list", "ls", "info"]
                        .iter()
                        .any(|read| action == OsStr::new(read))),
                "deployment device mutation requires a verified request"
            );
        }
        if self.log.borrow().is_some() && name == Some(OsStr::new("qvm-volume")) {
            ensure!(
                args.first().is_some_and(|action| ["list", "ls", "info"]
                    .iter()
                    .any(|read| action == OsStr::new(read))),
                "deployment volume mutation requires a verified request"
            );
        }
        Ok(())
    }

    /// Boot/admission/maintenance host operations cannot bypass a deployment request.
    pub(crate) fn require_separate_host_policy(&self) -> Result<()> {
        ensure!(
            self.log.borrow().is_none(),
            "deployment host mutation requires a verified request"
        );
        Ok(())
    }

    /// Explicit maintenance removal requires publication and cannot run through deployment policy.
    pub(crate) fn purge_remove<'a>(
        &self,
        request: airlock_deployment_core::purge::RemoveRequest<'a>,
    ) -> Result<airlock_deployment_core::purge::PurgeCleanup<'a>> {
        self.require_manual_setup()?;
        let args = request
            .arguments()
            .into_iter()
            .map(OsString::from)
            .collect::<Vec<_>>();
        let output = self.capture_inner(
            OsStr::new("qvm-remove"),
            &args,
            Duration::from_secs(60),
            &[],
        )?;
        Self::successful(OsStr::new("qvm-remove"), output)?;
        Ok(request.removed())
    }

    /// Keep a checked retirement baseline reachable under its transaction/VM identity.
    pub(crate) fn retirement_pin(
        &self,
        request: airlock_deployment_core::retirement::RetirementPin<'_>,
        root: &str,
    ) -> Result<()> {
        ensure!(
            self.log.borrow().is_some(),
            "deployment command journal is not configured"
        );
        let args = request
            .arguments(root)
            .into_iter()
            .map(OsString::from)
            .collect::<Vec<_>>();
        let captured =
            self.capture_inner(OsStr::new("nix-store"), &args, Duration::from_secs(60), &[])?;
        Self::successful(OsStr::new("nix-store"), captured)?;
        Ok(())
    }

    /// Apply only fixed reversible VM/tag/retention mutations from a verified request.
    pub(crate) fn retirement_deployment(
        &self,
        request: &airlock_deployment_core::retirement::RetirementRequest<'_>,
    ) -> Result<()> {
        ensure!(
            self.log.borrow().is_some(),
            "deployment command journal is not configured"
        );
        let mut commands = Vec::new();
        if let Some(args) = request.autostart_arguments() {
            commands.push(("qvm-prefs", args));
        }
        commands.push(("qvm-tags", request.tag_arguments()));
        if let Some(args) = request.retention_arguments() {
            commands.push((request.retention_program(), args));
        }
        for (program, args) in commands {
            let args = args.into_iter().map(OsString::from).collect::<Vec<_>>();
            let captured =
                self.capture_inner(OsStr::new(program), &args, Duration::from_secs(60), &[])?;
            Self::successful(OsStr::new(program), captured)?;
        }
        Ok(())
    }

    /// Dispatch only verified host/Nix arguments and the adapter captured before publication.
    pub(crate) fn host_deployment(
        &self,
        request: &airlock_deployment_core::host::HostRequest<'_>,
        root: &str,
    ) -> Result<String> {
        use airlock_deployment_core::host::Action;
        ensure!(
            self.log.borrow().is_some(),
            "deployment command journal is not configured"
        );
        ensure!(
            !matches!(request.action(), Action::InstallController),
            "controller publication requires the filesystem adapter"
        );
        let args = request
            .arguments(root)
            .into_iter()
            .map(OsString::from)
            .collect::<Vec<_>>();
        let timeout = if matches!(request.action(), Action::InstallBoot) {
            600
        } else {
            60
        };
        let program = OsStr::new(request.program());
        let captured = self.capture_inner(program, &args, Duration::from_secs(timeout), &[])?;
        Self::successful(program, captured)
    }

    /// Dispatch the exact checked VM name; there is no independent target or argument input.
    /// Qubes' faithful execution and any implicit dependency starts are external assumptions.
    pub fn start_deployment(
        &self,
        request: airlock_deployment_core::effects::StartRequest<'_>,
    ) -> Result<String> {
        ensure!(
            self.log.borrow().is_some(),
            "deployment command journal is not configured"
        );
        let captured = self.capture_inner(
            OsStr::new("qvm-start"),
            &[request.target().into()],
            Duration::from_secs(240),
            &[],
        )?;
        Self::successful(OsStr::new("qvm-start"), captured)
    }

    /// Dispatch the exact checked target and GUI force mode with the existing timeout policy.
    /// Qubes may kill the same target after 120 seconds; clients are never command targets.
    pub fn shutdown_deployment(
        &self,
        request: airlock_deployment_core::effects::ShutdownRequest<'_>,
    ) -> Result<String> {
        ensure!(
            self.log.borrow().is_some(),
            "deployment command journal is not configured"
        );
        let args: Vec<OsString> = request.arguments().into_iter().map(Into::into).collect();

        let captured = self.capture_inner(
            OsStr::new("qvm-shutdown"),
            &args,
            Duration::from_secs(150),
            &[],
        )?;
        Self::successful(OsStr::new("qvm-shutdown"), captured)
    }

    /// Transaction-local setup receipts; observation of this path grants no execution authority.
    pub(crate) fn configuration_log_directory(&self) -> Result<std::path::PathBuf> {
        Ok(self
            .log
            .borrow()
            .as_ref()
            .context("missing deployment journal")?
            .parent()
            .context("missing transaction directory")?
            .join("setup"))
    }

    /// Manual/boot reconciliation cannot dispatch through an active deployment runner.
    pub(crate) fn require_manual_setup(&self) -> Result<()> {
        ensure!(
            self.log.borrow().is_none(),
            "manual setup cannot bypass deployment requests"
        );
        Ok(())
    }

    /// Dispatch only the checked VM creation argv.
    pub(crate) fn create_deployment(
        &self,
        request: airlock_deployment_core::configuration::CreateRequest<'_>,
    ) -> Result<String> {
        self.configuration_call("qvm-create", request.arguments())
    }

    /// Dispatch the fixed tool, target and key/value retained by the verified setting request.
    pub(crate) fn setting_deployment(
        &self,
        request: airlock_deployment_core::configuration::SettingRequest<'_>,
    ) -> Result<String> {
        self.configuration_call(request.program(), request.arguments())
    }

    /// Invoke only the selected admitted global/legacy setup entry mode.
    pub(crate) fn configuration_batch(
        &self,
        request: airlock_deployment_core::configuration::BatchRequest<'_>,
    ) -> Result<String> {
        self.configuration_call(request.program(), request.arguments())
    }

    /// Select the Rust protocol or the recognized legacy usage response, refusing uncertainty.
    pub(crate) fn configuration_protocol(
        &self,
        request: airlock_deployment_core::configuration::BatchRequest<'_>,
    ) -> Result<SetupProtocol> {
        let args = request
            .arguments()
            .into_iter()
            .map(OsString::from)
            .collect::<Vec<_>>();
        let captured = self.capture_inner(
            OsStr::new(request.program()),
            &args,
            Duration::from_secs(30),
            &self.configuration_environment()?,
        )?;
        Self::configuration_version(&captured)
    }

    /// Negotiate an admitted boot helper using the same fail-closed protocol rules as deployment.
    pub(crate) fn boot_setup_protocol(&self, program: &str) -> Result<SetupProtocol> {
        let captured = self.capture_inner(
            OsStr::new(program),
            &["--protocol".into()],
            Duration::from_secs(30),
            &[],
        )?;
        Self::configuration_version(&captured)
    }

    /// Unknown versions and failed/limited queries cannot downgrade to legacy execution.
    fn configuration_version(captured: &Captured) -> Result<SetupProtocol> {
        ensure!(
            !captured.limited,
            "setup protocol query exceeded its limits"
        );
        if captured.status.success() {
            match captured.stdout.as_slice() {
                b"airlock.setup.v4\n" => Ok(SetupProtocol::Covered),
                b"airlock.setup.v3\n" => Ok(SetupProtocol::Bound),
                b"airlock.setup.v2\n" => Ok(SetupProtocol::UnboundNative),
                _ => anyhow::bail!("unsupported setup protocol response"),
            }
        } else {
            ensure!(
                captured.status.code() == Some(1)
                    && captured.stdout.is_empty()
                    && captured.stderr.starts_with(b"Usage: airlock-setup-config "),
                "setup protocol query failed without a recognized legacy response"
            );
            Ok(SetupProtocol::Legacy)
        }
    }

    /// Fixed transaction-local receipts and staged generations, with no caller-supplied environment.
    fn configuration_environment(&self) -> Result<Vec<(OsString, OsString)>> {
        let log = self.log.borrow();
        let transaction = log
            .as_ref()
            .context("deployment command journal is not configured")?
            .parent()
            .context("missing deployment transaction directory")?;
        Ok(vec![
            (
                "AIRLOCK_LOG_DIR".into(),
                transaction.join("setup").into_os_string(),
            ),
            (
                "AIRLOCK_STAGED_GENERATIONS".into(),
                transaction.join("staged.json").into_os_string(),
            ),
            (
                "AIRLOCK_SETUP_RUN_ID".into(),
                transaction
                    .file_name()
                    .context("missing attempt directory")?
                    .to_owned(),
            ),
        ])
    }

    /// External execution is trusted; all command parameters have already been fixed by a request.
    fn configuration_call(&self, program: &str, args: Vec<String>) -> Result<String> {
        let args = args.into_iter().map(OsString::from).collect::<Vec<_>>();
        let captured = self.capture_inner(
            OsStr::new(program),
            &args,
            Duration::from_secs(600),
            &self.configuration_environment()?,
        )?;
        Self::successful(OsStr::new(program), captured)
    }

    /// Run a file-backed transfer under a deadline and clean up all owned descendants.
    pub(crate) fn files(
        &self,
        program: &str,
        args: &[OsString],
        timeout: Duration,
        env: &[(OsString, OsString)],
        files: Files<'_>,
    ) -> Result<ExitStatus> {
        self.check_raw(OsStr::new(program), args)?;
        rustix::process::set_child_subreaper(Some(rustix::process::getpid()))?;
        let output = File::create(files.output)?;
        let errors = File::create(files.errors)?;
        let input = match files.input {
            Some(input) => Stdio::from(File::open(input)?),
            None => Stdio::null(),
        };
        let child = Command::new(program)
            .args(args)
            .env_remove("AIRLOCK_STAGED_GENERATIONS")
            .envs(env.iter().cloned())
            .stdin(input)
            .stdout(Stdio::from(output.try_clone()?))
            .stderr(Stdio::from(errors.try_clone()?))
            .process_group(0)
            .spawn()
            .with_context(|| format!("start {program}"))?;
        let group = Pid::from_child(&child);
        let mut child = OwnedChild {
            child: Some(child),
            group,
            reap_orphans: true,
        };
        let deadline = Instant::now()
            .checked_add(timeout)
            .context("command timeout too large")?;
        while !exited(group)? {
            ensure!(Instant::now() < deadline, "{program}: transfer timed out");
            ensure!(
                output.metadata()?.len() <= files.limit && errors.metadata()?.len() <= OUTPUT_LIMIT,
                "{program}: transfer output limit exceeded"
            );
            thread::sleep(Duration::from_millis(20));
        }
        let status = child.finish()?;
        ensure!(
            output.metadata()?.len() <= files.limit && errors.metadata()?.len() <= OUTPUT_LIMIT,
            "{program}: transfer output limit exceeded"
        );
        Ok(status)
    }

    /// Forward a duplex storage protocol without buffering or interpreting its payload.
    pub fn stream(&self, program: &str, args: &[OsString], timeout: Duration) -> Result<()> {
        self.check_raw(OsStr::new(program), args)?;
        rustix::process::set_child_subreaper(Some(rustix::process::getpid()))?;
        let child = Command::new(program)
            .args(args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .process_group(0)
            .spawn()?;
        let group = Pid::from_child(&child);
        let mut owned = OwnedChild {
            child: Some(child),
            group,
            reap_orphans: true,
        };
        let deadline = Instant::now() + timeout;
        while !exited(group)? {
            ensure!(Instant::now() < deadline, "{program}: protocol timed out");
            thread::sleep(Duration::from_millis(20));
        }
        if !owned.finish()?.success() {
            return Err(ProtocolFailed.into());
        }
        Ok(())
    }

    /// Capture bounded helper output under a time limit and reap owned descendants on every outcome.
    pub fn run(
        &self,
        program: impl AsRef<OsStr>,
        args: &[OsString],
        timeout: Duration,
        env: &[(OsString, OsString)],
    ) -> Result<String> {
        let captured = self.capture(program.as_ref(), args, timeout, env)?;
        Self::successful(program.as_ref(), captured)
    }

    /// Interpret captured evidence identically for checked starts and other helpers.
    fn successful(program: &OsStr, captured: Captured) -> Result<String> {
        let stdout = String::from_utf8(captured.stdout)?;
        let stderr = String::from_utf8(captured.stderr)?;
        ensure!(
            !captured.limited,
            "{program} exceeded its time or output limit",
            program = program.to_string_lossy()
        );
        ensure!(
            captured.status.success(),
            "{program} failed ({status}): {stderr}",
            program = program.to_string_lossy(),
            status = captured.status,
            stderr = stderr.trim()
        );

        Ok(stdout.trim().to_owned())
    }

    /// Collect helper evidence even after failure, enforcing the same limits and cleanup as `run`.
    pub fn capture(
        &self,
        program: impl AsRef<OsStr>,
        args: &[OsString],
        timeout: Duration,
        env: &[(OsString, OsString)],
    ) -> Result<Captured> {
        self.check_raw(program.as_ref(), args)?;
        self.capture_inner(program.as_ref(), args, timeout, env)
    }

    /// Spawn after the public entry point has selected either a checked request or a raw helper.
    fn capture_inner(
        &self,
        program: &OsStr,
        args: &[OsString],
        timeout: Duration,
        env: &[(OsString, OsString)],
    ) -> Result<Captured> {
        rustix::process::set_child_subreaper(Some(rustix::process::getpid()))?;

        let output = tempfile::tempfile()?;
        let errors = tempfile::tempfile()?;
        let mut command = Command::new(program);
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::from(output.try_clone()?))
            .stderr(Stdio::from(errors.try_clone()?))
            .process_group(0);
        command
            .env_remove("AIRLOCK_STAGED_GENERATIONS")
            .envs(env.iter().cloned());

        let child = command
            .spawn()
            .with_context(|| format!("start {program}", program = program.to_string_lossy()))?;
        let group = Pid::from_child(&child);
        let mut child = OwnedChild {
            child: Some(child),
            group,
            reap_orphans: true,
        };

        let deadline = Instant::now() + timeout;
        let mut limited = false;
        let status = loop {
            if exited(child.group)? {
                break child.finish()?;
            }
            if Instant::now() >= deadline
                || output.metadata()?.len() > OUTPUT_LIMIT
                || errors.metadata()?.len() > OUTPUT_LIMIT
            {
                limited = true;
                break child.finish()?;
            }
            thread::sleep(Duration::from_millis(20));
        };

        // A fast helper may exit between polls after exceeding its output budget.
        limited |=
            output.metadata()?.len() > OUTPUT_LIMIT || errors.metadata()?.len() > OUTPUT_LIMIT;

        let stdout = contents(output)?;
        let stderr = contents(errors)?;
        if let Some(directory) = self.log.borrow().as_ref() {
            let id = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos();
            crate::state::save(
                &directory.join(format!("command-{id}.json")),
                &serde_json::json!({"program":program.to_string_lossy(),"args":args.iter().map(|s| s.to_string_lossy()).collect::<Vec<_>>(),"status":status.code(),"limited":limited,"stdout":String::from_utf8_lossy(&stdout),"stderr":String::from_utf8_lossy(&stderr),"elapsed_seconds":timeout.saturating_sub(deadline.saturating_duration_since(Instant::now())).as_secs_f64()}),
            )?;
        }
        Ok(Captured {
            stdout,
            stderr,
            status,
            limited,
        })
    }

    /// Run a helper with default limits and return UTF-8 output only after successful exit.
    pub fn text(&self, program: &str, args: &[&str]) -> Result<String> {
        self.run(
            program,
            &args.iter().map(OsString::from).collect::<Vec<_>>(),
            Duration::from_secs(60),
            &[],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    /// Both helpers must enter before the first exits; the later sibling must survive cleanup.
    #[test]
    fn boot_workers_overlap_and_keep_siblings_until_completion() -> Result<()> {
        let root = tempfile::tempdir()?;
        let environment = [(
            "AIRLOCK_BOOT_WORKER_FIXTURE".into(),
            root.path().as_os_str().to_owned(),
        )];
        let arguments = ["boot_worker_fast", "boot_worker_slow"].map(|name| {
            vec![
                "--ignored".into(),
                "--exact".into(),
                format!("process::tests::{name}").into(),
            ]
        });
        let runner = Runner::default();
        let executable = std::env::current_exe()?;
        let outputs = runner.boot_workers(
            &executable,
            &arguments,
            Duration::from_secs(5),
            &environment,
        )?;
        for output in outputs {
            assert!(
                output.status.success() && !output.limited,
                "{error}",
                error = String::from_utf8_lossy(&output.stdout)
            );
        }
        assert!(root.path().join("slow-finished").exists());

        let output = runner.boot_workers(
            &executable,
            &arguments[1..],
            Duration::from_millis(100),
            &environment,
        )?;
        assert!(output[0].limited);
        let pid = std::fs::read_to_string(root.path().join("slow-pid"))?;
        assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
        Ok(())
    }

    /// Child fixture used only by the batch test's separately executed test binary.
    #[test]
    #[ignore = "internal subprocess fixture for boot_workers_overlap_and_keep_siblings_until_completion"]
    fn boot_worker_fast() -> Result<()> {
        let root = std::path::PathBuf::from(
            std::env::var_os("AIRLOCK_BOOT_WORKER_FIXTURE").context("worker fixture root")?,
        );
        std::fs::write(root.join("fast-started"), b"")?;
        let deadline = Instant::now() + Duration::from_secs(2);
        while !root.join("slow-started").exists() {
            ensure!(
                Instant::now() < deadline,
                "sibling was not started concurrently"
            );
            thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }

    /// Remain alive after the first helper exits so premature process-wide cleanup is observable.
    #[test]
    #[ignore = "internal subprocess fixture for boot_workers_overlap_and_keep_siblings_until_completion"]
    fn boot_worker_slow() -> Result<()> {
        let root = std::path::PathBuf::from(
            std::env::var_os("AIRLOCK_BOOT_WORKER_FIXTURE").context("worker fixture root")?,
        );
        std::fs::write(root.join("slow-pid"), std::process::id().to_string())?;
        std::fs::write(root.join("slow-started"), b"")?;
        thread::sleep(Duration::from_millis(300));
        std::fs::write(root.join("slow-finished"), b"")?;
        Ok(())
    }

    /// Every process entry checks raw device mutations before spawning; maintenance keeps its policy.
    #[test]
    fn raw_device_mutations_require_a_deployment_request() -> Result<()> {
        let runner = Runner::default();
        let args = ["pci", "unassign", "usr-assistant", "dom0:01_00.0:*"].map(OsString::from);
        runner.check_raw(OsStr::new("qvm-device"), &args)?;
        let log = tempfile::tempdir()?;
        // Configure an inert log directly; production requires a root-owned machine directory.
        *runner.log.borrow_mut() = Some(log.path().join("commands"));
        assert!(
            runner
                .check_raw(OsStr::new("/usr/bin/qvm-device"), &args)
                .is_err()
        );
        assert!(runner.check_raw(OsStr::new("qvm-pci"), &args).is_err());
        for action in ["list", "ls", "info"] {
            runner.check_raw(
                OsStr::new("qvm-device"),
                &["pci", action].map(OsString::from),
            )?;
        }
        assert!(
            runner
                .capture("qvm-device", &args, Duration::from_secs(1), &[])
                .is_err()
        );
        assert!(
            runner
                .stream("qvm-device", &args, Duration::from_secs(1))
                .is_err()
        );
        assert!(
            runner
                .files(
                    "qvm-device",
                    &args,
                    Duration::from_secs(1),
                    &[],
                    Files {
                        input: None,
                        output: &log.path().join("out"),
                        errors: &log.path().join("err"),
                        limit: 1024
                    }
                )
                .is_err()
        );
        assert!(!log.path().join("out").exists());
        Ok(())
    }

    /// Storage mutation and deletion cannot be smuggled through raw deployment process calls.
    #[test]
    fn raw_volume_and_remove_commands_require_separate_authority() -> Result<()> {
        let runner = Runner::default();
        runner.check_raw(
            OsStr::new("qvm-remove"),
            &["--force", "vm"].map(OsString::from),
        )?;
        *runner.log.borrow_mut() = Some("/inert/commands".into());
        for action in ["import", "resize", "clone", "revert", "extend"] {
            assert!(
                runner
                    .check_raw(
                        OsStr::new("/usr/bin/qvm-volume"),
                        &[action, "vm:private"].map(OsString::from)
                    )
                    .is_err()
            );
        }
        for action in ["list", "ls", "info"] {
            runner.check_raw(
                OsStr::new("qvm-volume"),
                &[action, "vm:private"].map(OsString::from),
            )?;
        }
        assert!(
            runner
                .check_raw(
                    OsStr::new("qvm-remove"),
                    &["--force", "vm"].map(OsString::from)
                )
                .is_err()
        );
        Ok(())
    }

    /// Only the exact supported protocol or known old-script usage response selects execution.
    #[test]
    fn setup_protocol_rejects_unknown_and_uncertain_responses() {
        let mut output = Captured {
            stdout: b"airlock.setup.v2\n".to_vec(),
            stderr: vec![],
            status: ExitStatus::from_raw(0),
            limited: false,
        };
        assert_eq!(
            Runner::configuration_version(&output).unwrap(),
            SetupProtocol::UnboundNative
        );
        output.stdout = b"airlock.setup.v3\n".to_vec();
        assert_eq!(
            Runner::configuration_version(&output).unwrap(),
            SetupProtocol::Bound
        );
        output.stdout = b"airlock.setup.v4\n".to_vec();
        assert_eq!(
            Runner::configuration_version(&output).unwrap(),
            SetupProtocol::Covered
        );
        for unexpected in [b"".as_slice(), b"airlock.setup.v5\n".as_slice()] {
            output.stdout = unexpected.to_vec();
            assert!(Runner::configuration_version(&output).is_err());
        }
        output.stdout.clear();
        output.status = ExitStatus::from_raw(1 << 8);
        assert!(Runner::configuration_version(&output).is_err());
        output.stderr = b"Usage: airlock-setup-config (--plan|--apply)\n".to_vec();
        assert_eq!(
            Runner::configuration_version(&output).unwrap(),
            SetupProtocol::Legacy
        );
        output.limited = true;
        assert!(Runner::configuration_version(&output).is_err());
        output.limited = false;
        output.status = ExitStatus::from_raw(2 << 8);
        assert!(Runner::configuration_version(&output).is_err());
    }
}
