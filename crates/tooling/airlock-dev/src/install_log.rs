//! A USB install transcript observes output without reading credentials or changing child protocols.

use crate::support;
use airlock_nix_core::runtime::{process::OwnedChild, progress};
use anyhow::{Context, Result, ensure};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fs::{OFlags, fcntl_getfl, fcntl_setfl},
};
use serde::Serialize;
use signal_hook::{
    consts::signal::{SIGHUP, SIGINT, SIGTERM},
    iterator::Signals,
};
use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{
        fs::{DirBuilderExt, OpenOptionsExt, symlink},
        process::ExitStatusExt,
    },
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// One install attempt, published before executing any build or source validation.
#[derive(Serialize)]
struct Summary {
    /// Stable format for workstation agents inspecting completed or active runs.
    schema: &'static str,
    /// Literal child argument vector, never reconstructed as executable shell text.
    command: Vec<String>,
    /// Checkout from which the user requested installation.
    repository: PathBuf,
    /// Directory inherited by the command, including Makefile selection.
    working_directory: PathBuf,
    /// Requested hardware identity, exported by Make without collecting other environment values.
    usb_serial: Option<String>,
    /// Committed source observed at invocation; the installer validates its captured source separately.
    revision: Option<String>,
    /// Machine checkout revision observed at invocation.
    machine_revision: Option<String>,
    /// Logger process, useful when distinguishing a running attempt from a stale record.
    pid: u32,
    /// UTC start time, for humans and directory ordering.
    started_at: String,
    /// UTC finish time; absent while the command runs.
    finished_at: Option<String>,
    /// Total duration measured by this process's monotonic clock.
    elapsed_seconds: f64,
    /// Running, succeeded, failed, or interrupted; no success is inferred from build output.
    status: &'static str,
    /// Actual child exit code, or the conventional 128 plus termination signal.
    exit_code: Option<u8>,
    /// Received or child termination signal, when interruption caused the outcome.
    signal: Option<i32>,
    /// Local observation or logging failure, separate from child diagnostics in console.log.
    error: Option<String>,
    /// Most recent observation of each timed stage, including nested build phases.
    phases: Vec<progress::Event>,
}

/// Disk output and line framing are bounded independently of the child's output volume.
struct Transcript {
    /// Unbuffered transcript file; readers can follow a still-running command.
    file: File,
    /// Monotonic origin shared by all displayed elapsed times.
    started: Instant,
    /// Whether each terminal stream needs a fresh timestamp prefix.
    starts: [bool; 2],
    /// Last stream written to the merged file; switches delimit partial lines.
    stream: Option<usize>,
    /// Partial progress frames only; ordinary output is forwarded immediately.
    lines: [Vec<u8>; 2],
    /// Overlong lines are forwarded but cannot be interpreted as bounded progress frames.
    overflow: [bool; 2],
    /// First disk failure; continue draining the child rather than abandoning provisioning midway.
    error: Option<String>,
}

impl Transcript {
    fn write(&mut self, stream: usize, bytes: &[u8], summary: &mut Summary) {
        for part in bytes.split_inclusive(|byte| *byte == b'\n') {
            let prefix = format!(
                "{time} +{elapsed:08.3}s [{name}] ",
                time = timestamp(SystemTime::now()),
                elapsed = self.started.elapsed().as_secs_f64(),
                name = ["stdout", "stderr"][stream],
            );
            let mut terminal = Vec::new();
            if self.starts[stream] {
                terminal.extend_from_slice(prefix.as_bytes());
            }
            terminal.extend_from_slice(part);
            let output: &mut dyn Write = if stream == 0 {
                &mut io::stdout()
            } else {
                &mut io::stderr()
            };
            // A closed viewer (for example `head`) must not discard the retained transcript.
            let _ = output.write_all(&terminal).and_then(|()| output.flush());

            let disk = (|| -> io::Result<()> {
                if self.stream != Some(stream) && self.stream.is_some_and(|last| !self.starts[last])
                {
                    self.file.write_all(b"\n")?;
                }
                if self.starts[stream] || self.stream != Some(stream) {
                    self.file.write_all(prefix.as_bytes())?;
                }
                self.file.write_all(part)
            })();
            if let Err(error) = disk {
                self.error.get_or_insert_with(|| error.to_string());
            }
            self.stream = Some(stream);
            self.starts[stream] = part.ends_with(b"\n");

            if !self.overflow[stream] {
                if self.lines[stream].len() + part.len() <= 8192 {
                    self.lines[stream].extend_from_slice(part);
                } else {
                    self.overflow[stream] = true;
                    self.lines[stream].clear();
                }
            }
            if part.ends_with(b"\n") {
                if let Some(frame) = self.lines[stream].strip_prefix(b"@airlock-progress ")
                    && let Ok(event) = serde_json::from_slice::<progress::Event>(frame)
                    && event.schema == "airlock.progress.v1"
                {
                    if let Some(previous) = summary
                        .phases
                        .iter_mut()
                        .find(|previous| previous.id == event.id)
                    {
                        *previous = event;
                    } else if summary.phases.len() < 4096 {
                        summary.phases.push(event);
                    }
                }
                self.lines[stream].clear();
                self.overflow[stream] = false;
            }
        }
    }
}

/// Format UTC directly, without spawning a command for every output line.
fn timestamp(time: SystemTime) -> String {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Gregorian civil date conversion; the offset moves the epoch to March 1.
    let days = (seconds / 86400) as i64 + 719468;
    let era = days / 146097;
    let day_of_era = days - era * 146097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = month_index + if month_index < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    let hour = seconds / 3600 % 24;
    let minute = seconds / 60 % 60;
    let second = seconds % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Atomically replace a relative convenience link; readers never see a partial pathname.
fn recent(parent: &Path, name: &str, run: &Path) -> Result<()> {
    let temporary = tempfile::Builder::new()
        .prefix(".link-")
        .tempdir_in(parent)?;
    let link = temporary.path().join("link");
    symlink(run.file_name().context("run directory name")?, &link)?;
    fs::rename(link, parent.join(name))?;
    Ok(())
}

fn code(status: ExitStatus) -> u8 {
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1))
        .try_into()
        .unwrap_or(1)
}

/// Time a child without capturing stdin or either output stream; private stdout protocols remain intact.
pub(crate) fn phase(stage: &str, arguments: &[OsString]) -> Result<u8> {
    ensure!(!arguments.is_empty(), "build phase requires a command");
    let span = progress::Span::start(stage);
    let status = Command::new(&arguments[0]).args(&arguments[1..]).status()?;
    if status.success() {
        span.complete();
    }
    Ok(code(status))
}

/// Start a private transcript before source checks, and retain its outcome even if spawning fails.
pub(crate) fn run(root: &Path, arguments: &[OsString]) -> Result<u8> {
    ensure!(!arguments.is_empty(), "USB install log requires a command");
    let parent = std::env::var_os("AIRLOCK_LOG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join(".airlock-logs"))
        .join("usb-install");
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&parent)?;
    let parent = fs::canonicalize(parent)?;
    // Serialize creation and latest publication so overlapping starts cannot move the link backwards.
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(parent.join(".latest.lock"))?;
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive)?;
    let started_at = timestamp(SystemTime::now());
    let run = tempfile::Builder::new()
        .prefix(&format!("{started_at}-"))
        .tempdir_in(&parent)?
        .keep();
    let mut transcript = Transcript {
        file: OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(run.join("console.log"))?,
        started: Instant::now(),
        starts: [true; 2],
        stream: None,
        lines: [Vec::new(), Vec::new()],
        overflow: [false; 2],
        error: None,
    };
    let mut summary = Summary {
        schema: "airlock.usb-install.v1",
        command: arguments
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect(),
        repository: root.to_owned(),
        working_directory: std::env::current_dir()?,
        usb_serial: std::env::var("USB_SERIAL").ok(),
        revision: None,
        machine_revision: None,
        pid: std::process::id(),
        started_at,
        finished_at: None,
        elapsed_seconds: 0.0,
        status: "running",
        exit_code: None,
        signal: None,
        error: None,
        phases: Vec::new(),
    };
    let summary_path = run.join("summary.json");
    support::record(&summary_path, &summary)?;
    recent(&parent, "latest", &run)?;
    drop(lock);
    transcript.write(
        1,
        format!(
            "USB install log: {path}\n",
            path = run.join("console.log").display()
        )
        .as_bytes(),
        &mut summary,
    );
    summary.revision = support::git(root, &["rev-parse", "HEAD"]).ok();
    summary.machine_revision =
        support::git(&root.join("airlock-machine"), &["rev-parse", "HEAD"]).ok();
    support::record(&summary_path, &summary)?;

    let outcome = observe(arguments, &mut transcript, &mut summary, &summary_path);
    if let Err(error) = &outcome {
        summary.error = Some(format!("{error:#}"));
        transcript.write(
            1,
            format!("USB install logger: {error:#}\n").as_bytes(),
            &mut summary,
        );
    }
    if let Err(error) = transcript.file.sync_all() {
        transcript.error.get_or_insert_with(|| error.to_string());
    }
    if let Some(error) = &transcript.error {
        summary.error = Some(format!("writing console.log: {error}"));
    }
    let child_exit = outcome.unwrap_or(1);
    let exit = if child_exit == 0 && transcript.error.is_some() {
        1
    } else {
        child_exit
    };
    summary.elapsed_seconds = transcript.started.elapsed().as_secs_f64();
    summary.finished_at = Some(timestamp(SystemTime::now()));
    summary.exit_code = Some(exit);
    summary.status = if summary.signal.is_some() {
        "interrupted"
    } else if exit == 0 {
        "succeeded"
    } else {
        "failed"
    };
    for event in &mut summary.phases {
        if matches!(event.state.as_str(), "started" | "progress" | "heartbeat") {
            event.state = "failed".into();
            event.error = Some("install command ended without a terminal stage event".into());
        }
    }
    transcript.write(
        1,
        format!(
            "USB install {status}; exit={exit}; elapsed={elapsed:.3}s; summary={path}\n",
            status = summary.status,
            elapsed = summary.elapsed_seconds,
            path = summary_path.display()
        )
        .as_bytes(),
        &mut summary,
    );
    support::record(&summary_path, &summary)?;
    if exit != 0 {
        recent(&parent, "latest-failed", &run)?;
    }
    Ok(exit)
}

/// Drain both pipes concurrently and forward partial lines without waiting for a newline.
fn observe(
    arguments: &[OsString],
    transcript: &mut Transcript,
    summary: &mut Summary,
    summary_path: &Path,
) -> Result<u8> {
    let mut signals = Signals::new([SIGINT, SIGTERM, SIGHUP])?;
    // Inherit the controlling terminal and foreground process group: sudo and ask-password
    // still use /dev/tty. Reading stdin here would risk recording secret input.
    let mut child = OwnedChild(
        Command::new(&arguments[0])
            .args(&arguments[1..])
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?,
    );
    let mut pipes: [Option<File>; 2] = [
        child
            .0
            .stdout
            .take()
            .map(|pipe| File::from(std::os::fd::OwnedFd::from(pipe))),
        child
            .0
            .stderr
            .take()
            .map(|pipe| File::from(std::os::fd::OwnedFd::from(pipe))),
    ];
    for pipe in pipes.iter().flatten() {
        fcntl_setfl(pipe, fcntl_getfl(pipe)? | OFlags::NONBLOCK)?;
    }
    let mut finished = None;
    let mut interrupted = None;
    let mut recorded = Instant::now();
    loop {
        for signal in signals.pending() {
            summary.signal.get_or_insert(signal);
            interrupted.get_or_insert_with(Instant::now);
            if finished.is_none()
                && let (Some(pid), Some(signal)) = (
                    rustix::process::Pid::from_raw(child.0.id() as i32),
                    rustix::process::Signal::from_named_raw(signal),
                )
            {
                let _ = rustix::process::kill_process(pid, signal);
            }
        }
        if interrupted.is_some_and(|time| time.elapsed() >= Duration::from_secs(10))
            && finished.is_none()
        {
            let _ = child.0.kill();
        }
        for (stream, pipe) in pipes.iter_mut().enumerate() {
            if let Some(input) = pipe {
                let mut bytes = [0; 16384];
                match input.read(&mut bytes) {
                    Ok(0) => *pipe = None,
                    Ok(size) => transcript.write(stream, &bytes[..size], summary),
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        if finished.is_none()
            && let Some(status) = child.0.try_wait()?
        {
            summary.signal = summary.signal.or(status.signal());
            finished = Some((status, Instant::now()));
        }
        if let Some((status, time)) = finished {
            if pipes.iter().all(Option::is_none) {
                return Ok(summary
                    .signal
                    .map_or_else(|| code(status), |signal| (128 + signal) as u8));
            }
            ensure!(
                time.elapsed() < Duration::from_secs(5),
                "child exited but descendants kept its output pipes open"
            );
        }
        if recorded.elapsed() >= Duration::from_secs(1) {
            summary.elapsed_seconds = transcript.started.elapsed().as_secs_f64();
            if let Err(error) = support::record(summary_path, summary) {
                transcript
                    .error
                    .get_or_insert_with(|| format!("updating summary: {error:#}"));
            }
            recorded = Instant::now();
        }
        let mut fds: Vec<_> = pipes
            .iter()
            .flatten()
            .map(|pipe| PollFd::new(pipe, PollFlags::IN))
            .collect();
        let timeout = Timespec {
            tv_sec: 0,
            tv_nsec: 50_000_000,
        };
        if let Err(error) = poll(&mut fds, Some(&timeout))
            && error != rustix::io::Errno::INTR
        {
            return Err(error.into());
        }
    }
}

#[cfg(test)]
mod tests;
