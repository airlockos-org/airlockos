//! Build observation stays on stderr and never changes a store receipt or package identity.
//! One sleeping reporter covers nested phases, including time spent waiting for external tools.

use anyhow::{Context, Result, ensure};
use clap::Args;
use std::{
    cell::RefCell,
    ffi::OsString,
    io::{self, Write},
    path::Path,
    process::Command,
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};

/// Build hooks use this wrapper when the underlying copy or move has no progress output.
#[derive(Args)]
pub(crate) struct Request {
    // Human-readable assembly phase, independent of the command's arguments.
    #[arg(long)]
    label: String,
    // Executable and literal arguments; no shell parsing or extra stdout receipt is introduced.
    #[arg(last = true, required = true, num_args = 1..)]
    command: Vec<OsString>,
}

/// One nested operation, whose counters describe completed work only.
struct Phase {
    // Concrete operation shown in the build log.
    name: String,
    // Monotonic clock retained while nested phases run.
    started: Instant,
    // Current object or file, without creating a line for every item.
    detail: String,
    // Completed and total bytes, set only when the total is known.
    bytes: Option<(u64, u64)>,
    // Tool currently being waited on; its arguments are deliberately omitted.
    command: Option<String>,
}

/// State shared with the sole reporter thread; it never participates in storage decisions.
struct State {
    // Build component used to distinguish interleaved Nix log lines.
    label: String,
    // Whole-operation elapsed time, including setup between phases.
    started: Instant,
    // Nested scopes; only the currently executing phase emits heartbeat lines.
    phases: Vec<Phase>,
    // Completed top-level phase timings; nested time is already included in these.
    timings: Vec<(String, Duration)>,
    // Best-effort log destination, replaceable by an in-memory observer in tests.
    emit: Arc<dyn Fn(&str) + Send + Sync>,
}

thread_local! {
    static ACTIVE: RefCell<Option<Arc<Mutex<State>>>> = const { RefCell::new(None) };
}

/// Restore an enclosing observer even if an operation unwinds.
struct Restore(
    // Previously selected observer, normally absent outside explicit image commands.
    Option<Arc<Mutex<State>>>,
);

impl Drop for Restore {
    fn drop(&mut self) {
        ACTIVE.with(|active| *active.borrow_mut() = self.0.take());
    }
}

/// Update only the observer attached to this synchronous image operation.
fn observe(operation: impl FnOnce(&mut State)) {
    ACTIVE.with(|active| {
        if let Some(state) = active.borrow().as_ref() {
            operation(&mut state.lock().unwrap_or_else(|error| error.into_inner()));
        }
    });
}

/// Format long phases without resetting minutes at an hour boundary.
fn elapsed(duration: Duration) -> String {
    let seconds = duration.as_secs();
    format!(
        "{minutes:02}:{seconds:02}",
        minutes = seconds / 60,
        seconds = seconds % 60
    )
}

impl State {
    /// Prefix a best-effort log record with its image component.
    fn line(&self, message: &str) {
        (self.emit)(&format!("{label}: {message}", label = self.label));
    }

    /// Describe live work without claiming a percentage for unknown totals.
    fn heartbeat(&self) {
        let Some(phase) = self.phases.last() else {
            self.line(&format!(
                "working, elapsed {time}",
                time = elapsed(self.started.elapsed())
            ));
            return;
        };
        let mut message = format!(
            "{name} — elapsed {time}",
            name = phase.name,
            time = elapsed(phase.started.elapsed())
        );
        if let Some((done, total)) = phase.bytes {
            message.push_str(&format!(
                " | {done:.2}/{total:.2} GiB",
                done = done as f64 / 1024f64.powi(3),
                total = total as f64 / 1024f64.powi(3)
            ));
        }
        if !phase.detail.is_empty() {
            message.push_str(&format!(" | {detail}", detail = phase.detail));
        }
        if let Some(command) = &phase.command {
            message.push_str(&format!(" | waiting for {command}"));
        }

        self.line(&message);
    }
}

/// Observe an explicit image operation without adding anything to stdout.
pub(super) fn run<T>(label: &str, operation: impl FnOnce() -> Result<T>) -> Result<T> {
    run_with(
        label,
        Duration::from_secs(5),
        Arc::new(|line| {
            let _ = writeln!(io::stderr().lock(), "{line}");
        }),
        operation,
    )
}

/// Inject time cadence and a log sink for bounded observation tests.
fn run_with<T>(
    label: &str,
    interval: Duration,
    emit: Arc<dyn Fn(&str) + Send + Sync>,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let state = Arc::new(Mutex::new(State {
        label: label.to_owned(),
        started: Instant::now(),
        phases: Vec::new(),
        timings: Vec::new(),
        emit,
    }));
    let _restore = Restore(ACTIVE.with(|active| active.replace(Some(state.clone()))));
    observe(|state| state.line("started"));

    let result = thread::scope(|scope| {
        let (stop, receiver) = mpsc::channel::<()>();
        let reporter = state.clone();
        scope.spawn(move || {
            while receiver.recv_timeout(interval) == Err(mpsc::RecvTimeoutError::Timeout) {
                reporter
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .heartbeat();
            }
        });

        let result = operation();
        drop(stop);
        result
    });

    observe(|state| {
        for (name, duration) in &state.timings {
            state.line(&format!("timing: {name} {time}", time = elapsed(*duration)));
        }
        state.line(&format!(
            "{outcome} after {time}",
            outcome = if result.is_ok() {
                "completed"
            } else {
                "failed"
            },
            time = elapsed(state.started.elapsed())
        ));
    });

    result
}

/// Report phase boundaries and retain inclusive timings without changing the result.
pub(super) fn phase<T>(name: &str, operation: impl FnOnce() -> Result<T>) -> Result<T> {
    observe(|state| {
        state.line(&format!("{name}…"));
        state.phases.push(Phase {
            name: name.to_owned(),
            started: Instant::now(),
            detail: String::new(),
            bytes: None,
            command: None,
        });
    });

    let result = operation();

    observe(|state| {
        if let Some(phase) = state.phases.pop() {
            let duration = phase.started.elapsed();
            state.line(&format!(
                "{name}: {outcome} after {time}{bytes}{detail}",
                outcome = if result.is_ok() {
                    "completed"
                } else {
                    "failed"
                },
                time = elapsed(duration),
                bytes = phase
                    .bytes
                    .map_or_else(String::new, |(done, total)| format!(
                        " | {done:.2}/{total:.2} GiB",
                        done = done as f64 / 1024f64.powi(3),
                        total = total as f64 / 1024f64.powi(3)
                    )),
                detail = if phase.detail.is_empty() {
                    String::new()
                } else {
                    format!(" | {detail}", detail = phase.detail)
                }
            ));
            if state.phases.is_empty() {
                state.timings.push((name.to_owned(), duration));
            }
        }
    });

    result
}

/// Replace the current work item; the reporter rate limits its display.
pub(super) fn detail(detail: &str) {
    observe(|state| {
        if let Some(phase) = state.phases.last_mut() {
            phase.detail = detail.to_owned();
        }
    });
}

/// Set a measured byte total before reading a known collection of files.
pub(super) fn bytes(total: u64) {
    observe(|state| {
        if let Some(phase) = state.phases.last_mut() {
            phase.bytes = Some((0, total));
        }
    });
}

/// Count bytes actually read; phases without a measured total remain indeterminate.
pub(super) fn advance(bytes: u64) {
    observe(|state| {
        if let Some(phase) = state.phases.last_mut()
            && let Some((done, _)) = &mut phase.bytes
        {
            *done = done.saturating_add(bytes);
        }
    });
}

/// Keep the current object visible while an external tool blocks.
pub(super) fn command<T>(program: &str, operation: impl FnOnce() -> Result<T>) -> Result<T> {
    let mut previous = None;
    observe(|state| {
        if let Some(phase) = state.phases.last_mut() {
            previous = phase.command.replace(
                Path::new(program)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned(),
            );
        }
    });

    let result = operation();

    observe(|state| {
        if let Some(phase) = state.phases.last_mut() {
            phase.command = previous;
        }
    });

    result
}

/// Inherit the wrapped tool's streams and fail the build when it fails.
pub(crate) fn execute(request: Request) -> Result<()> {
    run(&request.label, || {
        phase("Running tool", || {
            let program = &request.command[0];
            let status = command(&program.to_string_lossy(), || {
                Command::new(program)
                    .args(&request.command[1..])
                    .status()
                    .context("run image assembly tool")
            })?;
            ensure!(status.success(), "image assembly tool failed: {status}");
            Ok(())
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stalled tool remains observable before completion, and failures cannot print success.
    #[test]
    fn blocked_and_failed_phases_report_without_changing_results() {
        for fail in [false, true] {
            let lines = Arc::new(Mutex::new(Vec::new()));
            let captured = lines.clone();
            let (sender, receiver) = mpsc::channel();
            let result = run_with(
                "seed",
                Duration::from_millis(10),
                Arc::new(move |line| {
                    captured.lock().unwrap().push(line.to_owned());
                    if line.contains("waiting for tar") {
                        let _ = sender.send(());
                    }
                }),
                || {
                    phase("packages", || {
                        detail("1/2 objects, 1 added, 0 reused | package-a");
                        bytes(2 * 1024u64.pow(3));
                        advance(1024u64.pow(3));
                        command("/tools/tar", || {
                            receiver.recv_timeout(Duration::from_secs(3)).unwrap();
                            ensure!(!fail, "fixture failure");
                            Ok(17)
                        })
                    })
                },
            );

            assert_eq!(result.is_err(), fail);
            if !fail {
                assert_eq!(result.unwrap(), 17);
            }
            let lines = lines.lock().unwrap();
            assert!(lines.iter().any(|line| line.contains("1/2 objects")
                && line.contains("waiting for tar")
                && line.contains("1.00/2.00 GiB")));
            assert_eq!(lines.iter().any(|line| line.contains("completed")), !fail);
            assert_eq!(lines.iter().any(|line| line.contains("failed")), fail);
            assert!(ACTIVE.with(|active| active.borrow().is_none()));
        }
    }
}
