//! Request diagnostics travel on stderr; stdout remains the command's result protocol.
//! Remote events describe observations only and never supply paths or control decisions.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

const PREFIX: &str = "@airlock-progress ";
// Leave room for framing below Linux PIPE_BUF; shared stderr writers must not interleave JSON.
const MAX_EVENT: usize = 4000;
static NEXT: AtomicU64 = AtomicU64::new(1);

thread_local! {
    static RECORDER: RefCell<Option<Recorder>> = const { RefCell::new(None) };
    static ACTIVE: RefCell<BTreeMap<String, (Event, Instant)>> = const { RefCell::new(BTreeMap::new()) };
    static ACTIVITY_AT: RefCell<Option<Instant>> = const { RefCell::new(None) };
    static PULSE: RefCell<Option<Instant>> = const { RefCell::new(None) };
}

/// One locally timed stage event. Wall timestamps are informational across VMs.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    /// Version identifying this diagnostic protocol.
    pub schema: String,
    /// Span identity qualified by emitter, process, start time and local sequence.
    pub id: String,
    /// VM or computer which measured the duration.
    pub source: String,
    /// Concrete operation, such as packing or receiving artifacts.
    pub stage: String,
    /// Stage lifecycle: started, progress, heartbeat, completed or failed.
    pub state: String,
    /// Emitter's wall-clock Unix seconds, never subtracted across machines.
    pub timestamp: f64,
    /// Duration measured with the emitter's monotonic clock.
    pub elapsed_seconds: f64,
    /// Measured counters or a bounded current activity description.
    pub metrics: Value,
    /// Error associated with a failed stage.
    pub error: Option<String>,
}

/// A running stage; dropping an unfinished span records interruption rather than success.
pub struct Span {
    // Last emitted stage observation, including its most recent counters.
    event: Event,
    // Monotonic stage start, independent of wall-clock corrections.
    started: Instant,
    // Last counter publication, limiting disk and transport overhead.
    updated: Instant,
    // Whether a terminal event has already been emitted.
    finished: bool,
}

impl Span {
    /// Announce a stage immediately so blocked helpers remain visible to observers.
    pub fn start(stage: &str) -> Self {
        let source = fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap_or_else(|_| "unknown".into())
            .trim()
            .to_owned();
        let event = Event {
            schema: "airlock.progress.v1".into(),
            id: format!(
                "{source}:{pid}:{time}:{sequence}",
                pid = std::process::id(),
                time = super::now(),
                sequence = NEXT.fetch_add(1, Ordering::Relaxed)
            ),
            source,
            stage: stage.into(),
            state: "started".into(),
            timestamp: super::now(),
            elapsed_seconds: 0.0,
            metrics: json!({}),
            error: None,
        };
        emit(&event);
        Self {
            event,
            started: Instant::now(),
            updated: Instant::now(),
            finished: false,
        }
    }

    /// Publish actual counters, at most four times per second unless a stage finishes.
    pub fn update(&mut self, metrics: Value) {
        if let (Some(current), Some(update)) =
            (self.event.metrics.as_object_mut(), metrics.as_object())
        {
            current.extend(update.clone());
        }
        if self.updated.elapsed() >= Duration::from_millis(250) {
            self.publish("progress", None);
        }
    }

    /// Return the elapsed duration on this emitter's monotonic clock.
    pub fn elapsed_seconds(&self) -> f64 {
        self.started.elapsed().as_secs_f64()
    }

    /// Close a successful stage and retain its final counters.
    pub fn complete(mut self) {
        self.publish("completed", None);
        self.finished = true;
    }

    fn publish(&mut self, state: &str, error: Option<String>) {
        self.event.state = state.into();
        self.event.timestamp = super::now();
        self.event.elapsed_seconds = self.started.elapsed().as_secs_f64();
        self.event.error = error;
        emit(&self.event);
        self.updated = Instant::now();
    }
}

impl Drop for Span {
    fn drop(&mut self) {
        if !self.finished {
            self.publish("failed", Some("stage interrupted before completion".into()));
        }
    }
}

/// Measure an operation's success or failure without changing its return value.
pub fn phase<T, E: std::fmt::Display>(
    stage: &str,
    operation: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let mut span = Span::start(stage);
    let result = operation();
    span.publish(
        if result.is_ok() {
            "completed"
        } else {
            "failed"
        },
        result
            .as_ref()
            .err()
            .map(|error| error.to_string().chars().take(4096).collect()),
    );
    span.finished = true;
    result
}

fn emit(event: &Event) {
    ACTIVE.with_borrow_mut(|active| {
        if matches!(event.state.as_str(), "completed" | "failed") {
            active.remove(&event.id);
        } else if event.state != "heartbeat" {
            let started = active
                .get(&event.id)
                .map(|(_, start)| *start)
                .unwrap_or_else(Instant::now);
            active.insert(event.id.clone(), (event.clone(), started));
        }
    });
    observe(event);
    if let Some(frame) = wire(event) {
        let _ = io::stderr().lock().write_all(frame.as_bytes());
    }
}

/// Encode one atomic pipe write, retaining full local diagnostics but bounding remote detail text.
fn wire(event: &Event) -> Option<String> {
    let mut event = event.clone();
    event.error = event.error.map(|error| error.chars().take(512).collect());
    if let Some(activity) = event.metrics.get("activity").and_then(Value::as_str) {
        event.metrics["activity"] = json!(activity.chars().take(256).collect::<String>());
    }
    let mut bytes = serde_json::to_string(&event).ok()?;
    if bytes.len() > MAX_EVENT {
        event.metrics = json!({"details_truncated":true});
        bytes = serde_json::to_string(&event).ok()?;
    }
    (bytes.len() <= MAX_EVENT).then(|| format!("{PREFIX}{bytes}\n"))
}

/// Accept a bounded remote diagnostic frame. It carries no authorization or filesystem coordinates.
pub fn receive(line: &[u8]) -> bool {
    let Some(bytes) = line.strip_prefix(PREFIX.as_bytes()) else {
        return false;
    };
    if bytes.len() > MAX_EVENT {
        return false;
    }
    let Ok(event) = serde_json::from_slice::<Event>(bytes) else {
        return false;
    };
    if event.schema != "airlock.progress.v1"
        || !matches!(
            event.state.as_str(),
            "started" | "progress" | "heartbeat" | "completed" | "failed"
        )
        || event.id.len() > 256
        || event.source.len() > 128
        || event.stage.len() > 128
        || !event.metrics.is_object()
        || !event.elapsed_seconds.is_finite()
        || event.elapsed_seconds < 0.0
        || !event.timestamp.is_finite()
    {
        return false;
    }
    observe(&event);
    true
}

fn observe(event: &Event) {
    RECORDER.with_borrow_mut(|recorder| {
        if let Some(recorder) = recorder {
            // Observation failures cannot authorize, fail, or repeat a deployment.
            if let Err(error) = recorder.record(event) {
                eprintln!("progress recording failed: {error}");
            }
        }
    });
}

/// A private request event log and its atomically replaced, bounded status projection.
struct Recorder {
    // Directory chosen locally by the request owner, never by incoming events.
    directory: std::path::PathBuf,
    // Append-only detailed event history.
    log: File,
    // Latest event for each stage invocation, retaining completed attempts.
    operations: BTreeMap<String, Value>,
    // Total received events, including repeats of a stage's progress.
    sequence: u64,
    // Request start on the controller's own clock.
    started: Instant,
    // Bytes already written, bounding storage for one request.
    bytes: usize,
    // Status projection publication is throttled independently from event retention.
    snapshot_at: Option<Instant>,
    // Full helper diagnostics, bounded independently from structured events.
    diagnostics: File,
    // Bytes of helper diagnostics retained for this request.
    diagnostic_bytes: usize,
    // Last measured work update; heartbeats do not pretend that work advanced.
    last_progress: f64,
}

impl Recorder {
    fn record(&mut self, event: &Event) -> io::Result<()> {
        if self.operations.len() >= 256 && !self.operations.contains_key(&event.id) {
            let oldest = self
                .operations
                .iter()
                .min_by_key(|(_, event)| {
                    (
                        !matches!(event["state"].as_str(), Some("completed" | "failed")),
                        event["sequence"].as_u64(),
                    )
                })
                .map(|(id, _)| id.clone());
            if let Some(id) = oldest {
                self.operations.remove(&id);
            }
        }
        self.sequence += 1;
        if event.state != "heartbeat" {
            self.last_progress = super::now();
        }
        let mut value = serde_json::to_value(event)?;
        value["received_at"] = json!(super::now());
        value["request_elapsed_seconds"] = json!(self.started.elapsed().as_secs_f64());
        value["sequence"] = json!(self.sequence);
        value["started_sequence"] = self
            .operations
            .get(&event.id)
            .and_then(|old| old.get("started_sequence"))
            .cloned()
            .unwrap_or(json!(self.sequence));
        let bytes = serde_json::to_vec(&value)?;
        if self.bytes < 64 * 1024 * 1024 {
            self.log.write_all(&bytes)?;
            self.log.write_all(b"\n")?;
            self.bytes += bytes.len() + 1;
        }
        self.operations.insert(event.id.clone(), value.clone());
        let terminal = matches!(event.stage.as_str(), "request" | "activation")
            && matches!(event.state.as_str(), "completed" | "failed");
        let mut active = self
            .operations
            .values()
            .filter(|event| {
                !terminal
                    && matches!(
                        event["state"].as_str(),
                        Some("started" | "progress" | "heartbeat")
                    )
            })
            .collect::<Vec<_>>();
        active.sort_by_key(|event| std::cmp::Reverse(event["started_sequence"].as_u64()));
        active.truncate(32);
        if !terminal
            && event.state != "failed"
            && !active.is_empty()
            && self
                .snapshot_at
                .is_some_and(|last| last.elapsed() < Duration::from_millis(250))
        {
            return Ok(());
        }
        self.snapshot_at = Some(Instant::now());
        let current = active
            .iter()
            .max_by_key(|event| event["started_sequence"].as_u64())
            .map(|event| (*event).clone())
            .unwrap_or(value);
        let snapshot = json!({"schema":"airlock.progress-status.v1", "current":current, "active":active, "operations":self.operations.values().collect::<Vec<_>>(), "sequence":self.sequence, "last_progress_at":self.last_progress, "last_observation_at":super::now(), "request_elapsed_seconds":self.started.elapsed().as_secs_f64()});
        let mut file = tempfile::NamedTempFile::new_in(&self.directory)?;
        serde_json::to_writer(&mut file, &snapshot)?;
        file.persist(self.directory.join("status.json"))
            .map_err(|error| error.error)?;
        Ok(())
    }
}

/// Own a request recorder until the calling operation finishes.
pub struct Recording {
    // Restore an enclosing recorder after nested work or unwinding.
    previous: Option<Recorder>,
}

impl Drop for Recording {
    fn drop(&mut self) {
        let previous = self.previous.take();
        RECORDER.with_borrow_mut(|recorder| {
            *recorder = previous;
        });
    }
}

/// Start a fresh private log in a locally selected request directory.
pub fn record_to(directory: &Path) -> io::Result<Recording> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)?;
    let log = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join("events.jsonl"))?;
    let diagnostics = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join("tools.stderr.log"))?;
    let recorder = Recorder {
        directory: directory.into(),
        log,
        operations: BTreeMap::new(),
        sequence: 0,
        started: Instant::now(),
        bytes: 0,
        diagnostics,
        diagnostic_bytes: 0,
        snapshot_at: None,
        last_progress: super::now(),
    };
    let previous = RECORDER.replace(Some(recorder));
    Ok(Recording { previous })
}

/// Read the latest snapshot without mutating the request or interpreting diagnostics as decisions.
pub fn status(directory: &Path) -> io::Result<Option<Value>> {
    match File::open(directory.join("status.json")) {
        Ok(file) => {
            let mut value: Value =
                serde_json::from_reader(file.take(8 * 1024 * 1024)).map_err(io::Error::other)?;
            value["logs"] = json!({"source":fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default().trim(),"events":directory.join("events.jsonl"), "stderr":directory.join("tools.stderr.log")});
            Ok(Some(value))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Consume bounded stderr lines while preserving diagnostics and forwarding progress frames.
/// Each capture owns its buffer so simultaneous helpers cannot splice their events together.
#[derive(Default)]
pub(crate) struct Frames {
    // Incomplete stderr line; oversized lines are passed through as ordinary diagnostics.
    pending: Vec<u8>,
    // Oversized lines are plain diagnostics and cannot become truncated valid events.
    passthrough: bool,
}

impl Frames {
    pub(crate) fn push(&mut self, bytes: &[u8], forward: bool) -> Vec<u8> {
        let mut diagnostics = Vec::new();
        for byte in bytes {
            if self.passthrough {
                diagnostics.push(*byte);
                if *byte == b'\n' {
                    self.passthrough = false;
                }
            } else if *byte == b'\n' {
                let progress = receive(&self.pending);
                if !progress {
                    activity(&self.pending);
                    diagnostics.extend_from_slice(&self.pending);
                    diagnostics.push(b'\n');
                } else if !forward {
                    let _ = io::stderr()
                        .lock()
                        .write_all(&[self.pending.as_slice(), b"\n"].concat());
                }
                self.pending.clear();
            } else {
                self.pending.push(*byte);
                if self.pending.len() > MAX_EVENT + PREFIX.len() {
                    diagnostics.append(&mut self.pending);
                    self.passthrough = true;
                }
            }
        }
        diagnostics
    }

    pub(crate) fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pending)
    }
}

/// Count bytes accepted by a writer without buffering or inventing a completion percentage.
pub struct CountingWriter<'a, W> {
    // Original writer, including its normal error and backpressure behavior.
    writer: W,
    // Stage whose measured byte counters are updated.
    span: &'a mut Span,
    // Number of bytes successfully written.
    completed: u64,
    // Exact negotiated byte total for this payload.
    total: u64,
}

impl<'a, W: Write> CountingWriter<'a, W> {
    /// Start counting one known-size payload on an existing stage.
    pub fn new(writer: W, span: &'a mut Span, total: u64) -> Self {
        Self {
            writer,
            span,
            completed: 0,
            total,
        }
    }
}

impl<W: Write> Write for CountingWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = self.writer.write(bytes)?;
        self.completed += count as u64;
        self.span
            .update(json!({"bytes_completed":self.completed,"bytes_total":self.total}));
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

/// Refresh local elapsed durations while helpers block, without claiming byte or build progress.
pub fn heartbeat() {
    let due = PULSE.with_borrow_mut(|last| {
        if last.is_some_and(|last| last.elapsed() < Duration::from_secs(1)) {
            return false;
        }
        *last = Some(Instant::now());
        true
    });
    if !due {
        return;
    }
    let events = ACTIVE.with_borrow(|active| {
        active
            .values()
            .map(|(event, started)| {
                let mut event = event.clone();
                event.state = "heartbeat".into();
                event.timestamp = super::now();
                event.elapsed_seconds = started.elapsed().as_secs_f64();
                event
            })
            .collect::<Vec<_>>()
    });
    for event in events {
        emit(&event);
    }
}

/// Attach bounded helper diagnostics to the innermost local stage, with rate limiting.
fn activity(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let due = ACTIVITY_AT.with_borrow_mut(|last| {
        if last.is_some_and(|last| last.elapsed() < Duration::from_millis(250)) {
            return false;
        }
        *last = Some(Instant::now());
        true
    });
    if !due {
        return;
    }
    let event = ACTIVE.with_borrow(|active| {
        active
            .values()
            .max_by_key(|(_, start)| *start)
            .map(|(event, start)| {
                let mut event = event.clone();
                event.state = "progress".into();
                event.timestamp = super::now();
                event.elapsed_seconds = start.elapsed().as_secs_f64();
                event.metrics["activity"] = json!(
                    String::from_utf8_lossy(bytes)
                        .chars()
                        .take(1024)
                        .collect::<String>()
                );
                event
            })
    });
    if let Some(event) = event {
        emit(&event);
    }
}

/// Retain helper stderr in the current private request log, independently of progress sampling.
pub(crate) fn diagnostic(bytes: &[u8]) {
    RECORDER.with_borrow_mut(|recorder| {
        if let Some(recorder) = recorder {
            let count = bytes
                .len()
                .min((64 * 1024 * 1024usize).saturating_sub(recorder.diagnostic_bytes));
            if recorder.diagnostics.write_all(&bytes[..count]).is_ok() {
                recorder.diagnostic_bytes += count;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Frames survive arbitrary pipe boundaries; remote clocks never determine durations or approval.
    #[test]
    fn frames_publish_progress_and_failure_without_changing_authority() -> io::Result<()> {
        let temporary = tempfile::tempdir()?;
        let _recording = record_to(temporary.path())?;
        let result = phase("request", || -> Result<(), io::Error> {
            let span = Span::start("building_system");
            let mut remote = span.event.clone();
            remote.id = "dom0:receive:1".into();
            remote.source = "dom0".into();
            remote.stage = "receiving_payload".into();
            remote.timestamp = super::super::now() + 86400.0;
            remote.elapsed_seconds = 2.5;
            remote.metrics = json!({"bytes_completed":10,"bytes_total":20});
            let frame = format!("{PREFIX}{}\n", serde_json::to_string(&remote)?);
            let mut frames = Frames::default();
            for chunk in frame.as_bytes().chunks(7) {
                frames.push(chunk, true);
            }
            let events = fs::read_to_string(temporary.path().join("events.jsonl"))?;
            let observed: Value = serde_json::from_str(events.lines().last().unwrap())?;
            assert_eq!(observed["stage"], "receiving_payload");
            assert_eq!(observed["elapsed_seconds"], 2.5);
            assert_eq!(observed["metrics"]["bytes_completed"], 10);
            assert!(observed.get("decision").is_none());
            remote.state = "failed".into();
            remote.error = Some("receiver rejected checksum".into());
            assert!(receive(
                format!("{PREFIX}{}", serde_json::to_string(&remote)?).as_bytes()
            ));
            span.complete();
            Err(io::Error::other("transfer failed"))
        });
        assert!(result.is_err());
        let observed = status(temporary.path())?.unwrap();
        assert_eq!(observed["current"]["state"], "failed");
        assert_eq!(observed["current"]["error"], "transfer failed");
        assert!(observed["active"].as_array().unwrap().is_empty());
        assert!(!receive(b"@airlock-progress {}"));
        let mut large = Span::start("bounded_diagnostics");
        large.event.error = Some("界".repeat(4000));
        large.event.metrics = json!({"activity":"界".repeat(4000)});
        let encoded = wire(&large.event).unwrap();
        assert!(encoded.len() <= 4096);
        assert!(receive(encoded.trim_end().as_bytes()));
        large.complete();
        for path in ["events.jsonl", "status.json", "tools.stderr.log"] {
            assert_eq!(
                fs::metadata(temporary.path().join(path))?
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        Ok(())
    }

    /// A blocked real child still emits heartbeats, and its stderr remains available after failure.
    #[test]
    fn blocked_helpers_keep_elapsed_status_and_stderr() -> io::Result<()> {
        let temporary = tempfile::tempdir()?;
        let _recording = record_to(temporary.path())?;
        let mut span = Span::start("building_system");
        let result = super::super::process::run(
            std::process::Command::new(std::env::current_exe()?).args([
                "--ignored",
                "--exact",
                "runtime::progress::tests::progress_child",
                "--nocapture",
            ]),
            None,
            Some(Duration::from_secs(10)),
        )
        .map_err(io::Error::other)?;
        assert!(!result.status.success());
        assert!(!String::from_utf8_lossy(&result.stderr).contains(PREFIX));
        let observed = status(temporary.path())?.unwrap();
        assert!(observed["current"]["elapsed_seconds"].as_f64().unwrap() >= 1.0);
        assert!(
            observed["last_observation_at"].as_f64().unwrap()
                >= observed["last_progress_at"].as_f64().unwrap()
        );
        assert!(
            fs::read_to_string(temporary.path().join("tools.stderr.log"))?
                .contains("fixture compiler error")
        );
        span.update(json!({"bytes_completed":0,"bytes_total":1}));
        drop(span);
        assert_eq!(
            status(temporary.path())?.unwrap()["current"]["state"],
            "failed"
        );
        Ok(())
    }

    /// Subprocess fixture used by the bounded transport test above.
    #[test]
    #[ignore = "child fixture invoked by blocked_helpers_keep_elapsed_status_and_stderr"]
    fn progress_child() {
        let _span = Span::start("child_build");
        eprintln!("fixture compiler error");
        std::thread::sleep(Duration::from_millis(1200));
        panic!("expected child failure");
    }
}
