//! Child ownership and bounded capture. Locks stay with the orchestrator, never
//! an exec'd child. Dropping a pipe owner terminates and reaps its child.
use super::{Error, Result, require};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fs::{OFlags, fcntl_getfl, fcntl_setfl},
};
use std::{
    io::{self, Read, Write},
    os::fd::AsFd,
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

/// Maximum number of bytes captured from either helper output stream.
pub const LIMIT: usize = 32 * 1024 * 1024;

/// Child handle whose guard terminates and reaps unfinished work when dropped.
pub struct OwnedChild(
    /// Child handle killed and reaped if its owning guard is dropped early.
    pub Child,
);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

/// Captured helper outcome with independently bounded output streams.
pub struct Output {
    /// Child exit status after output has been collected.
    pub status: ExitStatus,
    /// Captured standard output bytes, subject to the runner limit.
    pub stdout: Vec<u8>,
    /// Captured diagnostic bytes, subject to the runner limit.
    pub stderr: Vec<u8>,
}

impl Output {
    /// Return stdout on successful exit, or preserve a bounded diagnostic and exit status.
    pub fn checked(self, operation: &str) -> Result<Vec<u8>> {
        if !self.status.success() {
            return Err(Error::Remote {
                operation: operation.to_owned(),
                message: String::from_utf8_lossy(&self.stderr)
                    .chars()
                    .take(4096)
                    .collect(),
                details: Box::new(
                    serde_json::json!({"exit_code":self.status.code(),"stdout":String::from_utf8_lossy(&self.stdout).chars().take(4096).collect::<String>(),"stderr":String::from_utf8_lossy(&self.stderr).chars().take(4096).collect::<String>()}),
                ),
            });
        }

        Ok(self.stdout)
    }
}

// A helper can exit while a descendant still holds its pipes. Even without an
// operation timeout, draining after leader exit must not wait indefinitely.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

fn nonblocking(pipe: &impl AsFd) -> io::Result<()> {
    fcntl_setfl(pipe, fcntl_getfl(pipe)? | OFlags::NONBLOCK)?;
    Ok(())
}

struct Capture<T> {
    /// Reader retained until EOF; inherited descriptors cannot block this reader.
    pipe: Option<T>,
    /// Captured stream data, bounded independently of the other output stream.
    bytes: Vec<u8>,
    /// Incomplete structured stderr events, isolated to this child stream.
    frames: super::progress::Frames,
}

impl<T: Read + AsFd> Capture<T> {
    fn new(pipe: T) -> io::Result<Self> {
        nonblocking(&pipe)?;
        Ok(Self {
            pipe: Some(pipe),
            bytes: Vec::new(),
            frames: super::progress::Frames::default(),
        })
    }

    fn read_ready(&mut self, stderr: bool, forward_stderr: bool) -> Result<bool> {
        let Some(pipe) = &mut self.pipe else {
            return Ok(false);
        };

        let mut buffer = [0; 65536];
        match pipe.read(&mut buffer) {
            Ok(0) => {
                let pending = self.frames.finish();
                require(
                    pending.len() <= LIMIT - self.bytes.len(),
                    "child output exceeded the capture limit",
                )?;
                self.bytes.extend_from_slice(&pending);
                self.pipe = None;
                Ok(true)
            }
            Ok(size) => {
                let captured = if stderr {
                    super::progress::diagnostic(&buffer[..size]);
                    self.frames.push(&buffer[..size], forward_stderr)
                } else {
                    buffer[..size].to_vec()
                };
                require(
                    captured.len() <= LIMIT - self.bytes.len(),
                    "child output exceeded the capture limit",
                )?;
                if forward_stderr {
                    let _ = io::stderr().write_all(&buffer[..size]);
                }
                self.bytes.extend_from_slice(&captured);
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(true),
            Err(error) => Err(error.into()),
        }
    }
}

/// Run a child with independently bounded stdout/stderr and an optional timeout.
///
/// Input and output progress concurrently through nonblocking pipes. The timeout
/// covers pipe I/O as well as child execution; after the child exits, inherited
/// pipes have at most five seconds to close. Early failure kills and reaps the
/// direct child. This runner does not manage descendant processes or their locks.
pub fn run(
    command: &mut Command,
    input: Option<Vec<u8>>,
    timeout: Option<Duration>,
) -> Result<Output> {
    run_capture(command, input, timeout, false)
}

/// Run a helper with the normal bounded capture while forwarding live stderr diagnostics.
pub fn run_forwarded(
    command: &mut Command,
    input: Option<Vec<u8>>,
    timeout: Option<Duration>,
) -> Result<Output> {
    run_capture(command, input, timeout, true)
}

fn run_capture(
    command: &mut Command,
    input: Option<Vec<u8>>,
    timeout: Option<Duration>,
    forward_stderr: bool,
) -> Result<Output> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    if input.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }

    let start = Instant::now();
    let mut child = OwnedChild(command.spawn().map_err(|source| Error::Command {
        program: command.get_program().to_string_lossy().into_owned(),
        source,
    })?);
    let mut stdout = Capture::new(child.0.stdout.take().expect("piped stdout"))?;
    let mut stderr = Capture::new(child.0.stderr.take().expect("piped stderr"))?;
    let mut stdin = child.0.stdin.take();
    if let Some(pipe) = &stdin {
        nonblocking(pipe)?;
    }

    let input = input.unwrap_or_default();
    let mut sent = 0;
    let mut write_error = None;
    let mut status = None;
    let mut exited_at = None;
    loop {
        super::progress::heartbeat();
        require(
            !timeout.is_some_and(|limit| start.elapsed() >= limit),
            "child command timed out; no success was recorded",
        )?;
        require(
            !exited_at.is_some_and(|time: Instant| time.elapsed() >= DRAIN_TIMEOUT),
            "child exited but inherited pipes did not close",
        )?;

        if status.is_none() {
            status = child.0.try_wait()?;
            if status.is_some() {
                exited_at = Some(Instant::now());
            }
        }

        let mut progressed = stdout.read_ready(false, false)?;
        progressed |= stderr.read_ready(true, forward_stderr)?;
        if sent == input.len() {
            stdin = None;
        }
        if let Some(pipe) = &mut stdin {
            let end = sent.saturating_add(65536).min(input.len());
            match pipe.write(&input[sent..end]) {
                Ok(0) => {
                    write_error = Some(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "child stdin closed",
                    ));
                    stdin = None;
                }
                Ok(size) => {
                    sent += size;
                    progressed = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    progressed = true;
                }
                Err(error) => {
                    write_error = Some(error);
                    stdin = None;
                }
            }
        }

        if let Some(status) = status
            && stdout.pipe.is_none()
            && stderr.pipe.is_none()
            && stdin.is_none()
        {
            if status.success()
                && let Some(error) = write_error
            {
                return Err(error.into());
            }

            return Ok(Output {
                status,
                stdout: stdout.bytes,
                stderr: stderr.bytes,
            });
        }
        if progressed {
            continue;
        }

        // Poll only descriptors still owned by this loop. A timeout or read
        // failure drops them directly, without joining blocked reader threads.
        let mut fds = Vec::with_capacity(3);
        if let Some(pipe) = &stdout.pipe {
            fds.push(PollFd::new(pipe, PollFlags::IN));
        }
        if let Some(pipe) = &stderr.pipe {
            fds.push(PollFd::new(pipe, PollFlags::IN));
        }
        if let Some(pipe) = &stdin {
            fds.push(PollFd::new(pipe, PollFlags::OUT));
        }
        let pause = Timespec {
            tv_sec: 0,
            tv_nsec: 25_000_000,
        };
        match poll(&mut fds, Some(&pause)) {
            Ok(_) | Err(rustix::io::Errno::INTR) => {}
            Err(error) => return Err(io::Error::from(error).into()),
        }
    }
}

/// Run a helper, forward stderr, and require successful exit before returning stdout.
pub fn output(program: &str, args: &[&str]) -> Result<Vec<u8>> {
    run_capture(Command::new(program).args(args), None, None, true)?.checked(program)
}

/// Return trimmed UTF-8 output from a successful helper invocation.
pub fn text(program: &str, args: &[&str]) -> Result<String> {
    Ok(String::from_utf8(output(program, args)?)
        .map_err(|_| Error::Message("command returned non-UTF-8 text".into()))?
        .trim()
        .to_owned())
}

/// Send a JSON line through the existing dom0 qrexec policy and decode its reply.
///
/// Reject failed exit, malformed JSON or a remote error field; this supplies no authority.
pub fn rpc(
    service: &str,
    request: &impl serde::Serialize,
    timeout: Option<Duration>,
) -> Result<serde_json::Value> {
    let mut bytes = serde_json::to_vec(request)?;
    bytes.push(b'\n');

    let result = run(
        Command::new("qrexec-client-vm").args(["dom0", service]),
        Some(bytes),
        timeout,
    )?;
    let parsed = super::decode::<serde_json::Value>(&result.stdout);
    if !result.status.success()
        || parsed.is_err()
        || parsed
            .as_ref()
            .ok()
            .is_some_and(|x| x.get("error").is_some())
    {
        let diagnostic = parsed.as_ref().err().map(ToString::to_string);
        return Err(Error::Remote {
            operation: service.to_owned(),
            message: parsed
                .as_ref()
                .ok()
                .and_then(|v| v.get("error"))
                .map(ToString::to_string)
                .unwrap_or_else(|| {
                    String::from_utf8_lossy(&result.stderr)
                        .chars()
                        .take(4096)
                        .collect::<String>()
                        + &diagnostic
                            .map(|error| format!("; invalid response: {error}"))
                            .unwrap_or_default()
                }),
            details: Box::new(
                serde_json::json!({"exit_code":result.status.code(),"response":parsed.ok(),"stdout":String::from_utf8_lossy(&result.stdout).chars().take(4096).collect::<String>(),"stderr":String::from_utf8_lossy(&result.stderr).chars().take(4096).collect::<String>()}),
            ),
        });
    }

    let value = parsed?;
    require(value.is_object(), "RPC response must be an object")?;
    Ok(value)
}
