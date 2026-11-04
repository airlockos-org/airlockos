//! Bounded output-only subscription. Input bytes terminate it; EOF permits a read-only client.

use super::{TICK, feed};
use anyhow::{Result, bail, ensure};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use std::io::{Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};

/// Missing session/publisher is a bounded startup condition, never an indefinite wait.
const INITIAL_WAIT: Duration = Duration::from_secs(10);

/// A stalled transport cannot keep even its one pending frame indefinitely.
const WRITE_WAIT: Duration = Duration::from_secs(2);

/// Periodic reconnect lets existing Qubes policy reauthorize long-running consumers.
/// Immediate revocation still requires lifecycle teardown by machine integration.
const LEASE: Duration = Duration::from_secs(300);

/// Pump immutable complete frames to qrexec without accepting commands or queueing history.
pub(super) fn run(directory: &Path) -> Result<()> {
    // Stdout is line-buffered, but frames contain binary headers and no newline.
    // Duplicate the descriptors into unbuffered Files so backpressure remains
    // visible to the nonblocking pump instead of a userspace buffering layer.
    let mut input = std::fs::File::from(rustix::io::dup(std::io::stdin())?);
    let mut output = std::fs::File::from(rustix::io::dup(std::io::stdout())?);
    pump(directory, &mut input, &mut output, LEASE)
}

/// Use nonblocking descriptor I/O so input, disconnects and deadlines remain observable.
pub(super) fn pump<R: Read + std::os::fd::AsFd, W: Write + std::os::fd::AsFd>(
    directory: &Path,
    input: &mut R,
    output: &mut W,
    lease: Duration,
) -> Result<()> {
    fcntl_setfl(&*input, fcntl_getfl(&*input)? | OFlags::NONBLOCK)?;
    fcntl_setfl(&*output, fcntl_getfl(&*output)? | OFlags::NONBLOCK)?;
    let started = Instant::now();
    let mut input_open = true;
    let mut previous = Vec::new();
    let mut pending = Vec::new();
    let mut sent = 0;
    let mut write_started = Instant::now();
    let mut next_read = Instant::now();
    loop {
        if started.elapsed() >= lease {
            return Ok(());
        }
        if input_open {
            match input.read(&mut [0]) {
                Ok(0) => input_open = false,
                Ok(_) => bail!("preferences subscription accepts no input"),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error.into()),
            }
        }

        if pending.is_empty() && Instant::now() >= next_read {
            match feed::read(directory) {
                Ok(frame) => {
                    if frame != previous {
                        pending = frame;
                        sent = 0;
                        write_started = Instant::now();
                    }
                }
                Err(_) if previous.is_empty() && started.elapsed() < INITIAL_WAIT => {}
                Err(error) => return Err(error),
            }
            next_read = Instant::now() + TICK;
        }
        if !pending.is_empty() {
            ensure!(
                write_started.elapsed() < WRITE_WAIT,
                "preferences subscriber is not reading"
            );
            match output.write(&pending[sent..]) {
                Ok(0) => bail!("preferences output closed"),
                Ok(count) => sent += count,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error.into()),
            }
            if sent == pending.len() {
                previous = std::mem::take(&mut pending);
            }
        }

        let events = if pending.is_empty() {
            PollFlags::empty()
        } else {
            PollFlags::OUT
        };
        let mut descriptors = vec![PollFd::new(&*output, events)];
        if input_open {
            descriptors.push(PollFd::new(&*input, PollFlags::IN));
        }
        let timeout = Timespec {
            tv_sec: 0,
            tv_nsec: TICK.as_nanos() as i64,
        };
        match poll(&mut descriptors, Some(&timeout)) {
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
        ensure!(
            !descriptors[0]
                .revents()
                .intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL),
            "preferences subscriber disconnected"
        );
    }
}
