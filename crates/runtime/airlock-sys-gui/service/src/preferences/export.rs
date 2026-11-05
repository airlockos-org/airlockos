//! Bounded output-only subscription. Input bytes terminate it; EOF permits a read-only client.

use super::feed;
use anyhow::{Result, bail, ensure};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fs::inotify;
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
    // Watch the stable directory before opening a snapshot: publication replaces
    // its inode atomically, and changes racing the initial read remain queued.
    let watch = inotify::init(inotify::CreateFlags::CLOEXEC | inotify::CreateFlags::NONBLOCK)?;
    inotify::add_watch(
        &watch,
        directory,
        inotify::WatchFlags::MOVED_TO
            | inotify::WatchFlags::CLOSE_WRITE
            | inotify::WatchFlags::DELETE
            | inotify::WatchFlags::ATTRIB
            | inotify::WatchFlags::DELETE_SELF
            | inotify::WatchFlags::MOVE_SELF,
    )?;
    let mut buffer = [std::mem::MaybeUninit::uninit(); 4096];
    let mut events = inotify::Reader::new(&watch, &mut buffer);
    let started = Instant::now();
    let mut input_open = true;
    let mut previous = Vec::new();
    let mut pending = Vec::new();
    let mut sent = 0;
    let mut write_started = Instant::now();
    let mut dirty = true;
    let mut expires = started + INITIAL_WAIT;
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

        if pending.is_empty() && (dirty || Instant::now() >= expires) {
            dirty = false;
            match feed::current(directory) {
                Ok((frame, lifetime)) => {
                    expires = Instant::now() + lifetime;
                    if frame != previous {
                        pending = frame;
                        sent = 0;
                        write_started = Instant::now();
                    }
                }
                Err(_) if previous.is_empty() && started.elapsed() < INITIAL_WAIT => {}
                Err(error) => return Err(error),
            }
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

        let output_events = if pending.is_empty() {
            PollFlags::empty()
        } else {
            PollFlags::OUT
        };
        let mut descriptors = vec![
            PollFd::new(&*output, output_events),
            PollFd::new(&watch, PollFlags::IN),
        ];
        if input_open {
            descriptors.push(PollFd::new(&*input, PollFlags::IN));
        }
        // A queued change is read immediately once an in-flight frame finishes.
        // Otherwise sleep until actual I/O or the nearest meaningful deadline.
        if pending.is_empty() && dirty {
            continue;
        }
        let deadline = (started + lease).min(if pending.is_empty() {
            expires
        } else {
            write_started + WRITE_WAIT
        });
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout = Timespec {
            tv_sec: remaining.as_secs() as i64,
            tv_nsec: i64::from(remaining.subsec_nanos()),
        };
        if events.is_buffer_empty() {
            match poll(&mut descriptors, Some(&timeout)) {
                Ok(_) => {}
                Err(rustix::io::Errno::INTR) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        ensure!(
            !descriptors[0]
                .revents()
                .intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL),
            "preferences subscriber disconnected"
        );
        // Bound work per wakeup, including an overflowing or busy producer. Lost
        // watches/overflow end this subscription, requiring a clean resubscribe.
        for _ in 0..256 {
            match events.next() {
                Ok(event) => {
                    ensure!(
                        !event.events().intersects(
                            inotify::ReadFlags::IGNORED
                                | inotify::ReadFlags::QUEUE_OVERFLOW
                                | inotify::ReadFlags::UNMOUNT
                                | inotify::ReadFlags::DELETE_SELF
                                | inotify::ReadFlags::MOVE_SELF
                        ),
                        "preferences feed watch lost"
                    );
                    dirty |= event
                        .file_name()
                        .is_some_and(|name| name.to_bytes() == b"snapshot");
                }
                Err(rustix::io::Errno::WOULDBLOCK) => break,
                Err(rustix::io::Errno::INTR) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        // Reader may have buffered more events than the work budget. Consume
        // those before sleeping rather than waiting for another kernel edge.
        if !events.is_buffer_empty() {
            dirty = true;
        }
    }
}
