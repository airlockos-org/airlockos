//! Byte progress for copies and activity counters for blocking device flushes.

use std::{
    fs,
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

pub(crate) struct Progress<'a> {
    // User-facing operation being measured, such as writing or verifying.
    label: &'a str,
    // Exact bytes expected; sparse writes count allocated extents only.
    total: u64,
    // Last published byte position used to avoid excessive output.
    last: Option<(u64, Instant)>,
}

impl<'a> Progress<'a> {
    pub(crate) fn new(label: &'a str, total: u64) -> Self {
        Self {
            label,
            total,
            last: None,
        }
    }

    pub(crate) fn report(&mut self, current: u64) {
        if self.last.is_some_and(|(size, time)| {
            current != self.total
                && current.saturating_sub(size) < 128 * 1024 * 1024
                && time.elapsed() < Duration::from_secs(2)
        }) {
            return;
        }

        let percent = if self.total == 0 {
            100
        } else {
            u128::from(current) * 100 / u128::from(self.total)
        };
        println!(
            "{}: {:.1} / {:.1} GiB ({percent}%)",
            self.label,
            current as f64 / 1024f64.powi(3),
            self.total as f64 / 1024f64.powi(3)
        );
        self.last = Some((current, Instant::now()));
    }
}

pub(crate) fn stats(path: &Path) -> Option<(u64, u64)> {
    let text = fs::read_to_string(path).ok()?;
    let fields: Vec<_> = text.split_whitespace().collect();
    Some((
        fields.get(6)?.parse::<u64>().ok()?.checked_mul(512)?,
        fields.get(8)?.parse().ok()?,
    ))
}

fn elapsed(seconds: u64) -> String {
    format!("{:02}:{:02}", seconds / 60, seconds % 60)
}

pub(crate) fn waiting<T>(
    label: &str,
    device: Option<&Path>,
    operation: impl FnOnce() -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    waiting_at(
        label,
        device.and_then(super::device::stats_path),
        Duration::from_secs(5),
        operation,
    )
}

pub(crate) fn waiting_at<T>(
    label: &str,
    counters: Option<PathBuf>,
    interval: Duration,
    operation: impl FnOnce() -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let started = Instant::now();
    let terminal = io::stdout().is_terminal();
    let initial = counters.as_ref().and_then(|p| stats(p));
    let (stop, receiver) = mpsc::channel::<()>();
    println!("{label}… waiting for completion");

    let result = thread::scope(|scope| {
        scope.spawn(move || {
            let mut previous = initial;
            let mut previous_time = started;
            let mut frame = 0;
            while receiver.recv_timeout(interval) == Err(mpsc::RecvTimeoutError::Timeout) {
                let now = Instant::now();
                let current = counters.as_ref().and_then(|p| stats(p));
                let mut message = format!(
                    "{label}: {} {} elapsed",
                    ["|", "/", "-", "\\"][frame % 4],
                    elapsed(started.elapsed().as_secs())
                );
                if let (Some(first), Some(old), Some(new)) = (initial, previous, current)
                    && new.0 >= old.0
                    && old.0 >= first.0
                {
                    message.push_str(&format!(
                        " | +{:.2} GiB written | {:.1} MiB/s | {} I/O in flight",
                        (new.0 - first.0) as f64 / 1024f64.powi(3),
                        (new.0 - old.0) as f64
                            / 1024f64.powi(2)
                            / now.duration_since(previous_time).as_secs_f64().max(0.001),
                        new.1
                    ));
                }

                let mut stream = io::stdout().lock();
                if terminal {
                    let _ = write!(stream, "\r\x1b[2K{message}");
                } else {
                    let _ = writeln!(stream, "{message}");
                }
                let _ = stream.flush();
                previous = current;
                previous_time = now;
                frame += 1;
            }
        });

        let result = operation();
        drop(stop);
        result
    });

    if terminal {
        println!();
    }
    if result.is_ok() {
        println!(
            "{label}: completed after {}",
            elapsed(started.elapsed().as_secs())
        );
    }

    result
}
