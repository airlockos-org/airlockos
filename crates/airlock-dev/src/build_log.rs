//! Keep human build logs informative during quiet phases without changing stdout.

use airlock_nix_core::runtime::process::OwnedChild;
use std::{
    io::{self, Read, Write},
    process::{Command, ExitStatus, Stdio},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};

/// Quiet builds emit one status line at this cadence; ordinary progress takes priority.
const INTERVAL: Duration = Duration::from_secs(15);

/// Observation of useful output, independent of whether the builder is making progress.
struct Progress {
    /// Monotonic start time of this Nix invocation.
    started: Instant,
    /// Most recent nonempty diagnostic forwarded to the user.
    last_output: Instant,
    /// Most recent fallback status, preventing repeated reports during continuous blank output.
    last_report: Instant,
    /// Bounded excerpt of the last diagnostic, providing context without claiming a current phase.
    last_message: String,
}

impl Progress {
    /// Start observing without inventing a stage before Nix reports one.
    fn new(now: Instant) -> Self {
        Self {
            started: now,
            last_output: now,
            last_report: now,
            last_message: String::new(),
        }
    }

    /// Record actual diagnostic activity; blank output must not hide quiet periods.
    fn observe(&mut self, bytes: &[u8], now: Instant) {
        let text = String::from_utf8_lossy(bytes);
        let line = text
            .lines()
            .rfind(|line| !line.trim().is_empty())
            .unwrap_or("");
        let mut escape = false;
        let message: String = line
            .chars()
            .filter(|character| {
                if *character == '\x1b' {
                    escape = true;
                    return false;
                }
                if escape {
                    if character.is_ascii_alphabetic() {
                        escape = false;
                    }
                    return false;
                }
                !character.is_control()
            })
            .take(160)
            .collect();
        if !message.trim().is_empty() {
            self.last_output = now;
            self.last_message = message.trim().to_owned();
        }
    }

    /// Describe elapsed and quiet time without equating a running command with forward progress.
    fn report(&mut self, now: Instant) -> Option<String> {
        let quiet = now.duration_since(self.last_output);
        if quiet < INTERVAL || now.duration_since(self.last_report) < INTERVAL {
            return None;
        }

        self.last_report = now;
        let context = if self.last_message.is_empty() {
            String::new()
        } else {
            format!(" | last output: {message}", message = self.last_message)
        };
        Some(format!(
            "Airlock build: Nix command still running | elapsed {elapsed} | no new log messages for {quiet}{context}",
            elapsed = elapsed(now.duration_since(self.started)),
            quiet = elapsed(quiet),
        ))
    }
}

/// Format elapsed minutes without wrapping at an hour boundary.
fn elapsed(duration: Duration) -> String {
    format!(
        "{minutes:02}:{seconds:02}",
        minutes = duration.as_secs() / 60,
        seconds = duration.as_secs() % 60,
    )
}

/// Forward diagnostics while recording only bytes actually written to the output.
struct Observed<W> {
    /// Human diagnostic destination; stdout remains inherited directly by Nix.
    output: W,
    /// Quiet-period clock shared with the reporter, never with build decisions.
    progress: Arc<Mutex<Progress>>,
}

impl<W: Write> Write for Observed<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = self.output.write(bytes)?;
        self.progress
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .observe(&bytes[..written], Instant::now());
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

/// Stream human-readable build diagnostics while retaining the child's exit status.
pub(crate) fn run(command: &mut Command) -> io::Result<ExitStatus> {
    let mut child = OwnedChild(command.stderr(Stdio::piped()).spawn()?);
    let stderr = child.0.stderr.take().expect("piped Nix stderr");
    let progress = Arc::new(Mutex::new(Progress::new(Instant::now())));
    thread::scope(|scope| {
        let (stop, receiver) = mpsc::channel::<()>();
        let reporter = progress.clone();
        scope.spawn(move || {
            while receiver.recv_timeout(Duration::from_secs(1))
                == Err(mpsc::RecvTimeoutError::Timeout)
            {
                let message = reporter
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .report(Instant::now());
                if let Some(message) = message {
                    let _ = writeln!(io::stderr().lock(), "{message}");
                }
            }
        });

        let result = forward(
            stderr,
            Observed {
                output: io::stderr(),
                progress,
            },
        )
        .and_then(|()| child.0.wait());
        // Disconnection wakes the reporter immediately, including on an I/O error.
        drop(stop);
        result
    })
}

/// Bound buffering even for very large source snippets in Nix error messages.
fn forward(mut input: impl Read, mut output: impl Write) -> io::Result<()> {
    let mut bytes = Vec::new();
    let mut continuation = false;
    let mut buffer = [0; 8192];
    loop {
        let size = match input.read(&mut buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if size == 0 {
            if !quiet_record(&bytes, true) {
                output.write_all(&bytes)?;
            }
            return output.flush();
        }

        for part in buffer[..size].split_inclusive(|byte| *byte == b'\n') {
            let complete = part.ends_with(b"\n");
            if continuation {
                output.write_all(part)?;
            } else {
                bytes.extend_from_slice(part);
                if bytes.len() >= buffer.len() || !quiet_record(&bytes, complete) {
                    output.write_all(&bytes)?;
                    bytes.clear();
                    continuation = !complete;
                } else if complete {
                    bytes.clear();
                }
            }
            if complete {
                continuation = false;
            }
        }
        output.flush()?;
    }
}

/// Recognize empty Nix records and exact setup chatter, allowing SGR colors and incomplete prefixes.
fn quiet_record(bytes: &[u8], complete: bool) -> bool {
    let mut plain = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"\x1b[") {
            index += 2;
            while index < bytes.len() && (bytes[index].is_ascii_digit() || bytes[index] == b';') {
                index += 1;
            }
            if index == bytes.len() && !complete {
                break;
            }
            if bytes.get(index) != Some(&b'm') {
                return false;
            }
            index += 1;
        } else if bytes[index] == 0x1b && index + 1 == bytes.len() && !complete {
            break;
        } else {
            plain.push(bytes[index]);
            index += 1;
        }
    }

    let separator = plain.iter().position(|byte| *byte == b'>');
    let prefix_end = separator.unwrap_or(plain.len());
    let nix_prefix = plain[..prefix_end]
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || b"+-._?=".contains(byte));
    let message = match separator {
        Some(separator) if nix_prefix && prefix_end > 0 => &plain[separator + 1..],
        Some(_) => return false,
        None if nix_prefix && !complete => return true,
        None => plain.as_slice(),
    }
    .trim_ascii();

    if separator.is_some() && message.is_empty() {
        return true;
    }

    let setup_message = b"structuredAttrs is enabled";
    if complete {
        message == setup_message
    } else {
        setup_message.starts_with(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Quiet reports are rate limited, retain context and resume after useful output stops.
    #[test]
    fn quiet_status_tracks_elapsed_time_and_last_output() {
        let start = Instant::now();
        let mut progress = Progress::new(start);
        assert!(progress.report(start + Duration::from_secs(14)).is_none());
        let report = progress.report(start + INTERVAL).unwrap();
        assert!(report.contains("elapsed 00:15"));
        assert!(report.contains("no new log messages for 00:15"));
        assert!(!report.contains("last output:"));
        assert!(progress.report(start + Duration::from_secs(16)).is_none());

        progress.observe(
            b"old message\n\x1b[32mnixos-disk-image> copying store\x1b[0m\n",
            start + Duration::from_secs(20),
        );
        assert!(progress.report(start + Duration::from_secs(30)).is_none());
        let report = progress.report(start + Duration::from_secs(35)).unwrap();
        assert!(report.contains("elapsed 00:35"));
        assert!(report.contains("last output: nixos-disk-image> copying store"));
        assert!(!report.contains('\x1b'));
        assert!(progress.report(start + Duration::from_secs(36)).is_none());
    }

    /// Suppressed setup and blank records cannot reset the fallback status clock or manufacture work.
    #[test]
    fn blank_build_output_still_allows_quiet_status() -> io::Result<()> {
        let now = Instant::now();
        let progress = Arc::new(Mutex::new(Progress::new(now - INTERVAL)));
        let mut output = Vec::new();
        forward(
            &b"nixos-disk-image>\nnixos-disk-image> \n\nimage> structuredAttrs is enabled\nstructuredAttrs is enabled\n"[..],
            Observed {
                output: &mut output,
                progress: progress.clone(),
            },
        )?;
        assert_eq!(output, b"\n");
        assert!(progress.lock().unwrap().report(now).is_some());
        Ok(())
    }

    /// Deliver fixed-size fragments to exercise records split across pipe reads.
    struct Fragmented<'a> {
        /// Bytes not yet delivered to the filter.
        remaining: &'a [u8],
        /// Maximum bytes made available by one read.
        size: usize,
    }

    impl Read for Fragmented<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let size = buffer.len().min(self.size);
            self.remaining.read(&mut buffer[..size])
        }
    }

    /// Exact setup chatter disappears while colors, similar diagnostics and arbitrary read splits survive.
    #[test]
    fn preserves_useful_output() -> io::Result<()> {
        let input = b"nixos-disk-image>\nnixos-disk-image> \r\n\x1b[32;1mnixos-disk-image>\x1b[0m \n\nstructuredAttrs is enabled\n\x1b[32;1mimage>\x1b[0m structuredAttrs is enabled\r\nnixos-disk-image> copying store\nimage> structuredAttrs is enabled: warning\nwarning: structuredAttrs is enabled\nerror: build failed\nhello >\n\xff>\nimage> final diagnostic";
        let expected = b"\nnixos-disk-image> copying store\nimage> structuredAttrs is enabled: warning\nwarning: structuredAttrs is enabled\nerror: build failed\nhello >\n\xff>\nimage> final diagnostic";
        for size in 1..=input.len() {
            let mut output = Vec::new();
            forward(
                Fragmented {
                    remaining: input,
                    size,
                },
                &mut output,
            )?;
            assert_eq!(output, expected, "read size {size}");
        }
        // A prompt is ordinary output as soon as its punctuation arrives; it
        // must not be held until a newline while the child waits for input.
        assert!(!quiet_record(b"Password: ", false));
        assert!(!quiet_record(b"image> structuredAttrs is", true));
        let mut output = Vec::new();
        forward(&b"image> structuredAttrs is enabled"[..], &mut output)?;
        assert!(output.is_empty());
        Ok(())
    }

    /// Long diagnostics are streamed intact, including continuations that resemble empty records.
    #[test]
    fn preserves_long_lines() -> io::Result<()> {
        let mut input = vec![b'x'; 8192];
        input.extend_from_slice(b"nixos-disk-image>\nimage> useful\n");
        let mut output = Vec::new();
        forward(&input[..], &mut output)?;
        assert_eq!(output, input);

        let mut input = b"image>".to_vec();
        input.resize(8192, b' ');
        input.extend_from_slice(b"useful diagnostic\n");
        output.clear();
        forward(&input[..], &mut output)?;
        assert_eq!(output, input);
        Ok(())
    }
}
