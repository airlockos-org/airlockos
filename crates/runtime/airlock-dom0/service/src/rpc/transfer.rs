//! Machine transport streams a gzip-compressed Nix export into the installed importer.
//! Wire deadlines, space checks and importer observation bound broken transfers;
//! successful import must report exactly the objects requested during negotiation.

use crate::model::StorePath;
use airlock_nix_core::runtime::process::OwnedChild;
use anyhow::{Result, ensure};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fs::{OFlags, fcntl_getfl, fcntl_setfl},
    process::{Pid, WaitId, WaitIdOptions, waitid},
};
use std::{
    collections::BTreeSet,
    fs::File,
    io::{self, BufReader, Read, Seek, SeekFrom, Write},
    os::fd::AsFd,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const HEADER_TIMEOUT: Duration = Duration::from_secs(60);

const TRANSFER_TIMEOUT: Duration = Duration::from_secs(1800);

const OUTPUT_LIMIT: u64 = 16 * 1024 * 1024;

const RESERVE: u64 = 2 * 1024 * 1024 * 1024;

/// Buffered transport input whose underlying descriptor is observed under deadlines.
pub(super) type Input = BufReader<DeadlineFile>;

/// Request descriptor and current transfer watch; fields stay private to this module.
pub(super) struct DeadlineFile {
    // Independent descriptor, closed across helper exec, for the qrexec stream.
    file: File,
    // Header and payload use separate budgets; neither can wait indefinitely.
    deadline: Instant,
    // Observe an importer only while its PID is owned and has not been reaped.
    importer: Option<ImportWatch>,
}

struct ImportWatch {
    // Owned unreaped child; NOWAIT observation prevents PID reuse during input waits.
    pid: Pid,
    // Bounded import result, checked even when the sender stops supplying input.
    output: File,
    // A successful importer can finish before gzip framing; allow a short drain.
    drain_deadline: Option<Instant>,
}

fn import_status(pid: Pid, output: &File) -> io::Result<bool> {
    if output.metadata()?.len() > OUTPUT_LIMIT {
        return Err(io::Error::other(
            "Nix importer output exceeds its size limit",
        ));
    }
    let status = match waitid(
        WaitId::Pid(pid),
        WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
    ) {
        Ok(status) => status,
        Err(rustix::io::Errno::INTR) => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if let Some(status) = status {
        if status.exit_status() != Some(0) {
            return Err(io::Error::other(
                "Nix closure importer exited unsuccessfully",
            ));
        }
        return Ok(true);
    }
    Ok(false)
}

impl ImportWatch {
    fn check(&mut self) -> io::Result<()> {
        if import_status(self.pid, &self.output)? {
            let deadline = self
                .drain_deadline
                .get_or_insert_with(|| Instant::now() + Duration::from_secs(5));
            if Instant::now() >= *deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Nix importer finished but sender did not close the transfer",
                ));
            }
        }
        Ok(())
    }
}

fn ready(
    fd: &impl AsFd,
    flags: PollFlags,
    deadline: Instant,
    mut check: impl FnMut() -> io::Result<()>,
) -> io::Result<()> {
    loop {
        check()?;
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "RPC transfer timed out",
            ));
        }
        let mut fds = [PollFd::new(fd, flags)];
        let pause = Timespec {
            tv_sec: 0,
            tv_nsec: 100_000_000,
        };
        match poll(&mut fds, Some(&pause)) {
            Ok(0) | Err(rustix::io::Errno::INTR) => continue,
            Ok(_) => return Ok(()),
            Err(error) => return Err(error.into()),
        }
    }
}

impl Read for DeadlineFile {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let watch = &mut self.importer;
        ready(&self.file, PollFlags::IN, self.deadline, || {
            if let Some(watch) = watch {
                watch.check()?;
            }
            Ok(())
        })?;
        self.file.read(buffer)
    }
}

pub(super) fn input() -> Result<Input> {
    let fd = rustix::io::fcntl_dupfd_cloexec(io::stdin(), 0)?;
    Ok(BufReader::new(DeadlineFile {
        file: File::from(fd),
        deadline: Instant::now() + HEADER_TIMEOUT,
        importer: None,
    }))
}

struct Counted<R> {
    // Remaining wire payload after the newline-terminated request header.
    inner: R,
    // Compressed bytes consumed, reported separately from NAR bytes.
    bytes: u64,
}

impl<R: Read> Read for Counted<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let size = self.inner.read(buffer)?;
        self.bytes = self
            .bytes
            .checked_add(size as u64)
            .ok_or_else(|| io::Error::other("wire length overflow"))?;
        Ok(size)
    }
}

/// Transfer accounting returned only after gzip and exact imported-object validation.
pub(super) struct Imported {
    /// Number of uncompressed bytes delivered to Nix before successful exit.
    pub(super) nar_bytes: u64,
    /// Number of compressed bytes consumed, including gzip framing.
    pub(super) compressed_bytes: u64,
}

pub(super) fn import(input: &mut Input, budget: u64, expected: &[StorePath]) -> Result<Imported> {
    let deadline = Instant::now() + TRANSFER_TIMEOUT;
    let output = tempfile::tempfile()?;
    let mut child = OwnedChild(
        Command::new("nix-store")
            .arg("--import")
            .stdin(Stdio::piped())
            .stdout(output.try_clone()?)
            .stderr(Stdio::inherit())
            .spawn()?,
    );
    input.get_mut().deadline = deadline;
    input.get_mut().importer = Some(ImportWatch {
        pid: Pid::from_child(&child.0),
        output: output.try_clone()?,
        drain_deadline: None,
    });

    let result = feed(input, budget, expected, &mut child, &output, deadline);
    // Never leave a PID watch behind after the owned child is reaped or killed.
    input.get_mut().importer = None;
    result
}

fn feed(
    input: &mut Input,
    budget: u64,
    expected: &[StorePath],
    child: &mut OwnedChild,
    output: &File,
    deadline: Instant,
) -> Result<Imported> {
    let pid = Pid::from_child(&child.0);
    let mut pipe = child.0.stdin.take().expect("piped stdin");
    fcntl_setfl(&pipe, fcntl_getfl(&pipe)? | OFlags::NONBLOCK)?;
    let wire = Counted {
        inner: input,
        bytes: 0,
    };
    let mut gzip = flate2::read::MultiGzDecoder::new(wire);
    let mut nar_bytes = 0u64;
    let mut next_space_check = 0;
    let mut buffer = vec![0; 1024 * 1024];
    loop {
        let size = gzip.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        nar_bytes = nar_bytes
            .checked_add(size as u64)
            .ok_or_else(|| io::Error::other("NAR length overflow"))?;
        ensure!(
            nar_bytes <= budget,
            "release stream exceeds dom0 import space limit"
        );
        if nar_bytes >= next_space_check {
            let space = rustix::fs::statvfs("/nix/store")?;
            let free = space
                .f_bavail
                .checked_mul(space.f_frsize)
                .ok_or_else(|| io::Error::other("store space overflow"))?;
            ensure!(
                free >= RESERVE,
                "dom0 free-space reserve exhausted during import"
            );
            next_space_check = nar_bytes.saturating_add(64 * 1024 * 1024);
        }
        let mut remaining = &buffer[..size];
        while !remaining.is_empty() {
            ready(&pipe, PollFlags::OUT, deadline, || {
                import_status(pid, output).map(|_| ())
            })?;
            match pipe.write(remaining) {
                Ok(0) => {
                    return Err(
                        io::Error::new(io::ErrorKind::WriteZero, "Nix importer closed").into(),
                    );
                }
                Ok(size) => remaining = &remaining[size..],
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    let compressed_bytes = gzip.into_inner().bytes;
    drop(pipe);

    loop {
        ensure!(
            output.metadata()?.len() <= OUTPUT_LIMIT,
            "Nix importer output exceeds its size limit"
        );
        if let Some(status) = child.0.try_wait()? {
            ensure!(status.success(), "Nix closure import failed ({status})");
            break;
        }
        ensure!(Instant::now() < deadline, "Nix closure import timed out");
        thread::sleep(Duration::from_millis(20));
    }
    let mut result = output.try_clone()?;
    result.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    result.take(OUTPUT_LIMIT + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= OUTPUT_LIMIT,
        "Nix importer output exceeds its size limit"
    );
    let imported = std::str::from_utf8(&bytes)?
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::parse)
        .collect::<std::result::Result<Vec<StorePath>, _>>()?;
    let unique = imported.iter().cloned().collect::<BTreeSet<_>>();
    ensure!(
        unique.len() == imported.len() && unique == expected.iter().cloned().collect(),
        "imported objects differ from negotiated missing inventory"
    );
    Ok(Imported {
        nar_bytes,
        compressed_bytes,
    })
}
