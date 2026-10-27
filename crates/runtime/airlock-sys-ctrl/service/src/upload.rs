//! Receive a bounded source upload under one deadline before importing it.

use airlock_nix_core::runtime::{Error, Result, decode, require};
use flate2::read::MultiGzDecoder;
use std::{
    fs::File,
    io::{self, Read, Seek},
    os::fd::AsFd,
    path::Path,
    time::{Duration, Instant},
};

/// One deadline covers the header and compressed body. Read directly from the
/// fd after poll: buffered reads must not wait past that deadline.
pub(crate) struct Upload {
    /// Incoming source stream read from the qrexec-connected standard input.
    input: io::Stdin,
    /// Absolute upload deadline shared by all reads.
    deadline: Instant,
}

impl Upload {
    pub fn new() -> Self {
        Self {
            input: io::stdin(),
            deadline: Instant::now() + Duration::from_secs(120),
        }
    }

    pub fn header<T: serde::de::DeserializeOwned>(&mut self) -> Result<T> {
        let mut bytes = Vec::new();
        while bytes.len() < 4096 {
            let mut byte = [0];
            require(self.read(&mut byte)? == 1, "truncated request header")?;
            bytes.push(byte[0]);
            if byte[0] == b'\n' {
                return decode(&bytes);
            }
        }

        Err(Error::Message("request header exceeds limit".into()))
    }

    pub fn archive(&mut self, size: u64) -> Result<File> {
        let mut archive = tempfile::tempfile()?;
        let copied = io::copy(&mut self.take(size), &mut archive)?;
        require(copied == size, "truncated source archive")?;

        archive.rewind()?;
        let mut tar = tar::Archive::new(
            MultiGzDecoder::new(&archive).take(2 * 1024 * 1024 * 1024 + 1024 * 1024),
        );
        let mut names = std::collections::BTreeSet::new();
        for entry in tar.entries()? {
            let mut entry = entry?;
            let name = entry.path()?.into_owned();
            require(
                entry.header().entry_type().is_file(),
                "source archive contains a non-regular member",
            )?;
            require(
                name == Path::new("repo.bundle") || name == Path::new("manifest.json"),
                "unexpected source archive member",
            )?;
            require(
                names.insert(name.clone()),
                "duplicate source archive member",
            )?;
            require(
                entry.size()
                    <= if name == Path::new("manifest.json") {
                        65536
                    } else {
                        2 * 1024 * 1024 * 1024
                    },
                "source archive member exceeds limit",
            )?;

            io::copy(&mut entry, &mut io::sink())?;
        }

        require(
            names.len() == 2,
            "source archive requires manifest.json and repo.bundle",
        )?;

        archive.rewind()?;
        Ok(archive)
    }
}

impl Read for Upload {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }

        loop {
            let remaining = self
                .deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "source upload exceeded 120 seconds",
                    )
                })?;
            let mut fds = [rustix::event::PollFd::new(
                &self.input,
                rustix::event::PollFlags::IN,
            )];
            let timeout = rustix::event::Timespec {
                tv_sec: remaining.as_secs() as i64,
                tv_nsec: remaining.subsec_nanos() as i64,
            };
            match rustix::event::poll(&mut fds, Some(&timeout)) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "source upload exceeded 120 seconds",
                    ));
                }
                Ok(_) => return rustix::io::read(self.input.as_fd(), buffer).map_err(Into::into),
                Err(rustix::io::Errno::INTR) => continue,
                Err(e) => return Err(e.into()),
            }
        }
    }
}
