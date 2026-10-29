//! Exercise the admitted clipboard from a controlled Linux participant.
//! Run in an isolated Airlock guest with its desktop adapter stopped, because
//! the existing GUI authority permits one live connection per principal. This
//! peer uses ordinary Qubes provisioning and never supplies its own identity.

use airlock_clipboard_core::shared::{DEFAULT_CAPACITY, Error, Format};
use airlock_machine_core::services::{ClipboardConnection, ClipboardEndpoint};
use airlock_sys_clipboard::shared::{self, DATA_CHUNK, Reply, Request};
use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, ValueEnum};
use std::{fs::File, io::Read, path::PathBuf, process::Command, time::Duration};
use xen_transport::{Channel, Offer, Peer, linux::Linux};

/// Distinct stages allow testing disconnect, replacement and a fresh service boot.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum Case {
    /// Publish a bounded offer and read it twice on the same authenticated connection.
    Roundtrip,
    /// Publish, then disconnect; another participant can subsequently read it.
    Copy,
    /// Verify the current offer twice without consuming it.
    Read,
    /// Disconnect with a partially written disk extent.
    Cancel,
    /// Require an empty clipboard after cancellation, clear or restart.
    Empty,
    /// Clear the clipboard through the ordinary replacement protocol.
    Clear,
    /// Reject authority escalation, stale requests and out-of-order writes.
    Faults,
}

/// No endpoint coordinates or authorization claims are accepted as command-line inputs.
#[derive(Parser)]
struct Args {
    /// Installed machine-derived membership, also used by the ordinary desktop adapter.
    #[arg(long, default_value = "/etc/airlock/clipboard.json")]
    config: PathBuf,
    /// Lifecycle stage exercised by this controlled participant.
    #[arg(long, value_enum, default_value = "roundtrip")]
    case: Case,
    /// Aggregate payload across two representations, generated in fixed chunks.
    #[arg(long, default_value_t = 6 * 1024 * 1024)]
    size: usize,
}

/// Own the authenticated mapping and a strictly increasing request sequence.
struct Client {
    /// Grants restricted by Xen to this actual Qubes domain.
    channel: Channel<Linux>,
    /// Last issued request; never reused or wrapped.
    sequence: u64,
}

impl Client {
    /// Provision through qrexec, whose trusted remote-domain context binds this peer.
    fn open(config: &ClipboardConnection) -> Result<Self> {
        let output = airlock_nix_core::runtime::process::run(
            Command::new("qrexec-client-vm").args([
                "--",
                config.gui.as_str(),
                "airlock.ClipboardConnect",
            ]),
            None,
            Some(Duration::from_secs(30)),
        )?;
        ensure!(
            output.status.success() && output.stdout.len() <= 16 * 1024,
            "trusted provisioning failed"
        );
        let endpoint: ClipboardEndpoint = serde_json::from_slice(&output.stdout)?;
        ensure!(
            endpoint.domain > 0
                && endpoint.domain < 0x7ff0
                && endpoint.principal > 0
                && endpoint.epoch > 0,
            "invalid trusted endpoint"
        );
        let backend = Linux::open(
            Peer {
                domain: endpoint.domain,
            },
            Offer {
                port: endpoint.port,
                grant: endpoint.grant,
                session: endpoint.epoch,
            },
        )
        .map_err(|error| anyhow::anyhow!("Xen endpoint: {error:?}"))?;
        Ok(Self {
            channel: Channel::new(backend),
            sequence: 0,
        })
    }

    /// Preserve stable service errors for negative assertions without logging private bytes.
    fn request(&mut self, request: Request) -> Result<Reply> {
        self.sequence = self.sequence.checked_add(1).context("sequence exhausted")?;
        shared::exchange(&mut self.channel, self.sequence, &request)
            .map_err(|error| anyhow::anyhow!("Xen exchange: {error:?}"))
    }

    /// Require a successful mutation and expose only its error category on failure.
    fn mutate(&mut self, request: Request) -> Result<()> {
        match self.request(request)? {
            Reply::Ok => Ok(()),
            Reply::Error(error) => bail!("mutation rejected: {error:?}"),
            _ => bail!("unexpected mutation reply"),
        }
    }

    /// Obtain replacement order before declaring or transferring any bytes.
    fn reserve(&mut self) -> Result<u64> {
        match self.request(Request::Reserve)? {
            Reply::Generation(generation) => Ok(generation),
            _ => bail!("reservation failed"),
        }
    }

    /// Stream synthetic data into two representations without allocating the full offer.
    fn copy(&mut self, size: usize, cancel: bool) -> Result<u64> {
        let generation = self.reserve()?;
        let formats = formats(size);
        self.mutate(Request::Declare {
            generation,
            formats: formats.clone(),
        })?;
        let mut bytes = [0; DATA_CHUNK];
        for (format, representation) in formats.iter().enumerate() {
            for offset in (0..representation.size).step_by(DATA_CHUNK) {
                let count = DATA_CHUNK.min(representation.size - offset);
                pattern(format, offset, &mut bytes[..count]);
                self.mutate(Request::Write {
                    generation,
                    format,
                    offset,
                    bytes: bytes[..count].to_vec(),
                })?;
                if cancel {
                    return Ok(generation);
                }
            }
        }
        self.mutate(Request::Complete { generation })?;
        Ok(generation)
    }

    /// Verify every promised byte twice, including unaligned representation boundaries.
    fn read(&mut self, size: usize) -> Result<u64> {
        let Reply::Offer(generation, Some(offer)) = self.request(Request::Offer)? else {
            bail!("no complete offer");
        };
        ensure!(
            offer.generation == generation && offer.formats == formats(size),
            "unexpected offer metadata"
        );
        let mut expected = [0; DATA_CHUNK];
        for _ in 0..2 {
            for (format, representation) in offer.formats.iter().enumerate() {
                for offset in (0..representation.size).step_by(DATA_CHUNK) {
                    let count = DATA_CHUNK.min(representation.size - offset);
                    let Reply::Data(bytes) = self.request(Request::Read {
                        generation,
                        format,
                        offset,
                    })?
                    else {
                        bail!("paste failed");
                    };
                    pattern(format, offset, &mut expected[..count]);
                    ensure!(
                        bytes == expected[..count],
                        "payload mismatch at format={format} offset={offset}"
                    );
                }
                ensure!(
                    matches!(self.request(Request::Read { generation, format, offset: representation.size })?, Reply::Data(bytes) if bytes.is_empty()),
                    "read passed representation end"
                );
            }
        }
        Ok(generation)
    }

    /// Require no complete offer; storage usage diagnostics check retirement separately.
    fn empty(&mut self) -> Result<()> {
        ensure!(
            matches!(self.request(Request::Offer)?, Reply::Offer(_, None)),
            "clipboard still published"
        );
        Ok(())
    }

    /// Exercise policy errors through the same direct data channel as normal requests.
    fn faults(&mut self) -> Result<()> {
        ensure!(
            matches!(
                self.request(Request::Connect {
                    principal: u64::MAX,
                    domain: 0
                })?,
                Reply::Error(Error::Unauthorized)
            ),
            "data peer acquired authority"
        );
        let stale = self.reserve()?;
        let generation = self.reserve()?;
        ensure!(
            matches!(
                self.request(Request::Complete { generation: stale })?,
                Reply::Error(Error::Stale)
            ),
            "stale completion accepted"
        );
        self.mutate(Request::Declare {
            generation,
            formats: formats(6 * 1024 * 1024),
        })?;
        ensure!(
            matches!(
                self.request(Request::Write {
                    generation,
                    format: 0,
                    offset: 1,
                    bytes: vec![1]
                })?,
                Reply::Error(Error::Order)
            ),
            "out-of-order write accepted"
        );
        self.empty()
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self
            .channel
            .close(self.channel.deadline_after(1_000_000_000));
    }
}

/// Use two formats to test the aggregate threshold, not a separate limit per format.
fn formats(size: usize) -> Vec<Format> {
    [size.div_ceil(2), size / 2]
        .into_iter()
        .enumerate()
        .map(|(index, size)| Format {
            name: format!("application/x-airlock-probe-{index}"),
            size,
        })
        .collect()
}

/// Distinguish representations, offsets and chunks without storing a whole test payload.
fn pattern(format: usize, offset: usize, bytes: &mut [u8]) {
    for (index, byte) in bytes.iter_mut().enumerate() {
        let position = offset + index;
        *byte = (position.wrapping_mul(31) ^ (position / 251) ^ (format * 113)) as u8;
    }
}

/// Emit only the case, resource bound and result; private bytes never enter diagnostics.
fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(
        (2..=DEFAULT_CAPACITY).contains(&args.size),
        "invalid aggregate size"
    );
    let mut bytes = Vec::new();
    File::open(&args.config)?
        .take(16 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 16 * 1024, "oversized membership contract");
    let config: ClipboardConnection = serde_json::from_slice(&bytes)?;
    ensure!(config.validate(), "invalid membership contract");
    let mut client = Client::open(&config)?;
    match args.case {
        Case::Roundtrip => {
            client.copy(args.size, false)?;
            client.read(args.size)?;
        }
        Case::Copy => {
            client.copy(args.size, false)?;
        }
        Case::Read => {
            client.read(args.size)?;
        }
        Case::Cancel => {
            client.copy(args.size, true)?;
        }
        Case::Empty => client.empty()?,
        Case::Clear => {
            let generation = client.reserve()?;
            client.mutate(Request::Declare {
                generation,
                formats: Vec::new(),
            })?;
            client.empty()?;
        }
        Case::Faults => client.faults()?,
    }
    println!(
        "{record}",
        record = serde_json::json!({"event":"clipboard-probe","case":format!("{case:?}", case=args.case),"size":args.size,"status":"passed"})
    );
    Ok(())
}
