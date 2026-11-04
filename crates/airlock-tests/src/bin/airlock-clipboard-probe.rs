//! Exercise the admitted clipboard from a controlled Linux participant.
//! Run in an isolated Airlock guest with its desktop adapter stopped, because
//! the existing GUI authority permits one live connection per principal. This
//! peer normally uses ordinary Qubes provisioning. The explicit stress mode instead
//! exercises a disposable guest boot-bound to a controlled laboratory authority.

#[path = "../clipboard_stress.rs"]
mod stress;

use airlock_clipboard_core::shared::{DEFAULT_CAPACITY, Error, Format, Generation};
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
    /// Stress independent endpoints using an explicitly boot-bound laboratory authority.
    Stress,
}

/// Normal GUI provisioning or explicitly selected disposable laboratory stress.
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
    /// Trusted console offer for a disposable guest booted with this Linux VM as authority.
    /// This test-only path bypasses no Xen permissions and is never used by desktop adapters.
    #[arg(long, requires = "peer_domain")]
    lab_authority: Option<PathBuf>,
    /// Actual Xen domain of this controlled Linux peer, selected by the laboratory toolstack.
    #[arg(long, requires = "lab_authority")]
    peer_domain: Option<u16>,
    /// Bounded replacement/fragmentation rounds; each round verifies the resulting bytes.
    #[arg(long, default_value_t = 32, value_parser = clap::value_parser!(u16).range(1..=256))]
    rounds: u16,
}

/// Own the authenticated mapping and a strictly increasing request sequence.
struct Client {
    /// Grants restricted by Xen to this actual Qubes domain.
    channel: Channel<Linux>,
    /// Last issued request; never reused or wrapped.
    sequence: u64,
}

/// A decoded policy rejection remains distinct from framing or transport failure.
#[derive(Debug)]
struct MutationRejected {
    /// Stable service category; the rejected request's bytes are never retained.
    reason: Error,
}

impl std::fmt::Display for MutationRejected {
    /// Expose the category without retaining request metadata or payload.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "mutation rejected: {reason:?}",
            reason = self.reason
        )
    }
}

impl std::error::Error for MutationRejected {}

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
        Self::attach(endpoint)
    }

    /// Map only an endpoint obtained from the trusted GUI or explicit laboratory authority.
    fn attach(endpoint: ClipboardEndpoint) -> Result<Self> {
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
            Reply::Error(reason) => Err(MutationRejected { reason }.into()),
            _ => bail!("unexpected mutation reply"),
        }
    }

    /// Obtain replacement order before declaring or transferring any bytes.
    fn reserve(&mut self) -> Result<Generation> {
        match self.request(Request::Reserve)? {
            Reply::Generation(generation) => Ok(generation),
            _ => bail!("reservation failed"),
        }
    }

    /// Stream synthetic data into two representations without allocating the full offer.
    fn copy(&mut self, size: usize, cancel: bool) -> Result<Generation> {
        self.publish(&formats(size), cancel)
    }

    /// Publish caller-selected metadata while generating data in fixed chunks.
    fn publish(&mut self, formats: &[Format], cancel: bool) -> Result<Generation> {
        self.publish_with_progress(formats, cancel, || Ok(()))
    }

    /// Progress other independently owned channels during a long synthetic copy.
    fn publish_with_progress(
        &mut self,
        formats: &[Format],
        cancel: bool,
        mut progress: impl FnMut() -> Result<()>,
    ) -> Result<Generation> {
        let generation = self.reserve()?;
        self.mutate(Request::Declare {
            generation,
            formats: formats.to_vec(),
        })?;
        let mut bytes = [0; DATA_CHUNK];
        for (format, representation) in formats.iter().enumerate() {
            for offset in (0..representation.size).step_by(DATA_CHUNK) {
                progress()?;
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
    fn read(&mut self, size: usize) -> Result<Generation> {
        self.verify(&formats(size))
    }

    /// Compare canonical metadata and two complete reads without logging content.
    fn verify(&mut self, formats: &[Format]) -> Result<Generation> {
        self.verify_with_progress(formats, || Ok(()))
    }

    /// Progress authority and idle peers without sharing the active channel across threads.
    fn verify_with_progress(
        &mut self,
        formats: &[Format],
        mut progress: impl FnMut() -> Result<()>,
    ) -> Result<Generation> {
        let Reply::Offer(generation, Some(offer)) = self.request(Request::Offer)? else {
            bail!("no complete offer");
        };
        ensure!(
            offer.generation == generation && offer.formats == formats,
            "unexpected offer metadata"
        );
        let mut expected = [0; DATA_CHUNK];
        for _ in 0..2 {
            for (format, representation) in offer.formats.iter().enumerate() {
                for offset in (0..representation.size).step_by(DATA_CHUNK) {
                    progress()?;
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
    if matches!(args.case, Case::Stress) {
        let endpoint = args
            .lab_authority
            .as_ref()
            .context("stress requires --lab-authority")?;
        let domain = args.peer_domain.context("stress requires --peer-domain")?;
        ensure!(
            (1..0x7ff0).contains(&domain),
            "invalid laboratory peer domain"
        );
        return stress::run(endpoint, domain, args.rounds);
    }
    ensure!(
        args.lab_authority.is_none(),
        "laboratory authority requires --case stress"
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
        Case::Stress => unreachable!("handled before normal provisioning"),
    }
    println!(
        "{record}",
        record = serde_json::json!({"event":"clipboard-probe","case":format!("{case:?}", case=args.case),"size":args.size,"status":"passed"})
    );
    Ok(())
}
