//! Hermit service with an authenticated authority and independent data connections.
//! Only the boot-provisioned GUI authority can attach peers. Clipboard bytes flow
//! directly between each Linux participant and Hermit, never through dom0.

use crate::shared::{self, Incoming, Reply, Request};
use airlock_clipboard_core::shared::{Clipboard, DEFAULT_CAPACITY, Error, Participant};
use std::collections::VecDeque;
use xen_transport::hermit::endpoint::{self, Endpoint, Pending};
use xen_transport::{Channel, Error as TransportError, Kind, Message, Peer};

/// One provisioned peer, bounded independently from other participants.
struct Connection {
    /// Authenticated membership and fresh connection lifetime.
    caller: Participant,
    /// Offered grant handshake, removed when the data channel is ready.
    pending: Option<Pending>,
    /// Exclusively owned channel after handshake completion.
    channel: Option<Channel<Endpoint>>,
    /// Partial request, bounded by the shared packet codec.
    incoming: Incoming,
    /// Unsent response frames; only one response may be outstanding.
    outgoing: VecDeque<Message>,
    /// Greatest completed request ID, preventing replay on a connection.
    sequence: u64,
    /// Last completed frame activity, bounding partial packets and dead peers.
    activity: u64,
}

impl Connection {
    /// Reserve an endpoint for a trusted principal/domain binding.
    fn new(principal: u64, domain: u16, epoch: u64) -> Result<Self, TransportError> {
        Ok(Self {
            caller: Participant { principal, epoch },
            pending: Some(Pending::new(Peer { domain }, epoch)?),
            channel: None,
            incoming: Incoming::default(),
            outgoing: VecDeque::new(),
            sequence: 0,
            activity: endpoint::now_ns(),
        })
    }

    /// Progress one peer fairly without waiting for queue space or a handshake.
    fn poll(&mut self) -> Result<Option<Request>, TransportError> {
        let now = endpoint::now_ns();
        if now.saturating_sub(self.activity) > 30_000_000_000 {
            return Err(TransportError::Timeout);
        }
        if let Some(pending) = &mut self.pending {
            if let Some(channel) = pending.accept()? {
                self.channel = Some(channel);
                self.pending = None;
                self.activity = now;
            }
        }
        if !self.flush()? {
            return Ok(None);
        }
        let Some(channel) = &mut self.channel else {
            return Ok(None);
        };
        for _ in 0..xen_transport::CAPACITY {
            let frame = match channel.try_recv() {
                Ok(frame) => frame,
                Err(TransportError::Empty) => return Ok(None),
                Err(error) => return Err(error),
            };
            if frame.kind != Kind::Request || frame.id <= self.sequence {
                return Err(TransportError::Malformed);
            }
            self.activity = now;
            if let Some(bytes) = self.incoming.push(&frame)? {
                self.sequence = frame.id;
                return Request::decode(&bytes).map(Some);
            }
        }
        Ok(None)
    }

    /// Send available response frames immediately, sleeping only for actual backpressure.
    fn flush(&mut self) -> Result<bool, TransportError> {
        let Some(channel) = &mut self.channel else {
            return Ok(false);
        };
        for _ in 0..xen_transport::CAPACITY {
            let Some(frame) = self.outgoing.front() else {
                break;
            };
            match channel.try_send(frame) {
                Ok(()) => {
                    self.outgoing.pop_front();
                    self.activity = endpoint::now_ns();
                }
                Err(TransportError::Full) => return Ok(false),
                Err(error) => return Err(error),
            }
        }
        Ok(self.outgoing.is_empty())
    }

    /// Retry cleanup while retaining mappings that a peer has not released yet.
    fn close(&mut self, now: u64) -> Result<(), TransportError> {
        if let Some(pending) = &mut self.pending {
            pending.close()?;
        }
        if let Some(channel) = &mut self.channel {
            channel.close(now)?;
        }
        Ok(())
    }

    /// Queue one bounded response; the main loop drains it without blocking.
    fn reply(&mut self, reply: Reply) -> Result<(), TransportError> {
        self.outgoing = shared::frames(Kind::Response, self.sequence, &reply.try_encode()?)?.into();
        self.flush()?;
        Ok(())
    }
}

/// Adapt the sole admitted ephemeral VBD to the OS-independent clipboard spool.
struct Disk {
    /// Exclusive device; its kernel driver owns bounded grants and I/O timeouts.
    device: xen_transport::hermit::block::Device,
}

impl airlock_clipboard_core::shared::storage::BlockDevice for Disk {
    fn sectors(&self) -> u64 {
        self.device.sectors()
    }

    fn read(&mut self, sector: u64, bytes: &mut [u8]) -> Result<(), Error> {
        self.device.read(sector, bytes).map_err(|_| Error::Io)
    }

    fn write(&mut self, sector: u64, bytes: &[u8]) -> Result<(), Error> {
        self.device.write(sector, bytes).map_err(|_| Error::Io)
    }

    fn flush(&mut self) -> Result<(), Error> {
        self.device.flush().map_err(|_| Error::Io)
    }
}

/// Run the normal clipboard until its trusted authority disconnects.
/// The service boot is the identity boundary; a lost authority requires a fresh
/// service boot rather than reusing stale provisioning capabilities.
pub fn run(authority: u16, nonce: &str, scratch_bytes: u64) -> Result<(), TransportError> {
    if authority == 0 || authority >= 0x7ff0 {
        return Err(TransportError::Malformed);
    }
    use airlock_clipboard_core::shared::storage::{RAM_LIMIT, Spool, Storage};

    let mut device = xen_transport::hermit::block::Device::open()?;
    if scratch_bytes < DEFAULT_CAPACITY as u64
        || device.sectors().checked_mul(512) != Some(scratch_bytes)
    {
        return Err(TransportError::Malformed);
    }
    device.flush()?;
    let storage = Spool::new(Disk { device }, RAM_LIMIT);
    println!(
        "AIRLOCK_CLIPBOARD_STORAGE_READY boot={nonce} capacity={scratch_bytes} ram_limit={RAM_LIMIT}"
    );
    let mut epoch = endpoint::now_ns().max(1);
    let mut control = Connection::new(0, authority, epoch)?;
    let offer = control.pending.as_ref().unwrap().offer();
    println!(
        "AIRLOCK_CLIPBOARD_OFFER boot={nonce} authority={authority} port={port} grant={grant} session={session}",
        port = offer.port,
        grant = offer.grant,
        session = offer.session
    );
    let mut ready = false;
    let mut clipboard = Clipboard::with_storage(DEFAULT_CAPACITY, storage);
    let mut usage = clipboard.storage().usage();
    let mut slots = airlock_clipboard_core::resources::Slots::new();
    let mut peers: Vec<Connection> =
        Vec::with_capacity(airlock_clipboard_core::resources::LIVE_LIMIT);
    let mut retiring: Vec<Connection> =
        Vec::with_capacity(airlock_clipboard_core::resources::SLOT_LIMIT);
    loop {
        let observed = endpoint::generation();
        let now = endpoint::now_ns();
        clipboard.tick(now);
        if let Some(request) = control.poll()? {
            let reply = match request {
                Request::Offer => Reply::Ok,
                Request::Connect { principal, domain }
                    if principal > 0 && domain > 0 && domain < 0x7ff0 =>
                {
                    if let Some(index) = peers
                        .iter()
                        .position(|peer| peer.caller.principal == principal)
                    {
                        let old = peers.remove(index);
                        clipboard.disconnect(old.caller);
                        assert!(slots.retire());
                        retiring.push(old);
                    }
                    if !slots.admit() {
                        Reply::Error(Error::Capacity)
                    } else {
                        epoch = epoch.checked_add(1).ok_or(TransportError::Corrupt)?;
                        match Connection::new(principal, domain, epoch) {
                            Ok(peer) => {
                                let offer = peer.pending.as_ref().unwrap().offer();
                                peers.push(peer);
                                Reply::Connected {
                                    epoch,
                                    port: offer.port,
                                    grant: offer.grant,
                                }
                            }
                            Err(_) => {
                                assert!(slots.release_live());
                                Reply::Error(Error::Capacity)
                            }
                        }
                    }
                }
                _ => Reply::Error(Error::Unauthorized),
            };
            control.reply(reply)?;
            if !ready {
                println!(
                    "AIRLOCK_CLIPBOARD_EXECUTING authority=normal readiness=connected boot={nonce}"
                );
                ready = true;
            }
        }

        let mut index = 0;
        while index < peers.len() {
            let peer = &mut peers[index];
            let outcome = match peer.poll() {
                Ok(Some(request)) => peer.reply(shared::execute_with_clock(
                    &mut clipboard,
                    endpoint::now_ns(),
                    peer.caller,
                    request,
                    endpoint::now_ns,
                )),
                Ok(None) => Ok(()),
                Err(error) => Err(error),
            };
            if outcome.is_err() {
                let peer = peers.remove(index);
                clipboard.disconnect(peer.caller);
                assert!(slots.retire());
                retiring.push(peer);
            } else {
                index += 1;
            }
        }
        let now = endpoint::now_ns();
        clipboard.tick(now);
        let current = clipboard.storage().usage();
        if current != usage {
            println!(
                "AIRLOCK_CLIPBOARD_STORAGE boot={nonce} ram_bytes={ram} disk_bytes={disk}",
                ram = current.ram_bytes,
                disk = current.disk_bytes
            );
            let (live, peak) = crate::heap::APPLICATION_HEAP.usage();
            println!(
                "AIRLOCK_CLIPBOARD_HEAP cap={} live={live} peak={peak}",
                crate::heap::APP_HEAP_BYTES
            );
            usage = current;
        }
        let before = retiring.len();
        retiring.retain_mut(|connection| connection.close(now).is_err());
        assert!(slots.release_retired(before - retiring.len()));
        assert_eq!(slots.counts(), (peers.len(), retiring.len()));
        // Event-driven waits also wake for bounded liveness and unfinished-copy cleanup.
        let interval = if retiring.is_empty() {
            1_000_000_000
        } else {
            10_000_000
        };
        match endpoint::wait(observed, now.saturating_add(interval)) {
            Ok(()) | Err(TransportError::Timeout) => (),
            Err(error) => return Err(error),
        }
    }
}
