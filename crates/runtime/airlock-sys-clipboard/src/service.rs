//! Hermit service with an authenticated authority and independent data connections.
//! Only the boot-provisioned GUI authority can attach peers. Clipboard bytes flow
//! directly between each Linux participant and Hermit, never through dom0.

use crate::shared::{self, Incoming, Reply, Request};
use airlock_clipboard_core::boot::{Challenge, Domain};
use airlock_clipboard_core::connections::{Connections, InsertError};
use airlock_clipboard_core::shared::{
    Caller, Clipboard, DEFAULT_CAPACITY, Error, Participant, Provisioner, Time,
};
use std::collections::VecDeque;
use xen_transport::hermit::endpoint::{self, Endpoint, Pending};
use xen_transport::{Channel, Error as TransportError, Kind, Message, Peer};

/// Provisioning authority and data permission have distinct ownership and dispatch.
enum Role {
    /// Sole GUI-bound connection owns the capability that may admit data callers.
    Authority(
        /// Object-bound capability held only by the GUI control connection.
        Provisioner,
    ),
    /// One revocable membership, never constructible from request metadata.
    Data(
        /// Revocable permission owned by this admitted data connection.
        Caller,
    ),
}

/// Exclusive transport ownership through handshake, operation and completed cleanup.
enum Transport {
    /// Grant offer exists but the peer has not completed the handshake.
    Pending(
        /// Offered resources whose cleanup can still require peer cooperation.
        Pending,
    ),
    /// Authenticated endpoint ready to send and receive framed messages.
    Connected(
        /// Sole channel owning its live endpoint and grant mappings.
        Channel<Endpoint>,
    ),
    /// Cleanup succeeded; no mappings or grants remain owned by this connection.
    Closed,
}

/// One provisioned peer, bounded independently from other participants.
struct Connection {
    /// Authority cannot be selected by a data-plane message.
    role: Role,
    /// Exactly one resource-owning lifecycle stage.
    transport: Transport,
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
    /// Own an already-created endpoint and its independently established permission.
    fn new(role: Role, pending: Pending) -> Self {
        Self {
            role,
            transport: Transport::Pending(pending),
            incoming: Incoming::default(),
            outgoing: VecDeque::new(),
            sequence: 0,
            activity: endpoint::now_ns(),
        }
    }

    /// Identify a data principal without exposing its permission or fabricating authority.
    fn principal(&self) -> Option<u64> {
        match &self.role {
            Role::Data(caller) => Some(caller.identity().principal()),
            Role::Authority(_) => None,
        }
    }

    /// Revoke data access before retaining the connection for fallible cleanup.
    fn revoke<S: airlock_clipboard_core::shared::storage::Storage>(
        &self,
        clipboard: &mut Clipboard<S>,
    ) {
        if let Role::Data(caller) = &self.role {
            clipboard.disconnect(caller);
            println!(
                "AIRLOCK_CLIPBOARD_PEER event=revoked principal={principal} epoch={epoch}",
                principal = caller.identity().principal(),
                epoch = caller.identity().epoch()
            );
        }
    }

    /// Progress one peer fairly without waiting for queue space or a handshake.
    fn poll(&mut self) -> Result<Option<Request>, TransportError> {
        let now = endpoint::now_ns();
        if now.saturating_sub(self.activity) > 30_000_000_000 {
            return Err(TransportError::Timeout);
        }
        if let Transport::Pending(pending) = &mut self.transport {
            if let Some(channel) = pending.accept()? {
                self.transport = Transport::Connected(channel);
                self.activity = now;
            }
        }
        if !self.flush()? {
            return Ok(None);
        }
        let Transport::Connected(channel) = &mut self.transport else {
            return Ok(None);
        };
        for _ in 0..xen_transport::CAPACITY {
            let frame = match channel.try_recv() {
                Ok(frame) => frame,
                Err(TransportError::Empty) => return Ok(None),
                Err(error) => return Err(error),
            };
            self.activity = now;
            if let Some(bytes) = self.incoming.push(&frame)? {
                self.sequence = self.incoming.completed_id();
                return Request::decode(&bytes)
                    .map(Some)
                    .map_err(shared::packet_error);
            }
        }
        Ok(None)
    }

    /// Send available response frames immediately, sleeping only for actual backpressure.
    fn flush(&mut self) -> Result<bool, TransportError> {
        let Transport::Connected(channel) = &mut self.transport else {
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
        match &mut self.transport {
            Transport::Pending(pending) => pending.close()?,
            Transport::Connected(channel) => channel.close(now)?,
            Transport::Closed => return Ok(()),
        }
        self.transport = Transport::Closed;
        match &self.role {
            Role::Data(caller) => println!(
                "AIRLOCK_CLIPBOARD_PEER event=closed principal={principal} epoch={epoch}",
                principal = caller.identity().principal(),
                epoch = caller.identity().epoch()
            ),
            Role::Authority(_) => println!("AIRLOCK_CLIPBOARD_AUTHORITY event=closed"),
        }
        Ok(())
    }

    /// Queue one bounded response; the main loop drains it without blocking.
    fn reply(&mut self, reply: Reply) -> Result<(), TransportError> {
        self.outgoing = shared::frames(
            Kind::Response,
            self.sequence,
            &reply.try_encode().map_err(shared::packet_error)?,
        )?
        .into();
        self.flush()?;
        Ok(())
    }
}

/// Bind one fresh core capability to the actual Xen peer chosen by the GUI authority.
/// Endpoint creation failure revokes membership before returning capacity to the ledger.
fn provision<S: airlock_clipboard_core::shared::storage::Storage>(
    clipboard: &mut Clipboard<S>,
    authority: &Provisioner,
    principal: u64,
    domain: Domain,
    epoch: u64,
) -> Result<(Connection, xen_transport::Offer), TransportError> {
    let identity = Participant::from_binding(principal, epoch).ok_or(TransportError::Malformed)?;
    let caller = clipboard
        .admit(authority, identity)
        .map_err(|_| TransportError::Malformed)?;
    let pending = match Pending::new(
        Peer {
            domain: domain.get(),
        },
        caller.identity().epoch(),
    ) {
        Ok(pending) => pending,
        Err(error) => {
            clipboard.disconnect(&caller);
            return Err(error);
        }
    };
    let offer = pending.offer();
    Ok((Connection::new(Role::Data(caller), pending), offer))
}

/// Adapt the sole admitted ephemeral VBD to the OS-independent clipboard spool.
// Verification exception: these four calls cross the external Hermit VBD ABI.
// Exact scope: geometry and owned read/write/flush effects; no range, offset,
// publication or error decisions are delegated to the adapter. The driver must
// preserve device geometry, transfer the supplied private byte window on success,
// and return uncertain I/O failures truthfully. Spool invalidates and poisons on
// failure, never publishes it, and never offers retired sectors. Its verified
// Storage/BlockDevice contracts state these dependency assumptions explicitly.
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
pub fn run(
    authority: Domain,
    challenge: &Challenge,
    scratch_bytes: u64,
) -> Result<(), TransportError> {
    use airlock_clipboard_core::shared::storage::{RAM_LIMIT, Spool, Storage};
    let nonce =
        core::str::from_utf8(challenge.as_bytes()).map_err(|_| TransportError::Malformed)?;

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
    let (mut clipboard, provisioner) = Clipboard::with_storage(DEFAULT_CAPACITY, storage);
    let authority = authority.get();
    let pending = Pending::new(Peer { domain: authority }, epoch)?;
    let offer = pending.offer();
    let mut control = Connection::new(Role::Authority(provisioner), pending);
    println!(
        "AIRLOCK_CLIPBOARD_OFFER boot={nonce} authority={authority} port={port} grant={grant} session={session}",
        port = offer.port,
        grant = offer.grant,
        session = offer.session
    );
    let mut ready = false;
    let mut usage = clipboard.storage().usage();
    let mut peers = Connections::<Connection>::new().map_err(|_| TransportError::TooLarge)?;
    let outcome = (|| {
        loop {
            let observed = endpoint::generation();
            let now = endpoint::now_ns();
            clipboard.tick(Time::observe(now));
            if let Some(request) = control.poll()? {
                let reply = match request {
                    Request::Offer => Reply::Ok,
                    Request::Connect { principal, domain }
                        if principal > 0 && domain > 0 && domain < 0x7ff0 =>
                    {
                        let mut index = 0;
                        while index < peers.live_len() {
                            let same = peers
                                .live_mut(index)
                                .is_some_and(|peer| peer.principal() == Some(principal));
                            if same {
                                if let Some(old) = peers.live_mut(index) {
                                    old.revoke(&mut clipboard);
                                }
                                peers.retire(index);
                                break;
                            }
                            index += 1;
                        }
                        let domain = Domain::from_raw(domain).ok_or(TransportError::Malformed)?;
                        epoch = epoch.checked_add(1).ok_or(TransportError::Corrupt)?;
                        let result = peers.insert_with(|| match &control.role {
                            Role::Authority(provisioner) => {
                                provision(&mut clipboard, provisioner, principal, domain, epoch)
                            }
                            Role::Data(_) => Err(TransportError::Corrupt),
                        });
                        match result {
                            Ok(offer) => {
                                println!(
                                    "AIRLOCK_CLIPBOARD_PEER event=admitted principal={principal} domain={domain} epoch={epoch}",
                                    domain = domain.get()
                                );
                                Reply::Connected {
                                    epoch,
                                    port: offer.port,
                                    grant: offer.grant,
                                }
                            }
                            Err(InsertError::Capacity) => Reply::Error(Error::Capacity),
                            // The dependency may retain uncertain partial construction in
                            // its bounded kernel quarantine. Terminate this service life;
                            // never recycle admission and continue creating endpoints.
                            Err(InsertError::Build(error)) => return Err(error),
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
            while index < peers.live_len() {
                let Some(peer) = peers.live_mut(index) else {
                    return Err(TransportError::Corrupt);
                };
                let outcome = match peer.poll() {
                    Ok(Some(request)) => match &peer.role {
                        Role::Data(caller) => {
                            let reply = shared::execute_with_clock(
                                &mut clipboard,
                                Time::observe(endpoint::now_ns()),
                                caller,
                                request,
                                || Time::observe(endpoint::now_ns()),
                            );
                            peer.reply(reply)
                        }
                        Role::Authority(_) => Err(TransportError::Corrupt),
                    },
                    Ok(None) => Ok(()),
                    Err(error) => Err(error),
                };
                if outcome.is_err() {
                    if let Some(peer) = peers.live_mut(index) {
                        peer.revoke(&mut clipboard);
                    }
                    peers.retire(index);
                } else {
                    index += 1;
                }
            }
            let now = endpoint::now_ns();
            clipboard.tick(Time::observe(now));
            let current = clipboard.storage().usage();
            if current != usage {
                println!(
                    "AIRLOCK_CLIPBOARD_STORAGE boot={nonce} ram_bytes={ram} disk_bytes={disk}",
                    ram = current.ram_bytes,
                    disk = current.disk_bytes
                );
                let (live, peak) = crate::heap::APPLICATION_HEAP.usage();
                println!(
                    "AIRLOCK_CLIPBOARD_HEAP cap={cap} live={live} peak={peak}",
                    cap = crate::heap::APP_HEAP_BYTES
                );
                usage = current;
            }
            let mut index = 0;
            while index < peers.retiring_len() {
                if !peers.reclaim_with(index, |connection| connection.close(now).is_ok()) {
                    index += 1;
                }
            }
            // Event-driven waits also wake for bounded liveness and unfinished-copy cleanup.
            let interval = if peers.retiring_len() == 0 {
                1_000_000_000
            } else {
                10_000_000
            };
            match endpoint::wait(observed, now.saturating_add(interval)) {
                Ok(()) | Err(TransportError::Timeout) => (),
                Err(error) => return Err(error),
            }
        }
    })();
    println!(
        "AIRLOCK_CLIPBOARD_SHUTDOWN boot={nonce} live={live} retiring={retiring}",
        live = peers.live_len(),
        retiring = peers.retiring_len()
    );
    while peers.live_len() > 0 {
        if let Some(peer) = peers.live_mut(0) {
            peer.revoke(&mut clipboard);
        }
        peers.retire(0);
    }
    // The authority owns this guest lifetime. Do not admit new work during cleanup.
    // Device bytes remain volatile and inaccessible; boot after failure starts empty.
    let shutdown_deadline = endpoint::now_ns().saturating_add(2_000_000_000);
    let mut attempts = 0;
    loop {
        let now = endpoint::now_ns();
        let mut index = 0;
        while index < peers.retiring_len() {
            if !peers.reclaim_with(index, |peer| peer.close(now).is_ok()) {
                index += 1;
            }
        }
        let control_closed = control.close(now).is_ok();
        if peers.retiring_len() == 0 && control_closed {
            return outcome;
        }
        if now >= shutdown_deadline || attempts >= 200 {
            // Guest termination delegates outstanding grant teardown to Xen/toolstack.
            // Never resume admission or reuse quarantined handles after this outcome.
            return Err(TransportError::Timeout);
        }
        attempts += 1;
        let observed = endpoint::generation();
        let _wake = endpoint::wait(
            observed,
            now.saturating_add(10_000_000).min(shutdown_deadline),
        );
    }
}
