//! The fixed native dom0 port is the authority boundary; a public parser or a
//! serialized domid cannot create this owner. Unknown I/O outcomes terminate
//! control; explicit close consumes the native client. There is no automatic
//! reconnect or replay in the same VM boot.

use airlock_qubes_control::{
    binding::{Assigned, Bound, Request},
    control::{Control, Step},
    projection::View,
};
use xen_transport::{
    Error as XenError,
    hermit::{
        endpoint,
        netback::{Netback, Status},
        vchan::Client,
    },
};

/// Failures exposed without QubesDB values or packet contents.
#[derive(Debug)]
pub enum Error {
    /// The original native Xen connection failed.
    Transport(
        /// Original native failure code, without control payloads.
        XenError,
    ),
    /// Framing, sequencing, clock, deadline or a bounded control capacity failed.
    Protocol,
    /// The original server closed its native connection.
    Closed,
    /// A caller supplied an owner other than the one captured for this barrier.
    Lease,
}

/// Result of one bounded scheduling turn. Every call checks native liveness
/// before consuming more data; only Idle is a drained native input observation.
#[derive(Debug)]
pub enum Event {
    /// No immediately readable data or outstanding acknowledgement remains.
    Idle,
    /// More bounded work remains or the native output is temporarily full.
    Progress,
    /// Native initial synchronization completed; source policies remain blocked.
    /// The application reports this with its admitted boot challenge. Its Qubes
    /// lifecycle owner must then request the normal upstream firewall reload:
    /// an initial dump cannot distinguish old roots from an unfinished update.
    Synchronized,
    /// A live update was applied; consult typed source rejection diagnostics.
    Changed,
    /// This exact handled-counter barrier received its native acknowledgement.
    Barrier {
        /// Nonreused local barrier selected by the deterministic control owner.
        serial: u32,
    },
}

/// The one actually owned dom0 QubesDB connection. This type has no unchecked
/// constructor, cloning or stream reset. Its mutable borrow excludes admission
/// while applying updates, and a Permit borrows it throughout one data operation.
#[must_use = "close the native connection explicitly before discarding its owner"]
pub struct Session {
    /// Fixed native dom0/111 stream; no clipboard framing is used.
    native: Client,
    /// Deterministic verified-body boundary for all control-data decisions.
    control: Control,
    /// One private buffer; ownership/counts come directly from the safe transport.
    input: [u8; 1024],
}

impl Session {
    /// Open the fixed native QubesDB endpoint. Missing setup (-2) has no mapping
    /// effect and may be retried by bounded startup code; any other failure needs
    /// VM teardown/recovery. The stream pump sends exactly one initial MULTIREAD.
    pub fn open() -> Result<Self, Error> {
        let now = endpoint::now_ns();
        let native =
            Client::open(0, 111, now.saturating_add(500_000_000)).map_err(Error::Transport)?;
        Ok(Self {
            native,
            control: Control::synchronizing_at(now),
            input: [0; 1024],
        })
    }

    /// Perform at most 1024 byte/control steps with bounded native prefix calls.
    /// Return promptly on backpressure; a continuing owner must schedule later
    /// turns fairly and call this before requesting a new interface permit.
    pub fn poll(&mut self) -> Result<Event, Error> {
        let result = self.poll_inner();
        if result.is_err() {
            self.control.disconnect();
        }
        result
    }

    /// Preserve exact byte/count correspondence at the narrow native boundary.
    fn poll_inner(&mut self) -> Result<Event, Error> {
        self.alive()?;
        for _ in 0..1024 {
            match self.control.step() {
                Step::Send => {
                    let count = self
                        .native
                        .try_write(self.control.outgoing())
                        .map_err(Error::Transport)?;
                    if count == 0 {
                        return Ok(Event::Progress);
                    }
                    if !self.control.published(count) {
                        return Err(Error::Protocol);
                    }
                }
                Step::Receive => {
                    let count = self
                        .native
                        .try_read(&mut self.input)
                        .map_err(Error::Transport)?;
                    if count == 0 {
                        return Ok(Event::Idle);
                    }
                    if !self.control.deliver(&self.input[..count]) {
                        return Err(Error::Protocol);
                    }
                }
                Step::Progress => (),
                Step::Synchronized => return Ok(Event::Synchronized),
                Step::Changed { .. } => return Ok(Event::Changed),
                Step::Barrier { serial } => return Ok(Event::Barrier { serial }),
                Step::Failed => return Err(Error::Protocol),
            }
        }
        Ok(Event::Progress)
    }

    /// Check monotonic deadlines and the actual original native endpoint.
    /// Any uncertain control effect closes the projection before returning.
    fn alive(&mut self) -> Result<(), Error> {
        if !self.control.tick(endpoint::now_ns()) {
            return Err(Error::Protocol);
        }
        match self.native.connected() {
            Ok(true) => Ok(()),
            Ok(false) => {
                self.control.disconnect();
                Err(Error::Closed)
            }
            Err(error) => {
                self.control.disconnect();
                Err(Error::Transport(error))
            }
        }
    }

    /// Borrow data for payload-free diagnostics. Data alone is not permission to
    /// forward or bind a raw domain ID; only an actual interface owner may be used.
    pub fn projection(&self) -> &View {
        self.control.projection()
    }

    /// Begin admission after the actual connected interface's toolstack
    /// assignment was observed. The pump must be at a request boundary.
    /// Native driver domains use Netback::attach so ordinary libxl teardown
    /// finishes without an external controller removing backend records. A native handled
    /// counter ACK fences earlier dom0 policy writes on the separate XS/QDB paths.
    /// The pending value stays bound to this original handle, peer and address
    /// observation. A policy/error/close may invalidate it while the barrier runs.
    pub fn prepare(&mut self, interface: &mut Netback) -> Result<Option<Pending>, Error> {
        self.alive()?;
        let mut bytes = [0; 128];
        let observation = interface.assignment(&mut bytes).map_err(Error::Transport)?;
        let Some(lease) = observation.lease() else {
            return Err(Error::Lease);
        };
        Ok(Request::begin(
            &mut self.control,
            self.native.handle(),
            lease,
            observation.peer(),
            observation.addresses(),
        )
        .map(|request| Pending { request }))
    }

    /// Consume the exact pending admission after its native barrier event. The
    /// supplied interface must still be the original owner. Recheck the native
    /// assignment and current policy, then borrow both for one bounded operation.
    /// An unrelated/fabricated serial cannot produce a pending admission value.
    pub fn admit(
        &mut self,
        interface: &mut Netback,
        pending: Pending,
    ) -> Result<Option<Certificate>, Error> {
        self.alive()?;
        let mut bytes = [0; 128];
        let observation = interface.assignment(&mut bytes).map_err(Error::Transport)?;
        let Some(lease) = observation.lease() else {
            return Err(Error::Lease);
        };
        let binding = match pending.request.finish(
            &self.control,
            self.native.handle(),
            lease,
            observation.peer(),
            observation.addresses(),
        ) {
            Some(value) => value,
            None => return Ok(None),
        };
        Ok(Some(Certificate { binding }))
    }

    /// Borrow permission for one bounded operation on an already bound owner.
    /// Drain pending control updates and progress native lifecycle first. The
    /// driver's backend watch rejects removed/recreated lease markers even when
    /// node changes coalesced. No XenStore transaction or QDB write is added to
    /// the packet copy itself; new-interface barriers happen only at binding.
    pub fn permit<'a>(
        &'a mut self,
        interface: &'a mut Netback,
        certificate: &'a Certificate,
    ) -> Result<Option<Permit<'a>>, Error> {
        self.alive()?;
        if !self.control.between_records() {
            return Ok(None);
        }
        // Do not call poll here: consuming an event internally could hide a
        // different interface's completed barrier from the application loop.
        let count = match self.native.try_read(&mut self.input) {
            Ok(value) => value,
            Err(error) => {
                self.control.disconnect();
                return Err(Error::Transport(error));
            }
        };
        if count > 0 {
            if !self.control.deliver(&self.input[..count]) {
                return Err(Error::Protocol);
            }
            return Ok(None);
        }
        if interface.progress().map_err(Error::Transport)? != Status::Ready {
            return Ok(None);
        }
        let Some(lease) = interface.handle() else {
            return Ok(None);
        };
        if !certificate.binding.eligible(
            &self.control,
            self.native.handle(),
            lease,
            interface.peer(),
        ) {
            return Ok(None);
        }
        Ok(Some(Permit {
            session: self,
            interface,
            certificate,
        }))
    }

    /// Consume this owner and explicitly release its native maps/events. Any
    /// uncertain release remains quarantined by the kernel until VM teardown.
    pub fn close(mut self) -> Result<(), Error> {
        self.control.disconnect();
        self.native.close().map_err(Error::Transport)
    }
}

/// Pending data decision, constructible only from this Session and an actual
/// connected interface. It is non-cloneable and consumed by admit.
pub struct Pending {
    /// Exact typed request produced by the deterministic state transition.
    request: Request,
}

impl Pending {
    /// Barrier correlation only; knowing this number cannot construct Pending.
    pub fn serial(&self) -> u32 {
        self.request.serial()
    }
}

/// A completed barrier bound to one connection and interface incarnation.
/// Reuse requires Session::permit and current policy; this cannot access a Xen
/// resource on its own and has no unchecked constructor or cloning operation.
pub struct Certificate {
    /// Completed deterministic decision carried unchanged to each effect gate.
    binding: Bound,
}

/// A single borrowed interface operation authorized against current data. It
/// cannot outlive either owner or overlap a policy replacement/lease retirement.
/// The caller must return it before polling the control stream again. Milestone
/// 03 uses the assigned set for source checks and the projection for packet rules.
pub struct Permit<'a> {
    /// The original live native control owner, immutably borrowed through accessors.
    session: &'a Session,
    /// The original exclusive interface owner, never chosen from packet contents.
    interface: &'a mut Netback,
    /// Original completed binding decision, rechecked against current policy.
    certificate: &'a Certificate,
}

impl<'a> Permit<'a> {
    /// Actual source-address authority for packet anti-spoofing decisions.
    pub fn assigned(&self) -> &Assigned {
        self.certificate.binding.assigned()
    }

    /// Current complete policy/configuration, held stable during this operation.
    pub fn projection(&self) -> &View {
        self.session.control.projection()
    }

    /// Consume permission for one native packet copy on this exact owner.
    /// This alone is not a packet allow decision; forwarding consumers must apply
    /// source checks and the current ordered snapshot before any output effect.
    pub fn receive(self, output: &'a mut [u8; 4096]) -> Result<Option<Received<'a>>, Error> {
        match self.interface.receive(output).map_err(Error::Transport)? {
            Some(length) => Ok(Some(Received {
                context: self,
                bytes: &output[..length],
            })),
            None => Ok(None),
        }
    }
}

/// One privately copied frame with the original interface and current policy
/// still borrowed. It exposes no second read or replay operation. Packet policy
/// can inspect these bytes and this stable context before choosing an output.
pub struct Received<'a> {
    /// Retains all exact source/connection/resource borrows until the decision ends.
    context: Permit<'a>,
    /// Exact private native prefix, immutable throughout parsing and policy checks.
    bytes: &'a [u8],
}

impl Received<'_> {
    /// Exact private packet bytes; their claimed source is never interface identity.
    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }

    /// Assigned source addresses belonging to the original native interface.
    pub fn assigned(&self) -> &Assigned {
        self.context.assigned()
    }

    /// Complete current policy/configuration held stable with this packet.
    pub fn projection(&self) -> &View {
        self.context.projection()
    }
}
