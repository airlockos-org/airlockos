//! smoltcp endpoint boundary for one DNS TCP fallback. The verified resolver
//! owns endpoint admission, query framing, response bounds, expiry and policy
//! revision checks. smoltcp supplies the entire TCP handshake, stream ordering,
//! acknowledgements and retransmission implementation; there is no custom TCP.
//!
//! Dependency correspondence: the IP device's MTU bounds every transmit token;
//! at most one input and two output packets are retained. Socket buffers are
//! fixed at one bounded DNS response and one question. All clocks are supplied
//! by the caller, and this adapter has no native send or ambient socket access.

use alloc::{collections::VecDeque, vec, vec::Vec};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp::{Socket, SocketBuffer},
    time::{Duration, Instant},
    wire::{HardwareAddress, IpAddress, IpCidr},
};
use vstd::prelude::*;

/// Actual maintained endpoint and its finite private IP device.
pub(crate) struct Connection {
    /// smoltcp IP interface, with one authoritative local IPv4 address.
    interface: Interface,
    /// Exactly one smoltcp TCP endpoint with owned bounded buffers.
    sockets: SocketSet<'static>,
    /// Original socket index; never selected using received packet claims.
    handle: SocketHandle,
    /// Private packet staging with no host or VM transport access.
    device: Queue,
}

/// Private IP packets exchanged only with the caller-owned resolver queue.
struct Queue {
    /// At most one supplied input datagram between polling turns.
    incoming: Option<Vec<u8>>,
    /// At most two MTU-sized outputs, bounded by transmit-token admission.
    outgoing: VecDeque<Vec<u8>>,
}

/// One consumed private input; no external memory can change after validation.
struct Receive(
    /// The exact private datagram fed by the resolver.
    Vec<u8>,
);

/// One admitted output slot, borrowed exclusively until token consumption.
struct Transmit<'a> {
    /// Queue whose length was below two when this token was created.
    outgoing: &'a mut VecDeque<Vec<u8>>,
}

impl Device for Queue {
    type RxToken<'a> = Receive;
    type TxToken<'a> = Transmit<'a>;

    fn receive(&mut self, _now: Instant) -> Option<(Receive, Transmit<'_>)> {
        if self.outgoing.len() >= 2 {
            return None;
        }
        let bytes = self.incoming.take()?;
        Some((
            Receive(bytes),
            Transmit {
                outgoing: &mut self.outgoing,
            },
        ))
    }

    fn transmit(&mut self, _now: Instant) -> Option<Transmit<'_>> {
        if self.outgoing.len() >= 2 {
            return None;
        }
        Some(Transmit {
            outgoing: &mut self.outgoing,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = crate::MTU;
        capabilities
    }
}

impl RxToken for Receive {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, operation: F) -> R {
        operation(&self.0)
    }
}

impl TxToken for Transmit<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, length: usize, operation: F) -> R {
        // A violation is a fatal codec/dependency contract failure, not an
        // accepted hostile length: smoltcp selects length using Device's MTU.
        assert!(length <= crate::MTU, "smoltcp exceeded its configured MTU");
        let mut bytes = vec![0; length];
        let result = operation(&mut bytes);
        self.outgoing.push_back(bytes);
        result
    }
}

verus! {

/// Opaque maintained endpoint; verification does not replace TCP with a model.
#[cfg(verus_keep_ghost)]
#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExConnection(/// Real smoltcp endpoint and private device.
    Connection);

/// Open one endpoint using only the resolver's previously selected addresses.
#[verifier::external_body]
pub(crate) fn open(local: [u8; 4], server: [u8; 4], port: u16, seed: u64, now: u64) -> Option<Connection> {
    let mut device = Queue { incoming: None, outgoing: VecDeque::new() };
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = seed;
    let time = Instant::from_millis((now / 1_000_000) as i64);
    let mut interface = Interface::new(config, &mut device, time);
    interface.update_ip_addrs(|addresses| { addresses.push(IpCidr::new(IpAddress::Ipv4(local.into()), 32)).expect("one address slot"); });
    interface.routes_mut().add_default_ipv4_route(server.into()).ok()?;
    let mut socket = Socket::new(SocketBuffer::new(vec![0; super::TCP_BYTES + 2]), SocketBuffer::new(vec![0; 273]));
    socket.set_timeout(Some(Duration::from_secs(10)));
    socket.connect(interface.context(), (IpAddress::Ipv4(server.into()), 53), (IpAddress::Ipv4(local.into()), port)).ok()?;
    let mut sockets = SocketSet::new(Vec::new());
    let handle = sockets.add(socket);
    Some(Connection { interface, sockets, handle, device })
}

/// Stage one already correlated private IP datagram without replacing pending input.
#[verifier::external_body]
pub(crate) fn input(connection: &mut Connection, bytes: &[u8])
    requires bytes@.len() <= crate::MTU,
{
    if connection.device.incoming.is_none() { connection.device.incoming = Some(bytes.to_vec()); }
}

/// Poll the maintained stack once and take at most one bounded IP output.
#[verifier::external_body]
pub(crate) fn poll(connection: &mut Connection, now: u64) -> (packet: Option<Vec<u8>>)
    ensures packet.is_some() ==> packet.unwrap()@.len() <= crate::MTU,
{
    connection.interface.poll(Instant::from_millis((now / 1_000_000) as i64), &mut connection.device, &mut connection.sockets);
    connection.device.outgoing.pop_front()
}

/// Give the socket only the unsent suffix; returned progress never exceeds it.
#[verifier::external_body]
pub(crate) fn write(connection: &mut Connection, bytes: &[u8]) -> (count: usize)
    ensures count <= bytes@.len(),
{ connection.sockets.get_mut::<Socket>(connection.handle).send_slice(bytes).unwrap_or(0) }

/// Copy at most the caller's remaining DNS budget from the ordered TCP stream.
#[verifier::external_body]
pub(crate) fn read(connection: &mut Connection, limit: usize) -> (bytes: Vec<u8>)
    requires limit <= super::TCP_BYTES + 2,
    ensures bytes@.len() <= limit,
{
    connection.sockets.get_mut::<Socket>(connection.handle).recv(|bytes| {
        let count = bytes.len().min(limit);
        (count, bytes[..count].to_vec())
    }).unwrap_or_default()
}

/// Ask the maintained socket to release its remote peer with a TCP reset.
#[verifier::external_body]
pub(crate) fn abort(connection: &mut Connection) {
    connection.device.outgoing.clear();
    connection.device.incoming = None;
    connection.sockets.get_mut::<Socket>(connection.handle).abort();
}

}
