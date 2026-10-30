//! Normal clipboard protocol shared by Hermit and its authenticated Linux endpoints.
//! Packets are bounded before allocation and fragmented across existing Xen frames.
//!
//! Verification exception: foreign Channel/Message methods are not modeled by
//! pinned vstd. This adapter relies on Message owning an immutable copied payload,
//! the channel retaining its constructor's authenticated peer, and send/receive
//! preserving kind, ID and bytes. It passes those exact owned bytes to the verified
//! codec/assembler and wraps the verified sender's exact payload without rebuilding
//! offsets. The compile-time payload-limit assertion protects the ABI bound;
//! direction and response-ID checks stay beside the foreign message operations.

pub use airlock_clipboard_core::values::{Generation, Time};
use xen_transport::{Backend, Channel, Error as TransportError, Kind, MAX_PAYLOAD, Message};

/// Largest complete control packet, including all offered format names.
pub use airlock_clipboard_core::packet::MAX_PACKET;

/// Largest payload chunk in one desktop representation operation.
pub use airlock_clipboard_core::packet::DATA_CHUNK;

pub use airlock_clipboard_core::protocol::{Reply, Request};

pub use airlock_clipboard_core::protocol::{execute, execute_with_clock};

/// Preserve stable wire failure categories at the external Xen transport boundary.
pub(crate) fn packet_error(error: airlock_clipboard_core::packet::PacketError) -> TransportError {
    match error {
        airlock_clipboard_core::packet::PacketError::Malformed => TransportError::Malformed,
        airlock_clipboard_core::packet::PacketError::TooLarge
        | airlock_clipboard_core::packet::PacketError::Capacity => TransportError::TooLarge,
    }
}

/// One verified, bounded packet assembler for this connection's lifetime.
pub struct Incoming {
    /// Immutable direction expected on this connection, chosen before reading frames.
    expected: Kind,
    /// Owns the exact contiguous prefix and rejects completed request identifiers.
    assembly: airlock_clipboard_core::framing::Assembly,
}

impl Default for Incoming {
    fn default() -> Self {
        Self {
            expected: Kind::Request,
            assembly: airlock_clipboard_core::framing::Assembly::new(),
        }
    }
}

impl Incoming {
    /// Receive only response frames for an exclusively owned request/reply client.
    pub fn responses() -> Self {
        Self {
            expected: Kind::Response,
            assembly: airlock_clipboard_core::framing::Assembly::new(),
        }
    }

    /// Accept one owned transport snapshot; terminal errors require connection retirement.
    pub fn push(&mut self, message: &Message) -> Result<Option<Vec<u8>>, TransportError> {
        if message.kind != self.expected {
            self.assembly.reject();
            return Err(TransportError::Malformed);
        }
        self.assembly
            .push(message.id, message.payload())
            .map_err(packet_error)
    }

    /// Correlate a response with the exact request whose packet completed validation.
    pub fn completed_id(&self) -> u64 {
        self.assembly.completed_id()
    }
}

// This protocol reuses the existing transport's payload size; a dependency change
// must not silently alter framing or invalidate the verified range bounds.
const _: () = assert!(MAX_PAYLOAD == airlock_clipboard_core::framing::FRAME_LIMIT);

/// Frame a complete packet with explicit total length and offset in every frame.
pub fn frames(kind: Kind, id: u64, bytes: &[u8]) -> Result<Vec<Message>, TransportError> {
    if !matches!(kind, Kind::Request | Kind::Response) {
        return Err(TransportError::Malformed);
    }
    let mut fragments =
        airlock_clipboard_core::framing::Fragments::new(bytes).map_err(packet_error)?;
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(fragments.remaining())
        .map_err(|_| TransportError::TooLarge)?;
    while let Some(frame) = fragments.next_frame() {
        frames.push(Message::new(kind, id, frame.as_bytes())?);
    }
    Ok(frames)
}

/// Execute one synchronous request on an exclusively owned authenticated connection.
pub fn exchange<B: Backend>(
    channel: &mut Channel<B>,
    id: u64,
    request: &Request,
) -> Result<Reply, TransportError> {
    let deadline = channel.deadline_after(10_000_000_000);
    for frame in frames(
        Kind::Request,
        id,
        &request.try_encode().map_err(packet_error)?,
    )? {
        channel.send(&frame, deadline)?;
    }
    let mut incoming = Incoming::responses();
    loop {
        let message = channel.recv(deadline)?;
        if message.id != id {
            return Err(TransportError::Malformed);
        }
        if let Some(bytes) = incoming.push(&message)? {
            return Reply::decode(&bytes).map_err(packet_error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use airlock_clipboard_core::shared::{Clipboard, Error, Participant};

    #[test]
    fn fragmented_binary_packets_roundtrip_and_reject_gaps_and_trailing_bytes() {
        let request = Request::Write {
            generation: Generation::from_wire(9),
            format: 1,
            offset: 2048,
            bytes: vec![255; DATA_CHUNK],
        };
        let encoded = request.try_encode().unwrap();
        let frames = frames(Kind::Request, 1, &encoded).unwrap();
        let mut incoming = Incoming::default();
        let mut completed = None;
        for frame in &frames {
            if let Some(bytes) = incoming.push(frame).unwrap() {
                completed = Some(bytes);
            }
        }
        assert_eq!(completed.unwrap(), encoded);
        assert!(matches!(
            Request::decode(&encoded),
            Ok(Request::Write { generation, .. }) if generation == Generation::from_wire(9)
        ));
        assert!(Incoming::default().push(&frames[1]).is_err());
        let mut invalid = Request::Offer.try_encode().unwrap();
        invalid.push(0);
        assert!(Request::decode(&invalid).is_err());
    }

    #[test]
    fn replay_interleaving_and_wrong_direction_require_a_fresh_connection() {
        let packet = vec![7; DATA_CHUNK];
        let first = frames(Kind::Request, 1, &packet).unwrap();
        let next = frames(Kind::Request, 2, &packet).unwrap();
        let mut incoming = Incoming::default();
        for frame in &first {
            incoming.push(frame).unwrap();
        }
        assert_eq!(incoming.completed_id(), 1);
        assert!(incoming.push(&first[0]).is_err());
        assert!(incoming.push(&next[0]).is_err());

        let mut incoming = Incoming::default();
        incoming.push(&first[0]).unwrap();
        assert!(incoming.push(&next[1]).is_err());
        assert!(incoming.push(&first[1]).is_err());

        let responses = frames(Kind::Response, 1, &packet).unwrap();
        let mut incoming = Incoming::default();
        assert!(incoming.push(&responses[0]).is_err());
        assert!(incoming.push(&first[0]).is_err());
        let mut response_receiver = Incoming::responses();
        let mut reconstructed = None;
        for frame in &responses {
            reconstructed = response_receiver.push(frame).unwrap();
        }
        assert_eq!(reconstructed.unwrap(), packet);
    }

    #[test]
    fn data_endpoint_cannot_provision_another_identity() {
        let (mut clipboard, provisioner) = Clipboard::new(1024);
        let caller = clipboard
            .admit(&provisioner, Participant::from_binding(1, 2).unwrap())
            .unwrap();
        assert!(matches!(
            execute(
                &mut clipboard,
                Time::observe(0),
                &caller,
                Request::Connect {
                    principal: 2,
                    domain: 3
                }
            ),
            Reply::Error(Error::Unauthorized)
        ));
    }
}
