//! Normal clipboard protocol shared by Hermit and its authenticated Linux endpoints.
//! Packets are bounded before allocation and fragmented across existing Xen frames.

use airlock_clipboard_core::shared::{
    Caller, Clipboard, Error, Format, MAX_FORMAT_NAME, MAX_FORMATS, Offer, Participant,
};
pub use airlock_clipboard_core::values::{Generation, Time};
use xen_transport::{Backend, Channel, Error as TransportError, Kind, MAX_PAYLOAD, Message};

/// Largest complete control packet, including all offered format names.
pub use airlock_clipboard_core::packet::MAX_PACKET;

/// Largest payload chunk in one desktop representation operation.
pub use airlock_clipboard_core::packet::DATA_CHUNK;

/// Operations accepted only after the transport has established caller identity.
pub enum Request {
    /// Query current clipboard generation and complete representations.
    Offer,
    /// Reserve replacement order before asynchronous desktop format conversion.
    Reserve,
    /// Declare the representations of this reserved generation.
    Declare {
        /// Reservation returned to this connection.
        generation: Generation,
        /// Bounded desktop representations, with exact byte lengths.
        formats: Vec<Format>,
    },
    /// Append one ordered private chunk.
    Write {
        /// Reserved generation owned by this connection.
        generation: Generation,
        /// Representation index within the original offer.
        format: usize,
        /// Contiguous byte offset.
        offset: usize,
        /// Private bytes, intentionally absent from Debug output.
        bytes: Vec<u8>,
    },
    /// Publish a completely received offer.
    Complete {
        /// Generation to publish atomically.
        generation: Generation,
    },
    /// Read a range without consuming published content.
    Read {
        /// Exact published generation; replacements invalidate reads.
        generation: Generation,
        /// Representation selected by the destination application.
        format: usize,
        /// First requested byte.
        offset: usize,
    },
    /// Provision a data endpoint; accepted only on the trusted authority connection.
    Connect {
        /// Stable principal from the admitted machine membership.
        principal: u64,
        /// Current Xen domain resolved through the Qubes administration API.
        domain: u16,
    },
}

/// Reply metadata and private bytes, never formatted for diagnostics.
pub enum Reply {
    /// Mutation completed successfully.
    Ok,
    /// Reservation assigned to this connection.
    Generation(
        /// Issued replacement identity within this service boot.
        Generation,
    ),
    /// Current generation, including clears, and any published offer.
    Offer(
        /// Latest replacement identity, including pending and cleared content.
        Generation,
        /// Complete metadata, absent while pending or empty.
        Option<Offer>,
    ),
    /// Bounded representation bytes.
    Data(
        /// Private representation bytes copied out of the shared transport.
        Vec<u8>,
    ),
    /// Endpoint coordinates delivered through authenticated Qubes provisioning.
    Connected {
        /// Fresh connection lifetime used by this principal.
        epoch: u64,
        /// Hermit event-channel port restricted to the peer.
        port: u32,
        /// Transmit page grant restricted to the peer.
        grant: u32,
    },
    /// Stable error category without payloads or untrusted strings.
    Error(
        /// Stable rejection reason.
        Error,
    ),
}

/// Execute only data-plane requests; control operations never acquire authority here.
pub fn execute<S: airlock_clipboard_core::shared::storage::Storage>(
    clipboard: &mut Clipboard<S>,
    now: Time,
    caller: &Caller,
    request: Request,
) -> Reply {
    execute_with_clock(clipboard, now, caller, request, || now)
}

/// Execute with a fresh time observation after synchronous storage completion.
pub fn execute_with_clock<S: airlock_clipboard_core::shared::storage::Storage>(
    clipboard: &mut Clipboard<S>,
    now: Time,
    caller: &Caller,
    request: Request,
    finished_at: impl FnOnce() -> Time,
) -> Reply {
    let result = match request {
        Request::Offer => clipboard
            .offer(caller)
            .map(|(generation, offer)| Reply::Offer(generation, offer)),
        Request::Reserve => clipboard.reserve(now, caller).map(Reply::Generation),
        Request::Declare {
            generation,
            formats,
        } => clipboard
            .declare(now, caller, generation, formats)
            .map(|()| Reply::Ok),
        Request::Write {
            generation,
            format,
            offset,
            bytes,
        } => clipboard
            .write(now, caller, generation, format, offset, &bytes)
            .map(|()| Reply::Ok),
        Request::Complete { generation } => clipboard
            .complete_with_clock(now, caller, generation, finished_at)
            .map(|()| Reply::Ok),
        Request::Read {
            generation,
            format,
            offset,
        } => clipboard
            .read(caller, generation, format, offset, DATA_CHUNK)
            .map(Reply::Data),
        Request::Connect { .. } => Err(Error::Unauthorized),
    };
    result.unwrap_or_else(Reply::Error)
}

/// Preserve stable wire failure categories at the external Xen transport boundary.
fn packet_error(error: airlock_clipboard_core::packet::PacketError) -> TransportError {
    match error {
        airlock_clipboard_core::packet::PacketError::Malformed => TransportError::Malformed,
        airlock_clipboard_core::packet::PacketError::TooLarge
        | airlock_clipboard_core::packet::PacketError::Capacity => TransportError::TooLarge,
    }
}

/// Cursor that checks every wire length before reading or allocating.
struct Reader<'a> {
    /// Verified position and immutable snapshot; callers cannot reconstruct indices.
    cursor: airlock_clipboard_core::packet::Cursor<'a>,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, TransportError> {
        Ok(Self {
            cursor: airlock_clipboard_core::packet::Cursor::new(bytes).map_err(packet_error)?,
        })
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], TransportError> {
        self.cursor
            .take(len)
            .map(|span| span.as_bytes())
            .map_err(packet_error)
    }

    fn byte(&mut self) -> Result<u8, TransportError> {
        self.cursor.byte().map_err(packet_error)
    }

    fn number(&mut self) -> Result<u64, TransportError> {
        self.cursor.number().map_err(packet_error)
    }

    fn size(&mut self, maximum: usize) -> Result<usize, TransportError> {
        self.cursor.size(maximum).map_err(packet_error)
    }

    fn formats(&mut self) -> Result<Vec<Format>, TransportError> {
        let count = self.size(MAX_FORMATS)?;
        let mut formats = Vec::new();
        formats
            .try_reserve_exact(count)
            .map_err(|_| TransportError::TooLarge)?;
        for _ in 0..count {
            let len = self.size(MAX_FORMAT_NAME)?;
            let text =
                std::str::from_utf8(self.take(len)?).map_err(|_| TransportError::Malformed)?;
            let mut name = String::new();
            name.try_reserve_exact(text.len())
                .map_err(|_| TransportError::TooLarge)?;
            name.push_str(text);
            let size = self.size(airlock_clipboard_core::shared::DEFAULT_CAPACITY)?;
            formats.push(Format { name, size });
        }
        Ok(formats)
    }

    fn finish(self) -> Result<(), TransportError> {
        self.cursor.finish().map_err(packet_error)
    }
}

fn number(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn formats(bytes: &mut Vec<u8>, formats: &[Format]) {
    number(bytes, formats.len() as u64);
    for format in formats {
        number(bytes, format.name.len() as u64);
        bytes.extend_from_slice(format.name.as_bytes());
        number(bytes, format.size as u64);
    }
}

impl Request {
    /// Serialize a request; packet framing enforces the total size before transmission.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = vec![2];
        match self {
            Self::Offer => bytes.push(0),
            Self::Reserve => bytes.push(1),
            Self::Declare {
                generation,
                formats: offered,
            } => {
                bytes.push(2);
                number(&mut bytes, generation.get());
                formats(&mut bytes, offered);
            }
            Self::Write {
                generation,
                format,
                offset,
                bytes: data,
            } => {
                bytes.push(3);
                number(&mut bytes, generation.get());
                number(&mut bytes, *format as u64);
                number(&mut bytes, *offset as u64);
                bytes.extend_from_slice(data);
            }
            Self::Complete { generation } => {
                bytes.push(4);
                number(&mut bytes, generation.get());
            }
            Self::Read {
                generation,
                format,
                offset,
            } => {
                bytes.push(5);
                number(&mut bytes, generation.get());
                number(&mut bytes, *format as u64);
                number(&mut bytes, *offset as u64);
            }
            Self::Connect { principal, domain } => {
                bytes.push(6);
                number(&mut bytes, *principal);
                number(&mut bytes, u64::from(*domain));
            }
        }
        bytes
    }

    /// Reject oversized, truncated, trailing or unsupported wire representations.
    pub fn decode(bytes: &[u8]) -> Result<Self, TransportError> {
        if bytes.len() > MAX_PACKET {
            return Err(TransportError::TooLarge);
        }
        let mut reader = Reader::new(bytes)?;
        if reader.byte()? != 2 {
            return Err(TransportError::Malformed);
        }
        let request = match reader.byte()? {
            0 => Self::Offer,
            1 => Self::Reserve,
            2 => Self::Declare {
                generation: Generation::from_wire(reader.number()?),
                formats: reader.formats()?,
            },
            3 => {
                let generation = Generation::from_wire(reader.number()?);
                let format = reader.size(MAX_FORMATS - 1)?;
                let offset = reader.size(airlock_clipboard_core::shared::DEFAULT_CAPACITY)?;
                if reader.cursor.remaining() > DATA_CHUNK {
                    return Err(TransportError::TooLarge);
                }
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(reader.cursor.remaining())
                    .map_err(|_| TransportError::TooLarge)?;
                bytes.extend_from_slice(reader.take(reader.cursor.remaining())?);
                Self::Write {
                    generation,
                    format,
                    offset,
                    bytes,
                }
            }
            4 => Self::Complete {
                generation: Generation::from_wire(reader.number()?),
            },
            5 => Self::Read {
                generation: Generation::from_wire(reader.number()?),
                format: reader.size(MAX_FORMATS - 1)?,
                offset: reader.size(airlock_clipboard_core::shared::DEFAULT_CAPACITY)?,
            },
            6 => Self::Connect {
                principal: reader.number()?,
                domain: reader.size(u16::MAX as usize)? as u16,
            },
            _ => return Err(TransportError::Malformed),
        };
        reader.finish()?;
        Ok(request)
    }
}

impl Reply {
    /// Serialize a bounded response without logging private content.
    pub fn encode(&self) -> Vec<u8> {
        self.try_encode()
            .expect("bounded clipboard reply allocation failed")
    }

    /// Encode into one bounded reservation, returning exhaustion to the service loop.
    pub fn try_encode(&self) -> Result<Vec<u8>, TransportError> {
        match self {
            Self::Data(data) if data.len() > DATA_CHUNK => return Err(TransportError::TooLarge),
            Self::Offer(_, Some(offer))
                if offer.formats.len() > MAX_FORMATS
                    || offer
                        .formats
                        .iter()
                        .any(|format| format.name.len() > MAX_FORMAT_NAME) =>
            {
                return Err(TransportError::TooLarge);
            }
            _ => (),
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(MAX_PACKET)
            .map_err(|_| TransportError::TooLarge)?;
        bytes.push(2);
        match self {
            Self::Ok => bytes.push(0),
            Self::Generation(generation) => {
                bytes.push(1);
                number(&mut bytes, generation.get());
            }
            Self::Offer(generation, offer) => {
                bytes.push(2);
                number(&mut bytes, generation.get());
                bytes.push(u8::from(offer.is_some()));
                if let Some(offer) = offer {
                    number(&mut bytes, offer.source.principal());
                    number(&mut bytes, offer.source.epoch());
                    formats(&mut bytes, &offer.formats);
                }
            }
            Self::Data(data) => {
                bytes.push(3);
                bytes.extend_from_slice(data);
            }
            Self::Connected { epoch, port, grant } => {
                bytes.push(4);
                number(&mut bytes, *epoch);
                number(&mut bytes, u64::from(*port));
                number(&mut bytes, u64::from(*grant));
            }
            Self::Error(error) => {
                bytes.push(255);
                bytes.push(match error {
                    Error::Unauthorized => 1,
                    Error::Stale => 2,
                    Error::Bounds => 3,
                    Error::Unsupported => 4,
                    Error::Order => 5,
                    Error::Timeout => 6,
                    Error::Capacity => 7,
                    Error::Io => 8,
                });
            }
        }
        Ok(bytes)
    }

    /// Decode a service response, checking every count and exact packet consumption.
    pub fn decode(bytes: &[u8]) -> Result<Self, TransportError> {
        if bytes.len() > MAX_PACKET {
            return Err(TransportError::TooLarge);
        }
        let mut reader = Reader::new(bytes)?;
        if reader.byte()? != 2 {
            return Err(TransportError::Malformed);
        }
        let reply = match reader.byte()? {
            0 => Self::Ok,
            1 => Self::Generation(Generation::from_wire(reader.number()?)),
            2 => {
                let generation = Generation::from_wire(reader.number()?);
                let offer = match reader.byte()? {
                    0 => None,
                    1 => Some(Offer {
                        generation,
                        source: Participant::from_binding(reader.number()?, reader.number()?)
                            .ok_or(TransportError::Malformed)?,
                        formats: reader.formats()?,
                    }),
                    _ => return Err(TransportError::Malformed),
                };
                Self::Offer(generation, offer)
            }
            3 => {
                if reader.cursor.remaining() > DATA_CHUNK {
                    return Err(TransportError::TooLarge);
                }
                Self::Data(reader.take(reader.cursor.remaining())?.to_vec())
            }
            4 => Self::Connected {
                epoch: reader.number()?,
                port: reader.size(u32::MAX as usize)? as u32,
                grant: reader.size(u32::MAX as usize)? as u32,
            },
            255 => Self::Error(match reader.byte()? {
                1 => Error::Unauthorized,
                2 => Error::Stale,
                3 => Error::Bounds,
                4 => Error::Unsupported,
                5 => Error::Order,
                6 => Error::Timeout,
                7 => Error::Capacity,
                8 => Error::Io,
                _ => return Err(TransportError::Malformed),
            }),
            _ => return Err(TransportError::Malformed),
        };
        reader.finish()?;
        Ok(reply)
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
    if bytes.is_empty() || bytes.len() > MAX_PACKET {
        return Err(TransportError::TooLarge);
    }
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(bytes.len().div_ceil(MAX_PAYLOAD - 8))
        .map_err(|_| TransportError::TooLarge)?;
    for (index, chunk) in bytes.chunks(MAX_PAYLOAD - 8).enumerate() {
        let mut payload = [0; MAX_PAYLOAD];
        payload[..4].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        payload[4..8].copy_from_slice(&((index * (MAX_PAYLOAD - 8)) as u32).to_le_bytes());
        payload[8..8 + chunk.len()].copy_from_slice(chunk);
        frames.push(Message::new(kind, id, &payload[..8 + chunk.len()])?);
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
    for frame in frames(Kind::Request, id, &request.encode())? {
        channel.send(&frame, deadline)?;
    }
    let mut incoming = Incoming::responses();
    loop {
        let message = channel.recv(deadline)?;
        if message.id != id {
            return Err(TransportError::Malformed);
        }
        if let Some(bytes) = incoming.push(&message)? {
            return Reply::decode(&bytes);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragmented_binary_packets_roundtrip_and_reject_gaps_and_trailing_bytes() {
        let request = Request::Write {
            generation: Generation::from_wire(9),
            format: 1,
            offset: 2048,
            bytes: vec![255; DATA_CHUNK],
        };
        let encoded = request.encode();
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
        let mut invalid = Request::Offer.encode();
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
