//! Normal clipboard protocol shared by Hermit and its authenticated Linux endpoints.
//! Packets are bounded before allocation and fragmented across existing Xen frames.

use airlock_clipboard_core::shared::{
    Clipboard, Error, Format, MAX_FORMAT_NAME, MAX_FORMATS, Offer, Participant,
};
use xen_transport::{Backend, Channel, Error as TransportError, Kind, MAX_PAYLOAD, Message};

/// Largest complete control packet, including all offered format names.
pub const MAX_PACKET: usize = 16 * 1024;

/// Largest payload chunk in one desktop representation operation.
pub const DATA_CHUNK: usize = 4096;

/// Operations accepted only after the transport has established caller identity.
pub enum Request {
    /// Query current clipboard generation and complete representations.
    Offer,
    /// Reserve replacement order before asynchronous desktop format conversion.
    Reserve,
    /// Declare the representations of this reserved generation.
    Declare {
        /// Reservation returned to this connection.
        generation: u64,
        /// Bounded desktop representations, with exact byte lengths.
        formats: Vec<Format>,
    },
    /// Append one ordered private chunk.
    Write {
        /// Reserved generation owned by this connection.
        generation: u64,
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
        generation: u64,
    },
    /// Read a range without consuming published content.
    Read {
        /// Exact published generation; replacements invalidate reads.
        generation: u64,
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
        u64,
    ),
    /// Current generation, including clears, and any published offer.
    Offer(
        /// Latest replacement identity, including pending and cleared content.
        u64,
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
pub fn execute(
    clipboard: &mut Clipboard,
    now: u64,
    caller: Participant,
    request: Request,
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
            .complete(now, caller, generation)
            .map(|()| Reply::Ok),
        Request::Read {
            generation,
            format,
            offset,
        } => clipboard
            .read(caller, generation, format, offset, DATA_CHUNK)
            .map(|bytes| Reply::Data(bytes.to_vec())),
        Request::Connect { .. } => Err(Error::Unauthorized),
    };
    result.unwrap_or_else(Reply::Error)
}

/// Cursor that checks every wire length before reading or allocating.
struct Reader<'a> {
    /// Remaining bytes of one already bounded packet.
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], TransportError> {
        if len > self.bytes.len() {
            return Err(TransportError::Malformed);
        }
        let (head, tail) = self.bytes.split_at(len);
        self.bytes = tail;
        Ok(head)
    }

    fn byte(&mut self) -> Result<u8, TransportError> {
        Ok(self.take(1)?[0])
    }

    fn number(&mut self) -> Result<u64, TransportError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn size(&mut self, maximum: usize) -> Result<usize, TransportError> {
        let n = usize::try_from(self.number()?).map_err(|_| TransportError::TooLarge)?;
        if n > maximum {
            return Err(TransportError::TooLarge);
        }
        Ok(n)
    }

    fn formats(&mut self) -> Result<Vec<Format>, TransportError> {
        let count = self.size(MAX_FORMATS)?;
        let mut formats = Vec::with_capacity(count);
        for _ in 0..count {
            let len = self.size(MAX_FORMAT_NAME)?;
            let name = std::str::from_utf8(self.take(len)?)
                .map_err(|_| TransportError::Malformed)?
                .to_owned();
            let size = self.size(airlock_clipboard_core::shared::DEFAULT_CAPACITY)?;
            formats.push(Format { name, size });
        }
        Ok(formats)
    }

    fn finish(self) -> Result<(), TransportError> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(TransportError::Malformed)
        }
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
                number(&mut bytes, *generation);
                formats(&mut bytes, offered);
            }
            Self::Write {
                generation,
                format,
                offset,
                bytes: data,
            } => {
                bytes.push(3);
                number(&mut bytes, *generation);
                number(&mut bytes, *format as u64);
                number(&mut bytes, *offset as u64);
                bytes.extend_from_slice(data);
            }
            Self::Complete { generation } => {
                bytes.push(4);
                number(&mut bytes, *generation);
            }
            Self::Read {
                generation,
                format,
                offset,
            } => {
                bytes.push(5);
                number(&mut bytes, *generation);
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
        let mut reader = Reader { bytes };
        if reader.byte()? != 2 {
            return Err(TransportError::Malformed);
        }
        let request = match reader.byte()? {
            0 => Self::Offer,
            1 => Self::Reserve,
            2 => Self::Declare {
                generation: reader.number()?,
                formats: reader.formats()?,
            },
            3 => {
                let generation = reader.number()?;
                let format = reader.size(MAX_FORMATS - 1)?;
                let offset = reader.size(airlock_clipboard_core::shared::DEFAULT_CAPACITY)?;
                if reader.bytes.len() > DATA_CHUNK {
                    return Err(TransportError::TooLarge);
                }
                let bytes = reader.take(reader.bytes.len())?.to_vec();
                Self::Write {
                    generation,
                    format,
                    offset,
                    bytes,
                }
            }
            4 => Self::Complete {
                generation: reader.number()?,
            },
            5 => Self::Read {
                generation: reader.number()?,
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
        let mut bytes = vec![2];
        match self {
            Self::Ok => bytes.push(0),
            Self::Generation(generation) => {
                bytes.push(1);
                number(&mut bytes, *generation);
            }
            Self::Offer(generation, offer) => {
                bytes.push(2);
                number(&mut bytes, *generation);
                bytes.push(u8::from(offer.is_some()));
                if let Some(offer) = offer {
                    number(&mut bytes, offer.source.principal);
                    number(&mut bytes, offer.source.epoch);
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
                });
            }
        }
        bytes
    }

    /// Decode a service response, checking every count and exact packet consumption.
    pub fn decode(bytes: &[u8]) -> Result<Self, TransportError> {
        if bytes.len() > MAX_PACKET {
            return Err(TransportError::TooLarge);
        }
        let mut reader = Reader { bytes };
        if reader.byte()? != 2 {
            return Err(TransportError::Malformed);
        }
        let reply = match reader.byte()? {
            0 => Self::Ok,
            1 => Self::Generation(reader.number()?),
            2 => {
                let generation = reader.number()?;
                let offer = match reader.byte()? {
                    0 => None,
                    1 => Some(Offer {
                        generation,
                        source: Participant {
                            principal: reader.number()?,
                            epoch: reader.number()?,
                        },
                        formats: reader.formats()?,
                    }),
                    _ => return Err(TransportError::Malformed),
                };
                Self::Offer(generation, offer)
            }
            3 => {
                if reader.bytes.len() > DATA_CHUNK {
                    return Err(TransportError::TooLarge);
                }
                Self::Data(reader.take(reader.bytes.len())?.to_vec())
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
                _ => return Err(TransportError::Malformed),
            }),
            _ => return Err(TransportError::Malformed),
        };
        reader.finish()?;
        Ok(reply)
    }
}

/// One bounded packet assembled across ordered transport frames.
#[derive(Default)]
pub struct Incoming {
    /// Sequence identity and declared total length of the active packet.
    active: Option<(u64, usize)>,
    /// Private bytes accumulated so far.
    bytes: Vec<u8>,
}

impl Incoming {
    /// Accept the next contiguous frame, returning a complete packet exactly once.
    pub fn push(&mut self, message: &Message) -> Result<Option<Vec<u8>>, TransportError> {
        let bytes = message.payload();
        if bytes.len() < 8 {
            return Err(TransportError::Malformed);
        }
        let length = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
        let offset = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
        if length == 0 || length > MAX_PACKET || bytes.len() == 8 {
            return Err(TransportError::TooLarge);
        }
        if self.active.is_none() {
            if offset != 0 {
                return Err(TransportError::Malformed);
            }
            self.active = Some((message.id, length));
        }
        if self.active != Some((message.id, length))
            || offset != self.bytes.len()
            || offset + bytes.len() - 8 > length
        {
            return Err(TransportError::Malformed);
        }
        self.bytes.extend_from_slice(&bytes[8..]);
        if self.bytes.len() == length {
            self.active = None;
            return Ok(Some(std::mem::take(&mut self.bytes)));
        }
        Ok(None)
    }
}

/// Frame a complete packet with explicit total length and offset in every frame.
pub fn frames(kind: Kind, id: u64, bytes: &[u8]) -> Result<Vec<Message>, TransportError> {
    if bytes.is_empty() || bytes.len() > MAX_PACKET {
        return Err(TransportError::TooLarge);
    }
    bytes
        .chunks(MAX_PAYLOAD - 8)
        .enumerate()
        .map(|(index, chunk)| {
            let mut payload = Vec::with_capacity(MAX_PAYLOAD);
            payload.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            payload.extend_from_slice(&((index * (MAX_PAYLOAD - 8)) as u32).to_le_bytes());
            payload.extend_from_slice(chunk);
            Message::new(kind, id, &payload)
        })
        .collect()
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
    let mut incoming = Incoming::default();
    loop {
        let message = channel.recv(deadline)?;
        if message.id != id || message.kind != Kind::Response {
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
            generation: 9,
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
            Ok(Request::Write { generation: 9, .. })
        ));
        assert!(Incoming::default().push(&frames[1]).is_err());
        let mut invalid = Request::Offer.encode();
        invalid.push(0);
        assert!(Request::decode(&invalid).is_err());
    }

    #[test]
    fn data_endpoint_cannot_provision_another_identity() {
        let mut clipboard = Clipboard::new(1024);
        let caller = Participant {
            principal: 1,
            epoch: 2,
        };
        assert!(matches!(
            execute(
                &mut clipboard,
                0,
                caller,
                Request::Connect {
                    principal: 2,
                    domain: 3
                }
            ),
            Reply::Error(Error::Unauthorized)
        ));
    }
}
