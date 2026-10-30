//! Clipboard wire values and bounded encoding, independent of transport or caller authority.
//! Decoding only constructs claims. All access remains checked by the owned Caller capability.

use crate::packet::{Cursor, DATA_CHUNK, MAX_PACKET, PacketError};
use crate::shared::{
    Caller, Clipboard, DEFAULT_CAPACITY, Error, Format, Generation, MAX_FORMAT_NAME, MAX_FORMATS,
    Offer, Participant, Time,
};
use alloc::{string::String, vec::Vec};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::string::StringSliceAdditionalSpecFns;

verus! {

broadcast use vstd::seq::group_seq_lemmas;


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

/// Wire-name bounds are syntax; clipboard policy applies stricter admissibility later.
pub open spec fn wire_formats(formats: Seq<Format>) -> bool {
    formats.len() <= MAX_FORMATS && (forall|i: int| 0 <= i < formats.len() ==>
        vstd::utf8::encode_utf8(formats[i].name@).len() <= MAX_FORMAT_NAME && formats[i].size <= DEFAULT_CAPACITY)
}

/// Canonical little-endian metadata encoding in source preference order.
pub open spec fn packed_formats(formats: Seq<Format>) -> Seq<u8>
    decreases formats.len(),
{
    if formats.len() == 0 { Seq::empty() } else {
        packed_formats(formats.drop_last()) + vstd::bytes::spec_u64_to_le_bytes(vstd::utf8::encode_utf8(formats.last().name@).len() as u64)
            + vstd::utf8::encode_utf8(formats.last().name@) + vstd::bytes::spec_u64_to_le_bytes(formats.last().size as u64)
    }
}

/// Accepted metadata has a fixed worst-case wire cost per representation.
proof fn packed_bound(formats: Seq<Format>)
    requires wire_formats(formats),
    ensures packed_formats(formats).len() <= formats.len() * (16 + MAX_FORMAT_NAME),
    decreases formats.len(),
{
    vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes();
    if formats.len() > 0 {
        assert(wire_formats(formats.drop_last()));
        packed_bound(formats.drop_last());
    }
}

/// Stable rejection tag; the value carries no rejected bytes or untrusted strings.
spec fn error_tag(error: Error) -> u8 {
    match error {
        Error::Unauthorized => 1, Error::Stale => 2, Error::Bounds => 3,
        Error::Unsupported => 4, Error::Order => 5, Error::Timeout => 6,
        Error::Capacity => 7, Error::Io => 8,
    }
}

/// A guarded little-endian word from a stable packet snapshot.
spec fn word(bytes: Seq<u8>, offset: int) -> u64 {
    vstd::bytes::spec_u64_from_le_bytes(bytes.subrange(offset, offset + 8))
}

/// Grammar of the remaining format entries; recursion is bounded by the checked count.
spec fn entries_syntax(bytes: Seq<u8>, offset: int, count: nat) -> bool
    decreases count,
{
    if count == 0 { offset == bytes.len() } else {
        0 <= offset && offset + 8 <= bytes.len() && word(bytes, offset) <= MAX_FORMAT_NAME
            && offset + 16 + word(bytes, offset) <= bytes.len()
            && vstd::utf8::valid_utf8(bytes.subrange(offset + 8, offset + 8 + word(bytes, offset)))
            && word(bytes, offset + 8 + word(bytes, offset)) <= DEFAULT_CAPACITY
            && entries_syntax(bytes, offset + 16 + word(bytes, offset), (count - 1) as nat)
    }
}

/// Complete format-list grammar, including exact consumption and bounded names/counts.
spec fn list_syntax(bytes: Seq<u8>, offset: int) -> bool {
    0 <= offset && offset + 8 <= bytes.len() && word(bytes, offset) <= MAX_FORMATS
        && entries_syntax(bytes, offset + 8, word(bytes, offset) as nat)
}

/// Acceptance grammar of request version 2, independent of the executable decoder.
pub closed spec fn request_syntax(bytes: Seq<u8>) -> bool {
    2 <= bytes.len() <= MAX_PACKET && bytes[0] == 2 && match bytes[1] {
        0 | 1 => bytes.len() == 2,
        2 => list_syntax(bytes, 10),
        3 => 26 <= bytes.len() <= 26 + DATA_CHUNK && word(bytes, 10) < MAX_FORMATS && word(bytes, 18) <= DEFAULT_CAPACITY,
        4 => bytes.len() == 10,
        5 => bytes.len() == 26 && word(bytes, 10) < MAX_FORMATS && word(bytes, 18) <= DEFAULT_CAPACITY,
        6 => bytes.len() == 18 && word(bytes, 10) <= u16::MAX,
        _ => false,
    }
}

/// Acceptance grammar of responses, including identity metadata and stable error tags.
pub closed spec fn reply_syntax(bytes: Seq<u8>) -> bool {
    2 <= bytes.len() <= MAX_PACKET && bytes[0] == 2 && match bytes[1] {
        0 => bytes.len() == 2,
        1 => bytes.len() == 10,
        2 => bytes.len() >= 11 && match bytes[10] {
            0 => bytes.len() == 11,
            1 => bytes.len() >= 35 && word(bytes, 11) > 0 && word(bytes, 19) > 0 && list_syntax(bytes, 27),
            _ => false,
        },
        3 => bytes.len() <= 2 + DATA_CHUNK,
        4 => bytes.len() == 26 && word(bytes, 10) <= u32::MAX && word(bytes, 18) <= u32::MAX,
        255 => bytes.len() == 3 && 1 <= bytes[2] <= 8,
        _ => false,
    }
}

/// Reject metadata that could exceed the bounded packet before any encoder allocation.
fn check_formats(formats: &[Format]) -> (out: Result<(), PacketError>)
    ensures out.is_ok() == wire_formats(formats@),
{
    if formats.len() > MAX_FORMATS { return Err(PacketError::TooLarge); }
    let mut i = 0;
    while i < formats.len()
        invariant i <= formats.len(), formats.len() <= MAX_FORMATS,
            forall|j: int| 0 <= j < i ==> vstd::utf8::encode_utf8(formats[j].name@).len() <= MAX_FORMAT_NAME && formats[j].size <= DEFAULT_CAPACITY,
        decreases formats.len() - i,
    {
        let format = &formats[i];
        let text = format.name.as_str();
        let name = text.as_bytes();
        if name.len() > MAX_FORMAT_NAME || format.size > DEFAULT_CAPACITY { return Err(PacketError::TooLarge); }
        assert(vstd::utf8::encode_utf8(formats[i as int].name@).len() <= MAX_FORMAT_NAME);
        i += 1;
    }
    Ok(())
}

impl<'a> Cursor<'a> {
    fn formats(&mut self) -> (out: Result<Vec<Format>, PacketError>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).contents() == old(self).contents(),
            list_syntax(old(self).contents(), old(self).position() as int) ==> out.is_ok() || out == Err(PacketError::Capacity),
            out.is_ok() ==> (list_syntax(old(self).contents(), old(self).position() as int)
                    == (final(self).position() == final(self).contents().len())) && wire_formats(out.unwrap()@)
                && final(self).position() >= old(self).position() + 8
                && old(self).contents().subrange(old(self).position() as int, final(self).position() as int)
                    == vstd::bytes::spec_u64_to_le_bytes(out.unwrap()@.len() as u64) + packed_formats(out.unwrap()@),
    {
        proof { vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes(); }
        let count = self.size(MAX_FORMATS)?;
        let mut formats = Vec::new();
        formats
            .try_reserve_exact(count)
            .map_err(|_error| -> (error: PacketError) ensures error == PacketError::Capacity { PacketError::Capacity })?;
        let mut i = 0;
        while i < count
            invariant self.valid(), self.contents() == old(self).contents(),
                i <= count <= MAX_FORMATS, formats@.len() == i,
                wire_formats(formats@), self.position() >= old(self).position() + 8,
                list_syntax(old(self).contents(), old(self).position() as int) == entries_syntax(self.contents(), self.position() as int, (count - i) as nat),
                self.contents().subrange(old(self).position() as int, self.position() as int)
                    == vstd::bytes::spec_u64_to_le_bytes(count as u64) + packed_formats(formats@),
            decreases count - i,
        {
            proof { vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes(); }
            let ghost previous = self.position();
            let ghost old_formats = formats@;
            let len = self.size(MAX_FORMAT_NAME)?;
            assert(self.contents().subrange(previous as int, self.position() as int) == vstd::bytes::spec_u64_to_le_bytes(len as u64));
            let text =
                core::str::from_utf8(self.take(len)?.as_bytes()).map_err(|_| PacketError::Malformed)?;
            let mut name = String::new();
            name.try_reserve_exact(text.len())
                .map_err(|_error| -> (error: PacketError) ensures error == PacketError::Capacity { PacketError::Capacity })?;
            name.push_str(text);
            let size = self.size(DEFAULT_CAPACITY)?;
            formats.push(Format { name, size });
            assert(formats@.drop_last() == old_formats);
            assert(self.contents().subrange(previous as int, self.position() as int)
                == vstd::bytes::spec_u64_to_le_bytes(len as u64) + vstd::utf8::encode_utf8(formats@.last().name@)
                    + vstd::bytes::spec_u64_to_le_bytes(size as u64));
            assert(self.contents().subrange(old(self).position() as int, self.position() as int)
                == self.contents().subrange(old(self).position() as int, previous as int)
                    + self.contents().subrange(previous as int, self.position() as int));
            i += 1;
        }
        Ok(formats)
    }

}

fn number(bytes: &mut Vec<u8>, value: u64)
    ensures final(bytes)@ == old(bytes)@ + vstd::bytes::spec_u64_to_le_bytes(value),
{
    let word = [
        (value & 0xff) as u8, ((value >> 8) & 0xff) as u8,
        ((value >> 16) & 0xff) as u8, ((value >> 24) & 0xff) as u8,
        ((value >> 32) & 0xff) as u8, ((value >> 40) & 0xff) as u8,
        ((value >> 48) & 0xff) as u8, ((value >> 56) & 0xff) as u8,
    ];
    proof { vstd::bytes::spec_u64_to_le_bytes_to_open(value); }
    assert(word@ =~= vstd::bytes::spec_u64_to_le_bytes(value));
    bytes.extend_from_slice(&word);
}

fn formats(bytes: &mut Vec<u8>, formats: &[Format])
    ensures final(bytes)@ == old(bytes)@ + vstd::bytes::spec_u64_to_le_bytes(formats@.len() as u64) + packed_formats(formats@),
{
    proof { vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes(); }
    number(bytes, formats.len() as u64);
    let mut i = 0;
    while i < formats.len()
        invariant i <= formats.len(), bytes@ == old(bytes)@ + vstd::bytes::spec_u64_to_le_bytes(formats@.len() as u64) + packed_formats(formats@.take(i as int)),
        decreases formats.len() - i,
    {
        proof { vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes(); }
        let format = &formats[i];
        let text = format.name.as_str();
        let name = text.as_bytes();
        number(bytes, name.len() as u64);
        bytes.extend_from_slice(name);
        number(bytes, format.size as u64);
        assert(formats@.take(i as int + 1).drop_last() == formats@.take(i as int));
        assert(formats@.take(i as int + 1).last() == formats[i as int]);
        i += 1;
    }
    assert(formats@.take(i as int) == formats@);
}

impl Request {
    /// Exactly the syntax bounds accepted by this wire version; this grants no access.
    pub open spec fn valid(&self) -> bool {
        match self {
            Self::Declare { formats, .. } => wire_formats(formats@),
            Self::Write { format, offset, bytes, .. } => *format < MAX_FORMATS && *offset <= DEFAULT_CAPACITY && bytes@.len() <= DATA_CHUNK,
            Self::Read { format, offset, .. } => *format < MAX_FORMATS && *offset <= DEFAULT_CAPACITY,
            _ => true,
        }
    }

    /// Canonical byte sequence, preserving every operation, field, name and payload byte.
    pub open spec fn wire(&self) -> Seq<u8> {
        seq![2u8] + match self {
            Self::Offer => seq![0u8], Self::Reserve => seq![1u8],
            Self::Declare { generation, formats } => seq![2u8] + vstd::bytes::spec_u64_to_le_bytes(generation.number())
                + vstd::bytes::spec_u64_to_le_bytes(formats@.len() as u64) + packed_formats(formats@),
            Self::Write { generation, format, offset, bytes } => seq![3u8] + vstd::bytes::spec_u64_to_le_bytes(generation.number())
                + vstd::bytes::spec_u64_to_le_bytes(*format as u64) + vstd::bytes::spec_u64_to_le_bytes(*offset as u64) + bytes@,
            Self::Complete { generation } => seq![4u8] + vstd::bytes::spec_u64_to_le_bytes(generation.number()),
            Self::Read { generation, format, offset } => seq![5u8] + vstd::bytes::spec_u64_to_le_bytes(generation.number())
                + vstd::bytes::spec_u64_to_le_bytes(*format as u64) + vstd::bytes::spec_u64_to_le_bytes(*offset as u64),
            Self::Connect { principal, domain } => seq![6u8] + vstd::bytes::spec_u64_to_le_bytes(*principal)
                + vstd::bytes::spec_u64_to_le_bytes(*domain as u64),
        }
    }

    /// Each decoded field denotes its exact canonical offset in the original packet.
    /// Metadata and data tails are compared as bytes, rather than reconstructing
    /// field indices in a transport adapter or relying on a round-trip test.
    pub closed spec fn decoded_from(&self, bytes: Seq<u8>) -> bool {
        bytes.len() >= 2 && bytes[0] == 2 && match self {
            Self::Offer => bytes[1] == 0 && bytes.len() == 2,
            Self::Reserve => bytes[1] == 1 && bytes.len() == 2,
            Self::Declare { generation, formats } => bytes[1] == 2 && bytes.len() >= 18
                && generation.number() == word(bytes, 2)
                && vstd::bytes::spec_u64_to_le_bytes(formats@.len() as u64) + packed_formats(formats@) == bytes.subrange(10, bytes.len() as int),
            Self::Write { generation, format, offset, bytes: data } => bytes[1] == 3 && bytes.len() >= 26
                && generation.number() == word(bytes, 2) && *format == word(bytes, 10) && *offset == word(bytes, 18)
                && data@ == bytes.subrange(26, bytes.len() as int),
            Self::Complete { generation } => bytes[1] == 4 && bytes.len() == 10 && generation.number() == word(bytes, 2),
            Self::Read { generation, format, offset } => bytes[1] == 5 && bytes.len() == 26
                && generation.number() == word(bytes, 2) && *format == word(bytes, 10) && *offset == word(bytes, 18),
            Self::Connect { principal, domain } => bytes[1] == 6 && bytes.len() == 18
                && *principal == word(bytes, 2) && *domain == word(bytes, 10),
        }
    }

    /// Serialize a request; packet framing enforces the total size before transmission.
    pub fn try_encode(&self) -> (out: Result<Vec<u8>, PacketError>)
        ensures out.is_ok() ==> self.valid() && out.unwrap()@ == self.wire() && out.unwrap()@.len() <= MAX_PACKET,
            out != Err(PacketError::Capacity) ==> out.is_ok() == self.valid(),
    {
        proof { vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes(); }

        match self {
            Self::Declare { formats, .. } => {
                check_formats(formats)?;
                proof { packed_bound(formats@); }
            },
            Self::Write { bytes, format, offset, .. } => {
                if bytes.len() > DATA_CHUNK || *format >= MAX_FORMATS || *offset > DEFAULT_CAPACITY { return Err(PacketError::TooLarge); }
            },
            Self::Read { format, offset, .. } if *format >= MAX_FORMATS || *offset > DEFAULT_CAPACITY => return Err(PacketError::TooLarge),
            _ => (),
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(MAX_PACKET).map_err(|_error| -> (error: PacketError) ensures error == PacketError::Capacity { PacketError::Capacity })?;
        bytes.push(2);
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
        Ok(bytes)
    }

    /// Reject oversized, truncated, trailing or unsupported wire representations.
    pub fn decode(bytes: &[u8]) -> (out: Result<Self, PacketError>)
        ensures out.is_ok() ==> out.unwrap().valid() && out.unwrap().decoded_from(bytes@),
            out != Err(PacketError::Capacity) ==> out.is_ok() == request_syntax(bytes@),
    {
        proof { vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes(); }

        if bytes.len() > MAX_PACKET {
            return Err(PacketError::TooLarge);
        }
        let mut reader = Cursor::new(bytes)?;
        if reader.byte()? != 2 {
            return Err(PacketError::Malformed);
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
                let offset = reader.size(DEFAULT_CAPACITY)?;
                if reader.remaining() > DATA_CHUNK {
                    return Err(PacketError::TooLarge);
                }
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(reader.remaining())
                    .map_err(|_error| -> (error: PacketError) ensures error == PacketError::Capacity { PacketError::Capacity })?;
                bytes.extend_from_slice(reader.take(reader.remaining())?.as_bytes());
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
                offset: reader.size(DEFAULT_CAPACITY)?,
            },
            6 => Self::Connect {
                principal: reader.number()?,
                domain: reader.size(u16::MAX as usize)? as u16,
            },
            _ => return Err(PacketError::Malformed),
        };
        proof {
            match &request {
                Self::Offer => { assert(bytes[1] == 0 && reader.position() == 2); },
                Self::Reserve => { assert(bytes[1] == 1 && reader.position() == 2); },
                Self::Declare { generation, formats } => {
                    assert(bytes[1] == 2 && reader.position() >= 18);
                    assert(generation.number() == word(bytes@, 2));
                    assert(vstd::bytes::spec_u64_to_le_bytes(formats@.len() as u64) + packed_formats(formats@)
                        == bytes@.subrange(10, reader.position() as int));
                },
                Self::Write { generation, format, offset, bytes: data } => {
                    assert(bytes[1] == 3 && reader.position() == bytes.len());
                    assert(generation.number() == word(bytes@, 2));
                    assert(*format == word(bytes@, 10));
                    assert(*offset == word(bytes@, 18));
                    assert(data@ == bytes@.subrange(26, reader.position() as int));
                },
                Self::Complete { generation } => { assert(bytes[1] == 4 && reader.position() == 10); assert(generation.number() == word(bytes@, 2)); },
                Self::Read { generation, format, offset } => {
                    assert(bytes[1] == 5 && reader.position() == 26);
                    assert(generation.number() == word(bytes@, 2));
                    assert(*format == word(bytes@, 10));
                    assert(*offset == word(bytes@, 18));
                },
                Self::Connect { principal, domain } => {
                    assert(bytes[1] == 6 && reader.position() == 18);
                    assert(*principal == word(bytes@, 2));
                    assert(*domain == word(bytes@, 10));
                },
            }
        }
        assert(request_syntax(bytes@) ==> reader.position() == bytes.len());
        reader.finish()?;
        assert(request.decoded_from(bytes@));
        Ok(request)
    }
}

impl Reply {
    /// Complete encodable replies preserve positive identity and generation consistency.
    pub open spec fn valid(&self) -> bool {
        match self {
            Self::Offer(generation, Some(offer)) => wire_formats(offer.formats@)
                && offer.generation == *generation && offer.source.principal_id() > 0 && offer.source.incarnation() > 0,
            Self::Data(bytes) => bytes@.len() <= DATA_CHUNK,
            _ => true,
        }
    }

    /// Canonical response bytes, independent of transport framing or diagnostics.
    pub closed spec fn wire(&self) -> Seq<u8> {
        seq![2u8] + match self {
            Self::Ok => seq![0u8],
            Self::Generation(generation) => seq![1u8] + vstd::bytes::spec_u64_to_le_bytes(generation.number()),
            Self::Offer(generation, offer) => seq![2u8] + vstd::bytes::spec_u64_to_le_bytes(generation.number())
                + match offer {
                    None => seq![0u8],
                    Some(offer) => seq![1u8] + vstd::bytes::spec_u64_to_le_bytes(offer.source.principal_id())
                        + vstd::bytes::spec_u64_to_le_bytes(offer.source.incarnation())
                        + vstd::bytes::spec_u64_to_le_bytes(offer.formats@.len() as u64) + packed_formats(offer.formats@),
                },
            Self::Data(bytes) => seq![3u8] + bytes@,
            Self::Connected { epoch, port, grant } => seq![4u8] + vstd::bytes::spec_u64_to_le_bytes(*epoch)
                + vstd::bytes::spec_u64_to_le_bytes(*port as u64) + vstd::bytes::spec_u64_to_le_bytes(*grant as u64),
            Self::Error(error) => seq![255u8, error_tag(*error)],
        }
    }

    /// The response's exact scalar fields, identity and byte tails in the original packet.
    pub closed spec fn decoded_from(&self, bytes: Seq<u8>) -> bool {
        bytes.len() >= 2 && bytes[0] == 2 && match self {
            Self::Ok => bytes[1] == 0 && bytes.len() == 2,
            Self::Generation(generation) => bytes[1] == 1 && bytes.len() == 10 && generation.number() == word(bytes, 2),
            Self::Offer(generation, offer) => bytes[1] == 2 && bytes.len() >= 11 && generation.number() == word(bytes, 2)
                && match offer {
                    None => bytes[10] == 0 && bytes.len() == 11,
                    Some(offer) => bytes[10] == 1 && bytes.len() >= 35 && offer.generation == *generation
                        && offer.source.principal_id() == word(bytes, 11) && offer.source.incarnation() == word(bytes, 19)
                        && vstd::bytes::spec_u64_to_le_bytes(offer.formats@.len() as u64) + packed_formats(offer.formats@)
                            == bytes.subrange(27, bytes.len() as int),
                },
            Self::Data(data) => bytes[1] == 3 && data@ == bytes.subrange(2, bytes.len() as int),
            Self::Connected { epoch, port, grant } => bytes[1] == 4 && bytes.len() == 26
                && *epoch == word(bytes, 2) && *port == word(bytes, 10) && *grant == word(bytes, 18),
            Self::Error(error) => bytes[1] == 255 && bytes.len() == 3 && error_tag(*error) == bytes[2],
        }
    }

    /// Encode into one bounded reservation, returning exhaustion to the service loop.
    pub fn try_encode(&self) -> (out: Result<Vec<u8>, PacketError>)
        ensures out.is_ok() ==> self.valid() && out.unwrap()@ == self.wire() && out.unwrap()@.len() <= MAX_PACKET,
            out != Err(PacketError::Capacity) ==> out.is_ok() == self.valid(),
    {
        proof { vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes(); }

        match self {
            Self::Data(data) if data.len() > DATA_CHUNK => return Err(PacketError::TooLarge),
            Self::Offer(generation, Some(offer)) => {
                check_formats(&offer.formats)?;
                if offer.generation != *generation || offer.source.principal() == 0 || offer.source.epoch() == 0 { return Err(PacketError::Malformed); }
                proof { packed_bound(offer.formats@); }
            },
            _ => (),
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(MAX_PACKET)
            .map_err(|_error| -> (error: PacketError) ensures error == PacketError::Capacity { PacketError::Capacity })?;
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
                bytes.push(if offer.is_some() { 1 } else { 0 });
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
    pub fn decode(bytes: &[u8]) -> (out: Result<Self, PacketError>)
        ensures out.is_ok() ==> out.unwrap().valid() && out.unwrap().decoded_from(bytes@),
            out != Err(PacketError::Capacity) ==> out.is_ok() == reply_syntax(bytes@),
    {
        proof { vstd::bytes::lemma_auto_spec_u64_to_from_le_bytes(); }

        if bytes.len() > MAX_PACKET {
            return Err(PacketError::TooLarge);
        }
        let mut reader = Cursor::new(bytes)?;
        if reader.byte()? != 2 {
            return Err(PacketError::Malformed);
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
                            .ok_or(PacketError::Malformed)?,
                        formats: reader.formats()?,
                    }),
                    _ => return Err(PacketError::Malformed),
                };
                Self::Offer(generation, offer)
            }
            3 => {
                if reader.remaining() > DATA_CHUNK {
                    return Err(PacketError::TooLarge);
                }
                let data = reader.take(reader.remaining())?.as_bytes();
                let mut bytes = Vec::new();
                bytes.try_reserve_exact(data.len()).map_err(|_error| -> (error: PacketError) ensures error == PacketError::Capacity { PacketError::Capacity })?;
                bytes.extend_from_slice(data);
                Self::Data(bytes)
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
                _ => return Err(PacketError::Malformed),
            }),
            _ => return Err(PacketError::Malformed),
        };
        proof {
            match &reply {
                Self::Ok => { assert(bytes[1] == 0 && reader.position() == 2); },
                Self::Generation(generation) => { assert(bytes[1] == 1 && reader.position() == 10); assert(generation.number() == word(bytes@, 2)); },
                Self::Offer(generation, offer) => {
                    assert(bytes[1] == 2);
                    assert(generation.number() == word(bytes@, 2));
                    match offer {
                        None => { assert(bytes[10] == 0 && reader.position() == 11); },
                        Some(offer) => {
                            assert(bytes[10] == 1 && reader.position() >= 35);
                            assert(offer.source.principal_id() == word(bytes@, 11));
                            assert(offer.source.incarnation() == word(bytes@, 19));
                            assert(vstd::bytes::spec_u64_to_le_bytes(offer.formats@.len() as u64) + packed_formats(offer.formats@)
                                == bytes@.subrange(27, reader.position() as int));
                        },
                    }
                },
                Self::Data(data) => { assert(bytes[1] == 3 && reader.position() == bytes.len()); assert(data@ == bytes@.subrange(2, reader.position() as int)); },
                Self::Connected { epoch, port, grant } => {
                    assert(bytes[1] == 4 && reader.position() == 26);
                    assert(*epoch == word(bytes@, 2));
                    assert(*port == word(bytes@, 10));
                    assert(*grant == word(bytes@, 18));
                },
                Self::Error(error) => { assert(bytes[1] == 255 && reader.position() == 3); assert(error_tag(*error) == bytes[2]); },
            }
        }
        assert(reply_syntax(bytes@) ==> reader.position() == bytes.len());
        reader.finish()?;
        assert(reply.decoded_from(bytes@));
        Ok(reply)
    }
}


/// Execute only data-plane requests; control operations never acquire authority here.
pub fn execute<S: crate::shared::storage::Storage>(
    clipboard: &mut Clipboard<S>,
    now: Time,
    caller: &Caller,
    request: Request,
) -> (reply: Reply)
    requires old(clipboard).valid(),
    ensures final(clipboard).valid(),
        !old(clipboard).authorized(caller) ==> reply is Error && reply->Error_0 == Error::Unauthorized && final(clipboard).unchanged(old(clipboard)),
{

    execute_with_clock(clipboard, now, caller, request, || now)
}

/// Execute with a fresh time observation after synchronous storage completion.
pub fn execute_with_clock<S: crate::shared::storage::Storage>(
    clipboard: &mut Clipboard<S>,
    now: Time,
    caller: &Caller,
    request: Request,
    finished_at: impl FnOnce() -> Time,
) -> (reply: Reply)
    requires old(clipboard).valid(), finished_at.requires(()),
    ensures final(clipboard).valid(),
        !old(clipboard).authorized(caller) ==> reply is Error && reply->Error_0 == Error::Unauthorized && final(clipboard).unchanged(old(clipboard)),
{

    proof { clipboard.unchanged_self(); }
    if clipboard.access(caller).is_err() { return Reply::Error(Error::Unauthorized); }
    let result = match request {
        Request::Offer => clipboard
            .offer(caller)
            .map(|(generation, offer)| -> (reply: Reply) ensures reply == Reply::Offer(generation, offer) { Reply::Offer(generation, offer) }),
        Request::Reserve => clipboard.reserve(now, caller).map(|generation| -> (reply: Reply) ensures reply == Reply::Generation(generation) { Reply::Generation(generation) }),
        Request::Declare {
            generation,
            formats,
        } => clipboard
            .declare(now, caller, generation, formats)
            .map(|_done| -> (reply: Reply) ensures reply == Reply::Ok { Reply::Ok }),
        Request::Write {
            generation,
            format,
            offset,
            bytes,
        } => clipboard
            .write(now, caller, generation, format, offset, &bytes)
            .map(|_done| -> (reply: Reply) ensures reply == Reply::Ok { Reply::Ok }),
        Request::Complete { generation } => clipboard
            .complete_with_clock(now, caller, generation, finished_at)
            .map(|_done| -> (reply: Reply) ensures reply == Reply::Ok { Reply::Ok }),
        Request::Read {
            generation,
            format,
            offset,
        } => clipboard
            .read(caller, generation, format, offset, DATA_CHUNK)
            .map(|bytes| -> (reply: Reply) ensures reply == Reply::Data(bytes) { Reply::Data(bytes) }),
        Request::Connect { .. } => Err(Error::Unauthorized),
    };
    match result { Ok(reply) => reply, Err(error) => Reply::Error(error) }
}


}

#[cfg(test)]
mod tests;
