//! Bounded parsing over one immutable, privately owned transport snapshot.
//! These executable readers establish the exact bytes consumed, not just bounds.
//! The Xen adapter must copy shared memory before borrowing this snapshot; Rust
//! references alone do not establish immutability of externally writable mappings.

use vstd::prelude::*;

verus! {

/// Maximum serialized clipboard packet before any decoder allocation.
pub const MAX_PACKET: usize = 16 * 1024;

/// Maximum data carried by one representation operation.
pub const DATA_CHUNK: usize = 4096;

/// Stable syntax/resource errors, containing no private bytes or format names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketError {
    /// Version, field, ordering or exact-consumption rule was violated.
    Malformed,
    /// A declared or observed size exceeded its explicit protocol bound.
    TooLarge,
    /// A fallible allocation could not reserve the bounded packet storage.
    Capacity,
}

/// An opaque checked byte range from this exact packet snapshot.
pub struct Span<'a> {
    /// Stable immutable bytes borrowed from the input lifetime.
    bytes: &'a [u8],
}

impl<'a> Span<'a> {
    /// Exact bytes represented by this validated borrow.
    pub closed spec fn contents(&self) -> Seq<u8> { self.bytes@ }

    /// Borrow the checked bytes without independently reconstructing their indices.
    pub fn as_bytes(&self) -> (bytes: &'a [u8])
        ensures bytes@ == self.contents(),
    { self.bytes }
}

/// Forward-only parser; failed reads preserve the cursor and never expose a partial field.
pub struct Cursor<'a> {
    /// Immutable packet snapshot, bounded on entry before downstream allocation.
    bytes: &'a [u8],
    /// Next unread byte, always inside or exactly at the end of the snapshot.
    offset: usize,
}

impl<'a> Cursor<'a> {
    /// Input bytes, independent of parsing progress.
    pub closed spec fn contents(&self) -> Seq<u8> { self.bytes@ }

    /// Checked position of the next unread byte.
    pub closed spec fn position(&self) -> usize { self.offset }

    /// Cursor progress and input size remain bounded at every transition.
    pub closed spec fn valid(&self) -> bool {
        self.offset <= self.bytes@.len() && self.bytes@.len() <= MAX_PACKET
    }

    /// Admit one bounded snapshot; an oversized packet cannot create a reader.
    pub fn new(bytes: &'a [u8]) -> (out: Result<Self, PacketError>)
        ensures out.is_ok() == (bytes.len() <= MAX_PACKET),
            out.is_ok() ==> out.unwrap().valid() && out.unwrap().position() == 0
                && out.unwrap().contents() == bytes@,
    {
        if bytes.len() > MAX_PACKET { Err(PacketError::TooLarge) }
        else { Ok(Self { bytes, offset: 0 }) }
    }

    /// Consume exactly the requested range, or reject truncation without moving.
    pub fn take(&mut self, count: usize) -> (out: Result<Span<'a>, PacketError>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).contents() == old(self).contents(),
            out.is_ok() == (count <= old(self).contents().len() - old(self).position()),
            out.is_ok() ==> final(self).position() == old(self).position() + count
                && out.unwrap().contents() == old(self).contents().subrange(
                    old(self).position() as int, old(self).position() as int + count),
            out.is_err() ==> final(self).position() == old(self).position(),
    {
        if count > self.bytes.len() - self.offset { return Err(PacketError::Malformed); }
        let start = self.offset;
        self.offset += count;
        let bytes = &self.bytes[start..self.offset];
        Ok(Span { bytes })
    }

    /// Consume one exact byte; no unchecked indexing is reachable on truncated input.
    pub fn byte(&mut self) -> (out: Result<u8, PacketError>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).contents() == old(self).contents(),
            out.is_ok() == (old(self).position() < old(self).contents().len()),
            out.is_ok() ==> final(self).position() == old(self).position() + 1
                && out.unwrap() == old(self).contents()[old(self).position() as int],
            out.is_err() ==> final(self).position() == old(self).position(),
    {
        match self.take(1) {
            Ok(span) => Ok(span.bytes[0]),
            Err(error) => Err(error),
        }
    }

    /// Decode the next eight bytes as exactly one little-endian protocol integer.
    pub fn number(&mut self) -> (out: Result<u64, PacketError>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).contents() == old(self).contents(),
            out.is_ok() == (old(self).position() + 8 <= old(self).contents().len()),
            out.is_ok() ==> final(self).position() == old(self).position() + 8
                && out.unwrap() == vstd::bytes::spec_u64_from_le_bytes(old(self).contents().subrange(
                    old(self).position() as int, old(self).position() as int + 8)),
            out.is_err() ==> final(self).position() == old(self).position(),
    {
        match self.take(8) {
            Ok(span) => Ok(vstd::bytes::u64_from_le_bytes(span.as_bytes())),
            Err(error) => Err(error),
        }
    }

    /// Consume one bounded wire size, distinguishing a truncated word from an excessive value.
    pub fn size(&mut self, maximum: usize) -> (out: Result<usize, PacketError>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).contents() == old(self).contents(),
            out.is_ok() == (old(self).position() + 8 <= old(self).contents().len()
                && vstd::bytes::spec_u64_from_le_bytes(old(self).contents().subrange(
                    old(self).position() as int, old(self).position() as int + 8)) <= maximum),
            out.is_ok() ==> out.unwrap() <= maximum && out.unwrap()
                == vstd::bytes::spec_u64_from_le_bytes(old(self).contents().subrange(
                    old(self).position() as int, old(self).position() as int + 8)),
            final(self).position() == if old(self).position() + 8 <= old(self).contents().len()
                { old(self).position() + 8 } else { old(self).position() as int },
    {
        match self.number() {
            Ok(value) => {
                if value > maximum as u64 { Err(PacketError::TooLarge) }
                else { Ok(value as usize) }
            },
            Err(error) => Err(error),
        }
    }

    /// Consume one exact four-byte frame-header integer.
    pub fn word32(&mut self) -> (out: Result<u32, PacketError>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).contents() == old(self).contents(),
            out.is_ok() == (old(self).position() + 4 <= old(self).contents().len()),
            out.is_ok() ==> final(self).position() == old(self).position() + 4
                && out.unwrap() == vstd::bytes::spec_u32_from_le_bytes(old(self).contents().subrange(
                    old(self).position() as int, old(self).position() as int + 4)),
            out.is_err() ==> final(self).position() == old(self).position(),
    {
        match self.take(4) {
            Ok(span) => Ok(vstd::bytes::u32_from_le_bytes(span.as_bytes())),
            Err(error) => Err(error),
        }
    }

    /// Report unconsumed bytes for explicit bounded trailing-data fields.
    pub fn remaining(&self) -> (count: usize)
        requires self.valid(),
        ensures count == self.contents().len() - self.position(),
    { self.bytes.len() - self.offset }

    /// Reject all trailing bytes; successful parsing must consume the exact packet.
    pub fn finish(self) -> (out: Result<(), PacketError>)
        ensures out.is_ok() == (self.position() == self.contents().len()),
    {
        if self.offset == self.bytes.len() { Ok(()) } else { Err(PacketError::Malformed) }
    }
}

}
