//! Ordered assembly over owned Xen-frame snapshots, independent of the transport.
//! Malformed or allocation-failed packets poison the assembler: callers retire
//! the connection rather than resuming an ambiguous partial transfer. Completed
//! request identifiers cannot be reused within this connection lifetime.

use crate::packet::{Cursor, MAX_PACKET, PacketError};
use alloc::vec::Vec;
use vstd::prelude::*;

verus! {

/// Existing transport payload size, including the two framing words.
pub const FRAME_LIMIT: usize = 224;

/// Nonempty payload and bounded, consistent framing words.
pub open spec fn well_formed(bytes: Seq<u8>) -> bool {
    8 < bytes.len() <= FRAME_LIMIT
        && 0 < total(bytes) <= MAX_PACKET
        && offset(bytes) + bytes.len() - 8 <= total(bytes)
}

/// Declared packet length in the first little-endian header word.
pub open spec fn total(bytes: Seq<u8>) -> int {
    vstd::bytes::spec_u32_from_le_bytes(bytes.subrange(0, 4)) as int
}

/// Declared byte offset in the second little-endian header word.
pub open spec fn offset(bytes: Seq<u8>) -> int {
    vstd::bytes::spec_u32_from_le_bytes(bytes.subrange(4, 8)) as int
}

/// Checked header and body borrow; raw bytes cannot fabricate one directly.
struct Frame<'a> {
    /// Bounded aggregate length, established from this snapshot's first word.
    total: usize,
    /// Checked body offset from this snapshot's second word.
    offset: usize,
    /// Exact nonempty body bytes from the same snapshot.
    body: &'a [u8],
}

impl<'a> Frame<'a> {
    /// Decode the exact framing words and body before any allocation or state mutation.
    fn parse(bytes: &'a [u8]) -> (out: Result<Self, PacketError>)
        ensures out.is_ok() == well_formed(bytes@), out != Err(PacketError::Capacity),
            out.is_ok() ==> out.unwrap().total == total(bytes@)
                && out.unwrap().offset == offset(bytes@)
                && out.unwrap().body@ == bytes@.subrange(8, bytes@.len() as int),
    {
        if bytes.len() <= 8 || bytes.len() > FRAME_LIMIT { return Err(PacketError::TooLarge); }
        let mut reader = Cursor::new(bytes)?;
        let total = reader.word32()? as usize;
        let offset = reader.word32()? as usize;
        if total == 0 || total > MAX_PACKET { return Err(PacketError::TooLarge); }
        let count = reader.remaining();
        if offset > total || count > total - offset { return Err(PacketError::Malformed); }
        let body = reader.take(count)?.as_bytes();
        Ok(Self { total, offset, body })
    }
}

/// One exclusive partial packet; its allocation is retained only until completion or failure.
struct Partial {
    /// Request identity shared by every frame of this packet.
    id: u64,
    /// Declared total, unchanged across continuation frames.
    total: usize,
    /// Exact contiguous prefix copied from privately owned frame snapshots.
    bytes: Vec<u8>,
}

/// Mutually exclusive framing states; poisoned connections cannot resume a packet.
enum Phase {
    /// No packet is currently being assembled.
    Idle,
    /// One nonempty, incomplete packet owns a bounded allocation.
    Receiving(
        /// Owned prefix and immutable identity/length of the active packet.
        Partial,
    ),
    /// A terminal framing or allocation failure requires connection retirement.
    Poisoned,
}

/// Bounded, replay-rejecting assembly for one authenticated connection lifetime.
pub struct Assembly {
    /// Exclusive packet ownership and terminal-error state.
    phase: Phase,
    /// Greatest completely assembled request; never wraps or decreases.
    last: u64,
}

impl Assembly {
    /// A receiving prefix is nonempty and strictly shorter than its bounded total.
    pub closed spec fn valid(&self) -> bool {
        match &self.phase {
            Phase::Receiving(partial) => partial.id > self.last
                && 0 < partial.bytes@.len() < partial.total <= MAX_PACKET,
            _ => true,
        }
    }

    /// Previously consumed request identity; zero means no completed packet yet.
    pub closed spec fn completed(&self) -> u64 { self.last }

    /// Only incomplete content is retained between calls.
    pub closed spec fn prefix(&self) -> Seq<u8> {
        match &self.phase { Phase::Receiving(partial) => partial.bytes@, _ => Seq::empty() }
    }

    /// A terminal error cannot accept further frames on the same assembler.
    pub closed spec fn poisoned(&self) -> bool { self.phase is Poisoned }

    /// Framing, identity and ordering conditions under which this snapshot may advance.
    pub closed spec fn eligible(&self, id: u64, bytes: Seq<u8>) -> bool {
        well_formed(bytes) && id > self.last && match &self.phase {
            Phase::Idle => offset(bytes) == 0,
            Phase::Receiving(partial) => id == partial.id && total(bytes) == partial.total
                && offset(bytes) == partial.bytes@.len(),
            Phase::Poisoned => false,
        }
    }

    /// Start an empty connection lifetime; no prior request identity is accepted implicitly.
    pub fn new() -> (assembly: Self)
        ensures assembly.valid(), assembly.completed() == 0, !assembly.poisoned(),
            assembly.prefix().len() == 0,
    { Self { phase: Phase::Idle, last: 0 } }

    /// Observe the last exact completion for response correlation without rebuilding a decision.
    pub fn completed_id(&self) -> (id: u64)
        ensures id == self.completed(),
    { self.last }

    /// Retire a connection after an invalid transport tag without retaining private bytes.
    pub fn reject(&mut self)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).poisoned(), final(self).prefix().len() == 0,
            final(self).completed() == old(self).completed(),
    { self.phase = Phase::Poisoned; }

    /// Copy one validated contiguous frame, returning the exact complete packet once.
    /// Capacity failure represents the underlying fallible allocator outcome; all
    /// other errors imply invalid framing/order. Errors discard the prefix and
    /// retain the greatest completed identity while permanently poisoning this instance.
    pub fn push(&mut self, id: u64, bytes: &[u8]) -> (out: Result<Option<Vec<u8>>, PacketError>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).completed() >= old(self).completed(),
            out.is_err() ==> final(self).poisoned() && final(self).prefix().len() == 0
                && final(self).completed() == old(self).completed(),
            out.is_ok() ==> old(self).eligible(id, bytes@) && !final(self).poisoned(),
            !old(self).eligible(id, bytes@) ==> out.is_err(),
            out == Err(PacketError::Capacity) ==> old(self).eligible(id, bytes@),
            out.is_err() && out != Err(PacketError::Capacity) ==> !old(self).eligible(id, bytes@),
            out.is_ok() && out.unwrap().is_some() ==>
                final(self).completed() == id && final(self).prefix().len() == 0
                && out.unwrap().unwrap()@ == old(self).prefix() + bytes@.subrange(8, bytes@.len() as int)
                && out.unwrap().unwrap()@.len() == total(bytes@),
            out == Ok(None) ==> final(self).completed() == old(self).completed()
                && final(self).prefix() == old(self).prefix() + bytes@.subrange(8, bytes@.len() as int)
                && final(self).prefix().len() < total(bytes@),
    {
        let frame = match Frame::parse(bytes) {
            Ok(frame) => frame,
            Err(error) => { self.phase = Phase::Poisoned; return Err(error); },
        };
        if id <= self.last { self.phase = Phase::Poisoned; return Err(PacketError::Malformed); }
        let phase = core::mem::replace(&mut self.phase, Phase::Poisoned);
        let mut partial = match phase {
            Phase::Idle => {
                if frame.offset != 0 { return Err(PacketError::Malformed); }
                let mut buffer = Vec::new();
                // Reserve the bounded total once; continuation frames cannot grow it.
                if buffer.try_reserve_exact(frame.total).is_err() { return Err(PacketError::Capacity); }
                Partial { id, total: frame.total, bytes: buffer }
            },
            Phase::Receiving(partial) => {
                if partial.id != id || partial.total != frame.total || partial.bytes.len() != frame.offset {
                    return Err(PacketError::Malformed);
                }
                partial
            },
            Phase::Poisoned => return Err(PacketError::Malformed),
        };
        partial.bytes.extend_from_slice(frame.body);
        if partial.bytes.len() == partial.total {
            self.last = id;
            self.phase = Phase::Idle;
            Ok(Some(partial.bytes))
        } else {
            self.phase = Phase::Receiving(partial);
            Ok(None)
        }
    }
}

}

impl Default for Assembly {
    fn default() -> Self {
        Self::new()
    }
}
