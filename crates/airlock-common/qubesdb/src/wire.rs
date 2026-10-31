//! Private native QubesDB records, independent of libvchan fragmentation.
//! Wire reference: QubesOS/qubes-core-qubesdb v4.3.2 include/qubesdb.h and
//! daemon/db-cmds.c. No upstream implementation body is copied here.
//! Native x86-64 headers have 65 meaningful initial bytes, three padding bytes,
//! and a little-endian u32 at offset 68. Padding and bytes after the first path
//! NUL are ignored because upstream reuses headers, including for end markers.

use alloc::vec::Vec;
use vstd::prelude::*;

verus! {

broadcast use vstd::seq::group_seq_lemmas;

/// Invalid native record framing; the original connection cannot be replayed.
/// Consumers must discard decisions requiring a live replication stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// Header/body framing does not satisfy the pinned native record grammar.
    MalformedRecord,
}

/// Native x86-64 qdb_hdr size, including the ABI's alignment padding.
pub const HEADER: usize = 72;

/// Upstream rejects data_len >= QDB_MAX_DATA, despite the header's inclusive prose.
pub const MAX_VALUE: usize = 3071;

/// Largest complete native record retained by the stream decoder.
pub const MAX_RECORD: usize = HEADER + MAX_VALUE;

/// Native opcode for one replicated write, including a zero-length completion marker.
pub const WRITE: u8 = 1;

/// Native opcode for the one full-replica synchronization request.
pub const SYNC: u8 = 2;

/// Native opcode for an exact deletion or a trailing-slash subtree deletion.
pub const REMOVE: u8 = 4;

/// Native positive acknowledgement, never a durability guarantee.
pub const OK: u8 = 7;

/// Native peer error; the control owner treats it as a terminal stream failure.
pub const ERROR: u8 = 9;

/// Native initial-synchronization entry or empty-path completion barrier.
pub const ENTRY: u8 = 11;

/// Native length interpreted by vstd's little-endian byte model.
pub open spec fn native_length(bytes: Seq<u8>) -> int {
    vstd::bytes::spec_u32_from_le_bytes(bytes.subrange(68, 72)) as int
}

/// Pinned upstream path alphabet, including its prohibition on a leading dash.
pub open spec fn path_byte(byte: u8, index: int) -> bool {
    (b'a' <= byte <= b'z') || (b'A' <= byte <= b'Z')
        || (b'0' <= byte <= b'9') || (byte == b'-' && index > 0)
        || byte == b'_' || byte == b'/' || byte == b'.'
        || byte == b':' || byte == b'@'
}

/// Exact path acceptance: a first NUL exists inside the 64-byte native field.
pub open spec fn path_at(bytes: Seq<u8>, length: int) -> bool {
    0 <= length < 64 && bytes[1+length] == 0
        && forall|i: int| 0 <= i < length ==> #[trigger] path_byte(bytes[1+i], i)
}

/// The first NUL boundary is unique because native path bytes exclude NUL.
pub proof fn path_unique(bytes: Seq<u8>, left: int, right: int)
    requires path_at(bytes, left), path_at(bytes, right),
    ensures left == right,
{
    if left < right { assert(path_byte(bytes[1+left], left)); }
    if right < left { assert(path_byte(bytes[1+right], right)); }
}

/// Direction-specific opcode and payload shape. Local-only watches/reads and
/// an unsolicited reverse sync request are not valid guest-replica commands.
pub open spec fn shape(kind: u8, path: Seq<u8>, count: int) -> bool {
    0 <= count <= MAX_VALUE && (
        (kind == WRITE && 0 < path.len() && path.last() != b'/')
        || (kind == REMOVE && 0 < path.len() && count == 0)
        || ((kind == OK || kind == ERROR) && count == 0)
        || (kind == ENTRY && (path.len() > 0 || count == 0))
    )
}

/// Private validated metadata. It describes peer bytes and grants no authority
/// to choose a Xen peer, interface identity or packet source.
pub struct Header {
    /// Native operation observed in the immutable record header.
    kind: u8,
    /// Exact bytes preceding the first NUL; shared padding is never retained.
    path: Vec<u8>,
    /// Exact bounded native body length; complete-body checks remain separate.
    count: u16,
}

impl Header {
    /// Observed native operation, independent of memory representation.
    pub closed spec fn kind(&self) -> u8 { self.kind }

    /// Exact path used to identify this record inside the private replica.
    pub closed spec fn path(&self) -> Seq<u8> { self.path@ }

    /// Exact advertised body length, bounded before allocation or copying.
    pub closed spec fn count(&self) -> u16 { self.count }

    /// Construction establishes every grammar/shape invariant once.
    pub closed spec fn valid(&self) -> bool {
        self.path@.len() < 64
            && (forall|i: int| 0 <= i < self.path@.len() ==> path_byte(self.path@[i], i))
            && shape(self.kind, self.path@, self.count as int)
    }

    /// Validate one complete private header snapshot. Unlike upstream's
    /// forced truncation, a nonterminated path is rejected rather than retargeted.
    pub fn decode(bytes: &[u8; HEADER]) -> (header: Option<Self>)
        ensures match header {
            Some(value) => value.valid() && value.kind() == bytes@[0]
                && value.count() == native_length(bytes@)
                && path_at(bytes@, value.path().len() as int)
                && value.path() == bytes@.subrange(1, 1+value.path().len() as int),
            None => !(exists|length: int| path_at(bytes@, length)
                && shape(bytes@[0], bytes@.subrange(1, 1+length), native_length(bytes@))),
        },
    {
        let count = vstd::bytes::u32_from_le_bytes(&bytes[68..72]);
        if count > MAX_VALUE as u32 { return None; }
        let mut path = Vec::new();
        let mut i = 0;
        while i < 64
            invariant i <= 64, path@ == bytes@.subrange(1, 1+i as int),
                count == native_length(bytes@), count <= MAX_VALUE,
                forall|j: int| 0 <= j < i ==> #[trigger] path_byte(bytes@[1+j], j),
                forall|length: int| #[trigger] path_at(bytes@, length) ==> i <= length,
            decreases 64-i,
        {
            let byte = bytes[1+i];
            if byte == 0 {
                let kind = bytes[0];
                let accepted = match kind {
                    WRITE => i > 0 && path[i-1] != b'/',
                    REMOVE => i > 0 && count == 0,
                    OK | ERROR => count == 0,
                    ENTRY => i > 0 || count == 0,
                    _ => false,
                };
                if !accepted {
                    proof {
                        assert forall|length: int| #[trigger] path_at(bytes@, length)
                            implies !shape(bytes@[0], bytes@.subrange(1, 1+length), native_length(bytes@)) by {
                            if length > i { assert(path_byte(bytes@[1+i as int], i as int)); }
                        }
                    }
                    return None;
                }
                let header = Self { kind, path, count: count as u16 };
                proof {
                    assert forall|j: int| 0 <= j < header.path@.len()
                        implies path_byte(#[trigger] header.path@[j], j) by {
                        assert(header.path@[j] == bytes@[1+j]);
                        assert(path_byte(bytes@[1+j], j));
                    }
                    assert(shape(kind, header.path@, count as int));
                    assert(header.valid());
                    assert(header.count() == native_length(bytes@));
                    assert(path_at(bytes@, header.path().len() as int));
                }
                return Some(header);
            }
            let accepted = byte.is_ascii_alphanumeric()
                || (byte == b'-' && i > 0) || byte == b'_' || byte == b'/'
                || byte == b'.' || byte == b':' || byte == b'@';
            if !accepted {
                proof {
                    assert forall|length: int| !#[trigger] path_at(bytes@, length) by {
                        if path_at(bytes@, length) && length > i {
                            assert(path_byte(bytes@[1+i as int], i as int));
                        }
                    }
                }
                return None;
            }
            proof {
                assert forall|length: int| #[trigger] path_at(bytes@, length) implies i+1 <= length by {
                    if length == i { assert(bytes@[1+length] == 0); }
                }
            }
            path.push(byte);
            i += 1;
        }
        None
    }

    /// Native opcode without interpreting a claim as an authorization decision.
    pub fn operation(&self) -> (kind: u8)
        requires self.valid(),
        ensures kind == self.kind(), shape(kind, self.path(), self.count() as int),
    { self.kind }

    /// Borrow only the exact validated private path bytes.
    pub fn key(&self) -> (path: &[u8])
        requires self.valid(),
        ensures path@ == self.path(), path@.len() < 64, shape(self.kind(), path@, self.count() as int),
    { self.path.as_slice() }

    /// Bounded body size used by the fragment assembler.
    pub fn value_length(&self) -> (length: usize)
        requires self.valid(),
        ensures length == self.count() && length <= MAX_VALUE,
    { self.count as usize }

    /// Encode the positive acknowledgement to this exact replicated operation.
    /// All ABI padding is initialized; acknowledgement is not persistence.
    pub fn acknowledge(&self) -> (bytes: [u8; HEADER])
        requires self.valid(),
        ensures bytes@[0] == OK && native_length(bytes@) == 0
            && bytes@.subrange(1, 1+self.path().len() as int) == self.path()
            && bytes@[1+self.path().len() as int] == 0,
    {
        let mut bytes = [0; HEADER];
        bytes[0] = OK;
        bytes[1..1+self.path.len()].copy_from_slice(self.path.as_slice());
        let length = vstd::bytes::u32_to_le_bytes(0);
        bytes[68..72].copy_from_slice(length.as_slice());
        proof { vstd::bytes::lemma_auto_spec_u32_to_from_le_bytes(); }
        bytes
    }
}

/// Native initial MULTIREAD header, with an empty root path and zero length.
pub open spec fn synchronization() -> Seq<u8> {
    Seq::new(HEADER as nat, |i: int| if i == 0 { SYNC } else { 0u8 })
}

/// Emit the one initial whole-database request on a fresh native connection.
pub fn synchronize() -> (bytes: [u8; HEADER])
    ensures bytes@ == synchronization(),
{
    let mut bytes = [0; HEADER];
    bytes[0] = SYNC;
    bytes
}

/// Exact native guest WRITE domain, independent of any consumer's key meanings.
pub open spec fn writable(path: Seq<u8>, value: Seq<u8>) -> bool {
    0 < path.len() < 64 && path.last() != b'/' && value.len() <= MAX_VALUE
        && (forall|i: int| 0 <= i < path.len() ==> path_byte(path[i], i))
        && (forall|i: int| 0 <= i < value.len() ==> value[i] != 0)
}

/// Validate a complete guest WRITE, including empty values and both native bounds.
pub(crate) fn writeable(path: &[u8], value: &[u8]) -> (accepted: bool)
    ensures accepted == writable(path@, value@),
{
    if path.is_empty() || path.len() >= 64 || path[path.len()-1] == b'/' || value.len() > MAX_VALUE { return false; }
    let mut i = 0;
    while i < path.len()
        invariant i <= path.len() < 64,
            forall|j: int| 0 <= j < i ==> path_byte(path@[j], j),
        decreases path.len()-i,
    {
        let byte = path[i];
        if !(byte.is_ascii_alphanumeric() || (byte == b'-' && i > 0)
            || byte == b'_' || byte == b'/' || byte == b'.' || byte == b':' || byte == b'@') { return false; }
        i += 1;
    }
    let mut i = 0;
    while i < value.len()
        invariant i <= value.len() <= MAX_VALUE,
            forall|j: int| 0 <= j < i ==> value@[j] != 0,
        decreases value.len()-i,
    {
        if value[i] == 0 { return false; }
        i += 1;
    }
    true
}

/// Encode one client WRITE after the request boundary validates the native path
/// and value. Key meanings and authorization remain responsibilities of consumers.
pub(crate) fn guest_write(path: &[u8], value: &[u8]) -> (bytes: Vec<u8>)
    requires 0 < path@.len() < 64, value@.len() <= MAX_VALUE,
        forall|i: int| 0 <= i < path@.len() ==> path_byte(path@[i], i),
    ensures bytes@.len() == HEADER+value@.len(), bytes@[0] == WRITE,
        bytes@.subrange(1, 1+path@.len() as int) == path@, bytes@[1+path@.len() as int] == 0,
        native_length(bytes@) == value@.len(), bytes@.subrange(HEADER as int, bytes@.len() as int) == value@,
{
    let mut header = [0; HEADER];
    header[0] = WRITE;
    header[1..1+path.len()].copy_from_slice(path);
    let length = vstd::bytes::u32_to_le_bytes(value.len() as u32);
    header[68..72].copy_from_slice(length.as_slice());
    proof {
        assert(header@.subrange(68, 72) =~= length@);
        vstd::bytes::lemma_auto_spec_u32_to_from_le_bytes();
        assert(native_length(header@) == value@.len());
    }

    let mut bytes = vstd::slice::slice_to_vec(&header);
    bytes.extend_from_slice(value);
    proof { assert(bytes@.subrange(68, 72) =~= header@.subrange(68, 72)); }
    bytes
}

/// A complete private record; bytes are not exposed until advertised length
/// and the upstream prohibition on embedded value NULs have been checked.
pub struct Message {
    /// Header from this same complete frame, never from a later shared reread.
    header: Header,
    /// Exact validated value, independently owned by the replica consumer.
    value: Vec<u8>,
}

impl Message {
    /// The body matches its header's advertised length and native data grammar.
    pub closed spec fn valid(&self) -> bool {
        self.header.valid() && self.value@.len() == self.header.count()
            && forall|i: int| 0 <= i < self.value@.len() ==> self.value@[i] != 0
    }

    /// Exact native header observation retained for this message.
    pub closed spec fn header(&self) -> Header { self.header }

    /// Exact owned body bytes, independent of transport fragmentation.
    pub closed spec fn value(&self) -> Seq<u8> { self.value@ }

    /// Bind a validated header to its exact complete private body. Reject an
    /// incomplete or oversized body and every embedded NUL before publication.
    pub fn new(header: Header, bytes: &[u8]) -> (message: Option<Self>)
        requires header.valid(),
        ensures match message {
            Some(value) => value.valid() && value.header() == header && value.value() == bytes@,
            None => bytes@.len() != header.count()
                || exists|i: int| 0 <= i < bytes@.len() && bytes@[i] == 0,
        },
    {
        if bytes.len() != header.count as usize { return None; }
        let mut value = Vec::new();
        let mut i = 0;
        while i < bytes.len()
            invariant i <= bytes.len() <= MAX_VALUE,
                value@ == bytes@.subrange(0, i as int),
                forall|j: int| 0 <= j < i ==> bytes@[j] != 0,
            decreases bytes.len()-i,
        {
            if bytes[i] == 0 { return None; }
            value.push(bytes[i]);
            i += 1;
        }
        Some(Self { header, value })
    }

    /// Inspect the metadata without permitting mutation of its association.
    pub fn metadata(&self) -> (header: &Header)
        ensures *header == self.header(),
    { &self.header }

    /// Associate only meaningful native fields with the exact consumed private
    /// record. Padding and trailing path storage intentionally have no semantics.
    pub open spec fn corresponds(&self, bytes: Seq<u8>) -> bool {
        self.valid() && bytes.len() == HEADER + self.header().count()
            && self.header().kind() == bytes[0]
            && self.header().count() == native_length(bytes)
            && path_at(bytes, self.header().path().len() as int)
            && self.header().path() == bytes.subrange(1, 1+self.header().path().len() as int)
            && self.value() == bytes.subrange(HEADER as int, bytes.len() as int)
    }

    /// Consume only these owned fields; callers cannot replace the header
    /// independently and retain a falsely validated Message.
    pub fn into_parts(self) -> (parts: (Header, Vec<u8>))
        requires self.valid(),
        ensures parts.0 == self.header() && parts.0.valid() && parts.1@ == self.value()
            && parts.1@.len() == parts.0.count() && parts.1@.len() <= MAX_VALUE,
    { (self.header, self.value) }
}

/// Native header grammar, independent of packet fragmentation or local state.
pub open spec fn accepted_header(bytes: Seq<u8>) -> bool {
    bytes.len() >= HEADER && exists|length: int| path_at(bytes, length)
        && shape(bytes[0], bytes.subrange(1, 1+length), native_length(bytes))
}

/// Complete useful native record, including exact body length and value grammar.
pub open spec fn complete_record(bytes: Seq<u8>) -> bool {
    accepted_header(bytes) && bytes.len() == HEADER + native_length(bytes)
        && forall|i: int| HEADER <= i < bytes.len() ==> bytes[i] != 0
}

/// A proper prefix which has not yet completed a valid native record. Header
/// bytes are uninterpreted until all 72 arrive; complete headers must be valid.
pub open spec fn incomplete_record(bytes: Seq<u8>) -> bool {
    bytes.len() < HEADER || (accepted_header(bytes) && bytes.len() < HEADER + native_length(bytes))
}

/// Record interpretation depends only on the first header, regardless of body.
proof fn header_prefix(bytes: Seq<u8>)
    requires bytes.len() >= HEADER,
    ensures accepted_header(bytes) == accepted_header(bytes.subrange(0, HEADER as int)),
        native_length(bytes) == native_length(bytes.subrange(0, HEADER as int)),
        forall|length: int| #[trigger] path_at(bytes, length)
            == path_at(bytes.subrange(0, HEADER as int), length),
{
    let prefix = bytes.subrange(0, HEADER as int);
    assert(prefix.subrange(68, 72) =~= bytes.subrange(68, 72));
    assert forall|length: int| 0 <= length < 64 implies
        #[trigger] prefix.subrange(1, 1+length) == bytes.subrange(1, 1+length) by {
        assert(prefix.subrange(1, 1+length) =~= bytes.subrange(1, 1+length));
    }
    assert forall|length: int| #[trigger] path_at(bytes, length) == path_at(prefix, length) by {
        assert forall|i: int| 0 <= i < length && 0 <= length < 64 implies
            #[trigger] path_byte(bytes[1+i], i) == path_byte(prefix[1+i], i) by {}
    }
    if accepted_header(bytes) {
        let length = choose|length: int| path_at(bytes, length)
            && shape(bytes[0], bytes.subrange(1, 1+length), native_length(bytes));
        assert(path_at(prefix, length));
        assert(shape(prefix[0], prefix.subrange(1, 1+length), native_length(prefix)));
    }
    if accepted_header(prefix) {
        let length = choose|length: int| path_at(prefix, length)
            && shape(prefix[0], prefix.subrange(1, 1+length), native_length(prefix));
        assert(path_at(bytes, length));
        assert(shape(bytes[0], bytes.subrange(1, 1+length), native_length(bytes)));
    }
}

/// Snapshot just the native header from owned stream bytes.
fn snapshot(bytes: &[u8]) -> (header: Option<[u8; HEADER]>)
    ensures match header {
        Some(value) => bytes@.len() >= HEADER && value@ == bytes@.subrange(0, HEADER as int),
        None => bytes@.len() < HEADER,
    },
{
    if bytes.len() < HEADER { return None; }
    let mut header = [0; HEADER];
    header.copy_from_slice(&bytes[..HEADER]);
    Some(header)
}

/// Incremental decoder for one bounded record. A malformed/ambiguous stream is
/// terminal; there is no byte scanning or replay to guess another frame boundary.
/// Infallible standard-library allocation failure is fatal to the guest lifetime;
/// allocations are bounded here, but this does not prove allocator availability.
pub struct Decoder {
    /// Private prefix of one record, never shared or published while incomplete.
    bytes: Vec<u8>,
    /// Exact completion length after validating the first native header.
    target: usize,
    /// Terminal framing failure; no later byte can produce a message.
    failed: bool,
}

impl Decoder {
    /// The decoder retains at most one bounded record. A live partial body is
    /// associated with its already validated original native length field.
    pub closed spec fn valid(&self) -> bool {
        self.bytes@.len() <= MAX_RECORD && (self.failed || (
            HEADER <= self.target <= MAX_RECORD && self.bytes@.len() < self.target
                && (self.bytes@.len() < HEADER ==> self.target == HEADER)
                && (self.bytes@.len() >= HEADER ==> accepted_header(self.bytes@)
                    && self.target == HEADER + native_length(self.bytes@))
        ))
    }

    /// Private consumed prefix of the current record.
    pub closed spec fn prefix(&self) -> Seq<u8> { self.bytes@ }

    /// Terminal failure state, independent of a caller's timeout diagnosis.
    pub closed spec fn failed(&self) -> bool { self.failed }

    /// Start with no data and a finite native header requirement.
    pub fn fresh() -> (decoder: Self)
        ensures decoder.valid() && !decoder.failed() && decoder.prefix().len() == 0,
    { Self { bytes: Vec::new(), target: HEADER, failed: false } }

    /// Number of retained private bytes in the current incomplete record.
    pub fn buffered(&self) -> (count: usize)
        requires self.valid(), ensures count == self.prefix().len(), count <= MAX_RECORD,
    { self.bytes.len() }

    /// Consume exactly one ordered byte. Valid complete records produce exact
    /// owned fields; shorter valid prefixes remain private. A caller bounds its
    /// scheduling turn and supplies independent assembly/synchronization deadlines.
    pub fn push(&mut self, byte: u8) -> (result: Result<Option<Message>, Failure>)
        requires old(self).valid(),
        ensures final(self).valid(),
            match result {
                Ok(Some(message)) => message.valid() && !old(self).failed() && !final(self).failed()
                    && message.corresponds(old(self).prefix().push(byte))
                    && final(self).prefix().len() == 0,
                Ok(None) => !old(self).failed() && !final(self).failed()
                    && final(self).prefix() == old(self).prefix().push(byte),
                Err(_) => final(self).failed(),
            },
            old(self).failed() ==> result.is_err(),
            !old(self).failed() && old(self).prefix().len()+1 < HEADER ==> matches!(result, Ok(None)),
            !old(self).failed() && complete_record(old(self).prefix().push(byte)) ==> matches!(result, Ok(Some(_))),
            !old(self).failed() && incomplete_record(old(self).prefix().push(byte)) ==> matches!(result, Ok(None)),
    {
        if self.failed { return Err(Failure::MalformedRecord); }
        let ghost before = self.bytes@;
        self.bytes.push(byte);
        proof {
            if self.bytes@.len() >= HEADER { header_prefix(self.bytes@); }
            if before.len() >= HEADER {
                header_prefix(before);
                assert(self.bytes@.subrange(0, HEADER as int) =~= before.subrange(0, HEADER as int));
            }
        }
        if self.bytes.len() == HEADER {
            let raw = match snapshot(self.bytes.as_slice()) { Some(value) => value, None => { self.failed = true; return Err(Failure::MalformedRecord); } };
            let header = match Header::decode(&raw) { Some(value) => value, None => { self.failed = true; return Err(Failure::MalformedRecord); } };
            proof {
                assert(path_at(self.bytes@, header.path().len() as int));
                assert(self.bytes@.subrange(1, 1+header.path().len() as int) =~= header.path());
                assert(accepted_header(self.bytes@));
            }
            self.target = HEADER + header.value_length();
        }
        if self.bytes.len() < self.target { return Ok(None); }
        let raw = match snapshot(self.bytes.as_slice()) { Some(value) => value, None => { self.failed = true; return Err(Failure::MalformedRecord); } };
        let header = match Header::decode(&raw) { Some(value) => value, None => { self.failed = true; return Err(Failure::MalformedRecord); } };
        let body = &self.bytes.as_slice()[HEADER..];
        let message = match Message::new(header, body) { Some(value) => value, None => { self.failed = true; return Err(Failure::MalformedRecord); } };
        proof {
            assert(message.valid());
            assert(message.header().count() == native_length(before.push(byte)));
            assert(message.header().path() == before.push(byte).subrange(1, 1+message.header().path().len() as int));
            assert(message.corresponds(before.push(byte)));
        }
        self.bytes = Vec::new();
        self.target = HEADER;
        Ok(Some(message))
    }
}


}
