//! Checked multi-format offer layout; names, aggregate sizes and uniqueness are policy.
//! Raw desktop metadata is a claim. Only an owned CheckedOffer establishes an
//! accepted layout, carried unchanged into storage allocation and publication.

use alloc::{string::String, vec::Vec};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::string::StringSliceAdditionalSpecFns;

verus! {

/// Maximum number of representations in one clipboard offer.
pub const MAX_FORMATS: usize = 64;

/// Maximum bytes in a format name, independent of payload capacity.
pub const MAX_FORMAT_NAME: usize = 192;


/// Failure categories carry no clipboard payload or format contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The connection is not a valid authenticated participant.
    Unauthorized,
    /// The requested generation has been replaced or never existed.
    Stale,
    /// A format, payload, or offer exceeds the configured resource bound.
    Bounds,
    /// File references and clipboard protocol control targets cannot be shared.
    Unsupported,
    /// The write does not belong to this connection, or chunks arrived out of order.
    Order,
    /// The incomplete offer exceeded its fixed deadline.
    Timeout,
    /// Available memory or disk could not accommodate this replacement.
    Capacity,
    /// Private storage failed; no partial offer is published or returned.
    Io,
}

/// Untrusted desktop representation claim; validation produces an owned CheckedOffer.
#[derive(Debug, PartialEq, Eq)]
pub struct Format {
    /// Desktop MIME type or X selection target identifying these bytes.
    pub name: String,
    /// Exact representation size, including zero-byte content.
    pub size: usize,
}

impl Clone for Format {
    fn clone(&self) -> (out: Self)
        ensures out.name@ == self.name@, out.size == self.size,
    { Self { name: self.name.clone(), size: self.size } }
}


/// File references are local-only even when a sender offers a text fallback.
pub open spec fn file_target(name: Seq<char>) -> bool {
    name == "text/uri-list"@ || name == "x-special/gnome-copied-files"@
        || name == "application/x-kde-cutselection"@ || name == "application/vnd.portal.filetransfer"@
        || name == "application/vnd.portal.files"@ || name == "x-special/nautilus-clipboard"@
}

/// X selection control messages and window/pixmap references are not clipboard data.
pub open spec fn control_target(name: Seq<char>) -> bool {
    name == "TARGETS"@ || name == "TIMESTAMP"@ || name == "MULTIPLE"@ || name == "INCR"@
        || name == "SAVE_TARGETS"@ || name == "DELETE"@ || name == "INSERT_SELECTION"@
        || name == "INSERT_PROPERTY"@ || name == "PIXMAP"@ || name == "BITMAP"@
        || name == "COLORMAP"@ || name == "WINDOW"@ || name == "DRAWABLE"@
}

/// Names must be nonempty bounded printable ASCII, excluding local references and control targets.
pub open spec fn data_target(name: Seq<char>) -> bool {
    0 < vstd::utf8::encode_utf8(name).len() <= MAX_FORMAT_NAME
        && (forall|i: int| 0 <= i < vstd::utf8::encode_utf8(name).len()
            ==> 0x20 <= #[trigger] vstd::utf8::encode_utf8(name)[i] <= 0x7e)
        && !file_target(name) && !control_target(name)
}

/// Sum in mathematical integers; validation must reject machine arithmetic overflow.
pub open spec fn payload_bytes(formats: Seq<Format>) -> int
    decreases formats.len(),
{
    if formats.len() == 0 { 0 } else {
        payload_bytes(formats.drop_last()) + formats.last().size
    }
}

/// Payload sizes are nonnegative, so a rejected prefix cannot fit a larger offer.
pub proof fn prefix_bound(formats: Seq<Format>, prefix: int)
    requires 0 <= prefix <= formats.len(),
    ensures 0 <= payload_bytes(formats),
        payload_bytes(formats.take(prefix)) <= payload_bytes(formats),
    decreases formats.len(),
{
    if formats.len() > 0 {
        if prefix < formats.len() {
            prefix_bound(formats.drop_last(), prefix);
            assert(formats.drop_last().take(prefix) == formats.take(prefix));
        } else {
            prefix_bound(formats.drop_last(), formats.len() - 1);
            assert(formats.take(prefix) == formats);
        }
    }
}

/// Complete admissibility, including valid names, unique representations and aggregate capacity.
pub open spec fn accepted(formats: Seq<Format>, capacity: usize) -> bool {
    formats.len() <= MAX_FORMATS && payload_bytes(formats) <= capacity
        && (forall|i: int| 0 <= i < formats.len() ==> data_target(formats[i].name@))
        && (forall|i: int, j: int| 0 <= j < i < formats.len() ==> formats[i].name@ != formats[j].name@)
}

/// Reject file references and desktop clipboard control targets at every endpoint.
/// Do not forward filenames as a text fallback when an offer contains file targets.
pub fn is_file_format(name: &str) -> (yes: bool)
    ensures yes == file_target(name@),
{
    name == "text/uri-list" || name == "x-special/gnome-copied-files"
        || name == "application/x-kde-cutselection" || name == "application/vnd.portal.filetransfer"
        || name == "application/vnd.portal.files" || name == "x-special/nautilus-clipboard"
}

/// Whether a representation carries transferable data rather than selection control.
pub fn is_data_format(name: &str) -> (yes: bool)
    ensures yes == data_target(name@),
{
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_FORMAT_NAME { return false; }
    let mut i = 0;
    while i < bytes.len()
        invariant i <= bytes.len(), bytes@ == name.spec_bytes(),
            forall|j: int| 0 <= j < i ==> 0x20 <= #[trigger] bytes[j] <= 0x7e,
        decreases bytes.len() - i,
    {
        if bytes[i] < 0x20 || bytes[i] > 0x7e { return false; }
        i += 1;
    }
    !is_file_format(name)
        && name != "TARGETS" && name != "TIMESTAMP" && name != "MULTIPLE" && name != "INCR"
        && name != "SAVE_TARGETS" && name != "DELETE" && name != "INSERT_SELECTION"
        && name != "INSERT_PROPERTY" && name != "PIXMAP" && name != "BITMAP"
        && name != "COLORMAP" && name != "WINDOW" && name != "DRAWABLE"
}

/// Validate raw metadata and compute its aggregate size with overflow-safe arithmetic.
fn checked_total(formats: &[Format], capacity: usize) -> (out: Result<usize, Error>)
    ensures out.is_ok() == accepted(formats@, capacity),
        out.is_ok() ==> out.unwrap() == payload_bytes(formats@),
{
    if formats.len() > MAX_FORMATS { return Err(Error::Bounds); }
    let mut total = 0usize;
    let mut i = 0;
    while i < formats.len()
        invariant i <= formats.len(), formats.len() <= MAX_FORMATS,
            total <= capacity, total == payload_bytes(formats@.take(i as int)),
            forall|k: int| 0 <= k < i ==> data_target(formats[k].name@),
            forall|k: int, j: int| 0 <= j < k < i ==> formats[k].name@ != formats[j].name@,
        decreases formats.len() - i,
    {
        let format = &formats[i];
        if !is_data_format(format.name.as_str()) { return Err(Error::Unsupported); }
        let mut j = 0;
        while j < i
            invariant j <= i, i < formats.len(), formats.len() <= MAX_FORMATS,
                format.name@ == formats[i as int].name@, format.size == formats[i as int].size,
                total <= capacity, total == payload_bytes(formats@.take(i as int)),
                forall|k: int| 0 <= k < i ==> data_target(formats[k].name@),
                forall|k: int, previous: int| 0 <= previous < k < i
                    ==> formats[k].name@ != formats[previous].name@,
                forall|k: int| 0 <= k < j ==> formats[k].name@ != format.name@,
            decreases i - j,
        {
            if formats[j].name.as_str() == format.name.as_str() {
                proof {
                    if accepted(formats@, capacity) {
                        assert(formats[i as int].name@ != formats[j as int].name@);
                        assert(false);
                    }
                }
                return Err(Error::Order);
            }
            j += 1;
        }
        if format.size > capacity - total {
            proof {
                prefix_bound(formats@, i as int + 1);
                assert(formats@.take(i as int + 1).drop_last() == formats@.take(i as int));
                assert(payload_bytes(formats@.take(i as int + 1)) == total + format.size);
            }
            return Err(Error::Bounds);
        }
        total += format.size;
        assert(formats@.take(i as int + 1).drop_last() == formats@.take(i as int));
        i += 1;
    }
    assert(formats@.take(formats.len() as int) == formats@);
    Ok(total)
}

/// Check a borrowed desktop offer without granting authority or allocating payload storage.
pub fn validate_formats(formats: &[Format], capacity: usize) -> (out: Result<(), Error>)
    ensures out.is_ok() == accepted(formats@, capacity),
{
    match checked_total(formats, capacity) { Ok(_) => Ok(()), Err(error) => Err(error) }
}

/// Owned, validated metadata and exact aggregate size; no caller can mutate its representation.
pub struct CheckedOffer {
    /// Stable metadata whose size and names were validated together.
    formats: Vec<Format>,
    /// Aggregate storage reservation obtained from the same checked metadata.
    total: usize,
}

impl CheckedOffer {
    /// Immutable metadata used in this checked layout.
    pub closed spec fn metadata(&self) -> Seq<Format> { self.formats@ }

    /// Exact aggregate byte count established by construction.
    pub closed spec fn bytes(&self) -> usize { self.total }

    /// Consume raw metadata only after validating every representation and the total.
    pub fn new(formats: Vec<Format>, capacity: usize) -> (out: Result<Self, Error>)
        ensures out.is_ok() == accepted(formats@, capacity),
            out.is_ok() ==> out.unwrap().metadata() == formats@
                && out.unwrap().bytes() == payload_bytes(formats@),
    {
        match checked_total(&formats, capacity) {
            Ok(total) => Ok(Self { formats, total }),
            Err(error) => Err(error),
        }
    }

    /// Transfer the exact checked metadata and byte count to their exclusive storage owner.
    pub fn into_parts(self) -> (parts: (Vec<Format>, usize))
        ensures parts.0@ == self.metadata(), parts.1 == self.bytes(),
    { (self.formats, self.total) }
}

}
