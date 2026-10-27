//! A shared desktop clipboard with atomic, multi-format replacement.
//!
//! The transport authenticates participants before calling this module. Content
//! has no expiry and reads never consume it. Only incomplete writes expire.
//! Access decisions are centralized here so future policies need not change
//! desktop format transfer or trust identities supplied by a requesting VM.

use alloc::{string::String, vec::Vec};

/// Maximum number of representations in one clipboard offer.
pub const MAX_FORMATS: usize = 64;

/// Maximum bytes in a format name, independent of payload capacity.
pub const MAX_FORMAT_NAME: usize = 192;

/// Maximum total payload retained in the default clipboard service.
pub const DEFAULT_CAPACITY: usize = 64 * 1024 * 1024;

/// Deadline for completing an in-flight replacement, in monotonic nanoseconds.
pub const WRITE_TIMEOUT: u64 = 120_000_000_000;

/// Participant identity assigned by the trusted connection provisioner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Participant {
    /// Stable identity within the admitted machine's clipboard membership.
    pub principal: u64,
    /// Fresh authenticated connection lifetime; never reused after disconnect.
    pub epoch: u64,
}

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
    /// Available memory could not accommodate this replacement.
    Capacity,
}

/// Metadata for an immutable representation; the body stays private to the service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Format {
    /// Desktop MIME type or X selection target identifying these bytes.
    pub name: String,
    /// Exact representation size, including zero-byte content.
    pub size: usize,
}

/// Public identity of a complete clipboard offer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    /// Monotonically increasing replacement identity within this service boot.
    pub generation: u64,
    /// Authenticated source of the content, retained independently of its connection.
    pub source: Participant,
    /// Available representations in their original preference order.
    pub formats: Vec<Format>,
}

/// One representation under construction or retained for repeated paste.
struct Representation {
    /// Format name and promised byte length.
    format: Format,
    /// Private bytes received in contiguous order, never included in Debug output.
    bytes: Vec<u8>,
}

/// Private offer state before or after publication.
struct Content {
    /// Globally ordered identity issued before reading any source bytes.
    generation: u64,
    /// Authenticated owner of this replacement.
    source: Participant,
    /// Representation buffers bounded by the service's total capacity.
    formats: Vec<Representation>,
    /// Fixed incomplete-write deadline; absent after explicit completion.
    deadline: Option<u64>,
}

/// One shared clipboard, with at most one pending replacement and one published offer.
pub struct Clipboard {
    /// Maximum combined length of the representations in an offer.
    capacity: usize,
    /// Latest issued identity; preserved even when a replacement fails.
    generation: u64,
    /// Complete data eligible for repeated reads.
    published: Option<Content>,
    /// Replacement being filled; never exposed to readers.
    pending: Option<Content>,
    /// Last monotonic observation; regressions invalidate unfinished transfers.
    last_time: u64,
}

impl Clipboard {
    /// Create an empty clipboard with an explicit per-offer payload bound.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            generation: 0,
            published: None,
            pending: None,
            last_time: 0,
        }
    }

    /// Check normal-mode membership at the single shared read/write policy boundary.
    /// The connection adapter must have authenticated both nonzero identity fields.
    fn access(&self, caller: Participant) -> Result<(), Error> {
        if caller.principal == 0 || caller.epoch == 0 {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    /// Forget an expired unfinished write; published content never expires.
    pub fn tick(&mut self, now: u64) {
        if now < self.last_time
            || self
                .pending
                .as_ref()
                .is_some_and(|p| p.deadline.is_some_and(|d| now >= d))
        {
            self.pending = None;
        }
        self.last_time = now;
    }

    /// Begin replacing the clipboard, invalidating every older offer immediately.
    /// An empty format list clears shared availability, including when a source
    /// copies local files that must remain usable only inside its own VM.
    pub fn begin(
        &mut self,
        now: u64,
        caller: Participant,
        formats: Vec<Format>,
    ) -> Result<u64, Error> {
        self.access(caller)?;
        self.tick(now);
        validate_formats(&formats, self.capacity)?;
        let generation = self.reserve(now, caller)?;
        self.declare(now, caller, generation, formats)?;
        Ok(generation)
    }

    /// Reserve replacement order as soon as the local clipboard owner changes.
    /// Slow format conversion cannot later replace a newer copy from another VM.
    pub fn reserve(&mut self, now: u64, caller: Participant) -> Result<u64, Error> {
        self.access(caller)?;
        self.tick(now);
        let generation = self.generation.checked_add(1).ok_or(Error::Bounds)?;
        let deadline = now.checked_add(WRITE_TIMEOUT).ok_or(Error::Bounds)?;
        self.generation = generation;
        self.published = None;
        self.pending = Some(Content {
            generation,
            source: caller,
            formats: Vec::new(),
            deadline: Some(deadline),
        });
        Ok(generation)
    }

    /// Describe representations for an already reserved replacement.
    /// Empty offers clear shared availability while leaving source-local file offers alone.
    pub fn declare(
        &mut self,
        now: u64,
        caller: Participant,
        generation: u64,
        formats: Vec<Format>,
    ) -> Result<(), Error> {
        self.access(caller)?;
        self.tick(now);
        validate_formats(&formats, self.capacity)?;
        let pending = self.pending.as_ref().ok_or(Error::Stale)?;
        if pending.source != caller
            || pending.generation != generation
            || !pending.formats.is_empty()
        {
            return Err(Error::Stale);
        }
        let deadline = pending.deadline;
        self.pending = None;
        if formats.is_empty() {
            return Ok(());
        }
        let mut representations = Vec::new();
        representations
            .try_reserve_exact(formats.len())
            .map_err(|_| Error::Capacity)?;
        for format in formats {
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(format.size)
                .map_err(|_| Error::Capacity)?;
            representations.push(Representation { format, bytes });
        }
        self.pending = Some(Content {
            generation,
            source: caller,
            formats: representations,
            deadline,
        });
        Ok(())
    }

    /// Append one contiguous chunk to an unfinished representation.
    pub fn write(
        &mut self,
        now: u64,
        caller: Participant,
        generation: u64,
        format: usize,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), Error> {
        self.access(caller)?;
        self.tick(now);
        let content = self.pending.as_mut().ok_or(Error::Stale)?;
        if content.generation != generation || content.source != caller {
            return Err(Error::Stale);
        }
        let representation = content.formats.get_mut(format).ok_or(Error::Bounds)?;
        let end = offset.checked_add(bytes.len()).ok_or(Error::Bounds)?;
        if offset != representation.bytes.len()
            || end > representation.format.size
            || bytes.is_empty()
        {
            self.pending = None;
            return Err(Error::Order);
        }
        representation.bytes.extend_from_slice(bytes);
        Ok(())
    }

    /// Publish all representations together after every promised byte arrived.
    pub fn complete(
        &mut self,
        now: u64,
        caller: Participant,
        generation: u64,
    ) -> Result<(), Error> {
        self.access(caller)?;
        self.tick(now);
        let content = self.pending.as_ref().ok_or(Error::Stale)?;
        if content.generation != generation || content.source != caller {
            return Err(Error::Stale);
        }
        if content.formats.is_empty()
            || content
                .formats
                .iter()
                .any(|r| r.bytes.len() != r.format.size)
        {
            self.pending = None;
            return Err(Error::Order);
        }
        let mut content = self.pending.take().ok_or(Error::Stale)?;
        content.deadline = None;
        self.published = Some(content);
        Ok(())
    }

    /// Return the latest issued generation and any completely published offer.
    /// The generation also changes on clear, allowing endpoints to discard stale data.
    pub fn offer(&self, caller: Participant) -> Result<(u64, Option<Offer>), Error> {
        self.access(caller)?;
        Ok((
            self.generation,
            self.published.as_ref().map(|content| Offer {
                generation: content.generation,
                source: content.source,
                formats: content.formats.iter().map(|r| r.format.clone()).collect(),
            }),
        ))
    }

    /// Read a bounded range from exactly the requested generation, without consuming it.
    pub fn read(
        &self,
        caller: Participant,
        generation: u64,
        format: usize,
        offset: usize,
        maximum: usize,
    ) -> Result<&[u8], Error> {
        self.access(caller)?;
        let content = self
            .published
            .as_ref()
            .filter(|c| c.generation == generation)
            .ok_or(Error::Stale)?;
        let representation = content.formats.get(format).ok_or(Error::Bounds)?;
        if offset > representation.bytes.len() || maximum == 0 {
            return Err(Error::Bounds);
        }
        let end = offset
            .saturating_add(maximum)
            .min(representation.bytes.len());
        Ok(&representation.bytes[offset..end])
    }

    /// Abort only this connection's unfinished write; completed copies remain readable.
    pub fn disconnect(&mut self, caller: Participant) {
        if self.pending.as_ref().is_some_and(|p| p.source == caller) {
            self.pending = None;
        }
    }
}

/// Reject file references and desktop clipboard control targets at every endpoint.
/// Do not forward filenames as a text fallback when an offer contains file targets.
pub fn is_file_format(name: &str) -> bool {
    matches!(
        name,
        "text/uri-list"
            | "x-special/gnome-copied-files"
            | "application/x-kde-cutselection"
            | "application/vnd.portal.filetransfer"
            | "application/vnd.portal.files"
            | "x-special/nautilus-clipboard"
    )
}

/// Whether a representation carries transferable data rather than selection control.
pub fn is_data_format(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_FORMAT_NAME
        && name.bytes().all(|b| (0x20..=0x7e).contains(&b))
        && !is_file_format(name)
        && !matches!(
            name,
            "TARGETS"
                | "TIMESTAMP"
                | "MULTIPLE"
                | "INCR"
                | "SAVE_TARGETS"
                | "DELETE"
                | "INSERT_SELECTION"
                | "INSERT_PROPERTY"
                | "PIXMAP"
                | "BITMAP"
                | "COLORMAP"
                | "WINDOW"
                | "DRAWABLE"
        )
}

/// Validate the complete offer before allocating or replacing clipboard storage.
pub fn validate_formats(formats: &[Format], capacity: usize) -> Result<(), Error> {
    if formats.len() > MAX_FORMATS {
        return Err(Error::Bounds);
    }
    let mut total = 0usize;
    for (index, format) in formats.iter().enumerate() {
        if !is_data_format(&format.name) {
            return Err(Error::Unsupported);
        }
        if formats[..index].iter().any(|f| f.name == format.name) {
            return Err(Error::Order);
        }
        total = total.checked_add(format.size).ok_or(Error::Bounds)?;
        if total > capacity {
            return Err(Error::Bounds);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
