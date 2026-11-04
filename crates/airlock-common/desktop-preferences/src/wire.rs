//! Complete JSON snapshots inside a fixed, bounded binary frame.
//!
//! Each frame starts with ASCII `ADPF`, a big-endian u16 version and a big-endian
//! u16 JSON payload length. Version 1 accepts exactly the current snapshot schema:
//! unknown, duplicate or missing fields fail decoding. Schema extensions require
//! a new protocol version and an explicit compatibility decision.

use crate::Snapshot;
use std::fmt;

/// Wire version accepted by this implementation; there is no guest negotiation.
pub const VERSION: u16 = 1;

/// Bytes of magic, version and payload length preceding every snapshot.
pub const HEADER_LEN: usize = 8;

/// Maximum complete frame, including its header; receivers never buffer more.
pub const MAX_FRAME_LEN: usize = 4096;

/// Failure of the snapshot frame or its validated payload.
#[derive(Debug)]
pub enum FrameError {
    /// The frame does not have the desktop preferences magic bytes.
    InvalidMagic,
    /// This endpoint cannot interpret the sender's protocol version.
    UnsupportedVersion {
        /// Version declared by the remote endpoint, without implying compatibility.
        received: u16,
    },
    /// The declared or encoded payload exceeds the complete-frame limit.
    PayloadTooLarge {
        /// Payload bytes, excluding the fixed header.
        length: usize,
    },
    /// A frame declares no payload instead of a complete snapshot.
    EmptyPayload,
    /// JSON syntax, schema or validated preference values are invalid.
    InvalidPayload {
        /// Parser or value-validation failure within the bounded payload.
        source: serde_json::Error,
    },
    /// The stream ended partway through a header or snapshot.
    TruncatedFrame,
    /// An earlier error ended this decoder's subscription; create a new one on reconnect.
    FailedDecoder,
}

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => formatter.write_str("invalid desktop preferences frame magic"),
            Self::UnsupportedVersion { received } => {
                write!(
                    formatter,
                    "unsupported desktop preferences version {received}"
                )
            }
            Self::PayloadTooLarge { length } => {
                write!(
                    formatter,
                    "desktop preferences payload too large: {length} bytes"
                )
            }
            Self::EmptyPayload => formatter.write_str("empty desktop preferences payload"),
            Self::InvalidPayload { .. } => {
                formatter.write_str("invalid desktop preferences payload")
            }
            Self::TruncatedFrame => formatter.write_str("truncated desktop preferences frame"),
            Self::FailedDecoder => {
                formatter.write_str("desktop preferences decoder already failed")
            }
        }
    }
}

impl std::error::Error for FrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidPayload { source } => Some(source),
            _ => None,
        }
    }
}

/// Encode one complete, validated snapshot, ready for the caller's existing transport.
///
/// Send this on subscription and after each effective change. Bounds on the typed
/// values keep normal encodings within [`MAX_FRAME_LEN`]; the final size is also
/// checked defensively. No caller-supplied names, paths or commands form a request.
pub fn encode_frame(snapshot: &Snapshot) -> Result<Vec<u8>, FrameError> {
    let payload =
        serde_json::to_vec(snapshot).map_err(|source| FrameError::InvalidPayload { source })?;
    check_length(payload.len())?;

    let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
    frame.extend_from_slice(b"ADPF");
    frame.extend_from_slice(&VERSION.to_be_bytes());
    // check_length caps this at 4088 bytes, which fits the wire's u16 length.
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Check payload size before receive buffering or frame assembly.
fn check_length(length: usize) -> Result<(), FrameError> {
    if length == 0 {
        return Err(FrameError::EmptyPayload);
    }
    if length > MAX_FRAME_LEN - HEADER_LEN {
        return Err(FrameError::PayloadTooLarge { length });
    }

    Ok(())
}

/// Incremental decoder for one subscription, with bounded storage and no I/O.
///
/// Feed arbitrary transport chunks to [`Self::decode`] until each chunk is
/// consumed. A successful result is a complete validated snapshot, never a
/// partially updated state. An error permanently fails this decoder: close that
/// subscription, retain the last applied snapshot, and create a new decoder on
/// reconnect. Call [`Self::finish`] when the transport reaches EOF.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    /// Current partial frame, bounded by MAX_FRAME_LEN including its header.
    buffer: Vec<u8>,
    /// Validated total frame length after a complete header has arrived.
    frame_length: Option<usize>,
    /// A framing or validation failure prevents resynchronization on attacker-chosen bytes.
    failed: bool,
}

impl FrameDecoder {
    /// Consume at most one frame from `input`, leaving any following bytes untouched.
    ///
    /// Returns `None` after consuming all available bytes of an incomplete frame.
    /// Returns an error on invalid headers or payloads, including unknown versions;
    /// subsequent calls return [`FrameError::FailedDecoder`]. Buffered state is
    /// discarded on error, and the caller must retain its last valid snapshot.
    ///
    /// ```
    /// use airlock_desktop_preferences::{FrameDecoder, Snapshot, encode_frame};
    /// let snapshot = Snapshot::default();
    /// let bytes = encode_frame(&snapshot)?;
    /// let mut input = bytes.as_slice();
    /// let mut decoder = FrameDecoder::default();
    /// assert_eq!(decoder.decode(&mut input)?, Some(snapshot));
    /// assert!(input.is_empty());
    /// decoder.finish()?;
    /// # Ok::<(), airlock_desktop_preferences::FrameError>(())
    /// ```
    pub fn decode(&mut self, input: &mut &[u8]) -> Result<Option<Snapshot>, FrameError> {
        if self.failed {
            return Err(FrameError::FailedDecoder);
        }

        let result = self.decode_next(input);
        if result.is_err() {
            self.failed = true;
            self.buffer.clear();
        }
        result
    }

    /// Check EOF without resetting preferences or implying that an initial snapshot arrived.
    ///
    /// Empty streams and EOF between frames are clean transport endings. EOF in
    /// any partial frame returns [`FrameError::TruncatedFrame`]. Neither outcome
    /// authorizes clearing the consumer's last valid state.
    pub fn finish(self) -> Result<(), FrameError> {
        if self.failed {
            return Err(FrameError::FailedDecoder);
        }
        if !self.buffer.is_empty() {
            return Err(FrameError::TruncatedFrame);
        }

        Ok(())
    }

    /// Copy only the bytes still needed for a header or an already bounded frame.
    fn fill(&mut self, input: &mut &[u8], length: usize) {
        let count = (length - self.buffer.len()).min(input.len());
        self.buffer.extend_from_slice(&input[..count]);
        *input = &input[count..];
    }

    /// Decode one frame after the public entry point checks the subscription state.
    fn decode_next(&mut self, input: &mut &[u8]) -> Result<Option<Snapshot>, FrameError> {
        if self.frame_length.is_none() {
            self.fill(input, HEADER_LEN);
            if self.buffer.len() < HEADER_LEN {
                return Ok(None);
            }
            if &self.buffer[..4] != b"ADPF" {
                return Err(FrameError::InvalidMagic);
            }

            let received = u16::from_be_bytes([self.buffer[4], self.buffer[5]]);
            if received != VERSION {
                return Err(FrameError::UnsupportedVersion { received });
            }

            let length = usize::from(u16::from_be_bytes([self.buffer[6], self.buffer[7]]));
            check_length(length)?;
            // Avoid Vec's geometric growth exceeding the bound on fragmented frames.
            self.buffer.reserve_exact(length);
            self.frame_length = Some(HEADER_LEN + length);
        }

        let length = self
            .frame_length
            .expect("a validated header sets the frame length");
        self.fill(input, length);
        if self.buffer.len() < length {
            return Ok(None);
        }

        let snapshot = serde_json::from_slice(&self.buffer[HEADER_LEN..])
            .map_err(|source| FrameError::InvalidPayload { source })?;
        self.buffer.clear();
        self.frame_length = None;
        Ok(Some(snapshot))
    }
}
