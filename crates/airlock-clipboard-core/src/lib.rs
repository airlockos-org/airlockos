//! Clipboard ownership, authorization and ordered transfer policy without an OS.
//!
//! A trusted adapter installs a single-use authorization separately from requests.
//! Caller identity and monotonic nanoseconds must come from that adapter, never
//! from the requesting VM. One instance serves one authenticated transport session.
//! No allocation occurs, and no clipboard bytes appear in diagnostic formatting.
#![no_std]
#![warn(missing_docs)]

extern crate alloc;

pub mod shared;

/// Maximum retained clipboard content, including an incomplete transfer.
pub const MAX_CONTENT: usize = 65_536;

/// Data bytes per frame; leaves space for protocol metadata in a 224-byte message.
pub const CHUNK_SIZE: usize = 192;

/// Maximum authorization and content lifetime in monotonic nanoseconds.
pub const MAX_LIFETIME: u64 = 30_000_000_000;

/// Maximum duration of either transfer; progress does not extend this deadline.
pub const TRANSFER_LIFETIME: u64 = 5_000_000_000;

/// Identity established by the trusted adapter, including a fresh session epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caller {
    /// Stable VM identity as resolved by the authority, not a reusable Xen domid.
    pub principal: u64,
    /// Authenticated connection generation; must change after reconnect.
    pub epoch: u64,
}

/// Operation allowed by a trusted GUI policy decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Replace the clipboard with newly copied bytes.
    Copy,
    /// Consume exactly the content identified by its copy authorization ID.
    Paste {
        /// Prevents a delayed paste approval from disclosing newer content.
        content: u64,
    },
}

/// A one-use policy decision installed through the trusted control interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Authorization {
    /// Strictly increasing decision ID for this service lifetime; zero is invalid.
    pub id: u64,
    /// Caller allowed to begin and finish the operation.
    pub caller: Caller,
    /// Approved operation and, for paste, the exact clipboard generation.
    pub action: Action,
    /// Absolute monotonic expiry; also bounds copied content's lifetime.
    pub expires: u64,
}

/// Fixed-capacity private frame data. Debug formatting deliberately omits bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct Chunk {
    /// Only the prefix of this array is meaningful; the rest stays zero.
    bytes: [u8; CHUNK_SIZE],
    /// Initialized prefix length, at most CHUNK_SIZE.
    len: usize,
}

impl core::fmt::Debug for Chunk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Chunk").field("len", &self.len).finish()
    }
}

impl Chunk {
    /// Copy a nonempty bounded slice into private frame storage.
    pub fn new(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > CHUNK_SIZE {
            return Err(Error::Bounds);
        }

        let mut result = Self {
            bytes: [0; CHUNK_SIZE],
            len: bytes.len(),
        };
        result.bytes[..bytes.len()].copy_from_slice(bytes);
        Ok(result)
    }

    /// Return only the initialized payload prefix.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

/// An untrusted operation. Identity and authorization are intentionally absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// Start an explicitly sized copy under the installed authorization.
    Copy {
        /// ID of the trusted copy decision; also becomes the content generation.
        transfer: u64,
        /// Exact number of bytes required before completion, including zero.
        size: usize,
    },
    /// Append the next contiguous copy frame.
    Write {
        /// Active copy decision ID.
        transfer: u64,
        /// Must equal the count already received.
        offset: usize,
        /// Private, bounded bytes to append.
        data: Chunk,
    },
    /// Commit a complete copy or acknowledge a completely read paste.
    Complete {
        /// Active operation ID.
        transfer: u64,
    },
    /// Begin consuming the exact generation approved by a paste decision.
    Paste {
        /// ID of the trusted paste decision, distinct from the copy ID.
        transfer: u64,
    },
    /// Read the next frame of an exclusively claimed paste.
    Read {
        /// Active paste decision ID.
        transfer: u64,
        /// Must equal the count already returned; rereads are rejected.
        offset: usize,
    },
    /// Erase an incomplete copy or claimed paste without restoring content.
    Cancel {
        /// Active operation ID.
        transfer: u64,
    },
}

/// Observable results; no response carries authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Response {
    /// Operation accepted, including explicit completion and cancellation.
    Ok,
    /// Paste claimed exclusively; the client must read this many bytes and complete.
    Size(
        /// Total content bytes claimed by this paste, including zero.
        usize,
    ),
    /// Next contiguous paste bytes.
    Data(
        /// Next private frame; ownership has already advanced past these bytes.
        Chunk,
    ),
}

/// Stable failure categories for policy and protocol responses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Error {
    /// No matching live authorization or transfer ownership.
    Unauthorized = 1,
    /// Request/decision ID was already observed or is older than the high-water mark.
    Replay = 2,
    /// The requested content or transfer no longer exists (including expiration).
    Unavailable = 3,
    /// Declared size, chunk size or lifetime exceeds a fixed bound.
    Bounds = 4,
    /// Another transfer or unused authorization occupies the single slot.
    Busy = 5,
    /// Wrong frame position or incomplete completion; the owned transfer is erased.
    Order = 6,
    /// Time regressed; secrets and authorization were erased.
    Clock = 7,
    /// Invalid application frame encoding.
    Malformed = 8,
}

/// Mutually exclusive lifecycle phases of the one private clipboard buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Empty,
    Copying,
    Ready,
    Pasting,
}

/// Fixed-memory clipboard for one authenticated session.
// Verification invariants: len <= MAX_CONTENT; position <= len; bytes beyond len
// are zero. Empty has no usable bytes. Ready follows only complete Copying.
// Pasting exclusively consumes Ready and can never transition back to Ready.
// Only an installed decision starts an operation; every continuation matches its
// owner and ID. High-water marks survive erasure and cannot wrap. Deadlines never
// extend on progress. Expiry and all terminal transfer failures erase the buffer.
pub struct Clipboard {
    /// Sole retained payload buffer; no backup survives paste or replacement.
    bytes: [u8; MAX_CONTENT],
    /// Current ownership phase.
    phase: Phase,
    /// Declared content length, bounded at copy start.
    len: usize,
    /// Next expected copy/write or paste/read offset.
    position: usize,
    /// Caller owning the active transfer.
    owner: Caller,
    /// Copy generation, retained while the content is ready or being pasted.
    content: u64,
    /// Active transfer's authorization ID.
    transfer: u64,
    /// Content deadline, inherited from copy approval.
    expires: u64,
    /// Transfer deadline, also bounded by approval and content deadlines.
    transfer_expires: u64,
    /// One pending authorization; no unbounded capability table.
    authorization: Option<Authorization>,
    /// Greatest installed authorization ID, retained after erasure.
    last_authorization: u64,
    /// Greatest request ID on the authenticated transport session.
    last_request: u64,
    /// Last trusted monotonic observation, retained after erasure.
    last_time: u64,
}

impl Default for Clipboard {
    fn default() -> Self {
        Self::new()
    }
}

impl Clipboard {
    /// Create an empty session. A restarted service requires fresh provisioning.
    pub const fn new() -> Self {
        Self {
            bytes: [0; MAX_CONTENT],
            phase: Phase::Empty,
            len: 0,
            position: 0,
            owner: Caller {
                principal: 0,
                epoch: 0,
            },
            content: 0,
            transfer: 0,
            expires: 0,
            transfer_expires: 0,
            authorization: None,
            last_authorization: 0,
            last_request: 0,
            last_time: 0,
        }
    }

    /// Install a trusted policy decision. Never call this with unauthenticated input.
    /// Rejects replay, excess lifetime and occupied slots without replacing them.
    pub fn authorize(&mut self, now: u64, decision: Authorization) -> Result<(), Error> {
        self.tick(now)?;
        if decision.id <= self.last_authorization {
            return Err(Error::Replay);
        }
        if decision.expires <= now || decision.expires - now > MAX_LIFETIME {
            return Err(Error::Bounds);
        }
        if self.authorization.is_some() || matches!(self.phase, Phase::Copying | Phase::Pasting) {
            return Err(Error::Busy);
        }

        self.last_authorization = decision.id;
        self.authorization = Some(decision);
        Ok(())
    }

    /// Erase expired content/transfers and approvals, including while idle.
    /// A regressing clock fails closed without lowering the last observation.
    pub fn tick(&mut self, now: u64) -> Result<(), Error> {
        if now < self.last_time {
            self.clear();
            return Err(Error::Clock);
        }

        self.last_time = now;
        if self.authorization.is_some_and(|a| now >= a.expires) {
            self.authorization = None;
        }
        if self.phase != Phase::Empty
            && (now >= self.expires
                || (matches!(self.phase, Phase::Copying | Phase::Pasting)
                    && now >= self.transfer_expires))
        {
            self.erase();
        }
        Ok(())
    }

    /// Next absolute deadline requiring cleanup; an adapter may block until then.
    pub fn deadline(&self) -> Option<u64> {
        let approval = self.authorization.map(|a| a.expires);
        let content = match self.phase {
            Phase::Empty => None,
            Phase::Ready => Some(self.expires),
            _ => Some(self.expires.min(self.transfer_expires)),
        };
        match (approval, content) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Process a request with injected trusted time and caller identity.
    /// Request IDs are strictly increasing across all callers on this connection.
    pub fn handle(
        &mut self,
        now: u64,
        caller: Caller,
        id: u64,
        request: Request,
    ) -> Result<Response, Error> {
        self.tick(now)?;
        if id <= self.last_request {
            return Err(Error::Replay);
        }
        self.last_request = id;

        match request {
            Request::Copy { transfer, size } => {
                let approval = self.approval(caller, transfer, Action::Copy)?;
                if size > MAX_CONTENT {
                    self.authorization = None;
                    return Err(Error::Bounds);
                }

                self.start(now, approval, size, Phase::Copying);
                Ok(Response::Ok)
            }
            Request::Paste { transfer } => {
                let approval = self.authorization.ok_or(Error::Unauthorized)?;
                self.approval(caller, transfer, approval.action)?;
                let Action::Paste { content } = approval.action else {
                    return Err(Error::Unauthorized);
                };
                self.authorization = None;
                if self.phase != Phase::Ready || self.content != content {
                    return Err(Error::Unavailable);
                }

                self.start(now, approval, self.len, Phase::Pasting);
                Ok(Response::Size(self.len))
            }
            Request::Write {
                transfer,
                offset,
                data,
            } => {
                self.owned(caller, transfer, Phase::Copying)?;
                if offset != self.position || data.len > self.len - self.position {
                    return self.abort_order();
                }

                self.bytes[offset..offset + data.len].copy_from_slice(data.bytes());
                self.position += data.len;
                Ok(Response::Ok)
            }
            Request::Read { transfer, offset } => {
                self.owned(caller, transfer, Phase::Pasting)?;
                if offset != self.position || offset == self.len {
                    return self.abort_order();
                }

                let end = self.len.min(offset + CHUNK_SIZE);
                let data = Chunk::new(&self.bytes[offset..end])?;
                // Even the already returned prefix is erased from retained state.
                wipe(&mut self.bytes[offset..end]);
                self.position = end;
                Ok(Response::Data(data))
            }
            Request::Complete { transfer } => {
                self.active(caller, transfer)?;
                if self.position != self.len {
                    return self.abort_order();
                }

                if self.phase == Phase::Copying {
                    self.phase = Phase::Ready;
                } else {
                    self.erase();
                }
                Ok(Response::Ok)
            }
            Request::Cancel { transfer } => {
                self.active(caller, transfer)?;
                self.erase();
                Ok(Response::Ok)
            }
        }
    }

    /// Erase payload and pending authority on disconnect, malformed input or shutdown.
    /// Replay high-water marks and trusted clock history survive this operation.
    pub fn clear(&mut self) {
        self.erase();
        self.authorization = None;
    }

    fn approval(&self, caller: Caller, id: u64, action: Action) -> Result<Authorization, Error> {
        let approval = self.authorization.ok_or(Error::Unauthorized)?;
        if approval.caller != caller || approval.id != id || approval.action != action {
            return Err(Error::Unauthorized);
        }
        Ok(approval)
    }

    fn start(&mut self, now: u64, approval: Authorization, size: usize, phase: Phase) {
        if phase == Phase::Copying {
            self.erase();
            self.content = approval.id;
            self.expires = approval.expires;
        }

        self.authorization = None;
        self.phase = phase;
        self.owner = approval.caller;
        self.transfer = approval.id;
        self.len = size;
        self.position = 0;
        self.transfer_expires = now
            .saturating_add(TRANSFER_LIFETIME)
            .min(approval.expires)
            .min(self.expires);
    }

    fn active(&self, caller: Caller, transfer: u64) -> Result<(), Error> {
        if !matches!(self.phase, Phase::Copying | Phase::Pasting) {
            return Err(Error::Unavailable);
        }
        if self.owner != caller || self.transfer != transfer {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    fn owned(&mut self, caller: Caller, transfer: u64, phase: Phase) -> Result<(), Error> {
        self.active(caller, transfer)?;
        if self.phase != phase {
            self.erase();
            return Err(Error::Order);
        }
        Ok(())
    }

    fn abort_order(&mut self) -> Result<Response, Error> {
        self.erase();
        Err(Error::Order)
    }

    fn erase(&mut self) {
        wipe(&mut self.bytes);
        self.phase = Phase::Empty;
        self.len = 0;
        self.position = 0;
        self.owner = Caller {
            principal: 0,
            epoch: 0,
        };
        self.content = 0;
        self.transfer = 0;
        self.expires = 0;
        self.transfer_expires = 0;
    }
}

impl Drop for Clipboard {
    fn drop(&mut self) {
        self.clear();
    }
}

fn wipe(bytes: &mut [u8]) {
    for byte in bytes {
        // Volatile writes keep terminal cleanup from being elided before teardown.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests;
