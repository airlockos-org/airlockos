//! Startup resource tuning carried by dom0's existing QubesDB connection.
//! JSON decoding supplies claims, never policy authority. Only `Limits::validate`
//! constructs effective settings. The native adapter selects once after initial
//! synchronization and retains that value until this VM exits.
//!
//! Serde owns JSON syntax, duplicate/unknown-field rejection and integer decoding.
//! Our verified validation owns the relationships and compiled ceilings. Neither
//! JSON settings nor resource availability can authorize a packet or interface.

use vstd::prelude::*;

verus! {

/// Maximum parameter document size, within QubesDB's 3071-byte value limit.
pub const MAX_DOCUMENT_BYTES: usize = 1024;

/// Maximum aggregate peer records supported by the current memory budget.
/// Increase only with the allocation and mixed-load measurements for that budget.
pub const MAX_RECORDS: usize = 8192;

/// Fixed application arena for the supported namespace and state ceilings.
/// Provisioning envelopes: 7 MiB for peer records and every associated index,
/// 4 MiB for DNS/cache/message state, 3 MiB for control records and projections,
/// and 4 MiB for reassembly, queued packets, native adapters and temporaries.
/// The remaining 6 MiB covers allocator overhead, fragmentation and transient
/// growth. These envelopes need mixed-load measurements before image acceptance;
/// requested-byte accounting or Rust type sizes alone do not establish fit.
pub const APPLICATION_HEAP_BYTES: usize = 24 * 1024 * 1024;

/// Claimed resource settings. Deserialization alone does not validate them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(verus_keep_ghost), derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(not(verus_keep_ghost), serde(deny_unknown_fields))]
pub struct Document {
    /// Schema version; only version one is understood by this executable.
    pub version: u32,
    /// Maximum live peer authorizations across all client interfaces.
    pub active_global: usize,
    /// Maximum live peer authorizations for one stable client identity.
    pub active_per_client: usize,
    /// Maximum stored peer reservations, including active flows' future retirement.
    pub retained_global: usize,
    /// Stored reservation budget for one client across all interface lifetimes.
    pub retained_per_client: usize,
    /// Interval between resource summaries; separate from lifecycle heartbeats.
    pub report_interval_seconds: u32,
}

impl Document {
    /// Every attached client has its own allowance within the global budgets.
    /// Each active flow reserves its own eventual retirement storage on admission.
    /// The gap between active and stored limits is headroom for connection churn;
    /// expiry never needs another peer record or evicts another client's reservation.
    pub open spec fn supported(&self) -> bool {
        self.version == 1
            && 0 < self.active_per_client <= MAX_RECORDS / crate::MAX_CLIENTS
            && 0 < self.retained_per_client <= MAX_RECORDS / crate::MAX_CLIENTS
            && self.active_per_client * crate::MAX_CLIENTS <= self.active_global
            && self.retained_per_client * crate::MAX_CLIENTS <= self.retained_global
            && self.active_global <= MAX_RECORDS
            && self.retained_global <= MAX_RECORDS
            && self.active_global < self.retained_global
            && self.active_per_client < self.retained_per_client
            && 1 <= self.report_interval_seconds <= 300
    }
}

/// Validated, immutable operating limits for one firewall VM lifetime.
/// Private representation prevents deserialization from bypassing validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Complete document selected together after the startup snapshot.
    document: Document,
}

impl Limits {
    /// The selected document satisfies all compiled resource constraints.
    pub closed spec fn valid(&self) -> bool { self.document.supported() }

    /// Complete selected values for contracts, independent of decoding.
    pub closed spec fn value(&self) -> Document { self.document }

    /// Validate a complete claim without clamping or silently substituting values.
    pub fn validate(document: Document) -> (limits: Option<Self>)
        ensures limits.is_some() == document.supported(),
            limits.is_some() ==> limits.unwrap().valid() && limits.unwrap().value() == document,
    {
        if document.version != 1
            || document.active_per_client == 0 || document.active_per_client > MAX_RECORDS / crate::MAX_CLIENTS
            || document.retained_per_client == 0 || document.retained_per_client > MAX_RECORDS / crate::MAX_CLIENTS
            || document.active_global > MAX_RECORDS || document.retained_global > MAX_RECORDS
        { return None; }

        if document.active_per_client * crate::MAX_CLIENTS > document.active_global
            || document.retained_per_client * crate::MAX_CLIENTS > document.retained_global
            || document.active_global >= document.retained_global
            || document.active_per_client >= document.retained_per_client
            || document.report_interval_seconds < 1 || document.report_interval_seconds > 300
        { return None; }

        Some(Self { document })
    }

    /// Reserve half the supported records for active work and half for churn.
    /// These operating defaults and the ceiling require mixed-load validation
    /// against the application arena before image acceptance.
    pub fn defaults() -> (limits: Self)
        ensures limits.valid(),
    {
        Self { document: Document { version: 1, active_global: 4096, active_per_client: 1024,
            retained_global: 8192, retained_per_client: 2048, report_interval_seconds: 30 } }
    }

    /// Borrow the effective settings without permitting mutation.
    pub fn document(&self) -> (document: &Document)
        requires self.valid(), ensures *document == self.value(), document.supported(),
    { &self.document }
}

/// Bound decoder input before invoking the trusted JSON library.
pub fn document_size_allowed(length: usize) -> (allowed: bool)
    ensures allowed == (0 < length <= MAX_DOCUMENT_BYTES),
{ length > 0 && length <= MAX_DOCUMENT_BYTES }

}

/// Startup failure categories, without echoing untrusted configuration bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Present documents must fit the transport/application byte ceiling.
    Size,
    /// Invalid JSON, missing/duplicate/unknown fields or invalid integer types.
    Json,
    /// Well-formed claims violate the version or resource constraints.
    Unsupported,
}

/// Decode one selected complete document, or choose defaults for genuine absence.
///
/// The caller must wait for initial database synchronization before using `None`.
/// Serde is a trusted syntax adapter; every decoded claim passes through the
/// verified validator. There is no fallback for a present but invalid document.
#[cfg(not(verus_keep_ghost))]
pub fn decode(document: Option<&[u8]>) -> Result<Limits, DecodeError> {
    let Some(bytes) = document else {
        return Ok(Limits::defaults());
    };
    if !document_size_allowed(bytes.len()) {
        return Err(DecodeError::Size);
    }

    let claim: Document = serde_json::from_slice(bytes).map_err(|_| DecodeError::Json)?;
    Limits::validate(claim).ok_or(DecodeError::Unsupported)
}
