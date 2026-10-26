//! Moving immutable software preserves content and identity before any reference changes.
//! Adapters authenticate decoded records, content hashes, durable writes and locked observations.

/// Typed backing-file and byte-range checks used before relocation content verification.
pub mod extent;

use extent::CheckedExtent;
use vstd::prelude::*;

verus! {

/// One immutable object's logical identity, separate from the location holding its bytes.
pub struct Identity {
    /// Exact object basename, including the shared `.tar-eof` marker.
    pub name: String,
    /// Original Nix store path; empty only for the shared terminator.
    pub path: String,
    /// Original unpacked-tree identity; empty only for the shared terminator.
    pub tree_hash: String,
}

/// Physical coordinates and immutable fragment contents decoded from one pool record.
pub struct Location {
    /// Original canonical pool, never inferred again from a replacement segment name.
    pub pool: String,
    /// Full physical segment filename identity.
    pub segment: String,
    /// First physical byte of the fragment.
    pub offset: u64,
    /// Positive number of fragment bytes, unchanged by relocation.
    pub size: u64,
    /// Digest of exactly the fragment bytes.
    pub digest: String,
}

/// One decoded record observed under admission exclusion.
pub struct Snapshot {
    /// Logical identity obtained from the same original record.
    pub identity: Identity,
    /// Its current physical location and fragment contents.
    pub location: Location,
    /// Fingerprint of the complete decoded record; decoding and collision resistance are adapter assumptions.
    pub revision: String,
}

/// Known durable transaction disposition; ambiguous spellings cannot authorize publication.
#[derive(Clone, Copy)]
pub enum Phase {
    /// The original compaction intent is published and accepts replacement locations.
    Preparing,
    /// Compaction finished; a stale copy request cannot publish additional replacements.
    Committed,
    /// Recovery aborted the original attempt; repair of published data remains separate.
    Aborted,
}

impl Phase {
    /// Reject unclassified persisted transaction states.
    pub fn decode(value: &str) -> (out: Option<Self>)
        ensures out.is_some() == (value@ == "preparing"@ || value@ == "committed"@ || value@ == "aborted"@),
            out.is_some() ==> (out.unwrap() is Preparing <==> value@ == "preparing"@),
            out.is_some() ==> (out.unwrap() is Committed <==> value@ == "committed"@),
            out.is_some() ==> (out.unwrap() is Aborted <==> value@ == "aborted"@),
    {
        if value == "preparing" { Some(Self::Preparing) }
        else if value == "committed" { Some(Self::Committed) }
        else if value == "aborted" { Some(Self::Aborted) }
        else { None }
    }
}

/// Original compaction journal observed immediately before publication.
pub struct Transaction {
    /// Pool that owns the protected transaction record.
    pub pool: String,
    /// Exact original attempt, also used by the replacement's history entry.
    pub id: String,
    /// Explicit decoded durable state.
    pub phase: Phase,
}

/// Structural identity is independent of incidental storage placement.
pub open spec fn same_identity(a: Identity, b: Identity) -> bool {
    a.name@ == b.name@ && a.path@ == b.path@ && a.tree_hash@ == b.tree_hash@
}

/// Positive bounded physical ranges and nonempty identities are required even for unchanged entries.
pub open spec fn valid_location(l: Location) -> bool {
    l.pool@.len() > 0 && l.segment@.len() > 0 && l.size > 0
        && l.offset + l.size <= u64::MAX && vstd::utf8::encode_utf8(l.digest@).len() == 64
}

/// A terminator has no tree or store path; ordinary objects require both.
pub open spec fn valid_snapshot(s: Snapshot) -> bool {
    s.identity.name@.len() > 0 && valid_location(s.location) && vstd::utf8::encode_utf8(s.revision@).len() == 64
        && if s.identity.name@ == ".tar-eof"@ { s.identity.path@.len() == 0 && s.identity.tree_hash@.len() == 0 }
            else { s.identity.path@.len() > 0 && s.identity.tree_hash@.len() > 0 }
}

/// A new location cannot change the source pool, length or fragment digest.
pub open spec fn same_content(a: Location, b: Location) -> bool {
    a.pool@ == b.pool@ && a.size == b.size && a.digest@ == b.digest@
}

/// Exact location equality retains both content and full physical coordinates.
pub open spec fn same_location(a: Location, b: Location) -> bool {
    same_content(a, b) && a.segment@ == b.segment@ && a.offset == b.offset
}

/// Stale observations cannot publish over another version of the object record.
pub open spec fn same_snapshot(a: Snapshot, b: Snapshot) -> bool {
    same_identity(a.identity, b.identity) && same_location(a.location, b.location) && a.revision@ == b.revision@
}

/// Copy-and-switch never overwrites the original immutable range.
pub open spec fn replacement(source: Location, target: Location) -> bool {
    valid_location(source) && valid_location(target) && same_content(source, target)
        && (source.segment@ != target.segment@ || source.offset + source.size <= target.offset || target.offset + target.size <= source.offset)
}

fn identity_matches(a: &Identity, b: &Identity) -> (out: bool) ensures out == same_identity(*a, *b),
{ a.name == b.name && a.path == b.path && a.tree_hash == b.tree_hash }

fn location_valid(l: &Location) -> (out: bool) ensures out == valid_location(*l),
{
    let digest = l.digest.as_str();
    let digest_bytes = digest.as_bytes();
    !l.pool.is_empty() && !l.segment.is_empty() && l.size > 0 && l.offset <= u64::MAX - l.size && digest_bytes.len() == 64
}

fn snapshot_valid(s: &Snapshot) -> (out: bool) ensures out == valid_snapshot(*s),
{
    let revision = s.revision.as_str();
    let revision_bytes = revision.as_bytes();
    if s.identity.name.is_empty() || !location_valid(&s.location) || revision_bytes.len() != 64 { return false; }
    if s.identity.name.as_str() == ".tar-eof" { s.identity.path.is_empty() && s.identity.tree_hash.is_empty() }
    else { !s.identity.path.is_empty() && !s.identity.tree_hash.is_empty() }
}

fn content_matches(a: &Location, b: &Location) -> (out: bool) ensures out == same_content(*a, *b),
{ a.pool == b.pool && a.size == b.size && a.digest == b.digest }

fn snapshot_matches(a: &Snapshot, b: &Snapshot) -> (out: bool) ensures out == same_snapshot(*a, *b),
{
    identity_matches(&a.identity, &b.identity) && content_matches(&a.location, &b.location)
        && a.location.segment == b.location.segment && a.location.offset == b.location.offset && a.revision == b.revision
}

/// Original source snapshot captured before copying; its target cannot be independently resupplied.
pub struct MovePlan {
    // Full original record binding, including all decoded-record fields through its fingerprint.
    source: Snapshot,
    // Exact compaction transaction that owns the copy.
    transaction: String,
}

impl MovePlan {
    /// Original source retained by this plan.
    pub closed spec fn original(&self) -> Snapshot { self.source }

    /// Original compaction attempt.
    pub closed spec fn attempt(&self) -> Seq<char> { self.transaction@ }

    /// Original source, available to executable adapters and specifications alike.
    pub fn source(&self) -> (out: &Snapshot) ensures *out == self.original(),
    { &self.source }

    /// Capture a valid immutable source and a named compaction attempt before external copying.
    pub fn new(source: Snapshot, transaction: String) -> (out: Option<Self>)
        ensures out.is_some() ==> out.unwrap().original() == source && out.unwrap().attempt() == transaction@,
    {
        if !snapshot_valid(&source) || transaction.is_empty() { return None; }
        Some(Self { source, transaction })
    }

    #[verifier::type_invariant]
    closed spec fn valid(&self) -> bool { valid_snapshot(self.source) && self.transaction@.len() > 0 }

    /// Bind a checked native read to the content-preserving publication request without a target override.
    pub fn copied_extent(self, checked: CheckedExtent) -> (out: Option<PublishRequest>)
        ensures out.is_some() ==> out.unwrap().origin() == self
            && out.unwrap().destination() == checked@.0
            && out.unwrap().destination().offset + out.unwrap().destination().size <= checked@.1.length,
    {
        self.copied(checked.into_location())
    }

    /// Accept only independently observed replacement bytes with the original content in disjoint storage.
    pub fn copied(self, target: Location) -> (out: Option<PublishRequest>)
        ensures out.is_some() ==> out.unwrap().origin() == self && out.unwrap().destination() == target,
    {
        proof { use_type_invariant(&self); }
        if !location_valid(&target) || !content_matches(&self.source.location, &target) { return None; }
        let source = &self.source.location;
        if source.segment == target.segment && source.offset + source.size > target.offset && target.offset + target.size > source.offset {
            return None;
        }
        Some(PublishRequest { plan: self, target })
    }
}

/// Valid replacement awaiting a fresh source and durable transaction check.
///
/// ```compile_fail,E0616
/// use airlock_deployment_core::retention::relocation::{Location, PublishRequest};
/// /// Adapters cannot replace the checked physical target with independently chosen coordinates.
/// fn substitute(request: &mut PublishRequest, target: Location) { request.target = target; }
/// ```
pub struct PublishRequest {
    // Original source and attempt binding; no object-name parameter accompanies publication.
    plan: MovePlan,
    // Content-equivalent, nonoverlapping replacement coordinates.
    target: Location,
}

impl PublishRequest {
    /// Original plan retained by the replacement request.
    pub closed spec fn origin(&self) -> MovePlan { self.plan }

    /// Exact physical replacement.
    pub closed spec fn destination(&self) -> Location { self.target }

    /// Exact original object and record fingerprint for fresh comparison.
    pub fn source(&self) -> (out: &Snapshot) ensures *out == self.origin().original(),
    { &self.plan.source }

    /// Original replacement, used directly to encode the published extent.
    pub fn target(&self) -> (out: &Location) ensures *out == self.destination(),
    { &self.target }

    /// Original attempt; completed or aborted attempts cannot accept late publication.
    pub fn transaction(&self) -> (out: &str) ensures out@ == self.origin().attempt(),
    { self.plan.transaction.as_str() }

    #[verifier::type_invariant]
    closed spec fn valid(&self) -> bool { replacement(self.plan.source.location, self.target) }

    /// Refuse stale source records, another pool/attempt, and non-executing durable transactions.
    pub fn confirm(self, current: &Snapshot, transaction: &Transaction) -> (out: Option<Publication>)
        ensures out.is_some() ==> out.unwrap().checked() == self
            && same_snapshot(self.origin().original(), *current)
            && transaction.pool@ == self.origin().original().location.pool@ && transaction.id@ == self.origin().attempt()
            && transaction.phase is Preparing,
    {
        if !snapshot_matches(&self.plan.source, current) || transaction.pool != self.plan.source.location.pool
            || transaction.id != self.plan.transaction || !matches!(transaction.phase, Phase::Preparing) { return None; }
        Some(Publication { request: self, _current: Ghost(*current), _transaction: Ghost(*transaction) })
    }
}

/// Consumed publication permission retaining fresh source and durable transaction evidence.
pub struct Publication {
    // The same checked replacement accepted before the fresh observations.
    request: PublishRequest,
    // Erased fresh source observation; filesystem truth and admission exclusion remain assumptions.
    _current: Ghost<Snapshot>,
    // Erased durable transaction evidence bound to the original pool and attempt.
    _transaction: Ghost<Transaction>,
}

impl Publication {
    /// Checked original replacement, unchanged by fresh observation validation.
    pub closed spec fn checked(&self) -> PublishRequest { self.request }

    #[verifier::type_invariant]
    closed spec fn valid(&self) -> bool {
        same_snapshot(self.request.plan.source, self._current@)
            && self._transaction@.pool@ == self.request.plan.source.location.pool@
            && self._transaction@.id@ == self.request.plan.transaction@ && self._transaction@.phase is Preparing
    }

    /// Forward the original checked source, replacement and attempt to the private publication adapter.
    pub fn request(&self) -> (out: &PublishRequest) ensures *out == self.checked(),
    { &self.request }
}

/// Checked repair of a convenience mirror from the authoritative canonical fragment record.
pub struct MirrorRequest {
    // Authority always flows from the canonical record, including after an interrupted publication.
    canonical: Snapshot,
    // Exact old mirror fingerprint; repair cannot overwrite a newer or unrelated mirror.
    mirror: Snapshot,
}

impl MirrorRequest {
    /// Exact authoritative canonical record.
    pub closed spec fn authority(&self) -> Snapshot { self.canonical }

    /// Exact original convenience mirror.
    pub closed spec fn previous(&self) -> Snapshot { self.mirror }

    #[verifier::type_invariant]
    closed spec fn valid(&self) -> bool {
        valid_snapshot(self.canonical) && valid_snapshot(self.mirror)
            && same_identity(self.canonical.identity, self.mirror.identity)
            && same_content(self.canonical.location, self.mirror.location)
    }

    /// Repair placement only; an object, tree, store-path or content disagreement refuses repair.
    pub fn new(canonical: Snapshot, mirror: Snapshot) -> (out: Option<Self>)
        ensures out.is_some() ==> out.unwrap().authority() == canonical && out.unwrap().previous() == mirror,
    {
        if !snapshot_valid(&canonical) || !snapshot_valid(&mirror)
            || !identity_matches(&canonical.identity, &mirror.identity) || !content_matches(&canonical.location, &mirror.location) { return None; }
        Some(Self { canonical, mirror })
    }

    /// Canonical source is the only replacement authority for the mirror adapter.
    pub fn canonical(&self) -> (out: &Snapshot) ensures *out == self.authority(),
    { &self.canonical }

    /// Original mirror whose exact decoded record is eligible for repair.
    pub fn mirror(&self) -> (out: &Snapshot) ensures *out == self.previous(),
    { &self.mirror }

    /// Fresh observations must still describe the same canonical record and old mirror.
    fn matches(&self, canonical: &Snapshot, mirror: &Snapshot) -> (out: bool)
        ensures out == (same_snapshot(self.authority(), *canonical) && same_snapshot(self.previous(), *mirror)),
    { snapshot_matches(&self.canonical, canonical) && snapshot_matches(&self.mirror, mirror) }

    /// Require fresh record agreement before constructing the only permission accepted by mirror writes.
    pub fn confirm(self, canonical: &Snapshot, mirror: &Snapshot) -> (out: Option<MirrorPublication>)
        ensures out.is_some() ==> out.unwrap().checked() == self
            && same_snapshot(self.authority(), *canonical) && same_snapshot(self.previous(), *mirror),
    {
        if !self.matches(canonical, mirror) { return None; }
        Some(MirrorPublication { request: self, _canonical: Ghost(*canonical), _mirror: Ghost(*mirror) })
    }
}

/// Consumed mirror-write permission; its checked source and target observations cannot be skipped.
///
/// ```compile_fail,E0616
/// use airlock_deployment_core::retention::relocation::{MirrorPublication, MirrorRequest};
/// /// A confirmed write cannot acquire another repair request without fresh confirmation.
/// fn substitute(publication: &mut MirrorPublication, request: MirrorRequest) { publication.request = request; }
/// ```
pub struct MirrorPublication {
    // Original canonical-to-mirror authority.
    request: MirrorRequest,
    // Erased current canonical observation, authenticated by the external adapter.
    _canonical: Ghost<Snapshot>,
    // Erased current mirror observation, authenticated by the external adapter.
    _mirror: Ghost<Snapshot>,
}

impl MirrorPublication {
    /// Original checked repair, unchanged by fresh-record confirmation.
    pub closed spec fn checked(&self) -> MirrorRequest { self.request }

    #[verifier::type_invariant]
    closed spec fn valid(&self) -> bool {
        same_snapshot(self.request.authority(), self._canonical@) && same_snapshot(self.request.previous(), self._mirror@)
    }

    /// Forward exactly the confirmed canonical source and original mirror to the write adapter.
    pub fn request(&self) -> (out: &MirrorRequest) ensures *out == self.checked(),
    { &self.request }
}

/// One decoded view entry: logical stream position and immutable identity precede physical placement.
pub struct Entry {
    /// Exact object basename from the original map row.
    pub object: String,
    /// Unchanged address in the logical tar stream exposed to the VM.
    pub logical_offset: u64,
    /// Physical source and immutable fragment contents for this row.
    pub location: Location,
}

/// Checked per-entry map replacement; complete map decoding and publication remain adapter duties.
pub struct RefreshRequest {
    // Original full map path, not independently supplied to the entry adapter.
    map: String,
    // Original row, preserving its object and logical address.
    original: Entry,
    // Canonical replacement retains exactly the row's original immutable contents.
    canonical: Snapshot,
}

impl RefreshRequest {
    /// Original map identity.
    pub closed spec fn map_name(&self) -> Seq<char> { self.map@ }

    /// Original logical map entry.
    pub closed spec fn before(&self) -> Entry { self.original }

    /// Checked canonical replacement.
    pub closed spec fn authority(&self) -> Snapshot { self.canonical }

    #[verifier::type_invariant]
    closed spec fn valid(&self) -> bool {
        self.map@.len() > 0 && valid_location(self.original.location) && valid_snapshot(self.canonical)
            && self.original.object@ == self.canonical.identity.name@
            && same_content(self.original.location, self.canonical.location)
            && self.original.logical_offset + self.original.location.size <= u64::MAX
    }

    /// Accept only same-object, same-pool, same-content relocation at the unchanged logical stream address.
    pub fn new(map: String, original: Entry, canonical: Snapshot) -> (out: Option<Self>)
        ensures out.is_some() ==> out.unwrap().map_name() == map@ && out.unwrap().before() == original && out.unwrap().authority() == canonical,
    {
        if map.is_empty() || !location_valid(&original.location) || !snapshot_valid(&canonical)
            || original.object != canonical.identity.name || !content_matches(&original.location, &canonical.location)
            || original.logical_offset > u64::MAX - original.location.size { return None; }
        Some(Self { map, original, canonical })
    }

    /// Preserve the original map identity through entry dispatch.
    pub fn map(&self) -> (out: &str) ensures out@ == self.map_name(),
    { self.map.as_str() }

    /// Replace physical placement while preserving the original object, logical offset, length and digest.
    pub fn apply(self) -> (out: Entry)
        ensures out.object@ == self.before().object@ && out.logical_offset == self.before().logical_offset
            && same_location(out.location, self.authority().location)
            && same_content(out.location, self.before().location),
    {
        proof { use_type_invariant(&self); }
        Entry { object: self.original.object, logical_offset: self.original.logical_offset, location: self.canonical.location }
    }
}

}
