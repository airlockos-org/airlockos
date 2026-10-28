//! First-boot handoff and cache reuse decisions over decoded evidence.
//!
//! Image and startup adapters authenticate manifests, hash snapshots and preserve
//! complete input sets. These checks bind their supplied observations; they do not
//! turn a boot receipt into deployment approval or prove external I/O faithful.

pub mod acceptance;

pub mod artifacts;

pub mod startup;

mod selection;

pub use selection::{Argument, BootField, RootRequest, SelectedGeneration, SetupRequest};

use vstd::prelude::*;

verus! {

/// Exact immutable artifacts and guest-facing layout selected for one boot VM.
pub struct Selection {
    /// VM whose generation is being selected.
    pub domain: String,
    /// Positive generation in that VM's namespace.
    pub generation: u64,
    /// Whole guest system store object.
    pub system: String,
    /// Guest root artifact within its store object.
    pub root: String,
    /// Descriptor artifact used to adopt the prepared software view.
    pub source: String,
    /// Kernel bundle selected by the topology.
    pub kernel: String,
    /// Storage sharing protocol.
    pub mode: String,
    /// Metadata block device exposed to the guest.
    pub device: String,
    /// External-data block device exposed to the guest.
    pub blob_device: String,
    /// Guest path at which the software view is mounted.
    pub mountpoint: String,
    /// Immutable-view implementation.
    pub backend: String,
}

/// Equality of selection meanings, independently of their wire encodings.
pub open spec fn same(a: Selection, b: Selection) -> bool {
    a.domain@ == b.domain@ && a.generation == b.generation
        && a.system@ == b.system@ && a.root@ == b.root@ && a.source@ == b.source@
        && a.kernel@ == b.kernel@ && a.mode@ == b.mode@ && a.device@ == b.device@
        && a.blob_device@ == b.blob_device@ && a.mountpoint@ == b.mountpoint@
        && a.backend@ == b.backend@
}

pub(crate) fn matching(a: &Selection, b: &Selection) -> (yes: bool)
    ensures yes == same(*a, *b),
{
    a.domain == b.domain && a.generation == b.generation
        && a.system == b.system && a.root == b.root && a.source == b.source
        && a.kernel == b.kernel && a.mode == b.mode && a.device == b.device
        && a.blob_device == b.blob_device && a.mountpoint == b.mountpoint
        && a.backend == b.backend
}

/// Complete ordered handoff: every requested VM has its exact observed selection.
pub open spec fn consistent(expected: Seq<Selection>, observed: Seq<Selection>) -> bool {
    expected.len() == observed.len()
        && forall|i: int| 0 <= i < expected.len() ==>
            expected[i].generation > 0 && same(#[trigger] expected[i], observed[i])
}

/// Checked immutable boot selections; this is compatibility evidence, not authority.
pub struct Handoff {
    // Exact selection set retained after comparing all observations.
    selections: Vec<Selection>,
}

impl View for Handoff {
    type V = Seq<Selection>;

    closed spec fn view(&self) -> Self::V { self.selections@ }
}

impl Handoff {
    /// Reject incomplete, substituted, reordered or zero-generation evidence.
    pub fn check(expected: Vec<Selection>, observed: &[Selection]) -> (out: Option<Self>)
        ensures out.is_some() == consistent(expected@, observed@),
            out.is_some() ==> out.unwrap()@ == expected@,
    {
        if expected.len() != observed.len() { return None; }
        let mut i = 0;
        while i < expected.len()
            invariant 0 <= i <= expected.len(), expected.len() == observed.len(),
                forall|j: int| 0 <= j < i ==> expected[j].generation > 0
                    && same(#[trigger] expected[j], observed[j]),
            decreases expected.len() - i,
        {
            if expected[i].generation == 0 || !matching(&expected[i], &observed[i]) { return None; }
            i += 1;
        }
        Some(Self { selections: expected })
    }

    /// Keep the checked-selection record mandatory in the setup process invocation.
    /// File contents and their binding to these paths are authenticated by the adapters.
    pub fn setup_arguments(&self, topology: &str, record: &str, digest: &str) -> (out: Vec<String>)
        ensures out.len() == 6 && out[0]@ == "--topology"@ && out[1]@ == topology@
            && out[2]@ == "--boot-selection"@ && out[3]@ == record@
            && out[4]@ == "--boot-selection-hash"@ && out[5]@ == digest@,
    {
        vec!["--topology".to_string(), topology.to_string(),
            "--boot-selection".to_string(), record.to_string(),
            "--boot-selection-hash".to_string(), digest.to_string()]
    }

    /// Borrow only selections that survived the complete comparison.
    pub fn selections(&self) -> (out: &[Selection])
        ensures out@ == self@,
    { &self.selections }
}

/// One observed configuration fingerprint, already tied to its VM by the adapter.
pub struct DomainState {
    /// VM identity; order and membership must match the requested boot scope.
    pub domain: String,
    /// Fingerprint of saved configuration and observed immutable artifacts.
    pub fingerprint: String,
}

/// A VM's complete observed configuration is unchanged.
pub open spec fn same_state(fresh: DomainState, saved: DomainState) -> bool {
    fresh.domain@ == saved.domain@ && fresh.fingerprint@.len() > 0
        && fresh.fingerprint@ == saved.fingerprint@
}

fn state_matches(fresh: &DomainState, saved: &DomainState) -> (yes: bool)
    ensures yes == same_state(*fresh, *saved),
{
    fresh.domain == saved.domain && !fresh.fingerprint.is_empty()
        && fresh.fingerprint == saved.fingerprint
}

/// Exact snapshot equality required to reuse completed configuration work.
pub open spec fn unchanged(fresh: Seq<DomainState>, saved: Seq<DomainState>) -> bool {
    fresh.len() == saved.len() && forall|i: int| 0 <= i < fresh.len() ==>
        same_state(#[trigger] fresh[i], saved[i])
}

/// Opaque decision to reuse configuration; live VM readiness must still be checked.
pub struct Reuse {
    // Input identity for which the supplied fresh and saved snapshots agree.
    identity: String,
}

impl View for Reuse {
    type V = Seq<char>;

    closed spec fn view(&self) -> Self::V { self.identity@ }
}

impl Reuse {
    /// Identify the selected inputs for which configuration reuse was checked.
    pub fn identity(&self) -> (out: &str)
        ensures out@ == self@,
    { self.identity.as_str() }

    /// A stale receipt or different observed configuration cannot skip setup.
    pub fn check(identity: String, saved_identity: &str, shared: &str, saved_shared: &str,
        fresh: &[DomainState], saved: &[DomainState]) -> (out: Option<Self>)
        ensures out.is_some() == (identity@.len() > 0 && identity@ == saved_identity@
            && shared@.len() > 0 && shared@ == saved_shared@ && unchanged(fresh@, saved@)),
            out.is_some() ==> out.unwrap()@ == identity@,
    {
        if identity.is_empty() || identity.as_str() != saved_identity
            || shared.is_empty() || shared != saved_shared || fresh.len() != saved.len() { return None; }
        let mut i = 0;
        while i < fresh.len()
            invariant 0 <= i <= fresh.len(), fresh.len() == saved.len(),
                forall|j: int| 0 <= j < i ==> same_state(#[trigger] fresh[j], saved[j]),
            decreases fresh.len() - i,
        {
            if !state_matches(&fresh[i], &saved[i]) { return None; }
            i += 1;
        }
        Some(Self { identity })
    }
}

}
