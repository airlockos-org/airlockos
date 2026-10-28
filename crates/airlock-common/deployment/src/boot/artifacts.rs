//! Derive guest boot contracts and check the complete set against packaged host files.
//! Decoding the complete topology and observing the actual store remain adapter duties.

use vstd::prelude::*;

verus! {

/// Complete boot declaration for one guest, projected by an exhaustive backend match.
pub enum Guest {
    /// Linux keeps writable disks and a shared immutable guest store.
    Nixos {
        /// Guest whose disks and kernel are required.
        name: String,
        /// Immutable guest operating system.
        system: String,
        /// Original root disk seed.
        root: String,
        /// Shared guest closure or prepared descriptor.
        store: String,
        /// Qubes kernel bundle name.
        kernel: String,
        /// Host-side kernel object when the topology supplies its source.
        kernel_source: Option<String>,
    },
    /// Hermit loads its executable from dom0 and has no guest disks.
    Hermit {
        /// Diskless guest whose executable must be retained.
        name: String,
        /// Store object containing the authenticated executable.
        system: String,
        /// Exact executable beneath that object.
        executable: String,
    },
}

/// Persistent or shared disk required by a Linux guest.
#[derive(Clone, Copy)]
pub enum Volume {
    /// Writable operating-system disk.
    Root,
    /// Persistent private guest data.
    Private,
    /// Immutable store metadata view.
    Store,
    /// Immutable store data view.
    StoreData,
}

impl Volume {
    /// Return the fixed upstream Qubes volume name.
    pub fn name(&self) -> (out: &str)
        ensures out@ == match self { Self::Root => "root"@, Self::Private => "private"@,
            Self::Store => "store"@, Self::StoreData => "store-data"@ },
    {
        match self { Self::Root => "root", Self::Private => "private",
            Self::Store => "store", Self::StoreData => "store-data" }
    }
}

/// The host object required by a declaration; Linux payloads belong in the guest pool.
pub open spec fn host_root(guest: Guest) -> Option<Seq<char>> {
    match guest {
        Guest::Nixos { kernel_source: Some(source), .. } => Some(source@),
        Guest::Nixos { kernel_source: None, .. } => None,
        Guest::Hermit { system, .. } => Some(system@),
    }
}

/// An observed packaged inventory contains this exact store object.
pub open spec fn contains(paths: Seq<String>, path: Seq<char>) -> bool {
    exists|i: int| 0 <= i < paths.len() && #[trigger] paths[i]@ == path
}

/// Every guest's required host object occurs in the packaged inventory.
pub open spec fn complete(guests: Seq<Guest>, paths: Seq<String>) -> bool {
    forall|i: int| 0 <= i < guests.len() ==> match host_root(#[trigger] guests[i]) {
        Some(root) => contains(paths, root), None => true,
    }
}

/// Whole guest set retained unchanged, preventing later checks from selecting a smaller scope.
pub struct Requirements {
    // All guests in the topology's canonical order, including diskless guests.
    guests: Vec<Guest>,
}

impl View for Requirements {
    type V = Seq<Guest>;

    closed spec fn view(&self) -> Self::V { self.guests@ }
}

impl Requirements {
    /// Retain every supplied declaration; derivation neither filters nor changes a backend.
    pub fn derive(guests: Vec<Guest>) -> (out: Self)
        ensures out@ == guests@,
    { Self { guests } }

    /// Borrow all declarations rather than accepting a caller-selected requirement list.
    pub fn guests(&self) -> (out: &[Guest])
        ensures out@ == self@,
    { &self.guests }
}

impl Guest {
    /// Identify the guest without erasing its backend contract.
    pub fn name(&self) -> (out: &str)
        ensures out@ == match self { Self::Nixos { name, .. } | Self::Hermit { name, .. } => name@ },
    { match self { Self::Nixos { name, .. } | Self::Hermit { name, .. } => name.as_str() } }

    /// Select the host requirement for either backend without a string-based backend filter.
    pub fn host_root(&self) -> (out: Option<&str>)
        ensures match out { Some(path) => host_root(*self) == Some(path@), None => host_root(*self).is_none() },
    {
        match self {
            Self::Nixos { kernel_source: Some(source), .. } => Some(source.as_str()),
            Self::Nixos { kernel_source: None, .. } => None,
            Self::Hermit { system, .. } => Some(system.as_str()),
        }
    }

    /// Derive the complete disk layout; Hermit deliberately requires no Linux volumes.
    pub fn volumes(&self) -> (out: Vec<Volume>)
        ensures match self { Self::Hermit { .. } => out.len() == 0,
            Self::Nixos { .. } => out.len() == 4 && out[0] is Root && out[1] is Private
                && out[2] is Store && out[3] is StoreData },
    {
        match self { Self::Nixos { .. } => vec![Volume::Root, Volume::Private, Volume::Store, Volume::StoreData],
            Self::Hermit { .. } => vec![] }
    }
}

/// Search the observed inventory without accepting a caller-supplied completeness claim.
fn present(paths: &[String], path: &str) -> (out: bool)
    ensures out == contains(paths@, path@),
{
    let mut i = 0;
    while i < paths.len()
        invariant 0 <= i <= paths.len(), forall|j: int| 0 <= j < i ==> #[trigger] paths[j]@ != path@,
        decreases paths.len() - i,
    {
        if paths[i].as_str() == path { return true; }
        i += 1;
    }
    false
}

/// Check this guest's derived host requirement without changing its backend contract.
fn retained(guest: &Guest, paths: &[String]) -> (out: bool)
    ensures out == match host_root(*guest) { Some(root) => contains(paths@, root), None => true },
{
    match guest.host_root() { Some(root) => present(paths, root), None => true }
}

/// Selected boot policy; recovery cannot stand in for the normal boot profile.
#[derive(Clone, Copy)]
pub enum Profile {
    /// Normal physical or lab startup with its declared guest services.
    Normal,
    /// Independent text recovery.
    Recovery,
}

/// Exact inputs observed when checking a seed; string/digest encoding is an adapter duty.
pub struct Identity {
    /// Normal or independent recovery selection.
    pub profile: Profile,
    /// Digest of the complete selected topology.
    pub topology: String,
    /// Canonical immutable seed coordinate.
    pub seed: String,
    /// Exact selected host system.
    pub host: String,
    /// Digest binding the seed's integrity inventory and retained host records.
    pub manifest: String,
}

/// All coordinates must be supplied before evidence can authorize assembly.
pub open spec fn valid(identity: Identity) -> bool {
    identity.topology@.len() > 0 && identity.seed@.len() > 0
        && identity.host@.len() > 0 && identity.manifest@.len() > 0
}

/// No coordinate, including the boot profile, can be exchanged after checking.
pub open spec fn same(a: Identity, b: Identity) -> bool {
    a.profile == b.profile && a.topology@ == b.topology@ && a.seed@ == b.seed@
        && a.host@ == b.host@ && a.manifest@ == b.manifest@
}

/// Opaque completeness evidence bound to one seed and selected topology.
///
/// ```compile_fail
/// use airlock_deployment_core::boot::artifacts::{CheckedImage, Identity, Requirements};
/// /// Constructing evidence directly would bypass completeness verification.
/// fn bypass(identity: Identity, requirements: Requirements) -> CheckedImage {
///     CheckedImage { identity, requirements }
/// }
/// ```
pub struct CheckedImage {
    // Exact immutable coordinates whose inventory passed the complete-set check.
    identity: Identity,
    // Complete original declarations, retained with the successful check.
    requirements: Requirements,
}

impl View for CheckedImage {
    type V = (Identity, Seq<Guest>);

    closed spec fn view(&self) -> Self::V { (self.identity, self.requirements@) }
}

impl Requirements {
    /// Reject any missing guest artifact and retain every original declaration with the binding.
    pub fn check(self, identity: Identity, paths: &[String]) -> (out: Option<CheckedImage>)
        ensures out.is_some() == (valid(identity) && complete(self@, paths@)),
            out.is_some() ==> out.unwrap()@ == (identity, self@),
    {
        if identity.topology.is_empty() || identity.seed.is_empty() || identity.host.is_empty()
            || identity.manifest.is_empty() { return None; }
        let mut i = 0;
        while i < self.guests.len()
            invariant 0 <= i <= self.guests.len(),
                forall|j: int| 0 <= j < i ==> match host_root(#[trigger] self.guests@[j]) {
                    Some(root) => contains(paths@, root), None => true,
                },
            decreases self.guests.len() - i,
        {
            if !retained(&self.guests[i], paths) { return None; }
            i += 1;
        }
        Some(CheckedImage { identity, requirements: self })
    }
}

impl CheckedImage {
    /// Borrow every guest declaration retained by the completeness check.
    pub fn requirements(&self) -> (out: &Requirements)
        ensures out@ == self@.1,
    { &self.requirements }

    /// Borrow the exact checked coordinates for the assembly adapter.
    pub fn identity(&self) -> (out: &Identity)
        ensures *out == self@.0,
    { &self.identity }

    /// Refuse evidence reuse with a different seed, topology, profile or host generation.
    pub fn matches(&self, wanted: &Identity) -> (out: bool)
        ensures out == same(self@.0, *wanted),
    {
        let profile = matches!((&self.identity.profile, &wanted.profile),
            (Profile::Normal, Profile::Normal) | (Profile::Recovery, Profile::Recovery));
        profile && self.identity.topology == wanted.topology && self.identity.seed == wanted.seed
            && self.identity.host == wanted.host && self.identity.manifest == wanted.manifest
    }
}

}
