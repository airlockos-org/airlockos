//! Match authenticated prepared storage to the caller's complete requested identity.
//! File decoding, checksums and closure hashing are adapter responsibilities. A successful
//! match selects only the manifest's original namespace and positive generation; it grants
//! neither deployment approval nor permission to modify writable guest storage.

use vstd::prelude::*;

verus! {

/// Boot identity shared by a prepared descriptor and its authenticated manifest.
pub struct Boot {
    /// Installed pool path, independent of a physical image-build location.
    pub pool: String,
    /// Storage namespace, not the consuming VM's Qubes name.
    pub namespace: String,
    /// Requested guest system.
    pub system: String,
    /// Immutable boot disk source.
    pub root: String,
    /// Paired Qubes kernel name.
    pub kernel: String,
    /// Closure hash computed from the requested paths and boot sources.
    pub closure: String,
}

/// Frontend layout and provenance retained by the committed generation.
pub struct Layout {
    /// Original closure source rather than its resolved physical directory.
    pub source: String,
    /// Metadata frontend presented to the guest.
    pub device: String,
    /// External-data frontend presented to the guest.
    pub blob_device: String,
    /// Guest software-store mountpoint.
    pub mountpoint: String,
    /// Immutable view implementation.
    pub backend: String,
}

/// Descriptor evidence, authenticated by the storage adapter before selection.
pub struct Descriptor {
    /// Complete boot binding, including the installed pool.
    pub boot: Boot,
    /// Generation addressed by the descriptor's checksummed manifest.
    pub number: u64,
}

/// Committed manifest evidence for the same addressed generation.
pub struct Manifest {
    /// Manifest boot identity.
    pub boot: Boot,
    /// Manifest source and frontend identities.
    pub layout: Layout,
    /// Independently loaded manifest generation.
    pub number: u64,
}

/// Exact request, before any prepared descriptor is read.
pub struct Expected {
    /// Required boot identity and freshly calculated closure hash.
    pub boot: Boot,
    /// Required provenance and frontend layout.
    pub layout: Layout,
    /// An explicit pin cannot be replaced by another matching boot generation.
    pub number: Option<u64>,
}

/// Equality of boot identities, independent of the matching implementation.
pub open spec fn same_boot(a: Boot, b: Boot) -> bool {
    a.pool@ == b.pool@ && a.namespace@ == b.namespace@ && a.system@ == b.system@
        && a.root@ == b.root@ && a.kernel@ == b.kernel@ && a.closure@ == b.closure@
}

/// Equality of source and guest-visible frontend identities.
pub open spec fn same_layout(a: Layout, b: Layout) -> bool {
    a.source@ == b.source@ && a.device@ == b.device@ && a.blob_device@ == b.blob_device@
        && a.mountpoint@ == b.mountpoint@ && a.backend@ == b.backend@
}

/// Both durable records must identify the exact requested software and layout.
pub open spec fn compatible(e: Expected, d: Descriptor, m: Manifest) -> bool {
    same_boot(e.boot, d.boot) && same_boot(e.boot, m.boot)
        && same_layout(e.layout, m.layout) && m.number > 0 && d.number == m.number
        && (e.number.is_some() ==> e.number.unwrap() == m.number)
}

fn boot_equal(a: &Boot, b: &Boot) -> (yes: bool)
    ensures yes == same_boot(*a, *b),
{
    a.pool == b.pool && a.namespace == b.namespace && a.system == b.system
        && a.root == b.root && a.kernel == b.kernel && a.closure == b.closure
}

fn layout_equal(a: &Layout, b: &Layout) -> (yes: bool)
    ensures yes == same_layout(*a, *b),
{
    a.source == b.source && a.device == b.device && a.blob_device == b.blob_device
        && a.mountpoint == b.mountpoint && a.backend == b.backend
}

/// A checked selection retains its original manifest; callers cannot replace its coordinates.
///
/// ```compile_fail
/// use airlock_deployment_core::attachment::prepared::{CheckedGeneration, Manifest};
/// fn forge(manifest: Manifest) -> CheckedGeneration {
///     CheckedGeneration { manifest }
/// }
/// ```
pub struct CheckedGeneration {
    /// Manifest selected by the complete identity check.
    manifest: Manifest,
}

impl View for CheckedGeneration {
    type V = Manifest;

    closed spec fn view(&self) -> Self::V { self.manifest }
}

impl CheckedGeneration {
    #[verifier::type_invariant]
    closed spec fn positive(&self) -> bool { self.manifest.number > 0 }

    /// Accept exactly matching, positive and correctly pinned generation evidence.
    pub fn check(expected: &Expected, descriptor: &Descriptor, manifest: Manifest) -> (out: Option<Self>)
        ensures out.is_some() == compatible(*expected, *descriptor, manifest),
            out.is_some() ==> out.unwrap()@ == manifest,
    {
        if manifest.number == 0 || descriptor.number != manifest.number
            || !boot_equal(&expected.boot, &descriptor.boot)
            || !boot_equal(&expected.boot, &manifest.boot)
            || !layout_equal(&expected.layout, &manifest.layout) {
            return None;
        }
        let different_pin = match expected.number {
            Some(number) => number != manifest.number,
            None => false,
        };
        if different_pin { return None; }
        Some(Self { manifest })
    }

    /// Load from the exact namespace checked against the caller and both records.
    pub fn namespace(&self) -> (out: &str)
        ensures out@ == self@.boot.namespace@,
    { &self.manifest.boot.namespace }

    /// Load only the original checked generation, without a separately supplied number.
    pub fn number(&self) -> (out: u64)
        ensures out == self@.number, out > 0,
    {
        proof { use_type_invariant(self); }
        self.manifest.number
    }
}

}
