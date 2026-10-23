//! Private storage is ready only when the private device backs the exact writable mount roots.
//! These are checks on a single decoded kernel observation, not a promise of continuing health.
//! Mountinfo decoding, block-device identification, directory resolution and external mount/helper
//! execution remain adapters. No saved receipt can replace a fresh observation.

use vstd::prelude::*;

verus! {

/// Kernel identity of the private block device, independent of its mount-source spelling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Device {
    /// Kernel block-device major number.
    pub major: u32,
    /// Kernel block-device minor number.
    pub minor: u32,
}

/// One decoded row from this process's mount namespace; duplicate targets are retained.
#[derive(Clone)]
pub struct Mount {
    /// Actual filesystem device reported by the kernel.
    pub device: Device,
    /// Absolute root of this mount within its filesystem, including bind-mount subdirectories.
    pub root: String,
    /// Absolute mountpoint in the current namespace.
    pub target: String,
    /// Kernel filesystem type, rather than the mount command's requested type.
    pub filesystem: String,
    /// Both the mount and its filesystem superblock permit writes.
    pub writable: bool,
    /// The mount disables set-user-ID execution.
    pub nosuid: bool,
    /// The mount disables device-node interpretation.
    pub nodev: bool,
}

/// Expected persistent mount, with a fixed destination and filesystem root.
#[derive(Clone, Copy)]
pub enum Location {
    /// Entire private filesystem at /rw.
    Private,
    /// Private /home directory bound at /home.
    Home,
    /// Private /usrlocal directory bound at /usr/local.
    Local,
}

/// Expected mountpoint, independent of the mount-table traversal.
pub open spec fn target(location: Location) -> Seq<char> {
    match location { Location::Private => "/rw"@, Location::Home => "/home"@, Location::Local => "/usr/local"@ }
}

/// Expected root within the private filesystem.
pub open spec fn root(location: Location) -> Seq<char> {
    match location { Location::Private => "/"@, Location::Home => "/home"@, Location::Local => "/usrlocal"@ }
}

/// Exact kernel device equality; names and labels cannot substitute another disk.
pub open spec fn same(a: Device, b: Device) -> bool { a.major == b.major && a.minor == b.minor }

fn device_eq(a: Device, b: Device) -> (yes: bool)
    ensures yes == same(a, b),
{ a.major == b.major && a.minor == b.minor }

/// Identity, filesystem root and write/security flags required for one persistent anchor.
pub open spec fn correct(mount: Mount, device: Device, location: Location) -> bool {
    device.major > 0 && same(mount.device, device) && mount.target@ == target(location)
        && mount.root@ == root(location) && mount.filesystem@ == "ext4"@
        && mount.writable && mount.nosuid && mount.nodev
}

/// Exactly one row denotes this mountpoint. Stacked mounts are ambiguous, even if one matches.
pub open spec fn unique(table: Seq<Mount>, location: Location, index: int) -> bool {
    0 <= index < table.len() && table[index].target@ == target(location)
        && forall|i: int| 0 <= i < table.len() && #[trigger] table[i].target@ == target(location) ==> i == index
}

/// The observation contains exactly one correct mount at the required persistent anchor.
pub open spec fn present(table: Seq<Mount>, device: Device, location: Location) -> bool {
    exists|i: int| unique(table, location, i) && correct(table[i], device, location)
}

/// Complete readiness covers each distinct persistent root in the same observation.
pub open spec fn ready(table: Seq<Mount>, device: Device) -> bool {
    present(table, device, Location::Private) && present(table, device, Location::Home)
        && present(table, device, Location::Local)
}

fn at(mount: &Mount, location: Location) -> (yes: bool)
    ensures yes == (mount.target@ == target(location)),
{
    match location {
        Location::Private => mount.target.as_str() == "/rw",
        Location::Home => mount.target.as_str() == "/home",
        Location::Local => mount.target.as_str() == "/usr/local",
    }
}

fn matching(mount: &Mount, device: Device, location: Location) -> (yes: bool)
    ensures yes == correct(*mount, device, location),
{
    let correct_root = match location {
        Location::Private => mount.root.as_str() == "/",
        Location::Home => mount.root.as_str() == "/home",
        Location::Local => mount.root.as_str() == "/usrlocal",
    };
    device.major > 0 && device_eq(mount.device, device) && at(mount, location)
        && correct_root && mount.filesystem.as_str() == "ext4" && mount.writable && mount.nosuid && mount.nodev
}

fn find(table: &[Mount], device: Device, location: Location) -> (out: Option<usize>)
    ensures out.is_some() == present(table@, device, location),
        out.is_some() ==> unique(table@, location, out.unwrap() as int)
            && correct(table[out.unwrap() as int], device, location),
{
    let mut found: Option<usize> = None;
    let mut i = 0;
    while i < table.len()
        invariant i <= table.len(),
            match found {
                Some(k) => k < i && table[k as int].target@ == target(location)
                    && forall|j: int| 0 <= j < i && #[trigger] table[j].target@ == target(location) ==> j == k,
                None => forall|j: int| 0 <= j < i ==> #[trigger] table[j].target@ != target(location),
            },
        decreases table.len() - i,
    {
        if at(&table[i], location) {
            if let Some(_previous) = found {
                assert forall|k: int| unique(table@, location, k) implies false by {
                    assert(k == _previous);
                    assert(k == i);
                }
                return None;
            }
            found = Some(i);
        }
        i += 1;
    }
    match found {
        Some(k) => {
            assert(unique(table@, location, k as int));
            if !matching(&table[k], device, location) {
                assert forall|j: int| unique(table@, location, j) implies !correct(table[j], device, location) by {
                    assert(j == k);
                }
                return None;
            }
            assert(present(table@, device, location));
            Some(k)
        },
        None => {
            assert forall|j: int| unique(table@, location, j) implies false by {
                assert(table[j].target@ != target(location));
            }
            None
        },
    }
}

/// Check an existing destination before permitting any writes through that mountpoint.
pub fn check_mount(device: Device, table: &[Mount], location: Location) -> (yes: bool)
    ensures yes == present(table@, device, location),
{ find(table, device, location).is_some() }

/// Whether upstream private-device initialization can run before the first mount.
/// A filesystem already mounted in the supplied namespace must not reach the initialization helper.
pub open spec fn unmounted(table: Seq<Mount>, device: Device) -> bool {
    device.major > 0 && forall|i: int| 0 <= i < table.len() ==>
        unused(#[trigger] table[i], device)
}

/// This row neither uses the private device nor occupies a persistent mount destination.
pub open spec fn unused(mount: Mount, device: Device) -> bool {
    !same(mount.device, device) && mount.target@ != "/rw"@
        && mount.target@ != "/home"@ && mount.target@ != "/usr/local"@
}

/// Refuse initialization when the private device is already mounted or a destination is occupied.
pub fn may_initialize(device: Device, table: &[Mount]) -> (yes: bool)
    ensures yes == unmounted(table@, device),
{
    if device.major == 0 { return false; }
    let mut i = 0;
    while i < table.len()
        invariant i <= table.len(), device.major > 0,
            forall|j: int| 0 <= j < i ==> unused(#[trigger] table[j], device),
        decreases table.len() - i,
    {
        if device_eq(table[i].device, device) || at(&table[i], Location::Private)
            || at(&table[i], Location::Home) || at(&table[i], Location::Local) { return false; }
        assert(unused(table[i as int], device));
        i += 1;
    }
    true
}

/// Checked /rw observation required before initializing directories inside the private filesystem.
pub struct PrivateMount {
    // Original private block-device identity.
    device: Device,
    // Complete decoded mount observation, including conflicting rows.
    table: Vec<Mount>,
}

impl View for PrivateMount {
    type V = (Device, Seq<Mount>);

    closed spec fn view(&self) -> Self::V { (self.device, self.table@) }
}

impl PrivateMount {
    #[verifier::type_invariant]
    closed spec fn valid(&self) -> bool { present(self.table@, self.device, Location::Private) }

    /// Reject wrong devices, roots, filesystems, flags and ambiguous private mountpoints.
    pub fn check(device: Device, table: Vec<Mount>) -> (out: Option<Self>)
        ensures out.is_some() == present(table@, device, Location::Private),
            out.is_some() ==> out.unwrap()@ == (device, table@),
    {
        find(&table, device, Location::Private)?;
        Some(Self { device, table })
    }

    /// Require both exact persistent bind mounts in the same kernel observation as /rw.
    pub fn ready(self) -> (out: Option<ReadyStorage>)
        ensures out.is_some() == ready(self@.1, self@.0),
            out.is_some() ==> out.unwrap()@ == self@,
    {
        proof { use_type_invariant(&self); }
        find(&self.table, self.device, Location::Home)?;
        find(&self.table, self.device, Location::Local)?;
        Some(ReadyStorage { device: self.device, _table: self.table })
    }
}

/// Successful check of all private mount anchors; no public constructor or stale-record loader.
///
/// ```compile_fail
/// use airlock_machine_planning::private_storage::{Device, ReadyStorage};
/// let ready = ReadyStorage { device: Device { major: 202, minor: 16 }, _table: Vec::new() };
/// ```
pub struct ReadyStorage {
    // Private block device observed by the adapter for this check.
    device: Device,
    // Single complete mount observation that passed every readiness condition.
    _table: Vec<Mount>,
}

impl View for ReadyStorage {
    type V = (Device, Seq<Mount>);

    closed spec fn view(&self) -> Self::V { (self.device, self._table@) }
}

impl ReadyStorage {
    #[verifier::type_invariant]
    closed spec fn valid(&self) -> bool { ready(self._table@, self.device) }

    /// Return the checked block-device identity without granting authority to remount it.
    pub fn device(&self) -> (out: Device)
        ensures out == self@.0, ready(self@.1, out),
    {
        proof { use_type_invariant(self); }
        self.device
    }
}

}
