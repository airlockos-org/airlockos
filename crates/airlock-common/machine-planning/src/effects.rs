//! Project complete deployment impact without granting execution authority.
//! Names describe VM scope; host configuration is bound by the approved source,
//! with a separate permission for required or unknown reboot requirements.

use vstd::prelude::*;

verus! {

/// Classified effects decoded from one complete deployment plan.
/// Metadata (source identity and retained-but-untouched VMs) grants no effect.
pub struct PlanEffects<'a> {
    /// Explicit VM reconciliation targets, distinct from detected configuration differences.
    pub configure: Vec<&'a str>,
    /// VM configuration differences, including software, services and properties.
    pub changed: Vec<&'a str>,
    /// VM system generations prepared for activation.
    pub stage: Vec<&'a str>,
    /// Explicit shutdown targets, including dependency-induced stops.
    pub stop: Vec<&'a str>,
    /// Explicit startup targets, including dependency-induced starts.
    pub start: Vec<&'a str>,
    /// Additional dependency-expanded configuration or runtime impact.
    pub affected: Vec<&'a str>,
    /// VMs retired while retaining their data.
    pub retire: Vec<&'a str>,
    /// Retired VMs restored to the active machine.
    pub restore: Vec<&'a str>,
    /// Private-volume source VMs.
    pub copy_sources: Vec<&'a str>,
    /// Private-volume destination VMs.
    pub copy_targets: Vec<&'a str>,
    /// GUI providers whose restart interrupts client connections.
    pub gui_providers: Vec<&'a str>,
    /// Clients affected by GUI-preservation operations.
    pub gui_clients: Vec<&'a str>,
    /// Previous owners of transferred PCI devices.
    pub pci_sources: Vec<&'a str>,
    /// New owners of transferred PCI devices.
    pub pci_targets: Vec<&'a str>,
    /// Firewalls whose reviewed startup settings change.
    pub firewall_parameters: Vec<&'a str>,
    /// Unclassified wire fields; even exempt operations must reject these.
    pub unknown: Vec<&'a str>,
    /// Only an explicit false establishes that host reboot permission is unnecessary.
    pub reboot: Option<bool>,
}

/// Name membership compares contents and ignores ordering and duplicate occurrences.
pub open spec fn member(names: Seq<&str>, name: Seq<char>) -> bool {
    exists|i: int| 0 <= i < names.len() && #[trigger] names[i]@ == name
}

/// Independent VM-impact relation: each source field supplies its own reason.
pub open spec fn affects(p: &PlanEffects, name: Seq<char>) -> bool {
    member(p.configure@, name) || member(p.changed@, name)
        || member(p.stage@, name)
        || member(p.stop@, name)
        || member(p.start@, name)
        || member(p.affected@, name)
        || member(p.retire@, name)
        || member(p.restore@, name)
        || member(p.copy_sources@, name)
        || member(p.copy_targets@, name)
        || member(p.gui_providers@, name)
        || member(p.gui_clients@, name)
        || member(p.pci_sources@, name)
        || member(p.pci_targets@, name)
        || member(p.firewall_parameters@, name)
}

/// Required and unestablished reboot outcomes both consume reboot permission.
pub open spec fn may_reboot(p: &PlanEffects) -> bool {
    p.reboot != Some(false)
}

/// Concatenation implements set union even when either list contains duplicates.
proof fn union(a: Seq<&str>, b: Seq<&str>)
    ensures forall|name: Seq<char>| #[trigger] member(a + b, name)
        == (member(a, name) || member(b, name)),
{
    assert forall|name: Seq<char>| #[trigger] member(a + b, name)
        == (member(a, name) || member(b, name)) by {
        if member(a + b, name) {
            let i = choose|i: int| 0 <= i < (a + b).len()
                && #[trigger] (a + b)[i]@ == name;
            if i < a.len() { assert(a[i]@ == name); }
            else { assert(b[i - a.len()]@ == name); }
        } else if member(a, name) {
            let i = choose|i: int| 0 <= i < a.len() && #[trigger] a[i]@ == name;
            assert((a + b)[i]@ == name);
        } else if member(b, name) {
            let i = choose|i: int| 0 <= i < b.len() && #[trigger] b[i]@ == name;
            assert((a + b)[a.len() + i]@ == name);
        }
    }
}

/// Append one classified field, preserving contents and multiplicity exactly.
fn append<'a>(out: &mut Vec<&'a str>, names: &[&'a str])
    ensures final(out)@ == old(out)@ + names@,
        forall|name: Seq<char>| #[trigger] member(final(out)@, name)
            == (member(old(out)@, name) || member(names@, name)),
{
    let mut i = 0;
    while i < names.len()
        invariant
            0 <= i <= names.len(),
            out@ == old(out)@ + names@.take(i as int),
        decreases names.len() - i,
    {
        out.push(names[i]);
        i += 1;
    }
    proof {
        assert(out@ == old(out)@ + names@);
        union(old(out)@, names@);
        assert forall|name: Seq<char>| #[trigger] member(out@, name)
            == (member(old(out)@, name) || member(names@, name)) by {
            assert(member(old(out)@ + names@, name)
                == (member(old(out)@, name) || member(names@, name)));
        }
    }
}

impl<'a> PlanEffects<'a> {
    /// Return exactly the classified VM impact, refusing unclassified extensions.
    /// The relation above, rather than an assumed caller-provided effect list,
    /// specifies both completeness and absence of invented VM authority.
    pub fn project(&self) -> (result: Option<Vec<&'a str>>)
        ensures
            result.is_some() == (self.unknown.len() == 0),
            result.is_some() ==> forall|name: Seq<char>|
                #[trigger] member(result.unwrap()@, name) == affects(self, name),
    {
        if !self.unknown.is_empty() { return None; }
        let mut out = Vec::new();
        append(&mut out, self.configure.as_slice());
        append(&mut out, self.changed.as_slice());
        append(&mut out, self.stage.as_slice());
        append(&mut out, self.stop.as_slice());
        append(&mut out, self.start.as_slice());
        append(&mut out, self.affected.as_slice());
        append(&mut out, self.retire.as_slice());
        append(&mut out, self.restore.as_slice());
        append(&mut out, self.copy_sources.as_slice());
        append(&mut out, self.copy_targets.as_slice());
        append(&mut out, self.gui_providers.as_slice());
        append(&mut out, self.gui_clients.as_slice());
        append(&mut out, self.pci_sources.as_slice());
        append(&mut out, self.pci_targets.as_slice());
        append(&mut out, self.firewall_parameters.as_slice());
        Some(out)
    }

    /// Interpret reboot permission without treating missing evidence as no reboot.
    pub fn requires_reboot_permission(&self) -> (required: bool)
        ensures required == may_reboot(self),
    {
        self.reboot != Some(false)
    }
}

}
