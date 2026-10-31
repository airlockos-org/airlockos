//! Ordered Qubes policy over a normalized IPv4 tuple. Missing DNS data rejects
//! the whole source, including when the unresolved rule would have dropped.

use crate::wire::codec;
use crate::wire::{Tuple, unicast};
use airlock_qubes_network::{
    address::Ip,
    projection::View,
    rule::{Action, Protocol},
};

#[cfg(verus_keep_ghost)]
use airlock_qubes_network::policy::Snapshot;
use airlock_qubes_network::{resolution::Resolved, rule::Rule};
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::view::View as ValueView;

verus! {

broadcast use { vstd::std_specs::iter::group_iter_axioms, crate::library::byte_array_equality,
    vstd::std_specs::vec::group_vec_axioms,
    vstd::std_specs::vecdeque::group_vec_dequeue_axioms,
    vstd::set::group_set_lemmas, vstd::seq_lib::group_filter_ensures, vstd::seq::group_seq_lemmas, vstd::seq_lib::group_seq_properties,
    vstd::seq::Seq::lemma_as_ref_index, vstd::slice::group_slice_axioms };

/// A native normalized network condition delegates its prefix interpretation
/// to the same smoltcp model used by the wire boundary.
closed spec fn prefix_matches(ip: Ip, prefix: u8, destination: [u8; 4]) -> bool {
    exists|bytes: [u8; 4]| ip == Ip::v4_value(bytes) && codec::prefix_matches(bytes, prefix, destination)
}

/// Normalization is injective, so a decoded network has one prefix meaning.
proof fn prefix_equivalent(ip: Ip, bytes: [u8; 4], prefix: u8, destination: [u8; 4])
    requires ip == Ip::v4_value(bytes),
    ensures prefix_matches(ip, prefix, destination) == codec::prefix_matches(bytes, prefix, destination),
{
    if prefix_matches(ip, prefix, destination) {
        let other = choose|other: [u8; 4]| ip == Ip::v4_value(other) && codec::prefix_matches(other, prefix, destination);
        Ip::v4_injective(bytes, other);
    }
}

/// Whole-source DNS must be complete even for a hostname in a later drop rule.
closed spec fn ready(view: View, snapshot: airlock_qubes_network::policy::Snapshot, now: u64) -> bool {
    !snapshot.unresolved_value() || exists|answers: airlock_qubes_network::resolution::Resolved|
        view.resolved_for(snapshot.source_value(), answers) && answers.unexpired(now)
}

/// Conjunction of the native rule's retained conditions, before its action.
closed spec fn rule_matches(view: View, rule: Rule, tuple: Tuple, icmp: u8, now: u64) -> bool {
    !(rule.dns_value() && rule.ports_value().is_some()
        && (rule.ports_value().unwrap().low() != 53 || rule.ports_value().unwrap().high() != 53))
        && match rule.protocol() { Protocol::Any => true, Protocol::Tcp => tuple.proto == 6,
            Protocol::Udp => tuple.proto == 17, Protocol::Icmp => tuple.proto == 1 }
        && match rule.network_value() { None => true, Some(network) => prefix_matches(network.address(), network.prefix(), tuple.dst) }
        && match rule.host_value() { None => true, Some(name) => exists|answers: airlock_qubes_network::resolution::Resolved|
            view.resolved_for(Ip::v4_value(tuple.src), answers) && answers.contains(name.bytes(), Ip::v4_value(tuple.dst), now) }
        && match rule.ports_value() { None => true, Some(ports) => (tuple.proto == 6 || tuple.proto == 17)
            && ports.low() <= tuple.dport <= ports.high() }
        && match rule.icmp_value() { None => true, Some(kind) => tuple.proto == 1 && icmp == kind }
        && (!rule.dns_value() || ((tuple.proto == 6 || tuple.proto == 17) && tuple.dport == 53
            && view.configuration_value().is_some()
            && view.configuration_value().unwrap().dns_value().contains(Ip::v4_value(tuple.dst))))
}

/// The first matching rule wins; only an entirely unmatched list uses default.
closed spec fn snapshot_decision(view: View, snapshot: Snapshot, tuple: Tuple, icmp: u8, now: u64) -> bool {
    (exists|i: int| 0 <= i < snapshot.rules_value().len()
        && rule_matches(view, snapshot.rules_value()[i].rule(), tuple, icmp, now)
        && snapshot.rules_value()[i].rule().action() == Action::Accept
        && (forall|j: int| 0 <= j < i ==> !rule_matches(view, snapshot.rules_value()[j].rule(), tuple, icmp, now)))
    || (snapshot.default_value() == Action::Accept
        && (forall|i: int| 0 <= i < snapshot.rules_value().len() ==> !rule_matches(view, snapshot.rules_value()[i].rule(), tuple, icmp, now)))
}

/// A source is usable only under its complete, fresh current publication.
pub(crate) closed spec fn decision(view: View, tuple: Tuple, icmp: u8, now: u64) -> bool {
    view.configuration_value().is_some() && exists|snapshot: Snapshot|
        view.complete_for(Ip::v4_value(tuple.src), snapshot) && ready(view, snapshot, now)
            && snapshot_decision(view, snapshot, tuple, icmp, now)
}

/// A matching rule with no earlier match is the unique policy decision.
proof fn first_decision(view: View, snapshot: Snapshot, tuple: Tuple, icmp: u8, now: u64, index: int)
    requires view.configuration_value().is_some(), view.complete_for(Ip::v4_value(tuple.src), snapshot),
        forall|other: Snapshot| view.complete_for(Ip::v4_value(tuple.src), other) ==> other == snapshot,
        ready(view, snapshot, now), 0 <= index < snapshot.rules_value().len(),
        rule_matches(view, snapshot.rules_value()[index].rule(), tuple, icmp, now),
        forall|j: int| 0 <= j < index ==> !rule_matches(view, snapshot.rules_value()[j].rule(), tuple, icmp, now),
    ensures decision(view, tuple, icmp, now) == (snapshot.rules_value()[index].rule().action() == Action::Accept),
{
    let rules = snapshot.rules_value();
    if rules[index].rule().action() == Action::Accept {
        assert(exists|i: int| 0 <= i < rules.len() && rule_matches(view, rules[i].rule(), tuple, icmp, now)
            && rules[i].rule().action() == Action::Accept
            && (forall|j: int| 0 <= j < i ==> !rule_matches(view, rules[j].rule(), tuple, icmp, now)));
        assert(snapshot_decision(view, snapshot, tuple, icmp, now));
        assert(exists|candidate: Snapshot| view.complete_for(Ip::v4_value(tuple.src), candidate)
            && ready(view, candidate, now) && snapshot_decision(view, candidate, tuple, icmp, now));
        assert(decision(view, tuple, icmp, now));
    } else {
        assert forall|i: int| 0 <= i < rules.len() && rule_matches(view, rules[i].rule(), tuple, icmp, now)
            && rules[i].rule().action() == Action::Accept
            implies !(forall|j: int| 0 <= j < i ==> !rule_matches(view, rules[j].rule(), tuple, icmp, now)) by {
            if i > index { assert(rule_matches(view, rules[index].rule(), tuple, icmp, now)); }
        }
        assert(!(forall|i: int| 0 <= i < rules.len() ==> !rule_matches(view, rules[i].rule(), tuple, icmp, now)));
        assert(!decision(view, tuple, icmp, now));
    }
}

/// Match destination policy after provider-DNS redirection, as Qubes prerouting
/// precedes its forwarding chain. No established-flow exception lives here.
pub(crate) fn allows(view: &View, tuple: Tuple, icmp: u8, now: u64) -> (allowed: bool)
    requires view.valid(), tuple.valid(),
    ensures allowed == decision(*view, tuple, icmp, now),
{
    let source = Ip::from_ipv4(tuple.src);
    let Some(snapshot) = view.policy(&source) else { return false; };
    let Some(_config) = view.config() else { return false; };
    if snapshot.unresolved() && !view.resolution(&source).is_some_and(|dns: &Resolved| -> (fresh: bool)
        requires dns.valid(), ensures fresh == dns.unexpired(now),
    { dns.fresh(now) }) { return false; }
    let rules = snapshot.rules();
    let mut index = 0;
    while index < rules.len()
        invariant view.valid(), snapshot.valid(), tuple.valid(),
            view.complete_for(source, *snapshot), source == Ip::v4_value(tuple.src),
            rules@ == snapshot.rules_value(), index <= rules@.len() <= airlock_qubes_network::policy::MAX_RULES,
            ready(*view, *snapshot, now), view.configuration_value().is_some(),
            forall|j: int| 0 <= j < rules@.len() ==> rules@[j].rule().valid()
                && rules@[j].rule().family_value() == 4,
            forall|j: int| 0 <= j < index ==> !rule_matches(*view, rules@[j].rule(), tuple, icmp, now),
            forall|other: Snapshot| view.complete_for(source, other) ==> other == *snapshot,
        decreases rules.len() - index,
    {
        let rule = rules[index].entry();
        if matches_rule(view, rule, tuple, icmp, now) {
            proof { assert(exists|i: int| 0 <= i < rules@.len()
                && rule_matches(*view, rules@[i].rule(), tuple, icmp, now)
                && (forall|j: int| 0 <= j < i ==> !rule_matches(*view, rules@[j].rule(), tuple, icmp, now))); }
            let accepted = matches!(rule.disposition(), Action::Accept);
            proof { first_decision(*view, *snapshot, tuple, icmp, now, index as int); }
            return accepted;
        }
        index += 1;
    }
    matches!(snapshot.default_action(), Action::Accept)
}

/// Evaluate every retained condition of one rule. This function grants no flow
/// authority; its exact result is consumed by the ordered first-match traversal.
fn matches_rule(view: &View, rule: &Rule, tuple: Tuple, icmp: u8, now: u64) -> (matches: bool)
    requires view.valid(), rule.valid(), rule.family_value() == 4, tuple.valid(),
    ensures matches == rule_matches(*view, *rule, tuple, icmp, now),
{
    if rule.matches_none() { return false; }
    let transport = match rule.transport() {
        Protocol::Any => true, Protocol::Tcp => tuple.proto == 6,
        Protocol::Udp => tuple.proto == 17, Protocol::Icmp => tuple.proto == 1,
    };
    if !transport { return false; }
    if let Some(network) = rule.network() {
        let Some(ip) = network.ip().ipv4() else { return false; };
        proof { prefix_equivalent(network.address(), ip, network.prefix(), tuple.dst); }
        if !codec::contains(ip, network.bits(), tuple.dst) { return false; }
    }
    if let Some(name) = rule.host() {
        let source = Ip::from_ipv4(tuple.src);
        let Some(dns) = view.resolution(&source) else { return false; };
        let Some(addresses) = dns.addresses(name.name(), now) else {
            proof { assert(!dns.contains(name.bytes(), Ip::v4_value(tuple.dst), now)); }
            return false;
        };
        let destination = Ip::from_ipv4(tuple.dst);
        if !addresses.iter().any(|ip: &Ip| -> (same: bool)
            requires ip.valid(), ensures same == (*ip == destination),
        { ip.same(&destination) }) {
            proof {
                assert(!addresses@.contains(destination));
                assert(!dns.contains(name.bytes(), destination, now));
            }
            return false;
        }
        proof {
            assert(addresses@.contains(destination));
            assert(dns.contains(name.bytes(), destination, now));
            assert(exists|answers: Resolved| view.resolved_for(source, answers)
                && answers.contains(name.bytes(), destination, now));
        }
    }
    if let Some(ports) = rule.ports() {
        let (low, high) = ports.bounds();
        if !matches!(tuple.proto, 6 | 17) || !(low..=high).contains(&tuple.dport) { return false; }
    }
    if rule.icmp_type().is_some_and(|kind: u8| -> (mismatch: bool)
        ensures mismatch == (tuple.proto != 1 || icmp != kind),
    { tuple.proto != 1 || icmp != kind }) { return false; }
    if rule.dns_target() {
        if !matches!(tuple.proto, 6 | 17) || tuple.dport != 53 { return false; }
        let Some(config) = view.config() else { return false; };
        let destination = Ip::from_ipv4(tuple.dst);
        if !config.dns().iter().any(|ip: &Ip| -> (same: bool)
            requires ip.valid(), ensures same == (*ip == destination),
        { ip.same(&destination) }) { return false; }
        proof { assert(config.dns_value().contains(destination)); }
    }
    true
}

/// Destination restrictions independent of the user's outbound allow rules.
/// Clients cannot reach another client or local service through a NAT shortcut.
pub(crate) fn remote(view: &View, destination: [u8; 4]) -> bool
    requires view.valid(),
{
    let Some(config) = view.config() else { return false; };
    if !unicast(destination) || config.contains(&Ip::from_ipv4(destination))
        || config.address().ipv4() == Some(destination)
        || config.provided_gateway().ipv4() == Some(destination) { return false; }
    let networks = [(config.address(), config.prefix()), (config.provided_gateway(), config.provided_prefix())];
    for &(address, prefix) in networks.iter()
        invariant forall|i: int| 0 <= i < 2 ==> networks@[i].0.valid() && networks@[i].1 <= 32,
    {
        let Some(ip) = address.ipv4() else { return false; };
        if prefix < 31 && (codec::broadcast(ip, prefix) == Some(destination) || codec::network(ip, prefix) == destination) { return false; }
    }
    true
}

/// Redirect only native provider DNS addresses, keeping normal DNS destinations
/// unchanged. Missing/unsafe actual resolvers fail closed.
pub(crate) fn redirect(view: &View, tuple: Tuple) -> (redirect: Option<Tuple>)
    requires view.valid(), tuple.valid(),
    ensures redirect.is_some() ==> redirect.unwrap().valid() && redirect.unwrap().src == tuple.src
        && redirect.unwrap().sport == tuple.sport && redirect.unwrap().dport == tuple.dport && redirect.unwrap().proto == tuple.proto,
{
    let mut redirected = tuple;
    let config = view.config()?;
    let index = if matches!(tuple.proto, 6 | 17) && tuple.dport == 53 {
        config.provided_dns().iter().position(|provided: &Ip| -> (same: bool)
            requires provided.valid(),
        { provided.ipv4() == Some(tuple.dst) })
    } else { None };
    if let Some(index) = index { redirected.dst = config.dns()[index].ipv4()?; }
    remote(view, redirected.dst).then_some(redirected)
}

}
