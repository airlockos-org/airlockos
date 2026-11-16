//! Check source-scoped revocation through real QubesDB publications and DNS TTLs.
//! Queues and neighbor state belong to the production engine; no VM harness is used.

use super::{Engine, Link, Neighbor, Owner};
use airlock_qubes_network::{
    address::Ip,
    cache::Cache,
    projection::View,
    resolution::{NameAnswers, Resolved},
};
use alloc::{format, vec, vec::Vec};

/// Replace one private replica record and deliver its matching live observation.
fn write(cache: &mut Cache, view: &mut View, key: &str, value: &str) {
    assert!(cache.put(key.as_bytes().to_vec(), value.as_bytes().to_vec(), true));
    assert!(view.changed(cache, key.as_bytes(), false));
}

/// Synchronize two authoritative source memberships, then publish fresh policies.
fn configured() -> (Cache, View) {
    let mut cache = Cache::empty();
    for (key, value) in [
        ("/qubes-netvm-network", "10.137.0.0"),
        ("/qubes-ip", "10.137.0.3"),
        ("/qubes-gateway", "10.137.0.1"),
        ("/qubes-netmask", "255.255.255.0"),
        ("/qubes-primary-dns", "1.1.1.1"),
        ("/qubes-secondary-dns", "9.9.9.9"),
        ("/qubes-mac", "02:00:00:00:00:03"),
        ("/qubes-netvm-gateway", "10.137.0.3"),
        ("/qubes-netvm-netmask", "255.255.255.255"),
        ("/qubes-netvm-primary-dns", "10.139.1.1"),
        ("/qubes-netvm-secondary-dns", "10.139.1.2"),
        ("/connected-ips", "10.137.0.8 10.137.0.9"),
        ("/connected-ips6", ""),
    ] {
        assert!(cache.put(key.as_bytes().to_vec(), value.as_bytes().to_vec(), false));
    }
    let mut view = View::synchronizing();
    assert!(view.synchronized(&cache));
    for last in [8, 9] {
        let root = format!("/qubes-firewall/10.137.0.{last}");
        write(&mut cache, &mut view, &format!("{root}/policy"), "accept");
        if last == 8 {
            write(
                &mut cache,
                &mut view,
                &format!("{root}/0000"),
                "action=accept dsthost=example.test",
            );
        }
        write(&mut cache, &mut view, &root, "");
    }
    (cache, view)
}

/// Complete exactly the policy's pending hostname obligation with a short TTL.
fn resolve(view: &mut View, now: u64, expires: u64) {
    let source = Ip::from_ipv4([10, 137, 0, 8]);
    let (revision, snapshot) = view.candidate(&source).unwrap();
    let answer = NameAnswers::new(
        b"example.test",
        vec![Ip::from_ipv4([203, 0, 113, 8])],
        expires,
        now,
        4,
    )
    .unwrap();
    let resolved = Resolved::new(snapshot, revision, vec![answer], now).unwrap();
    assert!(view.resolve(resolved, now));
}

/// Install local queue reservations with distinct native lifetime labels.
fn queues(view: &View) -> (Engine, Vec<Owner>) {
    let mut engine = Engine::new([42; 32]);
    assert!(engine.observe(view, 1));
    let mut owners = Vec::new();
    for last in [8, 9] {
        let owner = Owner {
            connection: 1,
            lease: u32::from(last),
            peer: u16::from(last),
        };
        engine.links.push(Link {
            owner,
            assigned: vec![Ip::from_ipv4([10, 137, 0, last])],
            incoming: Default::default(),
            outgoing: Default::default(),
            fragmented: None,
            fragment_turn: false,
            response_at: 0,
        });
        engine.deliver_frame(owner, view.generation(), vec![0; 60], 1);
        owners.push(owner);
    }
    engine.neighbors.push_back(Neighbor {
        owner: None,
        ip: *view.config().unwrap().gateway(),
        gateway: true,
        mac: Some([2, 0, 0, 0, 0, 1]),
        expires: 1000,
        requested: 0,
    });
    (engine, owners)
}

/// DNS expiry and completion revoke only their source; shared changes revoke all.
#[test]
fn dns_refresh_preserves_other_clients_and_gateway() {
    let (mut cache, mut view) = configured();
    resolve(&mut view, 0, 10);
    let (mut engine, owners) = queues(&view);
    let original = view.generation();
    assert!(view.expire(10));
    assert!(!view.source_unchanged(&Ip::from_ipv4([10, 137, 0, 8]), original));
    assert!(view.source_unchanged(&Ip::from_ipv4([10, 137, 0, 9]), original));
    assert!(engine.observe(&view, 10));
    assert!(engine.next_client(owners[0]).is_none());
    assert_eq!(engine.links[1].incoming.len(), 1);
    assert!(engine.gateway_reachable(&view, 10));
    resolve(&mut view, 10, 20);
    assert!(engine.observe(&view, 11));
    let output = engine.next_client(owners[1]).unwrap();
    assert_eq!(output.revision, original);
    engine.retry(output);
    assert!(engine.gateway_reachable(&view, 11));
    write(&mut cache, &mut view, "/qubes-gateway", "10.137.0.2");
    assert!(engine.observe(&view, 12));
    assert!(engine.next_client(owners[1]).is_none());
    assert!(!engine.gateway_reachable(&view, 12));
}

/// Replacing the same policy cannot revive already queued decisions; retiring
/// a hostile owner's queues must leave the healthy owner's reservation intact.
#[test]
fn same_policy_republication_and_owner_retirement_do_not_revive_output() {
    let (mut cache, mut view) = configured();
    resolve(&mut view, 0, 100);
    let (mut engine, owners) = queues(&view);
    let original = view.generation();
    write(
        &mut cache,
        &mut view,
        "/qubes-firewall/10.137.0.8/policy",
        "accept",
    );
    write(&mut cache, &mut view, "/qubes-firewall/10.137.0.8", "");
    resolve(&mut view, 2, 100);
    assert!(!view.source_unchanged(&Ip::from_ipv4([10, 137, 0, 8]), original));
    assert!(view.source_unchanged(&Ip::from_ipv4([10, 137, 0, 9]), original));
    engine.retire(owners[0], 3);
    assert!(engine.observe(&view, 3));
    assert!(engine.next_client(owners[0]).is_none());
    assert!(engine.next_client(owners[1]).is_some());
}

/// A slow pending query survives another source's completion, but not its own update.
#[test]
fn dns_query_tracks_its_source_instead_of_every_publication() {
    let (mut cache, mut view) = configured();
    write(
        &mut cache,
        &mut view,
        "/qubes-firewall/10.137.0.9/0000",
        "action=accept dsthost=other.test",
    );
    write(&mut cache, &mut view, "/qubes-firewall/10.137.0.9", "");
    let mut engine = Engine::new([42; 32]);
    engine.dns.cursor = 1;
    let (query, _) = engine.dns.tick(&view, 1, &mut engine.random);
    assert!(query.is_some());
    let original = engine.dns.pending.as_ref().unwrap().revision;
    let transaction = engine.dns.pending.as_ref().unwrap().transaction;
    resolve(&mut view, 1, 100);
    engine.dns.tick(&view, 2, &mut engine.random);
    let pending = engine.dns.pending.as_ref().unwrap();
    assert_eq!(pending.revision, original);
    assert_eq!(pending.transaction, transaction);
    write(
        &mut cache,
        &mut view,
        "/qubes-firewall/10.137.0.9/policy",
        "drop",
    );
    engine.dns.tick(&view, 3, &mut engine.random);
    assert!(engine.dns.pending.is_none());
}
