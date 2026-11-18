//! Exercise UDP port sharing and independent peer authorization using real
//! library-encoded packets. No native VM or network service is required.

use super::Owner;
use crate::diagnostics::Meters;
use crate::{
    SECOND,
    flow::{NewMapping, Table},
    wire::{Packet, Tuple},
};
use airlock_qubes_network::address::Ip;
use alloc::vec::Vec;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

/// Construct a distinct native lifetime without adding a production constructor.
fn owner(lease: u32) -> Owner {
    Owner {
        connection: 1,
        lease,
        peer: 7,
    }
}

/// Encode a valid UDP datagram, including the mandatory IPv6 checksum.
fn udp(ipv6: bool, remote: u8, sport: u16, dport: u16) -> Vec<u8> {
    let builder = if ipv6 {
        let mut source = [0; 16];
        source[0] = 0xfd;
        source[15] = 8;
        let mut destination = source;
        destination[0] = 0x20;
        destination[15] = remote;
        etherparse::PacketBuilder::ipv6(source, destination, 64)
    } else {
        etherparse::PacketBuilder::ipv4([10, 137, 0, 8], [203, 0, 113, remote], 64)
    };
    let mut bytes = Vec::new();
    builder
        .udp(sport, dport)
        .write(&mut bytes, b"probe")
        .unwrap();
    bytes
}

/// Admit a peer as the engine does after checking its current outbound policy.
fn create(table: &mut Table, owner: Owner, packet: &Packet<'_>, now: u64) -> u16 {
    let external = if packet.tuple.src.version() == 6 {
        Ip::parse(b"fd00::3").unwrap()
    } else {
        Ip::from_ipv4([10, 137, 0, 3])
    };
    let mapping = NewMapping {
        owner,
        policy: packet.tuple,
        quota: Ip::from_ipv4([10, 137, 0, 8]),
        external,
        mac: [2, 0, 0, 0, 0, 8],
        revision: 1,
    };
    table
        .create(
            mapping,
            packet,
            now,
            &mut ChaCha20Rng::from_seed([42; 32]),
            &mut Meters::new(),
        )
        .unwrap()
}

/// Peers share only the translation; reply lookup and owner lifetimes stay exact.
#[test]
fn udp_mapping_is_independent_of_remote_address_and_port() {
    for ipv6 in [false, true] {
        let mut table = Table::new();
        let first = udp(ipv6, 1, 41641, 3478);
        let second = udp(ipv6, 2, 41641, 41641);
        let third = udp(ipv6, 2, 41641, 50000);
        let a = create(&mut table, owner(1), &Packet::parse(&first).unwrap(), 0);
        let b = create(&mut table, owner(1), &Packet::parse(&second).unwrap(), 0);
        let c = create(&mut table, owner(1), &Packet::parse(&third).unwrap(), 0);
        let port = table.entries[&a].translated_port;
        assert_eq!(table.entries[&b].translated_port, port);
        assert_eq!(table.entries[&c].translated_port, port);
        assert_ne!(a, b);
        for id in [a, b, c] {
            assert_eq!(
                table.translated_id(table.entries[&id].translated()),
                Some(id)
            );
        }
        let unknown = Tuple {
            dport: 12345,
            ..table.entries[&a].translated()
        };
        assert!(table.translated_id(unknown).is_none());

        let d = create(&mut table, owner(2), &Packet::parse(&first).unwrap(), 0);
        assert_ne!(table.entries[&d].translated_port, port);
        let other_socket = udp(ipv6, 1, 41642, 3478);
        let e = create(
            &mut table,
            owner(1),
            &Packet::parse(&other_socket).unwrap(),
            0,
        );
        assert_ne!(table.entries[&e].translated_port, port);
    }
}

/// Idle packets cannot revive inbound permission, but fresh outbound traffic can.
/// Revocation remains final even when an outbound packet later appears.
#[test]
fn udp_idle_renewal_and_revocation_have_different_authority() {
    let mut table = Table::new();
    let bytes = udp(false, 1, 41641, 3478);
    let packet = Packet::parse(&bytes).unwrap();
    let id = create(&mut table, owner(1), &packet, 0);
    assert!(table.entries[&id].live(299 * SECOND));
    assert!(!table.entries[&id].live(300 * SECOND));
    table.maintain(301 * SECOND, &mut Meters::new());
    assert!(
        table
            .accept(id, &packet, false, None, 301 * SECOND, &mut Meters::new())
            .is_err()
    );
    assert!(
        table
            .accept(id, &packet, true, None, 301 * SECOND, &mut Meters::new())
            .is_ok()
    );
    assert!(table.entries[&id].live(600 * SECOND));
    table.retire(owner(1), 302 * SECOND, &mut Meters::new());
    assert!(
        table
            .accept(id, &packet, true, None, 303 * SECOND, &mut Meters::new())
            .is_err()
    );
}

/// Reclaiming one peer must preserve the socket port owned by another peer.
#[test]
fn shared_port_survives_peer_reclamation() {
    let mut table = Table::new();
    let first = udp(false, 1, 41641, 3478);
    let second = udp(false, 2, 41641, 41641);
    let third = udp(false, 3, 41641, 41641);
    let a = create(&mut table, owner(1), &Packet::parse(&first).unwrap(), 0);
    let b = create(
        &mut table,
        owner(1),
        &Packet::parse(&second).unwrap(),
        200 * SECOND,
    );
    let port = table.entries[&a].translated_port;
    let old_wire = table.entries[&a].translated();
    table.maintain(421 * SECOND, &mut Meters::new());
    assert!(!table.entries.contains_key(&a));
    assert!(table.translated_id(old_wire).is_none());
    assert_eq!(table.entries[&b].translated_port, port);
    let c = create(
        &mut table,
        owner(1),
        &Packet::parse(&third).unwrap(),
        421 * SECOND,
    );
    assert_eq!(table.entries[&c].translated_port, port);
}

/// A single shared UDP port cannot bypass the per-client peer-state budget.
#[test]
fn udp_peers_still_consume_individual_quota() {
    let mut table = Table::new();
    let limit = crate::parameters::Limits::defaults()
        .document()
        .active_per_client;
    for remote_port in 1..=limit as u16 {
        let bytes = udp(false, 1, 41641, remote_port);
        create(&mut table, owner(1), &Packet::parse(&bytes).unwrap(), 0);
    }
    let bytes = udp(false, 1, 41641, 30000);
    let packet = Packet::parse(&bytes).unwrap();
    let mapping = NewMapping {
        owner: owner(1),
        policy: packet.tuple,
        quota: Ip::from_ipv4([10, 137, 0, 8]),
        external: Ip::from_ipv4([10, 137, 0, 3]),
        mac: [2, 0, 0, 0, 0, 8],
        revision: 1,
    };
    assert!(
        table
            .create(
                mapping,
                &packet,
                0,
                &mut ChaCha20Rng::from_seed([42; 32]),
                &mut Meters::new()
            )
            .is_err()
    );
    assert_eq!(table.entries.len(), limit);
}

/// A reconnect keeps the same stored budget, while another client can still
/// allocate and the old translated tuple remains reserved until release.
#[test]
fn retirement_pressure_stays_with_the_original_client() {
    use crate::{
        AdmissionError,
        parameters::{Document, Limits},
    };

    let limits = Limits::validate(Document {
        active_global: 4,
        active_per_client: 1,
        retained_global: 8,
        retained_per_client: 2,
        ..Document::default()
    })
    .unwrap();
    let mut table = Table::with_parameters(limits);
    let mut meters = Meters::new();
    let mut random = ChaCha20Rng::from_seed([21; 32]);
    let bytes = udp(false, 1, 41641, 3478);
    let packet = Packet::parse(&bytes).unwrap();
    let first_quota = Ip::from_ipv4([10, 137, 0, 8]);
    let second_quota = Ip::from_ipv4([10, 137, 0, 9]);
    let mapping = |lease, quota| NewMapping {
        owner: owner(lease),
        policy: packet.tuple,
        quota,
        external: Ip::from_ipv4([10, 137, 0, 3]),
        mac: [2, 0, 0, 0, 0, 8],
        revision: 1,
    };

    let first = table
        .create(
            mapping(1, first_quota),
            &packet,
            0,
            &mut random,
            &mut meters,
        )
        .unwrap();
    let old_wire = table.entries[&first].translated();
    assert_eq!(
        table.create(
            mapping(2, first_quota),
            &packet,
            0,
            &mut random,
            &mut meters
        ),
        Err(AdmissionError::ActiveClient)
    );

    table.retire(owner(1), SECOND, &mut meters);
    let second = table
        .create(
            mapping(2, first_quota),
            &packet,
            SECOND,
            &mut random,
            &mut meters,
        )
        .unwrap();
    assert_ne!(table.entries[&second].translated_port, old_wire.sport);
    table.retire(owner(2), SECOND, &mut meters);
    assert_eq!(
        table.create(
            mapping(3, first_quota),
            &packet,
            SECOND,
            &mut random,
            &mut meters
        ),
        Err(AdmissionError::RetainedClient)
    );
    assert_eq!(table.translated_id(old_wire), Some(first));
    assert!(
        table
            .accept(first, &packet, false, None, SECOND, &mut meters)
            .is_err()
    );

    let other = table
        .create(
            mapping(4, second_quota),
            &packet,
            SECOND,
            &mut random,
            &mut meters,
        )
        .unwrap();
    assert_ne!(table.entries[&other].translated_port, old_wire.sport);
    table.maintain(420 * SECOND, &mut meters);
    assert_eq!(table.translated_id(old_wire), None);
    assert!(
        table
            .create(
                mapping(3, first_quota),
                &packet,
                420 * SECOND,
                &mut random,
                &mut meters
            )
            .is_ok()
    );
}

/// Different original DNS destinations can resolve to the same wire tuple.
/// The second admission reports a collision without overwriting the first.
#[test]
fn dns_redirect_collision_preserves_original_reply_owner() {
    use crate::AdmissionError;

    let mut table = Table::new();
    let mut meters = Meters::new();
    let mut random = ChaCha20Rng::from_seed([23; 32]);
    let primary = udp(false, 1, 41000, 53);
    let secondary = udp(false, 2, 41000, 53);
    let primary = Packet::parse(&primary).unwrap();
    let secondary = Packet::parse(&secondary).unwrap();
    let policy = Tuple {
        dst: Ip::from_ipv4([192, 0, 2, 53]),
        ..primary.tuple
    };
    let mapping = || NewMapping {
        owner: owner(1),
        policy,
        quota: Ip::from_ipv4([10, 137, 0, 8]),
        external: Ip::from_ipv4([10, 137, 0, 3]),
        mac: [2, 0, 0, 0, 0, 8],
        revision: 1,
    };
    let first = table
        .create(mapping(), &primary, 0, &mut random, &mut meters)
        .unwrap();
    let on_wire = table.entries[&first].translated();

    assert_eq!(
        table.create(mapping(), &secondary, 0, &mut random, &mut meters),
        Err(AdmissionError::TupleCollision)
    );
    assert_eq!(table.translated_id(on_wire), Some(first));
    assert_eq!(table.find(owner(1), secondary.tuple), None);
    assert_eq!(table.entries.len(), 1);
}
