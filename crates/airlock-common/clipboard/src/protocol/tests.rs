//! Check canonical wire compatibility, boundary metadata and distinct malformed inputs.

use super::*;
use alloc::{format, string::ToString, vec};

/// One small multi-format declaration with an exact, stable generation.
fn declaration() -> Request {
    Request::Declare {
        generation: Generation::from_wire(9),
        formats: vec![Format {
            name: "a".to_string(),
            size: 1,
        }],
    }
}

#[test]
fn every_operation_and_reply_preserves_its_exact_wire_bytes() {
    let generation = Generation::from_wire(9);
    let requests = [
        Request::Offer,
        Request::Reserve,
        declaration(),
        Request::Write {
            generation,
            format: 0,
            offset: 0,
            bytes: vec![0, 255, 7],
        },
        Request::Complete { generation },
        Request::Read {
            generation,
            format: 63,
            offset: DEFAULT_CAPACITY,
        },
        Request::Connect {
            principal: 7,
            domain: 65535,
        },
    ];
    for request in requests {
        let bytes = request.try_encode().unwrap();
        let decoded = Request::decode(&bytes).unwrap();
        assert_eq!(decoded.try_encode().unwrap(), bytes);
    }
    let replies = [
        Reply::Ok,
        Reply::Generation(generation),
        Reply::Offer(generation, None),
        Reply::Offer(
            generation,
            Some(Offer {
                generation,
                source: Participant::from_binding(1, 2).unwrap(),
                formats: vec![Format {
                    name: "text/plain".to_string(),
                    size: 0,
                }],
            }),
        ),
        Reply::Data(vec![255, 0, 127]),
        Reply::Connected {
            epoch: u64::MAX,
            port: u32::MAX,
            grant: u32::MAX,
        },
        Reply::Error(Error::Unauthorized),
        Reply::Error(Error::Io),
    ];
    for reply in replies {
        let bytes = reply.try_encode().unwrap();
        let decoded = Reply::decode(&bytes).unwrap();
        assert_eq!(decoded.try_encode().unwrap(), bytes);
    }
}

#[test]
fn maximum_wire_metadata_and_data_are_bounded_and_roundtrip() {
    let request = Request::Declare {
        generation: Generation::from_wire(1),
        formats: (0..MAX_FORMATS)
            .map(|index| Format {
                name: format!(
                    "{index:03}{suffix}",
                    suffix = "x".repeat(MAX_FORMAT_NAME - 3)
                ),
                size: DEFAULT_CAPACITY,
            })
            .collect(),
    };
    let bytes = request.try_encode().unwrap();
    assert!(bytes.len() <= MAX_PACKET);
    assert_eq!(
        Request::decode(&bytes).unwrap().try_encode().unwrap(),
        bytes
    );
    let request = Request::Write {
        generation: Generation::from_wire(1),
        format: 0,
        offset: 0,
        bytes: vec![255; DATA_CHUNK],
    };
    let bytes = request.try_encode().unwrap();
    assert_eq!(
        Request::decode(&bytes).unwrap().try_encode().unwrap(),
        bytes
    );
    let oversized = Request::Write {
        generation: Generation::from_wire(1),
        format: 0,
        offset: 0,
        bytes: vec![0; DATA_CHUNK + 1],
    };
    assert!(matches!(oversized.try_encode(), Err(PacketError::TooLarge)));
}

#[test]
fn truncation_trailing_utf8_counts_and_numeric_overflow_are_rejected() {
    let bytes = declaration().try_encode().unwrap();
    for end in 0..bytes.len() {
        assert!(Request::decode(&bytes[..end]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(Request::decode(&trailing).is_err());
    let mut count = bytes.clone();
    count[10..18].copy_from_slice(&65u64.to_le_bytes());
    assert!(Request::decode(&count).is_err());
    let mut name = bytes.clone();
    name[18..26].copy_from_slice(&193u64.to_le_bytes());
    assert!(Request::decode(&name).is_err());
    let mut utf8 = bytes.clone();
    utf8[26] = 255;
    assert!(Request::decode(&utf8).is_err());
    let mut size = bytes;
    let offset = size.len() - 8;
    size[offset..].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(Request::decode(&size).is_err());
    assert!(Request::decode(&[2, 255]).is_err());
    assert!(Reply::decode(&[2, 255, 0]).is_err());
    assert!(Reply::decode(&[3, 0]).is_err());
}

#[test]
fn inconsistent_offer_identity_is_never_serialized_or_accepted() {
    let generation = Generation::from_wire(3);
    let offer = Offer {
        generation,
        source: Participant::from_binding(1, 1).unwrap(),
        formats: vec![],
    };
    assert!(matches!(
        Reply::Offer(Generation::from_wire(4), Some(offer.clone())).try_encode(),
        Err(PacketError::Malformed)
    ));
    let mut bytes = Reply::Offer(generation, Some(offer)).try_encode().unwrap();
    bytes[11..19].fill(0);
    assert!(matches!(Reply::decode(&bytes), Err(PacketError::Malformed)));
}
