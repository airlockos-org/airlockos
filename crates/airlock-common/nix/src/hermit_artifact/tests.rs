//! Exercise malformed loader inputs and the distinction between integrity and authority.

use super::*;

/// Encode a little-endian field into the synthetic ELF fixture.
fn put(bytes: &mut [u8], offset: usize, size: usize, value: u64) {
    bytes[offset..offset + size].copy_from_slice(&value.to_le_bytes()[..size]);
}

/// Minimal static executable with one load and a Xen PVH entry note.
fn executable() -> Vec<u8> {
    let mut bytes = vec![0; 256];
    bytes[..8].copy_from_slice(b"\x7fELF\x02\x01\x01\xff");
    for (offset, size, value) in [
        (16, 2, 2),
        (18, 2, 62),
        (20, 4, 1),
        (24, 8, 0x2000f0),
        (32, 8, 64),
        (52, 2, 64),
        (54, 2, 56),
        (56, 2, 2),
        (64, 4, 1),
        (68, 4, 5),
        (80, 8, 0x200000),
        (88, 8, 0x200000),
        (96, 8, 256),
        (104, 8, 256),
        (112, 8, 4096),
        (120, 4, 4),
        (128, 8, 192),
        (152, 8, 24),
        (192, 4, 4),
        (196, 4, 8),
        (200, 4, 18),
        (208, 8, 0x2000f0),
    ] {
        put(&mut bytes, offset, size, value);
    }
    bytes[204..208].copy_from_slice(b"Xen\0");
    bytes
}

/// Bind the fixture to exact immutable source and executable identities.
fn descriptor(bytes: &[u8]) -> Descriptor {
    Descriptor {
        schema: Schema::V1,
        executable: "/nix/store/00000000000000000000000000000000-clipboard/kernel.elf"
            .parse()
            .unwrap(),
        sha256: format!("{digest:x}", digest = Sha256::digest(bytes))
            .parse()
            .unwrap(),
        bytes: bytes.len() as u64,
        source_revision: "a".repeat(40).parse().unwrap(),
        integration_revision: "b".repeat(40).parse().unwrap(),
        build_lock: "c".repeat(64).parse().unwrap(),
        authority: AuthorityMode::Disconnected,
    }
}

#[test]
fn integrity_does_not_authorize_test_peers() {
    let bytes = executable();
    let mut claim = descriptor(&bytes);
    assert_eq!(
        claim.verify(&bytes, 32 << 20, false).unwrap().entry,
        0x2000f0
    );
    claim.authority = AuthorityMode::Laboratory;
    assert_eq!(
        claim.verify(&bytes, 32 << 20, false),
        Err(InvalidArtifact("laboratory authority"))
    );
    assert!(claim.verify(&bytes, 32 << 20, true).is_ok());
    let mut substituted = bytes.clone();
    substituted[240] = 1;
    assert_eq!(
        claim.verify(&substituted, 32 << 20, true),
        Err(InvalidArtifact("digest mismatch"))
    );
    assert!(claim.verify(&bytes[..255], 32 << 20, true).is_err());
}

#[test]
fn truncated_and_hostile_elf_inputs_fail_closed() {
    let bytes = executable();
    for end in 0..bytes.len() {
        assert!(
            inspect(&bytes[..end], 32 << 20).is_err(),
            "truncation at {end}"
        );
    }
    for (offset, size, value) in [
        (18, 2, 3),
        (16, 2, 3),
        (32, 8, u64::MAX),
        (56, 2, 65),
        (64, 4, 2),
        (64, 4, 3),
        (68, 4, 7),
        (88, 8, u64::MAX),
        (96, 8, 257),
        (104, 8, u64::MAX),
        (112, 8, 3),
        (196, 4, u32::MAX as u64),
        (200, 4, 17),
        (208, 8, 0x300000),
    ] {
        let mut invalid = bytes.clone();
        put(&mut invalid, offset, size, value);
        assert!(inspect(&invalid, 32 << 20).is_err(), "field at {offset}");
    }
    assert!(inspect(&bytes, 2 << 20).is_err());
}

#[test]
fn ambiguous_and_non_file_backed_entries_are_rejected() {
    let mut bytes = executable();
    // A second load overlaps the original, even if it points to valid file bytes.
    bytes.copy_within(64..120, 120);
    assert_eq!(
        inspect(&bytes, 32 << 20),
        Err(InvalidArtifact("overlapping loads"))
    );

    let mut bytes = executable();
    put(&mut bytes, 96, 8, 200);
    assert!(inspect(&bytes, 32 << 20).is_err());

    let mut bytes = executable();
    bytes.copy_within(192..216, 216);
    put(&mut bytes, 152, 8, 48);
    assert_eq!(inspect(&bytes, 32 << 20), Err(InvalidArtifact("PVH note")));
}

#[test]
fn descriptor_rejects_unknown_fields_and_unbounded_size() {
    let mut claim = descriptor(&executable());
    claim.bytes = MAX_EXECUTABLE_BYTES + 1;
    assert!(claim.validate(false).is_err());
    let mut wire = serde_json::to_value(claim).unwrap();
    wire["authorized"] = true.into();
    assert!(serde_json::from_value::<Descriptor>(wire).is_err());
}
