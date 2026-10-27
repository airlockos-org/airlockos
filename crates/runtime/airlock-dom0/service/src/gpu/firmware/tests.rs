//! Synthetic ACPI wrappers exercise firmware validation without opening PCI devices or host firmware.

use super::*;

/// Recompute the byte checksum used by ACPI tables and PCI option ROMs.
fn checked(mut bytes: Vec<u8>, offset: usize) -> Vec<u8> {
    bytes[offset] = 0;
    bytes[offset] = 0_u8.wrapping_sub(bytes.iter().fold(0_u8, |sum, b| sum.wrapping_add(*b)));
    bytes
}

/// Build one unchanged ATOM ROM inside a VFCT containing an unrelated empty trailer.
fn source(duplicate: bool) -> (Vec<u8>, Vec<u8>) {
    let mut rom = vec![0; 512];
    rom[..3].copy_from_slice(&[0x55, 0xaa, 1]);
    rom[0x48..0x4a].copy_from_slice(&0x80_u16.to_le_bytes());
    rom[0x84..0x88].copy_from_slice(b"ATOM");
    rom[0x18..0x1a].copy_from_slice(&0xa0_u16.to_le_bytes());
    rom[0xa0..0xa4].copy_from_slice(b"PCIR");
    rom[0xa4..0xa6].copy_from_slice(&0x1002_u16.to_le_bytes());
    rom[0xa6..0xa8].copy_from_slice(&0x1681_u16.to_le_bytes());
    rom[0xb0..0xb2].copy_from_slice(&1_u16.to_le_bytes());
    let rom = checked(rom, 511);
    let mut image = Vec::new();
    for value in [4_u32, 0, 0] {
        image.extend_from_slice(&value.to_le_bytes());
    }
    for value in [0x1002_u16, 0x1681, 0, 0] {
        image.extend_from_slice(&value.to_le_bytes());
    }
    for value in [1_u32, 512] {
        image.extend_from_slice(&value.to_le_bytes());
    }
    image.extend_from_slice(&rom);
    let mut table = vec![0; 76];
    table[..4].copy_from_slice(b"VFCT");
    table[8] = 1;
    table[10..16].copy_from_slice(b"LENOVO");
    table[16..24].copy_from_slice(b"TEST    ");
    table[52..56].copy_from_slice(&76_u32.to_le_bytes());
    table.extend_from_slice(&image);
    if duplicate {
        table.extend_from_slice(&image);
    } else {
        table.extend_from_slice(&[0; 28]);
    }
    let length = table.len() as u32;
    table[4..8].copy_from_slice(&length.to_le_bytes());
    (checked(table, 9), rom)
}

/// Select the synthetic GPU and move only its ACPI wrapper to the VM's explicit address.
fn filtered(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Manifest)> {
    prepare(
        bytes,
        "0000:04:00.0".parse()?,
        "0000:00:05.0".parse()?,
        0x1002,
        0x1681,
        &digest(bytes),
    )
}

/// ROM bytes remain unchanged while wrapper coordinates, length and checksum are recomputed.
#[test]
fn filtering_preserves_rom_and_changes_only_the_wrapper() -> Result<()> {
    let (source, original) = source(false);
    let (table, rom, manifest) = filtered(&source)?;
    assert_eq!(rom, original);
    assert_eq!(&table[104..], rom);
    assert_eq!(dword(&table, 76)?, 0);
    assert_eq!(dword(&table, 80)?, 5);
    assert_eq!(dword(&table, 84)?, 0);
    assert_eq!(table.len(), 104 + rom.len());
    assert_eq!(checksum(&table), 0);
    assert!(!manifest.rom_modified);
    assert_eq!(manifest.source_image_count, 1);
    Ok(())
}

/// Untrusted ACPI lengths, offsets, identity and checksum errors fail before publication.
#[test]
fn malformed_and_ambiguous_firmware_is_rejected() -> Result<()> {
    let (source, _) = source(false);
    for (offset, value) in [
        (0, b"SSDT".to_vec()),
        (4, 12_u32.to_le_bytes().to_vec()),
        (52, 0_u32.to_le_bytes().to_vec()),
        (56, 76_u32.to_le_bytes().to_vec()),
        (100, 999999_u32.to_le_bytes().to_vec()),
    ] {
        let mut broken = source.clone();
        broken[offset..offset + value.len()].copy_from_slice(&value);
        assert!(filtered(&checked(broken, 9)).is_err(), "offset {offset}");
    }
    for offset in [9, 104 + 300] {
        let mut broken = source.clone();
        broken[offset] ^= 1;
        if offset != 9 {
            broken = checked(broken, 9);
        }
        assert!(
            filtered(&broken)
                .err()
                .unwrap()
                .to_string()
                .contains("checksum")
        );
    }
    let (duplicate, _) = self::source(true);
    assert!(
        filtered(&duplicate)
            .err()
            .unwrap()
            .to_string()
            .contains("exactly one")
    );
    assert!(
        prepare(
            &source,
            "0000:04:00.0".parse()?,
            "0000:00:05.0".parse()?,
            0x1002,
            0x1681,
            &"0".repeat(64)
        )
        .is_err()
    );
    assert!(
        prepare(
            &source,
            "0000:03:00.0".parse()?,
            "0000:00:05.0".parse()?,
            0x1002,
            0x1681,
            &digest(&source)
        )
        .is_err()
    );
    for address in ["0001:04:00.0", "0000:04:20.0", "04:00.0", "0000:04:00.8"] {
        assert!(address.parse::<Bdf>().is_err(), "{address}");
    }
    Ok(())
}
