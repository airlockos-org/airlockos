//! Exercise validated preferences and the subscription's framing boundaries.
//! These scenarios use byte chunks only; transport authority and toolkit I/O belong to adapters.

use airlock_desktop_preferences::{
    ColorScheme, CursorSize, CursorTheme, FontName, FrameDecoder, FrameError, HEADER_LEN,
    MAX_FRAME_LEN, ReducedMotion, Setting, Snapshot, TextScale, VERSION, ValueError, encode_frame,
};
use serde_json::{Value, json};

/// Construct a supported snapshot with independent color, contrast and motion preferences.
fn preferences() -> Snapshot {
    Snapshot {
        color_scheme: Setting::Supported(ColorScheme::PreferDark),
        interface_font: Setting::Supported(FontName::new("Adwaita Sans 11").unwrap()),
        document_font: Setting::Supported(FontName::new("Adwaita Sans 12").unwrap()),
        monospace_font: Setting::Supported(FontName::new("Adwaita Mono 11").unwrap()),
        text_scale: Setting::Supported(TextScale::new(1.25).unwrap()),
        cursor_theme: Setting::Supported(CursorTheme::new("Adwaita").unwrap()),
        cursor_size: Setting::Supported(CursorSize::new(24).unwrap()),
        high_contrast: Setting::Supported(false),
        enable_animations: Setting::Supported(true),
        reduced_motion: Setting::Supported(ReducedMotion::Reduce),
    }
}

/// Frame adversarial payloads independently of the validated snapshot encoder.
fn raw_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = b"ADPF".to_vec();
    frame.extend_from_slice(&VERSION.to_be_bytes());
    frame.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Encode a modified JSON tree without bypassing the receiver's validation.
fn json_frame(value: &Value) -> Vec<u8> {
    raw_frame(&serde_json::to_vec(value).unwrap())
}

/// Decode exactly one snapshot and assert that its entire frame was consumed.
fn decode(frame: &[u8]) -> Snapshot {
    let mut input = frame;
    let mut decoder = FrameDecoder::default();
    let snapshot = decoder.decode(&mut input).unwrap().unwrap();
    assert!(input.is_empty());
    decoder.finish().unwrap();
    snapshot
}

/// Verify that a malformed snapshot yields no partial result.
fn assert_invalid_payload(frame: &[u8]) {
    let mut input = frame;
    let mut decoder = FrameDecoder::default();
    assert!(matches!(
        decoder.decode(&mut input),
        Err(FrameError::InvalidPayload { .. })
    ));
}

/// Preserve all effective values, including explicit unsupported and no-preference states.
#[test]
fn supported_values_and_source_resets_round_trip() {
    let initial = preferences();
    assert_eq!(decode(&encode_frame(&initial).unwrap()), initial);

    let reset = Snapshot {
        color_scheme: Setting::Supported(ColorScheme::NoPreference),
        text_scale: Setting::Supported(TextScale::new(1.0).unwrap()),
        interface_font: Setting::Supported(FontName::new("Site Default 13").unwrap()),
        reduced_motion: Setting::Supported(ReducedMotion::NoPreference),
        ..initial.clone()
    };
    assert_ne!(reset, initial);
    assert_eq!(decode(&encode_frame(&reset).unwrap()), reset);

    let unsupported = Snapshot::default();
    assert_ne!(unsupported.color_scheme, reset.color_scheme);
    assert_eq!(decode(&encode_frame(&unsupported).unwrap()), unsupported);

    let light = Snapshot {
        color_scheme: Setting::Supported(ColorScheme::PreferLight),
        ..reset
    };
    assert_eq!(decode(&encode_frame(&light).unwrap()), light);

    // Decimal conversion must not round a valid multiplier to a different f64.
    for value in [0.5000000000000001, 0.9008081828513701, 2.9999999999999996] {
        let precise = Snapshot {
            text_scale: Setting::Supported(TextScale::new(value).unwrap()),
            ..Snapshot::default()
        };
        assert_eq!(decode(&encode_frame(&precise).unwrap()), precise);
    }
}

/// Bound native values before serialization and preserve Unicode font descriptions safely.
#[test]
fn constructors_enforce_semantic_bounds() {
    let font = FontName::new("日本語 Sans 12").unwrap();
    assert_eq!(font.as_str(), "日本語 Sans 12");
    assert!(FontName::new("é".repeat(128)).is_ok());
    for value in ["", " padded", "padded ", "line\nbreak", "nul\0", "c1\u{85}"] {
        assert_eq!(FontName::new(value), Err(ValueError::FontName));
    }
    assert_eq!(FontName::new("é".repeat(129)), Err(ValueError::FontName));

    assert_eq!(
        CursorTheme::new("Adwaita_1-dark.v2").unwrap().as_str(),
        "Adwaita_1-dark.v2"
    );
    assert!(CursorTheme::new("x".repeat(64)).is_ok());
    for value in [
        "",
        ".",
        "..",
        "../Adwaita",
        "/tmp/theme",
        "theme\nname",
        "é",
        "-theme",
    ] {
        assert_eq!(CursorTheme::new(value), Err(ValueError::CursorTheme));
    }
    assert_eq!(
        CursorTheme::new("x".repeat(65)),
        Err(ValueError::CursorTheme)
    );

    for value in [0.5, 1.0, 3.0] {
        assert_eq!(TextScale::new(value).unwrap().get(), value);
    }
    for value in [0.49, 3.01, -1.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert_eq!(TextScale::new(value), Err(ValueError::TextScale));
    }
    for value in [1, 24, 256] {
        assert_eq!(CursorSize::new(value).unwrap().get(), value);
    }
    for value in [0, 257, u16::MAX] {
        assert_eq!(CursorSize::new(value), Err(ValueError::CursorSize));
    }
}

/// Every possible two-chunk split delivers a snapshot only after its full frame arrives.
#[test]
fn arbitrary_fragmentation_never_exposes_partial_state() {
    let snapshot = preferences();
    let frame = encode_frame(&snapshot).unwrap();
    for split in 0..frame.len() {
        let mut decoder = FrameDecoder::default();
        let mut first = &frame[..split];
        assert_eq!(decoder.decode(&mut first).unwrap(), None);
        assert!(first.is_empty());

        let mut rest = &frame[split..];
        assert_eq!(decoder.decode(&mut rest).unwrap(), Some(snapshot.clone()));
        assert!(rest.is_empty());
        decoder.finish().unwrap();
    }
}

/// Coalesced frames retain boundaries, duplicate values and explicit loss of source support.
#[test]
fn subscription_delivers_complete_replacements() {
    let initial = preferences();
    let changed = Snapshot {
        interface_font: Setting::Unsupported,
        high_contrast: Setting::Supported(true),
        ..initial.clone()
    };
    let expected = [initial.clone(), initial, changed];
    let bytes: Vec<u8> = expected
        .iter()
        .flat_map(|snapshot| encode_frame(snapshot).unwrap())
        .collect();
    let mut input = bytes.as_slice();
    let mut decoder = FrameDecoder::default();
    for snapshot in expected {
        assert_eq!(decoder.decode(&mut input).unwrap(), Some(snapshot));
    }
    assert!(input.is_empty());
    assert_eq!(decoder.decode(&mut input).unwrap(), None);
    decoder.finish().unwrap();
}

/// EOF distinguishes incomplete frames from a clean boundary, even before the first snapshot.
#[test]
fn stream_termination_preserves_boundary_information() {
    FrameDecoder::default().finish().unwrap();
    let frame = encode_frame(&preferences()).unwrap();
    for end in [1, HEADER_LEN - 1, HEADER_LEN, frame.len() - 1] {
        let mut decoder = FrameDecoder::default();
        assert!(decoder.decode(&mut &frame[..end]).unwrap().is_none());
        assert!(matches!(decoder.finish(), Err(FrameError::TruncatedFrame)));
    }

    let mut decoder = FrameDecoder::default();
    assert!(decoder.decode(&mut frame.as_slice()).unwrap().is_some());
    decoder.finish().unwrap();
}

/// Header errors are rejected before accepting any bytes of a claimed payload.
#[test]
fn invalid_headers_end_the_subscription_before_payload_consumption() {
    let valid = encode_frame(&preferences()).unwrap();
    let mut bad_magic = valid.clone();
    bad_magic[0] = b'X';
    let mut decoder = FrameDecoder::default();
    let mut input = bad_magic.as_slice();
    assert!(matches!(
        decoder.decode(&mut input),
        Err(FrameError::InvalidMagic)
    ));
    assert_eq!(input.len(), valid.len() - HEADER_LEN);

    for version in [0, VERSION + 1, u16::MAX] {
        let mut frame = valid.clone();
        frame[4..6].copy_from_slice(&version.to_be_bytes());
        let mut input = frame.as_slice();
        let mut decoder = FrameDecoder::default();
        assert!(
            matches!(decoder.decode(&mut input), Err(FrameError::UnsupportedVersion { received }) if received == version)
        );
        assert_eq!(input.len(), valid.len() - HEADER_LEN);
    }

    for length in [MAX_FRAME_LEN - HEADER_LEN + 1, usize::from(u16::MAX)] {
        let mut header = valid[..HEADER_LEN].to_vec();
        header[6..8].copy_from_slice(&u16::try_from(length).unwrap().to_be_bytes());
        let mut decoder = FrameDecoder::default();
        assert!(
            matches!(decoder.decode(&mut header.as_slice()), Err(FrameError::PayloadTooLarge { length: actual }) if actual == length)
        );
    }

    let mut decoder = FrameDecoder::default();
    assert!(matches!(
        decoder.decode(&mut raw_frame(b"").as_slice()),
        Err(FrameError::EmptyPayload)
    ));
}

/// The largest allowed frame works one byte at a time; larger declarations already fail at the header.
#[test]
fn maximum_frame_and_escaped_font_values_fit_the_bound() {
    let snapshot = Snapshot {
        interface_font: Setting::Supported(FontName::new("\"\\".repeat(128)).unwrap()),
        document_font: Setting::Supported(FontName::new("a".repeat(256)).unwrap()),
        monospace_font: Setting::Supported(FontName::new("é".repeat(128)).unwrap()),
        cursor_theme: Setting::Supported(CursorTheme::new("x".repeat(64)).unwrap()),
        ..preferences()
    };
    let encoded = encode_frame(&snapshot).unwrap();
    assert!(encoded.len() <= MAX_FRAME_LEN);
    assert_eq!(decode(&encoded), snapshot);

    // JSON permits trailing whitespace. Pad a valid payload to the exact wire limit.
    let mut payload = encoded[HEADER_LEN..].to_vec();
    payload.resize(MAX_FRAME_LEN - HEADER_LEN, b' ');
    let frame = raw_frame(&payload);
    let mut decoder = FrameDecoder::default();
    for byte in &frame[..frame.len() - 1] {
        assert!(
            decoder
                .decode(&mut std::slice::from_ref(byte))
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(
        decoder.decode(&mut &frame[frame.len() - 1..]).unwrap(),
        Some(snapshot)
    );
    decoder.finish().unwrap();
}

/// Decoding enforces schema and typed bounds instead of trusting a producer's constructor use.
#[test]
fn invalid_snapshot_values_and_shapes_are_rejected() {
    let valid = serde_json::to_value(preferences()).unwrap();
    for (field, value) in [
        ("text_scale", json!({"supported": 0.0})),
        ("text_scale", json!({"supported": 3.1})),
        ("text_scale", json!({"supported": "NaN"})),
        ("cursor_size", json!({"supported": 0})),
        ("cursor_size", json!({"supported": 257})),
        ("cursor_size", json!({"supported": -1})),
        ("interface_font", json!({"supported": "line\nbreak"})),
        ("interface_font", json!({"supported": "a".repeat(257)})),
        ("cursor_theme", json!({"supported": "../theme"})),
        ("color_scheme", json!({"supported": "unknown"})),
        ("high_contrast", json!({"supported": "false"})),
        ("reduced_motion", Value::Null),
    ] {
        let mut malformed = valid.clone();
        malformed[field] = value;
        assert_invalid_payload(&json_frame(&malformed));
    }

    let mut missing = valid.clone();
    missing.as_object_mut().unwrap().remove("interface_font");
    assert_invalid_payload(&json_frame(&missing));
    let mut unknown = valid;
    unknown["command"] = json!("do-something");
    assert_invalid_payload(&json_frame(&unknown));

    assert_invalid_payload(&raw_frame(b"{not json}"));
    assert_invalid_payload(&raw_frame(&[0xff]));
    let json = serde_json::to_string(&preferences()).unwrap();
    let duplicate = format!(
        "{{\"high_contrast\":\"unsupported\",{tail}",
        tail = &json[1..]
    );
    assert_invalid_payload(&raw_frame(duplicate.as_bytes()));
    let trailing = format!("{json} {{}}");
    assert_invalid_payload(&raw_frame(trailing.as_bytes()));
}

/// A later malformed frame cannot produce a replacement; recovery uses a new subscription.
#[test]
fn failed_update_retains_last_valid_snapshot_until_reconnect() {
    let initial = preferences();
    let mut decoder = FrameDecoder::default();
    let applied = decoder
        .decode(&mut encode_frame(&initial).unwrap().as_slice())
        .unwrap()
        .unwrap();
    assert!(decoder.decode(&mut raw_frame(b"{}").as_slice()).is_err());
    assert_eq!(applied, initial);
    assert!(matches!(
        decoder.decode(&mut encode_frame(&Snapshot::default()).unwrap().as_slice()),
        Err(FrameError::FailedDecoder)
    ));
    assert!(matches!(decoder.finish(), Err(FrameError::FailedDecoder)));

    let replacement = Snapshot {
        text_scale: Setting::Supported(TextScale::new(2.0).unwrap()),
        ..initial
    };
    assert_eq!(decode(&encode_frame(&replacement).unwrap()), replacement);
}
