//! Check the boundary between serde decoding and validated startup settings.

use airlock_firewall_parameters::{DecodeError, Document, MAX_DOCUMENT_BYTES, decode, encode};

/// Defaults apply only to absent settings. Invalid explicit claims fail.
#[test]
fn startup_document_selection() {
    let defaults = Document::default();
    assert_eq!(*decode(None).unwrap().document(), defaults);

    let encoded = encode(defaults).unwrap();
    assert_eq!(
        *decode(Some(encoded.as_bytes())).unwrap().document(),
        defaults
    );
    let mut unknown = serde_json::to_value(defaults).unwrap();
    unknown["unexpected"] = true.into();
    assert_eq!(
        decode(Some(unknown.to_string().as_bytes())),
        Err(DecodeError::Json)
    );
    let unsupported = serde_json::to_vec(&Document {
        version: 2,
        ..defaults
    })
    .unwrap();
    assert_eq!(decode(Some(&unsupported)), Err(DecodeError::Unsupported));
    let invalid = serde_json::to_vec(&Document {
        active_per_client: 0,
        ..defaults
    })
    .unwrap();
    assert_eq!(decode(Some(&invalid)), Err(DecodeError::Unsupported));
    assert_eq!(
        decode(Some(&vec![b' '; MAX_DOCUMENT_BYTES + 1])),
        Err(DecodeError::Size)
    );
}
