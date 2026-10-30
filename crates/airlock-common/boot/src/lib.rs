//! Startup correlation primitives shared by Hermit services. A challenge
//! associates diagnostics with the current admitted boot; it grants no control,
//! peer, clipboard or network authority by itself.

#![no_std]
#![warn(missing_docs)]

use vstd::prelude::*;

verus! {

/// Deployment's canonical, printable UUID challenge; never an authorization token.
pub struct Challenge {
    /// Immutable ASCII bytes, safe to correlate in payload-free startup diagnostics.
    bytes: [u8; 36],
}

/// Return whether a byte is an ASCII decimal digit. Keep classification inside
/// the verified executable rather than assuming
/// an unmodeled u8::is_ascii_digit library contract. This single lint exception
/// preserves the exact predicate; it does not exempt parsing from verification.
#[expect(clippy::manual_is_ascii_check, reason = "Pinned Verus has no u8::is_ascii_digit contract; verify this exact predicate body")]
pub fn ascii_digit(byte: u8) -> (yes: bool)
    ensures yes == (b'0' <= byte <= b'9'),
{ (b'0'..=b'9').contains(&byte) }

/// The expected ASCII UUID layout, including fixed separator positions.
pub open spec fn challenge_bytes(bytes: Seq<u8>) -> bool {
    bytes.len() == 36 && (forall|i: int| 0 <= i < 36 ==>
        if i == 8 || i == 13 || i == 18 || i == 23 { bytes[i] == b'-' }
        else { b'0' <= #[trigger] bytes[i] <= b'9' || b'a' <= bytes[i] <= b'f' || b'A' <= bytes[i] <= b'F' })
}

impl Challenge {
    /// Exact deployment challenge, independent of its later textual formatting.
    pub closed spec fn value(&self) -> Seq<u8> { self.bytes@ }

    /// Accept exactly the canonical UUID grammar without allocation.
    pub fn parse(input: &[u8]) -> (out: Option<Self>)
        ensures out.is_some() == challenge_bytes(input@),
            out.is_some() ==> out.unwrap().value() == input@,
    {
        if input.len() != 36 { return None; }
        let mut bytes = [0; 36];
        let mut i = 0;
        while i < 36
            invariant i <= 36, input.len() == 36, bytes@.take(i as int) == input@.take(i as int),
                forall|j: int| 0 <= j < i ==> if j == 8 || j == 13 || j == 18 || j == 23 { input[j] == b'-' }
                    else { b'0' <= input[j] <= b'9' || b'a' <= input[j] <= b'f' || b'A' <= input[j] <= b'F' },
            decreases 36 - i,
        {
            let byte = input[i];
            let valid = if i == 8 || i == 13 || i == 18 || i == 23 {
                byte == b'-'
            } else {
                ascii_digit(byte) || (b'a'..=b'f').contains(&byte) || (b'A'..=b'F').contains(&byte)
            };
            if !valid { return None; }
            bytes[i] = byte;
            i += 1;
        }
        assert(bytes@.take(36) == bytes@);
        assert(input@.take(36) == input@);
        assert(bytes@ =~= input@);
        Some(Self { bytes })
    }

    /// Borrow validated ASCII for checked UTF-8 conversion at the logging boundary.
    pub fn as_bytes(&self) -> (bytes: &[u8])
        ensures bytes@ == self.value(),
    { &self.bytes }
}


}
