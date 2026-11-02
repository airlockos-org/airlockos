//! Startup correlation primitives shared by Hermit services. A challenge
//! associates diagnostics with the current admitted boot; it grants no control,
//! peer, clipboard or network authority by itself.

#![no_std]
#![warn(missing_docs)]

use vstd::prelude::*;

/// Reviewed application capabilities shared by authoring, admission and startup.
pub mod application;

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
    /// Trust scope: uuid::Uuid::try_parse_ascii and the fixed-array copy. The
    /// accepted library boundary avoids a second UUID parser; its correspondence
    /// to challenge_bytes is assumed, not proved. Requiring exactly 36 bytes
    /// selects the hyphenated form, and preserving the original bytes retains
    /// case-sensitive boot correlation. A challenge alone grants no authority.
    #[verifier::external_body]
    pub fn parse(input: &[u8]) -> (out: Option<Self>)
        ensures out.is_some() == challenge_bytes(input@),
            out.is_some() ==> out.unwrap().value() == input@,
    {
        if input.len() != 36 { return None; }
        uuid::Uuid::try_parse_ascii(input).ok()?;
        Some(Self { bytes: input.try_into().ok()? })
    }

    /// Borrow validated ASCII for checked UTF-8 conversion at the logging boundary.
    pub fn as_bytes(&self) -> (bytes: &[u8])
        ensures bytes@ == self.value(),
    { &self.bytes }
}


}
