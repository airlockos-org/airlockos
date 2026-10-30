//! Bounded validation of the admitted service boot contract.
//! These values are deployment observations, not message-supplied authorization.
//! Only the selected GUI domain may provision participants after connection.

use vstd::prelude::*;

verus! {

/// Exact deployment argument keys shared by executable matching and grammar.
const BOOT_KEY: [u8; 13] = *b"airlock.boot=";

/// Trusted GUI guest selected by the deployment.
const AUTHORITY_KEY: [u8; 18] = *b"airlock.authority=";

/// Exact volatile device geometry admitted by the deployment.
const SCRATCH_KEY: [u8; 16] = *b"airlock.scratch=";

/// Reserved argument namespace; unknown fields reject startup.
const AIRLOCK_KEY: [u8; 8] = *b"airlock.";


/// A normal Xen guest domain, excluding dom0 and reserved Xen identifiers.
#[derive(Clone, Copy, Debug)]
pub struct Domain {
    /// Validated nonzero, non-reserved Xen domain identifier.
    value: u16,
}

impl Domain {
    /// Domain identity represented by this boot or trusted provisioning observation.
    pub closed spec fn identity(&self) -> u16 { self.value }

    /// Validate a guest-domain observation without manufacturing caller authority.
    pub fn from_raw(value: u16) -> (out: Option<Self>)
        ensures out.is_some() == (0 < value < 0x7ff0),
            out.is_some() ==> out.unwrap().identity() == value,
    {
        if value == 0 || value >= 0x7ff0 { None } else { Some(Self { value }) }
    }

    /// Pass the exact checked identifier to the Xen endpoint constructor.
    pub fn get(&self) -> (value: u16)
        ensures value == self.identity(),
    { self.value }
}

/// Deployment's canonical, printable UUID challenge; never an authorization token.
pub struct Challenge {
    /// Immutable ASCII bytes, safe to correlate in payload-free startup diagnostics.
    bytes: [u8; 36],
}

/// Keep decimal classification inside the verified executable rather than assuming
/// an unmodeled u8::is_ascii_digit library contract. This single lint exception
/// preserves the exact predicate; it does not exempt parsing from verification.
#[expect(clippy::manual_is_ascii_check, reason = "Pinned Verus has no u8::is_ascii_digit contract; verify this exact predicate body")]
fn ascii_digit(byte: u8) -> (yes: bool)
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

/// Normal startup requires authority and storage; isolated startup never opens a disk.
pub enum Mode {
    /// No runtime IPC is provisioned; the guest parks after isolated startup evidence.
    Isolated,
    /// Deployment admitted a GUI authority and its exact volatile storage size.
    Connected {
        /// GUI guest selected by the approved deployment, never a data-plane claim.
        authority: Domain,
        /// Exact admitted encrypted volatile extent, checked against the VBD geometry.
        scratch_bytes: u64,
    },
}

/// Complete boot configuration, constructed only after all fields were validated together.
pub struct BootConfig {
    /// Correlates this invocation with its deployment's application-readiness challenge.
    challenge: Challenge,
    /// Consistent authority and storage contract.
    mode: Mode,
}

impl BootConfig {
    /// Complete challenge and authority/storage consistency required before effects.
    pub closed spec fn valid(&self) -> bool {
        challenge_bytes(self.challenge.value()) && match &self.mode {
            Mode::Isolated => true,
            Mode::Connected { authority, scratch_bytes } => 0 < authority.identity() < 0x7ff0
                && *scratch_bytes >= crate::shared::DEFAULT_CAPACITY && *scratch_bytes % 512 == 0,
        }
    }

    /// Immutable challenge bytes carried from the accepted boot argument.
    pub closed spec fn challenge_value(&self) -> Seq<u8> { self.challenge.value() }

    /// The complete checked startup mode, without independently reconstructed fields.
    pub closed spec fn mode_value(&self) -> Mode { self.mode }

    /// Consume the checked boot decision without reconstructing any field.
    pub fn into_parts(self) -> (parts: (Challenge, Mode))
        ensures parts.0.value() == self.challenge_value(), parts.1 == self.mode_value(),
    { (self.challenge, self.mode) }
}

/// Fixed rejection categories; no boot argument or clipboard content is retained.
#[derive(Clone, Copy, Debug)]
pub enum BootError {
    /// A required challenge or normal-mode field is absent.
    Missing,
    /// Syntax, range or mode consistency was violated.
    Malformed,
    /// A recognized field appeared more than once.
    Duplicate,
}

/// Partial observations collected before constructing the typed boot decision.
pub struct BootParser {
    /// Valid challenge, absent until the deployment's argument is observed.
    challenge: Option<Challenge>,
    /// Valid GUI domain, absent for the isolated mode.
    authority: Option<Domain>,
    /// Valid volatile storage size, meaningful only with a GUI domain.
    scratch: Option<u64>,
}

/// Exact nonempty decimal word; checked arithmetic rejects overflow.
spec fn decimal_value(bytes: Seq<u8>) -> int
    decreases bytes.len(),
{
    if bytes.len() == 0 { 0 } else { decimal_value(bytes.drop_last()) * 10 + bytes.last() - b'0' }
}

/// A valid decimal suffix cannot reduce an already parsed nonnegative prefix.
proof fn decimal_prefix(bytes: Seq<u8>, prefix: int)
    requires 0 <= prefix <= bytes.len(), forall|i: int| 0 <= i < bytes.len() ==> b'0' <= #[trigger] bytes[i] <= b'9',
    ensures 0 <= decimal_value(bytes), 0 <= decimal_value(bytes.take(prefix)) <= decimal_value(bytes),
    decreases bytes.len(),
{
    if bytes.len() > 0 {
        if prefix < bytes.len() {
            decimal_prefix(bytes.drop_last(), prefix);
            assert(bytes.drop_last().take(prefix) == bytes.take(prefix));
        } else {
            decimal_prefix(bytes.drop_last(), bytes.len() as int - 1);
            assert(bytes.take(prefix) == bytes);
        }
    }
}

/// Complete decimal grammar including a representable machine word.
spec fn decimal_syntax(bytes: Seq<u8>) -> bool {
    0 < bytes.len() <= 20 && (forall|i: int| 0 <= i < bytes.len() ==> b'0' <= #[trigger] bytes[i] <= b'9')
        && 0 <= decimal_value(bytes) <= u64::MAX
}

/// Recognize one bounded decimal value without accepting signs, whitespace or overflow.
fn decimal(bytes: &[u8]) -> (out: Option<u64>)
    ensures out.is_some() == (0 < bytes@.len() <= 20
        && (forall|i: int| 0 <= i < bytes@.len() ==> b'0' <= #[trigger] bytes[i] <= b'9')
        && 0 <= decimal_value(bytes@) <= u64::MAX),
        out.is_some() ==> out.unwrap() == decimal_value(bytes@),
{
    if bytes.is_empty() || bytes.len() > 20 { return None; }
    let mut value = 0u64;
    let mut i = 0;
    while i < bytes.len()
        invariant i <= bytes.len(), 0 < bytes.len() <= 20,
            value == decimal_value(bytes@.take(i as int)),
            forall|j: int| 0 <= j < i ==> b'0' <= #[trigger] bytes[j] <= b'9',
        decreases bytes.len() - i,
    {
        let byte = bytes[i];
        if !ascii_digit(byte) { return None; }
        let digit = (byte - b'0') as u64;
        assert(bytes@.take(i as int + 1).drop_last() == bytes@.take(i as int));
        if value > (u64::MAX - digit) / 10 {
            proof {
                if decimal_syntax(bytes@) {
                    decimal_prefix(bytes@, i as int + 1);
                    assert(decimal_value(bytes@.take(i as int + 1)) == value * 10 + digit);
                    assert(false);
                }
            }
            return None;
        }
        value = value * 10 + digit;
        i += 1;
    }
    assert(bytes@.take(i as int) == bytes@);
    Some(value)
}

/// Prefix grammar shared by field admission and its executable matcher.
spec fn keyed(bytes: Seq<u8>, key: Seq<u8>) -> bool {
    key.len() <= bytes.len() && bytes.take(key.len() as int) == key
}

/// Match a fixed key before borrowing its suffix; unrelated Hermit arguments are ignored.
fn prefix(bytes: &[u8], key: &[u8]) -> (yes: bool)
    ensures yes == (key.len() <= bytes.len() && bytes@.take(key.len() as int) == key@),
{
    if bytes.len() < key.len() { return false; }
    let mut i = 0;
    while i < key.len()
        invariant i <= key.len(), key.len() <= bytes.len(), bytes@.take(i as int) == key@.take(i as int),
        decreases key.len() - i,
    {
        if bytes[i] != key[i] { return false; }
        i += 1;
    }
    assert(key@.take(key.len() as int) == key@);
    true
}

impl BootParser {
    /// A complete boot decision has its challenge and a paired authority/storage mode.
    pub closed spec fn complete(&self) -> bool {
        self.challenge.is_some() && (self.authority.is_none() || self.scratch.is_some())
    }

    /// Exact admission grammar for the next argument, including duplicate rejection.
    pub closed spec fn accepts(&self, argument: Seq<u8>) -> bool {
        if keyed(argument, BOOT_KEY@) {
            self.challenge.is_none() && challenge_bytes(argument.skip(13))
        } else if keyed(argument, AUTHORITY_KEY@) {
            self.authority.is_none() && decimal_syntax(argument.skip(18))
                && 0 < decimal_value(argument.skip(18)) < 0x7ff0
        } else if keyed(argument, SCRATCH_KEY@) {
            self.scratch.is_none() && decimal_syntax(argument.skip(16))
                && decimal_value(argument.skip(16)) >= crate::shared::DEFAULT_CAPACITY
                && decimal_value(argument.skip(16)) % 512 == 0
        } else { !keyed(argument, AIRLOCK_KEY@) }
    }

    /// Successful argument handling preserves every unrelated observation exactly.
    pub closed spec fn updated(&self, previous: &Self, argument: Seq<u8>) -> bool {
        if keyed(argument, BOOT_KEY@) {
            self.challenge.is_some() && self.challenge.unwrap().value() == argument.skip(13)
                && self.authority == previous.authority && self.scratch == previous.scratch
        } else if keyed(argument, AUTHORITY_KEY@) {
            self.authority.is_some() && self.authority.unwrap().identity() == decimal_value(argument.skip(18))
                && self.challenge == previous.challenge && self.scratch == previous.scratch
        } else if keyed(argument, SCRATCH_KEY@) {
            self.scratch == Some(decimal_value(argument.skip(16)) as u64)
                && self.challenge == previous.challenge && self.authority == previous.authority
        } else { *self == *previous }
    }

    /// Every retained observation was validated before installation.
    pub closed spec fn valid(&self) -> bool {
        (self.challenge.is_some() ==> challenge_bytes(self.challenge.unwrap().value()))
            && (self.authority.is_some() ==> 0 < self.authority.unwrap().identity() < 0x7ff0)
            && (self.scratch.is_some() ==> self.scratch.unwrap() >= crate::shared::DEFAULT_CAPACITY
                && self.scratch.unwrap() % 512 == 0)
    }

    /// No Airlock boot fields have been observed yet.
    pub closed spec fn empty(&self) -> bool {
        self.challenge.is_none() && self.authority.is_none() && self.scratch.is_none()
    }

    /// Begin collecting a finite deployment command line without allocation.
    pub fn new() -> (parser: Self)
        ensures parser.valid(), parser.empty(),
    { Self { challenge: None, authority: None, scratch: None } }

    /// Consume one argument and return the sole parser continuation on success.
    /// Rejection consumes the parser, preventing finish after an ignored error.
    /// Unknown airlock.* fields fail closed; unrelated upstream arguments are ignored.
    pub fn push(mut self, argument: &[u8]) -> (out: Result<Self, BootError>)
        requires self.valid(),
        ensures out.is_ok() == self.accepts(argument@),
            out.is_ok() ==> out.unwrap().valid() && out.unwrap().updated(&self, argument@),
    {
        if prefix(argument, &BOOT_KEY) {
            if self.challenge.is_some() { return Err(BootError::Duplicate); }
            self.challenge = Some(Challenge::parse(&argument[13..]).ok_or(BootError::Malformed)?);
        } else if prefix(argument, &AUTHORITY_KEY) {
            if self.authority.is_some() { return Err(BootError::Duplicate); }
            let raw = decimal(&argument[18..]).ok_or(BootError::Malformed)?;
            if raw > u16::MAX as u64 { return Err(BootError::Malformed); }
            self.authority = Some(Domain::from_raw(raw as u16).ok_or(BootError::Malformed)?);
        } else if prefix(argument, &SCRATCH_KEY) {
            if self.scratch.is_some() { return Err(BootError::Duplicate); }
            let bytes = decimal(&argument[16..]).ok_or(BootError::Malformed)?;
            if bytes < crate::shared::DEFAULT_CAPACITY as u64 || !bytes.is_multiple_of(512) { return Err(BootError::Malformed); }
            self.scratch = Some(bytes);
        } else if prefix(argument, &AIRLOCK_KEY) {
            return Err(BootError::Malformed);
        }
        Ok(self)
    }

    /// Publish only a complete challenge and a consistent isolated/connected mode.
    pub fn finish(self) -> (out: Result<BootConfig, BootError>)
        requires self.valid(),
        ensures out.is_ok() == self.complete(), out.is_ok() ==> out.unwrap().valid(),
    {
        let challenge = self.challenge.ok_or(BootError::Missing)?;
        let mode = match (self.authority, self.scratch) {
            (None, _) => Mode::Isolated,
            (Some(authority), Some(scratch_bytes)) => Mode::Connected { authority, scratch_bytes },
            _ => return Err(BootError::Missing),
        };
        Ok(BootConfig { challenge, mode })
    }
}


impl Default for BootParser {
    fn default() -> (parser: Self)
        ensures parser.valid(), parser.empty(),
    { Self::new() }
}

}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical deployment challenge used only by these controlled native cases.
    const CHALLENGE: &[u8] = b"airlock.boot=01234567-89ab-cdef-0123-456789abcdef";

    #[test]
    fn isolated_and_connected_contracts_require_complete_consistent_fields() {
        assert!(BootParser::new().finish().is_err());
        let parser = BootParser::new()
            .push(b"sys-clipboard")
            .unwrap()
            .push(CHALLENGE)
            .unwrap();
        let (challenge, mode) = parser.finish().unwrap().into_parts();
        assert_eq!(challenge.as_bytes(), &CHALLENGE[13..]);
        assert!(matches!(mode, Mode::Isolated));
        let parser = BootParser::new()
            .push(CHALLENGE)
            .unwrap()
            .push(b"airlock.authority=7")
            .unwrap()
            .push(b"airlock.scratch=67108864")
            .unwrap();
        assert!(
            matches!(parser.finish().unwrap().into_parts().1, Mode::Connected { authority, scratch_bytes: 67108864 } if authority.get() == 7)
        );
        assert!(
            BootParser::new()
                .push(CHALLENGE)
                .unwrap()
                .push(b"airlock.authority=7")
                .unwrap()
                .finish()
                .is_err()
        );
        assert!(
            BootParser::new()
                .push(CHALLENGE)
                .unwrap()
                .push(b"airlock.scratch=67108864")
                .unwrap()
                .finish()
                .is_ok()
        );
    }

    #[test]
    fn duplicate_unknown_overflow_reserved_and_noncanonical_fields_fail_closed() {
        assert!(matches!(
            BootParser::new().push(CHALLENGE).unwrap().push(CHALLENGE),
            Err(BootError::Duplicate)
        ));
        for input in [
            b"airlock.authority=0".as_slice(),
            b"airlock.authority=32752",
            b"airlock.authority=65536",
            b"airlock.authority=-1",
            b"airlock.authority= 7",
            b"airlock.authority=18446744073709551616",
            b"airlock.scratch=67108865",
            b"airlock.scratch=0",
            b"airlock.unrecognized=7",
            b"airlock.boot=------------------------------------",
            b"airlock.boot=0123456789ab-cdef-0123-456789abcdef",
        ] {
            assert!(BootParser::new().push(input).is_err());
        }
        assert_eq!(decimal(b"18446744073709551615"), Some(u64::MAX));
        assert_eq!(decimal(b"18446744073709551616"), None);
    }
}
