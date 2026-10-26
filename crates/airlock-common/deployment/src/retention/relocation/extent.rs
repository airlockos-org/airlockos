//! Confine fragment reads to the exact claimed backing and a positive bounded byte range.
//! The adapter derives the canonical path, observes the open file and authenticates bytes.
//! These checks preserve those supplied identities; they do not prove pathname resolution,
//! SHA-256 correctness, truthful metadata, filesystem exclusion or durable publication.

#[cfg(verus_keep_ghost)]
use super::valid_location;

use super::{Location, location_valid};
use vstd::prelude::*;

verus! {

/// Metadata from the canonical backing file opened by the storage adapter.
pub struct Backing {
    /// Path derived from the requested pool and validated segment ID.
    pub path: String,
    /// Byte length of the same open file whose contents will be checked.
    pub length: u64,
    /// Only a regular file can supply an immutable fragment.
    pub regular: bool,
}

/// Lowercase hexadecimal syntax of one SHA-256 digest, independent of the parser loop.
pub open spec fn digest_valid(bytes: Seq<u8>) -> bool {
    bytes.len() == 64 && forall|i: int| 0 <= i < bytes.len() ==>
        (b'0' <= #[trigger] bytes[i] <= b'9' || b'a' <= bytes[i] <= b'f')
}

fn check_digest(digest: &str) -> (yes: bool)
    ensures yes == digest_valid(vstd::utf8::encode_utf8(digest@)),
{
    let bytes = digest.as_bytes();
    if bytes.len() != 64 { return false; }
    let mut i = 0;
    while i < bytes.len()
        invariant 0 <= i <= bytes.len(), bytes.len() == 64,
            bytes@ == vstd::utf8::encode_utf8(digest@),
            forall|j: int| 0 <= j < i ==>
                (b'0' <= #[trigger] bytes[j] <= b'9' || b'a' <= bytes[j] <= b'f'),
        decreases bytes.len() - i,
    {
        let byte = bytes[i];
        match byte {
            b'0'..=b'9' | b'a'..=b'f' => {},
            _ => return false,
        }
        i += 1;
    }
    true
}

/// Physical validity requires exact backing identity, digest syntax and mathematical containment.
pub open spec fn accepted(location: Location, recorded_path: Seq<char>, observed: Backing) -> bool {
    valid_location(location) && digest_valid(vstd::utf8::encode_utf8(location.digest@))
        && recorded_path == observed.path@ && observed.path@.len() > 0 && observed.regular
        && location.offset + location.size <= observed.length
}

/// A structurally checked read retains the original coordinates and open-file observation.
/// Content authentication remains an adapter duty, including when metadata-only checks are used.
///
/// ```compile_fail
/// use airlock_deployment_core::retention::relocation::{Location, extent::{Backing, CheckedExtent}};
/// /// Raw coordinates and metadata cannot manufacture a checked read.
/// fn forge(location: Location, backing: Backing) -> CheckedExtent {
///     CheckedExtent { location, backing }
/// }
/// ```
pub struct CheckedExtent {
    /// Exact physical coordinates and expected fragment digest supplied for validation.
    location: Location,
    /// Original backing identity, file type and length observed by the adapter.
    backing: Backing,
}

impl View for CheckedExtent {
    type V = (Location, Backing);

    closed spec fn view(&self) -> Self::V { (self.location, self.backing) }
}

impl CheckedExtent {
    #[verifier::type_invariant]
    closed spec fn valid(&self) -> bool { accepted(self.location, self.backing.path@, self.backing) }

    /// Reject redirected files, malformed digests and empty, overflowing or out-of-file ranges.
    pub fn check(location: Location, recorded_path: &str, backing: Backing) -> (out: Option<Self>)
        ensures out.is_some() == accepted(location, recorded_path@, backing),
            out.is_some() ==> out.unwrap()@ == (location, backing),
    {
        if !location_valid(&location) || !check_digest(location.digest.as_str())
            || recorded_path != backing.path.as_str() || backing.path.is_empty() || !backing.regular {
            return None;
        }
        if location.offset > backing.length || location.size > backing.length - location.offset {
            return None;
        }
        Some(Self { location, backing })
    }

    /// Select only the original coordinates and digest for seeking, hashing and cache identity.
    pub fn location(&self) -> (out: &Location)
        ensures *out == self@.0, valid_location(*out),
            out.offset + out.size <= self@.1.length,
    {
        proof { use_type_invariant(self); }
        &self.location
    }

    /// Retain the canonical path matched against the supplied extent's backing identity.
    pub fn backing(&self) -> (out: &str)
        ensures out@ == self@.1.path@,
    { self.backing.path.as_str() }

    /// Compute the exclusive byte boundary without wrapping and within the observed file.
    pub fn end(&self) -> (out: u64)
        ensures out == self@.0.offset + self@.0.size, out <= self@.1.length,
    {
        proof { use_type_invariant(self); }
        self.location.offset + self.location.size
    }

    /// Feed relocation the same checked coordinates, without a second target supplied by a caller.
    pub fn into_location(self) -> (out: Location)
        ensures out == self@.0, valid_location(out), out.offset + out.size <= self@.1.length,
    {
        proof { use_type_invariant(&self); }
        self.location
    }
}

}
