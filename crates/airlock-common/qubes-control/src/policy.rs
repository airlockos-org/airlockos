//! Per-source native policy completion, independent of full-database sync.
//! Dom0 removes a source's descendants, writes policy/rules, then writes an
//! empty value to its root. An old root survives those writes. Consequently an
//! initial dump never proves source completion, and live descendant changes
//! revoke the old snapshot until a new root write is consumed in stream order.
//!
//! Hostname rules remain explicit obligations, including drop rules. Milestone
//! 03 must resolve every obligation before activation; resolution failure blocks
//! the source. Like the pinned worker, resolution repeats on policy replacement,
//! rather than assuming an unsolicited periodic TTL refresh. Dom0 owns expiry:
//! it omits expired rules and rewrites policies from its existing expiry timer.
//! An unknown wire `expire` or `comment` option is rejected by the rule parser.

use alloc::vec::Vec;
use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
use crate::address;
use crate::address::Ip;
use crate::bytes::{copy, equal, find, prefix};
use crate::config::Config;
#[cfg(verus_keep_ghost)]
use crate::config::observed;
use crate::database::Cache;
#[cfg(verus_keep_ghost)]
use crate::database::MAX_ENTRIES;
use crate::number;
use crate::rule::{self, Action, Rule};

verus! {

/// Number of rules admitted per source, independently of four-digit rule IDs.
pub const MAX_RULES: usize = 256;

/// Exact source path prefix from the pinned network extension.
const FIREWALL: &[u8] = b"/qubes-firewall/";

/// Exact per-source path syntax, separate from arbitrary database key spelling.
pub open spec fn source_path(key: Seq<u8>, ip: Ip, end: int) -> bool {
    key.len() < 64 && key.len() >= 16 && key.subrange(0, 16) == b"/qubes-firewall/"@
        && address::cut(key.subrange(16, key.len() as int), end-16, b'/')
        && ip.describes(key.subrange(16, end))
}

/// One parsed path observation; it creates no interface or policy authority.
pub struct Path {
    /// Normalized source address from the exact authoritative key spelling.
    ip: Ip,
    /// End of the root, preceding any descendant slash.
    end: usize,
}

impl Path {
    /// Exact normalized source observation, never a packet-derived identity.
    pub closed spec fn source(&self) -> Ip { self.ip }

    /// Root byte boundary, preserving the native key spelling.
    pub closed spec fn end(&self) -> usize { self.end }

    /// Parse only the bounded firewall subtree. Unrelated or malformed keys
    /// never acquire a guessed source identity.
    pub fn parse(key: &[u8]) -> (path: Option<Self>)
        requires key@.len() < 64,
        ensures match path {
            Some(value) => value.source().valid() && source_path(key@, value.source(), value.end() as int),
            None => !(exists|ip: Ip, end: int| source_path(key@, ip, end)),
        },
    {
        if !prefix(key, FIREWALL) { return None; }
        let end = 16+find(&key[16..], b'/');
        let ip = Ip::parse(&key[16..end])?;
        Some(Self { ip, end })
    }

    /// Borrow the root slice from the exact key that was decoded. Callers must
    /// retain that correspondence rather than applying a saved offset to a new key.
    pub fn root<'a>(&self, key: &'a [u8]) -> (root: &'a [u8])
        requires source_path(key@, self.source(), self.end() as int),
        ensures root@ == key@.subrange(0, self.end() as int), root@.len() < 64,
    { &key[..self.end] }

    /// Exact private root boundary in the originally parsed key.
    pub fn boundary(&self) -> (end: usize)
        ensures end == self.end(),
    { self.end }

    /// Read the parsed source address without exposing mutable representation.
    pub fn ip(&self) -> (ip: &Ip)
        ensures *ip == self.source(), ip.valid(),
    { &self.ip }

    /// True only when this exact key is the source root, not a descendant.
    pub fn is_root(&self, key: &[u8]) -> (root: bool)
        requires source_path(key@, self.source(), self.end() as int),
        ensures root == (self.end() == key@.len()),
    { self.end == key.len() }
}

/// Four native decimal digits, including zero padding and sparse rule numbers.
pub open spec fn rule_id(bytes: Seq<u8>, id: int) -> bool {
    bytes.len() == 4 && number::digits(bytes, false) && number::decimal(bytes) == id
}

/// Decode all four digits; sparse ordering does not imply missing rules.
fn ordinal(bytes: &[u8]) -> (id: Option<u16>)
    requires bytes@.len() < 64,
    ensures match id {
        Some(value) => value <= 9999 && rule_id(bytes@, value as int),
        None => !(exists|value: int| rule_id(bytes@, value)),
    },
{
    if bytes.len() != 4 { return None; }
    number::parse(bytes, 9999, false).map(|value| value as u16)
}

/// Native mapped-IP path meaning, without granting authority to its source.
pub open spec fn mapped_path(key: Seq<u8>, ip: Ip, end: int) -> bool {
    11 <= key.len() < 64 && key.subrange(0, 11) == b"/mapped-ip/"@
        && address::cut(key.subrange(11, key.len() as int), end-11, b'/')
        && ip.describes(key.subrange(11, end))
}

/// Validate the pinned default mapping for a source. Qubes writes these keys
/// even without fake-IP features, so rejecting their mere presence would reject
/// ordinary clients. A changed visible IP/gateway or unknown child is explicitly
/// unsupported and blocks only this source. IPv6 currently has no native mapping.
pub fn mapping_supported(cache: &Cache, source: &Ip, config: &Config) -> (supported: bool)
    requires cache.valid(), source.valid(), config.valid(),
    ensures supported == (forall|i: int, ip: Ip, end: int|
        0 <= i < cache.entries().len() && mapped_path(cache.entries()[i].key(), ip, end)
            && ip.family() == source.family() && ip.words() == source.words()
            ==> end < cache.entries()[i].key().len() && (
                (cache.entries()[i].key().subrange(end+1, cache.entries()[i].key().len() as int) == b"visible-ip"@
                    && source.describes(cache.entries()[i].value()))
                || (cache.entries()[i].key().subrange(end+1, cache.entries()[i].key().len() as int) == b"visible-gateway"@
                    && config.provider_address().describes(cache.entries()[i].value())))),
{
    let entries = cache.all();
    let mut i = 0;
    while i < entries.len()
        invariant cache.valid(), source.valid(), config.valid(), i <= entries.len() <= MAX_ENTRIES,
        decreases entries.len()-i,
    {
        let key = entries[i].name();
        if prefix(key, b"/mapped-ip/") {
            let end = 11+find(&key[11..], b'/');
            if let Some(ip) = Ip::parse(&key[11..end])
                && ip.same(source) {
                    if end == key.len() { return false; }
                    let observed = match Ip::parse(entries[i].bytes()) { Some(value) => value, None => return false };
                    let child = &key[end+1..];
                    if equal(child, b"visible-ip") {
                        if !observed.same(source) { return false; }
                    } else if equal(child, b"visible-gateway") {
                        if !observed.same(config.provided_gateway()) { return false; }
                    } else { return false; }
                }
        }
        i += 1;
    }
    true
}

/// A typed rule and its native numeric ordering, with no positional guessing.
pub struct Ordered {
    /// Native four-digit rule number, independent of database enumeration order.
    id: u16,
    /// Fully interpreted supported options for exactly one source family.
    rule: Rule,
}

impl Ordered {
    /// Exact sparse native rule number.
    pub closed spec fn id(&self) -> u16 { self.id }

    /// Complete typed rule, separate from a packet decision.
    pub closed spec fn rule(&self) -> Rule { self.rule }

    /// Borrow a complete rule only after its containing snapshot was validated.
    pub fn entry(&self) -> (rule: &Rule)
        ensures *rule == self.rule(),
    { &self.rule }

    /// Native numeric order, useful for diagnostics and regression fixtures.
    pub fn number(&self) -> (id: u16)
        ensures id == self.id(),
    { self.id }
}

/// Observable reason a source cannot be activated. Every variant blocks that
/// source; malformed unrelated source policies do not invalidate a good source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejection {
    /// A source has no fresh live completion write after synchronization/update.
    Incomplete,
    /// Required root/default is absent or malformed.
    Default,
    /// Malformed option, duplicate/competing condition or unknown source child.
    Rule,
    /// Per-source rule capacity was exceeded.
    Capacity,
    /// Two spellings or duplicate normalized paths designate the same source.
    Alias,
    /// Native fake-IP/gateway mapping requires translation not implemented here.
    Mapping,
    /// At least one hostname requires successful resolution before activation.
    Dns,
    /// Complete global addressing/membership is unavailable.
    Configuration,
    /// The native control connection was lost; a fresh VM boot is required.
    Disconnected,
}

/// Exact complete policy for one source. This is validated data; runtime
/// transport ownership and a live interface are still needed for authorization.
pub struct Snapshot {
    /// Normalized authoritative source, independent of packet contents.
    pub(crate) source: Ip,
    /// Exact native root spelling used for completion and child correlation.
    root: Vec<u8>,
    /// Required native default disposition when no ordered rule matches.
    default: Action,
    /// At most MAX_RULES complete entries in ascending numeric order.
    rules: Vec<Ordered>,
    /// Whether a DNS obligation prevents immediate installation.
    pub(crate) unresolved: bool,
}

/// A child belongs to this exact source spelling, including its slash boundary.
pub open spec fn child_of(key: Seq<u8>, root: Seq<u8>) -> bool {
    key.len() > root.len() && key.subrange(0, root.len() as int) == root
        && key[root.len() as int] == b'/'
}

impl Snapshot {
    /// Typed source/default and bounded, unique, ordered same-family rules.
    pub closed spec fn valid(&self) -> bool {
        self.source.valid() && source_path(self.root@, self.source, self.root@.len() as int)
            && self.rules@.len() <= MAX_RULES
            && (forall|i: int| 0 <= i < self.rules@.len() ==> self.rules@[i].id() <= 9999
                && self.rules@[i].rule().valid() && self.rules@[i].rule().family == self.source.family())
            && (forall|i: int, j: int| 0 <= i < j < self.rules@.len() ==> self.rules@[i].id() < self.rules@[j].id())
            && self.unresolved == (exists|i: int| 0 <= i < self.rules@.len()
                && self.rules@[i].rule().has_hostname())
    }

    /// Exact root spelling whose marker published this snapshot.
    pub closed spec fn root_value(&self) -> Seq<u8> { self.root@ }

    /// Exact completed native record meanings. No rule can be silently omitted,
    /// added or reordered relative to its numeric key; all children are known.
    pub closed spec fn describes(&self, cache: Cache) -> bool {
        self.valid() && !cache.is_suppressed(self.source) && observed(cache, self.root@, Seq::empty())
            && (forall|i: int, ip: Ip, end: int| 0 <= i < cache.entries().len()
                && source_path(cache.entries()[i].key(), ip, end)
                && ip.family() == self.source.family() && ip.words() == self.source.words()
                ==> cache.entries()[i].key().subrange(0, end) == self.root@)
            && (exists|bytes: Seq<u8>| observed(cache, self.root@ + b"/policy"@, bytes)
                && rule::action_token(bytes, self.default))
            && (forall|i: int| 0 <= i < self.rules@.len() ==> exists|key: Seq<u8>, bytes: Seq<u8>|
                observed(cache, key, bytes) && child_of(key, self.root@)
                    && rule_id(key.subrange(self.root@.len() as int+1, key.len() as int), self.rules@[i].id() as int)
                    && self.rules@[i].rule().describes(bytes))
            && (forall|i: int| 0 <= i < cache.entries().len() && child_of(cache.entries()[i].key(), self.root@) ==>
                cache.entries()[i].key() == self.root@ + b"/policy"@
                || exists|j: int| 0 <= j < self.rules@.len()
                    && rule_id(cache.entries()[i].key().subrange(self.root@.len() as int+1, cache.entries()[i].key().len() as int), self.rules@[j].id() as int)
                    && self.rules@[j].rule().describes(cache.entries()[i].value()))
    }

    /// Collect a whole completed source using immutable replica observations.
    /// Initial roots are not eligible: the control owner calls this only for an
    /// actual live empty root WRITE. Unknown children reject the entire source.
    pub fn read(cache: &Cache, root: &[u8]) -> (result: Result<Self, Rejection>)
        requires cache.valid(), root@.len() < 64,
        ensures match result {
            Ok(value) => value.valid() && value.describes(*cache) && value.root@ == root@,
            Err(_) => !(exists|value: Snapshot| value.describes(*cache) && value.root@ == root@),
        },
    {
        let path = match Path::parse(root) { Some(value) => value, None => return Err(Rejection::Alias) };
        if !path.is_root(root) { return Err(Rejection::Alias); }
        if cache.source_suppressed(path.ip()) { return Err(Rejection::Capacity); }
        let marker = cache.read(root).ok_or(Rejection::Default)?;
        if !marker.is_empty() { return Err(Rejection::Default); }
        let mut default = None;
        let mut rules: Vec<Ordered> = Vec::new();
        let mut unresolved = false;
        let entries = cache.all();
        let mut i = 0;
        while i < entries.len()
            invariant i <= entries.len() <= MAX_ENTRIES, cache.valid(),
                root@.len() < 64, source_path(root@, path.source(), root@.len() as int),
                rules@.len() <= MAX_RULES,
                forall|j: int| 0 <= j < rules@.len() ==> rules@[j].rule().valid()
                    && rules@[j].rule().family == path.source().family() && rules@[j].id() <= 9999,
                forall|j: int, k: int| 0 <= j < k < rules@.len() ==> rules@[j].id() < rules@[k].id(),
                unresolved == (exists|j: int| 0 <= j < rules@.len() && rules@[j].rule().has_hostname()),
            decreases entries.len()-i,
        {
            let key = entries[i].name();
            if let Some(other) = Path::parse(key)
                && other.ip().same(path.ip()) && !equal(other.root(key), root) { return Err(Rejection::Alias); }
            if key.len() > root.len() && prefix(key, root) && key[root.len()] == b'/' {
                let child = &key[root.len()+1..];
                if equal(child, b"policy") {
                    default = match rule::action(entries[i].bytes()) { Some(value) => Some(value), None => return Err(Rejection::Default) };
                } else {
                    let id = match ordinal(child) { Some(value) => value, None => return Err(Rejection::Rule) };
                    let rule = match Rule::parse(entries[i].bytes(), path.ip().version()) { Some(value) => value, None => return Err(Rejection::Rule) };
                    if rules.len() == MAX_RULES { return Err(Rejection::Capacity); }
                    if rule.host().is_some() { unresolved = true; }
                    let mut at = 0;
                    while at < rules.len() && rules[at].number() < id
                        invariant at <= rules.len() <= MAX_RULES,
                            forall|j: int| 0 <= j < at ==> rules@[j].id() < id,
                        decreases rules.len()-at,
                    { at += 1; }
                    if at < rules.len() && rules[at].number() == id { return Err(Rejection::Alias); }
                    rules.insert(at, Ordered { id, rule });
                }
            }
            i += 1;
        }
        let default = match default { Some(value) => value, None => return Err(Rejection::Default) };
        Ok(Self { source: path.ip, root: copy(root), default, rules, unresolved })
    }

    /// Exact normalized source of this complete snapshot.
    pub fn source(&self) -> (source: &Ip)
        requires self.valid(), ensures *source == self.source, source.valid(),
    { &self.source }

    /// Borrow the exact native source root to construct its standard handled
    /// counter path. This is metadata, never a new transport/peer authority.
    pub fn root(&self) -> (root: &[u8])
        requires self.valid(), ensures root@ == self.root@,
            source_path(root@, self.source, root@.len() as int),
    { self.root.as_slice() }

    /// Required default disposition, never inferred from malformed/missing input.
    pub fn default_action(&self) -> (action: Action)
        requires self.valid(), ensures action == self.default,
    { self.default }

    /// Borrow all complete rules in their exact numeric order.
    pub fn rules(&self) -> (rules: &[Ordered])
        requires self.valid(), ensures rules@ == self.rules@, rules@.len() <= MAX_RULES,
    { self.rules.as_slice() }

    /// A whole-source DNS obligation; skipping only that rule is forbidden.
    pub fn unresolved(&self) -> (unresolved: bool)
        requires self.valid(), ensures unresolved == self.unresolved,
    { self.unresolved }
}

}
