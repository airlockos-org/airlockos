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
use vstd::slice::slice_to_vec;

#[cfg(verus_keep_ghost)]
use crate::address;
use crate::address::Ip;
use crate::cache::Cache;
use crate::config::Config;
#[cfg(verus_keep_ghost)]
use crate::config::observed;
use crate::number;
use crate::rule::{self, Action, Rule};

verus! {

broadcast use { vstd::seq::group_seq_lemmas, vstd::seq_lib::group_seq_properties, vstd::seq::Seq::lemma_as_ref_index, crate::address::cut_unique, Ip::unique };

/// Number of rules admitted per source, independently of four-digit rule IDs.
pub const MAX_RULES: usize = 256;

/// Exact per-source path syntax, separate from arbitrary database key spelling.
pub open spec fn source_path(key: Seq<u8>, ip: Ip, end: int) -> bool {
    key.len() < 64 && key.len() >= 16 && key.subrange(0, 16) == b"/qubes-firewall/"@
        && address::cut(key.subrange(16, key.len() as int), end-16, b'/')
        && ip.describes(key.subrange(16, end))
}

/// One native path has exactly one normalized source and root boundary.
pub proof fn source_unique(key: Seq<u8>, left: Ip, end: int, right: Ip, other: int)
    requires source_path(key, left, end), source_path(key, right, other),
    ensures left == right, end == other,
{
    address::cut_unique(key.subrange(16, key.len() as int), end-16, other-16, b'/');
    Ip::unique(left, right, key.subrange(16, end));
}

/// One parsed path observation; it creates no interface or policy authority.
pub struct Path {
    /// Normalized source address from the exact authoritative key spelling.
    ip: Ip,
    /// End of the root, preceding any descendant slash.
    end: usize,
}

impl Path {
    /// The normalized source and original bounded root boundary are valid.
    pub closed spec fn valid(&self) -> bool { self.ip.valid() && 16 < self.end < 64 }

    /// Exact normalized source observation, never a packet-derived identity.
    pub closed spec fn source(&self) -> Ip { self.ip }

    /// Root byte boundary, preserving the native key spelling.
    pub closed spec fn end(&self) -> usize { self.end }

    /// Parse only the bounded firewall subtree. Unrelated or malformed keys
    /// never acquire a guessed source identity.
    pub fn parse(key: &[u8]) -> (path: Option<Self>)
        requires key@.len() < 64,
        ensures match path {
            Some(value) => value.valid() && value.source().valid() && 16 < value.end() <= key@.len()
                && source_path(key@, value.source(), value.end() as int)
                && (forall|ip: Ip, end: int| #[trigger] source_path(key@, ip, end)
                    ==> ip == value.source() && end == value.end()),
            None => !(exists|ip: Ip, end: int| source_path(key@, ip, end)),
        },
    {
        if !key.starts_with(b"/qubes-firewall/") { return None; }
        proof { assert(key@.subrange(0, 16) =~= b"/qubes-firewall/"@); }
        let end = 16+key[16..].iter().position(|byte: &u8| -> (found: bool) ensures found == (*byte == b'/') { *byte == b'/' }).unwrap_or(key.len()-16);
        proof { assert(address::cut(key@.subrange(16, key@.len() as int), end-16, b'/')); }
        let ip = Ip::parse(&key[16..end])?;
        Some(Self { ip, end })
    }

    /// Borrow the root slice from the exact key that was decoded. Callers must
    /// retain that correspondence rather than applying a saved offset to a new key.
    pub fn root<'a>(&self, key: &'a [u8]) -> (root: &'a [u8])
        requires source_path(key@, self.source(), self.end() as int),
        ensures root@ == key@.subrange(0, self.end() as int), root@.len() < 64,
            source_path(root@, self.source(), root@.len() as int),
    {
        let root = &key[..self.end];
        proof {
            assert(root@.subrange(0, 16) =~= key@.subrange(0, 16));
            assert(root@.subrange(16, root@.len() as int) =~= key@.subrange(16, self.end() as int));
            assert(address::cut(root@.subrange(16, root@.len() as int), self.end()-16, b'/'));
        }
        root
    }

    /// Exact private root boundary in the originally parsed key.
    pub fn boundary(&self) -> (end: usize)
        ensures end == self.end(),
    { self.end }

    /// Read the parsed source address without exposing mutable representation.
    pub fn ip(&self) -> (ip: &Ip)
        requires self.valid(),
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
    proof {
        if number::digits(bytes@, false) {
            reveal_with_fuel(number::decimal, 5);
            assert(bytes@.drop_last().drop_last().drop_last().last() == bytes@[0]);
            assert(bytes@.drop_last().drop_last().last() == bytes@[1]);
            assert(bytes@.drop_last().last() == bytes@[2]);
            assert(bytes@.last() == bytes@[3]);
            assert(0 <= number::decimal(bytes@) <= 9999);
        }
    }
    number::parse(bytes, 9999, false).map(|value: u32| -> (id: u16)
        requires value <= 9999, ensures id as int == value,
        { value as u16 })
}

/// Native mapped-IP path meaning, without granting authority to its source.
pub open spec fn mapped_path(key: Seq<u8>, ip: Ip, end: int) -> bool {
    11 <= key.len() < 64 && key.subrange(0, 11) == b"/mapped-ip/"@
        && address::cut(key.subrange(11, key.len() as int), end-11, b'/')
        && ip.describes(key.subrange(11, end))
}

/// A record either belongs to another source or is one supported native mapping.
pub open spec fn mapping_record(key: Seq<u8>, value: Seq<u8>, source: Ip, config: Config) -> bool {
    forall|end: int| #[trigger] mapped_path(key, source, end) ==> end < key.len() && (
        (key.subrange(end+1, key.len() as int) == b"visible-ip"@ && source.describes(value))
        || (key.subrange(end+1, key.len() as int) == b"visible-gateway"@ && config.provided_gateway_value().describes(value)))
}

/// All current mapped-IP records preserve the source's native addressing.
pub open spec fn mapping_valid(cache: Cache, source: Ip, config: Config) -> bool {
    forall|i: int| 0 <= i < cache.entries().len() ==>
        mapping_record(cache.entries()[i].key(), cache.entries()[i].value(), source, config)
}

/// Check one complete native mapping record, without collecting or copying it.
fn supported_mapping(key: &[u8], value: &[u8], source: &Ip, config: &Config) -> (supported: bool)
    requires key@.len() < 64, source.valid(), config.valid(),
    ensures supported == mapping_record(key@, value@, *source, *config),
{
    if !key.starts_with(b"/mapped-ip/") { return true; }
    proof { assert(key@.subrange(0, 11) =~= b"/mapped-ip/"@); }
    let end = 11+key[11..].iter().position(|byte: &u8| -> (found: bool) ensures found == (*byte == b'/') { *byte == b'/' }).unwrap_or(key.len()-11);
    proof { assert(address::cut(key@.subrange(11, key@.len() as int), end-11, b'/')); }
    let ip = match Ip::parse(&key[11..end]) { Some(ip) => ip, None => return true };
    proof {
        assert forall|other: int| #[trigger] mapped_path(key@, *source, other) implies other == end && ip == *source by {
            address::cut_unique(key@.subrange(11, key@.len() as int), end-11, other-11, b'/');
            Ip::unique(ip, *source, key@.subrange(11, end as int));
        }
    }
    if !ip.same(source) { return true; }
    proof { assert(mapped_path(key@, *source, end as int)); }
    if end == key.len() { return false; }
    let observed = match Ip::parse(value) { Some(value) => value, None => return false };
    let child = &key[end+1..];
    if *child == *b"visible-ip".as_slice() {
        proof { assert(child@ =~= b"visible-ip"@); }
        let same = observed.same(source);
        proof { if source.describes(value@) { Ip::unique(observed, *source, value@); } }
        same
    } else if *child == *b"visible-gateway".as_slice() {
        proof { assert(child@ =~= b"visible-gateway"@); }
        let same = observed.same(config.provided_gateway());
        proof { if config.provided_gateway_value().describes(value@) { Ip::unique(observed, config.provided_gateway_value(), value@); } }
        same
    } else {
        proof {
            assert(child@ != b"visible-ip"@);
            assert(child@ != b"visible-gateway"@);
            assert(!mapping_record(key@, value@, *source, *config));
        }
        false
    }
}

/// Validate the pinned default mapping for a source. Qubes writes these keys
/// even without fake-IP features, so rejecting their mere presence would reject
/// ordinary clients. A changed visible IP/gateway or unknown child is explicitly
/// unsupported and blocks only this source. IPv6 currently has no native mapping.
pub fn mapping_supported(cache: &Cache, source: &Ip, config: &Config) -> (supported: bool)
    requires cache.valid(), source.valid(), config.valid(),
    ensures supported == mapping_valid(*cache, *source, *config),
{
    for (key, value) in cursor: cache.all()
        invariant cache.valid(), source.valid(), config.valid(),
            cursor.seq().len() == cache.entries().len(),
            forall|i: int| 0 <= i < cursor.seq().len() ==> cursor.seq()[i].0@ == cache.entries()[i].key()
                && cursor.seq()[i].1@ == cache.entries()[i].value() && cursor.seq()[i].0@.len() < 64,
            forall|i: int| 0 <= i < cursor.index() ==>
                mapping_record(cache.entries()[i].key(), cache.entries()[i].value(), *source, *config),
    {
        if !supported_mapping(key.as_slice(), value.as_slice(), source, config) {
            proof {
                assert(!mapping_record(cache.entries()[cursor.index()].key(), cache.entries()[cursor.index()].value(), *source, *config));
                assert(!mapping_valid(*cache, *source, *config));
            }
            return false;
        }
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

/// Numeric IDs are unique and every rule belongs to the same source family.
closed spec fn ordered(rules: Seq<Ordered>, family: u8) -> bool {
    rules.len() <= MAX_RULES
        && (forall|i: int| 0 <= i < rules.len() ==> rules[i].id() <= 9999
            && rules[i].rule().valid() && rules[i].rule().family_value() == family)
        && (forall|i: int, j: int| 0 <= i < j < rules.len() ==> rules[i].id() < rules[j].id())
}

/// Insert a complete entry with Vec's insertion primitive. The bounded search
/// preserves numeric order independently of the database's byte-key order.
fn insert_ordered(rules: &mut Vec<Ordered>, id: u16, rule: Rule) -> (inserted: bool)
    requires ordered(old(rules)@, rule.family_value()), old(rules)@.len() < MAX_RULES,
        id <= 9999, rule.valid(),
    ensures ordered(final(rules)@, rule.family_value()),
        inserted == !(exists|i: int| 0 <= i < old(rules)@.len() && old(rules)@[i].id() == id),
        !inserted ==> final(rules)@ == old(rules)@,
        inserted ==> final(rules)@.len() == old(rules)@.len()+1
            && final(rules)@.contains(Ordered { id, rule })
            && (forall|entry: Ordered| final(rules)@.contains(entry) == (old(rules)@.contains(entry) || entry == Ordered { id, rule })),
{
    let mut at = 0;
    while at < rules.len() && rules[at].number() < id
        invariant rules@ == old(rules)@, ordered(rules@, rule.family_value()),
            rule.valid(), id <= 9999, at <= rules.len() < MAX_RULES,
            forall|j: int| 0 <= j < at ==> rules@[j].id() < id,
        decreases rules.len()-at,
    { at += 1; }
    if at < rules.len() && rules[at].number() == id { return false; }
    let ghost previous = rules@;
    rules.insert(at, Ordered { id, rule });
    proof { previous.insert_ensures(at as int, Ordered { id, rule }); }
    true
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

/// Every non-default child consumes one of the finite native rule slots.
closed spec fn rule_records(cache: Cache, root: Seq<u8>, count: int) -> int {
    crate::cache::selected_count(cache.entries(), |entry: crate::cache::Entry|
        child_of(entry.key(), root) && entry.key() != root + b"/policy"@, count)
}

/// A typed ordered entry corresponds to this exact native child and body.
closed spec fn entry_matches(entry: Ordered, key: Seq<u8>, value: Seq<u8>, root: Seq<u8>) -> bool {
    child_of(key, root) && rule_id(key.subrange(root.len() as int+1, key.len() as int), entry.id() as int)
        && entry.rule().describes(value)
}

/// Exact meanings of the entries collected from the inspected cache prefix.
#[verifier::opaque]
closed spec fn collected(cache: Cache, root: Seq<u8>, source: Ip, rules: Seq<Ordered>, count: int) -> bool {
    ordered(rules, source.family())
        && (forall|i: int, ip: Ip, end: int| 0 <= i < count
            && source_path(cache.entries()[i].key(), ip, end) && ip == source
            ==> cache.entries()[i].key().subrange(0, end) == root)
        && (forall|entry: Ordered| rules.contains(entry) ==> exists|j: int| 0 <= j < count
            && entry_matches(entry, cache.entries()[j].key(), cache.entries()[j].value(), root))
        && (forall|i: int| 0 <= i < count && child_of(cache.entries()[i].key(), root) ==>
            cache.entries()[i].key() == root + b"/policy"@
            || exists|entry: Ordered| rules.contains(entry)
                && entry_matches(entry, cache.entries()[i].key(), cache.entries()[i].value(), root))
}

/// Moving to the next cache record preserves all previous rule meanings.
proof fn collect_next(cache: Cache, root: Seq<u8>, source: Ip, before: Seq<Ordered>, after: Seq<Ordered>, index: int)
    requires 0 <= index < cache.entries().len(), collected(cache, root, source, before, index),
        ordered(after, source.family()),
        forall|entry: Ordered| before.contains(entry) ==> after.contains(entry),
        forall|entry: Ordered| after.contains(entry) && !before.contains(entry)
            ==> entry_matches(entry, cache.entries()[index].key(), cache.entries()[index].value(), root),
        forall|ip: Ip, end: int| source_path(cache.entries()[index].key(), ip, end) && ip == source
            ==> cache.entries()[index].key().subrange(0, end) == root,
        child_of(cache.entries()[index].key(), root) ==> cache.entries()[index].key() == root + b"/policy"@
            || exists|entry: Ordered| after.contains(entry)
                && entry_matches(entry, cache.entries()[index].key(), cache.entries()[index].value(), root),
    ensures collected(cache, root, source, after, index+1),
{
    reveal(collected);
    assert forall|entry: Ordered| after.contains(entry) implies exists|j: int| 0 <= j < index+1
        && entry_matches(entry, cache.entries()[j].key(), cache.entries()[j].value(), root) by {
        if !before.contains(entry) { assert(entry_matches(entry, cache.entries()[index].key(), cache.entries()[index].value(), root)); }
    }
}

/// The exact slash boundary separates a native root from its complete child.
proof fn join_child(key: Seq<u8>, root: Seq<u8>)
    requires child_of(key, root),
    ensures key == root + b"/"@ + key.subrange(root.len() as int+1, key.len() as int),
{
    reveal_byteslit(b"/");
    let joined = root + b"/"@ + key.subrange(root.len() as int+1, key.len() as int);
    assert forall|i: int| 0 <= i < key.len() implies key[i] == joined[i] by {
        if i < root.len() { assert(key[i] == root[i]); }
        else if i == root.len() { assert(key[i] == b'/'); }
        else { assert(joined[i] == key.subrange(root.len() as int+1, key.len() as int)[i-root.len()-1]); }
    }
    assert(key =~= joined);
}

/// The one required default has either been collected or is absent from the prefix.
closed spec fn default_seen(cache: Cache, root: Seq<u8>, default: Option<Action>, count: int) -> bool {
    match default {
        Some(action) => exists|i: int| 0 <= i < count && cache.entries()[i].key() == root+b"/policy"@
            && rule::action_token(cache.entries()[i].value(), action),
        None => forall|i: int| 0 <= i < count ==> cache.entries()[i].key() != root+b"/policy"@,
    }
}

/// Extending the inspected prefix either observes its sole default or preserves it.
proof fn default_next(cache: Cache, root: Seq<u8>, before: Option<Action>, after: Option<Action>, index: int)
    requires 0 <= index < cache.entries().len(), default_seen(cache, root, before, index),
        (cache.entries()[index].key() != root+b"/policy"@ && after == before)
            || (cache.entries()[index].key() == root+b"/policy"@ && after.is_some()
                && rule::action_token(cache.entries()[index].value(), after.unwrap())),
    ensures default_seen(cache, root, after, index+1),
{ }

/// Any unresolved hostname obligation blocks publication of the whole source.
closed spec fn dns_pending(rules: Seq<Ordered>) -> bool {
    exists|entry: Ordered| rules.contains(entry) && entry.rule().has_hostname()
}

/// The independently meaningful outcome of interpreting one native database record.
enum Child {
    /// The record has no child under this source's exact native root.
    Other,
    /// The source's one required default disposition.
    Default(/// Validated native action, independent of rule ordering.
        Action),
    /// A whole same-family rule with its native sparse numeric identifier.
    Rule(/// Complete rule data; insertion and source capacity are checked separately.
        Ordered),
}

/// A record preserves source spelling and, if a child, has a supported meaning.
closed spec fn admissible(key: Seq<u8>, value: Seq<u8>, root: Seq<u8>, source: Ip) -> bool {
    (forall|end: int| source_path(key, source, end) ==> key.subrange(0, end) == root)
        && (!child_of(key, root)
            || (key == root+b"/policy"@ && exists|action: Action| rule::action_token(value, action))
            || (key != root+b"/policy"@ && (exists|id: int| #[trigger] rule_id(key.subrange(root.len() as int+1, key.len() as int), id))
                && rule::well_formed(value, source.family())))
}

/// Interpret one bounded record with the existing address, action and rule
/// parsers. This does not mutate the cache or publish a partial source policy.
#[verifier::rlimit(20)]
fn inspect(key: &[u8], value: &[u8], root: &[u8], source: &Ip) -> (result: Result<Child, Rejection>)
    requires key@.len() < 64, root@.len() < 64, source.valid(),
        source_path(root@, *source, root@.len() as int),
    ensures result.is_ok() == admissible(key@, value@, root@, *source),
        match result {
            Ok(Child::Other) => !child_of(key@, root@),
            Ok(Child::Default(action)) => key@ == root@+b"/policy"@ && rule::action_token(value@, action),
            Ok(Child::Rule(entry)) => entry.id() <= 9999 && entry.rule().valid()
                && entry.rule().family_value() == source.family() && key@ != root@+b"/policy"@
                && entry_matches(entry, key@, value@, root@),
            Err(_) => true,
        },
{
    proof { reveal_byteslit(b"/"); reveal_byteslit(b"policy"); reveal_byteslit(b"/policy"); }
    match Path::parse(key) {
        Some(other) if other.ip().same(source) && other.root(key) != root => return Err(Rejection::Alias),
        _ => (),
    }
    proof {
        assert forall|end: int| source_path(key@, *source, end) implies key@.subrange(0, end) == root@ by { }
    }
    if !(key.len() > root.len() && key.starts_with(root) && key[root.len()] == b'/') { return Ok(Child::Other); }
    proof { assert(key@.subrange(0, root@.len() as int) =~= root@); join_child(key@, root@); }
    let child = &key[root.len()+1..];
    if *child == *b"policy".as_slice() {
        proof { assert(child@ =~= b"policy"@); assert((b"/"@ + b"policy"@) =~= b"/policy"@); assert(key@ =~= root@ + b"/policy"@); }
        match rule::action(value) { Some(action) => Ok(Child::Default(action)), None => Err(Rejection::Default) }
    } else {
        proof { if key@ == root@ + b"/policy"@ { assert(child@ =~= b"policy"@); } }
        let id = ordinal(child).ok_or(Rejection::Rule)?;
        let rule = Rule::parse(value, source.version()).ok_or(Rejection::Rule)?;
        Ok(Child::Rule(Ordered { id, rule }))
    }
}

/// A fresh record cannot reuse a previously inspected four-digit rule number.
proof fn fresh_number(cache: Cache, root: Seq<u8>, source: Ip, rules: Seq<Ordered>, index: int, entry: Ordered)
    requires 0 <= index < cache.entries().len(), collected(cache, root, source, rules, index),
        entry_matches(entry, cache.entries()[index].key(), cache.entries()[index].value(), root),
        forall|i: int, j: int| 0 <= i < j < cache.entries().len() ==> cache.entries()[i].key() != cache.entries()[j].key(),
    ensures forall|i: int| 0 <= i < rules.len() ==> rules[i].id() != entry.id(),
{
    reveal(collected);
    assert forall|i: int| 0 <= i < rules.len() implies rules[i].id() != entry.id() by {
        if rules[i].id() == entry.id() {
            assert(rules.contains(rules[i]));
            let j = choose|j: int| 0 <= j < index
                && entry_matches(rules[i], cache.entries()[j].key(), cache.entries()[j].value(), root);
            number::decimal_unique(cache.entries()[index].key().subrange(root.len() as int+1, cache.entries()[index].key().len() as int),
                cache.entries()[j].key().subrange(root.len() as int+1, cache.entries()[j].key().len() as int));
            join_child(cache.entries()[index].key(), root);
            join_child(cache.entries()[j].key(), root);
            assert(cache.entries()[index].key() == cache.entries()[j].key());
        }
    }
}

impl Snapshot {
    /// Exact source retained by this completed source policy.
    pub closed spec fn source_value(&self) -> Ip { self.source }

    /// Exact default retained by this completed source policy.
    pub closed spec fn default_value(&self) -> Action { self.default }

    /// Exact rules retained by this completed source policy.
    pub closed spec fn rules_value(&self) -> Seq<Ordered> { self.rules@ }

    /// Exact unresolved retained by this completed source policy.
    pub closed spec fn unresolved_value(&self) -> bool { self.unresolved }

    /// Typed source/default and bounded, unique, ordered same-family rules.
    pub closed spec fn valid(&self) -> bool {
        self.source.valid() && source_path(self.root@, self.source, self.root@.len() as int)
            && self.rules@.len() <= MAX_RULES
            && (forall|i: int| 0 <= i < self.rules@.len() ==> self.rules@[i].id() <= 9999
                && self.rules@[i].rule().valid() && self.rules@[i].rule().family_value() == self.source.family())
            && (forall|i: int, j: int| 0 <= i < j < self.rules@.len() ==> self.rules@[i].id() < self.rules@[j].id())
            && self.unresolved == dns_pending(self.rules@)
    }

    /// Exact root spelling whose marker published this snapshot.
    pub closed spec fn root_value(&self) -> Seq<u8> { self.root@ }

    /// Exact completed native record meanings. No rule can be silently omitted,
    /// added or reordered relative to its numeric key; all children are known.
    pub closed spec fn describes(&self, cache: Cache) -> bool {
        self.valid() && !cache.is_suppressed(self.source) && observed(cache, self.root@, Seq::empty())
            && rule_records(cache, self.root@, cache.entries().len() as int) <= MAX_RULES
            && collected(cache, self.root@, self.source, self.rules@, cache.entries().len() as int)
            && (exists|bytes: Seq<u8>| observed(cache, self.root@ + b"/policy"@, bytes)
                && rule::action_token(bytes, self.default))
    }

    /// Every hostname in one complete interpretation is also an obligation in
    /// another interpretation of the same immutable completed source records.
    proof fn dns_included(&self, other: Self, cache: Cache)
        requires self.describes(cache), other.describes(cache), self.root@ == other.root@,
        ensures self.unresolved ==> other.unresolved,
    {
        reveal(collected);
        if self.unresolved {
            let entry = choose|entry: Ordered| self.rules@.contains(entry) && entry.rule().has_hostname();
            let index = choose|index: int| 0 <= index < cache.entries().len()
                && entry_matches(entry, cache.entries()[index].key(), cache.entries()[index].value(), self.root@);
            assert(cache.entries()[index].key() != self.root@+b"/policy"@);
            let replacement = choose|replacement: Ordered| other.rules@.contains(replacement)
                && entry_matches(replacement, cache.entries()[index].key(), cache.entries()[index].value(), other.root@);
            entry.rule().hostname_agrees(replacement.rule(), cache.entries()[index].value());
            assert(dns_pending(other.rules@));
        }
    }

    /// The exact completed bytes determine whether the whole source needs DNS.
    pub proof fn dns_agrees(&self, other: Self, cache: Cache)
        requires self.describes(cache), other.describes(cache), self.root_value() == other.root_value(),
        ensures self.unresolved_value() == other.unresolved_value(),
    {
        self.dns_included(other, cache);
        other.dns_included(*self, cache);
    }

    /// A complete snapshot gives every cache record a supported source-local meaning.
    proof fn record_admissible(&self, cache: Cache, index: int)
        requires self.describes(cache), 0 <= index < cache.entries().len(),
            forall|i: int, j: int| 0 <= i < j < cache.entries().len() ==> cache.entries()[i].key() != cache.entries()[j].key(),
        ensures admissible(cache.entries()[index].key(), cache.entries()[index].value(), self.root@, self.source),
    {
        reveal(collected);
        if child_of(cache.entries()[index].key(), self.root@) {
            if cache.entries()[index].key() == self.root@+b"/policy"@ {
                let bytes = choose|bytes: Seq<u8>| observed(cache, self.root@+b"/policy"@, bytes) && rule::action_token(bytes, self.default);
                let j = choose|j: int| 0 <= j < cache.entries().len() && cache.entries()[j].key() == self.root@+b"/policy"@ && cache.entries()[j].value() == bytes;
                assert(j == index);
                assert(bytes == cache.entries()[index].value());
            } else {
                let entry = choose|entry: Ordered| self.rules@.contains(entry)
                    && entry_matches(entry, cache.entries()[index].key(), cache.entries()[index].value(), self.root@);
                let j = choose|j: int| 0 <= j < self.rules@.len() && self.rules@[j] == entry;
                assert(rule::well_formed(cache.entries()[index].value(), self.source.family()));
            }
        }
    }

    /// Collect a whole completed source using immutable replica observations.
    /// Initial roots are not eligible: the control owner calls this only for an
    /// actual live empty root WRITE. Unknown children reject the entire source.
    #[verifier::rlimit(60)]
    pub fn read(cache: &Cache, root: &[u8]) -> (result: Result<Self, Rejection>)
        requires cache.valid(), root@.len() < 64,
        ensures match result {
            Ok(value) => value.valid() && value.describes(*cache) && value.root_value() == root@
                && source_path(root@, value.source_value(), root@.len() as int),
            Err(_) => !(exists|value: Snapshot| value.describes(*cache) && value.root_value() == root@),
        },
    {
        proof { reveal_byteslit(b"/"); reveal_byteslit(b"policy"); reveal_byteslit(b"/policy"); }
        let path = match Path::parse(root) { Some(value) => value, None => return Err(Rejection::Alias) };
        if !path.is_root(root) { return Err(Rejection::Alias); }
        if cache.source_suppressed(path.ip()) { return Err(Rejection::Capacity); }
        let marker = cache.read(root).ok_or(Rejection::Default)?;
        if !marker.is_empty() { return Err(Rejection::Default); }
        proof {
            assert(marker@ =~= Seq::<u8>::empty());
            assert(observed(*cache, root@, Seq::empty()));
            assert forall|candidate: Snapshot| candidate.describes(*cache) && candidate.root_value() == root@
                implies candidate.source_value() == path.source() by {
                source_unique(root@, candidate.source_value(), root@.len() as int, path.source(), root@.len() as int);
            }
        }
        let mut default: Option<Action> = None;
        let mut rules: Vec<Ordered> = Vec::new();
        let mut unresolved = false;
        proof { assert(collected(*cache, root@, path.source(), rules@, 0)) by { reveal(collected); } }
        for (key, value) in cursor: cache.all()
            invariant cache.valid(), path.valid(), source_path(root@, path.source(), root@.len() as int),
                path.source().valid(), !cache.is_suppressed(path.source()), observed(*cache, root@, Seq::empty()),
                root@.len() < 64, path.end() == root@.len(),
                forall|candidate: Snapshot| candidate.describes(*cache) && candidate.root_value() == root@
                    ==> candidate.source_value() == path.source(),
                cursor.seq().len() == cache.entries().len(),
                forall|i: int| 0 <= i < cursor.seq().len() ==> cursor.seq()[i].0@ == cache.entries()[i].key()
                    && cursor.seq()[i].1@ == cache.entries()[i].value()
                    && 0 < cursor.seq()[i].0@.len() < 64 && cursor.seq()[i].1@.len() <= crate::wire::MAX_VALUE,
                forall|i: int, j: int| 0 <= i < j < cache.entries().len() ==> cache.entries()[i].key() != cache.entries()[j].key(),
                collected(*cache, root@, path.source(), rules@, cursor.index()),
                ordered(rules@, path.source().family()),
                default_seen(*cache, root@, default, cursor.index()),
                rules@.len() == rule_records(*cache, root@, cursor.index()),
                unresolved == dns_pending(rules@),
        {
            proof { reveal_byteslit(b"/"); reveal_byteslit(b"policy"); reveal_byteslit(b"/policy"); }
            let ghost index = cursor.index();
            let ghost previous = rules@;
            let ghost previous_default = default;
            proof {
                assert(cache.entries()[index].key() == key@);
                assert(cache.entries()[index].value() == value@);
            }
            let child = match inspect(key.as_slice(), value.as_slice(), root, path.ip()) {
                Ok(child) => child,
                Err(reason) => {
                    proof {
                        assert forall|candidate: Snapshot| candidate.root_value() == root@
                            implies !candidate.describes(*cache) by {
                            if candidate.describes(*cache) { candidate.record_admissible(*cache, index); }
                        }
                    }
                    return Err(reason);
                }
            };
            match child {
                Child::Other => (),
                Child::Default(action) => { default = Some(action); }
                Child::Rule(entry) => {
                    if rules.len() == MAX_RULES {
                        proof {
                            crate::cache::accounting::count_monotone(cache.entries(), |entry: crate::cache::Entry|
                                child_of(entry.key(), root@) && entry.key() != root@ + b"/policy"@,
                                index+1, cache.entries().len() as int);
                            assert(rule_records(*cache, root@, index+1) == rules@.len()+1);
                        }
                        return Err(Rejection::Capacity);
                    }
                    if entry.rule.host().is_some() { unresolved = true; }
                    proof { fresh_number(*cache, root@, path.source(), rules@, index, entry); }
                    if !insert_ordered(&mut rules, entry.id, entry.rule) { return Err(Rejection::Alias); }
                }
            }
            proof {
                collect_next(*cache, root@, path.source(), previous, rules@, index);
                default_next(*cache, root@, previous_default, default, index);
            }
        }
        let default = match default { Some(value) => value, None => return Err(Rejection::Default) };
        Ok(Self { source: path.ip, root: slice_to_vec(root), default, rules, unresolved })
    }

    /// Exact normalized source of this complete snapshot.
    pub fn source(&self) -> (source: &Ip)
        requires self.valid(), ensures *source == self.source_value(), source.valid(),
    { &self.source }

    /// Borrow the exact native source root to construct its standard handled
    /// counter path. This is metadata, never a new transport/peer authority.
    pub fn root(&self) -> (root: &[u8])
        requires self.valid(), ensures root@ == self.root_value(),
            source_path(root@, self.source_value(), root@.len() as int),
    { self.root.as_slice() }

    /// Required default disposition, never inferred from malformed/missing input.
    pub fn default_action(&self) -> (action: Action)
        requires self.valid(), ensures action == self.default_value(),
    { self.default }

    /// Borrow all complete rules in their exact numeric order.
    pub fn rules(&self) -> (rules: &[Ordered])
        requires self.valid(), ensures rules@ == self.rules_value(), rules@.len() <= MAX_RULES,
            forall|i: int| 0 <= i < rules@.len() ==> rules@[i].rule().valid()
                && rules@[i].rule().family_value() == self.source_value().family(),
    { self.rules.as_slice() }

    /// A whole-source DNS obligation; skipping only that rule is forbidden.
    pub fn unresolved(&self) -> (unresolved: bool)
        requires self.valid(), ensures unresolved == self.unresolved_value(),
    { self.unresolved }
}

}
