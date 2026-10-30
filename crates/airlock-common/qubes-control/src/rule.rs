//! Pinned Qubes firewall option grammar, independent of packet matching.
//! core-admin 4.3.44 serializes only action/proto/dst4/dst6/dsthost/dstports/
//! specialtarget/icmptype. Expiry is enforced by dom0's timer and ordinary
//! policy rewrites; it is not an additional guest-side wire option.
//!
//! Compatibility decisions: reject duplicate options instead of Python dict's
//! last-value replacement, competing destinations instead of ignored fields,
//! and ports above 65535 (the admin parser permits 65536 but native packet
//! ports/nft cannot implement it). Unknown options and any malformed condition
//! reject the entire affected source. No condition is silently discarded.
//! A contradictory DNS/port condition is retained as a matches-none rule, as
//! in the pinned worker. Hostname values remain unresolved obligations: failure
//! to resolve every hostname blocks the source, including unresolved drop rules.

use alloc::vec::Vec;
use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
use crate::address;
use crate::address::Ip;
use crate::bytes::{copy, equal, find, in_range};
use crate::number;

verus! {

/// At most this many ordered rules can belong to one source snapshot.
pub const MAX_RULES: usize = 256;

/// Exact native rule disposition; default actions use the same two values.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Matching traffic may proceed to the consumer's other security checks.
    Accept,
    /// Matching traffic is denied, including already-established denied flows.
    Drop,
}

/// Exact observable semantics of a default-action token.
pub open spec fn action_token(bytes: Seq<u8>, action: Action) -> bool {
    match action { Action::Accept => bytes == b"accept"@, Action::Drop => bytes == b"drop"@ }
}

/// Decode a complete action token; no empty or unknown default becomes accept.
pub fn action(bytes: &[u8]) -> (action: Option<Action>)
    requires bytes@.len() <= 4096,
    ensures match action {
        Some(value) => action_token(bytes@, value),
        None => !(exists|value: Action| action_token(bytes@, value)),
    },
{
    if equal(bytes, b"accept") { Some(Action::Accept) }
    else if equal(bytes, b"drop") { Some(Action::Drop) }
    else { None }
}

/// Pinned network protocol conditions; Any means the option was absent.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// No explicit protocol restriction; ports, if present, mean TCP or UDP.
    Any,
    /// TCP packet condition.
    Tcp,
    /// UDP packet condition.
    Udp,
    /// ICMP for IPv4, ICMPv6 for IPv6, matching the pinned guest worker.
    Icmp,
}

/// Normative spelling of an explicitly present protocol.
pub open spec fn protocol_token(bytes: Seq<u8>, protocol: Protocol) -> bool {
    match protocol {
        Protocol::Any => false,
        Protocol::Tcp => bytes == b"tcp"@,
        Protocol::Udp => bytes == b"udp"@,
        Protocol::Icmp => bytes == b"icmp"@,
    }
}

/// Decode the complete pinned protocol language without a shell/service lookup.
fn protocol(bytes: &[u8]) -> (protocol: Option<Protocol>)
    requires bytes@.len() <= 4096,
    ensures match protocol {
        Some(value) => protocol_token(bytes@, value),
        None => !(exists|value: Protocol| protocol_token(bytes@, value)),
    },
{
    if equal(bytes, b"tcp") { Some(Protocol::Tcp) }
    else if equal(bytes, b"udp") { Some(Protocol::Udp) }
    else if equal(bytes, b"icmp") { Some(Protocol::Icmp) }
    else { None }
}

/// Safe pinned hostname alphabet; it is a DNS obligation, not a resolved address.
pub open spec fn hostname(bytes: Seq<u8>) -> bool {
    0 < bytes.len() <= 253 && forall|i: int| 0 <= i < bytes.len() ==>
        (b'a' <= bytes[i] <= b'z') || (b'0' <= bytes[i] <= b'9')
            || bytes[i] == b'-' || bytes[i] == b'.' || bytes[i] == b'_'
}

/// Bounded hostname claim. No constructor or accessor implies DNS success,
/// freshness, trusted origin or permission to skip an unresolved condition.
pub struct Hostname {
    /// Exact upstream-safe ASCII hostname bytes, kept separate from IP addresses.
    bytes: Vec<u8>,
}

impl Hostname {
    /// Exact hostname spelling retained from the completed source policy.
    pub closed spec fn bytes(&self) -> Seq<u8> { self.bytes@ }

    /// Validate a complete bounded hostname without invoking DNS or normalization.
    pub fn parse(bytes: &[u8]) -> (host: Option<Self>)
        ensures match host {
            Some(value) => hostname(value.bytes()) && value.bytes() == bytes@,
            None => !hostname(bytes@),
        },
    {
        if bytes.is_empty() || bytes.len() > 253 { return None; }
        let mut i = 0;
        while i < bytes.len()
            invariant i <= bytes.len() <= 253, bytes.len() > 0,
                forall|j: int| 0 <= j < i ==> (b'a' <= bytes@[j] <= b'z')
                    || (b'0' <= bytes@[j] <= b'9') || bytes@[j] == b'-'
                    || bytes@[j] == b'.' || bytes@[j] == b'_',
            decreases bytes.len()-i,
        {
            let byte = bytes[i];
            if !(in_range(byte, b'a', b'z') || in_range(byte, b'0', b'9')
                || byte == b'-' || byte == b'.' || byte == b'_') { return None; }
            i += 1;
        }
        Some(Self { bytes: copy(bytes) })
    }

    /// Borrow the exact bounded name for the consumer's pinned DNS resolver.
    pub fn name(&self) -> (bytes: &[u8])
        ensures bytes@ == self.bytes(), hostname(bytes@),
    { self.bytes.as_slice() }
}

/// An inclusive, validated native packet-port range.
#[derive(Clone, Copy)]
pub struct Ports {
    /// Smallest permitted destination port, including the valid numeric port zero.
    low: u16,
    /// Largest permitted destination port; it is never below low.
    high: u16,
}

/// Normative range spelling: one decimal port or two ordered endpoints.
pub open spec fn ports_token(bytes: Seq<u8>, low: int, high: int) -> bool {
    0 <= low <= high <= 65535 && (
        (number::digits(bytes, true) && low == high && number::decimal(bytes) == low)
        || (exists|index: int| address::cut(bytes, index, b'-') && index < bytes.len()
            && number::digits(bytes.subrange(0, index), true)
            && number::digits(bytes.subrange(index+1, bytes.len() as int), true)
            && number::decimal(bytes.subrange(0, index)) == low
            && number::decimal(bytes.subrange(index+1, bytes.len() as int)) == high)
    )
}

impl Ports {
    /// Validated minimum destination port.
    pub closed spec fn low(&self) -> u16 { self.low }

    /// Validated maximum destination port.
    pub closed spec fn high(&self) -> u16 { self.high }

    /// Decode exactly one bounded native range without accepting 65536 or wrap.
    pub fn parse(bytes: &[u8]) -> (ports: Option<Self>)
        requires bytes@.len() <= 4096,
        ensures match ports {
            Some(value) => ports_token(bytes@, value.low() as int, value.high() as int),
            None => !(exists|low: int, high: int| ports_token(bytes@, low, high)),
        },
    {
        let index = find(bytes, b'-');
        let low = {
            let value = number::parse(&bytes[..index], 65535, true)?;
            value as u16
        };
        let high = if index == bytes.len() { low } else {
            {
                let value = number::parse(&bytes[index+1..], 65535, true)?;
                value as u16
            }
        };
        if low > high { return None; }
        Some(Self { low, high })
    }

    /// Read the ordered inclusive endpoints for packet matching.
    pub fn bounds(&self) -> (bounds: (u16, u16))
        ensures bounds.0 == self.low() && bounds.1 == self.high(), bounds.0 <= bounds.1,
    { (self.low, self.high) }
}

/// One same-family destination prefix. Host bits may be present; the packet
/// consumer must compare exactly the indicated number of leading address bits.
pub struct Network {
    /// Parsed destination address, still a rule observation rather than authority.
    address: Ip,
    /// Prefix length within this exact address family's bit width.
    prefix: u8,
}

/// Exact destination-prefix language; bare addresses use their whole width.
pub open spec fn network_token(bytes: Seq<u8>, address: Ip, prefix: int, family: u8) -> bool {
    (family == 4 || family == 6) && address.valid() && address.family() == family
        && exists|index: int| address::cut(bytes, index, b'/')
            && (if family == 4 { address::ipv4(bytes.subrange(0, index), address.words()) }
                else { address::ipv6(bytes.subrange(0, index), address.words()) })
            && if index == bytes.len() { prefix == if family == 4 { 32int } else { 128int } }
                else { number::digits(bytes.subrange(index+1, bytes.len() as int), true)
                    && prefix == number::decimal(bytes.subrange(index+1, bytes.len() as int))
                    && 0 <= prefix <= if family == 4 { 32int } else { 128int } }
}

impl Network {
    /// Parsed destination address value.
    pub closed spec fn address(&self) -> Ip { self.address }

    /// Required number of leading matching bits.
    pub closed spec fn prefix(&self) -> u8 { self.prefix }

    /// The prefix is meaningful for this exact parsed family.
    pub closed spec fn valid(&self) -> bool {
        self.address.valid() && self.prefix <= if self.address.family() == 4 { 32int } else { 128int }
    }

    /// Decode an optional CIDR suffix and require the source's expected family.
    /// The address parser consumes the whole address part; extra slashes reject.
    pub fn parse(bytes: &[u8], family: u8) -> (network: Option<Self>)
        requires bytes@.len() <= 4096, family == 4 || family == 6,
        ensures match network {
            Some(value) => value.valid() && network_token(bytes@, value.address(), value.prefix() as int, family),
            None => !(exists|address: Ip, prefix: int| network_token(bytes@, address, prefix, family)),
        },
    {
        let index = find(bytes, b'/');
        let address = Ip::parse(&bytes[..index])?;
        if address.version() != family { return None; }
        let width = if family == 4 { 32 } else { 128 };
        let prefix = if index == bytes.len() { width } else {
            number::parse(&bytes[index+1..], width, true)?
        };
        Some(Self { address, prefix: prefix as u8 })
    }

    /// Borrow the same validated address supplied by the rule, without copying
    /// or substituting a packet's claimed source.
    pub fn ip(&self) -> (address: &Ip)
        requires self.valid(), ensures *address == self.address(), address.valid(),
    { &self.address }

    /// Prefix length to use unchanged during matching.
    pub fn bits(&self) -> (prefix: u8)
        requires self.valid(), ensures prefix == self.prefix(),
    { self.prefix }
}

/// Private typed options. Only the decoder constructs these; the rule owns the
/// complete unique set and validates relationships before exposing any getters.
enum Field {
    /// Exact matching disposition.
    Action(/// Parsed action token.
        Action),
    /// Explicit protocol condition.
    Protocol(/// Parsed explicit protocol, never Any.
        Protocol),
    /// Destination prefix of the source's exact address family.
    Network(/// Parsed CIDR/address condition.
        Network),
    /// Unresolved DNS hostname obligation.
    Host(/// Parsed bounded hostname.
        Hostname),
    /// Destination ports, ordered and within packet bounds.
    Ports(/// Parsed inclusive range.
        Ports),
    /// ICMP/ICMPv6 type, requiring the explicit ICMP protocol.
    Icmp(/// Native type value from 0 through 255.
        u8),
    /// Dynamic configured-DNS-address condition, not arbitrary port-53 traffic.
    Dns,
}

impl Field {
    /// Distinct option identity; both destination families occupy the same slot
    /// so competing same/different-family addresses cannot silently override.
    closed spec fn tag(&self) -> u8 {
        match self {
            Self::Action(_) => 0, Self::Protocol(_) => 1, Self::Network(_) => 2,
            Self::Host(_) => 3, Self::Ports(_) => 4, Self::Icmp(_) => 5, Self::Dns => 6,
        }
    }

    /// Every field has a meaningful same-family typed interpretation.
    closed spec fn valid(&self, family: u8) -> bool {
        match self {
            Self::Network(value) => value.valid() && value.address().family() == family,
            Self::Host(value) => hostname(value.bytes()),
            Self::Ports(value) => value.low() <= value.high(),
            Self::Protocol(value) => value != Protocol::Any,
            _ => true,
        }
    }

    /// Independent meaning of one exact option spelling and its typed value.
    closed spec fn meaning(&self, key: Seq<u8>, bytes: Seq<u8>, family: u8) -> bool {
        self.valid(family) && match self {
            Self::Action(value) => key == b"action"@ && action_token(bytes, *value),
            Self::Protocol(value) => key == b"proto"@ && protocol_token(bytes, *value),
            Self::Network(value) => key == (if family == 4 { b"dst4"@ } else { b"dst6"@ })
                && network_token(bytes, value.address(), value.prefix() as int, family),
            Self::Host(value) => key == b"dsthost"@ && hostname(bytes) && value.bytes() == bytes,
            Self::Ports(value) => key == b"dstports"@ && ports_token(bytes, value.low() as int, value.high() as int),
            Self::Icmp(value) => key == b"icmptype"@ && number::digits(bytes, true) && number::decimal(bytes) == *value,
            Self::Dns => key == b"specialtarget"@ && bytes == b"dns"@,
        }
    }

    /// Read the option identity for finite duplicate/conflict checking.
    fn ordinal(&self) -> (tag: u8)
        ensures tag == self.tag(), tag <= 6,
    {
        match self {
            Self::Action(_) => 0, Self::Protocol(_) => 1, Self::Network(_) => 2,
            Self::Host(_) => 3, Self::Ports(_) => 4, Self::Icmp(_) => 5, Self::Dns => 6,
        }
    }

    /// Decode a single exact option; unknown names and malformed known values
    /// are equally incapable of creating a partially interpreted allow rule.
    fn parse(key: &[u8], bytes: &[u8], family: u8) -> (field: Option<Self>)
        requires key@.len() <= 4096, bytes@.len() <= 4096, family == 4 || family == 6,
        ensures match field {
            Some(value) => value.meaning(key@, bytes@, family),
            None => !(exists|value: Field| value.meaning(key@, bytes@, family)),
        },
    {
        if equal(key, b"action") { return action(bytes).map(Self::Action); }
        if equal(key, b"proto") { return protocol(bytes).map(Self::Protocol); }
        if equal(key, b"dst4") || equal(key, b"dst6") {
            let expected = if equal(key, b"dst4") { 4 } else { 6 };
            if expected != family { return None; }
            return Network::parse(bytes, family).map(Self::Network);
        }
        if equal(key, b"dsthost") { return Hostname::parse(bytes).map(Self::Host); }
        if equal(key, b"dstports") { return Ports::parse(bytes).map(Self::Ports); }
        if equal(key, b"icmptype") {
            return number::parse(bytes, 255, true).map(|value| Self::Icmp(value as u8));
        }
        if equal(key, b"specialtarget") && equal(bytes, b"dns") { return Some(Self::Dns); }
        None
    }
}

/// Normative ordered token language with exact first-space/equals boundaries.
/// Payload conditions are typed meanings, never a collection of ignored strings.
closed spec fn field_stream(bytes: Seq<u8>, fields: Seq<Field>, family: u8) -> bool
    decreases fields.len(),
{
    fields.len() > 0 && exists|end: int, equals: int|
        address::cut(bytes, end, b' ') && end > 0
            && address::cut(bytes.subrange(0, end), equals, b'=') && 0 < equals < end-1
            && fields[0].meaning(bytes.subrange(0, equals), bytes.subrange(equals+1, end), family)
            && if fields.len() == 1 { end == bytes.len() }
                else { end < bytes.len() && field_stream(bytes.subrange(end+1, bytes.len() as int), fields.drop_first(), family) }
}

/// Decode at most eight options. Empty, leading/trailing whitespace, extra '='
/// and overlong option lists cannot be partially consumed as a valid prefix.
fn fields(bytes: &[u8], family: u8, remaining: usize) -> (fields: Option<Vec<Field>>)
    requires bytes@.len() <= 3071, family == 4 || family == 6, remaining <= 8,
    ensures match fields {
        Some(value) => 0 < value@.len() <= remaining && field_stream(bytes@, value@, family)
            && forall|i: int| 0 <= i < value@.len() ==> value@[i].valid(family),
        None => !(exists|value: Seq<Field>| 0 < value.len() <= remaining && field_stream(bytes@, value, family)),
    },
    decreases remaining,
{
    if remaining == 0 || bytes.is_empty() { return None; }
    let end = find(bytes, b' ');
    let token = &bytes[..end];
    let equals = find(token, b'=');
    if equals == 0 || equals == token.len() || equals+1 == token.len() { return None; }
    let field = Field::parse(&token[..equals], &token[equals+1..], family)?;
    if end == bytes.len() {
        return Some(alloc::vec![field]);
    }
    let mut tail = fields(&bytes[end+1..], family, remaining-1)?;
    tail.insert(0, field);
    Some(tail)
}

/// Exact last-present protocol; uniqueness makes it also the first-present one.
closed spec fn protocol_of(fields: Seq<Field>) -> Protocol
    decreases fields.len(),
{
    if fields.len() == 0 { Protocol::Any }
    else { match fields.last() { Field::Protocol(value) => value, _ => protocol_of(fields.drop_last()) } }
}

/// Exact matching disposition; a valid rule always contains exactly one action.
closed spec fn action_of(fields: Seq<Field>) -> Action
    decreases fields.len(),
{
    if fields.len() == 0 { Action::Drop }
    else { match fields.last() { Field::Action(value) => value, _ => action_of(fields.drop_last()) } }
}

/// Supported unique options and their meaningful cross-condition constraints.
closed spec fn coherent(fields: Seq<Field>, family: u8) -> bool {
    (family == 4 || family == 6) && 0 < fields.len() <= 8
        && (forall|i: int| 0 <= i < fields.len() ==> fields[i].valid(family))
        && (forall|i: int, j: int| 0 <= i < j < fields.len() ==> fields[i].tag() != fields[j].tag())
        && (exists|i: int| 0 <= i < fields.len() && fields[i].tag() == 0)
        && !((exists|i: int| 0 <= i < fields.len() && fields[i].tag() == 2)
            && (exists|i: int| 0 <= i < fields.len() && fields[i].tag() == 3))
        && ((exists|i: int| 0 <= i < fields.len() && fields[i].tag() == 5) ==> protocol_of(fields) == Protocol::Icmp)
        && (protocol_of(fields) == Protocol::Icmp ==>
            forall|i: int| 0 <= i < fields.len() ==> fields[i].tag() != 4 && fields[i].tag() != 6)
}

/// Useful accepted rule language, independent of executable parser control flow.
pub closed spec fn well_formed(bytes: Seq<u8>, family: u8) -> bool {
    bytes.len() <= 3071 && exists|fields: Seq<Field>| field_stream(bytes, fields, family) && coherent(fields, family)
}

/// A complete typed rule. No public constructor, field mutation or unchecked
/// conversion can bypass duplicate, option or cross-condition validation.
pub struct Rule {
    /// Exact bounded complete options in their source order.
    fields: Vec<Field>,
    /// Address family whose source snapshot owns this rule.
    pub(crate) family: u8,
}

impl Rule {
    /// Every option is supported, unique and consistent with its companions.
    pub closed spec fn valid(&self) -> bool { coherent(self.fields@, self.family) }

    /// Exact option meanings of this complete source token sequence.
    pub closed spec fn describes(&self, bytes: Seq<u8>) -> bool {
        field_stream(bytes, self.fields@, self.family)
    }

    /// Observed matching disposition from the one complete action option.
    pub closed spec fn action(&self) -> Action { action_of(self.fields@) }

    /// Exact protocol restriction, including an absent option's Any value.
    pub closed spec fn protocol(&self) -> Protocol { protocol_of(self.fields@) }

    /// Whether the complete native options contain a hostname obligation.
    pub closed spec fn has_hostname(&self) -> bool {
        exists|i: int| 0 <= i < self.fields@.len() && self.fields@[i].tag() == 3
    }

    /// Reject an entire malformed/unsupported rule. The caller rejects that
    /// source's whole snapshot; it must never skip just the rejected condition.
    pub fn parse(bytes: &[u8], family: u8) -> (rule: Option<Self>)
        ensures match rule {
            Some(value) => value.valid() && value.describes(bytes@) && value.family == family,
            None => !well_formed(bytes@, family),
        },
    {
        if bytes.len() > 3071 || (family != 4 && family != 6) { return None; }
        let parsed = fields(bytes, family, 8)?;
        let mut i = 0;
        let mut has_action = false;
        let mut has_network = false;
        let mut has_host = false;
        let mut has_ports = false;
        let mut has_icmp = false;
        let mut has_dns = false;
        let mut protocol = Protocol::Any;
        while i < parsed.len()
            invariant i <= parsed.len() <= 8, parsed.len() > 0, family == 4 || family == 6,
                forall|k: int| 0 <= k < parsed@.len() ==> parsed@[k].valid(family),
                forall|j: int, k: int| 0 <= j < k < i ==> parsed@[j].tag() != parsed@[k].tag(),
                has_action == (exists|j: int| 0 <= j < i && parsed@[j].tag() == 0),
                has_network == (exists|j: int| 0 <= j < i && parsed@[j].tag() == 2),
                has_host == (exists|j: int| 0 <= j < i && parsed@[j].tag() == 3),
                has_ports == (exists|j: int| 0 <= j < i && parsed@[j].tag() == 4),
                has_icmp == (exists|j: int| 0 <= j < i && parsed@[j].tag() == 5),
                has_dns == (exists|j: int| 0 <= j < i && parsed@[j].tag() == 6),
                protocol == protocol_of(parsed@.subrange(0, i as int)),
            decreases parsed.len()-i,
        {
            let tag = parsed[i].ordinal();
            let mut j = 0;
            while j < i
                invariant j <= i < parsed.len(),
                    forall|k: int| 0 <= k < j ==> parsed@[k].tag() != parsed@[i as int].tag(),
                decreases i-j,
            {
                if parsed[j].ordinal() == tag { return None; }
                j += 1;
            }
            match &parsed[i] {
                Field::Action(_) => has_action = true,
                Field::Protocol(value) => protocol = *value,
                Field::Network(_) => has_network = true,
                Field::Host(_) => has_host = true,
                Field::Ports(_) => has_ports = true,
                Field::Icmp(_) => has_icmp = true,
                Field::Dns => has_dns = true,
            }
            i += 1;
        }
        if !has_action || (has_network && has_host)
            || (has_icmp && protocol != Protocol::Icmp)
            || (protocol == Protocol::Icmp && (has_ports || has_dns)) { return None; }
        Some(Self { fields: parsed, family })
    }

    /// Read the exact completed rule action; missing-action input never reaches
    /// this representation and cannot acquire the Drop fallback as a valid parse.
    pub fn disposition(&self) -> (action: Action)
        requires self.valid(), ensures action == self.action(),
    {
        let mut action = Action::Drop;
        let mut i = 0;
        while i < self.fields.len()
            invariant i <= self.fields@.len(), action == action_of(self.fields@.subrange(0, i as int)),
            decreases self.fields.len()-i,
        {
            if let Field::Action(value) = &self.fields[i] { action = *value; }
            i += 1;
        }
        action
    }

    /// Read the explicit protocol or the meaningful absent-option Any value.
    pub fn transport(&self) -> (protocol: Protocol)
        requires self.valid(), ensures protocol == self.protocol(),
    {
        let mut protocol = Protocol::Any;
        let mut i = 0;
        while i < self.fields.len()
            invariant i <= self.fields@.len(), protocol == protocol_of(self.fields@.subrange(0, i as int)),
            decreases self.fields.len()-i,
        {
            if let Field::Protocol(value) = &self.fields[i] { protocol = *value; }
            i += 1;
        }
        protocol
    }

    /// Borrow any unresolved hostname obligation. A consumer cannot activate a
    /// policy by ignoring it, regardless of whether that rule accepts or drops.
    pub fn host(&self) -> (host: Option<&Hostname>)
        requires self.valid(),
        ensures match host {
            Some(value) => hostname(value.bytes()) && (exists|i: int| 0 <= i < self.fields@.len() && self.fields@[i] == Field::Host(*value)),
            None => forall|i: int| 0 <= i < self.fields@.len() ==> self.fields@[i].tag() != 3,
        },
    {
        let mut i = 0;
        while i < self.fields.len()
            invariant i <= self.fields.len(),
                forall|j: int| 0 <= j < i ==> self.fields@[j].tag() != 3,
            decreases self.fields.len()-i,
        {
            if let Field::Host(host) = &self.fields[i] { return Some(host); }
            i += 1;
        }
        None
    }
    /// Borrow the exact native destination-prefix restriction.
    pub fn network(&self) -> (restriction: Option<&Network>)
        requires self.valid(),
        ensures match restriction {
            Some(value) => value.valid() && value.address().family() == self.family && (exists|i: int| 0 <= i < self.fields@.len() && self.fields@[i] == Field::Network(*value)),
            None => forall|i: int| 0 <= i < self.fields@.len() ==> self.fields@[i].tag() != 2,
        },
    {
        let mut i = 0;
        while i < self.fields.len()
            invariant self.valid(), i <= self.fields.len(),
                forall|j: int| 0 <= j < i ==> self.fields@[j].tag() != 2,
            decreases self.fields.len()-i,
        {
            if let Field::Network(value) = &self.fields[i] { return Some(value); }
            i += 1;
        }
        None
    }

    /// Borrow the exact inclusive destination-port restriction.
    pub fn ports(&self) -> (restriction: Option<&Ports>)
        requires self.valid(),
        ensures match restriction {
            Some(value) => value.low() <= value.high() && (exists|i: int| 0 <= i < self.fields@.len() && self.fields@[i] == Field::Ports(*value)),
            None => forall|i: int| 0 <= i < self.fields@.len() ==> self.fields@[i].tag() != 4,
        },
    {
        let mut i = 0;
        while i < self.fields.len()
            invariant self.valid(), i <= self.fields.len(),
                forall|j: int| 0 <= j < i ==> self.fields@[j].tag() != 4,
            decreases self.fields.len()-i,
        {
            if let Field::Ports(value) = &self.fields[i] { return Some(value); }
            i += 1;
        }
        None
    }

    /// Exact native ICMP type restriction; absent permits any type of the
    /// already validated protocol. IPv6 consumers use ICMPv6 for this value.
    pub fn icmp_type(&self) -> (restriction: Option<u8>)
        requires self.valid(),
        ensures match restriction {
            Some(value) => self.protocol() == Protocol::Icmp && (exists|i: int| 0 <= i < self.fields@.len() && self.fields@[i] == Field::Icmp(value)),
            None => forall|i: int| 0 <= i < self.fields@.len() ==> self.fields@[i].tag() != 5,
        },
    {
        let mut i = 0;
        while i < self.fields.len()
            invariant self.valid(), i <= self.fields.len(),
                forall|j: int| 0 <= j < i ==> self.fields@[j].tag() != 5,
            decreases self.fields.len()-i,
        {
            if let Field::Icmp(value) = &self.fields[i] { return Some(*value); }
            i += 1;
        }
        None
    }

    /// Whether the rule also requires a configured DNS destination and port 53.
    /// The consumer must intersect this with every other supplied condition.
    pub fn dns_target(&self) -> (dns: bool)
        requires self.valid(),
        ensures dns == (exists|i: int| 0 <= i < self.fields@.len() && self.fields@[i].tag() == 6),
    {
        let mut i = 0;
        while i < self.fields.len()
            invariant self.valid(), i <= self.fields.len(),
                forall|j: int| 0 <= j < i ==> self.fields@[j].tag() != 6,
            decreases self.fields.len()-i,
        {
            if self.fields[i].ordinal() == 6 { return true; }
            i += 1;
        }
        false
    }

    /// Preserve the pinned worker's skip behavior for a DNS special-target rule
    /// with an explicit port range other than exactly 53. Such a rule is valid
    /// but matches no packets; broadening that range would change upstream policy.
    pub fn matches_none(&self) -> (never: bool)
        requires self.valid(),
        ensures never == ((exists|i: int| 0 <= i < self.fields@.len() && self.fields@[i].tag() == 6)
            && (exists|i: int, ports: Ports| 0 <= i < self.fields@.len()
                && self.fields@[i] == Field::Ports(ports) && (ports.low() != 53 || ports.high() != 53))),
    {
        if !self.dns_target() { return false; }
        match self.ports() { Some(value) => { let (low, high) = value.bounds(); low != 53 || high != 53 }, None => false }
    }

    /// Address family of the source snapshot that owns this complete rule.
    pub fn family(&self) -> (family: u8)
        requires self.valid(), ensures family == self.family, family == 4 || family == 6,
    { self.family }

}

}
