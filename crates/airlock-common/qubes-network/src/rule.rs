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

mod options;

use alloc::vec::Vec;
use vstd::prelude::*;
use vstd::slice::slice_to_vec;

#[cfg(verus_keep_ghost)]
use crate::address;
use crate::address::Ip;
use crate::number;
use options::Options;

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
    if bytes == b"accept" { Some(Action::Accept) }
    else if bytes == b"drop" { Some(Action::Drop) }
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
    if bytes == b"tcp" { Some(Protocol::Tcp) }
    else if bytes == b"udp" { Some(Protocol::Udp) }
    else if bytes == b"icmp" { Some(Protocol::Icmp) }
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
            if !(byte.is_ascii_lowercase() || byte.is_ascii_digit()
                || byte == b'-' || byte == b'.' || byte == b'_') { return None; }
            i += 1;
        }
        Some(Self { bytes: slice_to_vec(bytes) })
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
        let index = bytes.iter().position(|byte| *byte == b'-').unwrap_or(bytes.len());
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
        let index = bytes.iter().position(|byte| *byte == b'/').unwrap_or(bytes.len());
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

/// A complete rule with directly stored, validated conditions. The Serde schema
/// handles option names; construction enforces network meaning and combinations.
pub struct Rule {
    /// Required disposition from the single action option.
    action: Action,
    /// Explicit protocol or the meaningful absent-option Any value.
    protocol: Protocol,
    /// Optional same-family destination prefix.
    network: Option<Network>,
    /// Optional unresolved hostname obligation.
    host: Option<Hostname>,
    /// Optional ordered destination port range.
    ports: Option<Ports>,
    /// Optional ICMP type, valid only with the ICMP protocol.
    icmp: Option<u8>,
    /// Whether configured DNS destinations and port 53 must also match.
    dns: bool,
    /// Address family of the source snapshot owning this rule.
    pub(crate) family: u8,
}

/// Exact useful rule language, rather than successful tokenization alone.
pub closed spec fn well_formed(bytes: Seq<u8>, family: u8) -> bool {
    exists|rule: Rule| rule.family == family && rule.describes(bytes)
}

impl Rule {
    /// Every condition is valid and meaningful together with the others.
    pub closed spec fn valid(&self) -> bool {
        (self.family == 4 || self.family == 6)
            && (self.network.is_some() ==> self.network.unwrap().valid()
                && self.network.unwrap().address().family() == self.family)
            && (self.host.is_some() ==> hostname(self.host.unwrap().bytes()))
            && (self.ports.is_some() ==> self.ports.unwrap().low() <= self.ports.unwrap().high())
            && !(self.network.is_some() && self.host.is_some())
            && (self.icmp.is_some() ==> self.protocol == Protocol::Icmp)
            && (self.protocol == Protocol::Icmp ==> self.ports.is_none() && !self.dns)
    }

    /// Semantic meaning of every decoded field, including exact absence.
    closed spec fn interprets(&self, options: Options) -> bool {
        action_token(options.action@, self.action)
            && match options.proto {
                None => self.protocol == Protocol::Any,
                Some(bytes) => protocol_token(bytes@, self.protocol),
            }
            && match (options.dst4, options.dst6, self.network) {
                (None, None, None) => true,
                (Some(bytes), None, Some(network)) => self.family == 4
                    && network_token(bytes@, network.address(), network.prefix() as int, 4),
                (None, Some(bytes), Some(network)) => self.family == 6
                    && network_token(bytes@, network.address(), network.prefix() as int, 6),
                _ => false,
            }
            && match (options.dsthost, self.host) {
                (None, None) => true,
                (Some(bytes), Some(host)) => bytes@ == host.bytes(),
                _ => false,
            }
            && match (options.dstports, self.ports) {
                (None, None) => true,
                (Some(bytes), Some(ports)) => ports_token(bytes@, ports.low() as int, ports.high() as int),
                _ => false,
            }
            && match (options.icmptype, self.icmp) {
                (None, None) => true,
                (Some(bytes), Some(value)) => number::digits(bytes@, true) && number::decimal(bytes@) == value,
                _ => false,
            }
            && match options.specialtarget {
                None => !self.dns,
                Some(bytes) => self.dns && bytes@ == b"dns"@,
            }
    }

    /// Complete native option meaning, independent of option order.
    pub closed spec fn describes(&self, bytes: Seq<u8>) -> bool {
        self.valid() && exists|options: Options| options.describes(bytes) && self.interprets(options)
    }

    /// Exact disposition selected by the required action option.
    pub closed spec fn action(&self) -> Action { self.action }

    /// Exact protocol, including the absent-option Any value.
    pub closed spec fn protocol(&self) -> Protocol { self.protocol }

    /// Whether this rule carries an unresolved hostname obligation.
    pub closed spec fn has_hostname(&self) -> bool { self.host.is_some() }

    /// Decode the whole option schema, then reject every unsupported value or
    /// incompatible combination before constructing a usable rule.
    pub fn parse(bytes: &[u8], family: u8) -> (rule: Option<Self>)
        ensures match rule {
            Some(value) => value.valid() && value.describes(bytes@) && value.family == family,
            None => !well_formed(bytes@, family),
        },
    {
        if family != 4 && family != 6 { return None; }

        let options = Options::parse(bytes)?;
        let action = action(options.action.as_slice())?;
        let protocol = match options.proto { Some(bytes) => protocol(bytes.as_slice())?, None => Protocol::Any };
        let network = match (options.dst4, options.dst6) {
            (None, None) => None,
            (Some(bytes), None) if family == 4 => Some(Network::parse(bytes.as_slice(), 4)?),
            (None, Some(bytes)) if family == 6 => Some(Network::parse(bytes.as_slice(), 6)?),
            _ => return None,
        };
        let host = match options.dsthost { Some(bytes) => Some(Hostname::parse(bytes.as_slice())?), None => None };
        let ports = match options.dstports { Some(bytes) => Some(Ports::parse(bytes.as_slice())?), None => None };
        let icmp = match options.icmptype {
            Some(bytes) => Some(number::parse(bytes.as_slice(), 255, true)? as u8),
            None => None,
        };
        let dns = match options.specialtarget {
            None => false,
            Some(bytes) if bytes.as_slice() == b"dns" => true,
            _ => return None,
        };

        if network.is_some() && host.is_some() || icmp.is_some() && protocol != Protocol::Icmp
            || protocol == Protocol::Icmp && (ports.is_some() || dns) { return None; }

        Some(Self { action, protocol, network, host, ports, icmp, dns, family })
    }

    /// Read the required disposition without searching option records.
    pub fn disposition(&self) -> (action: Action)
        requires self.valid(), ensures action == self.action(),
    { self.action }

    /// Read the explicit protocol or the absent-option Any value.
    pub fn transport(&self) -> (protocol: Protocol)
        requires self.valid(), ensures protocol == self.protocol(),
    { self.protocol }

    /// Borrow the unresolved hostname, which must be resolved before activation.
    pub fn host(&self) -> (host: Option<&Hostname>)
        requires self.valid(),
        ensures match host {
            Some(value) => self.host == Some(*value) && hostname(value.bytes()),
            None => self.host.is_none(),
        },
    { self.host.as_ref() }

    /// Borrow the validated same-family destination restriction.
    pub fn network(&self) -> (network: Option<&Network>)
        requires self.valid(),
        ensures match network {
            Some(value) => self.network == Some(*value) && value.valid() && value.address().family() == self.family,
            None => self.network.is_none(),
        },
    { self.network.as_ref() }

    /// Borrow the validated inclusive destination-port range.
    pub fn ports(&self) -> (ports: Option<&Ports>)
        requires self.valid(),
        ensures match ports {
            Some(value) => self.ports == Some(*value) && value.low() <= value.high(),
            None => self.ports.is_none(),
        },
    { self.ports.as_ref() }

    /// Read the native ICMP type restriction; IPv6 consumers use ICMPv6.
    pub fn icmp_type(&self) -> (icmp: Option<u8>)
        requires self.valid(), ensures icmp == self.icmp,
            icmp.is_some() ==> self.protocol() == Protocol::Icmp,
    { self.icmp }

    /// Whether configured DNS destinations and port 53 must also match.
    pub fn dns_target(&self) -> (dns: bool)
        requires self.valid(), ensures dns == self.dns,
    { self.dns }

    /// Preserve the pinned worker's matches-none behavior when an explicit DNS
    /// special-target port range is anything other than exactly port 53.
    pub fn matches_none(&self) -> (never: bool)
        requires self.valid(),
        ensures never == (self.dns && self.ports.is_some()
            && (self.ports.unwrap().low() != 53 || self.ports.unwrap().high() != 53)),
    {
        if !self.dns { return false; }
        match &self.ports { Some(value) => { let (low, high) = value.bounds(); low != 53 || high != 53 }, None => false }
    }

    /// Address family of the source snapshot that owns this rule.
    pub fn family(&self) -> (family: u8)
        requires self.valid(), ensures family == self.family, family == 4 || family == 6,
    { self.family }
}

}
