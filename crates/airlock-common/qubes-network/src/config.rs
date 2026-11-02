//! Addressing and membership from the pinned QubesDB key contract. A complete
//! typed configuration is published as one value; the wire offers no transaction
//! across global keys. Each accepted version therefore represents the current
//! authoritative replica, not a guessed cross-key dom0 transaction boundary.
//! Interface authority additionally requires the actual XenStore-owned lease.

use alloc::vec::Vec;
use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
use crate::address;
use crate::address::Ip;
use crate::cache::Cache;
use crate::number;
#[cfg(verus_keep_ghost)]
mod mask;

verus! {

broadcast use { vstd::seq::group_seq_lemmas, vstd::seq_lib::group_seq_properties, vstd::seq::Seq::lemma_as_ref_index, crate::address::cut_unique, Ip::unique, crate::address::token_cut };

/// Matches the current native backend's bound, rather than an input-driven heap size.
pub const MAX_CLIENTS: usize = airlock_boot_core::application::NETWORK_CLIENTS;

/// One byte-exact MAC observation from the native `/qubes-mac` key.
pub struct Mac {
    /// Six parsed network-order octets; no mutable representation escapes.
    bytes: [u8; 6],
}

/// Native six-pair hexadecimal MAC syntax with exact colon positions.
pub open spec fn mac_token(bytes: Seq<u8>, value: Seq<u8>) -> bool {
    bytes.len() == 17 && value.len() == 6
        && (forall|i: int| 0 <= i < 6 ==> number::hex_word(bytes.subrange(i*3, i*3+2), value[i] as int))
        && (forall|i: int| 0 <= i < 5 ==> #[trigger] bytes[i*3+2] == b':')
}

impl Mac {
    /// Exact six network-order octets.
    pub closed spec fn value(&self) -> Seq<u8> { self.bytes@ }

    /// Consume the full native spelling, rejecting short pairs and trailing bytes.
    pub fn parse(bytes: &[u8]) -> (mac: Option<Self>)
        ensures match mac {
            Some(value) => mac_token(bytes@, value.value()),
            None => !(exists|value: Seq<u8>| mac_token(bytes@, value)),
        },
    {
        if bytes.len() != 17 { return None; }
        let mut value = [0; 6];
        let mut i = 0;
        while i < 6
            invariant i <= 6, bytes.len() == 17,
                forall|j: int| 0 <= j < i ==> number::hex_word(bytes@.subrange(j*3, j*3+2), value@[j] as int),
                forall|j: int| 0 <= j < i && j < 5 ==> #[trigger] bytes@[j*3+2] == b':',
            decreases 6-i,
        {
            let chunk = &bytes[i*3..i*3+2];
            let word = match number::parse_hex(chunk) {
                Some(value) => value,
                None => {
                    proof {
                        assert forall|candidate: Seq<u8>| !mac_token(bytes@, candidate) by {
                            if mac_token(bytes@, candidate) { assert(number::hex_word(chunk@, candidate[i as int] as int)); }
                        }
                    }
                    return None;
                }
            };
            proof { number::byte_bound(chunk@, word as int); }
            if word > 255 { return None; }
            if i < 5 && bytes[i*3+2] != b':' { return None; }
            value[i] = word as u8;
            i += 1;
        }
        Some(Self { bytes: value })
    }

    /// Borrow exact validated MAC bytes for the link consumer.
    pub fn bytes(&self) -> (bytes: &[u8; 6])
        ensures bytes@ == self.value(),
    { &self.bytes }
}

/// Exact key/value observation independent of cache storage order.
pub open spec fn observed(cache: Cache, key: Seq<u8>, bytes: Seq<u8>) -> bool {
    exists|i: int| 0 <= i < cache.entries().len()
        && cache.entries()[i].key() == key && cache.entries()[i].value() == bytes
}

/// No complete record exists at this exact native key.
pub open spec fn absent(cache: Cache, key: Seq<u8>) -> bool {
    forall|i: int| 0 <= i < cache.entries().len() ==> cache.entries()[i].key() != key
}

/// Typed address meaning of the authoritative bytes at one exact key.
pub open spec fn ip_at(cache: Cache, key: Seq<u8>, ip: Ip, family: u8) -> bool {
    ip.valid() && ip.family() == family && exists|bytes: Seq<u8>|
        observed(cache, key, bytes) && ip.describes(bytes)
}

/// Read one complete same-family address observation from the native replica.
fn read_ip(cache: &Cache, key: &[u8], family: u8) -> (ip: Option<Ip>)
    requires cache.valid(), key@.len() < 64, family == 4 || family == 6,
    ensures match ip {
        Some(value) => ip_at(*cache, key@, value, family)
            && (forall|other: Ip| #[trigger] ip_at(*cache, key@, other, family) ==> other == value),
        None => !(exists|value: Ip| ip_at(*cache, key@, value, family)),
    },
{
    let bytes = cache.read(key)?;
    let address = Ip::parse(bytes)?;
    if address.version() != family { return None; }
    Some(address)
}

/// Logical leading IPv4 mask bit, independent of signed integers or host byte order.
pub open spec fn mask_bit(mask: Ip, index: int) -> bool {
    let word = (mask.words()[0] as u32) << 16 | mask.words()[1] as u32;
    (word >> (31-index) as u32) & 1u32 != 0
}

/// Exactly the leading prefix bits are set in this IPv4 netmask.
pub open spec fn contiguous(mask: Ip, prefix: int) -> bool {
    0 <= prefix <= 32 && forall|i: int| 0 <= i < 32 ==> mask_bit(mask, i) == (i < prefix)
}

/// A contiguous IPv4 netmask's exact leading-one count.
fn mask_prefix(mask: &Ip) -> (prefix: Option<u8>)
    requires mask.valid(), mask.family() == 4,
    ensures match prefix {
        Some(value) => contiguous(*mask, value as int),
        None => !(exists|value: int| contiguous(*mask, value)),
    },
{
    let bits = u32::from(mask.word(0)?) << 16 | u32::from(mask.word(1)?);
    let prefix = bits.leading_ones();
    let total = bits.count_ones();
    proof {
        assert(bits == (mask.words()[0] as u32) << 16 | mask.words()[1] as u32);
        assert forall|candidate: int| #[trigger] contiguous(*mask, candidate) == mask::shape(bits, candidate) by {
            assert forall|i: int| 0 <= i < 32 implies mask_bit(*mask, i) == mask::bit(bits, i) by {}
        }
        mask::contiguous(bits, prefix, total);
    }
    if total != prefix { return None; }
    Some(prefix as u8)
}

/// A native netmask's contiguous leading-one count at its exact key.
pub open spec fn prefix_at(cache: Cache, key: Seq<u8>, prefix: int) -> bool {
    0 <= prefix <= 32 && exists|mask: Ip| ip_at(cache, key, mask, 4)
        && contiguous(mask, prefix)
}

/// Read and validate a contiguous native IPv4 netmask before deriving a route prefix.
fn read_mask(cache: &Cache, key: &[u8]) -> (prefix: Option<u8>)
    requires cache.valid(), key@.len() < 64,
    ensures match prefix {
        Some(value) => prefix_at(*cache, key@, value as int),
        None => !(exists|value: int| prefix_at(*cache, key@, value)),
    },
{
    let mask = read_ip(cache, key, 4)?;
    mask_prefix(&mask)
}

/// Exact ordered native membership text, allowing an empty list but no empty
/// elements, duplicate normalized addresses, repeated spaces or trailing space.
pub open spec fn members(bytes: Seq<u8>, ips: Seq<Ip>, family: u8) -> bool
    decreases ips.len(),
{
    if ips.len() == 0 { bytes.len() == 0 } else {
        ips[0].valid() && ips[0].family() == family
            && (forall|i: int| 0 < i < ips.len() ==> #[trigger] ips[i].words() != ips[0].words())
            && exists|end: int| address::cut(bytes, end, b' ')
                && ips[0].describes(bytes.subrange(0, end))
                && if ips.len() == 1 { end == bytes.len() }
                    else { end < bytes.len()-1 && members(bytes.subrange(end+1, bytes.len() as int), ips.drop_first(), family) }
    }
}

/// Exact typed member list at one native key, independent of key ordering.
pub open spec fn members_at(cache: Cache, key: Seq<u8>, ips: Seq<Ip>, family: u8) -> bool {
    ips.len() <= MAX_CLIENTS && exists|bytes: Seq<u8>| observed(cache, key, bytes) && members(bytes, ips, family)
}

/// A nonempty membership list has the exact first token selected by native splitting.
proof fn members_head(bytes: Seq<u8>, ips: Seq<Ip>, family: u8, end: int)
    requires members(bytes, ips, family), bytes.len() > 0, address::cut(bytes, end, b' '),
    ensures ips.len() > 0, ips[0].valid(), ips[0].family() == family,
        ips[0].describes(bytes.subrange(0, end)),
        ips.len() == 1 ==> end == bytes.len(),
        ips.len() > 1 ==> end < bytes.len()-1 && members(bytes.subrange(end+1, bytes.len() as int), ips.drop_first(), family),
        forall|i: int| 0 < i < ips.len() ==> #[trigger] ips[i].words() != ips[0].words(),
{
    let actual = choose|index: int| address::cut(bytes, index, b' ')
        && ips[0].describes(bytes.subrange(0, index))
        && if ips.len() == 1 { index == bytes.len() }
            else { index < bytes.len()-1 && members(bytes.subrange(index+1, bytes.len() as int), ips.drop_first(), family) };
    address::cut_unique(bytes, end, actual, b' ');
}

/// Complete native membership text has one ordered normalized interpretation.
proof fn members_unique(bytes: Seq<u8>, left: Seq<Ip>, right: Seq<Ip>, family: u8)
    requires members(bytes, left, family), members(bytes, right, family),
    ensures left == right,
    decreases left.len(),
{
    reveal(Ip::describes);
    if left.len() == 0 {
        if right.len() > 0 {
            let end = choose|end: int| address::cut(bytes, end, b' ') && right[0].describes(bytes.subrange(0, end));
        }
    } else {
        let end = choose|end: int| address::cut(bytes, end, b' ') && left[0].describes(bytes.subrange(0, end))
            && if left.len() == 1 { end == bytes.len() }
                else { end < bytes.len()-1 && members(bytes.subrange(end+1, bytes.len() as int), left.drop_first(), family) };
        members_head(bytes, right, family, end);
        Ip::unique(left[0], right[0], bytes.subrange(0, end));
        if left.len() == 1 {
            if right.len() > 1 { assert(end < bytes.len()-1); }
        } else {
            if right.len() == 1 { assert(end == bytes.len()); }
            members_unique(bytes.subrange(end+1, bytes.len() as int), left.drop_first(), right.drop_first(), family);
        }
    }
    assert(left =~= right);
}

/// A complete same-family connected-address list. Text is not a per-interface
/// identity: normalized membership must still match a real toolstack lease.
pub(crate) fn connected(bytes: &[u8], family: u8, remaining: usize) -> (ips: Option<Vec<Ip>>)
    requires bytes@.len() <= 3071, family == 4 || family == 6, remaining <= MAX_CLIENTS,
    ensures match ips {
        Some(value) => value@.len() <= remaining && members(bytes@, value@, family)
            && (forall|i: int| 0 <= i < value@.len() ==> value@[i].valid() && value@[i].family() == family)
            && (forall|i: int, j: int| 0 <= i < j < value@.len() ==> value@[i].words() != value@[j].words()),
        None => !(exists|value: Seq<Ip>| value.len() <= remaining && members(bytes@, value, family)),
    },
    decreases remaining,
{
    if bytes.is_empty() { return Some(Vec::new()); }
    if remaining == 0 { return None; }
    let end = bytes.iter().position(|byte: &u8| -> (found: bool) ensures found == (*byte == b' ') { *byte == b' ' }).unwrap_or(bytes.len());
    proof { assert(crate::address::cut(bytes@, end as int, b' ')); }
    proof {
        assert forall|candidate: Seq<Ip>| members(bytes@, candidate, family) implies candidate.len() > 0
            && candidate[0].valid() && candidate[0].family() == family
            && candidate[0].describes(bytes@.subrange(0, end as int))
            && (candidate.len() == 1 ==> end == bytes@.len())
            && (candidate.len() > 1 ==> end < bytes@.len()-1
                && members(bytes@.subrange(end as int+1, bytes@.len() as int), candidate.drop_first(), family)) by {
            members_head(bytes@, candidate, family, end as int);
        }
    }
    let ip = Ip::parse(&bytes[..end])?;
    if ip.version() != family { return None; }
    let mut tail = if end == bytes.len() { Vec::new() } else {
        if end+1 == bytes.len() { return None; }
        connected(&bytes[end+1..], family, remaining-1)?
    };
    let duplicate = tail.iter().any(|candidate: &Ip| -> (same: bool)
        requires candidate.valid(), candidate.family() == family, ip.family() == family,
        ensures same == (candidate.words() == ip.words()),
        { candidate.same(&ip) });
    if duplicate {
        proof {
            assert forall|candidate: Seq<Ip>| candidate.len() <= remaining implies !members(bytes@, candidate, family) by {
                if members(bytes@, candidate, family) {
                    members_head(bytes@, candidate, family, end as int);
                    Ip::unique(ip, candidate[0], bytes@.subrange(0, end as int));
                    if end < bytes@.len() {
                        members_unique(bytes@.subrange(end as int+1, bytes@.len() as int), tail@, candidate.drop_first(), family);
                    }
                }
            }
        }
        return None;
    }
    tail.insert(0, ip);
    Some(tail)
}

/// Read one required native member list and preserve its unique interpretation.
fn read_members(cache: &Cache, key: &[u8], family: u8) -> (ips: Option<Vec<Ip>>)
    requires cache.valid(), key@.len() < 64, family == 4 || family == 6,
    ensures match ips {
        Some(value) => members_at(*cache, key@, value@, family)
            && (forall|i: int| 0 <= i < value@.len() ==> value@[i].valid() && value@[i].family() == family)
            && (forall|i: int, j: int| 0 <= i < j < value@.len() ==> value@[i].words() != value@[j].words())
            && (forall|other: Seq<Ip>| #[trigger] members_at(*cache, key@, other, family) ==> other == value@),
        None => !(exists|other: Seq<Ip>| members_at(*cache, key@, other, family)),
    },
{
    let bytes = cache.read(key)?;
    let ips = connected(bytes, family, MAX_CLIENTS)?;
    proof {
        assert forall|other: Seq<Ip>| #[trigger] members_at(*cache, key@, other, family) implies other == ips@ by {
            let observed = choose|text: Seq<u8>| observed(*cache, key@, text) && members(text, other, family);
            assert(observed == bytes@);
            members_unique(bytes@, ips@, other, family);
        }
    }
    Some(ips)
}

/// Optional IPv6 addressing is complete only when both native keys are present.
pub struct Ipv6 {
    /// This VM's assigned upstream IPv6 address.
    address: Ip,
    /// Native upstream IPv6 gateway; the routed guest prefix is /128.
    gateway: Ip,
}

impl Ipv6 {
    /// Exact assigned IPv6 address.
    pub closed spec fn address_value(&self) -> Ip { self.address }

    /// Exact upstream IPv6 gateway.
    pub closed spec fn gateway_value(&self) -> Ip { self.gateway }

    /// Both values belong to IPv6 rather than a mixed-family fallback.
    pub closed spec fn valid(&self) -> bool {
        self.address.valid() && self.address.family() == 6
            && self.gateway.valid() && self.gateway.family() == 6
    }

    /// Borrow the exact assigned IPv6 address.
    pub fn address(&self) -> (address: &Ip)
        requires self.valid(), ensures address.valid() && address.family() == 6 && *address == self.address_value(),
    { &self.address }

    /// Borrow the exact selected upstream IPv6 gateway.
    pub fn gateway(&self) -> (gateway: &Ip)
        requires self.valid(), ensures gateway.valid() && gateway.family() == 6 && *gateway == self.gateway_value(),
    { &self.gateway }
}

/// Complete native addressing and membership, separate from source-rule publication.
/// Absence of IPv6 means disabled; an incomplete/malformed IPv6 pair blocks this
/// configuration rather than authorizing a fallback with ambiguous identity.
pub struct Config {
    /// Assigned upstream IPv4 source address from /qubes-ip.
    address: Ip,
    /// Upstream IPv4 gateway from /qubes-gateway.
    gateway: Ip,
    /// Exact contiguous prefix derived from /qubes-netmask.
    prefix: u8,
    /// Both native upstream DNS addresses, used unchanged for specialtarget=dns.
    dns: [Ip; 2],
    /// Native link MAC, independently validated before use by a packet consumer.
    mac: Mac,
    /// Complete upstream IPv6 pair, absent only when both native keys are absent.
    ipv6: Option<Ipv6>,
    /// Gateway exposed to connected clients by this network provider.
    provided_gateway: Ip,
    /// Contiguous provider-side IPv4 prefix.
    provided_prefix: u8,
    /// Provider-side DNS addresses, retained separately from upstream addressing.
    provided_dns: [Ip; 2],
    /// Provider-side IPv6 gateway, required before admitting any IPv6 clients.
    provided_ipv6: Option<Ip>,
    /// At most four normalized IPv4 client addresses.
    connected4: Vec<Ip>,
    /// At most four normalized IPv6 client addresses.
    connected6: Vec<Ip>,
}

impl Config {
    /// This VM's assigned upstream IPv4 address.
    pub closed spec fn address_value(&self) -> Ip { self.address }

    /// Upstream IPv4 router selected by dom0.
    pub closed spec fn gateway_value(&self) -> Ip { self.gateway }

    /// Contiguous upstream IPv4 prefix derived from the native netmask.
    pub closed spec fn prefix_value(&self) -> u8 { self.prefix }

    /// Upstream DNS addresses in native primary/secondary order.
    pub closed spec fn dns_value(&self) -> Seq<Ip> { self.dns@ }

    /// This VM's native six-byte Ethernet identity.
    pub closed spec fn mac_value(&self) -> Mac { self.mac }

    /// Complete optional upstream IPv6 address/gateway pair.
    pub closed spec fn ipv6_value(&self) -> Option<Ipv6> { self.ipv6 }

    /// IPv4 gateway presented to this VM's downstream clients.
    pub closed spec fn provided_gateway_value(&self) -> Ip { self.provided_gateway }

    /// IPv4 prefix on the downstream client network.
    pub closed spec fn provided_prefix_value(&self) -> u8 { self.provided_prefix }

    /// DNS addresses presented to downstream clients, in native order.
    pub closed spec fn provided_dns_value(&self) -> Seq<Ip> { self.provided_dns@ }

    /// Optional IPv6 gateway presented to downstream clients.
    pub closed spec fn provided_ipv6_value(&self) -> Option<Ip> { self.provided_ipv6 }

    /// Every field has a typed interpretation and all membership is bounded.
    pub closed spec fn valid(&self) -> bool {
        self.address.valid() && self.address.family() == 4
            && self.gateway.valid() && self.gateway.family() == 4 && self.prefix <= 32
            && self.provided_gateway.valid() && self.provided_gateway.family() == 4 && self.provided_prefix <= 32
            && (forall|i: int| 0 <= i < 2 ==> self.dns@[i].valid() && self.dns@[i].family() == 4
                && self.provided_dns@[i].valid() && self.provided_dns@[i].family() == 4)
            && (self.ipv6.is_some() ==> self.ipv6.unwrap().valid())
            && (self.provided_ipv6.is_some() ==> self.provided_ipv6.unwrap().valid() && self.provided_ipv6.unwrap().family() == 6)
            && self.connected4@.len() <= MAX_CLIENTS && self.connected6@.len() <= MAX_CLIENTS
            && (forall|i: int| 0 <= i < self.connected4@.len() ==> self.connected4@[i].valid() && self.connected4@[i].family() == 4)
            && (forall|i: int| 0 <= i < self.connected6@.len() ==> self.connected6@[i].valid() && self.connected6@[i].family() == 6)
            && (forall|i: int, j: int| 0 <= i < j < self.connected4@.len() ==> self.connected4@[i].words() != self.connected4@[j].words())
            && (forall|i: int, j: int| 0 <= i < j < self.connected6@.len() ==> self.connected6@[i].words() != self.connected6@[j].words())
            && (self.connected6@.len() > 0 ==> self.ipv6.is_some() && self.provided_ipv6.is_some())
    }

    /// Meaning of the complete native projection. Extra unrelated database
    /// records do not influence addressing; source policy and mapped-IP options
    /// are interpreted separately and cannot authorize an interface here.
    pub closed spec fn describes(&self, cache: Cache) -> bool {
        self.valid()
            && (exists|role: Seq<u8>| observed(cache, b"/qubes-netvm-network"@, role) && role.len() > 0)
            && ip_at(cache, b"/qubes-ip"@, self.address, 4)
            && ip_at(cache, b"/qubes-gateway"@, self.gateway, 4)
            && prefix_at(cache, b"/qubes-netmask"@, self.prefix as int)
            && ip_at(cache, b"/qubes-primary-dns"@, self.dns[0], 4)
            && ip_at(cache, b"/qubes-secondary-dns"@, self.dns[1], 4)
            && (exists|bytes: Seq<u8>| observed(cache, b"/qubes-mac"@, bytes) && mac_token(bytes, self.mac.value()))
            && match self.ipv6 {
                None => absent(cache, b"/qubes-ip6"@) && absent(cache, b"/qubes-gateway6"@),
                Some(value) => ip_at(cache, b"/qubes-ip6"@, value.address, 6)
                    && ip_at(cache, b"/qubes-gateway6"@, value.gateway, 6),
            }
            && ip_at(cache, b"/qubes-netvm-gateway"@, self.provided_gateway, 4)
            && prefix_at(cache, b"/qubes-netvm-netmask"@, self.provided_prefix as int)
            && ip_at(cache, b"/qubes-netvm-primary-dns"@, self.provided_dns[0], 4)
            && ip_at(cache, b"/qubes-netvm-secondary-dns"@, self.provided_dns[1], 4)
            && match self.provided_ipv6 {
                None => absent(cache, b"/qubes-netvm-gateway6"@),
                Some(value) => ip_at(cache, b"/qubes-netvm-gateway6"@, value, 6),
            }
            && members_at(cache, b"/connected-ips"@, self.connected4@, 4)
            && members_at(cache, b"/connected-ips6"@, self.connected6@, 6)
    }

    /// Exact provider-side address for native default mapping interpretation.
    pub closed spec fn provider_address(&self) -> Ip { self.provided_gateway }

    /// Network configuration excluding the independently changing client lists.
    pub closed spec fn same_network_as(&self, other: Config) -> bool {
        self.address == other.address && self.gateway == other.gateway && self.prefix == other.prefix
            && self.dns@ == other.dns@ && self.mac.value() == other.mac.value()
            && self.ipv6 == other.ipv6 && self.provided_gateway == other.provided_gateway
            && self.provided_prefix == other.provided_prefix && self.provided_dns@ == other.provided_dns@
            && self.provided_ipv6 == other.provided_ipv6
    }

    /// Compare complete network addressing while allowing independent membership
    /// additions/removals. Existing source snapshots survive only this equality;
    /// changed DNS/gateway/IPv6 invalidates them until fresh completion writes.
    pub fn same_network(&self, other: &Self) -> (same: bool)
        requires self.valid(), other.valid(),
        ensures same == self.same_network_as(*other),
    {
        if !self.address.same(&other.address) || !self.gateway.same(&other.gateway)
            || self.prefix != other.prefix || *self.mac.bytes() != *other.mac.bytes()
            || !self.provided_gateway.same(&other.provided_gateway) || self.provided_prefix != other.provided_prefix
        { return false; }
        proof { assert(self.mac.value() =~= other.mac.value()); }
        let mut i = 0;
        while i < 2
            invariant self.valid(), other.valid(), i <= 2,
                self.address == other.address && self.gateway == other.gateway && self.prefix == other.prefix,
                self.mac.value() == other.mac.value(), self.provided_gateway == other.provided_gateway,
                self.provided_prefix == other.provided_prefix,
                forall|j: int| 0 <= j < i ==> self.dns@[j] == other.dns@[j] && self.provided_dns@[j] == other.provided_dns@[j],
            decreases 2-i,
        {
            if !self.dns[i].same(&other.dns[i]) || !self.provided_dns[i].same(&other.provided_dns[i]) { return false; }
            i += 1;
        }
        proof {
            assert(self.dns@ =~= other.dns@);
            assert(self.provided_dns@ =~= other.provided_dns@);
        }
        match (&self.ipv6, &other.ipv6) {
            (None, None) => (),
            (Some(left), Some(right)) => {
                if !left.address.same(&right.address) || !left.gateway.same(&right.gateway) { return false; }
                proof { assert(*left == *right); }
            }
            _ => return false,
        }
        match (&self.provided_ipv6, &other.provided_ipv6) {
            (None, None) => true,
            (Some(left), Some(right)) => left.same(right),
            _ => false,
        }
    }

    /// Parse all required authoritative fields together. This does not activate
    /// a source policy or permit binding an interface using QubesDB alone.
    pub fn read(cache: &Cache) -> (config: Option<Self>)
        requires cache.valid(),
        ensures match config {
            Some(value) => value.valid() && value.describes(*cache),
            None => !(exists|value: Config| value.describes(*cache)),
        },
    {
        let role = cache.read(b"/qubes-netvm-network")?;
        if role.is_empty() { return None; }
        let address = read_ip(cache, b"/qubes-ip", 4)?;
        let gateway = read_ip(cache, b"/qubes-gateway", 4)?;
        let prefix = read_mask(cache, b"/qubes-netmask")?;
        let primary = read_ip(cache, b"/qubes-primary-dns", 4)?;
        let secondary = read_ip(cache, b"/qubes-secondary-dns", 4)?;
        let mac_text = cache.read(b"/qubes-mac")?;
        let mac = Mac::parse(mac_text)?;
        let ip6 = cache.read(b"/qubes-ip6");
        let gateway6 = cache.read(b"/qubes-gateway6");
        let ipv6 = match (ip6, gateway6) {
            (None, None) => None,
            (Some(_), Some(_)) => {
                let address = read_ip(cache, b"/qubes-ip6", 6)?;
                let gateway = read_ip(cache, b"/qubes-gateway6", 6)?;
                Some(Ipv6 { address, gateway })
            }
            _ => return None,
        };
        let provided_gateway = read_ip(cache, b"/qubes-netvm-gateway", 4)?;
        let provided_prefix = read_mask(cache, b"/qubes-netvm-netmask")?;
        let p_primary = read_ip(cache, b"/qubes-netvm-primary-dns", 4)?;
        let p_secondary = read_ip(cache, b"/qubes-netvm-secondary-dns", 4)?;
        let provided_ipv6 = if cache.read(b"/qubes-netvm-gateway6").is_some() {
            {
                let value = read_ip(cache, b"/qubes-netvm-gateway6", 6)?;
                Some(value)
            }
        } else { None };
        let connected4 = read_members(cache, b"/connected-ips", 4)?;
        let connected6 = read_members(cache, b"/connected-ips6", 6)?;
        if !connected6.is_empty() && (ipv6.is_none() || provided_ipv6.is_none()) { return None; }
        let config = Self { address, gateway, prefix, dns: [primary, secondary], mac, ipv6,
            provided_gateway, provided_prefix, provided_dns: [p_primary, p_secondary],
            provided_ipv6, connected4, connected6 };
        proof {
            assert(config.valid());
            assert(observed(*cache, b"/qubes-mac"@, mac_text@));
            assert(mac_token(mac_text@, config.mac.value()));
            assert(exists|bytes: Seq<u8>| observed(*cache, b"/qubes-mac"@, bytes) && mac_token(bytes, config.mac.value()));
            assert(match config.ipv6 {
                None => absent(*cache, b"/qubes-ip6"@) && absent(*cache, b"/qubes-gateway6"@),
                Some(value) => ip_at(*cache, b"/qubes-ip6"@, value.address, 6) && ip_at(*cache, b"/qubes-gateway6"@, value.gateway, 6),
            });
            assert(match config.provided_ipv6 {
                None => absent(*cache, b"/qubes-netvm-gateway6"@),
                Some(value) => ip_at(*cache, b"/qubes-netvm-gateway6"@, value, 6),
            });
            assert(ip_at(*cache, b"/qubes-primary-dns"@, config.dns[0], 4));
            assert(ip_at(*cache, b"/qubes-secondary-dns"@, config.dns[1], 4));
            assert(observed(*cache, b"/qubes-netvm-network"@, role@) && role@.len() > 0);
            assert(ip_at(*cache, b"/qubes-ip"@, config.address, 4) && ip_at(*cache, b"/qubes-gateway"@, config.gateway, 4));
            assert(prefix_at(*cache, b"/qubes-netmask"@, config.prefix as int));
            assert(ip_at(*cache, b"/qubes-netvm-gateway"@, config.provided_gateway, 4));
            assert(prefix_at(*cache, b"/qubes-netvm-netmask"@, config.provided_prefix as int));
            assert(ip_at(*cache, b"/qubes-netvm-primary-dns"@, config.provided_dns[0], 4));
            assert(ip_at(*cache, b"/qubes-netvm-secondary-dns"@, config.provided_dns[1], 4));
            assert(members_at(*cache, b"/connected-ips"@, config.connected4@, 4));
            assert(members_at(*cache, b"/connected-ips6"@, config.connected6@, 6));
            assert(config.describes(*cache));
        }
        Some(config)
    }

    /// Exact upstream IPv4 address selected by Qubes.
    pub fn address(&self) -> (ip: &Ip)
        requires self.valid(), ensures *ip == self.address_value(), ip.valid(), ip.family() == 4,
    { &self.address }

    /// Exact upstream default gateway, never derived from packet claims.
    pub fn gateway(&self) -> (ip: &Ip)
        requires self.valid(), ensures *ip == self.gateway_value(), ip.valid(), ip.family() == 4,
    { &self.gateway }

    /// Contiguous upstream prefix length derived from the native mask.
    pub fn prefix(&self) -> (prefix: u8)
        requires self.valid(), ensures prefix == self.prefix_value(), prefix <= 32,
    { self.prefix }

    /// Both native DNS addresses used by the pinned DNS special target.
    pub fn dns(&self) -> (ips: &[Ip; 2])
        requires self.valid(), ensures ips@ == self.dns_value(),
            forall|i: int| 0 <= i < 2 ==> ips@[i].valid() && ips@[i].family() == 4,
    { &self.dns }

    /// Exact native link MAC, without a mutable representation.
    pub fn mac(&self) -> (mac: &Mac)
        ensures mac.value() == self.mac_value().value(),
    { &self.mac }

    /// Complete optional upstream IPv6 addressing.
    pub fn ipv6(&self) -> (ipv6: Option<&Ipv6>)
        requires self.valid(), ensures match ipv6 {
            Some(value) => self.ipv6_value().is_some() && *value == self.ipv6_value().unwrap() && value.valid(),
            None => self.ipv6_value().is_none(),
        },
    { self.ipv6.as_ref() }

    /// Provider-side gateway assigned to connected clients.
    pub fn provided_gateway(&self) -> (ip: &Ip)
        requires self.valid(), ensures *ip == self.provided_gateway_value(), ip.valid(), ip.family() == 4,
    { &self.provided_gateway }

    /// Provider-side contiguous prefix, independent of the uplink prefix.
    pub fn provided_prefix(&self) -> (prefix: u8)
        requires self.valid(), ensures prefix == self.provided_prefix_value(), prefix <= 32,
    { self.provided_prefix }

    /// Provider DNS destinations, distinct from upstream DNS configuration.
    pub fn provided_dns(&self) -> (ips: &[Ip; 2])
        requires self.valid(), ensures ips@ == self.provided_dns_value(),
            forall|i: int| 0 <= i < 2 ==> ips@[i].valid() && ips@[i].family() == 4,
    { &self.provided_dns }

    /// Optional provider IPv6 gateway, required for IPv6 membership.
    pub fn provided_ipv6(&self) -> (ip: Option<&Ip>)
        requires self.valid(), ensures match ip {
            Some(value) => self.provided_ipv6_value().is_some() && *value == self.provided_ipv6_value().unwrap()
                && value.valid() && value.family() == 6,
            None => self.provided_ipv6_value().is_none(),
        },
    { self.provided_ipv6.as_ref() }

    /// Borrow normalized native membership for source-policy slots and binding
    /// checks. Membership alone cannot authenticate any packet or domain lifetime.
    pub fn clients(&self, family: u8) -> (clients: Option<&[Ip]>)
        requires self.valid(),
        ensures match clients {
            Some(value) => (family == 4 || family == 6) && value@.len() <= MAX_CLIENTS
                && (forall|i: int| 0 <= i < value@.len() ==> value@[i].valid() && value@[i].family() == family),
            None => family != 4 && family != 6,
        },
    {
        match family { 4 => Some(self.connected4.as_slice()), 6 => Some(self.connected6.as_slice()), _ => None }
    }

    /// Exact concatenated native client list; IPv4 and IPv6 membership remain
    /// distinct, and neither list supplies a per-interface domain identity.
    pub closed spec fn sources(&self) -> Seq<Ip> { self.connected4@ + self.connected6@ }

    /// Collect the small typed membership list without cloning mutable policy.
    pub fn all_sources(&self) -> (sources: Vec<Ip>)
        requires self.valid(),
        ensures sources@ == self.sources(), sources@.len() <= 2*MAX_CLIENTS,
            (forall|i: int| 0 <= i < sources@.len() ==> sources@[i].valid()),
            forall|i: int, j: int| 0 <= i < j < sources@.len() ==> sources@[i] != sources@[j],
    {
        let mut sources = Vec::new();
        let mut i = 0;
        while i < self.connected4.len()
            invariant self.valid(), i <= self.connected4.len() <= MAX_CLIENTS,
                sources@ == self.connected4@.subrange(0, i as int),
            decreases self.connected4.len()-i,
        { sources.push(self.connected4[i]); i += 1; }
        i = 0;
        while i < self.connected6.len()
            invariant self.valid(), i <= self.connected6.len() <= MAX_CLIENTS,
                sources@ == self.connected4@ + self.connected6@.subrange(0, i as int),
            decreases self.connected6.len()-i,
        { sources.push(self.connected6[i]); i += 1; }
        proof {
            assert forall|i: int, j: int| 0 <= i < j < sources@.len() implies sources@[i] != sources@[j] by {
                if j < self.connected4@.len() {
                    assert(self.connected4@[i].words() != self.connected4@[j].words());
                } else if i < self.connected4@.len() {
                    assert(sources@[i].family() == 4);
                    assert(sources@[j].family() == 6);
                } else {
                    assert(self.connected6@[i-self.connected4@.len() as int].words()
                        != self.connected6@[j-self.connected4@.len() as int].words());
                }
            }
        }
        sources
    }

    /// Test normalized membership, never source identity copied from a packet.
    pub fn contains(&self, address: &Ip) -> (member: bool)
        requires self.valid(), address.valid(),
        ensures member == self.sources().contains(*address),
    {
        let clients = if address.version() == 4 { self.connected4.as_slice() } else { self.connected6.as_slice() };
        let mut i = 0;
        while i < clients.len()
            invariant i <= clients.len() <= MAX_CLIENTS,
                forall|j: int| 0 <= j < i ==> clients@[j].family() != address.family() || clients@[j].words() != address.words(),
                clients@ == if address.family() == 4 { self.connected4@ } else { self.connected6@ },
                self.valid(), address.valid(),
            decreases clients.len()-i,
        {
            if clients[i].same(address) {
                proof {
                    if address.family() == 4 { assert(self.sources()[i as int] == *address); }
                    else { assert(self.sources()[self.connected4@.len() as int+i as int] == *address); }
                }
                return true;
            }
            i += 1;
        }
        false
    }
}

}
