//! Missing library contracts. Runtime operations remain in the standard library
//! and ChaCha; these boundaries neither select network policy nor grant owners.

use alloc::{
    collections::{BTreeMap, VecDeque},
    vec::Vec,
};
use rand_chacha::ChaCha20Rng;
#[cfg(verus_keep_ghost)]
use rand_core::RngCore;
use rand_core::SeedableRng;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::std_specs::iter::IteratorSpec;

verus! {

/// Connect vstd's existing elementwise array equality to structural bytes.
/// This is a proof about its supplied library specification, with no runtime
/// comparison wrapper and no new equality assumption.
pub(crate) broadcast proof fn byte_array_equality<const N: usize>(left: [u8; N], right: [u8; N])
    ensures #[trigger] <[u8; N] as vstd::std_specs::cmp::PartialEqSpec>::eq_spec(&left, &right) == (left == right),
{
    if <[u8; N] as vstd::std_specs::cmp::PartialEqSpec>::eq_spec(&left, &right) {
        assert(left@ =~= right@);
        assert(left =~= right);
    }
}

/// The actual upstream generator; no first-party random-number implementation.
#[cfg(verus_keep_ghost)]
#[verifier::external_type_specification]
#[verifier::external_body]
pub struct ExChaCha20Rng(/// Unchanged upstream state; no first-party generator is substituted.
    ChaCha20Rng);

/// Seed the unchanged library generator from caller-supplied platform entropy.
/// Correct allocation bounds do not assume any particular generated value.
#[verifier::external_body]
pub(crate) fn generator(seed: [u8; 32]) -> ChaCha20Rng { ChaCha20Rng::from_seed(seed) }

/// Exact upstream random-word interface. Unpredictability remains a dependency
/// and entropy-source assumption, not a conclusion of finite resource proofs.
#[cfg(verus_keep_ghost)]
#[verifier::external_trait_specification]
pub trait ExRngCore {
    type ExternalTraitSpecificationFor: RngCore;

    fn next_u32(&mut self) -> u32;

    fn next_u64(&mut self) -> u64;

    fn fill_bytes(&mut self, destination: &mut [u8]);
}

/// Delegate retention for unique resource records to the standard library.
/// Fn (rather than arbitrary stateful FnMut) lets the predicate's stable result
/// specify exactly which original record remains. This is the same dependency
/// boundary used by QubesDB's retained-record storage.
#[verifier::external_body]
pub(crate) fn retain_vec<T, F: Fn(&T) -> bool>(values: &mut Vec<T>, keep: F)
    requires old(values)@.no_duplicates(),
        forall|value: T| old(values)@.contains(value) ==> call_requires(keep, (&value,)),
    ensures final(values)@ == old(values)@.filter(|value: T| final(values)@.contains(value)),
        final(values)@.no_duplicates(), final(values)@.len() <= old(values)@.len(),
        forall|i: int| 0 <= i < final(values)@.len() ==> old(values)@.contains(final(values)@[i]),
        forall|value: T| old(values)@.contains(value) ==> call_ensures(keep, (&value,), final(values)@.contains(value)),
{ values.retain(keep); }

/// Delegate queue-record retention with the same exact stable predicate model.
#[verifier::external_body]
pub(crate) fn retain_deque<T, F: Fn(&T) -> bool>(values: &mut VecDeque<T>, keep: F)
    requires old(values)@.no_duplicates(),
        forall|value: T| old(values)@.contains(value) ==> call_requires(keep, (&value,)),
    ensures final(values)@ == old(values)@.filter(|value: T| final(values)@.contains(value)),
        final(values)@.no_duplicates(), final(values)@.len() <= old(values)@.len(),
        forall|i: int| 0 <= i < final(values)@.len() ==> old(values)@.contains(final(values)@[i]),
        forall|value: T| old(values)@.contains(value) ==> call_ensures(keep, (&value,), final(values)@.contains(value)),
{ values.retain(keep); }

/// Rust's derived Ord on these product types is a total order consistent with
/// structural equality. This missing vstd contract trusts compiler derives and
/// the standard map, not NAT admission, quota or lifecycle decisions.
#[verifier::external_body]
pub(crate) proof fn derived_key_order()
    ensures vstd::std_specs::btree::key_obeys_cmp_spec::<(crate::engine::Owner, crate::wire::Tuple)>(),
{ }

/// Native Option construction preserves the caller's value exactly.
pub assume_specification<T>[ bool::then_some ](condition: bool, value: T) -> (result: Option<T>)
    ensures result == if condition { Some(value) } else { None },
;

/// Counting a finite standard filter consumes exactly its remaining values.
pub assume_specification<I: Iterator, P: FnMut(&I::Item) -> bool>[ <core::iter::Filter<I, P> as Iterator>::count ](iter: core::iter::Filter<I, P>) -> (count: usize)
    requires IteratorSpec::obeys_prophetic_iter_laws(&iter), IteratorSpec::remaining(&iter).len() <= usize::MAX,
    ensures count == IteratorSpec::remaining(&iter).len(),
;

/// Mathematical subset inspected and selected by the standard map's filter.
pub(crate) uninterp spec fn selected_keys<V, F>(map: Map<u16, V>, predicate: F) -> Set<u16>;

/// Count values selected by a pure caller-supplied predicate using the standard
/// map iterator. Trust scope is std's key/value correspondence and count; every
/// predicate decision remains checked in the caller's verified closure.
#[verifier::external_body]
pub(crate) fn count_values<V, F: Fn(&V) -> bool>(map: &BTreeMap<u16, V>, keep: F) -> (count: usize)
    requires forall|port: u16| map@.dom().contains(port) ==> call_requires(keep, (&map@[port],)),
    ensures selected_keys(map@, keep).subset_of(map@.dom()), count == selected_keys(map@, keep).len(),
        count <= map@.len(),
        forall|port: u16| map@.dom().contains(port) ==> call_ensures(keep, (&map@[port],), selected_keys(map@, keep).contains(port)),
{ map.values().filter(|value| keep(value)).count() }

/// Select the standard map's first bounded ascending port window. The caller
/// supplies its work budget; expiry and quota decisions are not made here.
#[verifier::external_body]
pub(crate) fn port_window<V>(map: &BTreeMap<u16, V>, start: u16, limit: usize) -> (keys: Vec<u16>)
    requires limit <= crate::MAX_FLOWS,
    ensures keys@.len() <= limit, keys@.no_duplicates(),
        map@.len() <= limit && start == 0 ==> keys@.to_set() == map@.dom(),
        forall|i: int| 0 <= i < keys@.len() ==> map@.dom().contains(keys@[i]) && keys@[i] >= start,
        forall|i: int, j: int| 0 <= i < j < keys@.len() ==> keys@[i] < keys@[j],
        forall|key: u16| map@.dom().contains(key) && key >= start && !keys@.contains(key)
            ==> keys@.len() == limit && (forall|i: int| 0 <= i < keys@.len() ==> keys@[i] < key),
{ map.range(start..).take(limit).map(|(&key, _)| key).collect() }

}
