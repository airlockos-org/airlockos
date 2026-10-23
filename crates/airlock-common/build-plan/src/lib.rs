//! Derive exactly the local facts required by a build, then project its complete source requirements.
//! Cargo executes these Verus-checked bodies. TOML interpretation, paths, source-file existence and
//! Nix emission remain adapters. The specification describes positive requirements independently of
//! the solver; it does not claim to formalize Cargo's complete language or Rust compilation.
//! Target-discovery and embedded-asset obligations come from the manifest adapter. Actual filtered
//! Cargo tests check that interpretation; only the normalized rules and source projection are proved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

use vstd::prelude::*;

verus! {

broadcast use {vstd::string::group_string_axioms, vstd::seq_lib::group_seq_properties};

/// A positive build requirement: one or two facts imply another fact.
#[derive(Clone, Copy)]
pub struct Rule {
    /// Required package, dependency activation or feature fact.
    pub first: usize,
    /// Additional condition, used for optional and weakly forwarded features.
    pub second: Option<usize>,
    /// Fact implied when every premise holds.
    pub result: usize,
}

/// Facts represented by a finite executable mask.
pub open spec fn selected(mask: Seq<bool>) -> ISet<usize> {
    ISet::new(|i: usize| i < mask.len() && mask[i as int])
}

/// Every endpoint belongs to the declared fact universe.
pub open spec fn valid_rule(rule: Rule, count: usize) -> bool {
    rule.first < count && rule.result < count && (rule.second is Some ==> rule.second.unwrap() < count)
}

/// All premises of one logical requirement hold.
pub open spec fn ready(rule: Rule, facts: ISet<usize>) -> bool {
    facts.contains(rule.first) && (rule.second is Some ==> facts.contains(rule.second.unwrap()))
}

/// A set respects every declared requirement, regardless of rule enumeration order.
pub open spec fn closed(rules: Seq<Rule>, facts: ISet<usize>) -> bool {
    forall|r: int| 0 <= r < rules.len() && ready(rules[r], facts) ==> facts.contains(#[trigger] rules[r].result)
}

/// No chosen fact is absent from any closed superset of the original requested facts.
pub open spec fn minimal(rules: Seq<Rule>, seeds: ISet<usize>, facts: ISet<usize>) -> bool {
    forall|other: ISet<usize>| seeds.subset_of(other) && closed(rules, other) ==> #[trigger] facts.subset_of(other)
}

/// Least closed superset: completeness and soundness do not mention traversal or pass counts.
pub open spec fn closure(rules: Seq<Rule>, seeds: ISet<usize>, facts: ISet<usize>) -> bool {
    seeds.subset_of(facts) && closed(rules, facts) && minimal(rules, seeds, facts)
}

proof fn transfer(left: Seq<Rule>, right: Seq<Rule>, facts: ISet<usize>)
    requires left.to_set() == right.to_set(), closed(left, facts),
    ensures closed(right, facts),
{
    assert forall|r: int| 0 <= r < right.len() && ready(right[r], facts) implies facts.contains(#[trigger] right[r].result) by {
        assert(left.to_set().contains(right[r]));
        let k = choose|k: int| 0 <= k < left.len() && left[k] == right[r];
        assert(ready(left[k], facts));
    }
}

/// Duplicated or reordered requirements cannot alter the resulting package/feature set.
pub proof fn deterministic(left: Seq<Rule>, right: Seq<Rule>, seeds: ISet<usize>, first: Seq<bool>, second: Seq<bool>)
    requires left.to_set() == right.to_set(), first.len() == second.len(), first.len() <= usize::MAX,
        closure(left, seeds, selected(first)), closure(right, seeds, selected(second)),
    ensures first == second,
{
    transfer(left, right, selected(first));
    transfer(right, left, selected(second));
    assert(selected(first).subset_of(selected(second)));
    assert(selected(second).subset_of(selected(first)));
    assert(selected(first) =~= selected(second));
    assert forall|i: int| 0 <= i < first.len() implies #[trigger] first[i] == second[i] by {
        assert(selected(first).contains(i as usize) == first[i]);
        assert(selected(second).contains(i as usize) == second[i]);
    }
    assert(first =~= second);
}

/// Relate the executable mask update to mathematical set insertion.
proof fn insert(mask: Seq<bool>, fact: usize)
    requires fact < mask.len(),
    ensures selected(mask.update(fact as int, true)) == selected(mask).insert(fact),
{
    assert(selected(mask.update(fact as int, true)) =~= selected(mask).insert(fact));
}

/// Following a declared implication cannot add a fact outside a closed superset.
proof fn extend(rules: Seq<Rule>, seeds: ISet<usize>, facts: ISet<usize>, r: int)
    requires 0 <= r < rules.len(), minimal(rules, seeds, facts), ready(rules[r], facts),
    ensures minimal(rules, seeds, facts.insert(rules[r].result)),
{
    assert forall|other: ISet<usize>| seeds.subset_of(other) && closed(rules, other)
        implies #[trigger] facts.insert(rules[r].result).subset_of(other) by {
        assert(facts.subset_of(other));
        assert(ready(rules[r], other));
        assert(other.contains(rules[r].result));
    }
}

/// Immutable requirement graph with checked endpoint bounds.
pub struct Requirements {
    // Number of package, feature and dependency-activation facts.
    count: usize,
    // Original decoded requirement relation.
    rules: Vec<Rule>,
}

impl Requirements {
    /// Declared fact count.
    pub closed spec fn count(&self) -> usize { self.count }

    /// Original implication relation.
    pub closed spec fn rules(&self) -> Seq<Rule> { self.rules@ }

    #[verifier::type_invariant]
    closed spec fn valid(&self) -> bool {
        forall|r: int| 0 <= r < self.rules@.len() ==> valid_rule(self.rules@[r], self.count)
    }

    /// Reject invalid references before a rule can index a fact mask.
    pub fn new(count: usize, rules: Vec<Rule>) -> (out: Option<Self>)
        ensures out.is_some() ==> out.unwrap().count() == count && out.unwrap().rules() == rules@,
    {
        let mut r = 0;
        while r < rules.len()
            invariant r <= rules.len(), forall|k: int| 0 <= k < r ==> valid_rule(rules[k], count),
            decreases rules.len() - r,
        {
            let rule = rules[r];
            if rule.first >= count || rule.result >= count { return None; }
            let second_valid = match rule.second { Some(second) => second < count, None => true };
            if !second_valid { return None; }
            r += 1;
        }
        Some(Self { count, rules })
    }

    fn fires(&self, r: usize, mask: &[bool]) -> (yes: bool)
        requires r < self.rules().len(), mask.len() == self.count(),
        ensures yes == ready(self.rules()[r as int], selected(mask@)),
    {
        proof { use_type_invariant(self); }
        assert(valid_rule(self.rules()[r as int], self.count));
        let rule = self.rules[r];
        mask[rule.first] && match rule.second { Some(second) => mask[second], None => true }
    }

    fn complete(&self, mask: &[bool]) -> (yes: bool)
        requires mask.len() == self.count(),
        ensures yes == closed(self.rules(), selected(mask@)),
    {
        proof { use_type_invariant(self); }
        let mut r = 0;
        while r < self.rules.len()
            invariant r <= self.rules.len(), mask.len() == self.count,
                self.valid(),
                forall|k: int| 0 <= k < r && ready(self.rules()[k], selected(mask@)) ==> selected(mask@).contains(#[trigger] self.rules()[k].result),
            decreases self.rules.len() - r,
        {
            assert(valid_rule(self.rules()[r as int], self.count));
            if self.fires(r, mask) && !mask[self.rules[r].result] { return false; }
            r += 1;
        }
        true
    }

    /// Compute and check the least requirement closure; a failed completeness check never yields a plan.
    /// The bounded solver terminates even for cycles. Success is proved exact; acceptance of every
    /// well-formed graph is tested rather than part of this contract.
    pub fn solve(&self, seeds: Vec<bool>) -> (out: Option<Vec<bool>>)
        ensures out.is_some() ==> out.unwrap().len() == self.count()
            && closure(self.rules(), selected(seeds@), selected(out.unwrap()@)),
    {
        proof { use_type_invariant(self); }
        if seeds.len() != self.count { return None; }
        let ghost initial = seeds@;
        let mut mask = seeds;
        let mut pass = 0;
        while pass < self.count
            invariant pass <= self.count, mask.len() == self.count,
                self.valid(),
                selected(initial).subset_of(selected(mask@)), minimal(self.rules(), selected(initial), selected(mask@)),
            decreases self.count - pass,
        {
            let mut changed = false;
            let mut r = 0;
            while r < self.rules.len()
                invariant r <= self.rules.len(), mask.len() == self.count,
                    self.valid(),
                    selected(initial).subset_of(selected(mask@)), minimal(self.rules(), selected(initial), selected(mask@)),
                decreases self.rules.len() - r,
            {
                assert(valid_rule(self.rules()[r as int], self.count));
                let rule = self.rules[r];
                if self.fires(r, &mask) && !mask[rule.result] {
                    proof { insert(mask@, rule.result); extend(self.rules(), selected(initial), selected(mask@), r as int); }
                    mask.set(rule.result, true);
                    changed = true;
                }
                r += 1;
            }
            if !changed { break; }
            pass += 1;
        }
        if !self.complete(&mask) { return None; }
        Some(mask)
    }
}

/// Source requirement and its scope. Resolution inputs are shared by the whole workspace.
pub struct Input {
    /// Workspace-relative path, decoded and validated by the manifest adapter.
    pub path: String,
    /// Owning package index; absence means workspace-resolution or target-discovery metadata.
    pub package: Option<usize>,
    /// Only implicit build scripts may be missing; declared sources are mandatory.
    pub optional: bool,
}

/// Complete manifest and discovery obligations for one package.
pub struct Package {
    /// Original Cargo package name used for compilation.
    pub name: String,
    /// Manifest entry in the input table.
    pub manifest: usize,
    /// Entry files Cargo needs to discover otherwise implicit targets.
    pub discovery: Vec<usize>,
}

/// Exact compiler request retained together with the source plan.
pub struct Profile {
    /// Original package index in the canonical manifest table.
    pub package: usize,
    /// Whether Cargo's default features are enabled.
    pub defaults: bool,
    /// Original explicitly requested feature names, in command order.
    pub features: Vec<String>,
}

/// Why a non-package fact exists; dependency activation cannot be selected as a user feature.
pub enum Fact {
    /// Feature token belonging to one package.
    Feature {
        /// Owner in the canonical package table.
        package: usize,
        /// Original feature token.
        name: String,
    },
    /// Local dependency activation, derived only through the requirement rules.
    Dependency,
}

/// Whether one normalized input is required by the computed local package set.
pub open spec fn needed(input: Input, mask: Seq<bool>) -> bool {
    input.package is None || mask[input.package.unwrap() as int]
}

/// Shared metadata cannot be optional or depend on choosing a particular implementation.
pub open spec fn resolution(inputs: Seq<Input>, index: usize) -> bool {
    index < inputs.len() && inputs[index as int].package is None && !inputs[index as int].optional
}

/// Every package contributes its manifest and all necessary target-discovery entries.
pub open spec fn package_ok(package: Package, inputs: Seq<Input>) -> bool {
    resolution(inputs, package.manifest) && forall|d: int| 0 <= d < package.discovery.len()
        ==> resolution(inputs, #[trigger] package.discovery[d])
}

/// Original named feature request, including Cargo's separately controlled defaults.
pub open spec fn requested(profile: Profile, name: Seq<char>) -> bool {
    (profile.defaults && name == "default"@) || exists|f: int| 0 <= f < profile.features.len() && #[trigger] profile.features[f]@ == name
}

/// A feature name resolves only within its owning package's declarations.
pub open spec fn named(facts: Seq<Fact>, package: usize, name: Seq<char>) -> bool {
    exists|i: int| 0 <= i < facts.len() && match #[trigger] facts[i] {
        Fact::Feature { package: owner, name: token } => owner == package && token@ == name,
        Fact::Dependency => false,
    }
}

fn known(facts: &[Fact], package: usize, name: &str) -> (yes: bool)
    ensures yes == named(facts@, package, name@),
{
    let mut i = 0;
    while i < facts.len()
        invariant i <= facts.len(), forall|j: int| 0 <= j < i ==> match #[trigger] facts[j] {
            Fact::Feature { package: owner, name: token } => owner != package || token@ != name@,
            Fact::Dependency => true,
        },
        decreases facts.len() - i,
    {
        let matches = match &facts[i] {
            Fact::Feature { package: owner, name: token } => *owner == package && token.as_str() == name,
            Fact::Dependency => false,
        };
        if matches { return true; }
        i += 1;
    }
    false
}

/// Only the original package and its requested feature tokens are initial facts.
pub open spec fn seed_at(count: usize, facts: Seq<Fact>, profile: Profile, i: int) -> bool {
    if i < count { i == profile.package } else {
        match facts[i - count] {
            Fact::Feature { package, name } => package == profile.package && requested(profile, name@),
            Fact::Dependency => false,
        }
    }
}

/// Ordered feature arguments; a token is always paired with its own option.
pub open spec fn feature_arguments(features: Seq<String>, count: nat) -> Seq<Seq<char>>
    recommends count <= features.len(),
    decreases count,
{
    if count == 0 { seq![] } else {
        feature_arguments(features, (count - 1) as nat) + seq!["--features"@, features[count - 1]@]
    }
}

/// Package/default-feature prefix, independent of how arguments are assembled.
pub open spec fn base_arguments(package: Seq<char>, defaults: bool) -> Seq<Seq<char>> {
    if defaults { seq!["-p"@, package] } else { seq!["-p"@, package, "--no-default-features"@] }
}

/// Only argument values matter, not the addresses of borrowed strings.
pub open spec fn argument_values(args: Seq<&str>) -> Seq<Seq<char>> {
    args.map(|i: int, text: &str| text@)
}

proof fn append_argument(args: Seq<&str>, text: &str)
    ensures argument_values(args.push(text)) == argument_values(args).push(text@),
{
    assert(argument_values(args.push(text)) =~= argument_values(args).push(text@));
}

fn requests(profile: &Profile, name: &str) -> (yes: bool)
    ensures yes == requested(*profile, name@),
{
    if profile.defaults && name == "default" { return true; }
    let mut f = 0;
    while f < profile.features.len()
        invariant f <= profile.features.len(), !(profile.defaults && name@ == "default"@),
            forall|k: int| 0 <= k < f ==> profile.features[k]@ != name@,
        decreases profile.features.len() - f,
    {
        if profile.features[f].as_str() == name { return true; }
        f += 1;
    }
    false
}

fn seeds(packages: usize, facts: &[Fact], profile: &Profile) -> (out: Option<Vec<bool>>)
    requires profile.package < packages,
    ensures out.is_some() ==> out.unwrap().len() == packages + facts.len()
        && (forall|i: int| 0 <= i < out.unwrap().len() ==> out.unwrap()[i] == seed_at(packages, facts@, *profile, i)),
{
    if facts.len() > usize::MAX - packages { return None; }
    let mut mask: Vec<bool> = Vec::new();
    let mut p = 0;
    while p < packages
        invariant p <= packages, mask.len() == p,
            forall|i: int| 0 <= i < p ==> mask[i] == (i == profile.package),
        decreases packages - p,
    {
        mask.push(p == profile.package);
        p += 1;
    }
    let mut f = 0;
    while f < facts.len()
        invariant f <= facts.len(), mask.len() == packages + f, facts.len() <= usize::MAX - packages,
            forall|i: int| 0 <= i < mask.len() ==> mask[i] == seed_at(packages, facts@, *profile, i),
        decreases facts.len() - f,
    {
        let selected = match &facts[f] {
            Fact::Feature { package, name } => *package == profile.package && requests(profile, name.as_str()),
            Fact::Dependency => false,
        };
        mask.push(selected);
        f += 1;
    }
    Some(mask)
}

fn metadata(inputs: &[Input], index: usize) -> (yes: bool)
    ensures yes == resolution(inputs@, index),
{
    index < inputs.len() && inputs[index].package.is_none() && !inputs[index].optional
}

fn packages_ok(packages: &[Package], inputs: &[Input]) -> (yes: bool)
    ensures yes ==> forall|p: int| 0 <= p < packages.len() ==> package_ok(packages[p], inputs@),
{
    let mut p = 0;
    while p < packages.len()
        invariant p <= packages.len(), forall|i: int| 0 <= i < p ==> package_ok(packages[i], inputs@),
        decreases packages.len() - p,
    {
        let package = &packages[p];
        if !metadata(inputs, package.manifest) { return false; }
        let mut d = 0;
        while d < package.discovery.len()
            invariant d <= package.discovery.len(), resolution(inputs@, package.manifest),
                forall|i: int| 0 <= i < d ==> resolution(inputs@, package.discovery[i]),
            decreases package.discovery.len() - d,
        {
            if !metadata(inputs, package.discovery[d]) { return false; }
            d += 1;
        }
        p += 1;
    }
    true
}

fn projection(inputs: &[Input], mask: &[bool]) -> (out: Vec<usize>)
    requires forall|i: int| 0 <= i < inputs.len() && inputs[i].package is Some ==> inputs[i].package.unwrap() < mask.len(),
    ensures
        forall|k: int| 0 <= k < out.len() ==> out[k] < inputs.len() && needed(inputs[out[k] as int], mask@),
        forall|i: int| 0 <= i < inputs.len() ==> (out@.contains(i as usize) == needed(inputs[i], mask@)),
{
    let mut files: Vec<usize> = Vec::new();
    let mut i = 0;
    while i < inputs.len()
        invariant i <= inputs.len(),
            forall|j: int| 0 <= j < inputs.len() && inputs[j].package is Some ==> inputs[j].package.unwrap() < mask.len(),
            forall|k: int| 0 <= k < files.len() ==> files[k] < i && needed(inputs[files[k] as int], mask@),
            forall|j: int| 0 <= j < i ==> (files@.contains(j as usize) == needed(inputs[j], mask@)),
        decreases inputs.len() - i,
    {
        let include = match inputs[i].package { Some(package) => mask[package], None => true };
        assert(include == needed(inputs[i as int], mask@));
        let ghost before = files@;
        assert(!before.contains(i)) by {
            if before.contains(i) {
                let k = choose|k: int| 0 <= k < before.len() && before[k] == i;
                assert(before[k] < i);
            }
        }
        if include { files.push(i); }
        assert(files@.contains(i) == include);
        assert forall|j: int| 0 <= j < i + 1 implies (files@.contains(j as usize) == needed(inputs[j], mask@)) by {
            if j < i { assert(before.contains(j as usize) == needed(inputs[j], mask@)); }
            else { assert(j == i); }
        }
        i += 1;
    }
    files
}

/// Opaque source plan: source entries and compiler selection have one immutable owner.
pub struct CheckedPackageSource {
    // Original normalized source obligations.
    inputs: Vec<Input>,
    // Original package/name/manifest correspondence.
    packages: Vec<Package>,
    // Exact requested Cargo profile.
    profile: Profile,
    // Erased checked requirement graph, needed only to state the closure invariant.
    _graph: Ghost<Requirements>,
    // Checked least fact closure, with package facts first.
    mask: Vec<bool>,
    // Exact required source-table coordinates.
    files: Vec<usize>,
    // Erased original requested facts.
    _seeds: Ghost<Seq<bool>>,
    // Erased canonical feature/dependency fact declarations used to seed this exact profile.
    _facts: Ghost<Seq<Fact>>,
}

impl CheckedPackageSource {
    /// Original normalized obligations.
    pub closed spec fn inputs(&self) -> Seq<Input> { self.inputs@ }

    /// Original package table.
    pub closed spec fn packages(&self) -> Seq<Package> { self.packages@ }

    /// Original Cargo selection.
    pub closed spec fn profile(&self) -> Profile { self.profile }

    /// Complete selected source-table coordinates.
    pub closed spec fn files(&self) -> Seq<usize> { self.files@ }

    /// Immutable checked package/feature fact closure.
    pub closed spec fn mask(&self) -> Seq<bool> { self.mask@ }

    /// Exact decoded implication relation retained by the constructor.
    pub closed spec fn rules(&self) -> Seq<Rule> { self._graph@.rules@ }

    /// Exact decoded non-package identities used for profile seeding.
    pub closed spec fn facts(&self) -> Seq<Fact> { self._facts@ }

    #[verifier::type_invariant]
    closed spec fn valid(&self) -> bool {
        &&& self.profile.package < self.packages.len()
        &&& forall|f: int| 0 <= f < self.profile.features.len() ==> named(self._facts@, self.profile.package, #[trigger] self.profile.features[f]@)
        &&& self.mask.len() == self._graph@.count && self.packages.len() <= self.mask.len()
        &&& self._seeds@.len() == self.mask.len() && self.mask.len() == self.packages.len() + self._facts@.len()
        &&& forall|i: int| 0 <= i < self._seeds@.len() ==> self._seeds@[i] == seed_at(self.packages.len(), self._facts@, self.profile, i)
        &&& self.profile.features.len() <= (usize::MAX - 3) / 2
        &&& closure(self._graph@.rules@, selected(self._seeds@), selected(self.mask@))
        &&& self.mask@[self.profile.package as int]
        &&& forall|i: int| 0 <= i < self.inputs.len() ==> self.inputs@[i].package is Some ==> self.inputs@[i].package.unwrap() < self.packages.len()
        &&& forall|k: int| 0 <= k < self.files.len() ==> self.files@[k] < self.inputs.len() && needed(self.inputs@[self.files@[k] as int], self.mask@)
        &&& forall|i: int| 0 <= i < self.inputs.len() ==> (self.files@.contains(i as usize) == needed(self.inputs@[i], self.mask@))
        &&& forall|p: int| 0 <= p < self.packages.len() ==> self.packages@[p].manifest < self.inputs.len()
            && self.inputs@[self.packages@[p].manifest as int].package is None && !self.inputs@[self.packages@[p].manifest as int].optional
            && (forall|d: int| 0 <= d < self.packages@[p].discovery.len() ==> self.packages@[p].discovery[d] < self.inputs.len()
                && self.inputs@[self.packages@[p].discovery[d] as int].package is None && !self.inputs@[self.packages@[p].discovery[d] as int].optional)
    }

    /// Derive sources from the original profile and requirement graph; arbitrary selection masks are not accepted.
    pub fn check(packages: Vec<Package>, inputs: Vec<Input>, facts: Vec<Fact>, rules: Vec<Rule>, profile: Profile) -> (out: Option<Self>)
        ensures out.is_some() ==> out.unwrap().profile() == profile && out.unwrap().packages() == packages@
            && out.unwrap().inputs() == inputs@ && out.unwrap().rules() == rules@ && out.unwrap().facts() == facts@,
    {
        if profile.package >= packages.len() || !packages_ok(&packages, &inputs)
            || profile.features.len() > (usize::MAX - 3) / 2 { return None; }
        let mut f = 0;
        while f < profile.features.len()
            invariant f <= profile.features.len(), forall|j: int| 0 <= j < f ==> named(facts@, profile.package, profile.features[j]@),
            decreases profile.features.len() - f,
        {
            if !known(&facts, profile.package, profile.features[f].as_str()) { return None; }
            f += 1;
        }
        let mut i = 0;
        while i < inputs.len()
            invariant i <= inputs.len(),
                forall|j: int| 0 <= j < i && inputs[j].package is Some ==> inputs[j].package.unwrap() < packages.len(),
            decreases inputs.len() - i,
        {
            let owner_valid = match inputs[i].package { Some(owner) => owner < packages.len(), None => true };
            if !owner_valid { return None; }
            i += 1;
        }
        let initial = seeds(packages.len(), &facts, &profile)?;
        assert(initial[profile.package as int] == seed_at(packages.len(), facts@, profile, profile.package as int));
        assert(initial[profile.package as int]);
        let graph = Requirements::new(initial.len(), rules)?;
        let ghost original = initial@;
        let mask = graph.solve(initial)?;
        assert(selected(original).contains(profile.package));
        assert(selected(mask@).contains(profile.package));
        assert(mask[profile.package as int]);
        let files = projection(&inputs, &mask);
        Some(Self { packages, inputs, profile, _graph: Ghost(graph), mask, files, _seeds: Ghost(original), _facts: Ghost(facts@) })
    }

    /// Number of selected source requirements, including shared resolution/discovery metadata.
    pub fn file_count(&self) -> (out: usize) ensures out == self.files().len(),
    { self.files.len() }

    /// Return only a selected requirement, preserving its original path, owner and optionality.
    pub fn file(&self, position: usize) -> (out: Option<&Input>)
        ensures out.is_some() == (position < self.files().len()),
            out.is_some() ==> *out.unwrap() == self.inputs()[self.files()[position as int] as int],
    {
        proof { use_type_invariant(self); }
        if position >= self.files.len() { return None; }
        Some(&self.inputs[self.files[position]])
    }

    /// Package identity forwarded to Cargo comes from the same table as source ownership.
    pub fn package(&self) -> (out: &str)
        ensures out@ == self.packages()[self.profile().package as int].name@,
    {
        proof { use_type_invariant(self); }
        self.packages[self.profile.package].name.as_str()
    }

    /// Preserve the original default-feature policy.
    pub fn defaults(&self) -> (out: bool) ensures out == self.profile().defaults,
    { self.profile.defaults }

    /// Preserve the original explicit feature request, without replacing it with its expanded closure.
    pub fn features(&self) -> (out: &Vec<String>) ensures *out == self.profile().features,
    { &self.profile.features }

    /// Build Cargo's package and feature flags from the same immutable profile used for source selection.
    pub fn arguments(&self) -> (out: Vec<&str>)
        ensures argument_values(out@) == base_arguments(self.packages()[self.profile().package as int].name@, self.profile().defaults)
            + feature_arguments(self.profile().features@, self.profile().features.len() as nat),
    {
        proof { use_type_invariant(self); }
        let mut args = Vec::new();
        args.push("-p");
        args.push(self.package());
        if !self.profile.defaults { args.push("--no-default-features"); }
        let ghost base = base_arguments(self.packages()[self.profile().package as int].name@, self.profile().defaults);
        assert(argument_values(args@) =~= base);
        let mut f = 0;
        while f < self.profile.features.len()
            invariant f <= self.profile.features.len(), self.valid(),
                base == base_arguments(self.packages()[self.profile().package as int].name@, self.profile().defaults),
                argument_values(args@) == base + feature_arguments(self.profile.features@, f as nat),
            decreases self.profile.features.len() - f,
        {
            proof { append_argument(args@, "--features"); }
            args.push("--features");
            let feature = self.profile.features[f].as_str();
            proof { append_argument(args@, feature); }
            args.push(feature);
            f += 1;
        }
        args
    }

    /// Observe package membership for Cargo comparisons without exposing a mutable source mask.
    pub fn includes(&self, package: usize) -> (out: bool)
        ensures package < self.packages().len() ==> out == self.mask()[package as int],
    {
        proof { use_type_invariant(self); }
        package < self.packages.len() && self.mask[package]
    }
}

}
