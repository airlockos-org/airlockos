//! Preserve the exact ordered topology policy through text publication and refresh requests.
//! These production checks cover Airlock's restricted policy language. Qubes owns interpretation
//! of the complete policy directory, earlier static/bootstrap rules and enforcement. Filesystem
//! durability acknowledgments and truthful service observations come from the external adapters.

use vstd::prelude::*;
use vstd::string::StrSliceExecFns;

verus! {

broadcast use {vstd::string::group_string_axioms, vstd::seq_lib::group_seq_properties};

/// Installed daemon policy root, shared with machine authoring and runtime publication.
pub fn directory() -> (out: &'static str)
    ensures out@ == "/var/lib/airlock/qubes-policy.d"@,
{ "/var/lib/airlock/qubes-policy.d" }

/// Topology-owned filename; bootstrap files remain separate and earlier in Qubes' ordered search.
pub fn filename() -> (out: &'static str)
    ensures out@ == "90-airlock.policy"@,
{ "90-airlock.policy" }

/// Fixed comment-only prefix, specified independently of the executable renderer.
pub open spec fn header_text() -> Seq<char> {
    "# Managed by Airlock setup-config.\n# Source: airlock.qubes.topology.qrexec_policy.\n# Bootstrap config transport policy remains in 30-airlock-config.policy.\n"@
}

/// Fixed ownership marker and informational header; no policy directives or permissions.
pub fn header() -> (text: &'static str)
    ensures text@ == header_text(),
{
    r#"# Managed by Airlock setup-config.
# Source: airlock.qubes.topology.qrexec_policy.
# Bootstrap config transport policy remains in 30-airlock-config.policy.
"#
}

/// ASCII characters allowed inside literal service names and endpoints.
pub open spec fn atom(c: char) -> bool {
    (65 <= c as u32 <= 90) || (97 <= c as u32 <= 122) || (48 <= c as u32 <= 57)
        || c == '_' || c == '.' || c == '-'
}

fn atom_exec(c: char) -> (yes: bool)
    ensures yes == atom(c),
{
    let n = c as u32;
    (65..=90).contains(&n) || (97..=122).contains(&n) || (48..=57).contains(&n)
        || c == '_' || c == '.' || c == '-'
}

/// Literal tokens cannot insert whitespace, comments, directives or additional policy fields.
pub open spec fn literal(text: Seq<char>, argument: bool) -> bool {
    text.len() > 0 && forall|i: int| 0 <= i < text.len() ==>
        atom(#[trigger] text[i]) || (argument && (text[i] == ':' || text[i] == '+'))
}

fn literal_exec(text: &str, argument: bool) -> (yes: bool)
    ensures yes == literal(text@, argument),
{
    let n = text.unicode_len();
    if n == 0 { return false; }
    let mut i = 0;
    while i < n
        invariant n == text@.len(), n > 0, i <= n,
            forall|j: int| 0 <= j < i ==> atom(#[trigger] text@[j]) || (argument && (text@[j] == ':' || text@[j] == '+')),
        decreases n - i,
    {
        let c = text.get_char(i);
        if !atom_exec(c) && !(argument && (c == ':' || c == '+')) { return false; }
        i += 1;
    }
    true
}

/// Bootstrap transport names remain owned by the separate static policy.
pub open spec fn protected(service: Seq<char>) -> bool {
    service == "airlock.Config.CandidateExport"@ || service == "airlock.Config.ValidateCandidate"@
        || service == "airlock.Config.InputsImport"@ || service == "airlock.Config.ArchiveCandidate"@
        || service == "airlock.Config.ArchiveDeployment"@ || service == "airlock.Config.Status"@
        || service == "airlock.Config.Check"@ || service == "airlock.Config.Apply"@ || service == "airlock.Config.Rollback"@
}

fn protected_exec(service: &str) -> (yes: bool)
    ensures yes == protected(service@),
{
    service == "airlock.Config.CandidateExport" || service == "airlock.Config.ValidateCandidate"
        || service == "airlock.Config.InputsImport" || service == "airlock.Config.ArchiveCandidate"
        || service == "airlock.Config.ArchiveDeployment" || service == "airlock.Config.Status"
        || service == "airlock.Config.Check" || service == "airlock.Config.Apply" || service == "airlock.Config.Rollback"
}

/// Valid service namespace, excluding separately protected bootstrap permissions.
pub open spec fn service_name(text: Seq<char>) -> bool {
    text.len() > "airlock."@.len() && text.take("airlock."@.len() as int) == "airlock."@
        && literal(text, false) && !protected(text)
}

/// A validated literal Airlock service name; wildcard services and directives have no constructor.
pub struct Service {
    // Exact declared service spelling, never widened to a service prefix or wildcard.
    text: String,
}

impl View for Service {
    type V = Seq<char>;

    closed spec fn view(&self) -> Self::V { self.text@ }
}

impl Service {
    #[verifier::type_invariant]
    closed spec fn valid(&self) -> bool { service_name(self.text@) }

    /// Reject unsupported spellings and reserved bootstrap services without rewriting the name.
    pub fn new(text: String) -> (out: Option<Self>)
        ensures out.is_some() == service_name(text@), out.is_some() ==> out.unwrap()@ == text@,
    {
        let prefix = "airlock.";
        let length = prefix.unicode_len();
        if text.as_str().unicode_len() <= length { return None; }
        if text.as_str().substring_char(0, length) != prefix || !literal_exec(text.as_str(), false)
            || protected_exec(text.as_str()) { return None; }
        Some(Self { text })
    }
}

/// Qubes arguments are either the explicit wildcard or an exact '+'-prefixed argument.
pub open spec fn argument_name(text: Seq<char>) -> bool {
    text == "*"@ || (literal(text, true) && text[0] == '+')
}

/// A checked RPC argument, preserving exact matching separately from the wildcard.
pub struct Argument {
    // Exact wire spelling; '+' denotes the empty service argument in Qubes policy.
    text: String,
}

impl View for Argument {
    type V = Seq<char>;

    closed spec fn view(&self) -> Self::V { self.text@ }
}

impl Argument {
    #[verifier::type_invariant]
    closed spec fn valid(&self) -> bool { argument_name(self.text@) }

    /// Reject arguments the upstream policy parser cannot interpret as exact arguments.
    pub fn new(text: String) -> (out: Option<Self>)
        ensures out.is_some() == argument_name(text@), out.is_some() ==> out.unwrap()@ == text@,
    {
        if text.as_str() != "*" && (!literal_exec(text.as_str(), true) || text.as_str().get_char(0) != '+') { return None; }
        Some(Self { text })
    }
}

/// Supported endpoints include concrete guests, the explicit host source and a deny-only wildcard.
pub open spec fn endpoint_name(text: Seq<char>) -> bool {
    text == "@anyvm"@ || text == "dom0"@ || crate::topology::guest(text)
}

/// An endpoint with validated Qubes identity grammar; role restrictions are checked by Rule.
pub struct Endpoint {
    // Original endpoint spelling; no tag, disposable-VM or UUID expansion is supported here.
    text: String,
}

impl View for Endpoint {
    type V = Seq<char>;

    closed spec fn view(&self) -> Self::V { self.text@ }
}

impl Endpoint {
    #[verifier::type_invariant]
    closed spec fn valid(&self) -> bool { endpoint_name(self.text@) }

    /// Preserve exact VM identity and reject special endpoints outside the topology policy subset.
    pub fn new(text: String) -> (out: Option<Self>)
        ensures out.is_some() == endpoint_name(text@), out.is_some() ==> out.unwrap()@ == text@,
    {
        if text.as_str() != "@anyvm" && text.as_str() != "dom0" && !crate::topology::valid_guest(text.as_str()) { return None; }
        Some(Self { text })
    }
}

/// Supported rule actions; asking a user or redirecting execution is not part of topology policy.
#[derive(Clone, Copy)]
pub enum Action {
    /// Permit the exact endpoints and declared argument pattern.
    Allow,
    /// Refuse the matching request.
    Deny,
}

impl Action {
    /// Decode exactly the two supported wire actions; unknown actions never acquire a default.
    pub fn parse(text: &str) -> (out: Option<Self>)
        ensures match out { Some(Action::Allow) => text@ == "allow"@, Some(Action::Deny) => text@ == "deny"@,
            None => text@ != "allow"@ && text@ != "deny"@ },
    {
        if text == "allow" { Some(Self::Allow) } else if text == "deny" { Some(Self::Deny) } else { None }
    }
}

/// Untrusted decoded rule fields. Deserialization supplies data; only the verified decoder checks it.
#[cfg_attr(all(feature = "wire", not(verus_keep_ghost)), derive(serde::Deserialize))]
#[cfg_attr(all(feature = "wire", not(verus_keep_ghost)), serde(deny_unknown_fields))]
pub struct Declaration {
    /// Literal service spelling before namespace and protected-service validation.
    pub service: String,
    /// Exact or wildcard argument before grammar validation.
    pub argument: String,
    /// Source endpoint before identity validation.
    pub source: String,
    /// Target endpoint before dom0 and wildcard restrictions.
    pub target: String,
    /// Unclassified action; unknown values must not default to allow or deny.
    pub action: String,
}

/// Exact original five-field projection; validation cannot silently rewrite a declared row.
pub closed spec fn corresponds(rule: Rule, raw: Declaration) -> bool {
    rule.service@ == raw.service@ && rule.argument@ == raw.argument@ && rule.source@ == raw.source@
        && rule.target@ == raw.target@ && (if rule.action is Allow { raw.action@ == "allow"@ } else { raw.action@ == "deny"@ })
}

/// Independent encoding of decoded declarations before typed-rule construction.
pub open spec fn declared_line(raw: Declaration) -> Seq<char> {
    raw.service@ + " "@ + raw.argument@ + " "@ + raw.source@ + " "@ + raw.target@ + " "@ + raw.action@ + "\n"@
}

/// The declared order and multiplicity determine policy text, independently of validation traversal.
pub open spec fn declared_text(raw: Seq<Declaration>) -> Seq<char>
    decreases raw.len(),
{
    if raw.len() == 0 { header_text() } else { declared_text(raw.drop_last()) + declared_line(raw.last()) }
}

/// A rule cannot target dom0, and only denial can use a wildcard endpoint.
pub open spec fn permitted(source: Seq<char>, target: Seq<char>, action: Action) -> bool {
    target != "dom0"@ && (action is Allow ==> source != "@anyvm"@ && target != "@anyvm"@)
}

/// One fully checked rule; callers cannot replace fields after scope checking.
pub struct Rule {
    // Literal service identity, excluding the protected bootstrap list.
    service: Service,
    // Original exact or wildcard service argument.
    argument: Argument,
    // Original source identity, including the explicit host-source exception.
    source: Endpoint,
    // Original target, which cannot be dom0.
    target: Endpoint,
    // Explicit allow or deny action.
    action: Action,
}

impl View for Rule {
    type V = (Seq<char>, Seq<char>, Seq<char>, Seq<char>, Action);

    closed spec fn view(&self) -> Self::V { (self.service@, self.argument@, self.source@, self.target@, self.action) }
}

/// Independent rule validity, including each field's grammar and the permitted effect scope.
pub closed spec fn valid_rule(rule: Rule) -> bool {
    service_name(rule.service@) && argument_name(rule.argument@) && endpoint_name(rule.source@)
        && endpoint_name(rule.target@) && permitted(rule.source@, rule.target@, rule.action)
}

/// Exact five-field rule encoding; each declared row contributes one ordered line.
pub closed spec fn line(rule: Rule) -> Seq<char> {
    rule.service@ + " "@ + rule.argument@ + " "@ + rule.source@ + " "@ + rule.target@ + " "@
        + (if rule.action is Allow { "allow"@ } else { "deny"@ }) + "\n"@
}

impl Rule {
    #[verifier::type_invariant]
    closed spec fn valid(&self) -> bool { valid_rule(*self) }

    /// Bind all typed fields and enforce target/endpoint restrictions before rendering is possible.
    pub fn new(service: Service, argument: Argument, source: Endpoint, target: Endpoint, action: Action) -> (out: Option<Self>)
        ensures out.is_some() == permitted(source@, target@, action),
            out.is_some() ==> out.unwrap()@ == (service@, argument@, source@, target@, action),
    {
        proof { use_type_invariant(&service); use_type_invariant(&argument); use_type_invariant(&source); use_type_invariant(&target); }
        if target.text.as_str() == "dom0" || (matches!(action, Action::Allow)
            && (source.text.as_str() == "@anyvm" || target.text.as_str() == "@anyvm")) { return None; }
        Some(Self { service, argument, source, target, action })
    }

    fn decode(raw: &Declaration) -> (out: Option<Self>)
        ensures out.is_some() ==> corresponds(out.unwrap(), *raw),
    {
        let service = Service::new(raw.service.clone())?;
        let argument = Argument::new(raw.argument.clone())?;
        let source = Endpoint::new(raw.source.clone())?;
        let target = Endpoint::new(raw.target.clone())?;
        let action = Action::parse(raw.action.as_str())?;
        Self::new(service, argument, source, target, action)
    }

    fn render(&self) -> (text: String)
        ensures text@ == line(*self), valid_rule(*self),
    {
        proof {
            use_type_invariant(self);
            reveal_strlit(" ");
            reveal_strlit("\n");
            assert(" "@ =~= seq![' ']);
            assert("\n"@ =~= seq!['\n']);
        }
        broadcast use appended_character;
        let mut text = self.service.text.clone();
        text.push(' '); text.push_str(self.argument.text.as_str());
        text.push(' '); text.push_str(self.source.text.as_str());
        text.push(' '); text.push_str(self.target.text.as_str()); text.push(' ');
        text.push_str(match self.action { Action::Allow => "allow", Action::Deny => "deny" });
        text.push('\n');
        text
    }
}

/// Relate Rust's single-character append to the specification's token separators.
broadcast proof fn appended_character(text: Seq<char>, c: char)
    ensures #[trigger] text.push(c) == text + seq![c],
{
    assert(text.push(c) =~= text + seq![c]);
}

/// Ordered policy specification, independent of the executable append loop.
pub closed spec fn encoded(rules: Seq<Rule>) -> Seq<char>
    decreases rules.len(),
{
    if rules.len() == 0 { header_text() } else { encoded(rules.drop_last()) + line(rules.last()) }
}

proof fn append(rules: Seq<Rule>, i: int)
    requires 0 <= i < rules.len(),
    ensures encoded(rules.take(i + 1)) == encoded(rules.take(i)) + line(rules[i]),
{
    assert(rules.take(i + 1).drop_last() =~= rules.take(i));
    assert(rules.take(i + 1).last() == rules[i]);
}

proof fn projection(raw: Seq<Declaration>, rules: Seq<Rule>)
    requires raw.len() == rules.len(), forall|i: int| 0 <= i < rules.len() ==> corresponds(#[trigger] rules[i], raw[i]),
    ensures declared_text(raw) == encoded(rules),
    decreases rules.len(),
{
    if rules.len() > 0 {
        projection(raw.drop_last(), rules.drop_last());
        assert(corresponds(rules.last(), raw.last()));
        assert(declared_line(raw.last()) == line(rules.last()));
    }
}

/// Immutable complete policy whose text preserves every checked rule, duplicate and ordering.
pub struct CheckedPolicy {
    // Original ordered declarations, retained to bind publication to their exact projection.
    _rules: Vec<Rule>,
    // Cached verified encoding; adapters must publish these bytes without reconstructing rules.
    text: String,
}

impl View for CheckedPolicy {
    type V = (Seq<Rule>, Seq<char>);

    closed spec fn view(&self) -> Self::V { (self._rules@, self.text@) }
}

impl CheckedPolicy {
    #[verifier::type_invariant]
    closed spec fn valid(&self) -> bool {
        self.text@ == encoded(self._rules@) && forall|i: int| 0 <= i < self._rules.len() ==> valid_rule(#[trigger] self._rules@[i])
    }

    /// Encode exactly the supplied ordered rules, including an empty policy's fixed header.
    pub fn new(rules: Vec<Rule>) -> (out: Self)
        ensures out@.0 == rules@, out@.1 == encoded(rules@),
    {
        let mut text = header().to_string();
        let mut i = 0;
        while i < rules.len()
            invariant i <= rules.len(), text@ == encoded(rules@.take(i as int)),
                forall|j: int| 0 <= j < i ==> valid_rule(#[trigger] rules[j]),
            decreases rules.len() - i,
        {
            let row = rules[i].render();
            proof { append(rules@, i as int); }
            text.push_str(row.as_str());
            i += 1;
        }
        Self { _rules: rules, text }
    }

    /// Validate every decoded row and preserve its exact fields, position and multiplicity.
    /// One invalid rule rejects the entire policy before any publication is possible.
    pub fn decode(raw: Vec<Declaration>) -> (out: Option<Self>)
        ensures out.is_some() ==> out.unwrap()@.0.len() == raw@.len()
            && (forall|i: int| 0 <= i < raw@.len() ==> corresponds(#[trigger] out.unwrap()@.0[i], raw@[i]))
            && out.unwrap()@.1 == declared_text(raw@),
    {
        let mut rules = Vec::new();
        let mut i = 0;
        while i < raw.len()
            invariant i <= raw.len(), rules.len() == i,
                forall|j: int| 0 <= j < i ==> corresponds(#[trigger] rules[j], raw[j]),
            decreases raw.len() - i,
        {
            let rule = Rule::decode(&raw[i])?;
            rules.push(rule);
            i += 1;
        }
        proof { projection(raw@, rules@); }
        Some(Self::new(rules))
    }

    /// Borrow the verified publication bytes; no adapter-controlled renderer is involved.
    pub fn text(&self) -> (out: &str)
        ensures out@ == self@.1, out@ == encoded(self@.0),
    {
        proof { use_type_invariant(self); }
        self.text.as_str()
    }
}

/// Publication and informational preview paths selected together, without diagnostic JSON.
/// Filesystem resolution and the configured policy-directory check remain adapter duties.
///
/// ```compile_fail
/// use airlock_machine_planning::ipc_policy::{CheckedPolicy, Installation};
/// let bypass = Installation::new("/preview".into(), CheckedPolicy::new(vec![]));
/// ```
pub struct PolicyPaths {
    // Sole destination allowed to become an executable publication request.
    target: String,
    // Informational output, excluded from publication authority.
    rendered: String,
}

impl View for PolicyPaths {
    type V = (Seq<char>, Seq<char>);

    closed spec fn view(&self) -> Self::V { (self.target@, self.rendered@) }
}

impl PolicyPaths {
    #[verifier::type_invariant]
    closed spec fn valid(&self) -> bool {
        self.target@.len() > 0 && self.rendered@.len() > 0 && self.target@ != self.rendered@
    }

    /// Refuse missing or identical destinations while preserving both exact path identities.
    pub fn new(target: String, rendered: String) -> (out: Option<Self>)
        ensures out.is_some() == (target@.len() > 0 && rendered@.len() > 0 && target@ != rendered@),
            out.is_some() ==> out.unwrap()@ == (target@, rendered@),
    {
        if target.is_empty() || rendered.is_empty() || target == rendered { None }
        else { Some(Self { target, rendered }) }
    }

    /// Borrow the selected installation destination.
    pub fn target(&self) -> (out: &str)
        ensures out@ == self@.0,
    { self.target.as_str() }

    /// Borrow the separate informational preview destination.
    pub fn rendered(&self) -> (out: &str)
        ensures out@ == self@.1,
    { self.rendered.as_str() }

    /// Bind publication to this selection's target and exact checked policy, accepting no replacement path.
    pub fn installation(&self, policy: CheckedPolicy) -> (out: Installation)
        ensures out@ == (self@.0, policy@),
    {
        proof { use_type_invariant(self); }
        Installation::new(self.target.as_str().to_string(), policy).unwrap()
    }
}

/// One exact target and checked policy awaiting durable publication; it cannot request a refresh.
///
/// ```compile_fail
/// use airlock_machine_planning::ipc_policy::{CheckedPolicy, PolicyPaths};
/// let paths = PolicyPaths::new("/policy/90-airlock.policy".into(), "/logs/preview".into()).unwrap();
/// let pending = paths.installation(CheckedPolicy::new(vec![]));
/// let request = pending.request();
/// ```
pub struct Installation {
    // Caller-selected administrative policy path, retained without adapter substitution.
    target: String,
    // Original checked rules and their verified byte representation.
    policy: CheckedPolicy,
}

impl View for Installation {
    type V = (Seq<char>, (Seq<Rule>, Seq<char>));

    closed spec fn view(&self) -> Self::V { (self.target@, self.policy@) }
}

impl Installation {
    /// Bind a nonempty target to the complete checked policy before any publication effect.
    fn new(target: String, policy: CheckedPolicy) -> (out: Option<Self>)
        ensures out.is_some() == (target@.len() > 0), out.is_some() ==> out.unwrap()@ == (target@, policy@),
    {
        if target.is_empty() { return None; }
        Some(Self { target, policy })
    }

    /// Exact path consumed by the filesystem publisher.
    pub fn target(&self) -> (out: &str) ensures out@ == self@.0,
    { self.target.as_str() }

    /// Exact verified bytes consumed by that same publisher.
    pub fn text(&self) -> (out: &str) ensures out@ == self@.1.1, out@ == encoded(self@.1.0),
    { self.policy.text() }

    /// Accept matching readback only after the filesystem adapter has acknowledged durable publication.
    /// This checks the acknowledgment's binding; it does not prove that fsync/rename occurred.
    pub fn published(self, observed_target: &str, observed_text: &str) -> (out: Option<PublishedPolicy>)
        ensures out.is_some() == (observed_target@ == self@.0 && observed_text@ == self@.1.1),
            out.is_some() ==> out.unwrap()@ == self@,
    {
        if observed_target != self.target.as_str() || observed_text != self.policy.text() { return None; }
        Some(PublishedPolicy { binding: self })
    }
}

/// Matching publication acknowledgment, consumed when requesting the upstream refresh.
pub struct PublishedPolicy {
    // Original installation, whose identity survived the publication/readback check.
    binding: Installation,
}

impl View for PublishedPolicy {
    type V = (Seq<char>, (Seq<Rule>, Seq<char>));

    closed spec fn view(&self) -> Self::V { self.binding@ }
}

impl PublishedPolicy {
    /// Request a refresh only through a publication-bound, non-cloneable capability.
    pub fn request(self) -> (out: RefreshRequest) ensures out@ == self@,
    { RefreshRequest { binding: self.binding } }
}

/// The existing upstream service operations, never caller-supplied service names.
#[derive(Clone, Copy)]
pub enum RefreshKind {
    /// Ask a service with an explicit reload implementation to reread policy.
    Reload,
    /// Restart only an already active daemon when reload is unsupported or fails.
    Restart,
}

/// An external refresh outcome; only acknowledged running service state permits completion.
#[derive(Clone, Copy)]
pub enum RefreshOutcome {
    /// Successful refresh command followed by an active-service observation.
    Running,
    /// A rejected, failed, timed-out or inactive service observation.
    Failed,
    /// The adapter cannot establish whether the external operation completed.
    Uncertain,
}

/// A refresh bound to the exact durably published text; no public constructor or target setter.
///
/// ```compile_fail
/// use airlock_machine_planning::ipc_policy::RefreshRequest;
/// let request = RefreshRequest { binding: panic!("unpublished") };
/// ```
pub struct RefreshRequest {
    // Original checked policy and its publication target.
    binding: Installation,
}

impl View for RefreshRequest {
    type V = (Seq<char>, (Seq<Rule>, Seq<char>));

    closed spec fn view(&self) -> Self::V { self.binding@ }
}

impl RefreshRequest {
    /// Return only the fixed upstream daemon's operation and unit, preserving argument boundaries.
    pub fn arguments(&self, kind: RefreshKind) -> (out: Vec<String>)
        ensures out@.len() == 2,
            out@[0]@ == (if kind is Reload { "reload"@ } else { "try-restart"@ }),
            out@[1]@ == "qubes-qrexec-policy-daemon.service"@,
    {
        vec![match kind { RefreshKind::Reload => "reload".to_string(), RefreshKind::Restart => "try-restart".to_string() },
            "qubes-qrexec-policy-daemon.service".to_string()]
    }

    /// Observe the exact service whose refresh was requested, without accepting a replacement unit.
    pub fn active_arguments(&self) -> (out: Vec<String>)
        ensures out@.len() == 3, out@[0]@ == "is-active"@, out@[1]@ == "--quiet"@,
            out@[2]@ == "qubes-qrexec-policy-daemon.service"@,
    {
        vec!["is-active".to_string(), "--quiet".to_string(), "qubes-qrexec-policy-daemon.service".to_string()]
    }

    /// Inspect the exact installed policy again after the refresh operation.
    pub fn target(&self) -> (out: &str) ensures out@ == self@.0,
    { self.binding.target() }

    /// An unsuccessful or uncertain refresh cannot acknowledge a policy, nor can changed readback.
    pub fn complete(self, observed_target: &str, observed_text: &str, outcome: RefreshOutcome) -> (out: Option<RefreshedPolicy>)
        ensures out.is_some() == (outcome is Running && observed_target@ == self@.0 && observed_text@ == self@.1.1),
            out.is_some() ==> out.unwrap()@ == self@,
    {
        if !matches!(outcome, RefreshOutcome::Running) || observed_target != self.binding.target()
            || observed_text != self.binding.text() { return None; }
        Some(RefreshedPolicy { binding: self.binding })
    }
}

/// Successful refresh acknowledgment for the original checked policy, not an internal Qubes cache hash.
/// File observation, service health and faithful external parsing/enforcement remain adapter contracts.
pub struct RefreshedPolicy {
    // Original rules, exact encoded bytes and exact installed target, unchanged across both barriers.
    binding: Installation,
}

impl View for RefreshedPolicy {
    type V = (Seq<char>, (Seq<Rule>, Seq<char>));

    closed spec fn view(&self) -> Self::V { self.binding@ }
}

impl RefreshedPolicy {
    /// Borrow the exact acknowledged policy text for diagnostics without reconstructing its authority.
    pub fn text(&self) -> (out: &str) ensures out@ == self@.1.1, out@ == encoded(self@.1.0),
    { self.binding.text() }
}

}
