//! Select immutable-volume callback mutation requests before external execution.
//! Observed identity and mapper availability are adapter evidence, not authorization.
//! The plan fixes effect ordering and admission-lock requirements for one callback.

use vstd::prelude::*;

verus! {

/// Upstream immutable storage view implementation.
#[derive(Clone, Copy)]
pub enum ViewKind {
    /// Read-only metadata image opened directly by Qubes.
    MetadataImage,
    /// Filtered external-data mapper attached for a retained generation.
    ErofsBlobMap,
}

impl ViewKind {
    /// Reject unsupported view implementations at both Python and CLI boundaries.
    pub fn parse(name: &str) -> (out: Option<Self>)
        ensures out.is_some() == (name@ == "metadata-image"@ || name@ == "erofs-blob-map"@),
            out.is_some() ==> view_name(out.unwrap()) == name@,
    {
        if name == "metadata-image" { Some(Self::MetadataImage) }
        else if name == "erofs-blob-map" { Some(Self::ErofsBlobMap) }
        else { None }
    }

    /// Stable upstream configuration spelling of this view.
    pub fn name(&self) -> (out: &str)
        ensures out@ == view_name(*self),
    {
        match self { Self::MetadataImage => "metadata-image", Self::ErofsBlobMap => "erofs-blob-map" }
    }
}

/// Mathematical encoding of the supported upstream view kinds.
pub open spec fn view_name(kind: ViewKind) -> Seq<char> {
    match kind { ViewKind::MetadataImage => "metadata-image"@, ViewKind::ErofsBlobMap => "erofs-blob-map"@ }
}

/// Only immutable, persistent, source-independent volume options pass this gate.
pub struct ImmutableOptions {
    // View implementation whose persistence rules must be preserved.
    kind: ViewKind,
}

impl View for ImmutableOptions {
    type V = ViewKind;

    closed spec fn view(&self) -> ViewKind { self.kind }
}

impl ImmutableOptions {
    /// Refuse writable views, snapshot derivation and parent-volume sources.
    pub fn check(kind: ViewKind, writable: bool, snapshot: bool, source: bool) -> (out: Option<Self>)
        ensures out.is_some() == (!writable && !snapshot && !source),
            out.is_some() ==> out.unwrap()@ == kind,
    {
        if writable || snapshot || source { None } else { Some(Self { kind }) }
    }

    /// Checked volumes never request guest write access.
    pub fn writable(&self) -> (out: bool)
        ensures !out,
    { false }

    /// Checked volumes never request snapshot derivation.
    pub fn snapshot(&self) -> (out: bool)
        ensures !out,
    { false }

    /// Checked immutable identities survive VM shutdown.
    pub fn persistent(&self) -> (out: bool)
        ensures out,
    { true }

    /// Persist metadata image paths, but never retain a transient mapper as a view image.
    pub fn persisted_path(&self, path: Option<String>) -> (out: Option<String>)
        ensures out == (if self@ is MetadataImage { path } else { None }),
    {
        match self.kind { ViewKind::MetadataImage => path, ViewKind::ErofsBlobMap => None }
    }
}

/// Fixed lifecycle callbacks; unknown strings never select a default operation.
#[derive(Clone, Copy)]
pub enum Action {
    /// Validate definitions without attaching or pinning a generation.
    Create,
    /// Validate and reconcile a missing runtime mapper.
    Verify,
    /// Attach a view before publishing its running reference.
    Start,
    /// Release an attached view before removing its running reference.
    Stop,
    /// Reconcile the runtime device before upstream constructs a block device.
    BlockDevice,
    /// Reject import, resize and other writes to immutable software.
    Immutable,
}

/// Mathematical encoding of accepted lifecycle callback names.
pub open spec fn action_name(action: Action) -> Seq<char> {
    match action {
        Action::Create => "create"@, Action::Verify => "verify"@, Action::Start => "start"@,
        Action::Stop => "stop"@, Action::BlockDevice => "block-device"@, Action::Immutable => "immutable"@,
    }
}

impl Action {
    /// Decode only the supported lifecycle vocabulary.
    pub fn parse(name: &str) -> (out: Option<Self>)
        ensures out.is_some() == (name@ == "create"@ || name@ == "verify"@ || name@ == "start"@
            || name@ == "stop"@ || name@ == "block-device"@ || name@ == "immutable"@),
            out.is_some() ==> action_name(out.unwrap()) == name@,
    {
        if name == "create" { Some(Self::Create) }
        else if name == "verify" { Some(Self::Verify) }
        else if name == "start" { Some(Self::Start) }
        else if name == "stop" { Some(Self::Stop) }
        else if name == "block-device" { Some(Self::BlockDevice) }
        else if name == "immutable" { Some(Self::Immutable) }
        else { None }
    }
}

/// Narrow external operations performed by the existing storage engine.
#[derive(Clone, Copy)]
pub enum Effect {
    /// Check the immutable source paths and view metadata.
    Verify,
    /// Attach and validate the generation's filtered device.
    Attach,
    /// Release the generation's filtered device.
    Detach,
    /// Publish a running reference after successful preparation.
    Pin,
    /// Remove a running reference after successful release.
    Unpin,
}

/// Intended callback semantics, independent of the executable vector construction.
pub open spec fn expected(action: Action, kind: ViewKind, identity: bool, path_exists: bool) -> Option<Seq<Effect>> {
    match action {
        Action::Immutable => None,
        Action::Create => Some(seq![Effect::Verify]),
        Action::Stop => Some(if !identity { seq![] } else if kind is ErofsBlobMap {
            seq![Effect::Detach, Effect::Unpin] } else { seq![Effect::Unpin] }),
        Action::Start => if kind is ErofsBlobMap {
            if identity { Some(seq![Effect::Verify, Effect::Attach, Effect::Pin]) } else { None }
        } else { Some(if identity { seq![Effect::Verify, Effect::Pin] } else { seq![Effect::Verify] }) },
        Action::Verify | Action::BlockDevice => if kind is ErofsBlobMap && !path_exists {
            if identity { Some(seq![Effect::Verify, Effect::Attach]) } else { None }
        } else { Some(seq![Effect::Verify]) },
    }
}

/// Admission locking required around all mapper reconciliation and generation pin changes.
pub open spec fn lock_required(action: Action, kind: ViewKind, identity: bool) -> bool {
    (kind is ErofsBlobMap && !(action is Create) && !(action is Immutable))
        || (identity && (action is Start || action is Stop))
}

/// Decide admission locking before reading mapper availability, so planning observes protected state.
pub fn admission_lock(action: Action, kind: ViewKind, identity: bool) -> (out: bool)
    ensures out == lock_required(action, kind, identity),
{
    let runtime = matches!(action, Action::Start | Action::Stop | Action::Verify | Action::BlockDevice);
    (matches!(kind, ViewKind::ErofsBlobMap) && runtime)
        || (identity && matches!(action, Action::Start | Action::Stop))
}

/// Opaque ordered effects selected from one callback and its observed evidence.
pub struct LifecyclePlan {
    // Complete selected effect sequence; adapters cannot append another operation.
    effects: Vec<Effect>,
    // Admission lock required throughout this sequence's external execution.
    lock: bool,
}

impl View for LifecyclePlan {
    type V = (Seq<Effect>, bool);

    closed spec fn view(&self) -> Self::V { (self.effects@, self.lock) }
}

impl LifecyclePlan {
    /// Refuse immutable writes and mapper operations without a retained identity.
    pub fn select(action: Action, kind: ViewKind, identity: bool, path_exists: bool) -> (out: Option<Self>)
        ensures out.is_some() == expected(action, kind, identity, path_exists).is_some(),
            out.is_some() ==> out.unwrap()@.0 == expected(action, kind, identity, path_exists).unwrap()
                && out.unwrap()@.1 == lock_required(action, kind, identity),
    {
        if let Action::Immutable = action { return None; }
        let blob = matches!(kind, ViewKind::ErofsBlobMap);
        let stop = matches!(action, Action::Stop);
        let start = matches!(action, Action::Start);
        let create = matches!(action, Action::Create);
        let lock = admission_lock(action, kind, identity);
        let mut effects = Vec::new();
        if stop {
            if identity {
                if blob { effects.push(Effect::Detach); }
                effects.push(Effect::Unpin);
            }
        } else {
            effects.push(Effect::Verify);
            if blob && !create && (start || !path_exists) {
                if !identity { return None; }
                effects.push(Effect::Attach);
            }
            if start && identity { effects.push(Effect::Pin); }
        }
        Some(Self { effects, lock })
    }

    /// Whether the adapter must acquire and retain the admission lock before executing effects.
    pub fn requires_lock(&self) -> (out: bool)
        ensures out == self@.1,
    { self.lock }

    /// Exact ordered effect sequence, with verification before attachment and attachment before pinning.
    pub fn effects(&self) -> (out: &[Effect])
        ensures out@ == self@.0,
    { &self.effects }
}

}
