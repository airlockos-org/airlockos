//! Exercise the executable callback decisions used by the installed storage plugin.

use airlock_deployment_core::volume_lifecycle::{
    Action, Effect, ImmutableOptions, LifecyclePlan, ViewKind,
};

/// Render a selected effect sequence for assertions without duplicating selection logic.
fn effects(plan: &LifecyclePlan) -> Vec<&'static str> {
    plan.effects()
        .iter()
        .map(|effect| match effect {
            Effect::Verify => "verify",
            Effect::Attach => "attach",
            Effect::Detach => "detach",
            Effect::Pin => "pin",
            Effect::Unpin => "unpin",
        })
        .collect()
}

#[test]
fn normalization_rejects_derivation_and_never_persists_a_mapper() {
    for (writable, snapshot, source) in [
        (true, false, false),
        (false, true, false),
        (false, false, true),
    ] {
        assert!(
            ImmutableOptions::check(ViewKind::MetadataImage, writable, snapshot, source).is_none()
        );
    }
    let metadata = ImmutableOptions::check(ViewKind::MetadataImage, false, false, false).unwrap();
    assert!(!metadata.writable() && !metadata.snapshot() && metadata.persistent());
    assert_eq!(
        metadata.persisted_path(Some("/pool/image".into())),
        Some("/pool/image".into())
    );
    let blob = ImmutableOptions::check(ViewKind::ErofsBlobMap, false, false, false).unwrap();
    assert!(
        blob.persisted_path(Some("/dev/mapper/transient".into()))
            .is_none()
    );
}

#[test]
fn generation_start_and_stop_order_mapper_effects_before_running_references() {
    let start = LifecyclePlan::select(Action::Start, ViewKind::ErofsBlobMap, true, true).unwrap();
    assert_eq!(effects(&start), ["verify", "attach", "pin"]);
    assert!(start.requires_lock());
    let stop = LifecyclePlan::select(Action::Stop, ViewKind::ErofsBlobMap, true, true).unwrap();
    assert_eq!(effects(&stop), ["detach", "unpin"]);
    assert!(stop.requires_lock());
    let metadata =
        LifecyclePlan::select(Action::Start, ViewKind::MetadataImage, true, false).unwrap();
    assert_eq!(effects(&metadata), ["verify", "pin"]);
    assert!(metadata.requires_lock());
}

#[test]
fn create_legacy_and_reconciliation_callbacks_cannot_invent_generation_pins() {
    let create =
        LifecyclePlan::select(Action::Create, ViewKind::ErofsBlobMap, false, false).unwrap();
    assert_eq!(effects(&create), ["verify"]);
    assert!(!create.requires_lock());
    let legacy =
        LifecyclePlan::select(Action::Start, ViewKind::MetadataImage, false, true).unwrap();
    assert_eq!(effects(&legacy), ["verify"]);
    assert!(!legacy.requires_lock());
    let verify =
        LifecyclePlan::select(Action::Verify, ViewKind::ErofsBlobMap, true, false).unwrap();
    assert_eq!(effects(&verify), ["verify", "attach"]);
    assert!(verify.requires_lock());
    let existing =
        LifecyclePlan::select(Action::BlockDevice, ViewKind::ErofsBlobMap, true, true).unwrap();
    assert_eq!(effects(&existing), ["verify"]);
    assert!(existing.requires_lock());
    assert!(LifecyclePlan::select(Action::Start, ViewKind::ErofsBlobMap, false, true).is_none());
    assert!(LifecyclePlan::select(Action::Verify, ViewKind::ErofsBlobMap, false, false).is_none());
}

#[test]
fn unsupported_callbacks_and_immutable_mutations_fail_closed() {
    assert!(Action::parse("resize").is_none());
    assert!(ViewKind::parse("writable-image").is_none());
    assert!(LifecyclePlan::select(Action::Immutable, ViewKind::ErofsBlobMap, true, true).is_none());
    let no_identity =
        LifecyclePlan::select(Action::Stop, ViewKind::MetadataImage, false, false).unwrap();
    assert!(effects(&no_identity).is_empty());
}
