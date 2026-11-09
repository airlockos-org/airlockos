//! Check that ordinary Cargo's proof erasure retains the gate's execution behavior.

use airlock_deployment_core::publication::{Event, Publication};

#[test]
fn interruption_requires_new_acknowledgments() {
    let mut initial = Publication::new("attempt-1".into(), "intent-1".into());
    initial.advance(Event::IntentSaved);
    assert!(!initial.begin("attempt-1", "intent-1"));
    initial.advance(Event::ApprovalSaved);
    assert!(!initial.permits("attempt-1", "intent-1"));

    let mut recovered = Publication::new("attempt-2".into(), "intent-2".into());
    recovered.advance(Event::IntentSaved);
    recovered.advance(Event::ApprovalSaved);
    assert!(recovered.begin("attempt-2", "intent-2"));
    recovered.advance(Event::Interrupted);
    assert!(!recovered.begin("attempt-2", "intent-2"));
}

/// A retained receipt cannot cross a changed request, approval, boot or commit boundary.
#[test]
fn completed_publication_requires_the_original_binding() {
    use airlock_deployment_core::publication::completion_matches;
    assert!(completion_matches(
        true, "request", "request", "approval", "approval", "boot", "boot"
    ));
    assert!(!completion_matches(
        false, "request", "request", "approval", "approval", "boot", "boot"
    ));
    assert!(!completion_matches(
        true, "old", "request", "approval", "approval", "boot", "boot"
    ));
    assert!(!completion_matches(
        true, "request", "request", "revoked", "approval", "boot", "boot"
    ));
    assert!(!completion_matches(
        true, "request", "request", "approval", "approval", "previous", "boot"
    ));
}
