//! Shared genuine review and publication setup for deployment resource boundary tests.

use airlock_deployment_core::{operation::*, plan::AuthorizedPlan, publication::Event, review::*};
use airlock_machine_planning::effects::PlanEffects;

/// Empty classified plan; tests populate only the operation fields they exercise.
pub fn effects() -> PlanEffects<'static> {
    PlanEffects {
        configure: vec![],
        changed: vec![],
        stage: vec![],
        stop: vec![],
        start: vec![],
        affected: vec![],
        retire: vec![],
        restore: vec![],
        copy_sources: vec![],
        copy_targets: vec![],
        gui_providers: vec![],
        gui_clients: vec![],
        pci_sources: vec![],
        pci_targets: vec![],
        firewall_parameters: vec![],
        unknown: vec![],
        reboot: Some(false),
    }
}

/// Check real review data; no caller-provided permission flag is involved.
pub fn approved(plan: &PlanEffects, allowed: Vec<&str>) -> Result<AuthorizedPlan, Denial> {
    let review = Review {
        request: "review",
        revision: "revision",
        lock: "lock",
        guest: None,
        baseline: "baseline",
        fingerprint: Some("shown"),
        status: Status::Approved,
        release: None,
        operation: None,
        allowed,
        allow_reboot: false,
    };
    let binding = Binding {
        request: "review",
        release: "candidate",
        revision: "revision",
        lock: "lock",
    };
    let identity = Identity {
        release: "candidate",
        revision: "revision",
        lock: "lock",
        guest: None,
        baseline: Some("baseline"),
        previous_operation: None,
    };
    AuthorizedPlan::reviewed(
        &review,
        &binding,
        &identity,
        plan,
        vec![],
        PlanBinding::new("complete-plan".into()),
    )
}

/// Journal identities freshly extracted at a resource request.
pub fn context() -> ExecutionContext {
    ExecutionContext {
        attempt: AttemptId::new("attempt".into()),
        operation: OperationId::new("attempt".into()),
        authority: AuthorityBinding::new("authority".into()),
        plan: PlanBinding::new("complete-plan".into()),
    }
}

/// Create a real publication gate; optionally supply both acknowledgments and consume begin.
pub fn durable(plan: AuthorizedPlan, executing: bool) -> DurableOperation {
    let c = context();
    let operation = plan
        .operation(
            AttemptId::new("attempt".into()),
            AuthorityBinding::new("authority".into()),
        )
        .unwrap();
    let mut gate = operation
        .publication(
            &c.attempt,
            &c.operation,
            &c.authority,
            &c.plan,
            IntentBinding::new("intent".into()),
        )
        .unwrap();
    if executing {
        gate.advance(Event::IntentSaved);
        gate.advance(Event::ApprovalSaved);
        assert!(gate.begin(&c.attempt, &IntentBinding::new("intent".into())));
    }
    gate
}
