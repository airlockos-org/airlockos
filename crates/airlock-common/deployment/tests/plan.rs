//! Exercise complete-plan admission and its immutable execution binding.

use airlock_deployment_core::{
    operation::{AttemptId, AuthorityBinding, IntentBinding, OperationId, PlanBinding},
    plan::AuthorizedPlan,
    review::{Binding, Denial, Identity, Review, Status},
};
use airlock_machine_planning::effects::PlanEffects;

/// Empty classified plan with an established no-reboot outcome.
fn plan() -> PlanEffects<'static> {
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

/// Protected approval of one VM and the exact source/candidate/baseline.
fn review() -> Review<'static> {
    Review {
        request: "review",
        revision: "source",
        lock: "lock",
        guest: None,
        baseline: "baseline",
        fingerprint: Some("shown"),
        status: Status::Approved,
        release: None,
        operation: None,
        allowed: vec!["usr-home"],
        allow_reboot: false,
    }
}

/// Reviewed candidate mapping, independent of final artifacts.
fn binding() -> Binding<'static> {
    Binding {
        request: "review",
        release: "candidate",
        revision: "source",
        lock: "lock",
    }
}

/// Identity carries no independently supplied impact or reboot claims.
fn candidate() -> Identity<'static> {
    Identity {
        release: "candidate",
        revision: "source",
        lock: "lock",
        guest: None,
        baseline: Some("baseline"),
        previous_operation: None,
    }
}

/// Admit a full plan with no requested lifecycle subset.
fn check(p: &PlanEffects) -> Result<AuthorizedPlan, Denial> {
    AuthorizedPlan::reviewed(
        &review(),
        &binding(),
        &candidate(),
        p,
        vec![],
        PlanBinding::new("complete-plan".into()),
    )
}

/// Select the distinct effect source exercised by this regression.
fn category<'a>(p: &'a mut PlanEffects<'static>, index: usize) -> &'a mut Vec<&'static str> {
    match index {
        0 => &mut p.changed,
        1 => &mut p.stage,
        2 => &mut p.stop,
        3 => &mut p.start,
        4 => &mut p.affected,
        5 => &mut p.retire,
        6 => &mut p.restore,
        7 => &mut p.copy_sources,
        8 => &mut p.copy_targets,
        9 => &mut p.gui_providers,
        10 => &mut p.gui_clients,
        11 => &mut p.pci_sources,
        12 => &mut p.pci_targets,
        13 => &mut p.configure,
        _ => unreachable!(),
    }
}

/// Every classified source independently consumes scope, including non-lifecycle effects.
#[test]
fn every_effect_category_requires_approval() {
    for index in 0..14 {
        let mut p = plan();
        category(&mut p, index).push("usr-home");
        assert!(check(&p).is_ok(), "approved category {index}");
        category(&mut p, index).push("sys-net");
        assert!(matches!(check(&p), Err(Denial::Scope)), "category {index}");
    }
}

/// Full projection is exact as a set even with overlaps and duplicates across categories.
#[test]
fn composite_projection_is_complete_and_contains_no_invented_names() {
    let mut p = plan();
    p.changed = vec!["usr-home", "usr-home"];
    p.start = vec!["sys-net"];
    p.copy_sources = vec!["usr-home"];
    p.copy_targets = vec!["usr-data"];
    p.gui_providers = vec!["sys-gui"];
    p.gui_clients = vec!["usr-desktop"];
    p.pci_sources = vec!["usr-assistant"];
    p.pci_targets = vec!["sys-net"];
    let names = p
        .project()
        .unwrap()
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        names,
        [
            "usr-home",
            "sys-net",
            "usr-data",
            "sys-gui",
            "usr-desktop",
            "usr-assistant"
        ]
        .into_iter()
        .collect()
    );
    assert!(matches!(check(&p), Err(Denial::Scope)));
}

/// Unknown fields fail even under an administrative or review-disabled exception.
#[test]
fn unknown_effects_and_unknown_reboot_requirements_fail_closed() {
    let mut p = plan();
    p.unknown.push("future_effect");
    assert!(p.project().is_none());
    assert!(matches!(check(&p), Err(Denial::Unsupported)));
    assert!(AuthorizedPlan::policy_exempt(&p, vec![], PlanBinding::new("plan".into())).is_none());
    p.unknown.clear();
    for reboot in [None, Some(true)] {
        p.reboot = reboot;
        assert!(matches!(check(&p), Err(Denial::Scope)));
    }
    assert!(AuthorizedPlan::policy_exempt(&p, vec![], PlanBinding::new("plan".into())).is_some());
}

/// Identity checks remain required even when the effect projection is empty.
#[test]
fn wrong_identity_or_consumed_operation_cannot_authorize_an_empty_plan() {
    let mut c = candidate();
    c.release = "other";
    assert!(
        AuthorizedPlan::reviewed(
            &review(),
            &binding(),
            &c,
            &plan(),
            vec![],
            PlanBinding::new("plan".into())
        )
        .is_err()
    );
    c = candidate();
    c.baseline = Some("stale");
    assert!(
        AuthorizedPlan::reviewed(
            &review(),
            &binding(),
            &c,
            &plan(),
            vec![],
            PlanBinding::new("plan".into())
        )
        .is_err()
    );
    let mut r = review();
    r.status = Status::Started;
    r.release = Some("candidate");
    r.operation = Some("original");
    c = candidate();
    c.previous_operation = Some("replacement");
    assert!(
        AuthorizedPlan::reviewed(
            &r,
            &binding(),
            &c,
            &plan(),
            vec![],
            PlanBinding::new("plan".into())
        )
        .is_err()
    );
}

/// Publication cannot replace the binding captured when the complete plan was checked.
#[test]
fn checked_plan_is_the_plan_published() {
    for proposed in ["other-plan", "complete-plan"] {
        let operation = check(&plan())
            .unwrap()
            .operation(
                AttemptId::new("attempt".into()),
                AuthorityBinding::new("authority".into()),
            )
            .unwrap();
        let gate = operation.publication(
            &AttemptId::new("attempt".into()),
            &OperationId::new("attempt".into()),
            &AuthorityBinding::new("authority".into()),
            &PlanBinding::new(proposed.into()),
            IntentBinding::new("intent".into()),
        );
        assert_eq!(gate.is_some(), proposed == "complete-plan");
    }
}
