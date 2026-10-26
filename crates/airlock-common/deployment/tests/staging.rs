//! Complete staging uses genuine approval and durable gates before any backend selection.

mod support;

use airlock_deployment_core::{
    boot::{SelectedGeneration, Selection},
    operation::*,
    publication::Event,
    storage::{Definition, Native, staging::*},
};
use support::*;

/// One original native VM, optionally pinned by the admitted release.
fn definition(name: &str, generation: Option<u64>) -> Definition {
    Definition {
        executable: None,
        name: name.into(),
        service: "/native/service".into(),
        native: Some(Native {
            system: "/system".into(),
            root: "/root".into(),
            source: "/closure".into(),
            artifact: "/artifact".into(),
            kernel: "kernel".into(),
            kernel_source: String::new(),
            kernelopts: "init=/sbin/init".into(),
            private_size: None,
            generation,
        }),
    }
}

/// Trusted test observation of a complete committed identity, independently of approval.
fn identity(name: &str, generation: u64) -> Selection {
    Selection {
        domain: name.into(),
        generation,
        system: "/system".into(),
        root: "/root".into(),
        source: "/closure".into(),
        kernel: "kernel".into(),
        mode: "shared-closure".into(),
        device: "/dev/xvde".into(),
        blob_device: "/dev/xvdf".into(),
        mountpoint: "/nix/store".into(),
        backend: "erofs-objectmap".into(),
    }
}

/// Authenticate an inert test observation; production obtains the comparison from the pool loader.
fn retained(name: &str, generation: u64) -> Resolution {
    Resolution::Retained(Box::new(
        SelectedGeneration::check(identity(name, generation), &identity(name, generation)).unwrap(),
    ))
}

/// Planned dependency staging is required even without a generation pinned in the manifest.
#[test]
fn complete_staging_distinguishes_required_existing_and_nonnative_work() {
    let mut effects = effects();
    effects.configure = vec!["pinned", "dependency", "unchanged", "external"];
    effects.stage = vec!["dependency"];
    let p = approved(&effects, effects.configure.clone()).unwrap();
    let plan = p
        .storage(vec![
            definition("pinned", Some(7)),
            definition("dependency", None),
            definition("unchanged", None),
            Definition {
                executable: None,
                name: "external".into(),
                native: None,
                service: "/native/service".into(),
            },
        ])
        .unwrap();
    let gate = durable(p, true);
    assert!(matches!(
        plan.requirement(0),
        Some(Requirement::Resolve(Some(7)))
    ));
    assert!(matches!(
        plan.requirement(1),
        Some(Requirement::Resolve(None))
    ));
    assert!(matches!(plan.requirement(2), Some(Requirement::Existing)));
    assert!(matches!(plan.requirement(3), Some(Requirement::NonNative)));
    let staged = plan
        .check_staged(
            &gate,
            &context(),
            vec![
                retained("pinned", 7),
                retained("dependency", 9),
                Resolution::Existing,
                Resolution::NonNative,
            ],
        )
        .unwrap();
    for (index, expected) in [(0, Some(7)), (1, Some(9)), (2, None)] {
        let selected = plan
            .select_staged(&gate, &context(), &staged, index)
            .unwrap();
        assert_eq!(selected.store().unwrap().generation(), expected);
    }
    assert!(plan.select_staged(&gate, &context(), &staged, 3).is_none());
    assert!(plan.select_staged(&gate, &context(), &staged, 4).is_none());
}

/// Missing, reordered or invented entries never become an implicit unchanged-storage exception.
#[test]
fn incomplete_and_unjustified_staging_fails_closed() {
    let mut effects = effects();
    effects.configure = vec!["required", "unchanged"];
    effects.stage = vec!["required"];
    let p = approved(&effects, effects.configure.clone()).unwrap();
    let plan = p
        .storage(vec![
            definition("required", None),
            definition("unchanged", None),
        ])
        .unwrap();
    let gate = durable(p, true);
    for entries in [
        vec![],
        vec![retained("required", 7)],
        vec![Resolution::Existing, Resolution::Existing],
        vec![Resolution::NonNative, Resolution::Existing],
        vec![retained("required", 7), retained("unchanged", 8)],
        vec![Resolution::Existing, retained("required", 7)],
        vec![
            retained("required", 7),
            Resolution::Existing,
            Resolution::NonNative,
        ],
    ] {
        assert!(plan.check_staged(&gate, &context(), entries).is_none());
    }
    assert!(
        plan.check_staged(
            &gate,
            &context(),
            vec![retained("required", 7), Resolution::Existing]
        )
        .is_some()
    );
}

/// A storage observation cannot override any approved boot field or original numeric pin.
#[test]
fn selected_identity_and_layout_are_bound_to_original_definitions() {
    let mut effects = effects();
    effects.configure = vec!["vm"];
    let p = approved(&effects, vec!["vm"]).unwrap();
    let plan = p.storage(vec![definition("vm", Some(7))]).unwrap();
    let gate = durable(p, true);
    for field in [
        "domain",
        "system",
        "root",
        "source",
        "kernel",
        "mode",
        "device",
        "blob_device",
        "mountpoint",
        "backend",
    ] {
        let changed = || {
            let mut value = identity("vm", 7);
            match field {
                "domain" => value.domain = "foreign".into(),
                "system" => value.system = "/other".into(),
                "root" => value.root = "/other".into(),
                "source" => value.source = "/other".into(),
                "kernel" => value.kernel = "other".into(),
                "mode" => value.mode = "other".into(),
                "device" => value.device = "/dev/xvda".into(),
                "blob_device" => value.blob_device = "/dev/xvdb".into(),
                "mountpoint" => value.mountpoint = "/other".into(),
                _ => value.backend = "other".into(),
            }
            value
        };
        // A matching committed identity still needs to agree with the original checked definition.
        let selected = SelectedGeneration::check(changed(), &changed()).unwrap();
        assert!(
            plan.check_staged(
                &gate,
                &context(),
                vec![Resolution::Retained(Box::new(selected))]
            )
            .is_none(),
            "accepted changed {field}"
        );
    }
    assert!(
        plan.check_staged(&gate, &context(), vec![retained("foreign", 7)])
            .is_none()
    );
    assert!(
        plan.check_staged(&gate, &context(), vec![retained("vm", 8)])
            .is_none()
    );
    assert!(SelectedGeneration::check(identity("vm", 0), &identity("vm", 0)).is_none());
}

/// Changed authority or a different live attempt cannot reuse another attempt's staging token.
#[test]
fn staging_requires_durable_execution_and_preserves_all_context_bindings() {
    let mut effects = effects();
    effects.configure = vec!["vm"];
    let p = approved(&effects, vec!["vm"]).unwrap();
    let plan = p.storage(vec![definition("vm", Some(7))]).unwrap();
    let blocked = durable(approved(&effects, vec!["vm"]).unwrap(), false);
    assert!(
        plan.check_staged(&blocked, &context(), vec![retained("vm", 7)])
            .is_none()
    );
    let gate = durable(p, true);
    let staged = plan
        .check_staged(&gate, &context(), vec![retained("vm", 7)])
        .unwrap();
    for field in ["attempt", "operation", "authority", "plan"] {
        let mut c = context();
        match field {
            "attempt" => c.attempt = AttemptId::new("other".into()),
            "operation" => c.operation = OperationId::new("other".into()),
            "authority" => c.authority = AuthorityBinding::new("other".into()),
            _ => c.plan = PlanBinding::new("other".into()),
        }
        assert!(plan.select_staged(&gate, &c, &staged, 0).is_none());
    }
    let fresh = approved(&effects, vec!["vm"])
        .unwrap()
        .operation(
            AttemptId::new("fresh".into()),
            AuthorityBinding::new("authority".into()),
        )
        .unwrap();
    let c = ExecutionContext {
        attempt: AttemptId::new("fresh".into()),
        operation: OperationId::new("fresh".into()),
        authority: AuthorityBinding::new("authority".into()),
        plan: PlanBinding::new("complete-plan".into()),
    };
    let mut fresh_gate = fresh
        .publication(
            &c.attempt,
            &c.operation,
            &c.authority,
            &c.plan,
            IntentBinding::new("fresh-intent".into()),
        )
        .unwrap();
    fresh_gate.advance(Event::IntentSaved);
    fresh_gate.advance(Event::ApprovalSaved);
    assert!(fresh_gate.begin(&c.attempt, &IntentBinding::new("fresh-intent".into())));
    assert!(plan.select_staged(&fresh_gate, &c, &staged, 0).is_none());
    let fresh_staged = plan
        .check_staged(&fresh_gate, &c, vec![retained("vm", 7)])
        .unwrap();
    assert!(
        plan.select_staged(&fresh_gate, &c, &fresh_staged, 0)
            .is_some()
    );
}

/// An original stage target cannot disappear through an incomplete configure namespace.
#[test]
fn staging_scope_and_duplicate_coordinates_are_checked() {
    let mut effects = effects();
    effects.configure = vec!["vm"];
    effects.stage = vec!["dependency"];
    let p = approved(&effects, vec!["vm", "dependency"]).unwrap();
    assert!(p.storage(vec![definition("vm", None)]).is_none());
    effects.configure = vec!["vm", "vm"];
    effects.stage = vec![];
    let p = approved(&effects, vec!["vm"]).unwrap();
    let plan = p
        .storage(vec![definition("vm", None), definition("vm", None)])
        .unwrap();
    let gate = durable(p, true);
    assert!(
        plan.check_staged(
            &gate,
            &context(),
            vec![Resolution::Existing, Resolution::Existing]
        )
        .is_none()
    );
}

/// Retained inert evidence is not a capability, even when it has the correct generation number.
fn saved() -> persistence::Snapshot {
    persistence::Snapshot {
        operation: "attempt".into(),
        authority: "authority".into(),
        target: "candidate+fingerprint".into(),
        entries: vec![persistence::RecordedResolution::Retained(Box::new(
            identity("vm", 7),
        ))],
    }
}

/// Both the original source scope and every immutable generation field survive recovery.
#[test]
fn recovery_pin_rejects_substituted_snapshot_identity_or_classification() {
    let mut effects = effects();
    effects.configure = vec!["vm"];
    effects.stage = vec!["vm"];
    let plan = approved(&effects, vec!["vm"])
        .unwrap()
        .storage(vec![definition("vm", None)])
        .unwrap();
    for field in [
        "operation",
        "authority",
        "target",
        "missing",
        "extra",
        "generation",
        "source",
        "domain",
        "classification",
    ] {
        let mut s = saved();
        match field {
            "operation" => s.operation = "different".into(),
            "authority" => s.authority = "different".into(),
            "target" => s.target = "different".into(),
            "missing" => s.entries.clear(),
            "extra" => s
                .entries
                .push(persistence::RecordedResolution::Existing("extra".into())),
            "classification" => {
                s.entries[0] = persistence::RecordedResolution::Existing("vm".into())
            }
            _ => {
                let persistence::RecordedResolution::Retained(s) = &mut s.entries[0] else {
                    unreachable!()
                };
                match field {
                    "generation" => s.generation = 8,
                    "source" => s.source = "/other".into(),
                    _ => s.domain = "other".into(),
                }
            }
        }
        assert!(
            plan.pin(
                &context(),
                "candidate+fingerprint".into(),
                Some(&s),
                vec![retained("vm", 7)]
            )
            .is_none(),
            "accepted {field}"
        );
    }
    assert!(
        plan.pin(
            &context(),
            "candidate+fingerprint".into(),
            Some(&saved()),
            vec![retained("vm", 7)]
        )
        .is_some()
    );
    assert!(
        plan.pin(
            &context(),
            "candidate+fingerprint".into(),
            Some(&saved()),
            vec![retained("vm", 8)]
        )
        .is_none()
    );
}

/// A new plan and attempt may reuse an original selection, but never another target or authority.
#[test]
fn recovery_rebinds_exact_selections_to_a_fresh_checked_plan() {
    let mut effects = effects();
    effects.configure = vec!["vm"];
    effects.stage = vec!["vm"];
    let approved = airlock_deployment_core::plan::AuthorizedPlan::policy_exempt(
        &effects,
        vec![],
        PlanBinding::new("new-plan".into()),
    )
    .unwrap();
    let plan = approved.storage(vec![definition("vm", None)]).unwrap();
    let mut c = context();
    c.attempt = AttemptId::new("retry".into());
    c.plan = PlanBinding::new("new-plan".into());
    let s = saved();
    assert!(
        plan.pin(
            &c,
            "candidate+fingerprint".into(),
            Some(&s),
            vec![retained("vm", 7)]
        )
        .is_some()
    );
    c.plan = PlanBinding::new("foreign-plan".into());
    assert!(
        plan.pin(
            &c,
            "candidate+fingerprint".into(),
            Some(&s),
            vec![retained("vm", 7)]
        )
        .is_none()
    );
}

/// The durable gate must cover the same actual journal snapshot that was pinned before publication.
#[test]
fn pinned_execution_requires_durability_and_the_published_selection_set() {
    let mut effects = effects();
    effects.configure = vec!["vm"];
    effects.stage = vec!["vm"];
    let p = approved(&effects, vec!["vm"]).unwrap();
    let plan = p.storage(vec![definition("vm", None)]).unwrap();
    let gate = durable(p, true);
    let blocked = durable(approved(&effects, vec!["vm"]).unwrap(), false);
    let pin = || {
        plan.pin(
            &context(),
            "candidate+fingerprint".into(),
            None,
            vec![retained("vm", 7)],
        )
        .unwrap()
    };
    assert!(
        plan.activate_pinned(&blocked, &context(), pin(), &saved())
            .is_none()
    );
    let mut changed = saved();
    changed.entries[0] = persistence::RecordedResolution::Retained(Box::new(identity("vm", 8)));
    assert!(
        plan.activate_pinned(&gate, &context(), pin(), &changed)
            .is_none()
    );
    let checked = plan
        .activate_pinned(&gate, &context(), pin(), &saved())
        .unwrap();
    assert_eq!(
        plan.select_staged(&gate, &context(), &checked, 0)
            .unwrap()
            .store()
            .unwrap()
            .generation(),
        Some(7)
    );
}
