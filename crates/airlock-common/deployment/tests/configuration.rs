//! Exercise the production configuration authority, selectors and exact Qubes arguments.

use airlock_deployment_core::{
    configuration::{
        ConfigurationPlan, Definition, Denial, Helper, HelperKind, Kind, Selection, Setting,
        SettingObservation, SetupPhase,
    },
    inventory::PowerState,
    operation::{
        AttemptId, AuthorityBinding, DurableOperation, ExecutionContext, IntentBinding,
        OperationId, PlanBinding,
    },
    plan::AuthorizedPlan,
    publication::Event,
    review::{Binding, Identity, Review, Status},
};
use airlock_machine_planning::effects::PlanEffects;

/// The same admitted setup program and topology are retained for every helper phase.
fn helper() -> Helper {
    Helper {
        program: "/nix/store/approved-setup/bin/airlock-setup-config".into(),
        topology: "/candidate/topology.json".into(),
    }
}

/// Declared values exercise creation, explicit connections, features and services.
fn definition() -> Definition {
    Definition {
        name: "usr-home".into(),
        class: "AppVM".into(),
        label: "green".into(),
        template: Some("base".into()),
        properties: vec![Setting {
            name: "guivm".into(),
            value: "none".into(),
        }],
        features: vec![Setting {
            name: "feature".into(),
            value: "1".into(),
        }],
        services: vec![Setting {
            name: "service".into(),
            value: "on".into(),
        }],
        helper: Some(helper()),
    }
}

/// A protected review admits exactly one VM and no host reboot.
fn approved() -> AuthorizedPlan {
    let r = Review {
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
    };
    let binding = Binding {
        request: "review",
        release: "candidate",
        revision: "source",
        lock: "lock",
    };
    let identity = Identity {
        release: "candidate",
        revision: "source",
        lock: "lock",
        guest: None,
        baseline: Some("baseline"),
        previous_operation: None,
    };
    let effects = PlanEffects {
        configure: vec!["usr-home"],
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
    };
    AuthorizedPlan::reviewed(
        &r,
        &binding,
        &identity,
        &effects,
        vec![],
        PlanBinding::new("complete-plan".into()),
    )
    .unwrap()
}

/// Re-extracted journal identities; changing any field must block configuration.
fn context() -> ExecutionContext {
    ExecutionContext {
        attempt: AttemptId::new("attempt".into()),
        operation: OperationId::new("attempt".into()),
        authority: AuthorityBinding::new("authority".into()),
        plan: PlanBinding::new("complete-plan".into()),
    }
}

/// Bind one immutable definition before publishing intent; optionally enter execution.
fn authority(executing: bool) -> (ConfigurationPlan, DurableOperation) {
    let approved = approved();
    let configuration = approved
        .configuration(vec![definition()], helper())
        .unwrap();
    let operation = approved
        .operation(
            AttemptId::new("attempt".into()),
            AuthorityBinding::new("authority".into()),
        )
        .unwrap();
    let c = context();
    let mut durable = operation
        .publication(
            &c.attempt,
            &c.operation,
            &c.authority,
            &c.plan,
            IntentBinding::new("intent".into()),
        )
        .unwrap();
    if executing {
        durable.advance(Event::IntentSaved);
        durable.advance(Event::ApprovalSaved);
        assert!(durable.begin(&c.attempt, &IntentBinding::new("intent".into())));
    }
    (configuration, durable)
}

/// Exact admitted definitions, including helper paths, must cover the checked namespace.
#[test]
fn missing_duplicate_extra_and_substituted_definitions_are_rejected() {
    let p = approved();
    assert!(p.configuration(vec![], helper()).is_none());
    assert!(
        p.configuration(vec![definition(), definition()], helper())
            .is_none()
    );
    let mut wrong = definition();
    wrong.name = "sys-net".into();
    assert!(p.configuration(vec![wrong], helper()).is_none());
    let mut wrong = definition();
    wrong.helper.as_mut().unwrap().topology = "/other/topology.json".into();
    assert!(p.configuration(vec![wrong], helper()).is_none());
}

/// Every request kind requires publication, execution and unchanged immutable identities.
#[test]
fn missing_publication_wrong_context_and_interruption_block_effects() {
    let (p, not_ready) = authority(false);
    assert!(matches!(
        p.create(&not_ready, &context(), 0, false),
        Err(Denial::Context)
    ));
    let (p, mut gate) = authority(true);
    for changed in 0..4 {
        let mut c = context();
        match changed {
            0 => c.attempt = AttemptId::new("retry".into()),
            1 => c.operation = OperationId::new("other".into()),
            2 => c.authority = AuthorityBinding::new("substituted".into()),
            _ => c.plan = PlanBinding::new("other-plan".into()),
        }
        assert!(matches!(
            p.create(&gate, &c, 0, false),
            Err(Denial::Context)
        ));
        assert!(matches!(
            p.batch(&gate, &c, SetupPhase::Legacy),
            Err(Denial::Context)
        ));
    }
    assert!(p.create(&gate, &context(), 1, false).is_err());
    gate.advance(Event::Interrupted);
    assert!(p.helper(&gate, &context(), 0, HelperKind::Backend).is_err());
}

/// Creation and each setting family emit only the retained name and exact values.
#[test]
fn request_arguments_are_derived_from_the_retained_definition() {
    let (p, gate) = authority(true);
    assert_eq!(
        p.create(&gate, &context(), 0, false)
            .unwrap()
            .unwrap()
            .arguments(),
        [
            "--class",
            "AppVM",
            "--label",
            "green",
            "--template",
            "base",
            "usr-home"
        ]
    );
    assert!(p.create(&gate, &context(), 0, true).unwrap().is_none());
    for (kind, program, key, value) in [
        (Kind::Property, "qvm-prefs", "guivm", "none"),
        (Kind::Feature, "qvm-features", "feature", "1"),
        (Kind::Service, "qvm-service", "service", "on"),
    ] {
        let observation = SettingObservation {
            name: "usr-home",
            current: None,
            explicit: false,
            power: PowerState::classify("Halted"),
        };
        let request = p
            .setting(
                &gate,
                &context(),
                Selection {
                    domain: 0,
                    kind,
                    setting: 0,
                },
                &observation,
            )
            .unwrap()
            .unwrap();
        assert_eq!(request.program(), program);
        assert_eq!(request.arguments(), ["usr-home", key, value]);
    }
    let request = p.helper(&gate, &context(), 0, HelperKind::Backend).unwrap();
    assert_eq!(request.program(), Some(helper().program.as_str()));
    assert_eq!(
        request.arguments(),
        [
            "--apply",
            "--topology",
            "/candidate/topology.json",
            "--backend-only",
            "usr-home"
        ]
    );
}

/// A different VM's observation and every nonhalted/uncertain state fail before mutation.
#[test]
fn power_and_explicit_override_semantics_are_preserved() {
    let (p, gate) = authority(true);
    for power in ["Running", "Paused", "Transient", "unknown", ""] {
        let observation = SettingObservation {
            name: "usr-home",
            current: None,
            explicit: true,
            power: PowerState::classify(power),
        };
        assert!(matches!(
            p.setting(
                &gate,
                &context(),
                Selection {
                    domain: 0,
                    kind: Kind::Property,
                    setting: 0
                },
                &observation
            ),
            Err(Denial::Running)
        ));
    }
    let wrong = SettingObservation {
        name: "sys-net",
        current: None,
        explicit: true,
        power: PowerState::classify("Halted"),
    };
    assert!(matches!(
        p.setting(
            &gate,
            &context(),
            Selection {
                domain: 0,
                kind: Kind::Property,
                setting: 0
            },
            &wrong
        ),
        Err(Denial::Observation)
    ));
    for explicit in [false, true] {
        let same = SettingObservation {
            name: "usr-home",
            current: Some("None"),
            explicit,
            power: PowerState::classify("Halted"),
        };
        assert_eq!(
            p.setting(
                &gate,
                &context(),
                Selection {
                    domain: 0,
                    kind: Kind::Property,
                    setting: 0
                },
                &same
            )
            .unwrap()
            .is_some(),
            !explicit
        );
    }
    let unchanged = SettingObservation {
        name: "usr-home",
        current: Some("1"),
        explicit: false,
        power: PowerState::classify("Running"),
    };
    assert!(
        p.setting(
            &gate,
            &context(),
            Selection {
                domain: 0,
                kind: Kind::Feature,
                setting: 0
            },
            &unchanged
        )
        .unwrap()
        .is_none()
    );
}
