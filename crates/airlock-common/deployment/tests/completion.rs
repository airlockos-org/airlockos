//! Completion checks independent topology requirements and complete observed generation identities.

use airlock_deployment_core::{
    boot::Selection,
    completion::{Inputs, NativeObservation, Observation, Status, VerifiedGuests},
    operation::{AttemptId, AuthorityBinding, ExecutionContext, OperationId, PlanBinding},
    storage::{
        Definition, Native,
        staging::persistence::{RecordedResolution, Snapshot},
    },
};

/// Read-only journal identities; constructing these grants no deployment execution authority.
fn context() -> ExecutionContext {
    ExecutionContext {
        attempt: AttemptId::new("attempt".into()),
        operation: OperationId::new("attempt".into()),
        authority: AuthorityBinding::new("authority".into()),
        plan: PlanBinding::new("complete-plan".into()),
    }
}

/// One committed immutable boot identity, whose number can vary without changing its sources.
fn selection(generation: u64) -> Selection {
    Selection {
        domain: "vm".into(),
        generation,
        system: "/system".into(),
        root: "/root".into(),
        source: "/source".into(),
        kernel: "kernel".into(),
        mode: "shared-closure".into(),
        device: "/dev/xvde".into(),
        blob_device: "/dev/xvdf".into(),
        mountpoint: "/nix/store".into(),
        backend: "erofs-objectmap".into(),
    }
}

/// Required unpinned VM whose original journal selected generation seven.
fn inputs() -> Inputs {
    Inputs {
        context: context(),
        target: "candidate+fingerprint".into(),
        boot: "host-boot".into(),
        host: "/host".into(),
        definitions: vec![Definition {
            executable: None,
            name: "vm".into(),
            service: "/service".into(),
            native: Some(Native {
                system: "/system".into(),
                root: "/root".into(),
                source: "/source".into(),
                artifact: "/source".into(),
                kernel: "kernel".into(),
                kernel_source: String::new(),
                kernelopts: String::new(),
                private_size: None,
                generation: None,
            }),
        }],
        stage: vec!["vm".into()],
        running: vec!["vm".into()],
        snapshot: Snapshot {
            operation: "attempt".into(),
            authority: "authority".into(),
            target: "candidate+fingerprint".into(),
            entries: vec![RecordedResolution::Retained(Box::new(selection(7)))],
        },
    }
}

/// Raw storage/feature and running-system facts, rather than a caller-provided completion flag.
fn observation(generation: u64) -> Observation {
    Observation::Native(Box::new(NativeObservation {
        selection: selection(generation),
        feature_system: "/system".into(),
        feature_generation: generation,
        pool_selected: true,
        running_system: Some("/system".into()),
    }))
}

/// Matching software sources alone never permit a different originally unpinned generation.
#[test]
fn complete_generation_identity_is_required_before_success() {
    assert!(VerifiedGuests::check(inputs(), &[observation(8)]).is_none());
    let checked = VerifiedGuests::check(inputs(), &[observation(7)]).unwrap();
    assert!(matches!(
        checked.status(&context(), "candidate+fingerprint", "host-boot", "/host"),
        Some(Status::Complete)
    ));
    assert!(matches!(
        checked.status(
            &context(),
            "candidate+fingerprint",
            "host-boot",
            "/other-host"
        ),
        Some(Status::RebootRequired)
    ));
    assert!(
        checked
            .status(&context(), "candidate+fingerprint", "host-boot", "")
            .is_none()
    );
}

/// Missing observations, unknown requirements and lost snapshot classifications fail closed.
#[test]
fn complete_topology_and_original_staging_obligations_cannot_be_omitted() {
    assert!(VerifiedGuests::check(inputs(), &[]).is_none());
    assert!(VerifiedGuests::check(inputs(), &[observation(7), observation(7)]).is_none());
    for change in [
        "missing-snapshot",
        "extra-snapshot",
        "unchanged",
        "unknown-start",
        "unknown-stage",
        "duplicate",
    ] {
        let mut i = inputs();
        match change {
            "missing-snapshot" => i.snapshot.entries.clear(),
            "extra-snapshot" => i
                .snapshot
                .entries
                .push(RecordedResolution::Existing("other".into())),
            "unchanged" => i.snapshot.entries[0] = RecordedResolution::Existing("vm".into()),
            "unknown-start" => i.running.push("other".into()),
            "unknown-stage" => i.stage.push("other".into()),
            _ => {
                let extra = inputs().definitions.pop().unwrap();
                i.definitions.push(extra);
                i.snapshot
                    .entries
                    .push(RecordedResolution::Retained(Box::new(selection(7))));
                assert!(VerifiedGuests::check(i, &[observation(7), observation(7)]).is_none());
                continue;
            }
        }
        assert!(
            VerifiedGuests::check(i, &[observation(7)]).is_none(),
            "accepted {change}"
        );
    }
}

/// The selected feature, pool state and required running-system evidence must all agree.
#[test]
fn inconsistent_storage_and_runtime_observations_are_rejected() {
    for change in [
        "feature-system",
        "feature-generation",
        "unselected",
        "not-running",
        "wrong-running",
        "wrong-source",
        "wrong-vm",
    ] {
        let Observation::Native(mut n) = observation(7) else {
            unreachable!()
        };
        match change {
            "feature-system" => n.feature_system = "/other".into(),
            "feature-generation" => n.feature_generation = 8,
            "unselected" => n.pool_selected = false,
            "not-running" => n.running_system = None,
            "wrong-running" => n.running_system = Some("/other".into()),
            "wrong-source" => n.selection.source = "/other".into(),
            _ => n.selection.domain = "other".into(),
        }
        assert!(
            VerifiedGuests::check(inputs(), &[Observation::Native(n)]).is_none(),
            "accepted {change}"
        );
    }
}

/// Neither journal substitution nor reuse in another attempt/boot can publish completion.
#[test]
fn completion_preserves_journal_and_publication_bindings() {
    for field in ["operation", "authority", "target"] {
        let mut i = inputs();
        match field {
            "operation" => i.snapshot.operation = "different".into(),
            "authority" => i.snapshot.authority = "different".into(),
            _ => i.snapshot.target = "different".into(),
        }
        assert!(VerifiedGuests::check(i, &[observation(7)]).is_none());
    }
    let checked = VerifiedGuests::check(inputs(), &[observation(7)]).unwrap();
    for field in ["attempt", "operation", "authority", "plan"] {
        let mut c = context();
        match field {
            "attempt" => c.attempt = AttemptId::new("different".into()),
            "operation" => c.operation = OperationId::new("different".into()),
            "authority" => c.authority = AuthorityBinding::new("different".into()),
            _ => c.plan = PlanBinding::new("different".into()),
        }
        assert!(
            checked
                .status(&c, "candidate+fingerprint", "host-boot", "/host")
                .is_none()
        );
    }
    assert!(
        checked
            .status(&context(), "different", "host-boot", "/host")
            .is_none()
    );
    assert!(
        checked
            .status(&context(), "candidate+fingerprint", "later-boot", "/host")
            .is_none()
    );
}

/// Unchanged unpinned guests keep their explicit existing-storage policy; nonnative work is accounted for.
#[test]
fn explicit_compatibility_classifications_do_not_invent_pins_or_readiness() {
    let mut i = inputs();
    i.stage.clear();
    i.running.clear();
    i.snapshot.entries[0] = RecordedResolution::Existing("vm".into());
    let Observation::Native(mut n) = observation(8) else {
        unreachable!()
    };
    n.running_system = None;
    assert!(VerifiedGuests::check(i, &[Observation::Native(n)]).is_some());
    let mut i = inputs();
    i.definitions[0].native = None;
    i.stage.clear();
    i.running.clear();
    i.snapshot.entries[0] = RecordedResolution::NonNative("vm".into());
    assert!(VerifiedGuests::check(i, &[Observation::NonNative("vm".into())]).is_some());
    let mut i = inputs();
    i.definitions[0].native = None;
    i.stage.clear();
    i.snapshot.entries[0] = RecordedResolution::NonNative("vm".into());
    assert!(VerifiedGuests::check(i, &[Observation::NonNative("vm".into())]).is_none());
}

/// Hermit readiness binds the complete approved executable and cannot be replaced by domain liveness.
#[test]
fn hermit_completion_requires_exact_image_and_application_execution() {
    use airlock_deployment_core::storage::Executable;

    let hermit_inputs = || {
        let mut input = inputs();
        input.definitions[0].native = None;
        input.definitions[0].executable = Some(Executable {
            system: "/hermit".into(),
            descriptor: "digest+source+lock".into(),
        });
        input.snapshot.entries[0] = RecordedResolution::NonNative("vm".into());
        input
    };
    let observation = |descriptor: &str, running_system: Option<&str>| Observation::Hermit {
        name: "vm".into(),
        system: "/hermit".into(),
        descriptor: descriptor.into(),
        running_system: running_system.map(str::to_owned),
    };
    assert!(
        VerifiedGuests::check(
            hermit_inputs(),
            &[observation("digest+source+lock", Some("/hermit"))]
        )
        .is_some()
    );
    assert!(
        VerifiedGuests::check(
            hermit_inputs(),
            &[observation("other-image", Some("/hermit"))]
        )
        .is_none()
    );
    assert!(
        VerifiedGuests::check(
            hermit_inputs(),
            &[observation("digest+source+lock", Some("/old-hermit"))]
        )
        .is_none()
    );
    assert!(
        VerifiedGuests::check(hermit_inputs(), &[observation("digest+source+lock", None)])
            .is_none()
    );
    assert!(
        VerifiedGuests::check(hermit_inputs(), &[Observation::NonNative("vm".into())]).is_none()
    );
}
