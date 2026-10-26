//! Exercise the production storage projection and writable-state preservation boundary.

use airlock_deployment_core::{
    attachment::{
        AttachmentPlan, Backing, Definition, Generation, Slot, StorePair, WritablePair,
        WritableVolume, isolation,
    },
    inventory::PowerState,
};

/// One namespace-bound immutable generation with distinct metadata and external data.
fn generation() -> Generation {
    Generation {
        domain: "usr-home-runtime-store".into(),
        number: 7,
        closure_hash: "a".repeat(64),
        manifest: "/pool/domains/usr-home-runtime-store/generations/7/manifest.json".into(),
        metadata: "/pool/views/metadata.img".into(),
        metadata_size: 4096,
        data: "/pool/views/map.json".into(),
        data_size: 8192,
    }
}

/// Both immutable definitions are produced by the same checked projection.
fn definitions() -> Vec<Definition> {
    StorePair::new("usr-home", "airlock-closure".into(), generation())
        .unwrap()
        .definitions()
}

/// Independent writable backing, with a complete observation bound into its record.
fn writable(name: &str) -> WritableVolume {
    WritableVolume {
        backing: Backing {
            pool: "default".into(),
            vid: format!("usr-home/{name}"),
        },
        writable: true,
        persistent: true,
        snap_on_start: false,
        source: None,
        record: format!("complete observed {name} definition"),
    }
}

/// Try installation through the same constructor used by the native storage guard.
fn plan(definitions: Vec<Definition>, state: &str) -> Option<AttachmentPlan> {
    AttachmentPlan::new(
        "usr-home".into(),
        "StandaloneVM",
        PowerState::classify(state),
        false,
        WritablePair {
            root: writable("root"),
            private: writable("private"),
        },
        &[],
        definitions,
    )
}

#[test]
fn projection_retains_exact_identity_and_distinct_read_only_roles() {
    let projected = definitions();
    assert_eq!(projected.len(), 2);
    assert!(matches!(projected[0].slot, Slot::Store));
    assert!(matches!(projected[1].slot, Slot::StoreData));
    assert_eq!(projected[0].path, "/pool/views/metadata.img");
    assert_eq!(projected[1].path, "/pool/views/map.json");
    assert_eq!(projected[0].size, 4096);
    assert_eq!(projected[1].size, 8192);
    for definition in &projected {
        assert_eq!(definition.domain, "usr-home-runtime-store");
        assert_eq!(definition.generation, 7);
        assert!(!definition.writable && definition.persistent && !definition.snap_on_start);
    }
    assert!(plan(projected, "Halted").is_some());
}

#[test]
fn projection_rejects_another_namespace_or_invalid_generation() {
    assert!(StorePair::new("other-vm", "pool".into(), generation()).is_none());
    // A VM name or build-store namespace cannot stand in for its runtime view.
    for namespace in ["usr-home", "usr-home-build-store"] {
        let mut invalid = generation();
        invalid.domain = namespace.into();
        assert!(StorePair::new("usr-home", "pool".into(), invalid).is_none());
        let mut invalid = definitions();
        for definition in &mut invalid {
            definition.domain = namespace.into();
        }
        assert!(plan(invalid, "Halted").is_none());
    }

    let mut invalid = generation();
    invalid.number = 0;
    assert!(StorePair::new("usr-home", "pool".into(), invalid).is_none());
    let mut invalid = generation();
    invalid.data_size = 0;
    assert!(StorePair::new("usr-home", "pool".into(), invalid).is_none());
}

#[test]
fn writable_unknown_incomplete_and_mixed_generation_effects_are_rejected() {
    for name in ["root", "private", "volatile", "kernel", "unclassified"] {
        assert!(Slot::parse(name).is_none());
    }
    let mut incomplete = definitions();
    incomplete.pop();
    assert!(plan(incomplete, "Halted").is_none());
    let mut mixed = definitions();
    mixed[1].generation += 1;
    assert!(plan(mixed, "Halted").is_none());
    let mut writable = definitions();
    writable[0].writable = true;
    assert!(plan(writable, "Halted").is_none());
    let mut wrong_domain = definitions();
    wrong_domain[0].domain = "other-vm".into();
    wrong_domain[1].domain = "other-vm".into();
    assert!(plan(wrong_domain, "Halted").is_none());
    let mut swapped = definitions();
    swapped.swap(0, 1);
    assert!(plan(swapped, "Halted").is_none());
}

#[test]
fn halted_evidence_is_required_even_when_running_flag_is_false() {
    for state in ["Running", "Paused", "Crashed", "Transient", "unknown", ""] {
        assert!(plan(definitions(), state).is_none());
    }
    assert!(
        AttachmentPlan::new(
            "usr-home".into(),
            "StandaloneVM",
            PowerState::classify("Halted"),
            true,
            WritablePair {
                root: writable("root"),
                private: writable("private")
            },
            &[],
            definitions(),
        )
        .is_none()
    );
}

#[test]
fn aliases_and_derived_private_state_cannot_become_installation_evidence() {
    let root = writable("root");
    let private = writable("private");
    assert!(!isolation(&root, &root, &[]));
    assert!(!isolation(
        &root,
        &private,
        &[Backing {
            pool: "default".into(),
            vid: "usr-home/private".into()
        }]
    ));
    let mut derived = writable("private");
    derived.source = Some(Backing {
        pool: "default".into(),
        vid: "other-vm/private".into(),
    });
    assert!(!isolation(&root, &derived, &[]));
}

#[test]
fn completion_preserves_backing_and_complete_private_definition() {
    let request = plan(definitions(), "Halted").unwrap();
    assert_eq!(request.target(), "usr-home");
    assert_eq!(request.definitions().len(), 2);
    assert!(request.preserves(&writable("root"), &writable("private")));
    let mut replaced = writable("private");
    replaced.backing.vid = "other-vm/private".into();
    assert!(!request.preserves(&writable("root"), &replaced));
    let mut changed = writable("private");
    changed.record.push_str(" resized");
    assert!(!request.preserves(&writable("root"), &changed));
}

#[test]
fn builder_pair_requires_its_own_namespace_and_supported_consumer() {
    for target in ["usr-assistant", "sys-ctrl", "usr-home"] {
        let mut pair = definitions();
        pair[0].slot = Slot::BuilderStore;
        pair[1].slot = Slot::BuilderData;
        for definition in &mut pair {
            definition.domain = format!("{target}-build-store");
        }
        let request = AttachmentPlan::new(
            target.into(),
            "StandaloneVM",
            PowerState::classify("Halted"),
            false,
            WritablePair {
                root: writable("root"),
                private: writable("private"),
            },
            &[],
            pair,
        );
        assert_eq!(request.is_some(), target != "usr-home");
    }
    let mut wrong_namespace = definitions();
    wrong_namespace[0].slot = Slot::BuilderStore;
    wrong_namespace[1].slot = Slot::BuilderData;
    assert!(
        AttachmentPlan::new(
            "sys-ctrl".into(),
            "StandaloneVM",
            PowerState::classify("Halted"),
            false,
            WritablePair {
                root: writable("root"),
                private: writable("private")
            },
            &[],
            wrong_namespace,
        )
        .is_none()
    );
}

/// Bind a checked plan to the exact immutable pool used for ordered dispatch.
fn installation() -> airlock_deployment_core::attachment::CheckedInstallation {
    use airlock_deployment_core::attachment::{CheckedInstallation, Pool};
    CheckedInstallation::new(
        plan(definitions(), "Halted").unwrap(),
        Pool::new("airlock-closure".into(), "/pool".into()).unwrap(),
    )
    .unwrap()
}

#[test]
fn dispatch_preserves_target_generation_fields_and_order_until_exhaustion() {
    let checked = installation();
    let expected = definitions();
    let mut dispatch = checked.dispatch();
    for definition in expected {
        let request = dispatch.next_request().unwrap();
        assert_eq!(request.target(), checked.plan().target());
        let actual = request.definition();
        assert_eq!(actual.slot.name(), definition.slot.name());
        assert_eq!(actual.pool, definition.pool);
        assert_eq!(actual.domain, definition.domain);
        assert_eq!(actual.generation, definition.generation);
        assert_eq!(actual.closure_hash, definition.closure_hash);
        assert_eq!(actual.manifest, definition.manifest);
        assert_eq!(actual.path, definition.path);
        assert_eq!(actual.size, definition.size);
        assert!(!actual.writable && actual.persistent && !actual.snap_on_start);
    }
    assert!(dispatch.next_request().is_none());
    assert!(dispatch.next_request().is_none());
    assert!(std::ptr::eq(dispatch.finish().unwrap(), &checked));
}

#[test]
fn dispatch_cannot_finish_early_or_bind_a_different_pool() {
    use airlock_deployment_core::attachment::{CheckedInstallation, Pool};
    let checked = installation();
    assert!(checked.dispatch().finish().is_none());
    let mut dispatch = checked.dispatch();
    assert!(dispatch.next_request().is_some());
    assert!(dispatch.finish().is_none());
    assert!(
        CheckedInstallation::new(
            plan(definitions(), "Halted").unwrap(),
            Pool::new("other-pool".into(), "/pool".into()).unwrap()
        )
        .is_none()
    );
    assert!(Pool::new("".into(), "/pool".into()).is_none());
    assert!(Pool::new("airlock-closure".into(), "".into()).is_none());
}
