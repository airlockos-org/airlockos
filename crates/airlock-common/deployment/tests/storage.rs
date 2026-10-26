//! Exercise native-storage requests using real review and publication gates.

mod support;

use airlock_deployment_core::{inventory::PowerState, operation::*, storage::*};
use support::*;

/// The full checked plan authorises this VM independently of its dependencies.
fn checked() -> airlock_deployment_core::plan::AuthorizedPlan {
    let mut plan = effects();
    plan.configure = vec!["vm"];
    approved(&plan, vec!["vm"]).unwrap()
}

/// Immutable backend parameters captured from the original candidate.
fn definition() -> Definition {
    Definition {
        executable: None,
        name: "vm".into(),
        service: "/native/service".into(),
        native: Some(Native {
            system: "/system".into(),
            root: "/root-source".into(),
            source: "/closure-source".into(),
            artifact: "/closure-artifact".into(),
            kernel: "kernel".into(),
            kernel_source: "/kernel-source".into(),
            kernelopts: "console=hvc0".into(),
            private_size: Some(512),
            generation: Some(7),
        }),
    }
}

/// One independently checked committed identity; tests supply an inert storage observation.
fn selection(generation: u64) -> airlock_deployment_core::boot::Selection {
    airlock_deployment_core::boot::Selection {
        domain: "vm".into(),
        generation,
        system: "/system".into(),
        root: "/root-source".into(),
        source: "/closure-source".into(),
        kernel: "kernel".into(),
        mode: "shared-closure".into(),
        device: "/dev/xvde".into(),
        blob_device: "/dev/xvdf".into(),
        mountpoint: "/nix/store".into(),
        backend: "erofs-objectmap".into(),
    }
}

/// Preserve the full original sources in a genuine checked staging token.
fn resolutions(generation: u64) -> Vec<staging::Resolution> {
    vec![staging::Resolution::Retained(Box::new(
        airlock_deployment_core::boot::SelectedGeneration::check(
            selection(generation),
            &selection(generation),
        )
        .unwrap(),
    ))]
}

/// Named evidence is not an independently asserted stopped flag.
fn power(name: &str, state: &str) -> Power {
    Power {
        name: name.into(),
        state: PowerState::classify(state),
    }
}

/// Trusted resolution supplies a source-to-image association for subsequent checked selection.
fn artifact() -> RootArtifact {
    RootArtifact {
        name: "vm".into(),
        source: "/root-source".into(),
        image: "/admitted/root.img".into(),
        hash: "digest".into(),
    }
}

#[test]
fn exact_sources_kernel_and_storage_arguments_are_retained() {
    let p = checked();
    let plan = p.storage(vec![definition()]).unwrap();
    let durable = durable(p, true);
    let backend = plan.select(&durable, &context(), 0).unwrap();
    assert_eq!(
        backend.kernel().unwrap().parameters(),
        ("vm", "kernel", "/kernel-source")
    );
    let a = artifact();
    assert_eq!(
        backend
            .root(&a, &power("vm", "Halted"))
            .unwrap()
            .arguments(),
        ["import", "vm:root", "/admitted/root.img"]
    );
    let request = backend.resize(&power("vm", "Halted"), 100).unwrap();
    assert_eq!(request.volume(), "vm:private");
    assert_eq!(request.size(), 512);
    assert!(backend.resize(&power("vm", "Halted"), 512).is_none());
    assert!(backend.resize(&power("vm", "Halted"), 1024).is_none());
    assert!(
        plan.check_staged(&durable, &context(), vec![staging::Resolution::Existing])
            .is_none()
    );
    assert!(
        plan.check_staged(&durable, &context(), resolutions(8))
            .is_none()
    );
    let staged = plan
        .check_staged(&durable, &context(), resolutions(7))
        .unwrap();
    let selected = plan
        .select_staged(&durable, &context(), &staged, 0)
        .unwrap();
    let store = selected.store().unwrap();
    assert_eq!(store.generation(), Some(7));
    assert_eq!(store.program(), "/native/service");
    assert_eq!(
        store.arguments(),
        [
            "storage",
            "domain",
            "ensure-store",
            "vm",
            "/closure-source",
            "/closure-source",
            "--mode",
            "shared-closure",
            "--system",
            "/system",
            "--root",
            "/root-source",
            "--kernel",
            "kernel",
            "--device",
            "/dev/xvde",
            "--blob-device",
            "/dev/xvdf",
            "--mountpoint",
            "/nix/store",
            "--view-backend",
            "erofs-objectmap",
            "--require-retained"
        ]
    );
}

#[test]
fn destructive_volume_changes_require_named_halted_evidence_and_original_source() {
    let p = checked();
    let plan = p.storage(vec![definition()]).unwrap();
    let durable = durable(p, true);
    let backend = plan.select(&durable, &context(), 0).unwrap();
    for state in ["Running", "Paused", "Transient", "", "unknown"] {
        assert!(backend.root(&artifact(), &power("vm", state)).is_none());
        assert!(backend.resize(&power("vm", state), 100).is_none());
    }
    assert!(
        backend
            .root(&artifact(), &power("other", "Halted"))
            .is_none()
    );
    assert!(backend.resize(&power("other", "Halted"), 100).is_none());
    let mut changed = artifact();
    changed.source = "/different-root".into();
    assert!(backend.root(&changed, &power("vm", "Halted")).is_none());
    changed = artifact();
    changed.name = "other".into();
    assert!(backend.root(&changed, &power("vm", "Halted")).is_none());
    changed = artifact();
    changed.image.clear();
    assert!(backend.root(&changed, &power("vm", "Halted")).is_none());
}

#[test]
fn wrong_scope_indices_contexts_and_missing_backend_never_mint_requests() {
    let p = checked();
    let mut wrong = definition();
    wrong.name = "other".into();
    assert!(p.storage(vec![wrong]).is_none());
    assert!(p.storage(vec![]).is_none());
    let plan = p.storage(vec![definition()]).unwrap();
    let gate = durable(checked(), false);
    assert!(plan.select(&gate, &context(), 0).is_none());
    let gate = durable(checked(), true);
    assert!(plan.select(&gate, &context(), 1).is_none());
    for field in 0..4 {
        let mut c = context();
        match field {
            0 => c.attempt = AttemptId::new("different-attempt".into()),
            1 => c.operation = OperationId::new("different-operation".into()),
            2 => c.authority = AuthorityBinding::new("different-authority".into()),
            _ => c.plan = PlanBinding::new("different-candidate-baseline-plan".into()),
        }
        assert!(plan.select(&gate, &c, 0).is_none());
    }
    let mut no_native = definition();
    no_native.native = None;
    let no_native = p.storage(vec![no_native]).unwrap();
    assert!(no_native.select(&gate, &context(), 0).is_none());
}

/// Storage metadata is evidence only when its entire boot identity matches the checked backend.
fn evidence() -> StoreEvidence {
    StoreEvidence {
        name: "vm".into(),
        system: "/system".into(),
        root: "/root-source".into(),
        source: "/closure-source".into(),
        kernel: "kernel".into(),
        generation: 7,
        generation_text: "7".into(),
        closure_hash: "closure-digest".into(),
        view_image: "/metadata.img".into(),
        blob_map: "/blob-map".into(),
        blob_volume: "store-data".into(),
        restart_required: true,
        restarted: false,
    }
}

#[test]
fn boot_settings_and_daemon_restore_use_original_fields_and_validated_outcomes() {
    let p = checked();
    let plan = p.storage(vec![definition()]).unwrap();
    let durable = durable(p, true);
    let backend = plan.select(&durable, &context(), 0).unwrap();
    let halted = power("vm", "Halted");
    let kernel = backend.setting(BootField::Kernel, &halted).unwrap();
    assert_eq!(kernel.program(), "qvm-prefs");
    assert_eq!(kernel.arguments(), ["vm", "kernel", "kernel"]);
    let system = backend.setting(BootField::System, &halted).unwrap();
    assert_eq!(system.program(), "qvm-features");
    assert_eq!(
        system.arguments(),
        ["vm", "airlock-system-source", "/system"]
    );
    let e = evidence();
    let staged = plan
        .check_staged(&durable, &context(), resolutions(7))
        .unwrap();
    let selected = plan
        .select_staged(&durable, &context(), &staged, 0)
        .unwrap();
    let store = selected.store().unwrap();
    let outcome = store.outcome(&e).unwrap();
    assert_eq!(
        outcome
            .setting(ReceiptField::Generation, &halted)
            .unwrap()
            .arguments(),
        ["vm", "airlock-store-generation", "7"]
    );
    assert_eq!(
        outcome
            .setting(ReceiptField::BlobVolume, &halted)
            .unwrap()
            .arguments(),
        ["vm", "airlock-store-blob-volume", "store-data"]
    );
    assert_eq!(
        outcome.restart().unwrap().arguments(),
        ["try-restart", "qubesd.service"]
    );
    for state in ["Running", "Paused", "", "unknown"] {
        assert!(
            backend
                .setting(BootField::System, &power("vm", state))
                .is_none()
        );
        assert!(
            outcome
                .setting(ReceiptField::Generation, &power("vm", state))
                .is_none()
        );
        assert!(
            backend
                .root_setting(&artifact(), &power("vm", state))
                .is_none()
        );
    }
    assert!(
        outcome
            .setting(ReceiptField::Generation, &power("other", "Halted"))
            .is_none()
    );
    for substituted in 0..6 {
        let mut changed = evidence();
        match substituted {
            0 => changed.name = "other".into(),
            1 => changed.system = "/other-system".into(),
            2 => changed.root = "/other-root".into(),
            3 => changed.source = "/other-closure".into(),
            4 => changed.kernel = "other-kernel".into(),
            _ => changed.generation = 8,
        }
        assert!(store.outcome(&changed).is_none());
    }
    let mut restored = evidence();
    restored.restarted = true;
    assert!(store.outcome(&restored).unwrap().restart().is_none());
    restored.restarted = false;
    restored.restart_required = false;
    assert!(store.outcome(&restored).unwrap().restart().is_none());
}
