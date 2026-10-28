//! Exercise the same handoff and cache gates used by production first boot.

use airlock_deployment_core::boot::{DomainState, Handoff, Reuse, Selection};

/// All canonical guests appear once, and every hard edge respects the GUI phase boundary.
#[test]
fn foreground_schedule_checks_complete_partition_and_every_hard_edge() {
    use airlock_deployment_core::boot::startup::{Phase, Plan};
    let parents = vec![vec![], vec![], vec![1], vec![0, 2], vec![0]];
    let stages = vec![
        Phase::BeforeGui,
        Phase::Gui,
        Phase::AfterGui,
        Phase::AfterGui,
        Phase::BeforeGui,
    ];
    let plan = Plan::check(&parents, 1, stages.clone()).unwrap();
    for (i, phase) in stages.iter().enumerate() {
        assert!(plan.phase(i) == Some(*phase));
    }
    assert!(plan.phase(stages.len()).is_none());
    assert!(Plan::check(&parents, 1, stages[..4].to_vec()).is_none());
    let mut invalid = stages.clone();
    invalid[2] = Phase::BeforeGui;
    assert!(
        Plan::check(&parents, 1, invalid).is_none(),
        "clipboard cannot precede GUI authority"
    );
    let mut invalid = stages.clone();
    invalid[4] = Phase::Gui;
    assert!(
        Plan::check(&parents, 1, invalid).is_none(),
        "GUI handoff cannot occur twice"
    );
    let mut cyclic = parents;
    cyclic[1] = vec![2];
    assert!(Plan::check(&cyclic, 1, stages).is_none());
}

/// A mixed image needs a host kernel and a Hermit executable, while Linux payloads stay separate.
fn image_requirements() -> airlock_deployment_core::boot::artifacts::Requirements {
    use airlock_deployment_core::boot::artifacts::{Guest, Requirements};
    Requirements::derive(vec![
        Guest::Nixos {
            name: "usr-home".into(),
            system: "linux".into(),
            root: "root.img".into(),
            store: "guest-pool".into(),
            kernel: "qubes-kernel".into(),
            kernel_source: Some("host-kernel".into()),
        },
        Guest::Hermit {
            name: "sys-clipboard".into(),
            system: "clipboard".into(),
            executable: "clipboard/kernel.elf".into(),
        },
    ])
}

/// One normal boot binds the full topology, seed coordinate, selected host and integrity manifest.
fn image_identity() -> airlock_deployment_core::boot::artifacts::Identity {
    use airlock_deployment_core::boot::artifacts::{Identity, Profile};
    Identity {
        profile: Profile::Normal,
        topology: "all-guests".into(),
        seed: "seed-one".into(),
        host: "host-one".into(),
        manifest: "manifest-one".into(),
    }
}

/// The executable proof rejects an omitted backend and refuses every substituted image coordinate.
#[test]
fn image_completeness_retains_every_guest_and_exact_assembly_binding() {
    use airlock_deployment_core::boot::artifacts::Profile;
    let requirements = image_requirements();
    let guests = requirements.guests();
    assert_eq!(
        guests.iter().map(|guest| guest.name()).collect::<Vec<_>>(),
        ["usr-home", "sys-clipboard"]
    );
    assert_eq!(
        guests[0]
            .volumes()
            .iter()
            .map(|v| v.name())
            .collect::<Vec<_>>(),
        ["root", "private", "store", "store-data"]
    );
    assert!(guests[1].volumes().is_empty());
    assert!(
        requirements
            .check(image_identity(), &["host-kernel".into()])
            .is_none()
    );
    assert!(
        image_requirements()
            .check(image_identity(), &["clipboard".into()])
            .is_none()
    );
    let checked = image_requirements()
        .check(
            image_identity(),
            &["clipboard".into(), "host-kernel".into()],
        )
        .unwrap();
    assert_eq!(checked.requirements().guests().len(), 2);
    assert!(checked.matches(&image_identity()));
    for field in ["profile", "topology", "seed", "host", "manifest"] {
        let mut changed = image_identity();
        match field {
            "profile" => changed.profile = Profile::Recovery,
            "topology" => changed.topology = "recovery-only".into(),
            "seed" => changed.seed = "other-seed".into(),
            "host" => changed.host = "other-host".into(),
            _ => changed.manifest = "other-manifest".into(),
        }
        assert!(!checked.matches(&changed), "{field}");
    }
}

/// One generation with separate root, descriptor and guest device identities.
fn selection() -> Selection {
    Selection {
        domain: "sys-gui".into(),
        generation: 7,
        system: "/nix/store/system".into(),
        root: "/nix/store/root/root.img".into(),
        source: "/nix/store/descriptors/sys-gui".into(),
        kernel: "qubes-kernel".into(),
        mode: "shared-closure".into(),
        device: "/dev/xvde".into(),
        blob_device: "/dev/xvdf".into(),
        mountpoint: "/nix/store".into(),
        backend: "erofs-objectmap".into(),
    }
}

#[test]
fn complete_handoff_refuses_missing_substituted_and_invalid_selections() {
    let checked = Handoff::check(vec![selection()], &[selection()]).unwrap();
    assert_eq!(checked.selections()[0].generation, 7);
    assert!(Handoff::check(vec![selection()], &[]).is_none());
    assert!(Handoff::check(vec![], &[selection()]).is_none());
    for field in [
        "domain",
        "generation",
        "source",
        "root",
        "system",
        "kernel",
        "device",
        "blob",
        "mode",
        "mount",
        "backend",
    ] {
        let mut observed = selection();
        match field {
            "domain" => observed.domain = "usr-home".into(),
            "generation" => observed.generation += 1,
            "source" => observed.source.push_str("/other"),
            "root" => observed.root.push_str(".other"),
            "system" => observed.system.push_str("-other"),
            "kernel" => observed.kernel.push_str("-other"),
            "device" => observed.device = "/dev/xvdg".into(),
            "blob" => observed.blob_device = "/dev/xvdh".into(),
            "mode" => observed.mode = "other".into(),
            "mount" => observed.mountpoint = "/other".into(),
            _ => observed.backend = "other".into(),
        }
        assert!(
            Handoff::check(vec![selection()], &[observed]).is_none(),
            "{field}"
        );
    }
    let mut invalid = selection();
    invalid.generation = 0;
    assert!(Handoff::check(vec![invalid], &[selection()]).is_none());
}

/// Configuration evidence differs independently of VM liveness, which startup checks separately.
fn state(fingerprint: &str) -> DomainState {
    DomainState {
        domain: "sys-gui".into(),
        fingerprint: fingerprint.into(),
    }
}

#[test]
fn reuse_requires_the_exact_input_shared_state_and_complete_fresh_snapshots() {
    let checked = Reuse::check(
        "input".into(),
        "input",
        "shared",
        "shared",
        &[state("snapshot")],
        &[state("snapshot")],
    )
    .unwrap();
    assert_eq!(checked.identity(), "input");
    for (identity, shared) in [("stale", "shared"), ("input", "stale"), ("", "shared")] {
        assert!(
            Reuse::check(
                identity.into(),
                "input",
                shared,
                "shared",
                &[state("snapshot")],
                &[state("snapshot")]
            )
            .is_none()
        );
    }
    for saved in [
        vec![],
        vec![state("stale")],
        vec![DomainState {
            domain: "other".into(),
            fingerprint: "snapshot".into(),
        }],
    ] {
        assert!(
            Reuse::check(
                "input".into(),
                "input",
                "shared",
                "shared",
                &[state("snapshot")],
                &saved
            )
            .is_none()
        );
    }
    assert!(
        Reuse::check(
            "input".into(),
            "input",
            "shared",
            "shared",
            &[state("")],
            &[state("")]
        )
        .is_none()
    );
}

/// A checked selection is mandatory for requests; changed topology cannot reuse an earlier check.
#[test]
fn selected_setup_preserves_identity_and_requires_retained_storage() {
    use airlock_deployment_core::boot::{Argument, BootField, SelectedGeneration};
    let selected = SelectedGeneration::check(selection(), &selection()).unwrap();
    let request = selected.setup(&selection()).unwrap();
    assert_eq!(request.selection().generation, 7);
    for field in ["domain", "generation", "system", "root", "source", "kernel"] {
        let mut changed = selection();
        match field {
            "domain" => changed.domain = "other".into(),
            "generation" => changed.generation += 1,
            "system" => changed.system.push_str("-other"),
            "root" => changed.root.push_str("-other"),
            "source" => changed.source.push_str("-other"),
            _ => changed.kernel.push_str("-other"),
        }
        assert!(selected.setup(&changed).is_none(), "{field}");
        assert!(
            SelectedGeneration::check(changed, &selection()).is_none(),
            "{field}"
        );
    }
    let root_args = request.root_arguments();
    assert!(
        matches!(root_args.get(4), Some(Argument::Text(value)) if value == "sys-gui-runtime-store")
    );
    let args = request.store_arguments();
    assert!(matches!(args.last(), Some(Argument::Text(value)) if value == "--require-retained"));
    assert!(matches!(args.get(23), Some(Argument::Generation(7))));
    assert_eq!(
        request.setting_arguments(BootField::Kernel),
        ["sys-gui", "kernel", "qubes-kernel"]
    );
    assert_eq!(
        request.setting_arguments(BootField::System),
        ["sys-gui", "airlock-system-source", "/nix/store/system"]
    );
    let handoff = Handoff::check(vec![selection()], &[selection()]).unwrap();
    assert_eq!(
        handoff.setup_arguments("/topology", "/checked", "digest"),
        [
            "--topology",
            "/topology",
            "--boot-selection",
            "/checked",
            "--boot-selection-hash",
            "digest"
        ]
    );
}

/// Root import requires this VM's exact source and positive halted evidence, not merely a failed running check.
#[test]
fn selected_root_import_rejects_uncertain_power_and_substituted_artifacts() {
    use airlock_deployment_core::{
        boot::SelectedGeneration,
        inventory::PowerState,
        storage::{Power, RootArtifact},
    };
    let selected = SelectedGeneration::check(selection(), &selection()).unwrap();
    let request = selected.setup(&selection()).unwrap();
    let mut artifact = RootArtifact {
        name: "sys-gui".into(),
        source: "/nix/store/root/root.img".into(),
        image: "/pool/root.img".into(),
        hash: "digest".into(),
    };
    for state in ["Running", "Paused", "", "unknown"] {
        let power = Power {
            name: "sys-gui".into(),
            state: PowerState::classify(state),
        };
        assert!(request.root(&artifact, &power).is_none(), "{state}");
    }
    let power = Power {
        name: "sys-gui".into(),
        state: PowerState::classify("Halted"),
    };
    assert_eq!(
        request.root(&artifact, &power).unwrap().arguments(),
        ["import", "sys-gui:root", "/pool/root.img"]
    );
    artifact.source.push_str("-wrong");
    assert!(request.root(&artifact, &power).is_none());
    artifact.source = selection().root;
    artifact.name = "other".into();
    assert!(request.root(&artifact, &power).is_none());
}
