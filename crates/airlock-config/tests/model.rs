//! Exercise authoring identities, snapshots and preparation through the public Rust API.

use airlock_config::model::{
    self, AuthoringError as Error, GiB, Machine, Memory, MiB, Vm, VmHandle,
};
use airlock_machine_core::model::VmReference as ReferenceSetting;

/// Registered declarations with host defaults for independent model scenarios.
struct Fixture {
    /// Machine whose ownership and finalization rules are under test.
    machine: Machine,
    /// Network driver at the root of the uplink graph.
    network: VmHandle<model::NetworkDriver>,
    /// Firewall shared by personal and controller VMs.
    firewall: VmHandle<model::Firewall>,
    /// Personal VM used by the GUI launch target.
    home: VmHandle<model::Personal>,
    /// GUI selected by the host's display default.
    gui: VmHandle<model::Gui>,
    /// Admission controller selected by the host.
    controller: VmHandle<model::Controller>,
}

/// Declare a valid graph without assigning any VM to a machine yet.
fn declarations() -> Fixture {
    let mut machine = Machine::default();
    let network = Vm::network("sys-net", GiB(2)).unwrap();
    let firewall = Vm::firewall("sys-firewall", &network).unwrap();
    let home = Vm::personal("usr-home", &firewall, GiB(16)).unwrap();
    let gui = Vm::gui("sys-gui", &home).unwrap();
    let controller = Vm::controller("sys-ctrl", &firewall, GiB(32)).unwrap();
    machine.set_host(&gui, &firewall, &controller);

    Fixture {
        machine,
        network,
        firewall,
        home,
        gui,
        controller,
    }
}

impl Fixture {
    /// Register these exact declarations in dependency order.
    fn register(&mut self) {
        self.machine.add(&self.network).unwrap();
        self.machine.add(&self.firewall).unwrap();
        self.machine.add(&self.home).unwrap();
        self.machine.add(&self.gui).unwrap();
        self.machine.add(&self.controller).unwrap();
    }
}

/// Build one complete, valid machine before applying a scenario's changes.
fn fixture() -> Fixture {
    let mut fixture = declarations();
    fixture.register();
    fixture
}

/// Diagnostic authority follows declaration ownership and frozen inventories, not equal-looking names.
#[test]
fn diagnostics_validate_membership_and_freeze_component_sources() {
    use airlock_config::components::diagnostics::{self, Reader, Source};
    let mut local = fixture();
    let foreign = fixture();
    diagnostics::enable(&mut local.machine, &foreign.home);
    dependency_error(
        local.machine.finish().err().unwrap(),
        true,
        ("diagnostics", "observer", "usr-home"),
    );

    let missing = Vm::personal("usr-home", &local.firewall, GiB(8)).unwrap();
    diagnostics::enable(&mut local.machine, &missing);
    dependency_error(
        local.machine.finish().err().unwrap(),
        false,
        ("diagnostics", "observer", "usr-home"),
    );

    diagnostics::enable(&mut local.machine, &local.home);
    let before = local.machine.finish().unwrap();
    local.network.add_module(
        model::VmModule::from(rusix::nixos::NixosModule::empty()).with_diagnostic_source(Source {
            id: "component-kernel".parse().unwrap(),
            description: "Component-owned kernel evidence".into(),
            reader: Reader::Kernel {},
        }),
    );
    let after = local.machine.finish().unwrap();
    let find = |snapshot: &model::MachineSnapshot| {
        snapshot
            .diagnostic_access()
            .unwrap()
            .endpoints()
            .iter()
            .find(|endpoint| endpoint.target.as_str() == "sys-net")
            .unwrap()
            .sources
            .len()
    };
    assert_eq!(find(&after), find(&before) + 1);
    assert_eq!(
        before.diagnostic_access().unwrap().endpoints().len(),
        before.vms().count() + 1
    );
    airlock_config::generate(&after).unwrap();
    let policy = diagnostics::policy(after.diagnostic_access().unwrap());
    for rule in policy
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .filter(|fields| fields[4] == "allow")
    {
        assert_eq!(rule[2], "usr-home");
        assert!(rule.contains(&"autostart=no"));
    }
    local.network.add_diagnostic_source(Source {
        id: "journal".parse().unwrap(),
        description: "Duplicate".into(),
        reader: Reader::Kernel {},
    });
    assert!(matches!(
        local.machine.finish(),
        Err(Error::InvalidDiagnostics { .. })
    ));
}

/// Check the error category and the VM, relationship and target reported to the author.
fn dependency_error(error: Error, foreign: bool, expected: (&str, &str, &str)) {
    let (vm, relation, target) = match error {
        Error::ForeignMachine {
            vm,
            relation,
            target,
        } if foreign => (vm, relation, target),
        Error::MissingDependency {
            vm,
            relation,
            target,
        } if !foreign => (vm, relation, target),
        other => panic!("unexpected dependency error: {other:?}"),
    };
    assert_eq!((vm.as_str(), relation, target.as_str()), expected);
}

/// Failed registration leaves the recipient unchanged and the candidate usable in its owner.
fn registration<R>(
    mut source: Fixture,
    candidate: VmHandle<R>,
    foreign: bool,
    relation: &str,
    target: &str,
) {
    let mut recipient = fixture();
    if foreign {
        source.register();
    }

    let error = recipient.machine.add(&candidate).unwrap_err();
    dependency_error(
        error,
        foreign,
        (candidate.name().as_str(), relation, target),
    );
    assert_eq!(recipient.machine.finish().unwrap().vms().count(), 5);

    if !foreign {
        source.register();
    }
    source.machine.add(&candidate).unwrap();
}

/// Recheck edits after a successful snapshot before allowing another export.
#[test]
fn finish_rejects_invalid_resources() {
    for fault in ["reversed-memory", "zero-memory", "zero-cpu", "zero-private"] {
        let mut f = fixture();
        f.machine.finish().unwrap();

        match fault {
            "reversed-memory" => f.network.set_memory(Memory::Ballooned {
                initial: MiB(2048),
                maximum: MiB(1024),
            }),
            "zero-memory" => f.network.set_memory(Memory::Fixed(MiB(0))),
            "zero-cpu" => f.network.set_vcpus(0),
            "zero-private" => {
                let empty = Vm::personal("usr-empty", &f.network, GiB(0)).unwrap();
                f.machine.add(&empty).unwrap();
            }
            _ => unreachable!(),
        }

        let expected = if fault == "zero-private" {
            "usr-empty"
        } else {
            "sys-net"
        };
        assert!(
            matches!(f.machine.finish(), Err(Error::InvalidResources { vm, .. })
            if vm == expected),
            "fault: {fault}"
        );
    }
}

/// Reject same-name substitutes and leave failed registrations retryable.
#[test]
fn registration_requires_the_actual_dependency() {
    for foreign in [false, true] {
        let source = declarations();
        let candidate = Vm::firewall("new-firewall", &source.network).unwrap();
        registration(source, candidate, foreign, "network", "sys-net");

        let source = declarations();
        let candidate = Vm::personal("usr-new", &source.firewall, GiB(16)).unwrap();
        registration(source, candidate, foreign, "network", "sys-firewall");

        let source = declarations();
        let candidate = Vm::gui("new-gui", &source.home).unwrap();
        registration(source, candidate, foreign, "launch target", "usr-home");
    }
}

/// Keep membership exclusive even after the original machine is dropped.
#[test]
fn membership_cannot_be_transferred() {
    for drop_owner in [false, true] {
        let mut owner = Some(fixture());
        let network = owner.as_ref().unwrap().network.clone();
        if drop_owner {
            drop(owner.take());
        }

        let mut other = Machine::default();
        dependency_error(
            other.add(&network).unwrap_err(),
            true,
            ("sys-net", "registration", "sys-net"),
        );
        assert_eq!(other.finish().unwrap().vms().count(), 0);
    }
}

/// Distinguish invalid names, duplicate identities and repeated registration.
#[test]
fn registration_failures_are_atomic_and_retryable() {
    use model::{AuthoringError as Error, GiB, Machine, Vm};
    let mut machine = Machine::default();
    let network = Vm::network("sys-net", GiB(2)).unwrap();
    let firewall = Vm::firewall("sys-firewall", &network).unwrap();
    assert!(
        matches!(machine.add(&firewall), Err(Error::MissingDependency {
        vm, relation: "network", target,
    }) if vm == "sys-firewall" && target == "sys-net")
    );
    assert_eq!(machine.finish().unwrap().vms().count(), 0);

    machine.add(&network).unwrap();
    machine.add(&firewall).unwrap();
    assert!(
        matches!(machine.add(&network.clone()), Err(Error::AlreadyRegistered { name })
        if name == "sys-net")
    );
    let duplicate = Vm::network("sys-net", GiB(2)).unwrap();
    assert!(
        matches!(machine.add(&duplicate), Err(Error::DuplicateName { name })
        if name == "sys-net")
    );
    assert!(
        matches!(Vm::network("dom0", GiB(2)), Err(Error::InvalidName { name, .. })
        if name == "dom0")
    );

    let mut other = Machine::default();
    other.add(&duplicate).unwrap();
    assert_eq!(machine.finish().unwrap().vms().count(), 2);
}

/// Reject unresolved and foreign GUI handles, including expired declarations.
#[test]
fn display_reference_requires_actual_membership() {
    for state in ["missing", "foreign", "dropped"] {
        let f = fixture();
        let mut source = declarations();
        f.home.set_gui(&source.gui);
        if state == "foreign" {
            source.register();
        }
        if state == "dropped" {
            drop(source);
        }

        dependency_error(
            f.machine.finish().err().expect("invalid machine"),
            state == "foreign",
            ("usr-home", "GUI", "sys-gui"),
        );
        f.home.set_gui(&f.gui);
        f.machine.finish().unwrap();
    }
}

/// Check typed host defaults against declaration ownership at finalization.
#[test]
fn host_references_require_actual_membership() {
    for (relation, foreign, target) in [
        ("default GUI", false, "sys-gui"),
        ("default network", false, "sys-firewall"),
        ("admission controller", false, "sys-ctrl"),
        ("default GUI", true, "sys-gui"),
    ] {
        let mut f = fixture();
        let mut source = declarations();
        if foreign {
            source.register();
        }
        match relation {
            "default GUI" => f.machine.set_host(&source.gui, &f.firewall, &f.controller),
            "default network" => f.machine.set_host(&f.gui, &source.firewall, &f.controller),
            "admission controller" => f.machine.set_host(&f.gui, &f.firewall, &source.controller),
            _ => unreachable!(),
        }

        dependency_error(
            f.machine.finish().err().expect("invalid machine"),
            foreign,
            ("host", relation, target),
        );
    }
}

/// Require an explicit display assignment or a configured host default.
#[test]
fn missing_host_default_is_structured() {
    use model::{AuthoringError as Error, GiB, Machine, Vm};
    let mut machine = Machine::default();
    let network = Vm::network("sys-net", GiB(2)).unwrap();
    machine.add(&network).unwrap();
    let home = Vm::personal("usr-home", &network, GiB(16)).unwrap();
    machine.add(&home).unwrap();
    assert!(matches!(machine.finish(), Err(Error::MissingHostReference {
        vm, relation: "default GUI",
    }) if vm == "usr-home"));
}

/// Resolve display assignments and order startup without a launch-target cycle.
#[test]
fn gui_launch_target_and_display_assignment_can_point_back() {
    let Fixture {
        mut machine,
        firewall,
        home,
        gui,
        ..
    } = fixture();
    home.set_gui(&gui);
    let command = Vm::command("usr-cmd", &firewall, GiB(8)).unwrap();
    machine.add(&command).unwrap();
    let frozen = machine.finish().unwrap();

    let order = frozen.relationships().ordered().unwrap();
    let index = |name: &str| order.iter().position(|n| n.as_str() == name).unwrap();
    assert!(index("sys-gui") < index("usr-home"));
    assert!(index("sys-net") < index("sys-firewall"));
    assert!(index("sys-firewall") < index("usr-home"));

    let host = frozen.host().unwrap();
    assert_eq!(host.gui.as_str(), "sys-gui");
    assert_eq!(host.network.as_str(), "sys-firewall");
    assert_eq!(host.controller.as_str(), "sys-ctrl");
    for vm in frozen.vms() {
        let expected = match vm.name.as_str() {
            "sys-net" | "sys-firewall" => ReferenceSetting::Disabled,
            "sys-gui" => ReferenceSetting::Named("dom0".parse().unwrap()),
            "usr-cmd" => ReferenceSetting::Inherit,
            _ => ReferenceSetting::Named("sys-gui".parse().unwrap()),
        };
        assert_eq!(vm.guivm, expected);
        if let model::Role::Gui {
            default_application,
            ..
        } = &vm.role
        {
            assert_eq!(default_application.as_str(), "usr-home");
        }
    }
}

/// Keep all frozen values stable through edits, failed retries and builder disposal.
#[test]
fn snapshots_detach_resources_modules_and_relationships() {
    let Fixture {
        mut machine,
        network,
        firewall,
        home,
        gui,
        controller,
        ..
    } = fixture();
    let copied = firewall.clone();
    copied.set_vcpus(3);
    copied.add_module(
        rusix::nixos::NixosModule::empty()
            .system_packages(vec![rusix::interop::Nixpkgs::from_module().get("git")]),
    );
    let frozen = machine.finish().unwrap();
    firewall.set_vcpus(0);
    assert!(matches!(
        machine.finish(),
        Err(Error::InvalidResources { .. })
    ));
    firewall.set_vcpus(4);
    copied.add_module(
        rusix::nixos::NixosModule::empty()
            .system_packages(vec![rusix::interop::Nixpkgs::from_module().get("ripgrep")]),
    );

    let second_firewall = Vm::firewall("another-firewall", &network).unwrap();
    machine.add(&second_firewall).unwrap();
    let second_gui = Vm::gui("another-gui", &home).unwrap();
    machine.add(&second_gui).unwrap();
    home.set_gui(&second_gui);
    machine.set_host(&gui, &second_firewall, &controller);
    let later = machine.finish().unwrap();
    drop((
        machine,
        network,
        firewall,
        copied,
        home,
        gui,
        controller,
        second_firewall,
        second_gui,
    ));

    let old = frozen
        .vms()
        .find(|vm| vm.name.as_str() == "sys-firewall")
        .unwrap();
    let new = later
        .vms()
        .find(|vm| vm.name.as_str() == "sys-firewall")
        .unwrap();
    assert_eq!(old.settings.vcpus, 3);
    assert_eq!(new.settings.vcpus, 4);
    assert_eq!(old.modules.len(), 1);
    assert_eq!(new.modules.len(), 2);
    for (module, package) in new.modules.iter().zip(["git", "ripgrep"]) {
        assert!(
            rusix::nixos::compile_module(module)
                .unwrap()
                .module
                .source
                .contains(package)
        );
    }
    assert_eq!(frozen.host().unwrap().network.as_str(), "sys-firewall");
    assert_eq!(later.host().unwrap().network.as_str(), "another-firewall");
    let old_home = frozen
        .vms()
        .find(|vm| vm.name.as_str() == "usr-home")
        .unwrap();
    let new_home = later
        .vms()
        .find(|vm| vm.name.as_str() == "usr-home")
        .unwrap();
    assert_eq!(
        old_home.guivm,
        ReferenceSetting::Named("sys-gui".parse().unwrap())
    );
    assert_eq!(
        new_home.guivm,
        ReferenceSetting::Named("another-gui".parse().unwrap())
    );
    assert_eq!(old_home.role.uplink().unwrap().as_str(), "sys-firewall");
}

/// Reject names that contradict existing bootstrap scripts and admission policy.
#[test]
fn host_preserves_required_upstream_identities() {
    for (role, expected) in [("gui", "sys-gui"), ("controller", "sys-ctrl")] {
        let mut f = fixture();
        let actual = format!("renamed-{role}");
        if role == "gui" {
            let renamed = Vm::gui(&actual, &f.home).unwrap();
            f.machine.add(&renamed).unwrap();
            f.machine.set_host(&renamed, &f.firewall, &f.controller);
        } else {
            let renamed = Vm::controller(&actual, &f.firewall, GiB(32)).unwrap();
            f.machine.add(&renamed).unwrap();
            f.machine.set_host(&f.gui, &f.firewall, &renamed);
        }

        assert!(matches!(f.machine.finish(), Err(Error::RequiredIdentity {
            expected: required, actual: observed, ..
        }) if required == expected && observed == actual));
    }
}

/// Use runtime semantics for inherited, disabled and external provider references.
#[test]
fn common_dependencies_cover_defaults_devices_and_resets() {
    use airlock_machine_core::relationships::{Relationships, VmRelationships};
    use serde_json::json;
    let mut graph = Relationships {
        prefs: [
            ("default_netvm".into(), json!("sys-net")),
            ("default_guivm".into(), json!("sys-gui")),
            ("default_audiovm".into(), json!("sys-audio")),
        ]
        .into(),
        ..Relationships::default()
    };
    let app = "usr-home".parse().unwrap();
    graph.domains.insert(
        app,
        VmRelationships {
            netvm: ReferenceSetting::Inherit,
            template: ReferenceSetting::Named("tpl-base".parse().unwrap()),
            prefs: [
                ("audiovm".into(), json!(null)),
                ("dispvm".into(), json!("disp-web")),
            ]
            .into(),
            devices: json!({"usb": [{"backend": "sys-usb"}]}),
        },
    );
    let dependencies = graph.dependencies(false).unwrap();
    let names: Vec<_> = dependencies
        .values()
        .next()
        .unwrap()
        .iter()
        .map(|n| n.as_str())
        .collect();
    assert_eq!(
        names,
        ["disp-web", "sys-gui", "sys-net", "sys-usb", "tpl-base"]
    );
    assert!(
        !graph
            .dependencies(true)
            .unwrap()
            .values()
            .next()
            .unwrap()
            .iter()
            .any(|name| name.as_str() == "sys-gui")
    );

    for reset in [
        ReferenceSetting::Disabled,
        ReferenceSetting::Empty,
        ReferenceSetting::Named("dom0".parse().unwrap()),
    ] {
        graph.domains.values_mut().next().unwrap().netvm = reset;
        assert!(
            !graph
                .dependencies(false)
                .unwrap()
                .values()
                .next()
                .unwrap()
                .iter()
                .any(|name| name.as_str() == "sys-net")
        );
    }
}

/// Exercise shared cycle and device-shape checks without fake artifact metadata.
#[test]
fn common_ordering_rejects_display_cycles_and_bad_devices() {
    let Fixture { machine, .. } = fixture();
    let mut graph = machine.finish().unwrap().relationships();
    let gui_name = "sys-gui".parse().unwrap();
    graph
        .domains
        .get_mut(&gui_name)
        .unwrap()
        .prefs
        .insert("guivm".into(), "usr-home".into());
    assert!(
        graph
            .ordered()
            .unwrap_err()
            .to_string()
            .contains("dependency cycle")
    );
    graph
        .domains
        .get_mut(&gui_name)
        .unwrap()
        .prefs
        .insert("guivm".into(), serde_json::Value::Null);
    graph.domains.get_mut(&gui_name).unwrap().devices = serde_json::json!({"usb": 4});
    assert!(
        graph
            .dependencies(false)
            .unwrap_err()
            .to_string()
            .contains("invalid device assignments")
    );
}

/// Reject missing and foreign service targets even when a local VM has the same name.
#[test]
fn capture_contribution_retains_declaration_identity() {
    use airlock_config::components::{desktop, screen_capture};

    for scenario in ["missing", "foreign", "same-name", "valid"] {
        let mut f = fixture();
        f.gui.add_module(desktop::gnome());

        match scenario {
            "missing" | "valid" => {
                let target = Vm::personal("usr-other", &f.firewall, GiB(8)).unwrap();
                screen_capture::connect(&f.gui, &target);
                if scenario == "valid" {
                    f.machine.add(&target).unwrap();
                    let frozen = f.machine.finish().unwrap();
                    let gui = frozen
                        .vms()
                        .find(|vm| vm.name.as_str() == "sys-gui")
                        .unwrap();
                    assert_eq!(gui.modules.len(), 2);
                } else {
                    dependency_error(
                        f.machine.finish().err().expect("invalid machine"),
                        false,
                        ("sys-gui", "capture destination", "usr-other"),
                    );
                }
            }
            "foreign" => {
                let source = fixture();
                screen_capture::connect(&f.gui, &source.home);
                dependency_error(
                    f.machine.finish().err().expect("invalid machine"),
                    true,
                    ("sys-gui", "capture destination", "usr-home"),
                );
            }
            "same-name" => {
                let target = Vm::personal("usr-home", &f.firewall, GiB(8)).unwrap();
                screen_capture::connect(&f.gui, &target);
                drop(target);

                dependency_error(
                    f.machine.finish().err().expect("invalid machine"),
                    false,
                    ("sys-gui", "capture destination", "usr-home"),
                );
            }
            _ => unreachable!(),
        }
    }
}

/// Reject missing and duplicate GNOME capability declarations.
#[test]
fn capture_requires_one_gnome_component() {
    use airlock_config::components::{desktop, screen_capture};

    for count in [0, 2] {
        let f = fixture();
        for _ in 0..count {
            f.gui.add_module(desktop::gnome());
        }
        screen_capture::connect(&f.gui, &f.home);

        assert!(matches!(
            f.machine.finish(),
            Err(Error::InvalidCapture { .. })
        ));
    }
}

/// Reassign a destination without retaining the earlier grant or mutating an earlier snapshot.
#[test]
fn capture_reconnection_does_not_mutate_frozen_artifacts() {
    let Fixture {
        mut machine,
        firewall,
        home,
        gui,
        ..
    } = fixture();
    use airlock_config::components::{desktop, screen_capture};
    gui.add_module(desktop::gnome());
    screen_capture::connect(&gui, &home);
    let before = machine.finish().unwrap();
    let other = Vm::personal("other-files", &firewall, GiB(8)).unwrap();
    machine.add(&other).unwrap();
    screen_capture::connect(&gui, &other);
    let after = machine.finish().unwrap();
    assert_eq!(before.capture_connections()[0].target.as_str(), "usr-home");
    assert_eq!(
        after.capture_connections()[0].target.as_str(),
        "other-files"
    );
    assert!(!screen_capture::policy(after.capture_connections()).contains("usr-home"));
    assert_eq!(
        before
            .vms()
            .find(|vm| vm.name.as_str() == "usr-home")
            .unwrap()
            .modules
            .len(),
        1
    );
    assert!(
        after
            .vms()
            .find(|vm| vm.name.as_str() == "usr-home")
            .unwrap()
            .modules
            .is_empty()
    );
}

/// Exercise the source-to-artifact boundary without evaluating or building a system.
#[test]
fn preparation_separates_source_and_rejects_changed_artifacts() {
    let directory = tempfile::tempdir().unwrap();
    let source = &directory.path().join("source");
    std::fs::create_dir(source).unwrap();
    std::fs::write(source.join("declarations.rs"), "// configuration source\n").unwrap();
    std::fs::write(source.join(".gitignore"), "/target/\n").unwrap();
    for arguments in [
        vec!["init", "-q"],
        vec!["add", "."],
        vec![
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "source",
        ],
    ] {
        assert!(
            std::process::Command::new("git")
                .current_dir(source)
                .args(arguments)
                .status()
                .unwrap()
                .success()
        );
    }
    std::fs::write(source.join("editor-state"), "untracked").unwrap();
    let cache = &source.join("target/nix");
    let emit = |tree: &std::path::Path| -> Result<(), Box<dyn std::error::Error>> {
        let generated = airlock_config::flake("applications")?;
        std::fs::write(tree.join("flake.nix"), generated.source)?;
        Ok(())
    };
    let first = airlock_config::preparation::prepare(source, cache, emit).unwrap();
    let same = airlock_config::preparation::prepare(source, cache, emit).unwrap();
    assert_eq!(first, same);
    assert!(!first.join("target").exists());

    let external = airlock_config::preparation::prepare(
        source,
        &source.parent().unwrap().join("external-cache"),
        emit,
    )
    .unwrap();
    assert_eq!(first.file_name(), external.file_name());
    assert!(!first.join(".git").exists());
    assert!(!first.join("editor-state").exists());
    assert!(!source.join("flake.nix").exists());
    assert!(first.join("airlock-prepared.json").is_file());

    std::fs::write(first.join("flake.nix"), "changed artifact").unwrap();
    assert!(airlock_config::preparation::prepare(source, cache, emit).is_err());

    std::fs::write(source.join("declarations.rs"), "// edited source").unwrap();
    let changed = airlock_config::preparation::prepare(source, cache, emit).unwrap();
    assert_ne!(changed, first);

    use airlock_config::preparation::cache;
    let active = cache::lease(cache, &first).unwrap();
    cache::pin(cache, &changed, "validation").unwrap();
    assert!(cache::pin(cache, &changed, "../escape").is_err());
    assert!(cache::lease(cache, &external).is_err());
    let preview = cache::prune(cache, 0, false).unwrap();
    assert!(preview.candidates.is_empty());
    assert_eq!(preview.protected.len(), 2);
    drop(active);
    let unknown = cache.join("f".repeat(64));
    std::fs::create_dir(&unknown).unwrap();
    std::fs::write(unknown.join("airlock-prepared.json"), "unmanaged").unwrap();

    let preview = cache::prune(cache, 0, false).unwrap();
    assert_eq!(preview.candidates.len(), 1);
    assert!(first.exists());
    let removed = cache::prune(cache, 0, true).unwrap();
    assert_eq!(removed.candidates.len(), 1);
    assert!(!first.exists());
    assert!(changed.exists());
    cache::unpin(cache, "validation").unwrap();
    assert_eq!(
        cache::prune(cache, 1, true).unwrap().retained,
        vec![changed.clone()]
    );
    assert!(changed.exists());
    cache::prune(cache, 0, true).unwrap();
    assert!(!changed.exists());
    assert!(unknown.exists());

    assert!(airlock_config::preparation::prepare(source, &source.join("cache"), emit).is_err());
}

#[test]
fn backends_share_roles_and_freeze_independent_snapshots() {
    use model::{GuestBackend, HermitApplication, Role};

    let linux = Vm::nixos("service-linux", MiB(256)).unwrap();
    let hermit = Vm::hermit("sys-clipboard", MiB(32), HermitApplication::Clipboard).unwrap();
    let mut machine = Machine::default();
    machine.add(&linux).unwrap();
    machine.add(&hermit).unwrap();
    let snapshot = machine.finish().unwrap();
    assert!(snapshot.vms().all(|vm| matches!(vm.role, Role::Service)));
    let frozen = snapshot
        .vms()
        .find(|vm| vm.name.as_str() == "sys-clipboard")
        .unwrap();
    assert!(matches!(frozen.backend, GuestBackend::Hermit { .. }));
    assert!(frozen.modules.is_empty());
    assert_eq!(frozen.settings.root_image.0, 0);
    assert_eq!(frozen.guivm, ReferenceSetting::Disabled);
    hermit.set_memory(Memory::Fixed(MiB(64)));
    assert_eq!(frozen.settings.memory.bounds().0.0, 32);
    assert!(machine.finish().is_ok());
}

#[test]
fn hermit_rejects_linux_capabilities_and_unsupported_resources() {
    use model::HermitApplication;

    let hermit = Vm::hermit("sys-clipboard", MiB(32), HermitApplication::Clipboard).unwrap();
    let mut machine = Machine::default();
    machine.add(&hermit).unwrap();
    hermit.set_vcpus(2);
    assert!(machine.finish().is_err());
    hermit.set_vcpus(1);
    hermit.set_memory(Memory::Ballooned {
        initial: MiB(32),
        maximum: MiB(64),
    });
    assert!(machine.finish().is_err());
    hermit.set_memory(Memory::Fixed(MiB(32)));
    hermit.set_feature("qrexec", "1").unwrap();
    assert!(machine.finish().is_err());
}
