//! Check Qubes reference projection and deployment effects through the production planner.

use airlock_machine_core::{
    model::{GenerationApproval, GenerationInfo, Topology, VmReference},
    planning,
    relationships::{Relationships, VmRelationships},
};
use airlock_nix_core::identity::GuestName;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

/// Parse fixture names without inventing a second name-validation rule.
fn names(names: &[&str]) -> BTreeSet<GuestName> {
    names.iter().map(|name| name.parse().unwrap()).collect()
}

/// Give the relationship resolver declarations without requiring built artifacts.
fn relationships(names: &[&str]) -> Relationships {
    Relationships {
        domains: names
            .iter()
            .map(|name| (name.parse().unwrap(), VmRelationships::default()))
            .collect(),
        prefs: BTreeMap::new(),
    }
}

/// Build a typed topology whose immutable artifact paths are never accessed by pure planning.
fn topology(names: &[&str]) -> Topology {
    let system = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-test-system";
    let domain = json!({
        "class": "StandaloneVM", "netvm": null, "template": null,
        "backend": {
            "type": "nix-closure", "system": {"source": system},
            "root": {"source": format!("{system}/root.img")}, "kernel": {"name": "test"},
            "store": {"source": system, "mode": "shared-closure", "mountpoint": "/nix/store",
                "device": "/dev/xvde", "blobDevice": "/dev/xvdf", "viewBackend": "erofs-objectmap"},
        },
    });
    let domains: BTreeMap<_, _> = names.iter().map(|name| (*name, domain.clone())).collect();
    serde_json::from_value(json!({"schema": "airlock.qubes-topology.v1", "domains": domains}))
        .unwrap()
}

/// Prepared descriptors keep the same identity through topology, generation and approval records.
#[test]
fn prepared_descriptor_children_decode_across_runtime_records() {
    let baseline = serde_json::to_value(topology(&["sys-gui"])).unwrap();
    let root = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-descriptors";
    for source in [root.to_owned(), format!("{root}/sys-gui")] {
        let mut raw = baseline.clone();
        raw["domains"]["sys-gui"]["backend"]["store"]["source"] = json!(source);
        let topology: Topology = serde_json::from_value(raw.clone()).unwrap();
        topology.validate().unwrap();
        let backend = &topology.domains[&"sys-gui".parse().unwrap()].backend;
        let info: GenerationInfo = serde_json::from_value(json!({
            "schema":"airlock.closure-store.generation-info.v1", "status":"passed",
            "domain":"sys-gui-runtime-store", "generation":1, "selected":false, "manifest":"/pool/manifest.json", "system":backend.system.source,
            "root_source":backend.nixos().unwrap().root.source, "kernel_name":backend.nixos().unwrap().kernel.name,
            "closure_source":source, "store":{
                "mode":"shared-closure", "closure_hash":"fixture", "mountpoint":backend.nixos().unwrap().store.mountpoint,
                "device":backend.nixos().unwrap().store.device, "blob_device":backend.nixos().unwrap().store.blob_device,
                "view_backend":backend.nixos().unwrap().store.view_backend,
            },
            "verification":{"status":"passed"},
            "approval":{"transport":"qrexec", "approved_by":"usr-assistant", "source":source},
        }))
        .unwrap();
        let approval: GenerationApproval = serde_json::from_value(info.approval).unwrap();
        assert_eq!(info.closure_source, backend.nixos().unwrap().store.source);
        assert_eq!(approval.source, backend.nixos().unwrap().store.source);

        // Whole system identities still cannot name a child within a store object.
        raw["domains"]["sys-gui"]["backend"]["system"]["source"] = json!(format!("{root}/system"));
        assert!(serde_json::from_value::<Topology>(raw).is_err());
    }
}

#[test]
fn inherited_disabled_external_and_gui_relationships_keep_their_meaning() {
    let mut graph = relationships(&["usr-home", "sys-net", "sys-gui"]);
    graph.prefs.insert("default_netvm".into(), json!("sys-net"));
    graph.prefs.insert("default_guivm".into(), json!("sys-gui"));
    for provider in ["sys-net", "sys-gui"] {
        let provider = graph.domains.get_mut(&provider.parse().unwrap()).unwrap();
        provider.netvm = VmReference::Disabled;
        provider.prefs.insert("guivm".into(), json!(null));
    }
    let home = graph.domains.get_mut(&"usr-home".parse().unwrap()).unwrap();
    home.prefs.insert("audiovm".into(), json!("sys-audio"));
    home.devices = json!({"block": [{"backend": "sys-usb"}, {"backend": "dom0"}]});
    let home = "usr-home".parse().unwrap();
    assert_eq!(
        graph.dependencies(false).unwrap()[&home],
        names(&["sys-net", "sys-gui", "sys-audio", "sys-usb"])
    );
    assert_eq!(
        graph.dependencies(true).unwrap()[&home],
        names(&["sys-net", "sys-audio", "sys-usb"])
    );
    // The external providers remain visible to admission, but cannot become declared lifecycle targets.
    assert_eq!(graph.ordered().unwrap().len(), 3);

    let domain = graph.domains.get_mut(&home).unwrap();
    domain.netvm = VmReference::Disabled;
    domain.prefs.insert("guivm".into(), json!(null));
    assert_eq!(
        graph.dependencies(false).unwrap()[&home],
        names(&["sys-audio", "sys-usb"])
    );
    graph.domains.get_mut(&home).unwrap().netvm = VmReference::Empty;
    assert!(!graph.dependencies(false).unwrap()[&home].contains(&"sys-net".parse().unwrap()));
}

#[test]
fn cycles_and_invalid_references_fail_but_self_and_dom0_references_are_ignored() {
    let mut graph = relationships(&["usr-home", "sys-net"]);
    graph
        .domains
        .get_mut(&"usr-home".parse().unwrap())
        .unwrap()
        .netvm = VmReference::Named("sys-net".parse().unwrap());
    graph
        .domains
        .get_mut(&"sys-net".parse().unwrap())
        .unwrap()
        .netvm = VmReference::Named("usr-home".parse().unwrap());
    assert!(graph.ordered().is_err());
    graph
        .domains
        .get_mut(&"sys-net".parse().unwrap())
        .unwrap()
        .netvm = VmReference::Named("sys-net".parse().unwrap());
    assert_eq!(
        graph.ordered().unwrap(),
        vec![
            "sys-net".parse::<GuestName>().unwrap(),
            "usr-home".parse().unwrap()
        ]
    );
    graph
        .domains
        .get_mut(&"usr-home".parse().unwrap())
        .unwrap()
        .prefs
        .insert("guivm".into(), json!(42));
    assert!(graph.dependencies(false).is_err());
    graph
        .domains
        .get_mut(&"usr-home".parse().unwrap())
        .unwrap()
        .prefs
        .insert("guivm".into(), json!("dom0"));
    assert!(graph.dependencies(false).is_ok());
    graph
        .domains
        .get_mut(&"usr-home".parse().unwrap())
        .unwrap()
        .devices = json!({"block": {"backend": "sys-net"}});
    assert!(graph.dependencies(false).is_err());
}

#[test]
fn configuration_changes_propagate_and_new_dependencies_expand_startup() {
    let mut old = topology(&["usr-home", "sys-net", "usr-other"]);
    old.domains
        .get_mut(&"usr-home".parse().unwrap())
        .unwrap()
        .netvm = VmReference::Named("sys-net".parse().unwrap());
    old.domains
        .get_mut(&"usr-home".parse().unwrap())
        .unwrap()
        .prefs
        .insert("autostart".into(), json!(true));
    let initial = planning::plan(&old, &old, &names(&[]), &[], false).unwrap();
    assert_eq!(
        initial.start,
        vec![
            "sys-net".parse::<GuestName>().unwrap(),
            "usr-home".parse().unwrap()
        ]
    );
    let mut new = old.clone();
    new.domains
        .get_mut(&"sys-net".parse().unwrap())
        .unwrap()
        .features
        .insert("test-change".into(), json!("1"));
    let plan = planning::plan(
        &old,
        &new,
        &names(&["usr-home", "sys-net", "usr-other"]),
        &[],
        false,
    )
    .unwrap();
    assert_eq!(
        plan.affected.into_iter().collect::<BTreeSet<_>>(),
        names(&["sys-net", "usr-home"])
    );
    assert_eq!(
        plan.stop,
        vec![
            "usr-home".parse::<GuestName>().unwrap(),
            "sys-net".parse().unwrap()
        ]
    );
    // An unchanged running VM remains a legitimate startup reconciliation root.
    assert!(plan.start.contains(&"usr-other".parse().unwrap()));

    // Startup expansion uses the candidate edges, while impact propagation uses the baseline.
    old.domains
        .get_mut(&"usr-home".parse().unwrap())
        .unwrap()
        .netvm = VmReference::Disabled;
    let mut new = old.clone();
    new.domains
        .get_mut(&"usr-home".parse().unwrap())
        .unwrap()
        .netvm = VmReference::Named("sys-net".parse().unwrap());
    let plan = planning::plan(&old, &new, &names(&["usr-home"]), &[], false).unwrap();
    assert_eq!(plan.stop, vec!["usr-home".parse::<GuestName>().unwrap()]);
    assert_eq!(
        plan.start,
        vec![
            "sys-net".parse::<GuestName>().unwrap(),
            "usr-home".parse().unwrap()
        ]
    );
}

#[test]
fn a_newly_declared_provider_affects_existing_external_dependents() {
    let mut old = topology(&["usr-home"]);
    old.domains
        .get_mut(&"usr-home".parse().unwrap())
        .unwrap()
        .netvm = VmReference::Named("sys-net".parse().unwrap());
    let mut new = old.clone();
    new.domains.insert(
        "sys-net".parse().unwrap(),
        topology(&["sys-net"])
            .domains
            .remove(&"sys-net".parse().unwrap())
            .unwrap(),
    );
    let plan = planning::plan(&old, &new, &names(&["usr-home"]), &[], false).unwrap();
    assert_eq!(
        plan.affected.into_iter().collect::<BTreeSet<_>>(),
        names(&["sys-net", "usr-home"])
    );
    assert_eq!(plan.stop, vec!["usr-home".parse::<GuestName>().unwrap()]);
    assert_eq!(
        plan.start,
        vec![
            "sys-net".parse::<GuestName>().unwrap(),
            "usr-home".parse().unwrap()
        ]
    );
}

#[test]
fn gui_preservation_omits_only_eligible_soft_dependencies() {
    let mut old = topology(&["sys-gui", "usr-home"]);
    let home = old.domains.get_mut(&"usr-home".parse().unwrap()).unwrap();
    home.prefs.insert("guivm".into(), json!("sys-gui"));
    home.features
        .insert("airlock-gui-reconnect".into(), json!("1"));
    let mut new = old.clone();
    new.domains
        .get_mut(&"sys-gui".parse().unwrap())
        .unwrap()
        .features
        .insert("test-change".into(), json!("1"));
    let running = names(&["sys-gui", "usr-home"]);
    let plan = planning::plan(&old, &new, &running, &[], false).unwrap();
    assert_eq!(plan.stop, vec!["sys-gui".parse::<GuestName>().unwrap()]);
    assert_eq!(
        plan.gui_reconnect[&"sys-gui".parse().unwrap()],
        vec!["usr-home".parse::<GuestName>().unwrap()]
    );
    // A simultaneous hard network dependency on the provider forbids preserving the client.
    old.domains
        .get_mut(&"usr-home".parse().unwrap())
        .unwrap()
        .netvm = VmReference::Named("sys-gui".parse().unwrap());
    new.domains
        .get_mut(&"usr-home".parse().unwrap())
        .unwrap()
        .netvm = VmReference::Named("sys-gui".parse().unwrap());
    let plan = planning::plan(&old, &new, &running, &[], false).unwrap();
    assert_eq!(
        plan.stop,
        vec![
            "usr-home".parse::<GuestName>().unwrap(),
            "sys-gui".parse().unwrap()
        ]
    );
    assert!(plan.gui_reconnect.is_empty());
}

#[test]
fn declaration_order_does_not_change_the_serialized_plan() {
    let first = topology(&["usr-home", "sys-net", "usr-other"]);
    let second = topology(&["usr-other", "sys-net", "usr-home"]);
    let running = names(&["usr-home", "sys-net"]);
    let first = planning::plan(&first, &first, &running, &[], false).unwrap();
    let second = planning::plan(&second, &second, &running, &[], false).unwrap();
    assert_eq!(
        serde_json::to_value(first).unwrap(),
        serde_json::to_value(second).unwrap()
    );
}

#[test]
fn wire_shapes_retain_optional_reset_and_invalid_reference_semantics() {
    let mut graph = relationships(&["usr-home", "sys-net"]);
    graph.prefs.insert("default_netvm".into(), json!(42));
    graph
        .domains
        .get_mut(&"sys-net".parse().unwrap())
        .unwrap()
        .netvm = VmReference::Disabled;
    let home = "usr-home".parse().unwrap();
    assert!(graph.dependencies(false).is_err());
    graph.domains.get_mut(&home).unwrap().netvm = VmReference::Named("sys-net".parse().unwrap());
    graph
        .prefs
        .insert("default_dispvm".into(), json!("disp-external"));
    let refs = &graph.dependencies(false).unwrap()[&home];
    assert_eq!(refs, &names(&["sys-net", "disp-external"]));
    assert_eq!(
        graph.ordered().unwrap(),
        vec!["sys-net".parse::<GuestName>().unwrap(), home.clone()]
    );

    let d = graph.domains.get_mut(&home).unwrap();
    d.prefs.insert("guivm".into(), json!([]));
    assert!(graph.dependencies(false).is_err());
    assert!(graph.dependencies(true).is_ok());
    graph
        .domains
        .get_mut(&home)
        .unwrap()
        .prefs
        .insert("guivm".into(), json!(null));
    graph.domains.get_mut(&home).unwrap().devices = json!({"block": {"backend": "sys-net"}});
    assert!(graph.dependencies(false).is_err());
    // Non-object device containers and assignment rows without a backend remain optional.
    graph.domains.get_mut(&home).unwrap().devices = json!([42]);
    assert!(graph.dependencies(false).is_ok());
    graph.domains.get_mut(&home).unwrap().devices =
        json!({"block": [42, {}, {"backend": "bad/name"}]});
    assert!(graph.dependencies(false).is_err());
    graph.domains.get_mut(&home).unwrap().devices =
        json!({"block": [42, {}, {"backend": "sys-net"}]});
    assert_eq!(
        graph.dependencies(false).unwrap()[&home],
        names(&["sys-net", "disp-external"])
    );
}

#[test]
fn changed_added_removed_and_autostart_roots_preserve_distinct_semantics() {
    let mut old = topology(&["changed", "removed", "running", "stopped"]);
    old.domains
        .get_mut(&"running".parse().unwrap())
        .unwrap()
        .prefs
        .insert("autostart".into(), json!(false));
    old.domains
        .get_mut(&"stopped".parse().unwrap())
        .unwrap()
        .prefs
        .insert("autostart".into(), json!("true"));
    let mut new = old.clone();
    let removed = new.domains.remove(&"removed".parse().unwrap()).unwrap();
    new.domains.insert("added".parse().unwrap(), removed);
    new.domains
        .get_mut(&"changed".parse().unwrap())
        .unwrap()
        .features
        .insert("change".into(), json!("yes"));
    new.domains
        .get_mut(&"running".parse().unwrap())
        .unwrap()
        .prefs
        .insert("autostart".into(), json!(false));
    // A string spelling is not a boolean opt-in.
    new.domains
        .get_mut(&"stopped".parse().unwrap())
        .unwrap()
        .prefs
        .insert("autostart".into(), json!("true"));
    let retirement = ["removed".parse().unwrap()];
    let running = names(&["removed", "running"]);
    assert!(planning::plan(&old, &new, &running, &[], false).is_err());
    let plan = planning::plan(&old, &new, &running, &retirement, false).unwrap();
    assert_eq!(
        plan.changed.into_iter().collect::<BTreeSet<_>>(),
        names(&["added", "changed"])
    );
    assert_eq!(plan.start, vec!["running".parse::<GuestName>().unwrap()]);
    assert_eq!(plan.stop, vec!["removed".parse::<GuestName>().unwrap()]);
    assert_eq!(plan.retire, retirement);

    new.domains
        .get_mut(&"added".parse().unwrap())
        .unwrap()
        .prefs
        .insert("autostart".into(), json!(true));
    let plan = planning::plan(&old, &new, &running, &retirement, false).unwrap();
    assert_eq!(
        plan.start.into_iter().collect::<BTreeSet<_>>(),
        names(&["added", "running"])
    );
}

#[test]
fn only_kernel_and_host_preference_changes_seed_all_candidate_vms() {
    let old = topology(&["first", "second"]);
    let mut new = old.clone();
    new.qrexec_policy = json!({"rules": []});
    new.templates.insert("external".into(), json!({}));
    let plan = planning::plan(&old, &new, &names(&[]), &[], false).unwrap();
    assert!(plan.changed.is_empty());
    assert!(plan.start.is_empty());

    new.kernels.insert("new".into(), json!({}));
    let plan = planning::plan(&old, &new, &names(&[]), &[], false).unwrap();
    assert_eq!(
        plan.changed.into_iter().collect::<BTreeSet<_>>(),
        names(&["first", "second"])
    );
    assert!(plan.start.is_empty());

    let mut new = old.clone();
    new.prefs.insert("update".into(), json!(true));
    let plan = planning::plan(&old, &new, &names(&["first"]), &[], false).unwrap();
    assert_eq!(
        plan.changed.into_iter().collect::<BTreeSet<_>>(),
        names(&["first", "second"])
    );
    assert_eq!(plan.stop, vec!["first".parse::<GuestName>().unwrap()]);
}

#[test]
fn gui_preservation_respects_opt_in_changes_defaults_and_transitive_hard_dependents() {
    let mut old = topology(&["sys-gui", "service", "usr-home"]);
    old.domains
        .get_mut(&"usr-home".parse().unwrap())
        .unwrap()
        .prefs
        .insert("guivm".into(), json!("sys-gui"));
    old.domains
        .get_mut(&"usr-home".parse().unwrap())
        .unwrap()
        .features
        .insert("airlock-gui-reconnect".into(), json!("1"));
    let running = names(&["sys-gui", "usr-home"]);
    let mut new = old.clone();
    new.domains
        .get_mut(&"sys-gui".parse().unwrap())
        .unwrap()
        .features
        .insert("update".into(), json!("yes"));
    let plan = planning::plan(&old, &new, &running, &[], false).unwrap();
    assert_eq!(
        plan.gui_reconnect[&"sys-gui".parse().unwrap()],
        vec!["usr-home".parse::<GuestName>().unwrap()]
    );
    assert!(
        planning::plan(&old, &new, &names(&["sys-gui"]), &[], false)
            .unwrap()
            .gui_reconnect
            .is_empty()
    );

    // A changed client cannot be preserved even when it still opts in.
    new.domains
        .get_mut(&"usr-home".parse().unwrap())
        .unwrap()
        .features
        .insert("client-update".into(), json!("yes"));
    let plan = planning::plan(&old, &new, &running, &[], false).unwrap();
    assert!(plan.gui_reconnect.is_empty());
    assert!(plan.stop.contains(&"usr-home".parse().unwrap()));

    let mut new = old.clone();
    new.domains
        .get_mut(&"sys-gui".parse().unwrap())
        .unwrap()
        .features
        .insert("update".into(), json!("yes"));
    for topology in [&mut old, &mut new] {
        topology
            .domains
            .get_mut(&"usr-home".parse().unwrap())
            .unwrap()
            .netvm = VmReference::Named("service".parse().unwrap());
        topology
            .domains
            .get_mut(&"service".parse().unwrap())
            .unwrap()
            .netvm = VmReference::Named("sys-gui".parse().unwrap());
    }
    let plan = planning::plan(&old, &new, &running, &[], false).unwrap();
    assert!(plan.gui_reconnect.is_empty());
    assert_eq!(
        plan.stop,
        vec![
            "usr-home".parse::<GuestName>().unwrap(),
            "sys-gui".parse().unwrap()
        ]
    );

    // A host-default change seeds all VMs even when their local declarations are equal.
    let mut new = old.clone();
    new.prefs.insert("unrelated-default".into(), json!(true));
    assert!(
        planning::plan(&old, &new, &running, &[], false)
            .unwrap()
            .gui_reconnect
            .is_empty()
    );
}

#[test]
fn configuration_encoding_preserves_typed_equality_and_inherited_reference_distinctions() {
    let mut old = topology(&["client"]);
    old.domains
        .get_mut(&"client".parse().unwrap())
        .unwrap()
        .extra
        .insert("numeric-extension".into(), json!(-0.0));
    let mut new = old.clone();
    new.domains
        .get_mut(&"client".parse().unwrap())
        .unwrap()
        .extra
        .insert("numeric-extension".into(), json!(0.0));
    assert_eq!(old, new);
    assert!(
        planning::plan(&old, &new, &names(&[]), &[], false)
            .unwrap()
            .changed
            .is_empty()
    );

    // The serialized None cases must not collapse Inherit and Disabled.
    new.domains
        .get_mut(&"client".parse().unwrap())
        .unwrap()
        .netvm = VmReference::Inherit;
    assert_ne!(old, new);
    assert_eq!(
        planning::plan(&old, &new, &names(&[]), &[], false)
            .unwrap()
            .changed,
        vec!["client".parse::<GuestName>().unwrap()]
    );
}
