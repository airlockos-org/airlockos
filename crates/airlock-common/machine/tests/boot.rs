//! Boot input validation preserves declaration semantics across image/runtime decoding.

use airlock_machine_core::boot::BootInputs;
use serde_json::{Value, json};

/// A native guest with a descriptor child and an inherited network provider.
fn topology() -> Value {
    let object = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-artifacts";
    json!({"schema":"airlock.qubes-topology.v1", "domains":{"usr-home":{
        "class":"StandaloneVM", "backend":{
            "type":"nix-closure", "system":{"source":object},
            "root":{"source":format!("{object}/root.img")}, "kernel":{"name":"test"},
            "store":{"source":format!("{object}/usr-home"), "mode":"shared-closure",
                "mountpoint":"/nix/store", "device":"/dev/xvde", "blobDevice":"/dev/xvdf",
                "viewBackend":"erofs-objectmap"}
        }
    }}})
}

/// A reconnectable display link stays early, while clipboard authority and transitive clients wait.
#[test]
fn foreground_plan_preserves_hard_edges_and_reconnectable_display_links() -> anyhow::Result<()> {
    use airlock_deployment_core::boot::startup::Phase;
    let mut raw = topology();
    let guest = raw["domains"]["usr-home"].clone();
    for name in ["sys-net", "sys-gui", "sys-clipboard", "usr-headless"] {
        raw["domains"][name] = guest.clone();
    }
    raw["domains"]["sys-gui"]["services"] = json!({"guivm":true});
    raw["domains"]["sys-clipboard"]["features"] = json!({"airlock-clipboard-authority":"sys-gui"});
    raw["domains"]["usr-home"]["features"] =
        json!({"airlock-boot-foreground":"1", "airlock-clipboard-service":"sys-clipboard"});
    raw["domains"]["usr-home"]["netvm"] = json!("sys-net");
    raw["domains"]["usr-headless"]["features"] = json!({"airlock-boot-foreground":"1"});
    raw["domains"]["usr-headless"]["prefs"] = json!({"guivm":"sys-gui"});
    let inputs = BootInputs::new(raw)?;
    let plan = inputs.foreground_plan()?;
    let early = plan.phase(Phase::BeforeGui);
    let deferred = plan.phase(Phase::AfterGui);
    assert!(early.contains(&"sys-net".parse()?));
    assert!(early.contains(&"usr-headless".parse()?));
    assert_eq!(plan.phase(Phase::Gui), ["sys-gui".parse()?]);
    assert_eq!(deferred, ["sys-clipboard".parse()?, "usr-home".parse()?]);
    let all = early
        .into_iter()
        .chain(plan.phase(Phase::Gui))
        .chain(deferred)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(all.len(), plan.guests().len());
    let mut unresolved = inputs.raw().clone();
    unresolved["domains"]["usr-home"]["netvm"] = json!("sys-external");
    let unresolved = BootInputs::new(unresolved)?;
    assert!(
        unresolved
            .foreground_plan()
            .err()
            .unwrap()
            .to_string()
            .contains("outside the foreground plan")
    );
    Ok(())
}

#[test]
fn boot_inputs_preserve_omission_and_explicit_overrides() {
    let inherited = BootInputs::new(topology()).unwrap();
    assert!(
        inherited
            .topology()
            .domains
            .values()
            .next()
            .unwrap()
            .netvm
            .is_inherited()
    );
    assert!(
        inherited.raw()["domains"]["usr-home"]
            .get("netvm")
            .is_none()
    );
    let mut disabled = topology();
    disabled["domains"]["usr-home"]["netvm"] = Value::Null;
    let disabled = BootInputs::new(disabled).unwrap();
    assert!(
        !disabled
            .topology()
            .domains
            .values()
            .next()
            .unwrap()
            .netvm
            .is_inherited()
    );
    assert_eq!(disabled.raw()["domains"]["usr-home"]["netvm"], Value::Null);
}

#[test]
fn boot_inputs_reject_identity_errors_and_dependency_cycles() {
    let mut invalid = topology();
    invalid["domains"]["usr-home"]["backend"]["store"]["source"] = json!("/tmp/wrong");
    assert!(BootInputs::new(invalid).is_err());
    let mut cycle = topology();
    cycle["domains"]["sys-net"] = cycle["domains"]["usr-home"].clone();
    cycle["domains"]["usr-home"]["netvm"] = json!("sys-net");
    cycle["domains"]["sys-net"]["netvm"] = json!("usr-home");
    assert!(BootInputs::new(cycle).is_err());
}
