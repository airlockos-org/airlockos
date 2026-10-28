//! Mixed-backend topology validation keeps Linux storage out of Hermit declarations.

use airlock_machine_core::model::Topology;
use serde_json::{Value, json};

/// An immutable Hermit descriptor; these pure checks never open the fictional executable.
fn topology() -> Value {
    let system = "/nix/store/00000000000000000000000000000000-clipboard";
    json!({"schema":"airlock.qubes-topology.v1", "domains":{"sys-clipboard": {
        "class":"HermitVM", "netvm":null, "template":null,
        "prefs":{"virt_mode":"pvh", "kernel":"", "memory":32,"maxmem":32,"vcpus":1,"guivm":null,"audiovm":null},
        "features":{"qrexec":"", "gui":""},
        "backend":{"type":"hermit", "system":{"source":system}, "artifact":{
            "schema":"airlock.hermit-pvh.v1", "executable":format!("{system}/kernel.elf"),
            "sha256":"a".repeat(64), "bytes":1024, "source_revision":"b".repeat(40),
            "integration_revision":"c".repeat(40),"build_lock":"d".repeat(64),"authority":"disconnected"
        }}
    }}})
}

/// Decode and validate the same closed guest contract used at deployment admission.
fn valid(value: Value) -> bool {
    serde_json::from_value::<Topology>(value).is_ok_and(|topology| topology.validate().is_ok())
}

/// The topology adapter projects all guests without filtering the diskless backend out of requirements.
#[test]
fn complete_boot_requirements_preserve_both_backends() -> anyhow::Result<()> {
    let mut raw = topology();
    let system = "/nix/store/cccccccccccccccccccccccccccccccc-linux";
    let kernel = "/nix/store/dddddddddddddddddddddddddddddddd-kernel";
    raw["kernels"] = json!({"qubes-kernel":{"source":kernel}});
    raw["domains"]["usr-home"] = json!({
        "class":"StandaloneVM", "netvm":null, "template":null,
        "backend":{"type":"nix-closure", "system":{"source":system},
            "root":{"source":format!("{system}/root.img")}, "kernel":{"name":"qubes-kernel"},
            "store":{"source":system,"mode":"shared-closure","mountpoint":"/nix/store",
                "device":"/dev/xvde","blobDevice":"/dev/xvdf","viewBackend":"erofs-objectmap"}}
    });
    let inputs = airlock_machine_core::boot::BootInputs::new(raw)?;
    let requirements = inputs.requirements()?;
    assert_eq!(requirements.guests().len(), inputs.topology().domains.len());
    for name in inputs.topology().domains.keys() {
        assert_eq!(requirements.guest(name)?.name(), name.as_str());
    }
    assert_eq!(
        requirements.host_roots(),
        [
            "/nix/store/00000000000000000000000000000000-clipboard",
            kernel
        ]
    );
    Ok(())
}

#[test]
fn hermit_cannot_inherit_linux_storage_or_services() {
    assert!(valid(topology()));
    for (pointer, replacement) in [
        ("/domains/sys-clipboard/prefs/vcpus", json!(2)),
        ("/domains/sys-clipboard/prefs/maxmem", json!(64)),
        ("/domains/sys-clipboard/prefs/memory", json!(0)),
        ("/domains/sys-clipboard/features/qrexec", json!("0")),
        ("/domains/sys-clipboard/netvm", json!("sys-net")),
        ("/domains/sys-clipboard/class", json!("StandaloneVM")),
        (
            "/domains/sys-clipboard/backend/artifact/authority",
            json!("laboratory"),
        ),
    ] {
        let mut input = topology();
        *input.pointer_mut(pointer).unwrap() = replacement;
        assert!(!valid(input), "{pointer}");
    }
    for linux in ["root", "store", "kernel", "state", "modules"] {
        let mut input = topology();
        input["domains"]["sys-clipboard"]["backend"][linux] = json!({});
        assert!(!valid(input), "Linux field {linux}");
    }
}

/// Mixed generations use the same impact planner in both update and rollback directions.
#[test]
fn executable_updates_leave_an_unchanged_linux_guest_running() {
    use airlock_machine_core::planning;
    use std::collections::BTreeSet;

    let mut value = topology();
    let system = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-linux";
    value["domains"]["usr-home"] = json!({
        "class":"StandaloneVM", "netvm":null, "template":null,
        "backend":{"type":"nix-closure", "system":{"source":system},
            "root":{"source":format!("{system}/root.img")}, "kernel":{"name":"test"},
            "store":{"source":system,"mode":"shared-closure","mountpoint":"/nix/store",
                "device":"/dev/xvde","blobDevice":"/dev/xvdf","viewBackend":"erofs-objectmap"}}
    });
    let old: Topology = serde_json::from_value(value.clone()).unwrap();
    let image = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-clipboard";
    value["domains"]["sys-clipboard"]["backend"]["system"]["source"] = json!(image);
    value["domains"]["sys-clipboard"]["backend"]["artifact"]["executable"] =
        json!(format!("{image}/kernel.elf"));
    value["domains"]["sys-clipboard"]["backend"]["artifact"]["sha256"] = json!("f".repeat(64));
    let new: Topology = serde_json::from_value(value).unwrap();
    let running: BTreeSet<_> = ["sys-clipboard", "usr-home"]
        .into_iter()
        .map(|name| name.parse().unwrap())
        .collect();
    old.validate().unwrap();
    new.validate().unwrap();
    for (before, after) in [(&old, &new), (&new, &old)] {
        let plan = planning::plan(before, after, &running, &[], false).unwrap();
        assert!(
            plan.start
                .iter()
                .any(|name| name.as_str() == "sys-clipboard")
        );
        assert_eq!(
            plan.changed
                .iter()
                .map(|name| name.as_str())
                .collect::<Vec<_>>(),
            ["sys-clipboard"]
        );
        assert_eq!(
            plan.stop
                .iter()
                .map(|name| name.as_str())
                .collect::<Vec<_>>(),
            ["sys-clipboard"]
        );
        assert!(plan.retire.is_empty());
    }
}
