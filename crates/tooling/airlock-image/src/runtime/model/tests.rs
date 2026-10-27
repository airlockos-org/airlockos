//! Offline plans reject identity overrides before the Qubes adapter is invoked.

use super::*;
use serde_json::json;

/// A complete standalone VM declaration with no filesystem prerequisites.
fn topology() -> Value {
    json!({
        "kernels": {"test-kernel": {"source": "/kernel"}},
        "prefs": {"default_netvm": null},
        "domains": {"usr-home": {
            "class": "StandaloneVM", "label": "green", "netvm": null,
            "prefs": {"guivm": null, "virt_mode": "hvm", "autostart": false},
            "features": {"qrexec": true}, "services": {"example": false},
            "backend": {"type": "nix-closure", "system": {"source": "/nix/store/00000000000000000000000000000000-system"},
                "root": {"source": "/nix/store/00000000000000000000000000000000-root/root.img"}, "store": {"source": "/nix/store/00000000000000000000000000000000-prepared", "mode": "shared-closure", "device": "/dev/xvde", "blobDevice": "/dev/xvdf", "mountpoint": "/nix/store", "viewBackend": "erofs-objectmap"},
                "kernel": {"name": "test-kernel"}, "state": {"persistent_size": 33554432}}
        }}
    })
}

/// Deserialize the same wire format accepted by the image command.
fn checked(value: Value) -> Result<()> {
    validate(&serde_json::from_value(value)?)
}

/// Path escapes, unsupported backends and missing providers cannot become image plans.
#[test]
fn invalid_runtime_plans_are_rejected() {
    checked(topology()).unwrap();

    for (pointer, replacement) in [
        ("/domains/usr-home/backend/kernel/name", json!("../outside")),
        ("/domains/usr-home/class", json!("TemplateVM")),
        ("/kernels", json!({})),
        ("/domains/usr-home/netvm", json!("missing")),
        ("/domains/usr-home/prefs/guivm", json!("missing")),
        ("/domains/usr-home/features/qrexec", json!(["invalid"])),
    ] {
        let mut value = topology();
        *value.pointer_mut(pointer).unwrap() = replacement;
        assert!(checked(value).is_err(), "{pointer}");
    }

    let mut value = topology();
    let domain = value["domains"]
        .as_object_mut()
        .unwrap()
        .remove("usr-home")
        .unwrap();
    value["domains"]["../escape"] = domain;
    assert!(checked(value).is_err());
}

/// User preferences cannot replace the state owned by the offline Qubes adapter.
#[test]
fn managed_identity_and_storage_cannot_be_overridden() {
    for key in [
        "name",
        "uuid",
        "qid",
        "label",
        "dir_path",
        "volume_config",
        "events_enabled",
        "storage",
        "app",
        "_private",
    ] {
        let mut value = topology();
        value["domains"]["usr-home"]["prefs"][key] = json!("override");
        assert!(
            checked(value)
                .unwrap_err()
                .to_string()
                .contains("managed identity or storage"),
            "{key}"
        );
    }

    for key in [
        "offline_mode",
        "events_enabled",
        "pools",
        "domains",
        "labels",
        "store",
        "_private",
    ] {
        let mut value = topology();
        value["prefs"][key] = json!("override");
        assert!(checked(value).is_err(), "{key}");
    }
}

/// Explicit options survive unchanged while required storage options are added once.
#[test]
fn kernel_options_preserve_user_intent_and_reject_conflicts() {
    let mut value = topology()["domains"]["usr-home"].clone();
    value["prefs"]["kernelopts"] = json!("console=hvc0 quiet init=/sbin/init");
    let domain = serde_json::from_value(value.clone()).unwrap();
    let result = kernelopts(&domain).unwrap();
    let words: Vec<_> = result.split_whitespace().collect();
    assert_eq!(&words[..3], ["console=hvc0", "quiet", "init=/sbin/init"]);
    assert_eq!(
        words
            .iter()
            .filter(|word| **word == "init=/sbin/init")
            .count(),
        1
    );
    assert!(words.contains(&"airlock.system=/nix/store/00000000000000000000000000000000-system"));
    assert!(words.contains(&"airlock.storedev=/dev/xvde"));

    for invalid in [
        json!("init=/wrong"),
        json!("init=/wrong init=/sbin/init"),
        json!(42),
    ] {
        value["prefs"]["kernelopts"] = invalid;
        assert!(kernelopts(&serde_json::from_value(value.clone()).unwrap()).is_err());
    }
}

/// Built-in colors cannot be redefined and custom labels must agree across VMs.
#[test]
fn custom_labels_have_one_consistent_color() {
    let mut value = topology();
    value["domains"]["usr-home"]["features"]["airlock-label-color"] = json!("0xffffff");
    assert!(checked(value.clone()).is_err());

    value["domains"]["usr-home"]["label"] = json!("light-gray");
    value["domains"]["usr-home"]["features"]["airlock-label-color"] = json!("0xd3d3d3");
    checked(value.clone()).unwrap();
    value["domains"]["usr-other"] = value["domains"]["usr-home"].clone();
    value["domains"]["usr-other"]["features"]["airlock-label-color"] = json!("0xffffff");
    assert!(checked(value).is_err());
}

/// Missing providers inherit; explicit null is retained as an intentional reset.
#[test]
fn provider_declarations_preserve_inheritance() {
    // Qubes creates dom0 itself; the nested display relay may use that built-in provider.
    let mut relay = topology();
    relay["domains"]["usr-home"]["prefs"]["guivm"] = json!("dom0");
    checked(relay).unwrap();

    let explicit: Topology = serde_json::from_value(topology()).unwrap();
    assert_eq!(explicit.domains["usr-home"].netvm, VmReference::Disabled);
    assert_eq!(
        explicit.domains["usr-home"].prefs.get("guivm"),
        Some(&Value::Null)
    );

    let mut raw = topology();
    raw["domains"]["usr-home"]
        .as_object_mut()
        .unwrap()
        .remove("netvm");
    raw["domains"]["usr-home"]["prefs"]
        .as_object_mut()
        .unwrap()
        .remove("guivm");
    let inherited: Topology = serde_json::from_value(raw).unwrap();
    assert!(inherited.domains["usr-home"].netvm.is_inherited());
    assert!(!inherited.domains["usr-home"].prefs.contains_key("guivm"));
}
