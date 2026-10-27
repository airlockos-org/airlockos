//! Observe Qubes-resolved PCI identity before firmware generation or declared startup.
//! A successful check never attaches devices or overrides Xen's isolation decisions.

use super::{Bdf, Phase, attribute, driver, hex, pci_root};
use airlock_nix_core::identity::GuestName;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Vm {
    /// Non-administrative VM receiving the prepared firmware.
    pub name: GuestName,
    /// Qubes UUID binding the artifact to one VM rather than a reusable name.
    pub uuid: String,
    /// Firmware delivery supports HVM only.
    pub virt_mode: String,
    /// Effective inherited features, read through Qubes' template-aware API.
    pub features: Features,
    /// Complete persistent PCI assignments, including optional assignments.
    pub assignments: Vec<Assignment>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Features {
    /// Virtual display emulation must be disabled for this firmware path.
    pub video_model: String,
    /// UEFI is outside the supported SeaBIOS path.
    pub uefi: bool,
    /// The supported firmware transport requires a Linux stub domain.
    pub linux_stubdom: bool,
    /// Custom device arguments could invalidate the checked PCI address.
    pub qemu_extra_args: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Assignment {
    /// Optional PCI devices cannot establish a stable firmware identity.
    pub required: bool,
    /// Only devices provided by administrative domain zero are supported.
    pub backend_qid: u32,
    /// Qubes-resolved devices; wildcard or unavailable assignments must fail closed.
    pub devices: Vec<PciDevice>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PciDevice {
    /// Address supplied by Qubes rather than reconstructed from a topology port.
    pub host_bdf: Bdf,
    /// Upstream port identity retained for a fresh-assignment comparison at render time.
    pub port_id: String,
}

#[derive(Serialize)]
pub(super) struct Selected {
    /// Validated segment-zero PCI address of the assigned AMD display device.
    pub host_bdf: Bdf,
    /// PCI vendor read from this host's current sysfs state.
    pub vendor: u16,
    /// PCI device identifier used to select the firmware image.
    pub device: u16,
    /// Qubes port whose identity must remain unchanged through XML rendering.
    pub port_id: String,
}

pub(super) fn selected(vm: &Vm, slot: u8) -> Result<Selected> {
    ensure!(
        (8..=31).contains(&slot),
        "AMD VFCT guest slot must be between 8 and 31"
    );
    ensure!(
        vm.uuid.len() == 36
            && vm
                .uuid
                .bytes()
                .enumerate()
                .all(|(i, b)| if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }),
        "invalid VM UUID"
    );
    ensure!(vm.virt_mode == "hvm", "AMD VFCT requires an HVM VM");
    ensure!(
        vm.features.video_model == "none",
        "AMD VFCT requires video-model=none"
    );
    ensure!(
        !vm.features.uefi && vm.features.linux_stubdom,
        "AMD VFCT supports SeaBIOS with Linux stubdom only"
    );
    ensure!(
        vm.features.qemu_extra_args.is_empty(),
        "AMD VFCT does not support custom QEMU device arguments"
    );
    ensure!(
        vm.assignments.len() == 1,
        "AMD VFCT requires exactly one required PCI assignment"
    );
    let assignment = &vm.assignments[0];
    ensure!(
        assignment.required && assignment.backend_qid == 0 && assignment.devices.len() == 1,
        "AMD VFCT requires exactly one required PCI device supplied by dom0"
    );
    let device = &assignment.devices[0];
    ensure!(
        !device.port_id.is_empty()
            && device.port_id.len() <= 256
            && !device.port_id.chars().any(char::is_control),
        "invalid Qubes PCI port"
    );

    let path = pci_root().join(device.host_bdf.to_string());
    let vendor = attribute(&path.join("vendor"))?;
    let id = attribute(&path.join("device"))?;
    ensure!(
        vendor == 0x1002 && attribute(&path.join("class"))? >> 16 == 3,
        "assigned device is not an AMD display controller"
    );
    ensure!(
        driver(&path.join("driver"))? == "pciback",
        "AMD GPU must already be reserved to pciback at host boot"
    );
    Ok(Selected {
        host_bdf: device.host_bdf,
        vendor: vendor.try_into()?,
        device: id.try_into()?,
        port_id: device.port_id.clone(),
    })
}

#[derive(Deserialize)]
pub(super) struct Selection {
    /// A disabled physical-GPU profile must not inherit a stale assignment.
    #[serde(default = "enabled")]
    pub enable: bool,
    /// Selected physical address; absent only for a disabled profile.
    pub bdf: Option<Bdf>,
    /// Qubes' topology port; distinct from a PCI bus/device/function address.
    pub port: Option<String>,
    /// Configured PCI vendor identifier, expressed in hexadecimal.
    vendor: Option<String>,
    /// Configured PCI device identifier, expressed in hexadecimal.
    device: Option<String>,
}

fn enabled() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Inventory {
    /// Qubes-resolved host address for the requested topology port, when enabled.
    resolved: Option<Bdf>,
    /// Every domain's assigned and attached PCI devices, including dom0.
    domains: Vec<Domain>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Domain {
    // Qubes domain name; dom0 is valid here because the inventory includes it.
    name: String,
    // Upstream activity predicate, including paused or starting VMs.
    running: bool,
    // Persistent assignment records, without mutation or automatic replacement.
    assignments: Vec<Item>,
    // Live attachments that may conflict with the declared exclusive owner.
    attached: Vec<Item>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Item {
    // Backend domain that supplies this PCI port.
    backend: String,
    // Qubes port identity, possibly a wildcard assignment.
    port: String,
    // Upstream assignment mode; absent for attachment-only records.
    mode: Option<String>,
    // Wildcard matching is required for the declared persistent port assignment.
    device_id: Option<String>,
    // Any custom option is a conflict, not something to silently erase.
    options: Value,
}

pub(super) fn check(
    selection: &Selection,
    topology: &Value,
    inventory: &Inventory,
    phase: Phase,
) -> Result<Value> {
    if !selection.enable {
        ensure!(
            phase != Phase::Start,
            "physical sys-gui GPU ownership is disabled in this profile"
        );
        ensure!(inventory.domains.iter().all(|d| d.name!="sys-gui" || (d.assignments.is_empty() && d.attached.is_empty())),"physical sys-gui PCI state remains from another profile");
        return Ok(
            json!({"schema":"airlock.gui-gpu-check.v1","phase":phase,"status":"passed","enabled":false}),
        );
    }
    let bdf = selection.bdf.context("missing selected GPU address")?;
    let port = selection.port.as_ref().context("missing Qubes GPU port")?;
    ensure!(
        !port.is_empty() && port.len() <= 256 && !port.chars().any(char::is_control),
        "invalid Qubes GPU port"
    );
    let path = pci_root().join(bdf.to_string());
    ensure!(
        path.is_dir(),
        "selected GPU {bdf} is missing; review machine configuration"
    );
    for (field, expected) in [("vendor", &selection.vendor), ("device", &selection.device)] {
        ensure!(
            attribute(&path.join(field))?
                == hex(expected
                    .as_ref()
                    .context("missing selected hardware identifier")?)?,
            "GPU {bdf} {field} mismatch"
        );
    }
    ensure!(
        attribute(&path.join("class"))? >> 16 == 3,
        "selected PCI device is not a display controller"
    );
    ensure!(
        driver(&path.join("driver"))? == "pciback",
        "GPU {bdf} is not reserved to pciback"
    );
    ensure!(
        inventory.resolved == Some(bdf),
        "Qubes port dom0:{port} does not resolve to selected GPU {bdf}"
    );

    let domain = &topology["domains"]["sys-gui"];
    let expected =
        json!([{"backend":"dom0","id":port,"mode":"required","match":"port","options":{}}]);
    ensure!(
        domain["devices"]["pci"] == expected,
        "sys-gui topology does not contain exactly the selected required GPU assignment"
    );
    ensure!(
        domain["prefs"].get("autostart").is_none_or(|v| v == false)
            && domain["prefs"]["virt_mode"] == "hvm"
            && domain["features"]["video-model"] == "none",
        "sys-gui topology must use HVM, video-model=none and autostart=false"
    );

    let mut assigned = false;
    let mut running = false;
    let mut names = std::collections::BTreeSet::new();
    for vm in &inventory.domains {
        ensure!(names.insert(&vm.name), "duplicate domain in GPU inventory");
        if vm.name != "sys-gui" {
            ensure!(
                !vm.assignments
                    .iter()
                    .chain(&vm.attached)
                    .any(|item| item.backend == "dom0" && (item.port == *port || item.port == "*")),
                "selected GPU already assigned/attached to {}",
                vm.name
            );
            continue;
        }
        running = vm.running;
        ensure!(
            vm.attached
                .iter()
                .all(|i| i.backend == "dom0" && i.port == *port && i.options == json!({})),
            "sys-gui has conflicting attached PCI devices/options"
        );
        ensure!(
            vm.assignments.iter().all(|i| i.backend == "dom0"
                && i.port == *port
                && i.mode.as_deref() == Some("required")
                && i.device_id.as_deref() == Some("*")
                && i.options == json!({})),
            "sys-gui has a conflicting PCI assignment; refusing to replace it automatically"
        );
        ensure!(
            vm.assignments.len() <= 1,
            "sys-gui has multiple PCI assignments"
        );
        assigned = vm.assignments.len() == 1;
        ensure!(
            !running || assigned,
            "sys-gui is running without the declared persistent assignment"
        );
    }
    ensure!(
        phase != Phase::Start || assigned,
        "bootstrap has not persisted the required sys-gui GPU assignment"
    );
    Ok(
        json!({"schema":"airlock.gui-gpu-check.v1","phase":phase,"status":"passed","bdf":bdf,"port":port,"persistent_assignment":assigned,"running":running}),
    )
}
