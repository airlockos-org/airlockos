//! Read-only lab GPU checks; a bus reset is a refusal, never an override.

use super::{Bdf, driver, path};
use anyhow::Result;
use serde_json::{Value, json};
use std::{fs, path::Path};

fn read(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_owned())
}

pub(super) fn inspect() -> Result<Value> {
    let sysfs = path("AIRLOCK_GPU_SYSFS", "/sys");
    let proc = path("AIRLOCK_GPU_PROC", "/proc");
    let bdf: Bdf = "0000:04:00.0".parse()?;
    let device = sysfs.join("bus/pci/devices").join(bdf.to_string());
    let mut members = Vec::new();
    if let Ok(entries) = fs::read_dir(device.join("iommu_group/devices")) {
        for entry in entries {
            members.push(entry?.file_name().to_string_lossy().into_owned());
        }
    }
    members.sort();
    let methods: Vec<String> = read(&device.join("reset_method"))
        .unwrap_or_default()
        .replace(['[', ']'], "")
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    let owner = driver(&device.join("driver")).ok();
    let capabilities = read(&proc.join("xen/capabilities")).unwrap_or_default();
    let vendor = read(&device.join("vendor"));
    let product = read(&device.join("device"));
    let mut failures = Vec::new();
    if !capabilities.split_whitespace().any(|s| s == "control_d") {
        failures.push("not-xen-dom0");
    }
    if vendor.as_deref() != Some("0x1002") || product.as_deref() != Some("0x1681") {
        failures.push("unexpected-gpu");
    }
    if members != [bdf.to_string()] {
        failures.push("missing-or-shared-iommu-group");
    }
    if owner.as_deref() != Some("pciback") {
        failures.push("gpu-not-reserved-by-xen-pciback");
    }
    if methods.first().map(String::as_str) != Some("flr") {
        failures.push("function-level-reset-not-selected-review-required");
    }
    let mut drm = Vec::new();
    if let (Ok(entries), Ok(target)) = (
        fs::read_dir(sysfs.join("class/drm")),
        fs::canonicalize(&device),
    ) {
        for entry in entries {
            let entry = entry?;
            if entry.file_name().to_string_lossy().starts_with("card")
                && fs::canonicalize(entry.path().join("device")).ok().as_ref() == Some(&target)
            {
                drm.push(entry.path().join("device"));
            }
        }
    }
    drm.sort();
    if !drm.is_empty() {
        failures.push("dom0-still-has-gpu-drm-device");
    }
    Ok(json!({
        "schema": 1,
        "bdf": bdf,
        "vendor": vendor,
        "device": product,
        "driver": owner,
        "iommu_members": members,
        "reset_methods": methods,
        "dom0_drm_devices": drm,
        "assignment_gate_passed": failures.is_empty(),
        "failures": failures,
        "graphics_verified": false,
        "input_verified": false,
        "note": "Read-only preflight, not proof of passthrough or reset safety.",
    }))
}
