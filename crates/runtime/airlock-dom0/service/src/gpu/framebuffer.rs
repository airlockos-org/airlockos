//! Firmware framebuffers can retain the sole GPU before its VM starts.
//! Release only recognized platform devices after validating the complete handoff.

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const DRIVERS: [&str; 2] = ["efi-framebuffer", "simple-framebuffer"];

#[derive(PartialEq, Eq)]
struct Device {
    // Canonical platform device, which may be nested beneath its physical PCI parent.
    path: PathBuf,
    // Recognized current firmware driver, absent for a device awaiting first probe.
    driver: Option<PathBuf>,
}

fn entries(path: &Path) -> Result<Vec<PathBuf>> {
    match fs::read_dir(path) {
        Ok(items) => {
            let mut paths = items
                .map(|e| e.map(|e| e.path()))
                .collect::<std::io::Result<Vec<_>>>()?;
            paths.sort();
            Ok(paths)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e.into()),
    }
}

fn numbered(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix)
        .is_some_and(|tail| !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()))
}

fn name(path: &Path) -> Result<&str> {
    path.file_name()
        .and_then(|n| n.to_str())
        .context("invalid firmware device name")
}

fn read_attribute(path: &Path) -> Result<String> {
    let file = File::from(rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?);
    ensure!(
        file.metadata()?.is_file(),
        "sysfs attribute must be an existing regular file"
    );
    let mut text = String::new();
    file.take(65537).read_to_string(&mut text)?;
    ensure!(text.len() <= 65536, "sysfs attribute exceeds limit");
    Ok(text)
}

fn inventory(root: &Path, bdf: &str) -> Result<Vec<Device>> {
    let mut displays = Vec::new();
    for path in entries(&root.join("bus/pci/devices"))? {
        let text = read_attribute(&path.join("class"))?;
        let class = u32::from_str_radix(text.trim().trim_start_matches("0x"), 16)?;
        if class >> 16 == 3 {
            displays.push(name(&path)?.to_owned());
        }
    }
    ensure!(
        displays == [bdf],
        "boot framebuffer requires the selected sole display GPU; found {displays:?}"
    );
    let devices_root = fs::canonicalize(root.join("devices"))?;
    let bus = fs::canonicalize(root.join("bus/platform"))?;
    let mut devices = Vec::new();
    for entry in entries(&root.join("bus/platform/devices"))? {
        if !DRIVERS
            .iter()
            .any(|prefix| numbered(name(&entry).unwrap_or(""), &format!("{prefix}.")))
        {
            continue;
        }
        let path = fs::canonicalize(&entry)?;
        ensure!(
            path.starts_with(&devices_root)
                && path.file_name() == entry.file_name()
                && fs::canonicalize(path.join("subsystem"))? == bus,
            "not a firmware platform device: {}",
            entry.display()
        );
        let driver = match fs::symlink_metadata(path.join("driver")) {
            Ok(_) => Some(fs::canonicalize(path.join("driver"))?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        if let Some(driver) = &driver {
            ensure!(
                DRIVERS
                    .iter()
                    .any(|n| *driver == root.join("bus/platform/drivers").join(n)),
                "firmware driver mismatch"
            );
            ensure!(
                fs::canonicalize(driver.join(name(&path)?))? == path,
                "firmware driver registration mismatch"
            );
            ensure!(
                driver.join("unbind").try_exists()?,
                "firmware driver cannot be detached safely"
            );
        }
        ensure!(
            path.join("driver_override").try_exists()?,
            "firmware device has no driver override"
        );
        devices.push(Device { path, driver });
    }
    ensure!(
        devices.len() <= 1,
        "multiple firmware framebuffers: refusing an ambiguous handoff"
    );
    for fb in entries(&root.join("class/graphics"))? {
        if !numbered(name(&fb)?, "fb") {
            continue;
        }
        let owner = fs::canonicalize(fb.join("device"))?;
        ensure!(
            devices
                .iter()
                .any(|d| d.driver.is_some() && owner.starts_with(&d.path)),
            "unexpected framebuffer owner: {}",
            fb.display()
        );
    }
    Ok(devices)
}

struct Control {
    // Existing sysfs control whose descriptor stays pinned through the handoff.
    path: PathBuf,
    // Validated write payload for this exact control, never shell-interpreted.
    value: String,
    // Opened before any mutation; no late file creation or symlink traversal.
    file: File,
}

impl Control {
    fn open(path: PathBuf, value: String) -> Result<Self> {
        let file = File::from(rustix::fs::open(
            &path,
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?);
        ensure!(
            file.metadata()?.is_file(),
            "sysfs control must be an existing regular attribute"
        );
        Ok(Self { path, value, file })
    }
}

pub(super) fn release(root: &Path, bdf: &str) -> Result<Value> {
    release_with(root, bdf, |_, value, file| {
        file.write_all(value.as_bytes())?;
        Ok(())
    })
}

pub(super) fn release_with(
    root: &Path,
    bdf: &str,
    mut write: impl FnMut(&Path, &str, &mut File) -> Result<()>,
) -> Result<Value> {
    let devices = inventory(root, bdf)?;
    let mut consoles = Vec::new();
    for console in entries(&root.join("class/vtconsole"))? {
        if numbered(name(&console)?, "vtcon")
            && read_attribute(&console.join("name"))?.contains("frame buffer")
            && read_attribute(&console.join("bind"))?.trim() == "1"
        {
            consoles.push(console);
        }
    }
    ensure!(
        !devices.is_empty() || consoles.is_empty(),
        "fbcon remains bound without a recognized firmware framebuffer"
    );

    // Pin every control before touching the display. A missing or malformed
    // later control must not leave the console partially disconnected.
    let mut overrides = Vec::new();
    for device in &devices {
        if read_attribute(&device.path.join("driver_override"))?.trim() != "airlock-released" {
            overrides.push(Control::open(
                device.path.join("driver_override"),
                "airlock-released\n".into(),
            )?);
        }
    }
    let mut bindings = consoles
        .iter()
        .map(|p| Control::open(p.join("bind"), "0\n".into()))
        .collect::<Result<Vec<_>>>()?;
    let mut unbinds = Vec::new();
    for device in &devices {
        if let Some(driver) = &device.driver {
            unbinds.push(Control::open(
                driver.join("unbind"),
                format!("{}\n", name(&device.path)?),
            )?);
        }
    }
    ensure!(
        inventory(root, bdf)? == devices,
        "firmware framebuffer ownership changed before handoff"
    );

    for control in &mut overrides {
        write(&control.path, &control.value, &mut control.file)?;
        ensure!(
            read_attribute(&control.path)?.trim() == "airlock-released",
            "firmware driver override did not persist"
        );
    }
    for control in &mut bindings {
        write(&control.path, &control.value, &mut control.file)?;
        ensure!(
            read_attribute(&control.path)?.trim() == "0",
            "framebuffer console did not detach"
        );
    }
    for control in &mut unbinds {
        write(&control.path, &control.value, &mut control.file)?;
    }
    for device in &devices {
        ensure!(
            fs::symlink_metadata(device.path.join("driver"))
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "firmware driver still bound"
        );
    }
    ensure!(
        inventory(root, bdf)?.iter().all(|d| d.driver.is_none()),
        "firmware framebuffer remained bound after handoff"
    );
    Ok(
        json!({"schema":"airlock.boot-framebuffer.v1","status":if devices.iter().any(|d|d.driver.is_some()) {"released"}else{"no-framebuffer"},"gpu":bdf,"devices":devices.iter().map(|d|name(&d.path)).collect::<Result<Vec<_>>>()?,"consoles":consoles.iter().map(|p|name(p)).collect::<Result<Vec<_>>>()?}),
    )
}

#[cfg(test)]
mod tests;
