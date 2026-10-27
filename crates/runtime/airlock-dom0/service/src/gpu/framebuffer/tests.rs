//! Firmware framebuffer controls are validated before the console is disconnected.

use super::*;
use std::os::unix::fs::symlink;

const BDF: &str = "0000:09:03.0";

/// Disposable sysfs relationships reproduce both firmware framebuffer attachment layouts.
struct Tree {
    // Owns every attribute and symlink; no real kernel device is visible through this root.
    temporary: tempfile::TempDir,
    // Selected firmware platform driver with its pinned unbind attribute.
    driver: PathBuf,
    // Platform device which must never probe again after handoff.
    device: PathBuf,
    // Console which must detach after overrides are durable.
    console: PathBuf,
    // Framebuffer registration removed when the simulated driver unbinds.
    graphic: PathBuf,
}

impl Tree {
    /// Build a realistic device, driver, bus and console tree entirely in temporary storage.
    fn new(nested: bool, name: &str) -> Result<Self> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path();
        let gpu = root.join("devices/pci0000:00/0000:00:08.1").join(BDF);
        fs::create_dir_all(&gpu)?;
        fs::write(gpu.join("class"), "0x030000\n")?;
        let pci = root.join("bus/pci/devices");
        fs::create_dir_all(&pci)?;
        symlink(&gpu, pci.join(BDF))?;
        let driver = root.join("bus/platform/drivers").join(name);
        fs::create_dir_all(&driver)?;
        fs::write(driver.join("unbind"), "")?;
        let parent = if nested {
            gpu
        } else {
            root.join("devices/platform")
        };
        let device = parent.join(format!("{name}.0"));
        fs::create_dir_all(&device)?;
        fs::write(device.join("driver_override"), "")?;
        symlink(&driver, device.join("driver"))?;
        symlink(&device, driver.join(device.file_name().unwrap()))?;
        let platform = root.join("bus/platform/devices");
        fs::create_dir_all(&platform)?;
        symlink(&device, platform.join(device.file_name().unwrap()))?;
        symlink(platform.parent().unwrap(), device.join("subsystem"))?;
        let graphic = root.join("class/graphics/fb0");
        fs::create_dir_all(&graphic)?;
        symlink(&device, graphic.join("device"))?;
        let console = root.join("class/vtconsole/vtcon7");
        fs::create_dir_all(&console)?;
        fs::write(console.join("name"), "(M) frame buffer device\n")?;
        fs::write(console.join("bind"), "1\n")?;
        Ok(Self {
            temporary,
            driver,
            device,
            console,
            graphic,
        })
    }

    /// Apply one inert control write, including the observable effects of driver unbinding.
    fn write(&self, path: &Path, value: &str) -> Result<()> {
        fs::write(path, value)?;
        if path == self.driver.join("unbind") {
            fs::remove_file(self.device.join("driver"))?;
            fs::remove_file(self.driver.join(self.device.file_name().unwrap()))?;
            fs::remove_file(self.graphic.join("device"))?;
            fs::remove_dir(&self.graphic)?;
        }
        Ok(())
    }
}

/// Both supported drivers and layouts hand off once and prevent future automatic probing.
#[test]
fn handoff_is_ordered_repeatable_and_prevents_driver_reprobe() -> Result<()> {
    for (nested, name) in [(false, "efi-framebuffer"), (true, "simple-framebuffer")] {
        let tree = Tree::new(nested, name)?;
        let mut writes = Vec::new();
        let result = release_with(tree.temporary.path(), BDF, |path, value, _| {
            writes.push((path.to_owned(), value.to_owned()));
            tree.write(path, value)
        })?;
        assert_eq!(result["status"], "released");
        assert_eq!(
            writes,
            vec![
                (
                    tree.device.join("driver_override"),
                    "airlock-released\n".into()
                ),
                (tree.console.join("bind"), "0\n".into()),
                (tree.driver.join("unbind"), format!("{name}.0\n"))
            ]
        );
        assert_eq!(
            release_with(tree.temporary.path(), BDF, |_, _, _| panic!(
                "repeat handoff must not write"
            ))?["status"],
            "no-framebuffer"
        );

        fs::write(tree.device.join("driver_override"), "\n")?;
        let mut reprobe = Vec::new();
        release_with(tree.temporary.path(), BDF, |path, value, _| {
            reprobe.push(path.to_owned());
            tree.write(path, value)
        })?;
        assert_eq!(reprobe, [tree.device.join("driver_override")]);
    }
    Ok(())
}

/// A bad owner, bus, registration or missing attribute must leave every control untouched.
#[test]
fn inventory_failures_precede_all_display_writes() -> Result<()> {
    for fault in [
        "other-gpu",
        "unknown-fb",
        "wrong-gpu",
        "wrong-bus",
        "missing-bus",
        "wrong-driver",
        "wrong-registration",
    ] {
        let tree = Tree::new(false, "efi-framebuffer")?;
        let root = tree.temporary.path();
        let mut bdf = BDF;
        match fault {
            "other-gpu" => bdf = "0000:01:00.0",
            "wrong-gpu" => fs::write(
                root.join("bus/pci/devices").join(BDF).join("class"),
                "0x020000\n",
            )?,
            "unknown-fb" => {
                let other = root.join("class/graphics/fb1");
                fs::create_dir(&other)?;
                symlink(root.join("bus/pci/devices").join(BDF), other.join("device"))?;
            }
            "wrong-bus" | "missing-bus" => {
                fs::remove_file(tree.device.join("subsystem"))?;
                if fault == "wrong-bus" {
                    symlink(root.join("bus/pci"), tree.device.join("subsystem"))?;
                }
            }
            "wrong-driver" => {
                fs::remove_file(tree.device.join("driver"))?;
                let other = root.join("bus/platform/drivers/not-firmware");
                fs::create_dir(&other)?;
                symlink(other, tree.device.join("driver"))?;
            }
            "wrong-registration" => {
                let registration = tree.driver.join(tree.device.file_name().unwrap());
                fs::remove_file(&registration)?;
                symlink(root.join("devices"), registration)?;
            }
            _ => unreachable!(),
        }
        let mut written = false;
        assert!(
            release_with(root, bdf, |_, _, _| {
                written = true;
                Ok(())
            })
            .is_err(),
            "{fault}"
        );
        assert!(!written, "{fault}");
    }
    Ok(())
}

/// Pin all controls before the first write, rejecting missing files, FIFOs and redirected attributes.
#[test]
fn all_control_files_are_validated_before_mutation() -> Result<()> {
    for (control, damage) in [
        ("override", "missing"),
        ("console", "symlink"),
        ("unbind", "fifo"),
        ("unbind", "directory"),
    ] {
        let tree = Tree::new(false, "efi-framebuffer")?;
        let path = match control {
            "override" => tree.device.join("driver_override"),
            "console" => tree.console.join("bind"),
            _ => tree.driver.join("unbind"),
        };
        fs::remove_file(&path)?;
        match damage {
            "symlink" => {
                fs::write(tree.temporary.path().join("untouched"), "1\n")?;
                symlink(tree.temporary.path().join("untouched"), &path)?;
            }
            "fifo" => rustix::fs::mknodat(
                rustix::fs::CWD,
                &path,
                rustix::fs::FileType::Fifo,
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                0,
            )?,
            "directory" => fs::create_dir(&path)?,
            _ => {}
        }
        assert!(
            release_with(tree.temporary.path(), BDF, |_, _, _| panic!(
                "all controls must be pinned before mutation"
            ))
            .is_err()
        );
    }
    Ok(())
}

/// An unobserved override, console detach or driver unbind stops the remaining handoff steps.
#[test]
fn failed_handoff_stops_at_the_first_unverified_effect() -> Result<()> {
    for blocked in ["override", "console", "driver"] {
        let tree = Tree::new(false, "efi-framebuffer")?;
        let path = match blocked {
            "override" => tree.device.join("driver_override"),
            "console" => tree.console.join("bind"),
            _ => tree.driver.join("unbind"),
        };
        let mut writes = Vec::new();
        let result = release_with(tree.temporary.path(), BDF, |target, value, _| {
            if target != path {
                writes.push(target.to_owned());
                tree.write(target, value)?;
            }
            Ok(())
        });
        assert!(result.is_err(), "{blocked}");
        if blocked == "override" {
            assert!(writes.is_empty());
        } else {
            assert_eq!(writes[0], tree.device.join("driver_override"));
        }
    }
    Ok(())
}
