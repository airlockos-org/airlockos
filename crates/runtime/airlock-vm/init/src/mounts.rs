//! Locate the admitted EROFS store without depending on programs inside it.

use crate::{config::BootConfig, executable, log, mkdir};
use rustix::mount::{MountFlags, UnmountFlags, mount, unmount};
use std::{ffi::CString, fs, io, path::Path, process::Command, time::Duration};

/// Create an early mountpoint and tolerate filesystems already mounted by the kernel or initrd.
fn basic_mount(
    source: &str,
    target: &str,
    filesystem: &str,
    flags: MountFlags,
    data: Option<&std::ffi::CStr>,
) {
    if let Err(error) = mkdir(target, 0o755) {
        log(format_args!("cannot create {target}: {error}"));
        return;
    }

    if let Err(error) = mount(source, target, filesystem, flags, data)
        && error != rustix::io::Errno::BUSY
    {
        log(format_args!(
            "cannot mount {filesystem} on {target}: {error}"
        ));
    }
}

/// Make kernel metadata, devices and runtime scratch space available before reading boot options.
pub(super) fn basic() {
    let restricted = MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC;
    basic_mount("proc", "/proc", "proc", restricted, None);
    basic_mount("sysfs", "/sys", "sysfs", restricted, None);
    basic_mount(
        "devtmpfs",
        "/dev",
        "devtmpfs",
        MountFlags::NOSUID,
        Some(c"mode=0755"),
    );
    basic_mount(
        "tmpfs",
        "/run",
        "tmpfs",
        MountFlags::NOSUID | MountFlags::NODEV,
        Some(c"mode=0755"),
    );
}

/// Compare the mountpoint field, rather than matching unrelated devices or mount options.
fn has_mount(contents: &str, target: &str) -> bool {
    contents
        .lines()
        .any(|line| line.split_ascii_whitespace().nth(4) == Some(target))
}

/// Observe the current process's mount namespace, retaining the original best-effort error handling.
fn mounted(target: &str) -> bool {
    match fs::read_to_string("/proc/self/mountinfo") {
        Ok(contents) => has_mount(&contents, target),
        Err(error) => {
            log(format_args!("cannot read /proc/self/mountinfo: {error}"));
            false
        }
    }
}

/// Mount Qubes' separate kernel-module disk if the initrd has not already supplied it.
fn kernel_modules() {
    if mounted("/lib/modules") {
        return;
    }
    if let Err(error) = mkdir("/lib/modules", 0o755) {
        log(format_args!("cannot create /lib/modules: {error}"));
        return;
    }

    for device in ["/dev/xvdd", "/dev/vdd", "/dev/sdd"] {
        if rustix::fs::access(device, rustix::fs::Access::READ_OK).is_err() {
            continue;
        }
        for filesystem in ["ext4", "ext3"] {
            if mount(
                device,
                "/lib/modules",
                filesystem,
                MountFlags::RDONLY | MountFlags::NODEV,
                Some(c"ro"),
            )
            .is_ok()
            {
                log(format_args!("mounted Qubes kernel modules from {device}"));
                return;
            }
        }
    }
}

/// Ask the boot image's static BusyBox to load EROFS; a built-in driver needs no successful modprobe.
fn erofs_module() {
    if executable(Path::new("/sbin/modprobe"))
        && Command::new("/sbin/modprobe")
            .arg("erofs")
            .status()
            .is_ok_and(|status| status.success())
    {
        log("loaded kernel module erofs");
    }
}

/// Accept a mounted metadata/data pair only when it contains the kernel-selected executable init.
fn candidate(config: &BootConfig, device: &str, noisy: bool) -> bool {
    if rustix::fs::access(device, rustix::fs::Access::READ_OK).is_err() {
        return false;
    }
    if config.blob_device.is_empty() {
        if noisy {
            log("erofs store requires airlock.storeblobdev");
        }
        return false;
    }
    if let Err(error) = rustix::fs::access(&config.blob_device, rustix::fs::Access::READ_OK) {
        if noisy {
            log(format_args!(
                "cannot access candidate store blob device {device}: {error}",
                device = config.blob_device
            ));
        }
        return false;
    }

    let data = match CString::new(format!("ro,device={device}", device = config.blob_device)) {
        Ok(data) => data,
        Err(error) => {
            log(format_args!("invalid store blob device: {error}"));
            return false;
        }
    };
    if let Err(error) = mount(
        device,
        "/nix/store",
        "erofs",
        MountFlags::RDONLY | MountFlags::NODEV,
        Some(data.as_c_str()),
    ) {
        if noisy {
            log(format_args!(
                "cannot mount erofs candidate store device {device}: {error}"
            ));
        }
        return false;
    }

    if executable(&config.system.join("init")) {
        log(format_args!("mounted read-only Nix store from {device}"));
        return true;
    }
    if noisy {
        log(format_args!(
            "mounted {device}, but {system}/init is not present",
            system = config.system.display()
        ));
    }
    if let Err(error) = unmount("/nix/store", UnmountFlags::empty())
        && noisy
    {
        log(format_args!(
            "cannot unmount rejected store device {device}: {error}"
        ));
    }
    false
}

/// Repeat the established device search for thirty seconds, stopping on the first accepted store.
fn discover(
    config: &BootConfig,
    mut attempt: impl FnMut(&str, bool) -> bool,
    mut pause: impl FnMut(),
) -> bool {
    for round in 0..30 {
        for device in config.devices() {
            let noisy = round == 29 && config.device.as_deref() == Some(device);
            if attempt(device, noisy) {
                return true;
            }
        }
        pause();
    }
    false
}

/// Reuse a valid premounted store or locate the selected EROFS metadata/data pair.
pub(super) fn store(config: &BootConfig) -> io::Result<()> {
    mkdir("/nix/store", 0o555)?;
    if mounted("/nix/store") && executable(&config.system.join("init")) {
        log(format_args!(
            "using pre-mounted /nix/store containing {system}/init",
            system = config.system.display()
        ));
        return Ok(());
    }
    if config.format != "erofs" {
        return Err(io::Error::other(format!(
            "unsupported airlock.storefmt={format}",
            format = config.format
        )));
    }

    kernel_modules();
    erofs_module();
    if discover(
        config,
        |device, noisy| candidate(config, device, noisy),
        || std::thread::sleep(Duration::from_secs(1)),
    ) {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "could not mount a Nix store containing {system}/init",
        system = config.system.display()
    )))
}

#[cfg(test)]
mod tests {
    use super::{discover, has_mount};
    use crate::config::BootConfig;

    /// Discovery retries rejected devices and never probes beyond a valid candidate.
    #[test]
    fn device_search_is_ordered_and_bounded() {
        let config =
            BootConfig::parse("airlock.system=/nix/store/system airlock.storedev=/dev/preferred")
                .unwrap();
        let mut seen = Vec::new();
        let mut pauses = 0;
        assert!(discover(
            &config,
            |device, _| {
                seen.push(device.to_owned());
                device == "/dev/vde"
            },
            || pauses += 1
        ));
        assert_eq!(seen.first().map(String::as_str), Some("/dev/preferred"));
        assert_eq!(seen.last().map(String::as_str), Some("/dev/vde"));
        assert_eq!(pauses, 0);

        let mut attempts = 0;
        let mut noisy = Vec::new();
        assert!(!discover(
            &config,
            |device, report| {
                attempts += 1;
                if report {
                    noisy.push(device.to_owned());
                }
                false
            },
            || pauses += 1
        ));
        assert_eq!(attempts, 30 * config.devices().count());
        assert_eq!(pauses, 30);
        assert_eq!(noisy, ["/dev/preferred"]);
    }

    /// A device or nested directory mentioning the target is not itself that mountpoint.
    #[test]
    fn mountinfo_matches_the_exact_mountpoint() {
        let contents = r#"
            1 0 0:1 / /nix/store rw - erofs /dev/vde ro
            2 0 0:2 / /lib/modules rw - ext4 /dev/vdd ro
        "#;
        assert!(has_mount(contents, "/nix/store"));
        assert!(has_mount(contents, "/lib/modules"));
        assert!(!has_mount(contents, "/nix/store/system"));
        assert!(!has_mount(contents, "/dev/vde"));
    }
}
