//! Mount the VM's admitted read-only store, activate NixOS and replace PID 1 with its init.
//! The boot image carries this static executable and BusyBox independently of that store.

#![forbid(unsafe_code)]

mod config;

mod mounts;

use config::BootConfig;
use std::{
    fs::{self, DirBuilder},
    io,
    os::unix::{
        fs::{DirBuilderExt, symlink},
        process::CommandExt,
    },
    path::Path,
    process::{Command, ExitCode},
};

/// Report early-boot diagnostics on the inherited kernel console.
fn log(message: impl std::fmt::Display) {
    eprintln!("airlock-early-init: {message}");
}

/// Create missing parent directories with the same permissions as the final directory.
fn mkdir(path: &str, mode: u32) -> io::Result<()> {
    DirBuilder::new().recursive(true).mode(mode).create(path)
}

/// Check execute permission before accepting a candidate system or invoking the boot image's modprobe.
fn executable(path: &Path) -> bool {
    rustix::fs::access(path, rustix::fs::Access::EXEC_OK).is_ok()
}

/// Run activation to completion; failed or signalled activation must never reach the system init.
fn activate(system: &Path) -> io::Result<()> {
    let program = system.join("activate");
    let status = Command::new(&program).status().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("cannot run {program}: {error}", program = program.display()),
        )
    })?;
    if !status.success() {
        return Err(io::Error::other(format!("activation failed with {status}")));
    }
    Ok(())
}

/// Prepare the boot environment and hand off without creating a second init process.
fn boot() -> io::Result<()> {
    mounts::basic();

    for directory in [
        "/etc",
        "/nix/var/nix/profiles",
        "/run/qubes",
        "/var/log/qubes",
        "/rw",
        "/home",
        "/usr/local",
    ] {
        if let Err(error) = mkdir(directory, 0o755) {
            log(format_args!("cannot create {directory}: {error}"));
        }
    }
    if let Err(error) = symlink("/run", "/var/run")
        && error.kind() != io::ErrorKind::AlreadyExists
    {
        return Err(io::Error::new(
            error.kind(),
            format!("cannot initialize /var/run: {error}"),
        ));
    }

    let config = BootConfig::parse(&fs::read_to_string("/proc/cmdline")?)?;
    mounts::store(&config)?;
    activate(&config.system)?;

    let init = config.system.join("init");
    let error = Command::new(&init).args(std::env::args_os().skip(1)).exec();
    Err(io::Error::new(
        error.kind(),
        format!("cannot exec {init}: {error}", init = init.display()),
    ))
}

/// Exit only on a failed boot; successful startup replaces this executable with NixOS init.
fn main() -> ExitCode {
    match boot() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            log(error);
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::activate;
    use std::{fs, os::unix::fs::PermissionsExt};

    /// Actual child exit status gates handoff, including a missing activation executable.
    #[test]
    fn activation_requires_success() {
        let temporary = tempfile::tempdir().unwrap();
        let program = temporary.path().join("activate");
        assert!(activate(temporary.path()).is_err());

        for status in [0, 7] {
            fs::write(
                &program,
                format!(
                    r#"#!/bin/sh
exit {status}
"#
                ),
            )
            .unwrap();
            fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).unwrap();
            assert_eq!(activate(temporary.path()).is_ok(), status == 0);
        }
    }
}
