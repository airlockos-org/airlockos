//! Installation media carries a prepared machine onto a removable disk. These
//! commands validate its offline build inputs, prepare Qubes state and provision USBs.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

mod acceptance;

mod boot_filesystem;

mod preflight;

pub mod provisioning;

#[cfg(feature = "qubes")]
mod runtime;

mod support;

mod usb;

#[cfg(test)]
mod regression;

use std::process::ExitCode;

fn report(operation: &str, result: anyhow::Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{operation}: {error:#}");
            ExitCode::FAILURE
        }
    }
}

/// Parse USB command arguments and perform the explicitly selected operation.
/// Inspection is read-only; writing requires an exact serial and image digest.
pub fn usb_main() -> ExitCode {
    report("airlock-usb", usb::main())
}

/// Check that image inputs can build small configuration changes without a network.
/// A supplied image command runs only after passing evidence has been established.
pub fn check_main() -> ExitCode {
    report("airlock-image-check", acceptance::main())
}

/// Prepare initial Qubes state in a new output directory using its offline API.
/// Physical device assignments remain deferred until the installed machine boots.
#[cfg(feature = "qubes")]
pub fn runtime_main() -> ExitCode {
    report("airlock-prepare-runtime", runtime::main())
}

/// Prepare build-directory boot filesystems or closure manifests without provisioning devices.
pub fn boot_main() -> ExitCode {
    report("airlock-prepare-boot", boot_filesystem::main())
}
