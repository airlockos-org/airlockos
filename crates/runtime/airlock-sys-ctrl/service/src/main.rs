//! Sys-ctrl owns source review, detached builds and deployment handoff.
//! Dom0 remains the authority for protected approval and activation.

#![forbid(unsafe_code)]

mod build;

mod controller;

mod process;

mod records;

mod upload;

use airlock_nix_core::runtime::{
    Error, Result, decode, emit, home, now, protocol, report, require,
};

fn main() -> std::process::ExitCode {
    controller::main()
}
