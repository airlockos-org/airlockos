//! Reusable VM contributions connecting typed Airlock configuration to NixOS modules.

pub mod desktop;

pub mod clipboard;

#[path = "machine-source.rs"]
mod machine_source;

#[path = "screen-capture.rs"]
pub mod screen_capture;

/// Connect a designated diagnostic client to declared VM and host evidence.
pub mod diagnostics;
