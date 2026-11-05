//! Integration used inside Airlock VMs, including the capture wire format shared with sys-gui.
//! Executable entry points expose only their VM's operations; these helpers carry no dom0 authority.

#![warn(missing_docs)]
#![forbid(unsafe_code)]
pub mod appmenus;

pub mod capture;

pub mod gpu;

pub mod session;

#[cfg(feature = "desktop-preferences")]
pub mod preferences;

pub mod support;

pub mod private_storage;
