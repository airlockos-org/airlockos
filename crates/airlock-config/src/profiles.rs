//! Named machine definitions assembled from typed VM declarations.

/// VM configuration for the physical USB lab machine.
pub mod usb_lab;

/// Nested QEMU machine for bootstrap and network validation.
pub mod bootstrap;

/// Initial editable controller candidate with the nested machine resource envelope.
pub mod runtime;

/// Interactive QEMU development machine using normal Airlock VM services.
pub mod qemu_lab;
