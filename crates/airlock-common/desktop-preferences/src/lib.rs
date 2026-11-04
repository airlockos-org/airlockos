//! Desktop preferences exported by a GUI domain to its application VMs.
//!
//! A publisher sends one complete [`Snapshot`] when a subscription opens and another
//! whenever effective preferences change. A reset sends the newly effective value;
//! [`Setting::Unsupported`] explicitly removes a previously managed preference.
//! Transport loss is neither a reset nor an unsupported setting: consumers retain
//! their last valid state until a new subscription supplies a complete snapshot.
//!
//! This crate validates data and frames bytes. Callers own Qubes authentication,
//! connection limits, timeouts, GNOME access and local application of preferences.
//! Successful decoding establishes valid preferences, not a trusted sender.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

mod model;
mod wire;

pub use model::{
    ColorScheme, CursorSize, CursorTheme, FontName, ReducedMotion, Setting, Snapshot, TextScale,
    ValueError,
};
pub use wire::{FrameDecoder, FrameError, HEADER_LEN, MAX_FRAME_LEN, VERSION, encode_frame};
