//! Describe the GUI service's commands and, with `authoring`, its deployable package.
//! Runtime execution stays in the binary; machine composition grants its VM permissions.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub mod command;

#[cfg(feature = "authoring")]
pub mod authoring;
