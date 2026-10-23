//! Construct Airlock packages with explicit source trees and caller-owned package sets.
//! Source selection keeps unrelated runtime implementations out of application rebuilds.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

mod applications;

pub mod desktop;

pub mod adapters;

pub mod tools;

pub mod upstream;

pub mod overlays;

pub mod vm;

pub mod store;

pub mod script;

pub mod native;

mod workspace;

pub use applications::Application;

pub use workspace::{CheckedPackageSource, Workspace};
