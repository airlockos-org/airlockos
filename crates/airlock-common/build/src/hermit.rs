//! The two native executables share one packaging pipeline. This source list is
//! also used when Cargo regenerates their locks, so preparation cannot drift from
//! the workspace actually compiled by the immutable image builder.

/// One production application, excluding fixtures and workstation transports.
#[derive(Clone, Copy)]
pub struct Source {
    /// Artifact profile selected by the typed machine definition.
    pub profile: &'static str,
    /// Production binary; the package name is this value prefixed with airlock-.
    pub binary: &'static str,
    /// Local Cargo members copied into the bounded application workspace.
    pub members: &'static [&'static str],
    /// Reviewed fixed-output hash of its kernel/stdlib/application dependency catalog.
    pub vendor_hash: &'static str,
}

/// Explicit source selections shared by build authoring and Cargo lock preparation.
pub const APPLICATIONS: [Source; 2] = [
    Source {
        profile: "clipboard",
        binary: "sys-clipboard",
        members: &[
            "airlock-common/bounded-heap",
            "airlock-common/boot",
            "airlock-common/clipboard",
            "runtime/airlock-sys-clipboard",
        ],
        vendor_hash: "sha256-f05LS5ZwBQpTJoWNKQRclyCk0+6VaRlT8/qcLUu95+c=",
    },
    Source {
        profile: "firewall",
        binary: "sys-firewall",
        members: &[
            "airlock-common/bounded-heap",
            "airlock-common/boot",
            "airlock-common/qubesdb",
            "airlock-common/qubes-network",
            "airlock-common/firewall",
            "runtime/airlock-hermit-control",
            "runtime/airlock-sys-firewall",
        ],
        vendor_hash: "sha256-Dr/n09ZQJUwrMVfDnXsqQJLxSYDGlhxkDZMRkk2iL5o=",
    },
];
