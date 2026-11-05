//! Reviewed Git source identities shared by offline vendoring and crate graph generation.

/// A complete Git tree whose hash covers all crates supplied by that repository.
pub struct GitSource {
    /// Cargo source-replacement alias, shared with the installed authoring configuration.
    pub alias: &'static str,
    /// Cargo's repository URL, without its git+ prefix or revision query.
    pub repository: &'static str,
    /// Exact committed tree selected by the Cargo lockfile.
    pub revision: &'static str,
    /// Nix recursive source hash, including the source's required submodules.
    pub hash: &'static str,
}

/// Source hashes already reviewed for Airlock's application workspace.
/// Adding a new Git source requires recording its exact revision and tree hash.
pub const SOURCES: &[GitSource] = &[
    GitSource {
        alias: "rusix",
        repository: "https://github.com/rndhouse/rusix",
        revision: "36e989e8acfa292066363f04b449a1722efbb196",
        hash: "sha256-imwt8RWoAlhuKQCCXV5APCA8RPehaxEzOg5/5rPAFk4=",
    },
    GitSource {
        alias: "hermit",
        repository: "https://github.com/hermit-os/hermit-rs",
        revision: "e9dc6784ad1a2dc6d18c6819ee51198cab9fb78a",
        hash: "sha256-Doox+f2DRDn/J+PBLoiNAMoB9XgW3U3gqysw+mk61lw=",
    },
    GitSource {
        alias: "xen-transport",
        repository: "https://github.com/airlockos-org/hermit-xen",
        revision: "3e7fa593380e8044c73e2a3cadc8a9f58775e91e",
        hash: "sha256-hl+CC4ZdgsD0VrysjQ9GGkVTm5+cP6Bd+iVtU8x9HXc=",
    },
];
