//! Select Cargo inputs without copying every implementation into every package source.

use rusix::{
    interop::{
        NixPath,
        raw::{NixRepresentation, NixValue},
    },
    nix_record,
};

mod inputs;

/// Package sources and compiler feature selection checked together before Nix emission.
/// Its private plan is constructed by the production Verus gate; callers cannot replace its files.
/// Construct it through [`Workspace::package_source`]; the original workspace stays bound to the plan.
///
/// ```compile_fail,E0616
/// use airlock_build::{CheckedPackageSource, Workspace};
/// /// Source emission cannot switch an already checked plan to another workspace.
/// fn substitute(plan: &mut CheckedPackageSource, other: Workspace) { plan.workspace = other; }
/// ```
pub struct CheckedPackageSource {
    // Original symbolic source root; emission cannot substitute a different workspace.
    workspace: Workspace,
    // Original checked source obligations and exact Cargo package/feature request.
    plan: airlock_build_plan::CheckedPackageSource,
}

impl CheckedPackageSource {
    /// Return the verified package/default/feature flags, retaining this plan's original selection.
    pub fn arguments(&self) -> Vec<&str> {
        self.plan.arguments()
    }

    /// Emit only paths selected by the checked plan; optionality is explicit rather than inferred from a filename.
    pub fn source(&self, lib: &NixValue) -> NixValue {
        let files = (0..self.plan.file_count())
            .map(|position| {
                let input = self.plan.file(position).expect("checked source coordinate");
                let path = self.workspace.file(&input.path).as_expression();
                if input.optional {
                    lib.clone().select("fileset.maybeMissing").call(path)
                } else {
                    path
                }
            })
            .collect::<Vec<_>>();
        lib.clone().select("fileset.toSource").call(nix_record! {
            "root": self.workspace.root.clone(),
            "fileset": lib.clone().select("fileset.unions").call(NixValue::list(files)),
        })
    }
}

/// Cargo workspace sources supplied by the caller, including manifests and the shared lockfile.
#[derive(Clone)]
pub struct Workspace {
    /// Symbolic workspace root; generation never captures the developer's checkout path.
    root: NixPath,
}

impl Workspace {
    /// Check one package's source requirements and retain its original compiler feature selection.
    ///
    /// # Panics
    /// Panics for unknown packages/features, unsupported manifest declarations or invalid source requirements.
    pub fn package_source(
        &self,
        package: &str,
        defaults: bool,
        features: &[&str],
    ) -> CheckedPackageSource {
        CheckedPackageSource {
            workspace: self.clone(),
            plan: inputs::checked(package, defaults, features),
        }
    }

    /// Retain an explicit deferred path to the application's Cargo workspace.
    pub fn new(root: NixPath) -> Self {
        Self {
            root: NixPath::from_source_text(root.as_expression().to_text().into_expr::<String>()),
        }
    }

    /// Describe the shared Cargo lock and reviewed Git-source hashes for offline vendoring.
    /// The whole lock is vendored even for Linux-only packages; these hashes do not
    /// admit a Hermit image or change which applications a machine installs.
    pub fn cargo_lock(&self) -> NixValue {
        nix_record! {
            "lockFile": self.file("Cargo.lock").snapshot(),
            "outputHashes": nix_record! {
                // Both Rusix crates share this Git tree, including its pinned Nixpkgs test input.
                "rusix-0.1.1": "sha256-imwt8RWoAlhuKQCCXV5APCA8RPehaxEzOg5/5rPAFk4=",
                // importCargoLock's Git fetch includes the upstream kernel submodule.
                // The Hermit executable builder separately selects our patched kernel.
                "hermit-0.13.2": "sha256-Doox+f2DRDn/J+PBLoiNAMoB9XgW3U3gqysw+mk61lw=",
                "xen-transport-0.1.0": "sha256-QoIsghOb7bYGt3SXzNp4Ww1rkW8klPsIKLMDXY/yX20=",
            },
        }
    }

    /// Return the workspace root for consumers that admit the complete application source.
    pub fn root(&self) -> NixPath {
        self.root.clone()
    }

    /// Resolve an implementation-owned asset without reading or snapshotting the whole tree.
    pub fn file(&self, relative: &str) -> NixPath {
        self.root
            .join_relative(relative)
            .expect("workspace asset path is relative")
    }

    /// Select sources for a package with its default Cargo features enabled.
    /// Keep implementation sources for its local normal/build dependencies and required embedded assets.
    /// Cargo resolution also needs every local manifest and implicit library discovery entry file.
    ///
    /// # Panics
    /// Panics under the same conditions as [`Self::source_with_features`].
    pub fn source(&self, lib: &NixValue, package: &str) -> NixValue {
        self.source_with_features(lib, package, true, &[])
    }

    /// Select a package's local implementation inputs using the same features as its Cargo build.
    /// Resolve optional and transitive local dependencies from embedded Cargo declarations without
    /// invoking Cargo or reading the supplied checkout. Development dependencies are omitted;
    /// target-specific dependencies are conservatively retained for cross builds.
    ///
    /// # Panics
    /// Panics for a package or local path dependency absent from the source inventory,
    /// or for a local dependency inherited from `[workspace.dependencies]`.
    pub fn source_with_features(
        &self,
        lib: &NixValue,
        package: &str,
        default_features: bool,
        features: &[&str],
    ) -> NixValue {
        self.package_source(package, default_features, features)
            .source(lib)
    }
}
