//! Declare source and builder dependencies deferred until the machine is evaluated.

/// Declares the named Nix arguments and typed projections used by VM lowering.
#[rusix::args]
pub(crate) mod args {
    use rusix::interop::{NixAttrs, NixCallable, NixPath};

    /// Caller-provided roots of the deferred Nix expressions used by VM factories.
    #[rusix(root)]
    struct Inputs {
        /// The caller's library, including any custom module-priority helpers.
        lib: Library,
        /// Existing factory, applied lazily for the system requested by the Nix caller.
        mk_airlock_qube_builders: NixCallable<Builders, rusix::Expr<String>>,
        /// Qubes VM kernel selected by the caller; never frozen during Rust generation.
        airlock_qubes_vm_kernel_name: String,
        /// Machine repository containing the existing role implementation modules.
        airlock_support: NixPath,
        /// Disables automatic network startup for the original debugging workflow.
        network_debug: bool,
        /// Directory containing the separately compiled Rust-authored VM modules.
        modules_directory: NixPath,
        /// Source of the existing controller and CLI packages.
        airlock_apps: NixPath,
        /// Build-worker inputs forwarded to controller and assistant systems.
        extra_vm_special_args: NixAttrs,
    }

    /// Module-priority and conditional helpers projected from the caller's library.
    struct Library {
        /// Gives a module definition priority over ordinary downstream definitions.
        mk_force: NixCallable,
        /// Provides overridable controller display defaults.
        mk_default: NixCallable,
        /// Includes debug-only VM definitions without forcing the excluded branch.
        optional_attrs: NixCallable<NixCallable<NixAttrs>, rusix::Expr<bool>>,
    }

    /// Builder functions returned after selecting the requested target system.
    #[rusix(value)]
    struct Builders {
        /// Native VM closure/image constructor exported through Rusix.
        mk_nix_native_domain: NixCallable<NixAttrs>,
        /// Native Hermit PVH executable constructor.
        mk_hermit_domain: NixCallable<NixAttrs>,
    }
}
