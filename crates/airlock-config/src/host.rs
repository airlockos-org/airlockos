//! Compose the bootstrap host around existing Qubes modules.
//! Evaluated VM descriptors and the kernel package arrive from the existing builders.

use crate::model::{HostSnapshot, MachineSnapshot};
use rusix::interop::{
    PackageFunction,
    raw::{NixRepresentation, NixValue},
};
use rusix::nix_record;

pub(crate) mod physical;

mod diagnostics;

pub(crate) mod nested;

mod store;

mod boot;

mod setup;

mod admission;

mod vbios;

mod gpu;

pub(crate) mod dom0;

pub(crate) mod deployment;

/// Declares the named inputs needed to compose dom0 from evaluated VM descriptors.
#[rusix::args]
mod args {
    use rusix::interop::{NixAttrs, NixPath};

    /// Deferred host inputs supplied after the VM builders have been evaluated.
    #[rusix(root)]
    struct Inputs {
        /// Module-system priority helpers supplied by NixOS.
        lib: NixAttrs,
        /// All materialized VM descriptors, including their real closure paths.
        airlock_config_domains: NixAttrs,
        /// Caller-selected kernel packages, indexed by Qubes kernel name.
        airlock_kernels: NixAttrs,
        /// Existing host and deployment implementation modules.
        airlock_support: NixPath,
        /// Native application workspace used by host deployment services.
        airlock_apps: NixPath,
    }
}

/// Builds the bootstrap host entry point from the snapshot's relationships.
/// The caller supplies evaluated VM descriptors and kernel packages; existing
/// Qubes modules implement setup, policy and deployment from those inputs. Host
/// relationships come from the same finalized snapshot as the VM factories.
pub(crate) fn modules(host: &HostSnapshot, machine: &MachineSnapshot) -> PackageFunction {
    PackageFunction::from_function_attrs(args::argument_names().iter().copied(), |arguments| {
        let inputs = args::from_value(arguments);

        // Keep host defaults overridable through the caller's module-priority helper.
        let default = |value: NixValue| inputs.lib().get("mkDefault").call(value);

        let configuration = nix_record! {
            "imports": NixValue::list([deployment::module(
                &inputs.airlock_support(),
                &airlock_build::Workspace::new(inputs.airlock_apps()),
            )]),
            "airlock": nix_record! {
                "machineDeployment": nix_record! {
                    "enable": true,
                    "profile": "controller-lab",
                },
                "poolAdmission": nix_record! {
                    "enable": default(true.into()),
                    "caller": default(host.controller.as_str().into()),
                    "targets": default(
                        inputs
                            .lib()
                            .get("attrNames")
                            .call(inputs.airlock_config_domains())
                            .as_expression(),
                    ),
                },
                "qubes": nix_record! {
                    "enable": true,
                    "setupConfigOnBoot": nix_record! {
                        "enable": true,
                    },
                    "startNetworkProvidersOnBoot": nix_record! {
                        "enable": true,
                    },
                    "deferredSetupConfigOnBoot": nix_record! {
                        "enable": true,
                    },
                    "configCurrentBootstrapOnBoot": nix_record! {
                        "enable": false,
                    },
                    "prefs": nix_record! {
                        "default_kernel": "",
                        "default_guivm": host.gui.as_str(),
                        "default_netvm": host.network.as_str(),
                    },
                    "templates": nix_record! {},
                    "kernels": inputs.airlock_kernels(),
                    "domains": inputs.airlock_config_domains(),
                    "qrexecPolicy": nix_record! {
                        "rules": NixValue::list([]),
                    },
                    "configAccessPolicy": nix_record! {
                        "enable": false,
                    },
                },
            },
            "virtualisation": nix_record! {
                "diskSize": default(131072_i64.into()),
            },
        };

        let mut modules = vec![nested::vm(true), configuration];
        modules.push(crate::components::clipboard::host_module(
            machine.clipboard_connections(),
            airlock_build::Workspace::new(inputs.airlock_apps()),
        ));
        if let Some(access) = machine.diagnostic_access() {
            modules.push(crate::components::diagnostics::host_module(
                access,
                airlock_build::Workspace::new(inputs.airlock_apps()),
            ));
        }
        let capture_policy = NixValue::function_attrs_open(["pkgs"], |arguments| {
            let package = arguments
                .clone()
                .select("pkgs.writeTextDir")
                .call("etc/qubes/policy.d/45-airlock-screen-capture.policy")
                .call(crate::components::screen_capture::policy(
                    machine.capture_connections(),
                ));
            (
                Vec::<(&str, NixValue)>::new(),
                nix_record! {
                    "virtualisation": nix_record! {
                        "qubes": nix_record! {
                            "packages": NixValue::list([package]),
                        },
                    },
                },
            )
        });
        modules.push(capture_policy);

        (Vec::<(&str, NixValue)>::new(), NixValue::list(modules))
    })
}
