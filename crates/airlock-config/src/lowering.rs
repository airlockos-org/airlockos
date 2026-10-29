//! Converts typed VM intent into lazy calls to Airlock's existing Nix builders.

use crate::inputs::args::{self, Inputs};
use crate::model::{GuiDisplay, Label, MachineSnapshot, MiB, Role, Virtualization, VmSnapshot};
use rusix::interop::raw::{NixRepresentation, NixValue};
use rusix::interop::{NixAttrs, NixCallable, NixExpression, PackageFunction};
use rusix::{Expr, IntoRusixValue, nix_record};
use std::collections::BTreeMap;

/// Exact named arguments supplied to `mkNixNativeDomain`, including omitted optional fields.
#[derive(IntoRusixValue)]
pub(crate) struct DomainArguments {
    /// Validated Qubes identity supplied by the machine definition.
    name: String,
    /// Selects the existing VM implementation; personal VMs start from the base role.
    #[rusix(rename = "guestRole")]
    vm_role: &'static str,
    /// Trim optional NixOS conveniences for infrastructure and command VMs.
    minimal: bool,
    /// Existing role modules and separately compiled Rust module contributions.
    modules: Vec<NixValue>,
    /// Size of the small boot filesystem, in the units expected by the builder.
    #[rusix(rename = "rootImageSizeMiB")]
    root_image_size_mi_b: MiB,
    /// Caller-selected kernel identity, retained as a deferred expression.
    kernel_name: Expr<String>,
    /// Qubes label emitted from a Rust enum.
    label: Label,
    /// Null for isolated infrastructure, otherwise the selected network provider.
    netvm: Option<String>,
    /// Qubes preferences, with some values still dependent on Nix arguments.
    prefs: Preferences,
    /// Qubes feature names contain hyphens, so a map preserves their literal spelling.
    features: BTreeMap<String, String>,
    /// Role-specific Qubes service switches.
    services: BTreeMap<&'static str, bool>,
    /// Driver and assistant roles explicitly clear inherited PCI assignments.
    #[rusix(omit_none)]
    devices: Option<NixValue>,
    /// Only roles owning a private volume contribute state settings.
    #[rusix(omit_none)]
    state: Option<State>,
    /// Preserve the GUI factory's explicit configuration identity.
    #[rusix(omit_none)]
    configuration_name: Option<String>,
    /// Supplies the machine source to Rust modules during NixOS import resolution.
    #[rusix(omit_none)]
    extra_special_args: Option<NixValue>,
}

/// Persistent-volume settings included only for roles that own writable state.
#[derive(IntoRusixValue)]
struct State {
    /// Qubes consumes private-volume capacity as bytes rather than MiB.
    persistent_size: i64,
}

/// Qubes runtime preferences passed through the existing builder.
/// Their keys use snake_case, unlike the builder's own named arguments.
#[derive(IntoRusixValue)]
#[rusix(rename_all = "preserve")]
struct Preferences {
    /// Firewall debug mode changes this only when the generated Nix is evaluated.
    autostart: Expr<bool>,
    /// Omission inherits the host default; a Nix null explicitly disables a GUI.
    #[rusix(omit_none)]
    guivm: Option<NixValue>,
    /// Physical displays do not use an audio VM; other roles retain builder defaults.
    #[rusix(omit_none)]
    audiovm: Option<NixValue>,
    /// Preserve each default role's inclusion in Qubes backups.
    include_in_backups: bool,
    /// Memory allocated at boot, in MiB.
    memory: MiB,
    /// Upper memory allocation, in MiB.
    maxmem: MiB,
    /// Virtual CPUs exposed to this VM.
    vcpus: u16,
    /// Only network roles publish Qubes networking to downstream VMs.
    #[rusix(omit_none)]
    provides_network: Option<bool>,
    /// Driver selects HVM; assistant explicitly resets its former HVM setting to PVH.
    #[rusix(omit_none)]
    virt_mode: Option<Virtualization>,
}

/// Build target-system factories indexed by validated VM identity.
/// Only a finalized snapshot is accepted; Nix evaluates package and image dependencies lazily.
pub(crate) fn builders(machine: &MachineSnapshot) -> PackageFunction {
    PackageFunction::from_function_attrs(args::argument_names().iter().copied(), |arguments| {
        let inputs = args::from_value(arguments);
        let factories = machine.vms().map(|vm| {
            let export = vm.name.to_string();

            // Defer target-system selection and image construction to the Nix caller.
            let factory = NixCallable::<NixAttrs, Expr<String>>::from_function(|system| {
                inputs
                    .mk_airlock_qube_builders()
                    .call(system)
                    .bind(|builders| match vm.backend {
                        crate::model::GuestBackend::Nixos => builders
                            .mk_nix_native_domain()
                            .try_call(domain(&inputs, vm))
                            .expect("statically structured domain arguments"),
                        crate::model::GuestBackend::Hermit { .. } => {
                            builders.mk_hermit_domain().call(nix_record! {
                                "name": vm.name.as_str(),
                                "memory": i64::from(vm.settings.memory.bounds().0.0),
                                "vcpus": i64::from(vm.settings.vcpus),
                                "autostart": vm.settings.autostart.unwrap_or(false),
                                "clipboardAuthority": vm.features.get("airlock-clipboard-authority").map_or_else(NixValue::null, |name| name.as_str().into()),
                            })
                        }
                    })
            });

            (export, factory.as_expression())
        });

        (
            vec![
                ("networkDebug", false.into()),
                ("modulesDirectory", NixValue::null()),
                ("userModulesDirectory", NixValue::null()),
                ("airlockApps", NixValue::null()),
                ("extraVmSpecialArgs", nix_record! {}),
            ],
            NixAttrs::new(factories).as_expression(),
        )
    })
}

/// Translates one VM into the existing builder's role, resource and module arguments.
/// Preserves omitted versus explicit-null preferences and module order so the
/// Rust-authored definition retains the original Nix behavior and derivation identity.
pub(crate) fn domain(inputs: &Inputs, vm: &VmSnapshot) -> DomainArguments {
    let role = &vm.role;
    let name = vm.name.to_string();
    let (memory, maxmem) = vm.settings.memory.bounds();
    let mut features = BTreeMap::from([("airlock-managed", "1"), ("airlock-role", name.as_str())]);
    let mut services = BTreeMap::from([("network-manager", false)]);

    let (vm_role, autostart, virtualization) = match role {
        Role::Service | Role::Isolated { .. } => ("base", false.into(), Virtualization::Pvh),
        Role::NetworkDriver { .. } => {
            features.insert("airlock-boot-foreground", "1");
            features.insert("airlock-auto-network-pci", "1");
            features.insert("airlock-network-provider", name.as_str());
            services.insert("network-manager", true);
            ("sys-net", true.into(), Virtualization::Hvm)
        }
        Role::Firewall { .. } => {
            features.insert("airlock-boot-foreground", "1");
            features.insert("airlock-network-provider", name.as_str());
            features.insert("servicevm", "1");
            ("sys-firewall", !inputs.network_debug(), Virtualization::Pvh)
        }
        Role::Personal { .. } => {
            features.insert("airlock-boot-foreground", "1");
            features.insert("airlock-label-color", "0x6b7a3d");
            features.insert("airlock-gui-reconnect", "1");
            features.insert("menu-items", "*");
            ("base", true.into(), Virtualization::Pvh)
        }
        Role::Gui {
            display: GuiDisplay::PhysicalAmd,
            ..
        } => {
            features = BTreeMap::from([("video-model", "none"), ("airlock-role", "sys-gui")]);
            services = BTreeMap::from([("guivm", true), ("guivm-gui-agent", false)]);
            ("sys-gui", false.into(), Virtualization::Hvm)
        }
        Role::Gui { .. } => {
            features.extend([
                ("gui", "1"),
                ("gui-allow-fullscreen", "1"),
                ("servicevm", "1"),
            ]);
            services.extend([("guivm", true), ("guivm-gui-agent", true)]);
            ("sys-gui", true.into(), Virtualization::Pvh)
        }
        // Background boot starts the controller after the assistant is ready.
        Role::Controller { .. } => ("sys-ctrl", true.into(), Virtualization::Pvh),
        Role::Assistant { .. } => {
            features.extend([
                ("airlock-label-color", "0xd3d3d3"),
                ("airlock-gui-reconnect", "1"),
                ("menu-items", "*"),
                ("airlock-auto-network-pci", "0"),
                ("airlock-network-provider", "0"),
            ]);
            services.extend([("qubes-firewall", false), ("qubes-network", false)]);
            ("usr-assistant", true.into(), Virtualization::Pvh)
        }
        Role::Command { .. } => {
            features.insert("airlock-role", "cmd");
            ("cmd", false.into(), Virtualization::Pvh)
        }
    };

    features.extend(
        vm.features
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
    );

    let provider = matches!(role, Role::NetworkDriver { .. } | Role::Firewall { .. });
    if provider {
        services.extend([
            ("qubes-firewall", true),
            ("qubes-network", true),
            ("qubes-updates-proxy", true),
        ]);
    }

    let physical_gui = matches!(
        role,
        Role::Gui {
            display: GuiDisplay::PhysicalAmd,
            ..
        }
    );
    let mut modules = if physical_gui {
        crate::vm_modules::physical_gui(inputs, vm)
    } else {
        vec![crate::vm_modules::inline(inputs, vm).as_expression()]
    };
    // Physical display settings follow GNOME so package ordering matches the machine.
    let physical_settings = if physical_gui { modules.pop() } else { None };

    if matches!(role, Role::Personal { .. }) {
        modules.push(crate::vm::personal());
    }

    if matches!(role, Role::Controller { .. }) {
        modules.push(crate::vm::application_gui());
        modules.extend(crate::vm::worker_modules(crate::vm::WorkerRole::Controller));
    }

    if matches!(role, Role::Assistant { .. }) {
        modules.push(crate::vm::development());
    }

    if !vm.modules.is_empty() {
        modules.push(
            inputs
                .modules_directory()
                .join_relative(&format!("{name}.nix", name = vm.name))
                .expect("validated VM module name")
                .as_expression(),
        );
    }

    modules.extend(physical_settings);
    modules.push(user_configuration(inputs, &name));

    DomainArguments {
        name: name.clone(),
        vm_role,
        minimal: !matches!(role, Role::Personal { .. }),
        modules,
        root_image_size_mi_b: vm.settings.root_image,
        kernel_name: inputs.airlock_qubes_vm_kernel_name(),
        label: vm.settings.label,
        netvm: role.uplink().map(|provider| provider.to_string()),
        prefs: Preferences {
            autostart: vm.settings.autostart.map_or(autostart, Into::into),
            guivm: reference_value(&vm.guivm),
            audiovm: physical_gui.then(NixValue::null),
            include_in_backups: true,
            memory,
            maxmem,
            vcpus: vm.settings.vcpus,
            provides_network: if matches!(role, Role::Assistant { .. }) {
                Some(false)
            } else {
                provider.then_some(true)
            },
            virt_mode: match virtualization {
                Virtualization::Hvm => Some(Virtualization::Hvm),
                Virtualization::Pvh => {
                    matches!(role, Role::Assistant { .. }).then_some(Virtualization::Pvh)
                }
            },
        },
        features: features
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect(),
        services,
        devices: (physical_gui
            || matches!(role, Role::NetworkDriver { .. } | Role::Assistant { .. }))
        .then(|| {
            nix_record! {
                "pci": NixValue::list([]),
            }
        }),
        state: role.private_volume().map(|size| State {
            persistent_size: size.bytes(),
        }),
        configuration_name: matches!(role, Role::Gui { .. }).then(|| {
            if physical_gui {
                format!("airlock-domain-{name}-usb-gui-lab")
            } else {
                format!("airlock-domain-{name}")
            }
        }),
        extra_special_args: {
            let worker = matches!(role, Role::Controller { .. } | Role::Assistant { .. });
            let additions = !vm.modules.is_empty();

            (worker || additions).then(|| {
                let arguments = if worker {
                    inputs.extra_vm_special_args().as_expression()
                } else {
                    nix_record! {}
                };

                if additions {
                    arguments.merge_attrs(nix_record! {
                        "airlockSupport": inputs.airlock_support(),
                    })
                } else {
                    arguments
                }
            })
        },
    }
}

/// Import the VM's optional user module through ordinary NixOS module merging.
/// The path remains a Nix input: Rust never reads or embeds the module contents.
pub(crate) fn user_configuration(inputs: &Inputs, name: &str) -> NixValue {
    let directory = inputs.user_modules_directory();
    let path = directory
        .join_relative(&format!("{name}.nix"))
        .expect("validated VM name");
    let imports = NixValue::if_else(
        directory.as_expression().equals(NixValue::null()),
        NixValue::list([]),
        NixValue::if_else(
            NixValue::builtin("pathExists").call(path.clone()),
            NixValue::list([path.as_expression()]),
            NixValue::list([]),
        ),
    );
    nix_record! { "imports": imports }
}

/// Preserve the common reference type's omission, null, empty and named Nix values.
fn reference_value(reference: &airlock_machine_core::model::VmReference) -> Option<NixValue> {
    use airlock_machine_core::model::VmReference;

    match reference {
        VmReference::Inherit => None,
        VmReference::Disabled => Some(NixValue::null()),
        VmReference::Empty => Some("".into()),
        VmReference::Named(name) => Some(name.as_str().into()),
    }
}
