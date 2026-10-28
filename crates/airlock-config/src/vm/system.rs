//! Assemble the Qubes VM lifecycle, private storage and role-specific service contracts.
//! Upstream Qubes remains responsible for Xen communication and qrexec execution.

mod options;

mod rpc;

mod services;

use super::{configuration, gui, network, private_store};
use airlock_build::{Application, Workspace};
use rusix::{
    interop::{
        NixExpression, NixPath,
        raw::{NixRepresentation, NixValue},
    },
    nix_record,
    nixos::{ContextualModule, ModuleBody, ModuleContext},
};

/// NixOS evaluation context and the application workspace used by VM services.
struct System<'a> {
    /// This VM's final package set, library and merged settings.
    context: &'a ModuleContext,
    /// Native application sources used to build VM integration commands.
    workspace: &'a Workspace,
}

/// Construct one VM's userspace from captured machine and application sources.
pub(super) fn module(source: &NixPath, workspace: &Workspace) -> NixValue {
    ContextualModule::new(|context| {
        let system = System {
            context: &context,
            workspace,
        };
        let network = network::Packages {
            qubes_path: system.qubes_path(),
            python: system.python(),
            provider_packages: system.network_packages(),
        };
        let configuration = system.configuration();

        ModuleBody::new(system.when(system.setting("enable"), configuration))
            .key("airlock.vm.system")
            .import_value(options::module())
            .import_value(network::module(&network))
            .import_value(gui::module(source, workspace))
            .import_value(super::authoring::module(source, workspace))
    })
    .into_expression()
}

impl System<'_> {
    /// Build the local native guest adapter with the captured application workspace.
    fn native(&self) -> NixValue {
        Application::VmService
            .build(&self.context.pkgs, self.workspace)
            .as_expression()
    }

    /// Select the target system's package, preserving its overlays and platform.
    fn package(&self, name: &str) -> NixValue {
        self.context.pkgs.clone().select(name)
    }

    /// Collect target packages in their declared search order.
    fn packages(&self, names: &[&str]) -> NixValue {
        NixValue::list(names.iter().map(|name| self.package(name)))
    }

    /// Read a merged VM setting supplied by the machine's composition.
    fn setting(&self, name: &str) -> NixValue {
        self.context
            .config
            .clone()
            .select("airlock.qubeGuest")
            .select(name)
    }

    /// Identify an enabled role without comparing a machine's VM name.
    fn role(&self, role: &str) -> NixValue {
        self.setting("role").equals(role)
    }

    /// Select a capability shared by several role implementations.
    fn roles(&self, roles: &[&str]) -> NixValue {
        NixValue::builtin("elem")
            .call(self.setting("role"))
            .call(NixValue::list(roles.iter().map(|role| (*role).into())))
    }

    /// Delay a conditional definition until NixOS evaluates its option values.
    fn when(&self, condition: NixValue, value: NixValue) -> NixValue {
        self.context
            .lib
            .clone()
            .select("mkIf")
            .call(condition)
            .call(value)
    }

    /// Supply an ordinary overrideable default to the surrounding machine.
    fn default(&self, value: impl Into<NixValue>) -> NixValue {
        self.context
            .lib
            .clone()
            .select("mkDefault")
            .call(value.into())
    }

    /// Quote one complete shell argument while retaining store dependencies.
    fn quote(&self, value: NixValue) -> NixValue {
        self.context
            .lib
            .clone()
            .select("escapeShellArg")
            .call(value)
    }

    /// Build an executable search path with the caller's library.
    fn bin_path(&self, packages: NixValue) -> NixValue {
        self.context
            .lib
            .clone()
            .select("makeBinPath")
            .call(packages)
    }

    /// Include a list only when the role has the required capability.
    fn optional(&self, condition: NixValue, values: NixValue) -> NixValue {
        NixValue::if_else(condition, values, NixValue::list([]))
    }

    /// Identify configuration roles whose repositories need initialization before qrexec starts.
    fn configuration_role(&self) -> NixValue {
        self.roles(&[
            "sys-config-vault",
            "sys-config-staging",
            "sys-config-validator",
        ])
    }

    /// Identify roles that receive offline inputs through a separate root-owned import RPC.
    fn imports_inputs(&self) -> NixValue {
        self.roles(&["sys-config-staging", "sys-config-validator"])
    }

    /// Identify VMs providing Xen network backends and firewall services.
    fn network_provider(&self) -> NixValue {
        self.roles(&["sys-net", "sys-firewall"])
    }

    /// Keep Qubes' startup tools on the same systemd package as the selected NixOS system.
    fn qubes_path(&self) -> NixValue {
        NixValue::concat_lists([
            self.packages(&[
                "coreutils",
                "diffutils",
                "e2fsprogs",
                "findutils",
                "gawk",
                "glibc.bin",
                "gnugrep",
                "kmod",
                "qubes-core-qubesdb",
                "qubes-linux-utils",
            ]),
            NixValue::list([
                self.context.config.clone().select("systemd.package"),
                self.package("util-linux"),
            ]),
        ])
    }

    /// Supply upstream forwarding, firewall and proxy commands in their established order.
    fn network_packages(&self) -> NixValue {
        self.packages(&[
            "conntrack-tools",
            "iproute2",
            "iptables",
            "networkmanager",
            "nftables",
            "procps",
            "qubes-vmm-xen",
            "tinyproxy",
        ])
    }

    /// Supply upstream RPC and network programs with the QubesDB Python bindings.
    fn python(&self) -> NixValue {
        let database = self
            .package("qubes-core-qubesdb")
            .override_args(nix_record! {
                "withPython": true,
                "python": self.package("python3"),
            })
            .select("pythonModule");

        self.package("python3.withPackages")
            .call(NixValue::function(|packages| {
                NixValue::list([
                    packages.clone().select("dbus-python"),
                    packages.clone().select("pygobject3"),
                    packages.select("pyxdg"),
                    database,
                ])
            }))
    }

    /// Share the store wrapper and configuration programs between boot services and RPC handlers.
    fn configuration(&self) -> NixValue {
        let nix = private_store::package(
            &self.context.lib,
            &self.context.pkgs,
            &self.context.config.clone().select("airlock.qubeGuest"),
        );

        nix.bind(|nix| {
            let seed = super::seed::configuration(self.workspace);
            let programs = configuration::constructor()
                .as_expression()
                .call(nix_record! {
                    "pkgs": self.context.pkgs.clone(),
                    "lib": self.context.lib.clone(),
                    "settings": self.context.config.clone().select("airlock.qubeGuest"),
                    "nix": nix.clone(),
                    "seed": seed,
                    "publicInputs": "/etc/airlock/config-inputs",
                    "stagingPath": self.role_path("sys-config-staging".into(), &nix),
                });

            programs.bind(|programs| {
                self.context
                    .lib
                    .clone()
                    .select("mkMerge")
                    .call(NixValue::list([
                        self.base(),
                        services::configuration(self, &nix, &programs),
                        rpc::configuration(self, &programs),
                        self.environment(&nix, &programs),
                    ]))
            })
        })
    }

    /// Supply initialization commands independently of the ambient qrexec environment.
    fn role_path(&self, role: NixValue, nix: &NixValue) -> NixValue {
        let uses_nix = NixValue::builtin("elem").call(role).call(NixValue::list(
            [
                "sys-config-vault",
                "sys-config-staging",
                "sys-config-validator",
                "cmd",
            ]
            .map(Into::into),
        ));

        self.bin_path(NixValue::concat_lists([
            self.packages(&[
                "coreutils",
                "gawk",
                "gitMinimal",
                "gnutar",
                "jq",
                "qubes-core-qubesdb",
                "util-linux",
            ]),
            self.optional(
                uses_nix,
                NixValue::concat_lists([
                    NixValue::list([nix.clone(), self.package("nix")]),
                    self.packages(&[
                        "cargo",
                        "rustc",
                        "stdenv.cc",
                        "pkg-config",
                        "gnumake",
                        "gnused",
                    ]),
                ]),
            ),
        ]))
    }

    /// Combine explicit workspace directories with Codex state while avoiding duplicate operations.
    fn persistent_paths(&self) -> NixValue {
        self.context
            .lib
            .clone()
            .select("unique")
            .call(NixValue::concat_lists([
                self.setting("cmdPersistentPaths"),
                NixValue::list([self.setting("codexHome")]),
            ]))
    }

    /// Assert private-state boundaries and install the Xen boot and unprivileged user baseline.
    fn base(&self) -> NixValue {
        let mut assertions = vec![nix_record! {
            "assertion": self.setting("user").equals("").equals(false),
            "message": "The primary VM user must not be empty.",
        }];
        for (setting, prefix) in [
            ("configRepoPath", "/home/"),
            ("configValidationPath", "/home/"),
            ("configArchivePath", "/home/"),
            ("configNixStoreRoot", "/rw/"),
            ("configInputsPath", "/rw/"),
            ("codexHome", "/home/"),
        ] {
            assertions.push(nix_record! {
                "assertion": self
                    .context
                    .lib
                    .clone()
                    .select("hasPrefix")
                    .call(prefix)
                    .call(self.setting(setting)),
                "message": format!("VM {setting} must live under {prefix} for private storage."),
            });
        }
        assertions.push(nix_record! {
            "assertion": self
                .context
                .lib
                .clone()
                .select("all")
                .call(self.context.lib.clone().select("hasPrefix").call("/home/"))
                .call(self.persistent_paths()),
            "message": "Command workspace directories must live under /home/ for private storage.",
        });

        nix_record! {
            "assertions": NixValue::list(assertions),
            "airlock": nix_record! {
                "sysGuiGuest": nix_record! {
                    "enable": self.role("sys-gui"),
                },
            },
            "boot": nix_record! {
                "loader": nix_record! {
                    "grub": nix_record! {
                        "enable": false,
                    },
                },
                "initrd": nix_record! {
                    "systemd": nix_record! {
                        "enable": self.default(true),
                    },
                    "availableKernelModules": strings(&[
                        "xen-blkfront",
                        "xen-fbfront",
                        "xen-kbdfront",
                        "xen-netfront",
                        "xen-pcifront",
                        "xen-scsifront",
                        "xen-tpmfront",
                    ]),
                    "kernelModules": strings(&["xen-blkfront", "xen-netfront", "dm_mod", "dm_snapshot"]),
                },
                "kernelModules": NixValue::concat_lists([
                    strings(&["xen-evtchn", "xen-gntalloc", "xen-gntdev", "xen-privcmd"]),
                    self.optional(self.network_provider(), strings(&["xen-netback"])),
                ]),
                "kernelParams": strings(&["console=hvc0"]),
            },
            "fileSystems": nix_record! {
                "/": nix_record! {
                    "device": "/dev/mapper/dmroot",
                    "fsType": "ext4",
                },
            },
            "networking": nix_record! {
                "hostName": self.default("airlock-qube"),
            },
            "users": nix_record! {
                "mutableUsers": self.default(false),
                "allowNoPasswordLogin": self.default(true),
                "groups": nix_record! {
                    "qubes": nix_record! {},
                },
                "users": NixValue::builtin("listToAttrs").call(NixValue::list([nix_record! {
                    "name": self.setting("user"),
                    "value": nix_record! {
                        "isNormalUser": true,
                        "group": "users",
                        "extraGroups": strings(&["qubes"]),
                    },
                }])),
            },
            "security": nix_record! {
                "pam": nix_record! {
                    "services": nix_record! {
                        "qrexec": nix_record! {
                            "rootOK": true,
                            "startSession": true,
                            "setLoginUid": false,
                        },
                    },
                },
            },
            "services": nix_record! {
                "timesyncd": nix_record! {
                    "enable": false,
                },
            },
            "system": nix_record! {
                "stateVersion": "26.05",
            },
        }
    }

    /// Install packages and Nix capabilities according to the declared role.
    fn environment(&self, nix: &NixValue, programs: &NixValue) -> NixValue {
        let private_nix = self.context.lib.clone().select("hiPrio").call(nix.clone());
        let role = self.setting("role");
        let mut roles = vec![
            ("base", NixValue::list([])),
            ("sys-net", self.network_packages()),
            ("sys-firewall", self.network_packages()),
            ("usr-assistant", NixValue::list([private_nix.clone()])),
            (
                "sys-ctrl",
                NixValue::list([
                    private_nix.clone(),
                    self.package("gitMinimal"),
                    self.package("jq"),
                ]),
            ),
        ];
        for (role, names) in [
            (
                "sys-config-vault",
                &[
                    "configVaultInit",
                    "configVaultArchiveCandidate",
                    "configVaultArchiveDeployment",
                    "configVaultExportCurrent",
                ][..],
            ),
            (
                "sys-config-staging",
                &[
                    "configStagingExportCandidate",
                    "configStagingImportCurrent",
                    "configStagingInit",
                    "configStagingValidate",
                ][..],
            ),
            (
                "sys-config-validator",
                &["configValidatorValidateCandidate", "configValidatorInit"][..],
            ),
        ] {
            roles.push((
                role,
                NixValue::concat_lists([
                    NixValue::list(names.iter().map(|name| programs.clone().select(name))),
                    NixValue::list([private_nix.clone()]),
                    self.packages(&["gawk", "gitMinimal", "gnutar", "jq"]),
                ]),
            ));
        }
        roles.push((
            "cmd",
            NixValue::concat_lists([
                NixValue::list([private_nix]),
                self.packages(&[
                    "bashInteractive",
                    "cacert",
                    "cargo",
                    "clippy",
                    "codex",
                    "diffutils",
                    "fd",
                    "file",
                    "findutils",
                    "gawk",
                    "git",
                    "gnugrep",
                    "gnumake",
                    "gnused",
                    "gnutar",
                    "gzip",
                    "jq",
                    "less",
                    "openssh",
                    "procps",
                    "python3",
                    "ripgrep",
                    "rustc",
                    "uv",
                    "vim",
                    "which",
                    "xz",
                    "zellij",
                ]),
            ]),
        ));

        nix_record! {
            "environment": nix_record! {
                "systemPackages": NixValue::concat_lists([
                    NixValue::list([self.native()]),
                    self.packages(&[
                        "qubes-core-qubesdb",
                        "qubes-core-agent-linux",
                        "qubes-linux-utils",
                        "python3.pkgs.qubes-core-qrexec",
                        "python3.pkgs.qubes-core-qrexec.domU",
                    ]),
                    NixValue::record(roles).attr_or(role, NixValue::list([])),
                ]),
                "sessionVariables": self.when(
                    self.role("cmd"),
                    nix_record! {
                        "CODEX_HOME": self.setting("codexHome"),
                    },
                ),
            },
            "nix": nix_record! {
                "settings": self.when(
                    self.roles(&[
                        "sys-config-vault",
                        "sys-config-staging",
                        "sys-config-validator",
                        "cmd",
                        "usr-assistant",
                        "sys-ctrl",
                    ]),
                    nix_record! {
                        "allowed-users": NixValue::list([self.setting("user")]),
                        "experimental-features": strings(&["nix-command", "flakes"]),
                    },
                ),
            },
        }
    }
}

/// Preserve declaration order for static systemd dependencies and kernel-module lists.
fn strings(values: &[&str]) -> NixValue {
    NixValue::list(values.iter().map(|value| (*value).into()))
}
