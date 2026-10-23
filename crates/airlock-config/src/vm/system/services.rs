//! Preserve Qubes startup ordering and initialize private state before accepting RPCs.

use super::{System, strings};
use rusix::{interop::raw::NixValue, nix_record, nix_text};

/// Install upstream service packages and the Airlock ordering needed for writable VM state.
pub(super) fn configuration(system: &System<'_>, nix: &NixValue, programs: &NixValue) -> NixValue {
    let agent = system.package("qubes-core-agent-linux");
    let directories = NixValue::record([
        ("/run/qubes", directory("qubes", "0770")),
        ("/var/log/qubes", directory("qubes", "0770")),
        ("/var/lib/qubes", directory("root", "0755")),
    ]);
    let services = nix_record! {
        "qubes-sysinit": nix_record! {
            "enable": true,
            "wantedBy": strings(&["sysinit.target"]),
            "after": strings(&["systemd-modules-load.service", "qubes-db.service"]),
            "requires": strings(&["qubes-db.service"]),
            "before": strings(&["sysinit.target"]),
            "path": system.qubes_path(),
            "serviceConfig": oneshot().merge_attrs(nix_record! {
                "ExecStart": nix_text!(
                    "{agent}/lib/qubes/init/qubes-sysinit.sh",
                    agent = agent.clone(),
                ),
            }),
            "unitConfig": nix_record! {
                "DefaultDependencies": false,
            },
        },
        "airlock-qubes-db-diagnostics": diagnostic(
            system,
            "Print QubesDB VM diagnostics to the console",
            diagnostics_command(system, "database"),
        ),
        "airlock-qubes-qrexec-diagnostics": diagnostic(
            system,
            "Print qrexec VM diagnostics to the console",
            diagnostics_command(system, "qrexec"),
        ),
        "airlock-qubes-rw-init-diagnostics": diagnostic(
            system,
            "Print Qubes private storage diagnostics to the console",
            diagnostics_command(system, "storage"),
        ),
        "airlock-config-guest-init-diagnostics": system.when(
            system.configuration_role(),
            diagnostic(
                system,
                "Print Airlock configuration VM diagnostics to the console",
                diagnostics_command(system, "configuration"),
            ),
        ),
        "airlock-qubes-rw-init": nix_record! {
            "description": "Initialize Qubes private storage mounts for NixOS VMs",
            "wantedBy": strings(&["multi-user.target"]),
            "wants": strings(&["dev-xvdb.device"]),
            "after": strings(&["dev-xvdb.device", "qubes-sysinit.service"]),
            "requires": strings(&["qubes-sysinit.service"]),
            "before": strings(&[
                "systemd-user-sessions.service",
                "qubes-qrexec-agent.service",
            ]),
            "path": system.qubes_path(),
            "script": airlock_build::native::hook(
                &system.context.pkgs,
                "airlock-private-storage-init",
                crate::commands::contract(
                    &system.context.pkgs,
                    "private-storage-init",
                    [
                        ("agent", agent.clone()),
                        ("bash", system.package("bash")),
                        ("user", system.setting("user")),
                        ("service", system.native()),
                    ],
                ),
            ),
            "serviceConfig": oneshot(),
            "unitConfig": nix_record! {
                "OnFailure": strings(&["airlock-qubes-rw-init-diagnostics.service"]),
            },
        },
        "airlock-config-inputs-mount": system.when(system.imports_inputs(), input_mount(system)),
        // Ordering alone permits login after a failed initialization. Also reobserve live mounts
        // when sessions are enabled, rather than treating RemainAfterExit as persistence evidence.
        "systemd-user-sessions": nix_record! {
            "requires": strings(&["airlock-qubes-rw-init.service"]),
            "after": strings(&["airlock-qubes-rw-init.service"]),
            "serviceConfig": nix_record! {
                "ExecStartPre": nix_text!(
                    "{service}/bin/airlock-vm-service runtime private-storage-check",
                    service = system.native(),
                ),
            },
        },
        "airlock-config-guest-init": system.when(
            system.configuration_role(),
            initialization(system, nix, programs),
        ),
        "airlock-cmd-guest-init": system.when(system.role("cmd"), command_workspace(system)),
        "qubes-db": nix_record! {
            "enable": true,
            "wantedBy": strings(&["sysinit.target"]),
            "after": strings(&[
                "systemd-modules-load.service",
                "systemd-tmpfiles-setup.service",
            ]),
            "requires": strings(&["systemd-tmpfiles-setup.service"]),
            "overrideStrategy": "asDropin",
            "unitConfig": nix_record! {
                "OnFailure": strings(&["airlock-qubes-db-diagnostics.service"]),
            },
        },
        "qubes-qrexec-agent": qrexec(system),
        "qubes-meminfo-writer": nix_record! {
            "enable": true,
            "wantedBy": strings(&["multi-user.target"]),
            "before": strings(&["systemd-user-sessions.service"]),
        },
    };

    nix_record! {
        "systemd": nix_record! {
            "tmpfiles": nix_record! {
                "packages": NixValue::list([agent, system.package("qubes-linux-utils")]),
                "settings": nix_record! {
                    "10-airlock-qubes-guest": directories,
                },
            },
            "packages": NixValue::concat_lists([
                system.packages(&[
                    "qubes-core-qubesdb.daemon",
                    "python3.pkgs.qubes-core-qrexec.domU",
                    "qubes-linux-utils",
                ]),
                system.optional(
                    system.network_provider(),
                    system.packages(&["qubes-vmm-xen"]),
                ),
            ]),
            "services": services,
        },
    }
}

/// Create a root-owned Qubes runtime directory with an explicit access mode.
fn directory(group: &str, mode: &str) -> NixValue {
    nix_record! {
        "d": nix_record! {
            "user": "root",
            "group": group,
            "mode": mode,
        },
    }
}

/// Keep completed initialization services active so dependent units cannot race their setup.
fn oneshot() -> NixValue {
    nix_record! {
        "Type": "oneshot",
        "RemainAfterExit": true,
    }
}

/// Report a failed startup to both the journal and console without restarting privileged services.
fn diagnostic(system: &System<'_>, description: &str, script: NixValue) -> NixValue {
    nix_record! {
        "description": description,
        "path": NixValue::concat_lists([
            system.packages(&[
                "coreutils",
                "findutils",
                "gnugrep",
                "kmod",
                "qubes-core-qubesdb",
            ]),
            NixValue::list([
                system.context.config.clone().select("systemd.package"),
                system.package("util-linux"),
            ]),
        ]),
        "script": script,
        "serviceConfig": nix_record! {
            "Type": "oneshot",
            "StandardOutput": "journal+console",
            "StandardError": "journal+console",
        },
    }
}

/// Expose imported sources only after the persistent private volume is mounted.
fn input_mount(system: &System<'_>) -> NixValue {
    let private = strings(&["airlock-qubes-rw-init.service"]);

    nix_record! {
        "description": "Expose imported Airlock config inputs",
        "wantedBy": strings(&["multi-user.target"]),
        "wants": private.clone(),
        "requires": private.clone(),
        "after": private,
        "before": strings(&[
            "airlock-config-guest-init.service",
            "qubes-qrexec-agent.service",
        ]),
        "path": system.packages(&["coreutils", "gnused", "jq", "util-linux"]),
        "script": airlock_build::native::hook(&system.context.pkgs, "airlock-inputs-mount", crate::commands::contract(&system.context.pkgs, "inputs-mount", [
                ("service", system.native()),
                (
                    "inputsPath",
                    system.setting("configInputsPath"),
                ),
                (
                    "storeRoot",
                    system.setting("configNixStoreRoot"),
                ),
                (
                    "publicInputs",
                    "/etc/airlock/config-inputs".into(),
                ),
            ])),
        "serviceConfig": oneshot(),
    }
}

/// Initialize exactly the configured repository role, as its unprivileged owner.
fn initialization(system: &System<'_>, nix: &NixValue, programs: &NixValue) -> NixValue {
    let mounts = system.optional(
        system.imports_inputs(),
        strings(&["airlock-config-inputs-mount.service"]),
    );
    let private =
        NixValue::concat_lists([strings(&["airlock-qubes-rw-init.service"]), mounts.clone()]);
    let commands = NixValue::record(
        [
            (
                "sys-config-vault",
                ("configVaultInit", "airlock-config-vault-init"),
            ),
            (
                "sys-config-staging",
                ("configStagingInit", "airlock-config-staging-init"),
            ),
            (
                "sys-config-validator",
                ("configValidatorInit", "airlock-config-validator-init"),
            ),
        ]
        .map(|(role, (package, command))| {
            (
                role,
                nix_text!(
                    "{package}/bin/{command}",
                    package = programs.clone().select(package),
                    command = command,
                )
                .into(),
            )
        }),
    );
    let command = commands.attr_or(
        system.setting("role"),
        nix_text!(
            "{coreutils}/bin/true",
            coreutils = system.package("coreutils"),
        ),
    );

    nix_record! {
        "description": "Initialize Airlock config repositories in Qubes private storage",
        "wantedBy": strings(&["multi-user.target"]),
        "wants": private.clone(),
        "requires": private,
        "after": NixValue::concat_lists([
            strings(&["airlock-qubes-rw-init.service", "qubes-db.service"]),
            mounts,
        ]),
        "before": strings(&["qubes-qrexec-agent.service"]),
        "path": system.packages(&["coreutils", "qubes-core-qubesdb", "util-linux"]),
        "script": airlock_build::native::hook(&system.context.pkgs, "airlock-configuration-init", crate::commands::contract(&system.context.pkgs, "configuration-init", [
                ("service", system.native()),
                ("role", system.setting("role")),
                ("utilLinux", system.package("util-linux")),
                ("user", system.setting("user")),
                ("coreutils", system.package("coreutils")),
                (
                    "path",
                    system.role_path(system.setting("role"), nix),
                ),
                ("command", command),
            ])),
        "serviceConfig": oneshot(),
        "unitConfig": nix_record! {
            "OnFailure": strings(&["airlock-config-guest-init-diagnostics.service"]),
        },
    }
}

/// Create persistent command-workspace directories with restricted permissions for Codex state.
fn command_workspace(system: &System<'_>) -> NixValue {
    let directories = system
        .context
        .lib
        .clone()
        .select("concatMapStrings")
        .call(NixValue::function(|path| {
            let mode = NixValue::if_else(
                path.clone().equals(system.setting("codexHome")),
                "0700",
                "0755",
            );

            nix_text!(
                r#"
                install -d -m {mode} -o {user} -g users {path}
            "#,
                mode = mode,
                user = system.quote(system.setting("user")),
                path = system.quote(path),
            )
            .into()
        }))
        .call(system.persistent_paths());
    let script = NixValue::concat_text([
        nix_text!(
            r#"
        set -eu

        install -d -m 0700 -o {user} -g users {store}
    "#,
            user = system.quote(system.setting("user")),
            store = system.quote(system.setting("configNixStoreRoot")),
        )
        .into(),
        directories,
    ]);
    let private = strings(&["airlock-qubes-rw-init.service"]);

    nix_record! {
        "description": "Initialize persistent Airlock command-workspace state",
        "wantedBy": strings(&["multi-user.target"]),
        "wants": private.clone(),
        "requires": private.clone(),
        "after": private,
        "before": strings(&["qubes-qrexec-agent.service"]),
        "path": system.packages(&["coreutils", "util-linux"]),
        "script": script,
        "serviceConfig": oneshot(),
    }
}

/// Start qrexec after role initialization, with the network-provider ordering required by Qubes.
fn qrexec(system: &System<'_>) -> NixValue {
    let initialization = NixValue::concat_lists([
        system.optional(
            system.configuration_role(),
            strings(&["airlock-config-guest-init.service"]),
        ),
        system.optional(
            system.role("cmd"),
            strings(&["airlock-cmd-guest-init.service"]),
        ),
    ]);
    let normal = NixValue::concat_lists([
        strings(&[
            "airlock-qubes-rw-init.service",
            "systemd-user-sessions.service",
        ]),
        initialization.clone(),
    ]);
    let provider = NixValue::concat_lists([
        strings(&["xendriverdomain.service", "airlock-qubes-rw-init.service"]),
        initialization.clone(),
    ]);

    nix_record! {
        "enable": true,
        "wantedBy": strings(&["multi-user.target"]),
        "wants": strings(&["airlock-qubes-rw-init.service"]),
        "requires": NixValue::concat_lists([
            strings(&["airlock-qubes-rw-init.service"]),
            initialization,
        ]),
        "after": NixValue::if_else(
            system.network_provider(),
            system.context.lib.clone().select("mkForce").call(provider),
            normal,
        ),
        "before": system.optional(system.network_provider(), strings(&["network.target"])),
        "aliases": strings(&["qubes-core-agent.service"]),
        "overrideStrategy": "asDropin",
        "unitConfig": nix_record! {
            "OnFailure": strings(&["airlock-qubes-qrexec-diagnostics.service"]),
        },
    }
}

/// Supply local service diagnostics as one native command in the failure unit.
fn diagnostics_command(system: &System<'_>, kind: &str) -> NixValue {
    airlock_build::native::hook(
        &system.context.pkgs,
        "airlock-guest-diagnostics",
        nix_record! {
            "program": nix_text!("{service}/bin/airlock-vm-service", service = system.native()),
            "args": NixValue::list(["diagnostics".into(), kind.into(), "--user".into(), system.setting("user")]),
            "inherit_args": false,
        },
    )
}
