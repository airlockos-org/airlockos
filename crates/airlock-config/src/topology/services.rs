//! Order topology setup, mutable Qubes policy and configuration bootstrap at host startup.

use airlock_build::tools::Tool;
use rusix::{interop::raw::NixValue, nix_record, nix_text, nixos::ModuleContext};

/// Preserve the boot milestones that precede VM startup and configuration transport.
pub(super) fn configuration(context: &ModuleContext, cfg: &NixValue, tools: &NixValue) -> NixValue {
    let common = strings(&[
        "libvirtd.service",
        "qubes-db-dom0.service",
        "qubesd.service",
        "qubes-qrexec-policy-daemon.service",
    ]);
    let setup = cfg.clone().select("setupConfigOnBoot");
    let providers = cfg.clone().select("startNetworkProvidersOnBoot");
    let deferred = cfg.clone().select("deferredSetupConfigOnBoot");
    let bootstrap = cfg.clone().select("configCurrentBootstrapOnBoot");
    let access = cfg.clone().select("configAccessPolicy");
    let setup_command = NixValue::concat_text([
        command(tools, Tool::Setup, " --apply"),
        NixValue::if_else(
            setup.clone().select("scope").equals("boot-critical"),
            " --boot-critical",
            "",
        ),
    ]);
    let setup_environment = nix_record! {
        "AIRLOCK_LOG_DIR": setup.clone().select("logDir"),
    }
    .merge_attrs(
        context
            .lib
            .clone()
            .select("optionalAttrs")
            .call(
                setup
                    .clone()
                    .select("statusDevice")
                    .equals(NixValue::null())
                    .equals(false),
            )
            .call(nix_record! {
                "AIRLOCK_SETUP_CONFIG_STATUS_DEVICE": setup.clone().select("statusDevice"),
            }),
    );
    let provider_dependencies =
        NixValue::concat_lists([common.clone(), strings(&["airlock-setup-config.service"])]);
    let deferred_dependencies = NixValue::concat_lists([
        provider_dependencies.clone(),
        strings(&["airlock-start-network-providers.service"]),
    ]);
    let bootstrap_before = optional(&bootstrap, "airlock-config-bootstrap-current.service");
    let bootstrap_dependencies = NixValue::concat_lists([
        strings(&[
            "airlock-setup-config.service",
            "qubes-db-dom0.service",
            "qubesd.service",
            "qubes-qrexec-policy-daemon.service",
        ]),
        optional(&providers, "airlock-start-network-providers.service"),
        optional(&deferred, "airlock-setup-config-deferred.service"),
    ]);

    policy(context, tools).merge_attrs(nix_record! {
        "airlock-setup-config": enabled(
            context,
            &setup,
            service(
                "Set up the declared Airlock Qubes topology",
                common,
                NixValue::list([]),
                setup_environment,
                nix_record! {
                    "ExecStart": setup_command,
                    // Persist the completed milestone before subsequent services transfer physical devices.
                    "ExecStartPost": nix_text!(
                        "{systemd}/bin/journalctl --sync",
                        systemd = context.pkgs.clone().select("systemd"),
                    ),
                },
            ),
        ),
        "airlock-start-network-providers": enabled(
            context,
            &providers,
            service(
                "Start declared Airlock root network providers",
                provider_dependencies,
                NixValue::concat_lists([
                    optional(&deferred, "airlock-setup-config-deferred.service"),
                    bootstrap_before.clone(),
                ]),
                nix_record! {
                    "AIRLOCK_LOG_DIR": providers.clone().select("logDir"),
                },
                nix_record! {
                    "ExecStart": command(tools, Tool::StartProviders, ""),
                },
            ),
        ),
        "airlock-setup-config-deferred": enabled(
            context,
            &deferred,
            service(
                "Set up deferred Airlock Qubes VMs",
                deferred_dependencies,
                bootstrap_before,
                nix_record! {
                    "AIRLOCK_LOG_DIR": deferred.clone().select("logDir"),
                },
                nix_record! {
                    "ExecStart": command(tools, Tool::Setup, " --apply --deferred"),
                },
            ),
        ),
        "airlock-config-bootstrap-current": enabled(
            context,
            &bootstrap,
            service(
                "Initialize configuration staging from the vault baseline",
                bootstrap_dependencies,
                NixValue::list([]),
                nix_record! {
                    "AIRLOCK_LOG_DIR": bootstrap.clone().select("logDir"),
                    "AIRLOCK_CONFIG_VAULT_VM": access.clone().select("vault"),
                    "AIRLOCK_CONFIG_STAGING_VM": access.clone().select("staging"),
                    "AIRLOCK_CONFIG_CURRENT_EXPORT_SERVICE": access.clone().select("currentExportService"),
                    "AIRLOCK_CONFIG_CURRENT_IMPORT_SERVICE": access.select("currentImportService"),
                },
                nix_record! {
                    "ExecStart": command(tools, Tool::BootstrapCurrent, ""),
                },
            ),
        ),
    })
}

/// Leave completed startup milestones intact across system switches.
fn service(
    description: &str,
    dependencies: NixValue,
    before: NixValue,
    environment: NixValue,
    execution: NixValue,
) -> NixValue {
    nix_record! {
        "description": description,
        "wantedBy": strings(&["multi-user.target"]),
        "wants": dependencies.clone(),
        "after": dependencies,
        "before": before,
        "restartIfChanged": false,
        "stopIfChanged": false,
        "environment": environment,
        "serviceConfig": nix_record! {
            "Type": "oneshot",
            "RemainAfterExit": true,
        }
        .merge_attrs(execution),
    }
}

/// Select a startup service without forcing disabled configuration branches.
fn enabled(context: &ModuleContext, setting: &NixValue, value: NixValue) -> NixValue {
    context
        .lib
        .clone()
        .select("mkIf")
        .call(setting.clone().select("enable"))
        .call(value)
}

/// Include an ordering edge only when its corresponding startup operation exists.
fn optional(setting: &NixValue, service: &str) -> NixValue {
    NixValue::if_else(
        setting.clone().select("enable"),
        strings(&[service]),
        NixValue::list([]),
    )
}

/// Resolve a packaged operation and retain its closure dependency in systemd's command.
fn command(tools: &NixValue, tool: Tool, arguments: &str) -> NixValue {
    nix_text!(
        "{package}/bin/{name}{arguments}",
        package = tools.clone().select(tool.export_name()),
        name = tool.export_name(),
        arguments = arguments,
    )
    .into()
}

/// Combine immutable bootstrap policy with the runtime-owned topology policy file.
fn policy(context: &ModuleContext, tools: &NixValue) -> NixValue {
    let script = airlock_build::native::writer(&context.pkgs, false)
        .call("airlock-qubes-policy-path")
        .call(crate::commands::contract(
            &context.pkgs,
            "policy-path",
            [
                ("service", tools.clone().select(Tool::Dom0.export_name())),
                ("static", "/etc/qubes/policy.d".into()),
                (
                    "runtime",
                    airlock_machine_core::services::policy_directory().into(),
                ),
                (
                    "managed",
                    airlock_machine_core::services::policy_filename().into(),
                ),
                ("coreutils", context.pkgs.clone().select("coreutils")),
                ("find", context.pkgs.clone().select("findutils")),
                ("grep", context.pkgs.clone().select("gnugrep")),
            ],
        ));
    let daemon = context
        .pkgs
        .clone()
        .select("python3.pkgs.qubes-core-qrexec");

    nix_record! {
        "airlock-qubes-policy-path": nix_record! {
            "description": "Prepare the mutable Airlock qrexec policy path",
            "before": strings(&["qubes-qrexec-policy-daemon.service"]),
            "serviceConfig": nix_record! {
                "Type": "oneshot",
                "RemainAfterExit": true,
                "ExecStart": script.to_text(),
            },
        },
        "qubes-qrexec-policy-daemon": nix_record! {
            "overrideStrategy": "asDropin",
            "requires": strings(&["airlock-qubes-policy-path.service"]),
            "after": strings(&["airlock-qubes-policy-path.service"]),
            "serviceConfig": nix_record! {
                "ExecStart": context.lib.clone().select("mkForce").call(NixValue::list([
                    "".into(),
                    nix_text!(
                        "{daemon}/bin/qrexec-policy-daemon --policy-path {directory}",
                        daemon = daemon,
                        directory = airlock_machine_core::services::policy_directory(),
                    )
                    .into(),
                ])),
            },
        },
    }
}

/// Preserve dependency order in systemd lists.
fn strings(values: &[&str]) -> NixValue {
    NixValue::list(values.iter().map(|value| (*value).into()))
}
