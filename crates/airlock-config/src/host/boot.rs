//! Supervise boot stages without allowing a failed hardware check to become a successful boot.

use airlock_build::{Workspace, script::substitute, tools::Tool};
use airlock_machine_core::boot::{BOOT_UNIT_OVERHEAD_SECONDS, GUEST_HELPER_SECONDS};
use rusix::{
    interop::{
        NixExpression, NixPath,
        raw::{NixRepresentation, NixValue},
    },
    nix_record, nix_text,
    nixos::{ContextualModule, ModuleBody, ModuleContext},
};

/// Install persistent boot supervision and the guarded desktop status RPCs.
pub(super) fn module(source: &NixPath, workspace: &Workspace) -> NixValue {
    ContextualModule::new(|context| {
        let service = Tool::Dom0
            .build(&context.pkgs, workspace, source)
            .as_expression();
        let start_ready = Tool::StartReady
            .build(&context.pkgs, workspace, source)
            .as_expression();
        let config = service.bind(|service| configuration(&context, service, start_ready));
        let declaration = nix_record! {
            "options": nix_record! {
                "airlock": nix_record! {
                    "bootSupervisor": nix_record! {
                        "enable": context
                            .lib
                            .clone()
                            .select("mkEnableOption")
                            .call("persistent guarded VM boot supervision"),
                    },
                },
            },
        };

        // Readiness consumes console evidence. Qubes deliberately permits its admin
        // group to write /var/log/xen, so keep Xen's logs under a protected parent.
        let console = nix_record! {
            "systemd": nix_record! {
                "services": nix_record! {
                    "xenconsoled": nix_record! {
                        "environment": nix_record! { "XENCONSOLED_LOG_DIR": "/var/log/airlock-xen-console" },
                        "serviceConfig": nix_record! {
                            "LogsDirectory": "airlock-xen-console",
                            "LogsDirectoryMode": "0755",
                        },
                    },
                },
            },
        };
        ModuleBody::new(context.lib.clone().select("mkMerge").call(NixValue::list([
            console,
            context.lib.clone().select("mkIf")
                .call(context.config.clone().select("airlock.bootSupervisor.enable"))
                .call(config),
        ])))
        .key("airlock.host.boot-supervisor")
        .import_value(declaration)
    })
    .into_expression()
}

/// Compose startup gates, failure recording and recovery consoles around the native supervisor.
fn configuration(context: &ModuleContext, service: NixValue, start_ready: NixValue) -> NixValue {
    let package = |name| context.pkgs.clone().select(name);
    let when = |condition, value| {
        context
            .lib
            .clone()
            .select("mkIf")
            .call(condition)
            .call(value)
    };
    let command = |operation: &str| {
        nix_text!(
            "{service}/bin/airlock-dom0-service boot-supervisor {operation}",
            service = service.clone(),
            operation = operation,
        )
    };
    let desktop_check: NixValue = nix_text!(
        "{service}/bin/airlock-dom0-service wait-desktop-ready --topology {topology}",
        service = service.clone(),
        topology = "/var/lib/airlock/system/current-topology.json",
    )
    .into();
    let desktop = context
        .config
        .clone()
        .select("airlock.guiGpu.enable")
        .and(context.config.clone().select("airlock.guiGpu.startOnBoot"));
    let split = desktop.clone().and(
        context
            .config
            .clone()
            .select("airlock.machineDeployment.enable"),
    );
    let gate: NixValue = nix_text!(
        "{coreutils}/bin/test ! -e /run/airlock/boot-supervisor/recovery-required.json",
        coreutils = package("coreutils"),
    )
    .into();
    let failure = strings(&["airlock-boot-failure@%n.service"]);
    let background = strings(&["airlock-boot-background-failure.service"]);
    let preparation = strings(&["airlock-boot-attempt-prepare.service"]);
    let guarded = |on_failure: NixValue, timeout: NixValue| {
        nix_record! {
            "unitConfig": nix_record! {
                "OnFailure": on_failure,
            },
            "serviceConfig": nix_record! {
                "ExecCondition": NixValue::list([gate.clone()]),
                "TimeoutStartSec": timeout,
            },
        }
    };
    // Sequential provider and autostart loops need a budget for every declared VM.
    // Counting all domains also covers inherited providers and avoids a second role projection.
    let domains = NixValue::builtin("length").call(
        NixValue::builtin("attrNames").call(context.config.clone().select("airlock.qubes.domains")),
    );
    let sequential_budget = NixValue::builtin("add")
        .call(BOOT_UNIT_OVERHEAD_SECONDS as i64)
        .call(
            NixValue::builtin("mul")
                .call(domains)
                .call(GUEST_HELPER_SECONDS as i64),
        );
    let mut services = vec![
        (
            "airlock-boot-guest@",
            when(
                split.clone(),
                nix_record! {
                    "description": "Start and verify Airlock boot guest %i",
                    // No installation target or ordering against setup: the coordinator
                    // submits these only after the selected configuration and providers
                    // are ready, and can finish the desktop while the assistant continues.
                    "serviceConfig": nix_record! {
                        "Type": "oneshot",
                        "RemainAfterExit": true,
                        "ExecCondition": NixValue::list([gate.clone()]),
                        "ExecStart": nix_text!(
                            "{start_ready}/bin/airlock-start-qube-ready %i /run/airlock/startup/topology.json",
                            start_ready = start_ready,
                        ),
                        "TimeoutStartSec": GUEST_HELPER_SECONDS as i64,
                        "TimeoutStopSec": 15_i64,
                    },
                },
            ),
        ),
        (
            "airlock-boot-shutdown-record",
            nix_record! {
                "wantedBy": strings(&["shutdown.target"]),
                "before": strings(&["shutdown.target"]),
                "unitConfig": nix_record! {
                    "DefaultDependencies": false,
                },
                "serviceConfig": nix_record! {
                    "Type": "oneshot",
                    "ExecStart": command("shutdown-requested"),
                },
            },
        ),
        (
            "airlock-boot-background-failure",
            when(
                desktop.clone(),
                nix_record! {
                    "serviceConfig": nix_record! {
                        "Type": "oneshot",
                        "ExecStart": command("degraded"),
                    },
                },
            ),
        ),
        (
            "getty@tty1",
            nix_record! {
                "enable": false,
            },
        ),
        (
            "autovt@tty1",
            nix_record! {
                "enable": false,
            },
        ),
        (
            "airlock-boot-attempt-prepare",
            nix_record! {
                "description": "Recover an interrupted Airlock boot before VM logs are reopened",
                "wantedBy": strings(&["multi-user.target"]),
                "before": strings(&[
                    "xenconsoled.service",
                    "qubesd.service",
                    "airlock-setup-config.service",
                ]),
                "serviceConfig": nix_record! {
                    "Type": "oneshot",
                    "RemainAfterExit": true,
                    "ExecStart": command("prepare"),
                },
            },
        ),
        (
            "airlock-boot-failure@",
            nix_record! {
                "description": "Capture Airlock boot failure for %i",
                "serviceConfig": nix_record! {
                    "Type": "oneshot",
                    "ExecStart": command("fail unit:%i 'systemd boot stage failed'"),
                    // Even a failure to record diagnostics must leave a usable login console.
                    "ExecStopPost": nix_text!(
                        "{systemd}/bin/systemctl --no-block start airlock-boot-failure-console.service",
                        systemd = package("systemd"),
                    ),
                    "TimeoutStartSec": 90_i64,
                },
            },
        ),
        (
            "airlock-boot-failure-console",
            nix_record! {
                "description": "Show an actionable console after a supervised boot failure",
                "conflicts": strings(&["airlock-boot-recovery-console.service"]),
                "after": strings(&[
                    "airlock-setup-config.service",
                    "airlock-boot-recovery-console.service",
                ]),
                "serviceConfig": console(context, &service, false),
            },
        ),
        (
            "airlock-boot-recovery-console",
            nix_record! {
                "description": "Keep an interrupted Airlock boot on a diagnostic console",
                "wantedBy": strings(&["multi-user.target"]),
                "after": preparation.clone(),
                "unitConfig": nix_record! {
                    "ConditionPathExists": "/run/airlock/boot-supervisor/recovery-required.json",
                },
                "serviceConfig": console(context, &service, true),
            },
        ),
        (
            "airlock-setup-config",
            nix_record! {
                "after": preparation.clone(),
                "unitConfig": nix_record! {
                    "OnFailure": failure.clone(),
                },
                "serviceConfig": nix_record! {
                    "ExecCondition": NixValue::list([gate.clone()]),
                    "ExecStartPre": NixValue::list([command(
                        "stage topology 'checking startup configuration'",
                    )
                    .into()]),
                },
            },
        ),
        (
            "airlock-setup-config-deferred",
            when(
                split.clone(),
                nix_record! {
                    "unitConfig": nix_record! {
                        "OnFailure": background.clone(),
                    },
                    "serviceConfig": nix_record! {
                        "ExecCondition": NixValue::list([gate.clone()]),
                        "TimeoutStartSec": 1800_i64,
                    },
                },
            ),
        ),
        (
            "airlock-desktop-ready",
            when(
                split.clone(),
                nix_record! {
                    "unitConfig": nix_record! { "OnFailure": failure.clone() },
                    "serviceConfig": nix_record! {
                        "ExecCondition": NixValue::list([gate.clone()]),
                        "ExecStartPost": command("desktop-ready"),
                    },
                },
            ),
        ),
        (
            "airlock-start-network-providers",
            guarded(
                NixValue::if_else(split.clone(), background.clone(), failure.clone()),
                sequential_budget.clone(),
            ),
        ),
        (
            "airlock-start-gui-gpu",
            guarded(failure.clone(), sequential_budget.clone()),
        ),
        (
            "airlock-input-boot-guard",
            when(
                context
                    .config
                    .clone()
                    .select("airlock.inputProxy.sender.enable"),
                nix_record! {
                    "requires": preparation.clone(),
                    "after": preparation.clone(),
                    "unitConfig": nix_record! {
                        "OnFailure": failure.clone(),
                    },
                    "serviceConfig": nix_record! {
                        "ExecCondition": NixValue::list([gate.clone()]),
                    },
                },
            ),
        ),
        (
            "airlock-gui-input-boot-ready",
            when(
                split.clone().and(
                    context
                        .config
                        .clone()
                        .select("airlock.inputProxy.sender.enable"),
                ),
                nix_record! {
                    "unitConfig": nix_record! {
                        "OnFailure": failure.clone(),
                    },
                    "serviceConfig": nix_record! {
                        "ExecCondition": NixValue::list([gate.clone()]),
                    },
                },
            ),
        ),
        (
            "airlock-machine-autostart",
            nix_record! {
                "unitConfig": nix_record! {
                    "OnFailure": NixValue::if_else(desktop.clone(), background, failure),
                },
                "serviceConfig": nix_record! {
                    "ExecStartPre": NixValue::if_else(
                        desktop.clone().and(split.equals(false)),
                        NixValue::list([desktop_check, command("desktop-ready").into()]),
                        NixValue::list([]),
                    ),
                    "ExecCondition": NixValue::list([gate]),
                    "TimeoutStartSec": sequential_budget,
                },
            },
        ),
    ];
    for name in ["xenconsoled", "qubesd"] {
        services.push((
            name,
            nix_record! {
                "requires": preparation.clone(),
                "after": preparation.clone(),
            },
        ));
    }

    context.lib.clone().select("mkMerge").call(NixValue::list([
        nix_record! {
            "environment": nix_record! {
                "systemPackages": NixValue::list([service.clone()]),
                "etc": nix_record! {
                    "airlock/boot-readiness.json": nix_record! {
                        "text": NixValue::builtin("toJSON").call(nix_record! {
                            "schema": "airlock.boot-readiness.v1",
                            "desktop": desktop.clone(),
                            "input_target": NixValue::if_else(
                                context.config.clone().select("airlock.inputProxy.sender.enable"),
                                context.config.clone().select("airlock.inputProxy.sender.target"),
                                NixValue::null(),
                            ),
                        }),
                    },
                },
            },
            "systemd": nix_record! {
                "services": NixValue::record(services),
            },
        },
        when(
            desktop,
            super::setup::desktop_rpcs(
                context,
                &service,
                "boot-supervisor",
                "40-airlock-boot-desktop.policy",
                &[
                    ("airlock.BootStatus", "desktop-status"),
                    ("airlock.BootRetry", "retry-services"),
                ],
            ),
        ),
    ]))
}

/// Open a tty1 login after reporting preserved evidence; never clear failure state implicitly.
fn console(context: &ModuleContext, service: &NixValue, recovery: bool) -> NixValue {
    let name = if recovery {
        "airlock-boot-recovery-console"
    } else {
        "airlock-boot-failure-console"
    };
    let script = if recovery {
        include_str!("boot/recovery-console.sh")
    } else {
        include_str!("boot/failure-console.sh")
    };
    let executable = context
        .pkgs
        .clone()
        .select("writeShellScript")
        .call(name)
        .call(substitute(
            script,
            [
                ("service", service.clone()),
                ("ncurses", context.pkgs.clone().select("ncurses")),
                ("coreutils", context.pkgs.clone().select("coreutils")),
                ("utilLinux", context.pkgs.clone().select("util-linux")),
            ],
        ));

    nix_record! {
        "Type": "idle",
        "ExecStart": executable.to_text(),
        "Restart": "always",
        "RestartSec": 1_i64,
        "StandardInput": "tty",
        "StandardOutput": "tty",
        "StandardError": "tty",
        "TTYPath": "/dev/tty1",
        "TTYReset": true,
        "TTYVHangup": true,
    }
}

/// Preserve static systemd dependency order.
fn strings(values: &[&str]) -> NixValue {
    NixValue::list(values.iter().map(|value| (*value).into()))
}
