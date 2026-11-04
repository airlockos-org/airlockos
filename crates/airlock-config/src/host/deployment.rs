//! Configure source-reviewed machine deployment and its existing Qubes control interfaces.

mod options;

mod services;

use airlock_build::{Workspace, tools::Tool};
use rusix::{
    interop::{
        NixExpression, NixPath,
        raw::{NixRepresentation, NixValue},
    },
    nix_record, nix_text,
    nixos::{ContextualModule, ModuleBody, ModuleContext},
};

/// Install the native coordinator and guarded startup services for an authored machine.
pub(crate) fn module(source: &NixPath, workspace: &Workspace) -> NixValue {
    named_module(source, workspace, "airlock.host.deployment")
}

/// Give an explicitly selected repair implementation a distinct module identity.
pub(crate) fn named_module(source: &NixPath, workspace: &Workspace, key: &str) -> NixValue {
    ContextualModule::new(|context| {
        let engine = Tool::Dom0
            .build(&context.pkgs, workspace, source)
            .as_expression();
        let setup = Tool::Setup
            .build(&context.pkgs, workspace, source)
            .as_expression();
        let cfg = context.config.clone().select("airlock.machineDeployment");
        let configuration = engine.bind(|engine| {
            context.lib.clone().select("mkMerge").call(NixValue::list([
                metadata(&context, &cfg, &engine),
                rpcs(&context, &engine),
                services::configuration(&context, &cfg, &engine, setup),
            ]))
        });

        ModuleBody::new(
            context
                .lib
                .clone()
                .select("mkIf")
                .call(cfg.select("enable"))
                .call(configuration),
        )
        .key(key)
        .import_value(options::declarations(&context))
    })
    .into_expression()
}

/// Write deployment policy and committed source metadata consumed by the native coordinator.
fn metadata(context: &ModuleContext, cfg: &NixValue, engine: &NixValue) -> NixValue {
    let when = |condition, value| {
        context
            .lib
            .clone()
            .select("mkIf")
            .call(condition)
            .call(value)
    };
    let source = cfg.clone().select("initialSource");
    let marker = nix_record! {
        "text": nix_text!(r#"
        v1
    "#),
    };
    let guarded = context
        .config
        .clone()
        .select("airlock.guiGpu.enable")
        .and(context.config.clone().select("airlock.guiGpu.startOnBoot"));

    nix_record! {
        "airlock": nix_record! {
            "qubes": nix_record! {
                "deferredSetupConfigOnBoot": nix_record! {
                    "enable": when(
                        guarded.clone(),
                        context.lib.clone().select("mkForce").call(true),
                    ),
                },
            },
        },
        "system": nix_record! {
            "build": nix_record! {
                "machineDeploymentCoordinator": engine.clone(),
            },
        },
        "environment": nix_record! {
            "systemPackages": NixValue::list([engine.clone()]),
            "etc": nix_record! {
                "airlock/split-startup": when(guarded, marker.clone()),
                "airlock/review-required": when(cfg.clone().select("userReview"), marker),
                "airlock/machine-source.json": when(
                    source.clone().equals(NixValue::null()).equals(false),
                    nix_record! {
                        "text": NixValue::builtin("toJSON").call(
                            nix_record! {
                                "schema": "airlock.machine-source.v1",
                            }
                            .merge_attrs(source),
                        ),
                    },
                ),
                "airlock/machine-profile": nix_record! {
                    "text": nix_text!(
                        r#"
                    {profile}
                "#,
                        profile = cfg.clone().select("profile"),
                    ),
                },
                "airlock/generation-retention.json": nix_record! {
                    "text": NixValue::builtin("toJSON").call(nix_record! {
                        "enabled": cfg.clone().select("generationRetention.enable"),
                        "newest": 2_i64,
                        "weeklyDays": 7_i64,
                        "keepAgingSuccessor": true,
                    }),
                },
            },
        },
    }
}

/// Install exact sudo helpers paired with Qubes caller checks for each coordinator operation.
fn rpcs(context: &ModuleContext, engine: &NixValue) -> NixValue {
    let mut files = Vec::new();
    let mut commands = Vec::new();
    for (name, operation, accepts_argument, developer) in [
        ("airlock.Ctrl.ReviewControl", "review-control", false, false),
        (
            "airlock.Ctrl.BuildPrepare",
            "rpc build-prepare",
            false,
            false,
        ),
        ("airlock.Pool.AdmitBuild", "build-receive", true, false),
        (
            "airlock.Ctrl.MachineControl",
            "rpc machine-control",
            false,
            true,
        ),
        (
            "airlock.Ctrl.GuestPlan",
            "rpc guest-receive plan",
            false,
            false,
        ),
        (
            "airlock.Ctrl.GuestApply",
            "rpc guest-receive apply",
            false,
            false,
        ),
        (
            "airlock.Ctrl.MachinePlan",
            "rpc machine-receive plan",
            false,
            false,
        ),
        (
            "airlock.Ctrl.MachineApply",
            "rpc machine-receive apply",
            false,
            false,
        ),
        (
            "airlock.Ctrl.MachinePrepare",
            "rpc machine-receive prepare",
            false,
            false,
        ),
        (
            "airlock.Pool.AdmitCandidate",
            "admission-receive",
            true,
            false,
        ),
    ] {
        let arguments = if accepts_argument {
            r#" "$1" --caller sys-ctrl"#
        } else {
            ""
        };
        let count = if accepts_argument { 1_i64 } else { 0_i64 };
        let helper = context
            .pkgs
            .clone()
            .select("writeShellScript")
            .call(format!("{name}-root"))
            .call(nix_text!(
                r#"
                set -eu
                [ "$#" -eq {count} ] || exit 2
                exec {engine}/bin/airlock-dom0-service {operation}{arguments}
            "#,
                count = count,
                engine = engine.clone(),
                operation = operation,
                arguments = arguments,
            ));
        let allowed = if developer {
            "usr-assistant|sys-ctrl"
        } else {
            "sys-ctrl"
        };
        let forwarded = if accepts_argument {
            r#" "${QREXEC_SERVICE_ARGUMENT:-}""#
        } else {
            ""
        };
        let handler = context
            .pkgs
            .clone()
            .select("writeShellScript")
            .call(format!("{name}-qrexec"))
            .call(nix_text!(
                r#"
                set -eu
                case "${{QREXEC_REMOTE_DOMAIN:-}}" in {allowed}) ;; *) exit 1 ;; esac
                exec /run/wrappers/bin/sudo -n {helper}{forwarded}
            "#,
                allowed = allowed,
                helper = helper.clone(),
                forwarded = forwarded,
            ));
        files.push((
            format!("qubes-rpc/{name}"),
            nix_record! {
                "source": handler,
                "mode": "0555",
            },
        ));
        commands.push(nix_record! {
            "command": helper.to_text(),
            "options": NixValue::list(["NOPASSWD".into()]),
        });
    }
    let policy = |name, text| {
        context
            .pkgs
            .clone()
            .select("writeTextDir")
            .call(name)
            .call(text)
    };

    nix_record! {
        "environment": nix_record! {
            "etc": NixValue::record(files),
        },
        "security": nix_record! {
            "sudo": nix_record! {
                "extraRules": NixValue::list([nix_record! {
                    "users": NixValue::list([context.config.clone().select("airlock.dom0.user")]),
                    "commands": NixValue::list(commands),
                }]),
            },
        },
        "virtualisation": nix_record! {
            "qubes": nix_record! {
                "packages": NixValue::list([
                    policy(
                        "etc/qubes/policy.d/05-airlock-retired.policy",
                        include_str!("deployment/retired.policy"),
                    ),
                    policy(
                        "etc/qubes/policy.d/43-airlock-ctrl-guest.policy",
                        include_str!("deployment/controller.policy"),
                    ),
                ]),
            },
        },
    }
}
