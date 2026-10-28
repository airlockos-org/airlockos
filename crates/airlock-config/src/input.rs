//! Forward trusted physical input across the dom0-to-GUI Qubes boundary.
//! Admission uses Qubes lifecycle events and explicit receiver readiness, never VM autostart.

use airlock_build::{Application, Workspace, tools::Tool, upstream};
use rusix::{
    interop::{
        NixExpression, NixPath,
        raw::{NixRepresentation, NixValue},
    },
    nix_record, nix_text,
    nixos::{ContextualModule, ModuleBody, ModuleContext},
};

/// Upstream device handlers retained for the Qubes input protocol.
const SERVICES: [&str; 3] = [
    "qubes.InputKeyboard",
    "qubes.InputMouse",
    "qubes.InputTablet",
];

/// Install only the selected sender or receiver side of physical input transport.
pub(crate) fn module(source: &NixPath, workspace: &Workspace) -> NixValue {
    ContextualModule::new(|context| {
        let package = upstream::input_proxy(&context.pkgs).as_expression();
        let service = Tool::Dom0
            .build(&context.pkgs, workspace, source)
            .as_expression();
        let settings = context.config.clone().select("airlock.inputProxy");
        let config = package.bind(|proxy| {
            service.bind(|service| {
                context.lib.clone().select("mkMerge").call(NixValue::list([
                    context
                        .lib
                        .clone()
                        .select("mkIf")
                        .call(settings.clone().select("receiver.enable"))
                        .call(receiver(&context, proxy.clone(), workspace)),
                    context
                        .lib
                        .clone()
                        .select("mkIf")
                        .call(settings.clone().select("sender.enable"))
                        .call(sender(&context, &settings, proxy, service)),
                ]))
            })
        });

        ModuleBody::new(config)
            .key("airlock.input")
            .import_value(options(&context))
    })
    .into_expression()
}

/// Declare the input boundary and validate the selected GUI identity through the NixOS type.
fn options(context: &ModuleContext) -> NixValue {
    let enable = |description| {
        context
            .lib
            .clone()
            .select("mkEnableOption")
            .call(description)
    };

    nix_record! {
        "options": nix_record! {
            "airlock": nix_record! {
                "inputProxy": nix_record! {
                    "receiver": nix_record! {
                        "enable": enable("dom0 input reception in the physical GUI VM"),
                    },
                    "sender": nix_record! {
                        "enable": enable("automatic dom0 input forwarding to the physical GUI VM"),
                        "target": context.lib.clone().select("mkOption").call(nix_record! {
                            "type": context
                                .lib
                                .clone()
                                .select("types.strMatching")
                                .call("[a-zA-Z][a-zA-Z0-9_-]*"),
                            "default": "sys-gui",
                            "description": "Already-running GUI VM receiving physical input.",
                        }),
                    },
                },
            },
        },
    }
}

/// Restrict every root input handler to dom0 before opening the kernel's uinput device.
fn receiver(context: &ModuleContext, proxy: NixValue, workspace: &Workspace) -> NixValue {
    let script = |name, text: NixValue| {
        airlock_build::native::writer(&context.pkgs, false)
            .call(name)
            .call(text)
    };
    let root: NixValue = nix_text!(
        r#"
        force-user='root'
    "#
    )
    .into();
    let mut files = Vec::new();
    for service in SERVICES {
        let handler = script(
            service,
            nix_text!(
                r#"
            set -eu
            # The greeter also needs input; only dom0 may create root-owned devices.
            [ "${{QREXEC_REMOTE_DOMAIN:-}}" = dom0 ] || exit 1
            exec {proxy}/etc/qubes-rpc/{service}
        "#,
                proxy = proxy.clone(),
                service = service,
            )
            .into(),
        );
        files.push((
            format!("qubes-rpc/{service}"),
            nix_record! {
                "source": handler,
            },
        ));
        files.push((
            format!("qubes/rpc-config/{service}"),
            nix_record! {
                "text": root.clone(),
            },
        ));
    }
    let device = script(
        "airlock-input-device",
        crate::commands::contract(&context.pkgs, "device-receiver", [("proxy", proxy.clone())]),
    );
    let handlers = SERVICES
        .map(|service| format!("--handler /etc/qubes-rpc/{service}"))
        .join(" ");
    let vm_service = Application::VmService
        .build(&context.pkgs, workspace)
        .as_expression();
    let ready = script(
        "airlock-input-receiver-ready",
        crate::commands::contract(
            &context.pkgs,
            "receiver-ready",
            [
                ("handlers", handlers.into()),
                ("service", vm_service.clone()),
            ],
        ),
    );
    let initialization = script(
        "airlock-input-initialization",
        crate::commands::contract(
            &context.pkgs,
            "input-initialization",
            [
                ("service", vm_service),
                ("systemd", context.pkgs.clone().select("systemd")),
            ],
        ),
    );
    files.extend([
        (
            "qubes-rpc/airlock.InputDevice".into(),
            nix_record! {
                "source": device,
                "mode": "symlink",
            },
        ),
        (
            "qubes/rpc-config/airlock.InputDevice".into(),
            nix_record! {
                "text": root.clone(),
            },
        ),
        (
            "qubes-rpc/airlock.InputReceiverReady".into(),
            nix_record! {
                "source": ready,
                "mode": "symlink",
            },
        ),
        (
            "qubes-rpc/airlock.InputInitialization".into(),
            nix_record! { "source": initialization, "mode": "symlink" },
        ),
        (
            "qubes/rpc-config/airlock.InputInitialization".into(),
            nix_record! { "text": root.clone(), "mode": "0444" },
        ),
        (
            "qubes/rpc-config/airlock.InputReceiverReady".into(),
            nix_record! {
                "text": root,
                "mode": "0444",
            },
        ),
    ]);

    nix_record! {
        "systemd": nix_record! {
            "targets": nix_record! {
                // Receiver-only guests acknowledge setup without starting a display manager.
                "airlock-input-initialized": nix_record! { "description": "dom0 input initialization completed" },
            },
        },
        "boot": nix_record! {
            "kernelModules": strings(&["uinput"]),
        },
        "environment": nix_record! {
            "systemPackages": NixValue::list([proxy]),
            "etc": NixValue::record(files),
        },
    }
}

/// Keep host-originated forwarding separate from VM-originated policy authorization.
fn sender(
    context: &ModuleContext,
    settings: &NixValue,
    proxy: NixValue,
    service: NixValue,
) -> NixValue {
    let target = settings.clone().select("sender.target");
    let quoted = context
        .lib
        .clone()
        .select("escapeShellArg")
        .call(target.clone());
    let qrexec = context
        .pkgs
        .clone()
        .select("python3.pkgs.qubes-core-qrexec.dom0");
    let connect = airlock_build::native::writer(&context.pkgs, false)
        .call("airlock-connect-gui-input")
        .call(crate::commands::contract(
            &context.pkgs,
            "connect-input",
            [
                (
                    "admin",
                    context
                        .pkgs
                        .clone()
                        .select("python3.pkgs.qubes-core-admin-client"),
                ),
                ("quotedTarget", target.clone()),
                ("service", service.clone()),
                ("qrexec", qrexec.clone()),
                ("systemd", context.pkgs.clone().select("systemd")),
            ],
        ));
    let boot = context
        .config
        .clone()
        .select("airlock.machineDeployment.enable")
        .and(context.config.clone().select("airlock.guiGpu.enable"))
        .and(context.config.clone().select("airlock.guiGpu.startOnBoot"));
    let optional_network = NixValue::if_else(
        boot,
        NixValue::list([]),
        strings(&["airlock-start-network-providers.service"]),
    );
    let executable: NixValue =
        nix_text!("{service}/bin/airlock-dom0-service", service = service).into();
    let boot_guard = strings(&["airlock-input-boot-guard.service"]);

    nix_record! {
        "assertions": NixValue::list([
            nix_record! {
                "assertion": context
                    .config
                    .clone()
                    .select("virtualisation.qubes.dom0.enable"),
                "message": "The physical input sender must run in Qubes dom0.",
            },
            nix_record! {
                "assertion": target
                    .clone()
                    .equals("dom0")
                    .equals(false)
                    .and(settings.clone().select("receiver.enable").equals(false)),
                "message": "Physical input must cross from dom0 to a separate GUI VM.",
            },
        ]),
        "environment": nix_record! {
            "systemPackages": NixValue::list([proxy.clone()]),
        },
        // Qubes owns the joined policy directory; contribute through its package list.
        "virtualisation": nix_record! {
            "qubes": nix_record! {
                "packages": NixValue::list([policy(context, target)]),
            },
        },
        "systemd": nix_record! {
            "targets": nix_record! {
                "airlock-gui-input": nix_record! {
                    "description": "Forward discovered physical input devices to the GUI VM",
                    "wants": strings(&["airlock-gui-input-discovery.service"]),
                },
            },
            "services": nix_record! {
                "airlock-input-boot-guard": nix_record! {
                    "description": "Check kernel input initialization and attempt one bounded recovery",
                    "wantedBy": strings(&["multi-user.target"]),
                    "after": NixValue::concat_lists([
                        strings(&[
                            "systemd-udev-trigger.service",
                            "airlock-setup-config.service",
                        ]),
                        optional_network,
                    ]),
                    "before": strings(&[
                        "airlock-start-gui-gpu.service",
                        "airlock-gui-input-connect.service",
                    ]),
                    "path": NixValue::list([context.pkgs.clone().select("systemd")]),
                    "serviceConfig": nix_record! {
                        "Type": "oneshot",
                        "RemainAfterExit": true,
                        "ExecStart": nix_text!(
                            "{executable} input boot-guard",
                            executable = executable.clone(),
                        ),
                        "ExecStopPost": nix_text!(
                            "{executable} input finalize",
                            executable = executable.clone(),
                        ),
                        "TimeoutStartSec": 75_i64,
                        "TimeoutStopSec": 5_i64,
                        "Restart": "no",
                        "UMask": "0077",
                    },
                },
                "airlock-start-gui-gpu": context
                    .lib
                    .clone()
                    .select("mkIf")
                    .call(
                        context
                            .config
                            .clone()
                            .select("airlock.guiGpu")
                            .attr_or("startOnBoot", false),
                    )
                    .call(nix_record! {
                        "requires": boot_guard.clone(),
                        "after": boot_guard.clone(),
                    }),
                "airlock-gui-input-connect": nix_record! {
                    "description": "Connect physical input after the GUI VM is ready",
                    "requires": boot_guard,
                    "after": strings(&["qubesd.service", "airlock-input-boot-guard.service"]),
                    "unitConfig": nix_record! { "StartLimitIntervalSec": 0_i64 },
                    "serviceConfig": nix_record! {
                        "Type": "oneshot",
                        "ExecStart": connect.to_text(),
                        // Include the 65-second receiver RPC, Xen identity checks
                        // and forwarding discovery instead of truncating their budgets.
                        "TimeoutStartSec": 240_i64,
                        "Restart": "on-failure",
                        "RestartSec": 3_i64,
                    },
                },
                "airlock-gui-input-events": nix_record! {
                    "description": "Coordinate physical input from Qubes VM lifecycle events",
                    "wantedBy": strings(&["multi-user.target"]),
                    "requires": strings(&["airlock-setup-config.service"]),
                    "wants": strings(&["qubesd.service"]),
                    "after": strings(&["airlock-setup-config.service", "qubesd.service"]),
                    "serviceConfig": nix_record! {
                        "Type": "simple",
                        "ExecStart": nix_text!(
                            "{executable} input events --target {target}",
                            executable = executable.clone(),
                            target = quoted.clone(),
                        ),
                        "Restart": "on-failure",
                        "RestartSec": 5_i64,
                    },
                },
                "airlock-gui-input-discovery": nix_record! {
                    "description": "Discover and forward trusted local input devices",
                    "partOf": strings(&["airlock-gui-input.target"]),
                    "after": strings(&["qubesd.service"]),
                    "serviceConfig": nix_record! {
                        "Type": "notify",
                        "NotifyAccess": "all",
                        "ExecStart": nix_text!(
                            "{executable} input discover --target {target} --qrexec {qrexec}/bin/qrexec-client \
                             --sender {proxy}/bin/input-proxy-sender \
                             --inventory /var/lib/airlock/input/trusted-devices.json \
                             --notify {systemd}/bin/systemd-notify",
                            executable = executable,
                            target = quoted,
                            qrexec = qrexec,
                            proxy = proxy,
                            systemd = context.pkgs.clone().select("systemd"),
                        ),
                        "StateDirectory": "airlock/input",
                        "StateDirectoryMode": "0700",
                        "Restart": "on-failure",
                        "RestartSec": 2_i64,
                        "KillMode": "control-group",
                        "TimeoutStopSec": 5_i64,
                        "UMask": "0077",
                        "PrivateTmp": true,
                    },
                },
            },
        },
    }
}

/// Deny VM-originated input calls while dom0 uses its upstream administrative qrexec path.
fn policy(context: &ModuleContext, target: NixValue) -> NixValue {
    let rules = NixValue::concat_text(
        SERVICES
            .into_iter()
            .chain([
                "airlock.InputDevice",
                "airlock.InputReceiverReady",
                "airlock.InputInitialization",
            ])
            .map(|service| {
                nix_text!(
                    r#"
            {service} * @anyvm {target} deny
        "#,
                    service = service,
                    target = target.clone(),
                )
                .into()
            }),
    );

    context
        .pkgs
        .clone()
        .select("runCommand")
        .call("airlock-gui-input-policy")
        .call(nix_record! {})
        .call(nix_text!(
            r#"
            install -d -m 0755 "$out/etc/qubes/policy.d"
            cat > "$out/etc/qubes/policy.d/40-airlock-gui-input.policy" <<'EOF'
            {rules}EOF
        "#,
            rules = rules,
        ))
}

/// Preserve static dependency and capability list order.
fn strings(values: &[&str]) -> NixValue {
    NixValue::list(values.iter().map(|value| (*value).into()))
}
