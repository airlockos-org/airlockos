//! Forward application windows through the Qubes GUI agent and its graphical user session.
//! Application VMs run no desktop shell; the GUI VM owns the display and window management.

use airlock_build::{Application, Workspace, script::substitute};
use rusix::{
    interop::{
        NixExpression, NixPath,
        raw::{NixRepresentation, NixValue},
    },
    nix_record, nix_text,
    nixos::{ContextualModule, ModuleBody, ModuleContext},
};

/// Install application-window forwarding, bounded readiness RPCs and session scale settings.
pub(super) fn module() -> NixValue {
    ContextualModule::new(|context| {
        let declaration = nix_record! {
            "options": nix_record! {
                "airlock": nix_record! {
                    "appGui": nix_record! {
                        "scale": context.lib.clone().select("mkOption").call(nix_record! {
                            "type": context.lib.clone().select("types.ints.between").call(1_i64).call(4_i64),
                            "default": 1_i64,
                            "description": "Integer X11 rendering scale matching the GUI VM's Xwayland scale.",
                        }),
                    },
                },
            },
        };

        ModuleBody::new(configuration(&context))
            .key("airlock.vm.app-gui")
            .import_value(declaration)
    })
    .into_expression()
}

/// Adapt upstream session commands while preserving qrexec's graphical environment.
fn session(context: &ModuleContext) -> NixValue {
    let pkgs = &context.pkgs;
    let package = |name| pkgs.clone().select(name);
    let python = package("python3.withPackages").call(NixValue::function(|python| {
        NixValue::list(
            ["pyxdg", "pygobject3", "dbus-python"].map(|name| python.clone().select(name)),
        )
    }));
    let autostart = airlock_build::native::writer(&context.pkgs, false)
        .call("qubes-session-autostart")
        .call(crate::commands::contract(
            &context.pkgs,
            "autostart",
            [
                ("coreAgent", package("qubes-core-agent-linux")),
                ("coreAgentSource", package("qubes-core-agent-linux.src")),
                ("sitePackages", package("python3.sitePackages")),
                ("python", python),
            ],
        ));
    let upstream = package("runCommand")
        .call("airlock-qubes-app-session")
        .call(nix_record! {})
        .call(substitute(
            include_str!("app-gui/upstream-session.sh"),
            [
                ("agent", package("qubes-gui-agent-linux")),
                ("autostart", autostart),
                ("coreutils", package("coreutils")),
            ],
        ));
    let scale = context.config.clone().select("airlock.appGui.scale");

    airlock_build::native::writer(&context.pkgs, false)
        .call("airlock-qubes-scaled-session")
        .call(crate::commands::contract(
            &context.pkgs,
            "session",
            [
                ("scale", scale.clone()),
                (
                    "cursorSize",
                    NixValue::builtin("mul").call(24_i64).call(scale),
                ),
                ("coreutils", package("coreutils")),
                ("session", upstream),
            ],
        ))
}

/// Bind RPC implementations once before installing their files and user-routing contracts.
fn rpc_files(context: &ModuleContext) -> NixValue {
    let pkgs = &context.pkgs;
    let package = |name| pkgs.clone().select(name);
    let script = |name, text| {
        airlock_build::native::writer(&context.pkgs, false)
            .call(name)
            .call(text)
    };
    let path = context
        .lib
        .clone()
        .select("makeBinPath")
        .call(NixValue::list(
            ["coreutils", "gnugrep", "libxcvt", "xrandr"].map(package),
        ));
    let monitor_layout = script(
        "airlock-qubes-set-monitor-layout",
        crate::commands::contract(
            &context.pkgs,
            "monitor-layout",
            [
                ("path", path),
                ("coreutils", package("coreutils")),
                ("agent", package("qubes-gui-agent-linux")),
            ],
        ),
    );
    let open_url = script(
        "airlock-open-url-in-vm",
        crate::commands::contract(&context.pkgs, "open-url", [("glib", package("glib.bin"))]),
    );

    let workspace = Workspace::new(NixPath::from_source_text(
        package("airlockAppsSource").to_text().into_expr::<String>(),
    ));
    let ready = script(
        "airlock-app-session-ready",
        crate::commands::contract(
            &context.pkgs,
            "session-ready",
            [(
                "service",
                Application::VmService
                    .build(pkgs, &workspace)
                    .as_expression(),
            )],
        ),
    );
    let user_config = nix_text!(
        "force-user='{user}'\n",
        user = context.config.clone().select("airlock.qubeGuest.user"),
    );

    nix_record! {
        "xdg/autostart/qubes-qrexec-fork-server.desktop": nix_record! {
            "text": nix_text!(
                r#"
                [Desktop Entry]
                Name=qrexec-fork-server
                Exec={qrexec}/bin/qrexec-fork-server
                Terminal=false
                Type=Application
            "#,
                qrexec = package("python3.pkgs.qubes-core-qrexec.domU"),
            ),
        },
        "X11/xorg-qubes.conf.template": nix_record! {
            "source": nix_text!(
                "{agent}/etc/X11/xorg-qubes.conf.template",
                agent = package("qubes-gui-agent-linux"),
            ),
        },
        "X11/xinit/xinitrc": nix_record! {
            "source": session(context),
        },
        "qubes-rpc/qubes.SetMonitorLayout": nix_record! {
            "source": monitor_layout,
        },
        "qubes/rpc-config/qubes.SetMonitorLayout": nix_record! {
            "text": user_config.clone(),
        },
        "qubes-rpc/airlock.OpenUrl": nix_record! {
            "source": open_url,
            "mode": "symlink",
        },
        "qubes/rpc-config/airlock.OpenUrl": nix_record! {
            "text": user_config.clone(),
        },
        "qubes-rpc/airlock.AppSessionReady": nix_record! {
            "source": ready,
            "mode": "symlink",
        },
        "qubes/rpc-config/airlock.AppSessionReady": nix_record! {
            "text": user_config,
            "mode": "0444",
        },
    }
}

/// Configure upstream agent services and the packages needed inside each application VM.
fn configuration(context: &ModuleContext) -> NixValue {
    let pkgs = &context.pkgs;
    let packages =
        |names: &[&str]| NixValue::list(names.iter().map(|name| pkgs.clone().select(name)));
    let agent = pkgs.clone().select("qubes-gui-agent-linux");

    agent.bind(|agent| {
        nix_record! {
            "environment": nix_record! {
                // Icon RPCs resolve themes through the active profile even in a headless VM.
                "pathsToLink": NixValue::list(["/share/icons".into(), "/share/pixmaps".into()]),
                "systemPackages": NixValue::concat_lists([
                    NixValue::list([agent.clone(), airlock_build::desktop::icons(pkgs).as_expression()]),
                    packages(&[
                        "dbus",
                        "hicolor-icon-theme",
                        "adwaita-icon-theme",
                        "libxcvt",
                        "xrandr",
                        "xsetroot",
                        "xdpyinfo",
                    ]),
                ]),
                "etc": rpc_files(context),
            },
            "fonts": nix_record! {
                "packages": packages(&["nerd-fonts.symbols-only"]),
            },
            "services": nix_record! {
                "udev": nix_record! {
                    "packages": NixValue::list([agent.clone()]),
                },
                "dbus": nix_record! {
                    "enable": true,
                },
            },
            "boot": nix_record! {
                "kernel": nix_record! {
                    "sysctl": nix_record! {
                        "vm.compact_unevictable_allowed": 0_i64,
                    },
                },
            },
            "systemd": nix_record! {
                "packages": NixValue::list([agent]),
                "services": nix_record! {
                    "qubes-gui-agent": nix_record! {
                        // Upstream qubes-gui-runuser has a 256-byte PATH buffer.
                        "environment": nix_record! {
                            "ENV_PATH": "/run/current-system/sw/bin:/run/wrappers/bin",
                        },
                        "enable": true,
                        "wantedBy": NixValue::list(["multi-user.target".into()]),
                        "requires": NixValue::list([
                            "qubes-db.service".into(),
                            "airlock-qubes-rw-init.service".into(),
                        ]),
                        "after": NixValue::list([
                            "qubes-db.service".into(),
                            "qubes-qrexec-agent.service".into(),
                            "airlock-qubes-rw-init.service".into(),
                            "systemd-user-sessions.service".into(),
                        ]),
                        // The GUI VM's vchan backend can start after the application VM.
                        "unitConfig": nix_record! {
                            "StartLimitIntervalSec": 0_i64,
                        },
                        "serviceConfig": nix_record! {
                            "Restart": "on-failure",
                            "RestartSec": "5s",
                        },
                        "path": packages(&[
                            "coreutils",
                            "gnused",
                            "qubes-core-agent-linux",
                            "qubes-core-qubesdb",
                            "shadow",
                            "util-linux",
                            "systemd",
                            "dbus",
                            "xsetroot",
                        ]),
                    },
                },
            },
            "security": nix_record! {
                "pam": nix_record! {
                    "services": nix_record! {
                        "qubes-gui-agent": nix_record! {
                            "rootOK": true,
                            "startSession": true,
                        },
                    },
                },
            },
        }
    })
}
