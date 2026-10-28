//! Compose the physical GNOME display and the existing nested Qubes display relay.
//! The relay retains its small X11 session; physical desktop policy belongs to the GNOME component.

use airlock_build::{Application, Workspace};
use airlock_sys_gui_service::authoring::{self, Sources};
use rusix::{
    interop::{
        NixExpression, NixPath,
        raw::{NixRepresentation, NixValue},
    },
    nix_record, nix_text,
    nixos::{ContextualModule, ModuleBody, ModuleContext},
};

/// Configure a GUI VM without moving display or input authority out of Qubes.
pub(super) fn module(source: &NixPath, workspace: &Workspace) -> NixValue {
    ContextualModule::new(|context| {
        let sources = Sources::new(workspace.root());
        let deployment = authoring::deployment(&context.pkgs, &sources);
        let vm_service = Application::VmService
            .build(&context.pkgs, workspace)
            .as_expression();
        let gui = Gui { context: &context };
        let configuration = deployment
            .package()
            .as_expression()
            .bind(|service| gui.configuration(service, vm_service.clone()));

        ModuleBody::new(gui.when(gui.setting("enable"), configuration))
            .key("airlock.vm.gui")
            .import_value(gui.options())
            .import_value(crate::input::module(source, workspace))
            .import_value(crate::dev_terminal::module())
    })
    .into_expression()
}

/// The GUI module's final NixOS settings and target package set.
struct Gui<'a> {
    /// Module context evaluated for this VM, independent of the host package set.
    context: &'a ModuleContext,
}

impl Gui<'_> {
    /// Select a display setting after the machine's modules have been merged.
    fn setting(&self, name: &str) -> NixValue {
        self.context
            .config
            .clone()
            .select("airlock.sysGuiGuest")
            .select(name)
    }

    /// Select an executable or library from this VM's packages.
    fn package(&self, name: &str) -> NixValue {
        self.context.pkgs.clone().select(name)
    }

    /// Collect target packages in declaration order.
    fn packages(&self, names: &[&str]) -> NixValue {
        NixValue::list(names.iter().map(|name| self.package(name)))
    }

    /// Delay a conditional definition until the NixOS fixed point is available.
    fn when(&self, condition: NixValue, value: NixValue) -> NixValue {
        self.context
            .lib
            .clone()
            .select("mkIf")
            .call(condition)
            .call(value)
    }

    /// Override upstream defaults where the Qubes display relay owns service startup.
    fn force(&self, value: impl Into<NixValue>) -> NixValue {
        self.context
            .lib
            .clone()
            .select("mkForce")
            .call(value.into())
    }

    /// Supply a setting that the machine's selected desktop may override normally.
    fn default(&self, value: impl Into<NixValue>) -> NixValue {
        self.context
            .lib
            .clone()
            .select("mkDefault")
            .call(value.into())
    }

    /// Select a list of packages or dependencies only when its capability is enabled.
    fn optional(&self, condition: NixValue, value: NixValue) -> NixValue {
        NixValue::if_else(condition, value, NixValue::list([]))
    }

    /// Build either an RPC executable file or an interactive command package.
    fn script(&self, name: &str, text: NixValue, bin: bool) -> NixValue {
        airlock_build::native::writer(&self.context.pkgs, bin)
            .call(name)
            .call(text)
    }

    /// Declare only the display controls consumed by the GUI service composition.
    fn options(&self) -> NixValue {
        let lib = &self.context.lib;
        let enable = |description| lib.clone().select("mkEnableOption").call(description);
        let option = |kind: NixValue, default: NixValue, description: &str| {
            lib.clone().select("mkOption").call(nix_record! {
                "type": kind,
                "default": default,
                "description": description,
            })
        };

        nix_record! {
            "options": nix_record! {
                "airlock": nix_record! {
                    "sysGuiGuest": nix_record! {
                        "enable": enable("the Airlock GUI VM"),
                        "displayMode": option(
                            lib.clone()
                                .select("types.enum")
                                .call(strings(&["hybrid", "physical-amd-lab"])),
                            "hybrid".into(),
                            "Qubes relay or physical AMD display ownership.",
                        ),
                        "physicalDesktopOnBoot": enable("automatic physical desktop login after VM boot"),
                        "enableXfce": option(
                            lib.clone().select("types.bool"),
                            true.into(),
                            "X11 desktop session used by the nested Qubes relay.",
                        ),
                        "applicationMenus": nix_record! {
                            "enable": option(
                                lib.clone().select("types.bool"),
                                true.into(),
                                "Discover applications in VMs assigned to this GUI VM.",
                            ),
                        },
                        "defaultApplicationVM": option(
                            lib.clone()
                                .select("types.nullOr")
                                .call(lib.clone().select("types.str")),
                            "usr-home".into(),
                            "VM handling web links; null selects local applications.",
                        ),
                    },
                },
            },
        }
    }

    /// Share the application launcher between menu synchronization and web-link routing.
    fn configuration(&self, service: NixValue, vm_service: NixValue) -> NixValue {
        let launcher = self.script(
            "airlock-launch-qube-app",
            crate::commands::contract(
                &self.context.pkgs,
                "app-launcher",
                [
                    ("service", service.clone()),
                    (
                        "workspace",
                        NixValue::if_else(
                            self.context
                                .config
                                .clone()
                                .select("services.desktopManager.gnome.enable"),
                            "--workspace",
                            "",
                        ),
                    ),
                ],
            ),
            true,
        );

        launcher.bind(|launcher| self.install(service, vm_service, launcher))
    }

    /// Install GUI packages, display services, Qubes RPCs and application refresh timers.
    fn install(&self, service: NixValue, vm_service: NixValue, launcher: NixValue) -> NixValue {
        let hybrid = self.setting("displayMode").equals("hybrid");
        let agent = self.package("qubes-gui-agent-linux");
        let login = self.script(
            "airlock-gui-login-xserver",
            crate::commands::contract(
                &self.context.pkgs,
                "login-xserver",
                [
                    ("coreutils", self.package("coreutils")),
                    ("bash", self.package("bash")),
                    ("xdpyinfo", self.package("xdpyinfo")),
                    ("daemon", self.package("qubes-gui-daemon")),
                    ("xserver", self.package("xorg-server")),
                    ("utilLinux", self.package("util-linux")),
                ],
            ),
            false,
        );
        let physical = self.script(
            "airlock-gui-physical-xserver",
            crate::commands::contract(
                &self.context.pkgs,
                "physical-xserver",
                [
                    ("daemon", self.package("qubes-gui-daemon")),
                    ("xserver", self.package("xorg-server")),
                ],
            ),
            false,
        );
        let sync = self.script(
            "airlock-sync-qube-appmenus",
            nix_record! {
                "program": nix_text!("{service}/bin/airlock-sys-gui-service", service = service.clone()),
                "args": strings(&["sync-appmenus"]),
                "argument_count": 1_i64,
            },
            true,
        );
        let poweroff = self.context.lib.clone().select("hiPrio").call(self.script(
            "xfce4-session-logout",
            crate::commands::contract(
                &self.context.pkgs,
                "poweroff-session-action",
                [
                    (
                        "admin",
                        self.package("python3.pkgs.qubes-core-admin-client"),
                    ),
                    ("xfceSession", self.package("xfce4-session")),
                ],
            ),
            true,
        ));
        let packages = NixValue::concat_lists([
            self.packages(&[
                "qubes-gui-agent-linux",
                "qubes-gui-daemon",
                "qubes-manager",
                "qubes-artwork",
                "python3.pkgs.qubes-core-admin-client",
            ]),
            self.packages(&[
                "python3.pkgs.qubes-desktop-linux-manager",
                "xdpyinfo",
                "xinit",
                "xorgserver",
                "xdotool",
                "xterm",
            ]),
            NixValue::list([
                launcher.clone(),
                sync,
                airlock_build::desktop::icons(&self.context.pkgs).as_expression(),
                airlock_build::desktop::identity(
                    &self.context.pkgs,
                    airlock_build::desktop::DESKTOP_ID,
                    "AirlockOS",
                    airlock_build::desktop::DESKTOP_ID,
                ),
            ]),
            self.optional(
                self.setting("enableXfce"),
                NixValue::list([
                    self.package("xfce4-session"),
                    poweroff,
                    self.package("xfce4-panel"),
                    self.package("xfdesktop"),
                ]),
            ),
            self.optional(
                self.setting("applicationMenus.enable"),
                NixValue::list([service.clone()]),
            ),
            self.optional(
                self.setting("defaultApplicationVM")
                    .equals(NixValue::null())
                    .equals(false),
                self.web_links(&launcher),
            ),
        ]);
        let qubes_gui = self.optional(hybrid.clone(), strings(&["qubes-gui-agent.service"]));
        let physical_boot = hybrid
            .clone()
            .equals(false)
            .and(self.setting("physicalDesktopOnBoot"));

        let login_gate = physical_boot.clone().and(
            self.context
                .config
                .clone()
                .select("airlock.inputProxy.receiver.enable"),
        );
        let input_startup = self.script(
            "airlock-input-startup",
            crate::commands::contract(
                &self.context.pkgs,
                "input-startup",
                [("service", vm_service.clone())],
            ),
            false,
        );
        let input_dependency = self.optional(
            login_gate.clone(),
            strings(&["airlock-input-startup.service"]),
        );

        nix_record! {
            "airlock": nix_record! {
                "inputProxy": nix_record! {
                    "receiver": nix_record! {
                        "enable": self.default(hybrid.clone().equals(false)),
                    },
                },
            },
            "boot": nix_record! {
                "kernelModules": strings(&["xen-gntalloc", "xen-gntdev", "xen-evtchn"]),
            },
            "environment": nix_record! {
                "systemPackages": packages,
                "etc": self.files(&service, &agent, &hybrid),
            },
            "services": nix_record! {
                "udev": nix_record! {
                    "packages": NixValue::list([agent.clone()]),
                },
                "xserver": nix_record! {
                    "enable": true,
                    "desktopManager": nix_record! {
                        "xfce": nix_record! {
                            "enable": self.setting("enableXfce"),
                        },
                        "xterm": nix_record! {
                            "enable": false,
                        },
                    },
                    "displayManager": nix_record! {
                        "xserverBin": self
                            .context
                            .lib
                            .clone()
                            .select("mkOverride")
                            .call(50_i64)
                            .call(NixValue::if_else(hybrid.clone(), login, physical)),
                        "xserverArgs": self.when(hybrid.clone(), self.force(NixValue::list([]))),
                        "lightdm": nix_record! {
                            "enable": self.default(true),
                            "extraConfig": self.when(
                                hybrid.clone(),
                                nix_text!(r#"
                                logind-check-graphical=false
                                minimum-vt=8
                            "#)
                                .into(),
                            ),
                            "extraSeatDefaults": self.when(
                                hybrid.clone(),
                                nix_text!(r#"
                                type=xlocal
                                xserver-share=true
                            "#)
                                .into(),
                            ),
                        },
                    },
                },
                "displayManager": nix_record! {
                    "defaultSession": "xfce",
                    "autoLogin": nix_record! {
                        "enable": false,
                    },
                },
            },
            "systemd": nix_record! {
                "defaultUnit": self.when(
                    hybrid.clone().equals(false),
                    self.force(NixValue::if_else(
                        self.setting("physicalDesktopOnBoot"),
                        "graphical.target",
                        "multi-user.target",
                    )),
                ),
                "packages": NixValue::list([agent]),
                "targets": nix_record! {
                    // GDM is activated only by dom0's fixed initialization handoff.
                    "airlock-input-initialized": self.when(login_gate.clone(), nix_record! {
                        "wants": strings(&["display-manager.service"]),
                    }),
                },
                "services": nix_record! {
                    // Reserve tty1 for startup progress and the greeter; other VTs keep recovery consoles.
                    "getty@tty1": nix_record! {
                        "enable": self.when(login_gate.clone(), false.into()),
                    },
                    "airlock-input-startup": self.when(login_gate.clone(), nix_record! {
                        "description": "Show startup while dom0 initializes input forwarding",
                        "wantedBy": strings(&["graphical.target"]),
                        "before": strings(&["display-manager.service"]),
                        "after": strings(&["systemd-udev-trigger.service"]),
                        "partOf": strings(&["display-manager.service"]),
                        "serviceConfig": nix_record! {
                            "Type": "oneshot",
                            "RemainAfterExit": true,
                            "ExecStartPre": nix_text!("-{kbd}/bin/chvt 1", kbd = self.package("kbd")),
                            "ExecStart": input_startup.to_text(),
                            "TimeoutStartSec": 15_i64,
                        },
                    }),
                    "display-manager": nix_record! {
                        "wantedBy": self.force(self.optional(
                            physical_boot.and(login_gate.equals(false)),
                            strings(&["graphical.target"]),
                        )),
                        "requires": NixValue::concat_lists([
                            strings(&["airlock-qubes-rw-init.service", "systemd-user-sessions.service"]),
                            qubes_gui.clone(),
                            input_dependency.clone(),
                        ]),
                        "after": NixValue::concat_lists([
                            strings(&["airlock-qubes-rw-init.service"]),
                            qubes_gui,
                            input_dependency,
                        ]),
                        "serviceConfig": nix_record! {
                            "ExecStartPre": nix_text!(
                                "{service}/bin/airlock-vm-service runtime private-storage-check",
                                service = vm_service,
                            ),
                        },
                    },
                    "qubes-gui-agent": nix_record! {
                        "enable": hybrid.clone(),
                        "wantedBy": strings(&["multi-user.target"]),
                        "after": strings(&[
                            "qubes-db.service",
                            "qubes-qrexec-agent.service",
                            "systemd-user-sessions.service",
                        ]),
                        "unitConfig": nix_record! {
                            "ConditionPathExists": self.force(""),
                        },
                        "path": self.packages(&[
                            "coreutils",
                            "gnused",
                            "qubes-core-agent-linux",
                            "qubes-core-qubesdb",
                            "shadow",
                            "util-linux",
                            "systemd",
                        ]),
                    },
                },
                "user": self.menu_refresh(&service),
                "tmpfiles": nix_record! {
                    "rules": NixValue::concat_lists([
                        strings(&[
                            "d /var/log/qubes 2775 root qubes - -",
                            "f /run/qubes-service/guivm 0644 root root - -",
                            "f /run/qubes-service-environment 0644 root root - -",
                        ]),
                        self.optional(
                            hybrid,
                            strings(&["f /run/qubes-service/guivm-gui-agent 0644 root root - -"]),
                        ),
                    ]),
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
            "xdg": nix_record! {
                "mime": nix_record! {
                    "defaultApplications": self.when(
                        self.setting("defaultApplicationVM")
                            .equals(NixValue::null())
                            .equals(false),
                        nix_record! {
                            "x-scheme-handler/http": "airlock-open-url.desktop",
                            "x-scheme-handler/https": "airlock-open-url.desktop",
                        },
                    ),
                },
            },
        }
    }

    /// Refresh menus within the authenticated desktop session rather than a root system service.
    fn menu_refresh(&self, service: &NixValue) -> NixValue {
        nix_record! {
            "services": nix_record! {
                "airlock-application-menus": self.when(
                    self.setting("applicationMenus.enable"),
                    nix_record! {
                        "description": "Refresh applications from VMs assigned to this GUI VM",
                        "after": strings(&["graphical-session.target"]),
                        "partOf": strings(&["graphical-session.target"]),
                        "serviceConfig": nix_record! {
                            "Type": "oneshot",
                            "ExecStart": nix_text!(
                                "{service}/bin/airlock-sys-gui-service menus reconcile",
                                service = service.clone(),
                            ),
                            "TimeoutStartSec": "10min",
                            "KillMode": "control-group",
                        },
                    },
                ),
            },
            "timers": nix_record! {
                "airlock-application-menus": self.when(
                    self.setting("applicationMenus.enable"),
                    nix_record! {
                        "wantedBy": strings(&["graphical-session.target"]),
                        "partOf": strings(&["graphical-session.target"]),
                        "timerConfig": nix_record! {
                            "OnActiveSec": "2s",
                            "OnUnitInactiveSec": "30s",
                            "AccuracySec": "1s",
                        },
                    },
                ),
            },
        }
    }

    /// Route web links through the selected VM's normal MIME handler.
    fn web_links(&self, launcher: &NixValue) -> NixValue {
        let target = self.setting("defaultApplicationVM");
        let target = NixValue::if_else(target.clone().equals(NixValue::null()), "", target);
        let command = self.script(
            "airlock-open-url",
            crate::commands::contract(
                &self.context.pkgs,
                "open-url-launcher",
                [("launcher", launcher.clone()), ("target", target)],
            ),
            true,
        );
        let desktop = self.package("makeDesktopItem").call(nix_record! {
            "name": "airlock-open-url",
            "desktopName": "Open web link",
            "exec": "airlock-open-url %u",
            "icon": "web-browser",
            "noDisplay": true,
            "mimeTypes": strings(&["x-scheme-handler/http", "x-scheme-handler/https"]),
        });

        NixValue::list([command, desktop])
    }

    /// Supply the icon receiver's Admin API imports at the session boundary.
    /// Adding the client to the daemon package itself would create a cycle,
    /// because the upstream client already depends on that daemon.
    fn icon_receiver(&self) -> NixValue {
        self.script(
            "airlock-qubes-icon-receiver",
            nix_record! {
                "program": nix_text!(
                    "{daemon}/lib/qubes/icon-receiver",
                    daemon = self.package("qubes-gui-daemon"),
                ),
                "env": nix_record! {
                    "PYTHONPATH": self.package("python3.pkgs.makePythonPath")
                        .call(NixValue::list([self.package("python3.pkgs.qubes-core-admin-client")])),
                },
                "prefix_env": nix_record! {
                    "PATH": self.context.lib.clone().select("makeBinPath").call(
                        self.packages(&["python3.pkgs.qubes-core-qrexec.domU"]),
                    ),
                },
            },
            false,
        )
    }

    /// Install Qubes display protocol adapters and their authenticated-session restrictions.
    fn files(&self, service: &NixValue, agent: &NixValue, hybrid: &NixValue) -> NixValue {
        let user = self.context.config.clone().select("airlock.qubeGuest.user");
        let force_user: NixValue = nix_text!(
            r#"
            force-user='{user}'
        "#,
            user = user,
        )
        .into();
        let receive = self.script(
            "airlock-receive-qube-appmenus",
            crate::commands::contract(
                &self.context.pkgs,
                "receive-appmenus",
                [
                    ("coreutils", self.package("coreutils")),
                    ("service", service.clone()),
                ],
            ),
            false,
        );
        let session = self.script(
            "airlock-gui-login-session",
            crate::commands::contract(
                &self.context.pkgs,
                "gui-session",
                [
                    ("utilLinux", self.package("util-linux")),
                    ("systemd", self.package("systemd")),
                    ("coreutils", self.package("coreutils")),
                ],
            ),
            false,
        );
        let xfce = self.script(
            "airlock-qubes-xfce-session",
            nix_text!(
                r#"
            export XSESSION={xfce}/bin/xfce4-session
            exec {agent}/bin/qubes-session
        "#,
                xfce = self.package("xfce4-session"),
                agent = agent.clone(),
            )
            .into(),
            false,
        );
        let mut files = vec![
            (
                "xdg/autostart/qubes-icon-receiver.desktop",
                nix_record! {
                    "text": nix_text!(r#"
                        [Desktop Entry]
                        Name=Qubes window icon receiver
                        Comment=Receives and updates Qubes window icons
                        Icon=qubes
                        Exec={receiver}
                        Terminal=false
                        Type=Application
                    "#, receiver = self.icon_receiver()),
                },
            ),
            (
                "qubes-rpc/qubes.SyncAppMenus",
                nix_record! {
                    "source": receive,
                    "mode": "symlink",
                },
            ),
            (
                "qubes/rpc-config/qubes.SyncAppMenus",
                nix_record! {
                    "text": force_user.clone(),
                    "mode": "0444",
                },
            ),
            (
                "qubes/rpc-config/qubes.SetMonitorLayout",
                nix_record! {
                    "text": force_user,
                },
            ),
            (
                "X11/xinit/xinitrc",
                nix_record! {
                    "source": NixValue::if_else(
                        self.setting("enableXfce"),
                        xfce,
                        nix_text!("{agent}/bin/qubes-session", agent = agent.clone()),
                    ),
                },
            ),
            (
                "qubes-rpc/qubes.GuiVMSession",
                self.when(
                    hybrid.clone(),
                    nix_record! {
                        "source": session,
                    },
                ),
            ),
        ];
        for path in [
            "X11/xorg-qubes.conf.template",
            "qubes-rpc/qubes.SetMonitorLayout",
            "qubes/rpc-config/qubes.GuiVMSession",
        ] {
            files.push((
                path,
                nix_record! {
                    "source": nix_text!("{agent}/etc/{path}", agent = agent.clone(), path = path),
                },
            ));
        }
        for path in [
            "qubes-rpc/qubes.WindowIconUpdater",
            "qubes/guid.conf",
            "qubes/rpc-config/qubes.WindowIconUpdater",
            "xdg/autostart/qubes-screen-layout-watches.desktop",
        ] {
            files.push((
                path,
                nix_record! {
                    "source": nix_text!(
                        "{daemon}/etc/{path}",
                        daemon = self.package("qubes-gui-daemon"),
                        path = path,
                    ),
                },
            ));
        }

        NixValue::record(files)
    }
}

/// Preserve the declaration order of static service dependencies and desktop categories.
fn strings(values: &[&str]) -> NixValue {
    NixValue::list(values.iter().map(|value| (*value).into()))
}
