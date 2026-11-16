//! Keep each opted-in application VM's Tailscale identity in its own private
//! volume and expose a fixed local enrollment operation. Enabling Tailscale,
//! SSH access and firewall policy remain explicit VM choices.

use airlock_build::Application;
use rusix::{
    interop::raw::{NixRepresentation, NixValue},
    nix_record, nix_text,
    nixos::{ContextualModule, ModuleBody},
};

/// Supply only the upstream tools used by bounded connectivity checks and login.
pub(super) fn path(pkgs: &NixValue, lib: &NixValue) -> NixValue {
    lib.clone().select("makeBinPath").call(NixValue::list(
        ["coreutils", "glibc.bin", "iproute2", "curl", "tailscale"]
            .map(|name| pkgs.clone().select(name)),
    ))
}

/// Bind private daemon state and install local enrollment only when Tailscale is enabled.
pub(super) fn module() -> NixValue {
    ContextualModule::new(|context| {
        let pkgs = &context.pkgs;
        let native = Application::VmService
            .build(pkgs, &airlock_build::native::workspace(pkgs))
            .as_expression();
        // Sudo admits exactly this fixed operation without arguments. It does
        // not grant arbitrary tailscale flags, a root shell or qrexec authority.
        let enrollment_package = airlock_build::native::command(
            pkgs,
            "airlock-tailscale-enroll",
            nix_record! {
                "program": nix_text!("{native}/bin/airlock-vm-service", native = native.clone()),
                "args": NixValue::list(["runtime".into(), "tailscale-up-local".into()]),
                "prefix_env": nix_record! { "PATH": path(pkgs, &context.lib) },
            },
            true,
        );
        let local_enrollment: NixValue = nix_text!(
            "{package}/bin/airlock-tailscale-enroll", package = enrollment_package.clone(),
        ).into();
        let enrollment_window = airlock_build::native::writer(pkgs, true)
            .call("airlock-connect-tailscale")
            .call(crate::commands::contract(
                pkgs,
                "tailscale-window",
                [
                    ("console", pkgs.clone().select("gnome-console")),
                    ("service", native),
                    ("enrollment", local_enrollment.clone()),
                    ("title", nix_text!("Connect Tailscale — {hostname}", hostname = context.config.clone().select("networking.hostName")).into()),
                ],
            ));
        let enrollment_desktop = pkgs.clone().select("makeDesktopItem").call(nix_record! {
            "name": "airlock-tailscale",
            "desktopName": "Connect Tailscale",
            "comment": "Connect this VM to Tailscale and display the login URL",
            "exec": nix_text!("{window}/bin/airlock-connect-tailscale", window = enrollment_window.clone()),
            "icon": airlock_build::desktop::ICON_NAME,
            "startupWMClass": airlock_build::desktop::TAILSCALE_ID,
            "categories": NixValue::list(["System".into(), "Network".into()]),
        });
        let private_ready = NixValue::list(["airlock-qubes-rw-init.service".into()]);
        let state_ready = NixValue::list(["airlock-agent-tailscale-state.service".into()]);
        let hostname = context
            .lib
            .clone()
            .select("escapeShellArg")
            .call(context.config.clone().select("networking.hostName"));
        let configuration = nix_record! {
            "security": nix_record! {
                "sudo": nix_record! {
                    "extraRules": NixValue::list([nix_record! {
                        "users": NixValue::list([context.config.clone().select("airlock.qubeGuest.user")]),
                        "runAs": "root",
                        "commands": NixValue::list([nix_record! {
                            // Empty sudo arguments forbid all caller-supplied options.
                            "command": nix_text!(r#"{enrollment} """#, enrollment = local_enrollment.clone()),
                            "options": NixValue::list(["NOPASSWD".into()]),
                        }]),
                    }]),
                },
            },
            "environment": nix_record! {
                "systemPackages": NixValue::list([enrollment_window, enrollment_desktop, enrollment_package]),
            },
            "fonts": nix_record! {
                "packages": NixValue::list([pkgs.clone().select("dejavu_fonts")]),
            },
            "systemd": nix_record! {
                "services": nix_record! {
                    "airlock-agent-tailscale-state": nix_record! {
                        "wantedBy": NixValue::list(["multi-user.target".into()]),
                        "requires": private_ready.clone(),
                        "after": private_ready,
                        "before": NixValue::list(["tailscaled.service".into()]),
                        "serviceConfig": nix_record! {
                            "Type": "oneshot",
                            "RemainAfterExit": true,
                        },
                        "script": nix_text!(
                            r#"
                            {coreutils}/bin/install -d -m 0700 /rw/config/tailscale
                            "#,
                            coreutils = context.pkgs.clone().select("coreutils"),
                        ),
                    },
                    "tailscaled": nix_record! {
                        "requires": state_ready.clone(),
                        "after": state_ready,
                        "serviceConfig": nix_record! {
                            "BindPaths": NixValue::list([
                                "/rw/config/tailscale:/var/lib/tailscale".into()
                            ]),
                            "ExecStartPost": NixValue::list([nix_text!(
                                "{tailscale}/bin/tailscale set --hostname={hostname}",
                                tailscale = context.pkgs.select("tailscale"),
                                hostname = hostname,
                            ).into()]),
                        },
                    },
                },
            },
        };

        ModuleBody::new(
            context
                .lib
                .select("mkIf")
                .call(context.config.select("services.tailscale.enable"))
                .call(configuration),
        )
        .key("airlock.vm.tailscale-state")
    })
    .into_expression()
}
