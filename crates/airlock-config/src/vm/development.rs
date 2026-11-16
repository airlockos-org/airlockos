//! Provide the development VM's persistent workspace and development-only remote access.

use super::{WorkerRole, worker};
use airlock_build::{Application, Workspace};
use rusix::{
    interop::{
        NixPath,
        raw::{NixRepresentation, NixValue},
    },
    nix_record, nix_text,
    nixos::{ContextualModule, ModuleBody},
};

/// Install workspace initialization, Tailnet access and the developer's private build tools.
pub(super) fn module() -> NixValue {
    ContextualModule::new(|context| {
        let cfg = context.config.select("airlock.qubeGuest");
        let user = cfg.clone().select("user");
        let pkgs = &context.pkgs;
        let package = |name: &str| pkgs.clone().select(name);
        let packages = |names: &[&str]| NixValue::list(names.iter().map(|name| package(name)));
        let quote = |value| context.lib.clone().select("escapeShellArg").call(value);
        let state: NixValue =
            nix_text!("/home/{user}/.local/state/airlock", user = user.clone()).into();
        let private_ready = NixValue::list(["airlock-qubes-rw-init.service".into()]);
        let workspace_ready = NixValue::list(["airlock-usr-assistant-workspace.service".into()]);
        let oneshot = nix_record! {
            "Type": "oneshot",
            "RemainAfterExit": true,
        };
        let as_user = oneshot.clone().merge_attrs(nix_record! {
            "User": user.clone(),
        });
        let native_workspace = Workspace::new(NixPath::from_source_text(
            package("airlockAppsSource").to_text().into_expr::<String>(),
        ));
        let file = |relative| native_workspace.file(relative).snapshot();
        let native = Application::VmService
            .build(pkgs, &native_workspace)
            .as_expression();
        let tailscale_path = super::tailscale::path(pkgs, &context.lib);
        let tailscale_up = airlock_build::native::command(
            pkgs,
            "airlock-dev-tailscale-up",
            nix_record! {
                "program": nix_text!("{native}/bin/airlock-vm-service", native = native.clone()),
                "args": NixValue::list(["runtime".into(), "tailscale-up".into()]),
                "prefix_env": nix_record! { "PATH": tailscale_path.clone() },
            },
            false,
        );

        let configuration = nix_record! {
            "services": nix_record! {
                "tailscale": nix_record! {
                    "enable": true,
                    "extraUpFlags": NixValue::list(["--ssh".into()]),
                },
            },
            "airlock": nix_record! {
                "qubeGuest": nix_record! {
                    "configRepoPath": context
                        .lib
                        .clone()
                        .select("mkDefault")
                        .call(nix_text!("/home/{user}/airlockos-machine", user = user.clone())),
                    // This privileged development VM is the Tailnet route to the lab host.
                    "allowQrexecUserSelection": true,
                },
                "devDom0Terminal": nix_record! {
                    "guest": nix_record! {
                        "enable": true,
                    },
                },
            },
            "networking": nix_record! {
                "firewall": nix_record! {
                    "interfaces": nix_record! {
                        "tailscale0": nix_record! {
                            "allowedTCPPorts": NixValue::list([22_i64.into()]),
                        },
                    },
                },
            },
            "environment": nix_record! {
                "systemPackages": packages(&[
                    "codex",
                    "gnome-console",
                    "gnumake",
                    "jq",
                    "python3",
                    "ripgrep",
                    "uv",
                    "zellij",
                ]),
                "sessionVariables": nix_record! {
                    "CODEX_HOME": cfg.clone().select("codexHome"),
                    "AIRLOCK_DATA_ROOT": state.clone(),
                    "AIRLOCK_LOG_DIR": nix_text!("{state}/logs", state = state),
                    "AIRLOCK_NIX_ROOT": cfg.clone().select("configNixStoreRoot"),
                    // The installed wrapper selects the admitted overlay store.
                    "AIRLOCK_NIX_CONFIGURED": "1",
                    "UV_PYTHON": nix_text!("{python}/bin/python3", python = package("python3")),
                    "UV_PYTHON_DOWNLOADS": "never",
                },
                "etc": nix_record! {
                    "airlock/usr-assistant/AGENTS.md": nix_record! {
                        "source": file("airlock-config/assets/usr-assistant/AGENTS.md"),
                    },
                    "airlock/usr-assistant/home-AGENTS.md": nix_record! {
                        "source": file("airlock-config/assets/usr-assistant/home-AGENTS.md"),
                    },
                    "airlock/usr-assistant/operations.md": nix_record! {
                        "source": file("airlock-config/assets/usr-assistant/operations.md"),
                    },
                    "qubes-rpc/airlock.DevTailscaleUp": nix_record! {
                        "source": tailscale_up,
                        "mode": "symlink",
                    },
                    "qubes/rpc-config/airlock.DevTailscaleUp": nix_record! {
                        "text": "force-user='root'\n",
                        "mode": "0444",
                    },
                },
            },
            "systemd": nix_record! {
                "services": nix_record! {
                    "airlock-usr-assistant-workspace": nix_record! {
                        "description": "Initialize persistent usr-assistant workspace and guidance",
                        "wantedBy": NixValue::list(["multi-user.target".into()]),
                        "requires": private_ready.clone(),
                        "after": private_ready,
                        "before": NixValue::list([
                            "airlock-machine-source-seed.service".into(),
                            "qubes-qrexec-agent.service".into(),
                        ]),
                        "path": packages(&["coreutils"]),
                        "script": nix_text!(
                            r#"
                        {native}/bin/airlock-vm-service runtime workspace \
                          {codex} /etc/airlock/usr-assistant/AGENTS.md \
                          {home} /etc/airlock/usr-assistant/home-AGENTS.md \
                          {repo}
                    "#,
                            native = native.clone(),
                            codex = quote(cfg.clone().select("codexHome")),
                            home = quote(nix_text!("/home/{user}", user = user).into()),
                            repo = quote(cfg.clone().select("configRepoPath")),
                        ),
                        "serviceConfig": as_user.clone(),
                    },
                    "airlock-usr-assistant-git-identity": nix_record! {
                        "description": "Initialize missing repository Git identity defaults",
                        "wantedBy": NixValue::list(["multi-user.target".into()]),
                        "requires": workspace_ready.clone(),
                        "after": NixValue::concat_lists([
                            workspace_ready,
                            NixValue::list(["airlock-machine-source-seed.service".into()]),
                        ]),
                        "before": NixValue::list(["qubes-qrexec-agent.service".into()]),
                        "path": packages(&["gitMinimal"]),
                        "script": nix_text!(
                            r#"
                        {native}/bin/airlock-vm-service runtime git-identity {repo}
                    "#,
                            native = native,
                            repo = quote(cfg.select("configRepoPath")),
                        ),
                        "serviceConfig": as_user,
                    },
                },
            },
        };

        ModuleBody::new(configuration)
            .key("airlock.vm.development")
            .import_value(super::app_gui::module())
            .import_value(super::tailscale::module())
            .import_value(worker::module(WorkerRole::Development))
            .import_value(worker::store(WorkerRole::Development))
            .import_value(worker::seed())
    })
    .into_expression()
}
