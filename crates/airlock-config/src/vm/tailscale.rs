//! Keep each opted-in application VM's Tailscale identity in its own private
//! volume. Enrollment, SSH access and firewall policy remain explicit VM choices.

use rusix::{
    interop::raw::NixValue,
    nix_record, nix_text,
    nixos::{ContextualModule, ModuleBody},
};

/// Bind daemon state after private storage is ready, only when Tailscale is enabled.
pub(super) fn module() -> NixValue {
    ContextualModule::new(|context| {
        let private_ready = NixValue::list(["airlock-qubes-rw-init.service".into()]);
        let state_ready = NixValue::list(["airlock-agent-tailscale-state.service".into()]);
        let hostname = context
            .lib
            .clone()
            .select("escapeShellArg")
            .call(context.config.clone().select("networking.hostName"));
        let configuration = nix_record! {
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
