//! Inspect desktop preference installation without realizing VM images or service packages.

use super::*;

/// Project real machine configurations, including headless VMs and the publisher's fixed RPC.
pub(super) fn installation(inputs: NixValue) -> NixValue {
    NixValue::builtin("getFlake")
        .call(inputs.select("root").to_text())
        .bind(|flake| {
            let configurations = flake.select("nixosConfigurations");
            let domains = [
                "sys-gui",
                "usr-home",
                "usr-assistant",
                "sys-ctrl",
                "sys-net",
            ];
            NixValue::record(domains.map(|name| {
                let config = configurations
                    .clone()
                    .select_segments([format!("airlock-domain-{name}"), "config".into()]);
                let etc = config.clone().select("environment.etc");
                (
                    name,
                    NixValue::record([
                        (
                            "unit",
                            config
                                .clone()
                                .select("systemd.user.services")
                                .attr_or("airlock-desktop-preferences", NixValue::null()),
                        ),
                        (
                            "binding",
                            etc.clone()
                                .attr_or("airlock/desktop-preferences.json", NixValue::null()),
                        ),
                        (
                            "rpc",
                            etc.attr_or(
                                "qubes/rpc-config/airlock.DesktopPreferences",
                                NixValue::null(),
                            ),
                        ),
                        ("user", config.clone().select("airlock.qubeGuest.user")),
                        ("portal", config.clone().select("xdg.portal.enable")),
                        ("environment", config.select("environment.sessionVariables")),
                    ]),
                )
            }))
        })
}
