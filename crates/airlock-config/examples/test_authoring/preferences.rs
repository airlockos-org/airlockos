//! Inspect desktop preference installation without realizing VM images or service packages.

use super::*;

/// Project real machine configurations, including headless VMs and the publisher's fixed RPC.
pub(super) fn installation(inputs: NixValue) -> NixValue {
    NixValue::builtin("getFlake")
        .call(inputs.select("root").to_text())
        .bind(|flake| {
            // Public configuration aliases also expose nested lab VMs. Inspect
            // the actual physical-machine entries for every identity instead.
            let entries = flake
                .clone()
                .select("lib.machineGuestEntries")
                .call("x86_64-linux");
            let domains = [
                "sys-gui",
                "usr-home",
                "usr-assistant",
                "sys-ctrl",
                "sys-net",
            ];
            let mut report = domains
                .map(|name| {
                    let config = entries.clone().select(name).select("configuration.config");
                    let etc = config.clone().select("environment.etc");
                    (
                        name,
                        NixValue::record([
                            (
                                "unit",
                                config
                                    .clone()
                                    .select("systemd.user.services")
                                    .attr_or("airlock-desktop-preferences", NixValue::null())
                                    .bind(|unit| {
                                        NixValue::if_else(
                                            unit.clone().equals(NixValue::null()),
                                            NixValue::null(),
                                            // Unset optional NixOS unit options have no value to serialize.
                                            NixValue::record(
                                                [
                                                    "wantedBy",
                                                    "partOf",
                                                    "after",
                                                    "environment",
                                                    "serviceConfig",
                                                ]
                                                .map(|field| (field, unit.clone().select(field))),
                                            ),
                                        )
                                    }),
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
                })
                .to_vec();
            let packages =
                flake.select("nixosConfigurations.machine.config.virtualisation.qubes.packages");
            let policy = NixValue::builtin("head")
                .call(
                    NixValue::builtin("filter")
                        .call(NixValue::function(|package| {
                            package
                                .select("name")
                                .equals("43-airlock-desktop-preferences.policy")
                        }))
                        .call(packages),
                )
                .select("text");
            report.push(("policy", policy));
            NixValue::record(report)
        })
}
