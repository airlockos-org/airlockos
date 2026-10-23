//! Rust-authored fixtures evaluated by the native integration suite.

use super::*;
use rusix::nix_text;

/// Inspect evaluated configuration for test icon rpc selects largest suitable packaged bitmap.
pub(super) fn bitmap_icons(inputs: NixValue) -> NixValue {
    NixValue::builtin("getFlake")
        .call(NixValue::concat_text([inputs
            .clone()
            .select("root")
            .to_text()]))
        .bind(|f| {
            f.clone()
                .select_segments(["nixosConfigurations", "airlock-domain-usr-home", "config"])
                .bind(live_vm_interfaces_bitmap_icons_body)
        })
}

/// Inspect evaluated configuration for test icon rpc renders complex application svgs.
pub(super) fn svg_icons(inputs: NixValue) -> NixValue {
    NixValue::builtin("getFlake")
        .call(NixValue::concat_text([inputs
            .clone()
            .select("root")
            .to_text()]))
        .bind(|f| {
            f.clone()
                .select_segments(["nixosConfigurations", "airlock-domain-usr-home", "config"])
                .bind(|cfg| {
                    cfg.clone()
                        .select_segments(["nixpkgs", "pkgs"])
                        .bind(|pkgs| {
                            cfg.clone()
                                .select_segments([
                                    "environment",
                                    "etc",
                                    "qubes-rpc/qubes.GetImageRGBA",
                                    "source",
                                ])
                                .bind(|handler| {
                                    live_vm_interfaces_svg_icons_body(handler, pkgs.clone())
                                })
                        })
                })
        })
}

/// Inspect evaluated configuration for interfaces.
pub(super) fn interfaces(inputs: NixValue) -> NixValue {
    NixValue::builtin("getFlake")
        .call(NixValue::concat_text([inputs
            .clone()
            .select("root")
            .to_text()]))
        .bind(|f| {
            NixValue::function(|name| {
                NixValue::function(|packages| {
                    NixValue::builtin("head").call(
                        NixValue::builtin("filter")
                            .call(NixValue::function(|p| {
                                p.clone()
                                    .attr_or("pname", p.clone().select_segments(["name"]))
                                    .equals(name.clone())
                            }))
                            .call(packages.clone()),
                    )
                })
            })
            .bind(|find| {
                f.clone()
                    .select_segments(["nixosConfigurations", "airlock-domain-sys-gui", "config"])
                    .bind(|gui| {
                        f.clone()
                            .select_segments([
                                "nixosConfigurations",
                                "machine",
                                "config",
                                "specialisation",
                                "usb-lab",
                                "configuration",
                            ])
                            .bind(|host| {
                                live_vm_interfaces_interfaces_2(host, find.clone(), gui.clone())
                            })
                    })
            })
        })
}

/// Build the live vm interfaces test icon rpc selects largest suitable packaged bitmap
/// contribution using the caller supplied deferred values.
fn live_vm_interfaces_bitmap_icons_body(cfg: NixValue) -> NixValue {
    cfg.clone()
        .select_segments(["nixpkgs", "pkgs"])
        .bind(|pkgs| {
            cfg.clone()
                .select_segments([
                    "environment",
                    "etc",
                    "qubes-rpc/qubes.GetImageRGBA",
                    "source",
                ])
                .bind(|handler| {
                    pkgs.clone()
                        .select_segments(["runCommand"])
                        .call(NixValue::from("airlock-icon-size-selection"))
                        .call(field(
                            ["XDG_DATA_DIRS"],
                            NixValue::concat_text([
                                pkgs.clone()
                                    .select_segments(["hicolor-icon-theme"])
                                    .to_text(),
                                NixValue::from("/share:"),
                                pkgs.clone().select_segments(["firefox"]).to_text(),
                                NixValue::from("/share"),
                            ]),
                        ))
                        .call(nix_text!(
                            r#"
                            printf 'xdgicon:firefox\n' | {handler} > "$out"
                            "#,
                            handler = handler,
                        ))
                })
        })
}

/// Build the live vm interfaces test icon rpc renders complex application svgs contribution using
/// the caller supplied deferred values.
fn live_vm_interfaces_svg_icons_body(handler: NixValue, pkgs: NixValue) -> NixValue {
    {
        let script = nix_text!(
            r#"
            mkdir -p "$out"
            printf '%s\n' "{contacts}/share/icons/hicolor/scalable/apps/org.gnome.Contacts.svg" | {handler} > "$out/contacts.rgba"
            printf '%s\n' "{logs}/share/icons/hicolor/scalable/apps/org.gnome.Logs.svg" | {handler} > "$out/logs.rgba"
            printf '%s\n' "{fonts}/share/icons/hicolor/scalable/apps/org.gnome.font-viewer.svg" | {handler} > "$out/fonts.rgba"
            export XDG_DATA_DIRS="{icons}/share:{hicolor}/share"
            printf '%s\n' 'xdgicon:org.airlockos.Airlock' | {handler} > "$out/airlock.rgba"
            printf '%s\n' 'xdgicon:org.airlockos.Airlock-symbolic' | {handler} > "$out/airlock-symbolic.rgba"
            printf '%s\n' 'xdgicon:org.airlockos.Setup' | {handler} > "$out/setup.rgba"
            printf '%s\n' 'xdgicon:org.airlock.ctrl' | {handler} > "$out/control.rgba"
            "#,
            contacts = pkgs.clone().select("gnome-contacts"),
            logs = pkgs.clone().select("gnome-logs"),
            fonts = pkgs.clone().select("gnome-font-viewer"),
            handler = handler,
            icons = airlock_build::desktop::icons(&pkgs).as_expression(),
            hicolor = pkgs.clone().select("hicolor-icon-theme"),
        );

        pkgs.clone()
            .select_segments(["runCommand"])
            .call(NixValue::from("airlock-complex-svg-icons"))
            .call(NixValue::record(Vec::<(&str, NixValue)>::new()))
            .call(script)
    }
}

/// Build the live vm interfaces interfaces contribution using the caller supplied deferred values.
fn live_vm_interfaces_interfaces_body(
    control_policy: NixValue,
    find: NixValue,
    gui: NixValue,
    host: NixValue,
    policy: NixValue,
) -> NixValue {
    {
        let field_sync = native_contract(NixValue::concat_text([
            find.clone()
                .call(NixValue::from("airlock-sync-qube-appmenus"))
                .call(
                    gui.clone()
                        .select_segments(["environment", "systemPackages"]),
                )
                .to_text(),
            NixValue::from("/bin/airlock-sync-qube-appmenus"),
        ]));

        let field_qrexec_python_path = NixValue::concat_text([
            gui.clone()
                .select_segments(["nixpkgs", "pkgs", "python3", "pkgs", "qubes-core-qrexec"])
                .to_text(),
            NixValue::from("/"),
            gui.clone()
                .select_segments(["nixpkgs", "pkgs", "python3", "sitePackages"])
                .to_text(),
        ]);

        NixValue::record([
            ("sync", field_sync),
            (
                "receiver",
                native_contract(gui.clone().select_segments([
                    "environment",
                    "etc",
                    "qubes-rpc/qubes.SyncAppMenus",
                    "source",
                ])),
            ),
            (
                "receiverUser",
                gui.clone().select_segments([
                    "environment",
                    "etc",
                    "qubes/rpc-config/qubes.SyncAppMenus",
                    "text",
                ]),
            ),
            (
                "policy",
                NixValue::builtin("readFile").call(NixValue::concat_text([
                    policy.clone().to_text(),
                    NixValue::from("/etc/qubes/policy.d/50-airlock-sys-gui.policy"),
                ])),
            ),
            ("qrexecPythonPath", field_qrexec_python_path),
            (
                "controlPolicy",
                NixValue::builtin("readFile").call(NixValue::concat_text([
                    control_policy.clone().to_text(),
                    NixValue::from("/etc/qubes/policy.d/43-airlock-ctrl-guest.policy"),
                ])),
            ),
            (
                "prepare",
                NixValue::builtin("readFile").call(host.clone().select_segments([
                    "environment",
                    "etc",
                    "qubes-rpc/airlock.Ctrl.MachinePrepare",
                    "source",
                ])),
            ),
            (
                "candidate",
                NixValue::builtin("readFile").call(host.clone().select_segments([
                    "environment",
                    "etc",
                    "qubes-rpc/airlock.Pool.AdmitCandidate",
                    "source",
                ])),
            ),
        ])
    }
}

/// Build the live vm interfaces interfaces contribution using the caller supplied deferred values.
fn live_vm_interfaces_interfaces_2(host: NixValue, find: NixValue, gui: NixValue) -> NixValue {
    find.clone()
        .call(NixValue::from("50-airlock-sys-gui.policy"))
        .call(
            host.clone()
                .select_segments(["virtualisation", "qubes", "packages"]),
        )
        .bind(|policy| {
            find.clone()
                .call(NixValue::from("43-airlock-ctrl-guest.policy"))
                .call(
                    host.clone()
                        .select_segments(["virtualisation", "qubes", "packages"]),
                )
                .bind(|control_policy| {
                    live_vm_interfaces_interfaces_body(
                        control_policy,
                        find.clone(),
                        gui.clone(),
                        host.clone(),
                        policy.clone(),
                    )
                })
        })
}
