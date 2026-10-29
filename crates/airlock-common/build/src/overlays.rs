//! Extend upstream package sets with Airlock's Qubes integration patches.

use crate::Workspace;
use rusix::{
    interop::raw::{NixRepresentation, NixValue},
    nix_record, nix_text,
};

/// Replace only upstream's scheduler selection, preserving its dom0 weight policy.
const QUBES_SCHEDULER: &str = r#"
scheduler=$(xl info | awk '$1 == "xen_scheduler" { print $3 }')
case "$scheduler" in
    credit|credit2) xl "sched-$scheduler" -d 0 -w 2000 ;;
    *) echo "Qubes startup: cannot set dom0 weight for Xen scheduler '$scheduler'" >&2 ;;
esac
"#;

/// Select the complete pinned Codex distribution on supported hosts.
pub fn codex() -> NixValue {
    NixValue::function(|final_pkgs| {
        NixValue::function(|previous| {
            nix_record! {
                "codex": NixValue::if_else(
                    previous.clone().select("stdenv.hostPlatform.system").equals("x86_64-linux"),
                    super::upstream::codex(&final_pkgs).as_expression(),
                    previous.select("codex"),
                ),
            }
        })
    })
}

/// Keep upstream dom0 startup compatible with Xen's scheduler and resolve its Qubes client commands.
pub fn qubes_startup() -> NixValue {
    NixValue::function(|_| {
        NixValue::function(|previous| {
            let extension = NixValue::function(|python_packages| {
                NixValue::function(|packages| {
                    let usb = packages.clone().select("qubes-app-linux-usb-proxy");
                    let exporter =
                        usb.clone()
                            .select("sys-usb")
                            .override_attrs(NixValue::function(|old| {
                                nix_record! {
                                    // This custom patch phase does not run postPatch hooks. Fix the
                                    // Python source before wrapPython preserves its interpreter line.
                                    "patchPhase": NixValue::concat_text([
                                        old.attr_or("patchPhase", ""),
                                        "\n".into(),
                                        nix_text!(r#"
                                            substituteInPlace src/usb-reset \
                                      --replace-fail /usr/bin/python3 {python}
                                "#, python = previous.clone().select("python3.interpreter")).into(),
                                    ]),
                                }
                            }));

                    nix_record! {
                        "qubes-app-linux-usb-proxy": usb.override_attrs(NixValue::function(|old| {
                            nix_record! {
                                "passthru": old.select("passthru").merge_attrs(nix_record! {
                                    "sys-usb": exporter,
                                }),
                            }
                        })),
                        "qubes-core-admin": packages.select("qubes-core-admin").override_attrs(
                            NixValue::function(|old| nix_record! {
                                // patsh resolves upstream's bare qvm-features command at build time.
                                "nativeBuildInputs": NixValue::concat_lists([
                                    old.clone().attr_or("nativeBuildInputs", NixValue::list([])),
                                    NixValue::list([python_packages.clone().select("qubes-core-admin-client")]),
                                ]),
                                "postPatch": NixValue::concat_text([
                                    old.attr_or("postPatch", ""),
                                    nix_text!(r#"
                                    substituteInPlace linux/aux-tools/startup-misc.sh \
                                      --replace-fail 'xl sched-credit -d 0 -w 2000' {scheduler}
                                    bash -n linux/aux-tools/startup-misc.sh
                                    # These administrative RPCs call the daemon's own query client,
                                    # not the separately packaged QubesDB client.
                                    substituteInPlace qubes-rpc/qubes.FeaturesRequest \
                                      qubes-rpc/qubes.NotifyTools qubes-rpc/qubes.NotifyUpdates \
                                      --replace-fail {wrong_query} "$out/bin/qubesd-query"
                                    # Ephemeral volumes must use the immutable Nix dependency,
                                    # including on hosts without distribution /usr/sbin links.
                                    substituteInPlace qubes/utils.py \
                                      --replace-fail /usr/sbin/cryptsetup {cryptsetup}/bin/cryptsetup
                                "#,
                                    scheduler = previous.clone().select("lib.escapeShellArg").call(QUBES_SCHEDULER),
                                    wrong_query = nix_text!("{client}/bin/qubesd-query", client = previous.clone().select("qubes-core-qubesdb")),
                                    cryptsetup = previous.clone().select("cryptsetup"),
                                    ).into(),
                                ]),
                            }),
                        ),
                    }
                })
            });
            let unchanged = NixValue::function(|_| NixValue::function(|_| nix_record! {}));
            let python = previous
                .clone()
                .select("python3.override")
                .call(NixValue::function(|arguments| {
                    nix_record! {
                        "packageOverrides": previous.clone().select("lib.composeExtensions")
                            .call(arguments.attr_or("packageOverrides", unchanged))
                            .call(extension),
                    }
                }));

            let notifications =
                previous.clone()
                    .select("qubes-notification-proxy")
                    .override_attrs(NixValue::function(|old| {
                        nix_record! {
                            // Upstream's lndir join transplants leaf symlinks. The stdenv
                            // deduplication hook would turn this RPC's absolute package
                            // link into ../../bin, which escapes the joined directory.
                            "dontRewriteSymlinks": true,
                            // Upstream links libqubes-pure but omits its runtime search path.
                            "postFixup": NixValue::concat_text([
                                old.attr_or("postFixup", ""),
                                "\n".into(),
                                nix_text!(r#"
                                    {patchelf}/bin/patchelf --add-rpath {utils}/lib "$out/bin/qubes-notification-proxy-server"
                                    {patchelf}/bin/patchelf --add-rpath {utils}/lib "$out/bin/qubes-notification-proxy-client"
                                "#,
                                    patchelf = previous.clone().select("patchelf"),
                                    utils = previous.clone().select("qubes-linux-utils"),
                                ).into(),
                            ]),
                        }
                    }));

            nix_record! { "python3": python, "qubes-notification-proxy": notifications }
        })
    })
}

/// Retain existing patches and append Airlock's protocol extensions from the application workspace.
pub fn gui_window_state(workspace: &Workspace) -> NixValue {
    NixValue::function(|_| {
        NixValue::function(|previous| {
            NixValue::record(
                [
                    (
                        "qubes-gui-common",
                        &[
                            "0001-protocol-add-maximize-window-flags.patch",
                            "0002-protocol-add-interactive-window-move-message.patch",
                        ][..],
                    ),
                    (
                        "qubes-gui-agent-linux",
                        &[
                            "0001-gui-agent-forward-minimize-and-maximize-requests.patch",
                            "0002-gui-agent-forward-interactive-window-move-requests.patch",
                            "0003-preserve-xorg-across-guivm-restart.patch",
                        ][..],
                    ),
                    (
                        "qubes-gui-daemon",
                        &[
                            "0001-gui-daemon-apply-maximize-window-flags.patch",
                            "0002-gui-daemon-apply-interactive-window-move-requests.patch",
                        ][..],
                    ),
                ]
                .map(|(package, patches)| {
                    let updated =
                        previous
                            .clone()
                            .select(package)
                            .override_attrs(NixValue::function(|old| {
                                nix_record! {
                                    "patches": NixValue::concat_lists([
                                        old.attr_or("patches", NixValue::list([])),
                                        NixValue::list(patches.iter().map(|patch| workspace.file(
                                            &format!("patches/{package}/{patch}"),
                                        ).snapshot().as_expression())),
                                    ]),
                                }
                            }));

                    (package, updated)
                }),
            )
        })
    })
}

/// Correct per-CPU memory accounting and run upstream integration checks against the patch.
pub fn memory_accounting(workspace: &Workspace) -> NixValue {
    NixValue::function(|_| {
        NixValue::function(|previous| {
            let file = |path| workspace.file(path);
            let smoke = previous
                .clone()
                .select("writeText")
                .call("memory-accounting-smoke.c")
                .call(include_str!(
                    "../../../airlock-tests/fixtures/memory_accounting.c"
                ));
            nix_record! {
                "qubes-linux-utils": previous.select("qubes-linux-utils").override_attrs(
                    NixValue::function(|old| nix_record! {
                        "patches": NixValue::concat_lists([
                            old.clone().attr_or("patches", NixValue::list([])),
                            NixValue::list([file(
                                "patches/qubes-linux-utils/\
                                 0001-account-for-per-cpu-free-pages.patch",
                            ).snapshot().as_expression()]),
                        ]),
                        "postPatch": NixValue::concat_text([
                            old.clone().attr_or("postPatch", ""),
                            nix_text!(r#"
                            cp {header} qmemman/memory-accounting.h
                        "#, header = file(
                            "patches/qubes-linux-utils/memory-accounting.h",
                        ).snapshot()).into(),
                        ]),
                        "doCheck": true,
                        "checkPhase": nix_text!(r#"
                        runHook preCheck
                        $CC -std=c11 -Wall -Wextra -Werror -DAIRLOCK_MEMORY_SELFTEST \
                          -I qmemman {smoke} -o memory-accounting-check
                        ./memory-accounting-check
                        runHook postCheck
                    "#, smoke = smoke),
                    }),
                ),
            }
        })
    })
}

/// Remove unsupported upstream template installation actions while retaining the VM manager.
pub fn template_tools() -> NixValue {
    NixValue::function(|_| NixValue::function(|previous| without_template_tools(&previous)))
}

/// Build the optional manager override against the package set being extended.
fn without_template_tools(previous: &NixValue) -> NixValue {
    let script = NixValue::builtin("replaceStrings")
        .call(NixValue::list(["@sitePackages@".into()]))
        .call(NixValue::list([previous
            .clone()
            .select("python3.sitePackages")]))
        .call(include_str!("template-tools.sh"));
    let manager = previous.clone().select("qubes-manager").override_attrs(NixValue::function(|old| {
        nix_record! {
            "passthru": old.clone().attr_or("passthru", nix_record! {}).merge_attrs(nix_record! {
                "airlockTemplateToolsRemoved": true,
            }),
            "postInstall": NixValue::concat_text([old.attr_or("postInstall", ""), script]),
        }
    }));

    NixValue::if_else(
        previous.clone().has_attr("qubes-manager"),
        nix_record! { "qubes-manager": manager },
        nix_record! {},
    )
}

/// Apply image-builder fixes and hide unsupported template operations in the host package set.
pub fn image_tools(workspace: &Workspace) -> NixValue {
    NixValue::function(|_| {
        NixValue::function(|previous| {
            let lib = previous.clone().select("lib");
            let erofs = previous
                .clone()
                .select("erofs-utils")
                .override_attrs(NixValue::function(|old| {
                    let affected = lib
                        .clone()
                        .select("versionAtLeast")
                        .call(old.clone().select("version"))
                        .call("1.9")
                        .and(
                            lib.select("versionOlder")
                                .call(old.clone().select("version"))
                                .call("1.9.4"),
                        );
                    let patch = |name| {
                        workspace
                            .file(&format!("patches/erofs-utils/{name}"))
                            .snapshot()
                            .as_expression()
                    };

                    nix_record! {
                        "patches": NixValue::concat_lists([
                            old.attr_or("patches", NixValue::list([])),
                            NixValue::if_else(
                                affected,
                                NixValue::list([patch("erofs-incremental-data.patch")]),
                                NixValue::list([]),
                            ),
                            NixValue::list([patch("erofs-tar-metadata-index.patch")]),
                        ]),
                    }
                }));
            let lkl = previous
                .clone()
                .select("lkl")
                .override_attrs(NixValue::function(|old| {
                    nix_record! { "postPatch": NixValue::concat_text([
                        old.attr_or("postPatch", ""),
                        nix_text!(r#"
                            substituteInPlace tools/lkl/cptofs.c \
                      --replace-fail 'lkl_start_kernel("mem=100M")' 'lkl_start_kernel("mem=1024M")'
                "#).into(),
                    ]) }
                }));

            nix_record! { "erofs-utils": erofs, "lkl": lkl }
                .merge_attrs(without_template_tools(&previous))
        })
    })
}

#[cfg(test)]
mod startup_tests {
    use super::QUBES_SCHEDULER;
    use std::process::{Command, Output};

    /// Execute the upstream integration fragment with an inert xl command, never a real hypervisor.
    fn observe(scheduler: &str, exit: &str) -> std::io::Result<Output> {
        let fixture = r#"
            xl() {
                if [ "$1" = info ]; then
                    printf 'xen_scheduler : %s\n' "$AIRLOCK_TEST_SCHEDULER"
                else
                    printf '%s\n' "$@"
                    return "$AIRLOCK_TEST_XL_EXIT"
                fi
            }
        "#;
        Command::new("bash")
            .args([
                "-c",
                &format!(
                    r#"
                {fixture}
                {QUBES_SCHEDULER}
            "#
                ),
            ])
            .env("AIRLOCK_TEST_SCHEDULER", scheduler)
            .env("AIRLOCK_TEST_XL_EXIT", exit)
            .output()
    }

    /// Set the existing dom0 weight through the active scheduler and retain a real xl failure.
    #[test]
    fn dom0_weight_uses_the_active_xen_scheduler() -> std::io::Result<()> {
        for scheduler in ["credit", "credit2"] {
            let output = observe(scheduler, "0")?;
            assert!(output.status.success());
            assert_eq!(
                String::from_utf8_lossy(&output.stdout),
                format!("sched-{scheduler}\n-d\n0\n-w\n2000\n")
            );
        }
        let unsupported = observe("null", "0")?;
        assert!(unsupported.stdout.is_empty());
        assert!(String::from_utf8_lossy(&unsupported.stderr).contains("cannot set dom0 weight"));
        assert_eq!(observe("credit2", "7")?.status.code(), Some(7));
        Ok(())
    }
}
