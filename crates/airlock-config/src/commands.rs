//! Native command contracts replacing first-party shell entry points.
//! Deferred Nix values remain individual arguments; no command string is evaluated at runtime.

use airlock_build::{Application, native};
use rusix::interop::raw::{NixRepresentation, NixValue};
use std::collections::BTreeMap;

/// Bind package paths and settings to one existing native operation.
pub(crate) fn contract<const N: usize>(
    pkgs: &NixValue,
    kind: &str,
    bindings: [(&str, NixValue); N],
) -> NixValue {
    let mut b: BTreeMap<&str, NixValue> = bindings.into_iter().collect();
    let vm = || {
        Application::VmService
            .build(pkgs, &native::workspace(pkgs))
            .as_expression()
    };
    // A local service is only pulled into operations that own behavior, not upstream adapters.
    let special = matches!(
        kind,
        "gui-session"
            | "login-xserver"
            | "client"
            | "handler"
            | "shell"
            | "open-url"
            | "poweroff-session-action"
            | "open-url-launcher"
            | "session"
    );
    if special && !b.contains_key("service") {
        b.insert("service", vm());
    }
    if kind == "open-url" {
        b.insert("shell", pkgs.clone().select("bash"));
    }
    let value = |key: &str| {
        b.get(key)
            .cloned()
            .unwrap_or_else(|| panic!("missing native command binding {key} for {kind}"))
    };
    let text = |template: &str| {
        // Unused bindings can contain other launchers. Repeating them for every
        // literal argument expands nested command expressions exponentially.
        let selected: Vec<_> = b
            .iter()
            .filter(|(key, _)| template.contains(&format!("@{key}@")))
            .collect();
        if selected.is_empty() {
            return NixValue::from(template);
        }

        let names = selected.iter().map(|(key, _)| format!("@{key}@").into());
        let values = selected.iter().map(|(_, value)| (*value).clone().to_text());
        NixValue::builtin("replaceStrings")
            .call(NixValue::list(names))
            .call(NixValue::list(values))
            .call(template)
    };
    let (program, arguments, inherit): (&str, &[&str], bool) = match kind {
        "app-launcher" => ("@service@/bin/airlock-sys-gui-service", &["launch"], true),
        "session-ready" => ("@service@/bin/airlock-vm-service", &["session-ready"], true),
        "connect-input" => (
            "@service@/bin/airlock-dom0-service",
            &["input", "connect", "--target", "@quotedTarget@"],
            false,
        ),
        "receiver-ready" => (
            "@service@/bin/airlock-vm-service",
            &[
                "input-receiver-ready",
                "--handler",
                "/etc/qubes-rpc/airlock.InputDevice",
                "--handler",
                "/etc/qubes-rpc/qubes.InputKeyboard",
                "--handler",
                "/etc/qubes-rpc/qubes.InputMouse",
                "--handler",
                "/etc/qubes-rpc/qubes.InputTablet",
            ],
            false,
        ),
        "device-receiver" => (
            "@proxy@/bin/input-proxy-receiver",
            &["--keyboard", "--mouse", "--tablet"],
            false,
        ),
        "policy-path" => (
            "@service@/bin/airlock-dom0-service",
            &[
                "config",
                "policy-paths",
                "--static-dir",
                "@static@",
                "--runtime-dir",
                "@runtime@",
                "--managed-file",
                "@managed@",
            ],
            false,
        ),
        "config-nix-store" => (
            "@service@/bin/airlock-vm-service",
            &[
                "nix",
                "--executable",
                "@nix@/bin/nix-store",
                "--root",
                "@storeRoot@",
                "--pinned",
                "--store-command",
                "--",
            ],
            true,
        ),
        "private-store" => (
            "@service@/bin/airlock-vm-service",
            &[
                "nix",
                "--executable",
                "@nix@/bin/nix",
                "--root",
                "@storeRoot@",
            ],
            true,
        ),
        "machine-build" | "machine-source" => (
            "@service@/bin/airlock-vm-service",
            &[
                "worker",
                "--repo",
                "@repo@",
                "--state",
                "@state@",
                "--cache",
                "@cache@",
                "--store",
                "@storeRoot@",
            ],
            true,
        ),
        "machine-seed" => (
            "@service@/bin/airlock-vm-service",
            &[
                "worker",
                "--repo",
                "@repo@",
                "--state",
                "@state@",
                "--cache",
                "@cache@",
                "--store",
                "@storeRoot@",
                "seed",
                "--archive",
                "@archive@",
                "--user",
                "@user@",
            ],
            false,
        ),
        "receive-appmenus" => (
            "@coreutils@/bin/timeout",
            &[
                "--signal=TERM",
                "--kill-after=5s",
                "90s",
                "@service@/bin/airlock-sys-gui-service",
                "menus",
                "receive",
            ],
            false,
        ),
        "existing-uplinks" => (
            "@service@/bin/airlock-vm-service",
            &["runtime", "existing-uplinks"],
            false,
        ),
        "external-ip" => (
            "@service@/bin/airlock-vm-service",
            &["runtime", "external-ip", "--"],
            true,
        ),
        "firewall" => (
            "@service@/bin/airlock-vm-service",
            &["runtime", "firewall", "--agent", "@agent@"],
            false,
        ),
        "networkmanager-hook" => (
            "@service@/bin/airlock-vm-service",
            &["runtime", "network-hook", "--dnat", "@dnat@", "--"],
            true,
        ),
        "networkmanager-state" => (
            "@service@/bin/airlock-vm-service",
            &["runtime", "network-manager-state"],
            false,
        ),
        "configuration-init" => (
            "@service@/bin/airlock-vm-service",
            &[
                "runtime",
                "configuration-init",
                "--role",
                "@role@",
                "--user",
                "@user@",
                "--path",
                "@path@",
                "--command",
                "@command@",
            ],
            false,
        ),
        "inputs-mount" => (
            "@service@/bin/airlock-vm-service",
            &[
                "runtime",
                "mount-inputs",
                "--inputs",
                "@inputsPath@",
                "--store",
                "@storeRoot@",
                "--public",
                "@publicInputs@",
            ],
            false,
        ),
        "private-storage-init" => (
            "@service@/bin/airlock-vm-service",
            &[
                "runtime",
                "private-storage",
                "--agent",
                "@agent@",
                "--bash",
                "@bash@/bin/bash",
                "--user",
                "@user@",
            ],
            false,
        ),
        "store-check" => (
            "@service@/bin/airlock-vm-service",
            &["runtime", "store-check"],
            false,
        ),
        "usr-assistant-tailscale-enrollment" => (
            "@service@/bin/airlock-sys-gui-service",
            &["tailscale-enrollment"],
            false,
        ),
        "usr-assistant-tailscale-window" => (
            "@xterm@/bin/xterm",
            &[
                "-hold",
                "-fa",
                "DejaVu Sans Mono",
                "-fs",
                "16",
                "-geometry",
                "100x30",
                "-T",
                "Start usr-assistant Tailscale",
                "-e",
                "/run/wrappers/bin/sudo",
                "-n",
                "@enrollment@",
            ],
            false,
        ),
        "dnat" => (
            "@python@/bin/python",
            &["@agent@/lib/qubes/qubes-setup-dnat-to-ns"],
            true,
        ),
        "updates-rpc" => ("@socat@/bin/socat", &["STDIO", "TCP:127.0.0.1:8082"], false),
        "xorg" => ("@xserver@/bin/X", &[], true),
        "physical-xserver" => ("@xserver@/bin/Xorg", &[], true),
        "autostart" => (
            "@python@/bin/python",
            &["@coreAgentSource@/app-menu/qubes-session-autostart"],
            true,
        ),
        "monitor-layout" => (
            "@coreutils@/bin/timeout",
            &[
                "--signal=TERM",
                "--kill-after=5s",
                "60s",
                "@agent@/bin/qubes-set-monitor-layout",
            ],
            true,
        ),
        "poweroff" => (
            "/run/wrappers/bin/sudo",
            &["-n", "@systemd@/bin/systemctl", "poweroff"],
            false,
        ),
        "gui-session" => (
            "@service@/bin/airlock-vm-service",
            &[
                "desktop",
                "gui-session",
                "--systemctl",
                "@systemd@/bin/systemctl",
                "--journalctl",
                "@systemd@/bin/journalctl",
            ],
            false,
        ),
        "login-xserver" => (
            "@service@/bin/airlock-vm-service",
            &[
                "desktop",
                "login-xserver",
                "--probe",
                "@xdpyinfo@/bin/xdpyinfo",
                "--server",
                "@xserver@/bin/Xephyr",
                "--preload",
                "@daemon@/lib/qubes-gui-daemon/shmoverride.so",
                "--",
            ],
            true,
        ),
        "client" => (
            "@service@/bin/airlock-vm-service",
            &[
                "desktop",
                "terminal-client",
                "--qrexec",
                "@qrexec@/bin/qrexec-client-vm",
            ],
            false,
        ),
        "handler" => (
            "@service@/bin/airlock-vm-service",
            &[
                "desktop",
                "terminal-handler",
                "--callers",
                "@callers@",
                "--user",
                "@user@",
                "--script",
                "@utilLinux@/bin/script",
                "--logger",
                "@utilLinux@/bin/logger",
                "--id",
                "@coreutils@/bin/id",
                "--shell",
                "@shell@",
                "--",
            ],
            true,
        ),
        "shell" => (
            "@service@/bin/airlock-vm-service",
            &[
                "desktop",
                "terminal-shell",
                "--shell",
                "@bash@/bin/bash",
                "--stty",
                "@coreutils@/bin/stty",
                "--terminfo",
                "@ncurses@/share/terminfo",
            ],
            false,
        ),
        "open-url" => (
            "@service@/bin/airlock-vm-service",
            &[
                "desktop",
                "open-url",
                "--gio",
                "@glib@/bin/gio",
                "--shell",
                "@shell@/bin/bash",
            ],
            false,
        ),
        "open-url-launcher" => (
            "@service@/bin/airlock-vm-service",
            &[
                "desktop",
                "url-launcher",
                "--launcher",
                "@launcher@/bin/airlock-launch-qube-app",
                "--target",
                "@target@",
                "--",
            ],
            true,
        ),
        "poweroff-session-action" => (
            "@service@/bin/airlock-vm-service",
            &[
                "desktop",
                "power-action",
                "--qvm-run",
                "@admin@/bin/qvm-run",
                "--logout",
                "@xfceSession@/bin/xfce4-session-logout",
                "--",
            ],
            true,
        ),
        "session" => (
            "@service@/bin/airlock-vm-service",
            &[
                "desktop",
                "app-session",
                "--session",
                "@session@",
                "--scale",
                "@scale@",
                "--cursor-size",
                "@cursorSize@",
            ],
            false,
        ),
        _ => panic!("unknown native command contract {kind}"),
    };
    let mut args = NixValue::list(arguments.iter().map(|argument| text(argument)));
    if kind == "app-launcher" || kind == "private-store" {
        let option = value(if kind == "app-launcher" {
            "workspace"
        } else {
            "pinned"
        });
        args = NixValue::concat_lists([
            args,
            NixValue::if_else(
                option.clone().equals(""),
                NixValue::list([]),
                NixValue::list([option]),
            ),
        ]);
    }
    if kind == "private-store" {
        args = NixValue::concat_lists([args, NixValue::list(["--".into()])]);
    }
    if kind == "machine-build" || kind == "machine-source" {
        args = NixValue::concat_lists([
            args,
            NixValue::list([if kind == "machine-build" {
                "build".into()
            } else {
                "source".into()
            }]),
        ]);
    }
    let mut fields = vec![
        ("program", text(program)),
        ("args", args),
        ("inherit_args", inherit.into()),
    ];
    let mut env = Vec::new();
    let mut prefix = Vec::new();
    if matches!(
        kind,
        "machine-build"
            | "machine-source"
            | "private-store"
            | "external-ip"
            | "networkmanager-hook"
    ) {
        prefix.push(("PATH", value("path")));
    }
    if matches!(kind, "store-check" | "monitor-layout") {
        env.push(("PATH", value("path")));
    }
    if kind == "connect-input" {
        prefix.push(("PATH", text("@admin@/bin:@qrexec@/bin:@systemd@/bin")));
    }
    if kind == "xorg" {
        prefix.push((
            "LD_PRELOAD",
            text("@daemon@/lib/qubes-gui-daemon/shmoverride.so"),
        ));
    }
    if kind == "physical-xserver" {
        env.push((
            "LD_PRELOAD",
            text("@daemon@/lib/qubes-gui-daemon/shmoverride.so"),
        ));
    }
    if kind == "autostart" {
        prefix.push(("PYTHONPATH", text("@coreAgent@/@sitePackages@")));
    }
    if !env.is_empty() {
        fields.push(("env", NixValue::record(env)));
    }
    if !prefix.is_empty() {
        fields.push(("prefix_env", NixValue::record(prefix)));
    }
    if matches!(kind, "poweroff" | "device-receiver") {
        fields.push((
            "callers",
            NixValue::list([if kind == "poweroff" {
                "sys-gui".into()
            } else {
                "dom0".into()
            }]),
        ));
    }
    if matches!(kind, "poweroff" | "device-receiver" | "receive-appmenus") {
        fields.push(("empty_service_argument", true.into()));
    }
    NixValue::record(fields)
}
