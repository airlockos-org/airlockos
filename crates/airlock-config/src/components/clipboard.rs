//! Connect one Hermit clipboard to a GUI session and its resolved application VMs.
//! Finalization derives endpoint contracts, startup relationships and exact Qubes
//! permissions together. Machine authors select relationships rather than scripts.

use super::machine_source;
use crate::model::{
    AuthoringError, GuestBackend, Gui, Hermit, HostSnapshot, Service, VmHandle, VmSnapshot,
};
use airlock_build::{Application, Workspace};
use airlock_machine_core::{model::VmReference, services::ClipboardConnection};
use rusix::{
    interop::{
        NixPath,
        raw::{NixRepresentation, NixValue},
    },
    nix_record, nix_text,
    nixos::{ContextualModule, ModuleBody, NixosModule},
};

/// Share normal clipboard content among this GUI and every VM assigned to it.
/// The Hermit service needs at least 128 MiB for the bounded multi-format payload.
/// File offers remain local; no protected mode or gesture authority is enabled.
pub fn connect(gui: &VmHandle<Gui>, service: &VmHandle<Service, Hermit>) {
    gui.clipboard_service(service);
}

/// Freeze membership from resolved display assignments before installing any endpoints.
pub(crate) fn configure(
    vms: &mut [VmSnapshot],
    connections: &mut [ClipboardConnection],
    host: Option<&HostSnapshot>,
) -> Result<(), AuthoringError> {
    for connection in connections {
        let service = vms
            .iter()
            .find(|vm| vm.name == connection.service)
            .ok_or_else(|| AuthoringError::InvalidClipboard {
                reason: "missing clipboard service".into(),
            })?;
        if !matches!(service.backend, GuestBackend::Hermit { .. })
            || service.settings.memory.bounds().0.0 < 128
        {
            return Err(AuthoringError::InvalidClipboard {
                reason: "normal clipboard requires a Hermit service with at least 128 MiB".into(),
            });
        }
        connection.participants = vms
            .iter()
            .filter(|vm| {
                matches!(vm.backend, GuestBackend::Nixos)
                    && (vm.name == connection.gui
                        || match &vm.guivm {
                            VmReference::Named(gui) => gui.as_str() == connection.gui.as_str(),
                            VmReference::Inherit => {
                                host.is_some_and(|host| host.gui == connection.gui)
                            }
                            _ => false,
                        })
            })
            .map(|vm| vm.name.clone())
            .collect();
        connection.participants.sort();
        if !connection.validate() {
            return Err(AuthoringError::InvalidClipboard {
                reason: "clipboard requires one GUI and at most 32 unique Linux participants"
                    .into(),
            });
        }
        for vm in vms.iter_mut() {
            if vm.name == connection.service {
                vm.features.insert(
                    "airlock-clipboard-authority".into(),
                    connection.gui.to_string(),
                );
            }
            if connection.participants.contains(&vm.name) {
                vm.features
                    .insert("gui-secure-copy-sequence".into(), "none".into());
                vm.features
                    .insert("gui-secure-paste-sequence".into(), "none".into());
                if vm.name != connection.gui {
                    vm.features.insert(
                        "airlock-clipboard-service".into(),
                        connection.service.to_string(),
                    );
                }
                vm.modules
                    .push(endpoint(connection.clone(), vm.name == connection.gui));
            }
        }
    }
    Ok(())
}

/// Derive exact provisioning and lifecycle permissions; clipboard bytes never enter dom0.
pub fn policy(connections: &[ClipboardConnection]) -> String {
    let mut policy = String::new();
    for connection in connections {
        let gui = &connection.gui;
        let service = &connection.service;
        policy.push_str(&format!("airlock.ClipboardEndpoint + {gui} dom0 allow\n"));
        for participant in &connection.participants {
            if participant != gui {
                policy.push_str(&format!(
                    "airlock.ClipboardConnect + {participant} {gui} allow user=root\n"
                ));
            }
            policy.push_str(&format!(
                "admin.vm.property.Get +xid {gui} {participant} allow target=dom0\n"
            ));
        }
        for operation in ["Start", "Kill", "CurrentState"] {
            policy.push_str(&format!(
                "admin.vm.{operation} + {gui} {service} allow target=dom0\n"
            ));
        }
        policy.push_str(&format!(
            "admin.vm.property.Get +xid {gui} {service} allow target=dom0\n"
        ));
        // The old secure clipboard shortcut must not bypass shared generation state.
        for participant in &connection.participants {
            for operation in ["Copy", "Paste"] {
                policy.push_str(&format!(
                    "qubes.Clipboard{operation} * {gui} {participant} deny\n"
                ));
            }
        }
    }
    policy.push_str("airlock.ClipboardConnect * @anyvm @anyvm deny\nairlock.ClipboardEndpoint * @anyvm @anyvm deny\n");
    policy
}

/// Install a user-session adapter and, on its GUI, a separate root provisioner.
fn endpoint(connection: ClipboardConnection, authority: bool) -> NixosModule {
    NixosModule::with_arguments([machine_source::ARGUMENT], move |inputs| {
        let workspace = Workspace::new(NixPath::from_expression(
            inputs.pkgs.clone().select("airlockAppsSource"),
        ));
        let package = Application::VmService
            .build(&inputs.pkgs, &workspace)
            .as_expression();
        let executable = nix_text!(
            "{package}/bin/airlock-vm-service",
            package = package.clone()
        );
        let user = inputs.config.clone().select("airlock.qubeGuest.user");
        let config = serde_json::to_string(&connection).expect("clipboard contract serializes");
        let session_arguments = if authority {
            "clipboard session --local"
        } else {
            "clipboard session"
        };
        let session = nix_record! {
            "description": "Share this graphical session's clipboard through Hermit",
            "partOf": NixValue::list(["graphical-session.target".into()]),
            "path": NixValue::list([inputs.pkgs.clone().select("python3.pkgs.qubes-core-qrexec.domU")]),
            "unitConfig": nix_record! { "StartLimitIntervalSec": 0_i64 },
            "serviceConfig": nix_record! {
                "ExecStart": nix_text!("{executable} {arguments}", executable = executable.clone(), arguments = session_arguments),
                "Restart": "on-failure", "RestartSec": "2s", "NoNewPrivileges": true,
            },
        };
        let mut etc = vec![
            (
                "airlock/clipboard.json",
                nix_record! { "text": config.clone() },
            ),
            (
                "xdg/autostart/airlock-clipboard.desktop",
                nix_record! { "text": nix_text!(r#"
                [Desktop Entry]
                Type=Application
                Name=Airlock Clipboard
                Exec={executable} clipboard activate
                NoDisplay=true
            "#, executable = executable.clone()) },
            ),
        ];
        if authority {
            let rpc = inputs
                .pkgs
                .clone()
                .select("writeShellScript")
                .call("airlock-clipboard-connect")
                .call(nix_text!(
                    r#"
                exec {executable} clipboard connect
            "#,
                    executable = executable.clone()
                ));
            etc.push((
                "qubes-rpc/airlock.ClipboardConnect",
                nix_record! { "source": rpc },
            ));
            etc.push((
                "qubes/rpc-config/airlock.ClipboardConnect",
                nix_record! { "text": "force-user='root'\n" },
            ));
        }
        let mut modules = vec![ModuleBody::new(nix_record! {
            "assertions": NixValue::list([nix_record! {
                "assertion": inputs.config.clone().select("environment.etc").select_segments(["airlock/clipboard.json"]).select("text").equals(config),
                "message": "Clipboard membership must be changed through the typed Rust connection.",
            }]),
            "environment": nix_record! { "systemPackages": NixValue::list([package]), "etc": NixValue::record(etc) },
            "users": nix_record! {
                "groups": nix_record! { "airlock-clipboard": nix_record! {} },
                "users": NixValue::builtin("listToAttrs").call(NixValue::list([nix_record! { "name": user, "value": nix_record! { "extraGroups": NixValue::list(["airlock-clipboard".into()]) } }])),
            },
            "boot": nix_record! { "kernelModules": NixValue::list(["xen-gntdev".into(), "xen-gntalloc".into(), "xen-evtchn".into()]) },
            "services": nix_record! { "udev": nix_record! { "extraRules": nix_text!(r#"
                SUBSYSTEM=="misc", KERNEL=="xen*gntdev", GROUP="airlock-clipboard", MODE="0660"
                SUBSYSTEM=="misc", KERNEL=="xen*gntalloc", GROUP="airlock-clipboard", MODE="0660"
                SUBSYSTEM=="misc", KERNEL=="xen*evtchn", GROUP="airlock-clipboard", MODE="0660"
            "#) } },
            "systemd": nix_record! { "user": nix_record! { "services": nix_record! { "airlock-clipboard": session } } },
        })];
        if authority {
            modules.push(ModuleBody::new(nix_record! {
                "systemd": nix_record! { "services": nix_record! { "airlock-clipboard-authority": nix_record! {
                    "description": "Provision authenticated clipboard peers through Qubes",
                    "wantedBy": NixValue::list(["multi-user.target".into()]),
                    "after": NixValue::list(["qubes-qrexec-agent.service".into()]),
                    "requires": NixValue::list(["qubes-qrexec-agent.service".into()]),
                    "path": NixValue::list([inputs.pkgs.clone().select("python3.pkgs.qubes-core-admin-client"), inputs.pkgs.clone().select("python3.pkgs.qubes-core-qrexec.domU")]),
                    "unitConfig": nix_record! { "StartLimitIntervalSec": 0_i64 },
                    "serviceConfig": nix_record! {
                        "ExecStart": nix_text!("{executable} clipboard authority", executable = executable.clone()),
                        "Restart": "on-failure", "RestartSec": "3s", "RuntimeDirectory": "airlock-clipboard", "RuntimeDirectoryMode": "0750", "Group": "airlock-clipboard",
                    },
                } } },
            }));
        }
        modules
            .into_iter()
            .fold(ModuleBody::empty(), |body, module| body.module(module))
    })
}

/// Install the boot-offer observer and generated permissions in dom0.
pub(crate) fn host_module(
    connections: &[ClipboardConnection],
    workspace: Workspace,
    physical: bool,
) -> NixValue {
    let connections = connections.to_vec();
    ContextualModule::new(move |inputs| {
        let service = Application::Dom0.build(&inputs.pkgs, &workspace).as_expression();
        let endpoint = inputs.pkgs.clone().select("writeShellScript").call("airlock-clipboard-endpoint").call(nix_text!(r#"
            exec {service}/bin/airlock-dom0-service clipboard-endpoint --config /etc/airlock/clipboards.json
        "#, service = service));
        let rules = policy(&connections);
        let mut etc = vec![
            ("airlock/clipboards.json", nix_record! { "text": serde_json::to_string(&connections).expect("clipboard contracts serialize") }),
            ("qubes-rpc/airlock.ClipboardEndpoint", nix_record! { "source": endpoint }),
        ];
        if !physical { etc.push(("qubes/policy.d/44-airlock-clipboard.policy", nix_record! { "text": rules.clone() })); }
        let body = ModuleBody::new(nix_record! { "environment": nix_record! { "etc": NixValue::record(etc) } });
        if physical {
            let policy = inputs.pkgs.clone().select("writeTextDir").call("etc/qubes/policy.d/44-airlock-clipboard.policy").call(rules);
            body.module(ModuleBody::new(nix_record! { "virtualisation": nix_record! { "qubes": nix_record! { "packages": NixValue::list([policy]) } } }))
        } else { body }
    }).into_expression()
}
