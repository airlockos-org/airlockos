//! Install the native first-login setup application and session startup notifications.

use rusix::interop::raw::NixRepresentation;

use super::ModuleContext;
use airlock_sys_gui_service::command::DesktopCommand;
use rusix::{interop::raw::NixValue, nix_record, nix_text};

/// Adds the setup launcher and startup entries when this machine enables its GUI role.
/// The wrapper exposes the upstream Qubes client tools required by the native application.
pub(super) fn configuration(inputs: &ModuleContext, service: &super::Deployment) -> NixValue {
    let workspace = airlock_build::Workspace::new(rusix::interop::NixPath::from_expression(
        inputs.pkgs.clone().select("airlockAppsSource"),
    ));
    let native = airlock_build::Application::GuiSetup.build(&inputs.pkgs, &workspace);

    let setup = inputs
        .pkgs
        .clone()
        .select("writeShellApplication")
        .call(nix_record! {
            "name": "airlock-sys-gui-setup",
            "runtimeInputs": NixValue::list([inputs
                .pkgs
                .clone()
                .select("python3.pkgs.qubes-core-admin-client")]),
            "text": nix_text!(
                r#"
                    exec {native}/bin/airlock-sys-gui-setup "$@"
                "#,
                native = native,
            ),
        });
    let launcher = inputs
        .pkgs
        .clone()
        .select("makeDesktopItem")
        .call(nix_record! {
            "name": airlock_build::desktop::SETUP_ID,
            "desktopName": "AirlockOS Setup",
            "exec": nix_text!("{setup}/bin/airlock-sys-gui-setup", setup = setup.clone()),
            "icon": airlock_build::desktop::SETUP_ID,
            "startupWMClass": airlock_build::desktop::SETUP_ID,
            "categories": NixValue::list(["Settings".into()]),
        });

    let configuration = nix_record! {
        "environment": nix_record! {
            "systemPackages": NixValue::list([
                setup.clone(), launcher,
                airlock_build::desktop::icons(&inputs.pkgs).as_expression(),
                airlock_build::desktop::identity(
                    &inputs.pkgs, airlock_build::desktop::DESKTOP_ID, "AirlockOS",
                    airlock_build::desktop::DESKTOP_ID,
                ),
                airlock_build::desktop::identity(
                    &inputs.pkgs, airlock_build::desktop::CONTROL_ID, "sys-ctrl: Airlock Control",
                    &format!("sys-ctrl:{id}", id = airlock_build::desktop::CONTROL_ID),
                ),
            ]),
            "etc": nix_record! {
                "xdg/autostart/airlock-boot-notification.desktop": nix_record! {
                    "text": nix_text!(
                        r#"
                            [Desktop Entry]
                            Type=Application
                            Name=AirlockOS startup status
                            Icon={icon}
                            Exec={command}
                            OnlyShowIn=GNOME;
                        "#,
                        command = service.desktop_command(&DesktopCommand::BootNotification),
                        icon = airlock_build::desktop::ICON_NAME,
                    ),
                },
                "xdg/autostart/org.airlockos.Setup.desktop": nix_record! {
                    "text": nix_text!(
                        r#"
                            [Desktop Entry]
                            Type=Application
                            Name=AirlockOS Setup
                            Icon={icon}
                            Exec={setup}/bin/airlock-sys-gui-setup --auto
                            OnlyShowIn=GNOME;
                        "#,
                        setup = setup,
                        icon = airlock_build::desktop::SETUP_ID,
                    ),
                },
            },
        },
    };

    inputs
        .lib
        .clone()
        .select("mkIf")
        .call(inputs.config.clone().select("airlock.sysGuiGuest.enable"))
        .call(configuration)
}
