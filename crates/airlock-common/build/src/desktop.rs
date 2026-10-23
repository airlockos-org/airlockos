//! Install trusted desktop artwork and attribution without granting application launch authority.

use rusix::{
    interop::{
        Package,
        raw::{NixRepresentation, NixValue},
    },
    nix_record, nix_text,
};

pub use airlock_desktop::{CONTROL_ID, DESKTOP_ID, ICON_NAME, SETUP_ID, TAILSCALE_ID};

/// Install scalable and symbolic artwork under the identities used by desktop applications.
/// Aliases share the same source files; application VMs can resolve them through Qubes' icon RPC.
pub fn icons(pkgs: &NixValue) -> Package {
    let color = pkgs
        .clone()
        .select("writeText")
        .call("airlock.svg")
        .call(airlock_desktop::ICON_SVG);
    let symbolic = pkgs
        .clone()
        .select("writeText")
        .call("airlock-symbolic.svg")
        .call(airlock_desktop::SYMBOLIC_SVG);
    let entries = [ICON_NAME, DESKTOP_ID, SETUP_ID, CONTROL_ID]
        .into_iter()
        .flat_map(|id| {
            [
                nix_record! {
                    "name": format!("share/icons/hicolor/scalable/apps/{id}.svg"),
                    "path": color.clone(),
                },
                nix_record! {
                    "name": format!("share/icons/hicolor/symbolic/apps/{id}-symbolic.svg"),
                    "path": symbolic.clone(),
                },
            ]
        });

    Package::from_expression(
        pkgs.clone()
            .select("linkFarm")
            .call("airlock-desktop-icons")
            .call(NixValue::list(entries)),
    )
}

/// Give GNOME a hidden desktop identity for a service or review-only window.
/// Its executable deliberately does nothing: attribution must not introduce a new way
/// to launch a privileged review or replay an enrollment/notification request.
pub fn identity(pkgs: &NixValue, id: &str, name: &str, window_class: &str) -> NixValue {
    pkgs.clone().select("makeDesktopItem").call(nix_record! {
        "name": id,
        "desktopName": name,
        "icon": id,
        "noDisplay": true,
        "startupWMClass": window_class,
        "exec": nix_text!("{coreutils}/bin/true", coreutils = pkgs.clone().select("coreutils")),
    })
}
