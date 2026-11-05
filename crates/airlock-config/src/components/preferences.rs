//! Derive desktop preference installation and Qubes permission from resolved GUI assignments.
//! Upstream maintains guivm tags for ordinary and disposable VMs; no guest selects its authority.

use crate::model::{GuestBackend, HostSnapshot, Role, VmSnapshot};
use airlock_machine_core::model::VmReference;
use airlock_nix_core::identity::GuestName as VmName;
use rusix::{
    interop::raw::NixValue,
    nix_record,
    nixos::{ContextualModule, ModuleBody, NixosModule},
};
use std::collections::BTreeMap;

/// Explicit reset values keep removing a relationship compatible with whole-machine reconciliation.
const SOURCE: &str = "airlock-desktop-preferences-source";

/// Membership is also a lifecycle input: changing it must restart the publisher VM.
const MEMBERS: &str = "airlock-desktop-preferences-members";

/// Install clients only for a GNOME provider, and record membership in its deployment identity.
pub(crate) fn configure(
    vms: &mut [VmSnapshot],
    publishers: &[VmName],
    host: Option<&HostSnapshot>,
) {
    let mut members = publishers
        .iter()
        .map(|name| (name.clone(), Vec::<String>::new()))
        .collect::<BTreeMap<_, _>>();
    for vm in vms
        .iter_mut()
        .filter(|vm| matches!(vm.backend, GuestBackend::Nixos))
    {
        vm.features.insert(SOURCE.into(), String::new());
        vm.features.insert(MEMBERS.into(), String::new());
        if matches!(vm.role, Role::Gui { .. }) {
            continue;
        }
        let gui = match &vm.guivm {
            VmReference::Named(name) => Some(name.as_str()),
            VmReference::Inherit => host.map(|host| host.gui.as_str()),
            VmReference::Disabled | VmReference::Empty => None,
        };
        let Some(gui) = gui.and_then(|name| publishers.iter().find(|gui| gui.as_str() == name))
        else {
            continue;
        };
        vm.features.insert(SOURCE.into(), gui.to_string());
        members.get_mut(gui).unwrap().push(vm.name.to_string());
        vm.modules.push(binding(gui.clone()));
    }
    for vm in vms {
        if let Some(mut clients) = members.remove(&vm.name) {
            clients.sort();
            // Ordinary deployment already stops changed GUI providers. Binding
            // membership into their identity tears down old qrexec streams,
            // including disposable clients, before new policy takes effect.
            vm.features.insert(
                MEMBERS.into(),
                serde_json::to_string(&clients).expect("GUI membership serializes"),
            );
        }
    }
}

/// Install a trusted source name through the common GUI module, never through a peer's snapshot.
fn binding(gui: VmName) -> NixosModule {
    NixosModule::with_context(move |context| {
        ModuleBody::new(nix_record! {
            "airlock": nix_record! { "appGui": nix_record! { "preferencesSource": gui.as_str() } },
            "assertions": NixValue::list([nix_record! {
                "assertion": context.config.select("airlock.appGui.preferencesSource").equals(gui.as_str()),
                "message": "Desktop preferences source must match the typed GUI association.",
            }]),
        }).import_value(crate::vm::application_gui())
    })
}

/// Permit only the fixed no-argument read service to each actual GUI provider.
/// Qubes updates guivm tags on association changes and gives disposables their actual domain identity.
/// Policy-only edits affect new calls; supported reassignment uses whole-machine lifecycle teardown.
pub fn policy<'a>(vms: impl Iterator<Item = &'a VmSnapshot>) -> String {
    let mut publishers = vms
        .filter(|vm| {
            vm.features
                .get(MEMBERS)
                .is_some_and(|value| !value.is_empty())
        })
        .map(|vm| vm.name.to_string())
        .collect::<Vec<_>>();
    publishers.sort();
    let mut policy = String::new();
    for gui in publishers {
        policy.push_str(&format!(
            "airlock.DesktopPreferences + @tag:guivm-{gui} {gui} allow autostart=no\n"
        ));
    }
    policy.push_str("airlock.DesktopPreferences * @anyvm @anyvm deny\n");
    policy
}

/// Place the closed preferences policy before general GUI rules, without any guest admin permission.
pub(crate) fn host_module(text: String) -> NixValue {
    ContextualModule::new(move |context| {
        let policy = context.pkgs.clone().select("writeTextDir")
            .call("etc/qubes/policy.d/43-airlock-desktop-preferences.policy").call(text.clone());
        ModuleBody::new(nix_record! {
            "virtualisation": nix_record! { "qubes": nix_record! { "packages": NixValue::list([policy]) } },
        })
    }).into_expression()
}
