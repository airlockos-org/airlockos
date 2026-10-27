//! Assemble installation media from the same native services used by the installed machine.

mod store;

mod usb;

mod local;

mod console;

mod repair;

use airlock_build::Workspace;
use rusix::{
    interop::{
        NixPath,
        raw::{NixRepresentation, NixValue},
    },
    nix_record,
};

/// Export image operations with explicit application sources and deferred target package sets.
pub(crate) fn constructors() -> NixValue {
    NixValue::function(|apps| {
        let workspace = Workspace::new(NixPath::from_expression(apps));

        nix_record! {
            "preparedStore": NixValue::function_attrs_open(["pkgs", "entries", "offlineInputs"], |args| {
                (
                    vec![("offlineInputs", NixValue::null())],
                    store::prepared(
                        &args.clone().select("pkgs"),
                        &workspace,
                        args.clone().select("entries"),
                        args.select("offlineInputs"),
                    ),
                )
            }),
            "repair": repair::constructor(&workspace),
            "runtimeTool": NixValue::function(|pkgs| store::runtime_tool(&pkgs, &workspace)),
            "usb": usb::module(&workspace),
            "console": console::module(),
        }
    })
}

/// Build the installed runtime preparation command with its Qubes bridge.
pub(crate) use store::runtime_tool;

/// Build immutable VM payloads and their independent builder views.
pub(crate) use store::prepared as prepared_store;

/// Construct the USB image module from the selected application source.
pub(crate) use usb::module as usb_module;

/// Construct the independent physical console image.
pub(crate) use console::module as console_module;

/// Construct a guarded host-only repair against an admitted baseline.
pub(crate) use repair::constructor as repair_constructor;

/// Assemble a QEMU disk using the same prepared VM pool and Qubes runtime as physical images.
pub(crate) use local::module as local_module;
