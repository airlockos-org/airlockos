//! Preserve Qubes lifecycle ordering while calling native GPU validation and firmware code.

use crate::argument;
use airlock_qubes::{descriptor, gpu, values};
use pyo3::{
    prelude::*,
    types::{PyDict, PyTuple},
};
use serde_json::{Value, json};

/// Execute a native GPU operation with Qubes-compatible errors and no subprocess protocol.
fn call(py: Python<'_>, request: Value) -> PyResult<Value> {
    py.detach(|| airlock_dom0_service::gpu_request(request))
        .map_err(|error| crate::exception(py, "QubesException", format!("AMD VFCT: {error:#}")))
}

/// Observe inherited feature and assignment values without changing upstream objects.
fn snapshot(vm: &Bound<'_, PyAny>) -> PyResult<Value> {
    gpu::vm(vm).map_err(|error| crate::exception(vm.py(), "QubesException", error))
}

/// Read Rust-validated settings for this VM; ordinary VMs have no GPU override.
fn settings(vm: &Bound<'_, PyAny>) -> PyResult<Value> {
    call(
        vm.py(),
        json!({"operation":"settings", "name":vm.getattr("name")?.extract::<String>()?}),
    )
}

/// Dispatch methods bound to Qubes' own Extension base class.
fn invoke(
    name: &str,
    args: &Bound<'_, PyTuple>,
    _kwargs: Option<&Bound<'_, PyDict>>,
) -> PyResult<Py<PyAny>> {
    let py = args.py();
    let extension = argument(args, 0)?;
    if name == "render" {
        let xml = argument(args, 1)?;
        let vm = argument(args, 2)?;
        let settings = settings(&vm)?;
        let xml = if settings.is_null() {
            xml.extract::<String>()?
        } else {
            let report = values::plain(&values::optional(&vm, "_airlock_amd_vbios")?)
                .map_err(|error| crate::exception(py, "QubesException", error))?;
            let rendered = call(
                py,
                json!({
                    "operation":"render", "vm":snapshot(&vm)?, "slot":settings["guestSlot"],
                    "report":report, "xml":xml.extract::<String>()?,
                }),
            )?;
            rendered
                .as_str()
                .ok_or_else(|| {
                    pyo3::exceptions::PyTypeError::new_err("native renderer returned non-text XML")
                })?
                .to_owned()
        };
        return Ok(py
            .import("markupsafe")?
            .getattr("Markup")?
            .call1((xml,))?
            .unbind());
    }

    let vm = argument(args, 1)?;
    match name {
        "settings" => return Ok(values::python(py, &settings(&vm)?)?.unbind()),
        "on_load" => {
            vm.getattr("app")?
                .getattr("env")?
                .getattr("filters")?
                .set_item("airlock_amd_vbios", extension.getattr("render")?)?;
            // Instance pre-events run before the upstream PCI extension's class handlers.
            for (event, method) in [
                ("domain-pre-start", "on_pre_start"),
                ("device-pre-attach:pci", "on_hotplug"),
                ("device-pre-detach:pci", "on_hotplug"),
            ] {
                vm.call_method1("add_handler", (event, extension.getattr(method)?))?;
            }
        }
        "on_pre_start" => {
            vm.setattr("_airlock_amd_vbios", py.None())?;
            let settings = settings(&vm)?;
            if !settings.is_null() {
                call(
                    py,
                    json!({"operation":"validate", "vm":snapshot(&vm)?, "slot":settings["guestSlot"]}),
                )?;
            }
        }
        "on_pre_spawn" => {
            let settings = settings(&vm)?;
            if settings.is_null() {
                return Ok(py.None());
            }
            let prepare = || -> PyResult<()> {
                let report = call(
                    py,
                    json!({"operation":"prepare", "vm":snapshot(&vm)?, "slot":settings["guestSlot"]}),
                )?;
                vm.setattr("_airlock_amd_vbios", values::python(py, &report)?)?;
                let xml = vm.call_method0("create_config_file")?;
                let native = vm
                    .getattr("app")?
                    .getattr("vmm")?
                    .getattr("libvirt_conn")?
                    .call_method1("domainXMLToNative", ("xen-xl", xml, 0))?
                    .extract::<String>()?;
                call(
                    py,
                    json!({
                        "operation":"verify", "vm":snapshot(&vm)?, "slot":settings["guestSlot"],
                        "report":report, "native":native,
                    }),
                )?;
                vm.getattr("log")?.call_method1(
                    "info",
                    ("airlock-amd-vbios prepared %s", report.to_string()),
                )?;
                Ok(())
            };
            if let Err(error) = prepare() {
                vm.setattr("_airlock_amd_vbios", py.None())?;
                return Err(crate::exception(
                    py,
                    "QubesException",
                    format!("AMD VFCT preparation failed: {error}"),
                ));
            }
        }
        "on_stop" => vm.setattr("_airlock_amd_vbios", py.None())?,
        "on_hotplug" => {
            call(
                py,
                json!({
                    "operation":"hotplug", "name":vm.getattr("name")?.extract::<String>()?,
                    "running":vm.call_method0("is_running")?.is_truthy()?,
                }),
            )?;
        }
        _ => return Err(pyo3::exceptions::PyAttributeError::new_err(name.to_owned())),
    }
    Ok(py.None())
}

/// Register lifecycle metadata through Qubes' own decorators on native method descriptors.
pub(super) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = module.py();
    let extension = py.import("qubes.ext")?;
    let namespace = PyDict::new(py);
    for name in ["settings", "render", "on_pre_start", "on_hotplug"] {
        namespace.set_item(name, descriptor::method(py, name, invoke, false)?)?;
    }
    for (name, events) in [
        ("on_load", vec!["domain-init", "domain-load"]),
        ("on_pre_spawn", vec!["domain-pre-spawn"]),
        ("on_stop", vec!["domain-start-failed", "domain-stopped"]),
    ] {
        let method = descriptor::method(py, name, invoke, false)?;
        let decorate = extension
            .getattr("handler")?
            .call(PyTuple::new(py, events)?, None)?;
        namespace.set_item(name, decorate.call1((method,))?)?;
    }
    module.add(
        "AMDVBIOS",
        descriptor::subclass(py, "AMDVBIOS", extension.getattr("Extension")?, &namespace)?,
    )?;
    Ok(())
}
