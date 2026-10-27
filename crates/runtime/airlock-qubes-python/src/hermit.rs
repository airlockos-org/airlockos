//! A diskless Qubes VM class using upstream libvirt lifecycle and native artifact checks.
//! The feature holding the executable is installed by the checked configuration plan.

use crate::argument;
use airlock_nix_core::hermit_artifact::{AuthorityMode, Descriptor};
use airlock_qubes::descriptor;
use pyo3::{
    prelude::*,
    types::{PyDict, PyTuple},
};

/// Decode the exact image identity retained in the VM's approved configuration.
fn artifact(vm: &Bound<'_, PyAny>) -> PyResult<Descriptor> {
    let value = vm
        .getattr("features")?
        .get_item("airlock-hermit-artifact")?
        .extract::<String>()?;
    serde_json::from_str(&value).map_err(|error| crate::exception(vm.py(), "QubesException", error))
}

/// Resolve the admitted GUI reference through live upstream Qubes objects.
fn authority(vm: &Bound<'_, PyAny>, image: &Descriptor) -> PyResult<Option<u16>> {
    if image.authority != AuthorityMode::Normal {
        return Ok(None);
    }
    let name = vm
        .getattr("features")?
        .get_item("airlock-clipboard-authority")?
        .extract::<String>()?;
    name.parse::<airlock_nix_core::identity::GuestName>()
        .map_err(|e| crate::exception(vm.py(), "QubesException", e))?;
    let gui = vm.getattr("app")?.getattr("domains")?.get_item(&name)?;
    if !gui.call_method0("is_running")?.is_truthy()? {
        return Err(crate::exception(
            vm.py(),
            "QubesException",
            "clipboard GUI authority must be running",
        ));
    }
    let domain = gui.getattr("xid")?.extract::<u16>()?;
    if domain == 0 || domain >= 0x7ff0 {
        return Err(crate::exception(
            vm.py(),
            "QubesException",
            "invalid clipboard GUI domain",
        ));
    }
    Ok(Some(domain))
}

/// Implement only the guest ABI differences; upstream Qubes owns lifecycle execution.
fn invoke(
    name: &str,
    args: &Bound<'_, PyTuple>,
    kwargs: Option<&Bound<'_, PyDict>>,
) -> PyResult<Py<PyAny>> {
    let py = args.py();
    let vm = argument(args, 0)?;
    match name {
        "__init__" => {
            vm.setattr("volume_config", PyDict::new(py))?;
            py.import("qubes.vm.qubesvm")?
                .getattr("QubesVM")?
                .getattr("__init__")?
                .call(args, kwargs)?;
        }
        "kernel_path" => {
            return Ok(artifact(&vm)?
                .executable
                .as_str()
                .into_pyobject(py)?
                .into_any()
                .unbind());
        }
        "initramfs_path" => return Ok(py.None()),
        "on_pre_start" => {
            let image = artifact(&vm)?;
            let memory = vm.getattr("memory")?.extract::<u64>()?;
            let valid = vm.getattr("virt_mode")?.extract::<String>()? == "pvh"
                && vm.getattr("vcpus")?.extract::<u64>()? == 1
                && vm.getattr("maxmem")?.extract::<u64>()? == memory
                && vm.getattr("kernel")?.extract::<String>()?.is_empty()
                && vm.getattr("netvm")?.is_none()
                && vm.getattr("guivm")?.is_none()
                && vm.getattr("audiovm")?.is_none()
                && vm.getattr("volumes")?.len()? == 0
                && !vm
                    .getattr("features")?
                    .call_method1("get", ("qrexec", false))?
                    .is_truthy()?
                && !vm
                    .getattr("features")?
                    .call_method1("get", ("gui", false))?
                    .is_truthy()?;
            if !valid {
                return Err(crate::exception(
                    py,
                    "QubesException",
                    "incompatible Hermit guest configuration",
                ));
            }
            py.detach(|| airlock_dom0_service::hermit::verify(&image, memory))
                .map_err(|error| crate::exception(py, "QubesException", error))?;
            let name = vm.getattr("name")?.extract::<String>()?;
            let generation = vm
                .getattr("features")?
                .get_item("airlock-hermit-generation")?
                .extract::<String>()?;
            let authority = authority(&vm, &image)?;
            let nonce = py
                .detach(|| {
                    airlock_dom0_service::hermit::preparing_with_authority(
                        &name,
                        &image,
                        &generation,
                        authority,
                    )
                })
                .map_err(|error| crate::exception(py, "QubesException", error))?;
            vm.setattr("_airlock_hermit_nonce", nonce)?;
            vm.setattr("_airlock_hermit_authority", authority)?;
            vm.getattr("log")?.call_method1(
                "info",
                (
                    "airlock-hermit state=verified artifact=%s source=%s generation=%s",
                    image.sha256.as_str(),
                    image.source_revision.as_str(),
                    generation,
                ),
            )?;
        }
        "create_config_file" => {
            let xml = py
                .import("qubes.vm.qubesvm")?
                .getattr("QubesVM")?
                .getattr("create_config_file")?
                .call1((&vm,))?
                .extract::<String>()?;
            let image = artifact(&vm)?;
            let memory = vm.getattr("memory")?.extract::<u64>()?;
            let nonce = vm.getattr("_airlock_hermit_nonce")?.extract::<String>()?;
            let authority = authority(&vm, &image)?;
            if image.authority == AuthorityMode::Normal
                && authority
                    != vm
                        .getattr("_airlock_hermit_authority")?
                        .extract::<Option<u16>>()?
            {
                return Err(crate::exception(
                    py,
                    "QubesException",
                    "clipboard authority restarted during boot",
                ));
            }
            let xml = airlock_dom0_service::hermit::boot_xml_with_authority(
                &xml, &image, memory, &nonce, authority,
            )
            .map_err(|error| crate::exception(py, "QubesException", error))?;
            return Ok(xml.into_pyobject(py)?.into_any().unbind());
        }
        "on_started" => {
            let name = vm.getattr("name")?.extract::<String>()?;
            let xid = vm.getattr("xid")?.extract::<u32>()?;
            airlock_dom0_service::hermit::started(&name, xid)
                .map_err(|error| crate::exception(py, "QubesException", error))?;
            vm.getattr("log")?
                .call_method1("info", ("airlock-hermit state=started xid=%s", xid))?;
        }
        "on_stopped" => {
            let name = vm.getattr("name")?.extract::<String>()?;
            airlock_dom0_service::hermit::stopped(&name)
                .map_err(|error| crate::exception(py, "QubesException", error))?;
            vm.getattr("log")?.call_method1(
                "info",
                ("airlock-hermit state=stopped execution-evidence=removed",),
            )?;
        }
        _ => return Err(pyo3::exceptions::PyAttributeError::new_err(name.to_owned())),
    }
    Ok(py.None())
}

/// Register a normal QubesVM subclass with no root, private, volatile or kernel volumes.
pub(super) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = module.py();
    let namespace = PyDict::new(py);
    namespace.set_item(
        "__init__",
        descriptor::method(py, "__init__", invoke, false)?,
    )?;
    namespace.set_item(
        "create_config_file",
        descriptor::method(py, "create_config_file", invoke, false)?,
    )?;
    for name in ["kernel_path", "initramfs_path"] {
        namespace.set_item(name, descriptor::property(py, name, invoke)?)?;
    }
    for (name, events) in [
        ("on_pre_start", vec!["domain-pre-start"]),
        ("on_started", vec!["domain-start"]),
        ("on_stopped", vec!["domain-stopped", "domain-start-failed"]),
    ] {
        let method = descriptor::method(py, name, invoke, false)?;
        let decorate = py
            .import("qubes.events")?
            .getattr("handler")?
            .call(PyTuple::new(py, events)?, None)?;
        namespace.set_item(name, decorate.call1((method,))?)?;
    }
    let base = py.import("qubes.vm.qubesvm")?.getattr("QubesVM")?;
    module.add(
        "HermitVM",
        descriptor::subclass(py, "HermitVM", base, &namespace)?,
    )?;
    Ok(())
}
