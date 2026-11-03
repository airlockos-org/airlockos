//! Read Qubes relationships and enforce the immutable generation's native-vif scope.
//! Qubes retains device creation, startup, reattachment and policy publication.

use super::artifact;
use airlock_nix_core::hermit_artifact::{Descriptor, NetworkAttachment};
use airlock_qubes::descriptor;
use pyo3::{
    prelude::*,
    types::{PyDict, PyTuple, PyType},
};

/// Read the protected topology containing this exact executable descriptor.
fn contract(
    vm: &Bound<'_, PyAny>,
    image: &Descriptor,
) -> PyResult<airlock_dom0_service::hermit::NetworkContract> {
    let name = vm.getattr("name")?.extract::<String>()?;
    let generation = vm
        .getattr("features")?
        .get_item("airlock-hermit-generation")?
        .extract::<String>()?;
    vm.py()
        .detach(|| airlock_dom0_service::hermit::network_contract(&name, image, &generation))
        .map_err(|error| crate::exception(vm.py(), "QubesException", error))
}

/// Reject live downstream relationships outside the reviewed native firewall scope.
/// Bounded upstream object inspection is not a new network-management API.
pub(super) fn validate_provider(vm: &Bound<'_, PyAny>, image: &Descriptor) -> PyResult<()> {
    if !image.application.networking() {
        return Ok(());
    }
    let declared = contract(vm, image)?;
    let upstream = vm.getattr("netvm")?;
    if upstream.is_none()
        || upstream.getattr("name")?.extract::<String>()? != declared.provider.as_str()
        || !vm.getattr("provides_network")?.is_truthy()?
    {
        return Err(crate::exception(
            vm.py(),
            "QubesException",
            "firewall upstream differs from its reviewed generation",
        ));
    }
    let mut count = 0;
    for client in vm.getattr("connected_vms")?.try_iter()? {
        count += 1;
        if count > 4 {
            return Err(crate::exception(
                vm.py(),
                "QubesException",
                "native firewall client capacity exceeded",
            ));
        }
        let client = client?;
        let name = client.getattr("name")?.extract::<String>()?;
        if !declared
            .clients
            .iter()
            .any(|client| client.as_str() == name)
            || !client.getattr("netvm")?.is(vm)
        {
            return Err(crate::exception(
                vm.py(),
                "QubesException",
                "undeclared native firewall client",
            ));
        }
    }
    Ok(())
}

/// Capture only the ordinary Qubes properties used by its pinned net.xml template.
/// Qubes validates MAC syntax; std IP parsers retain the exact assigned address.
pub(super) fn attachment(
    vm: &Bound<'_, PyAny>,
    image: &Descriptor,
) -> PyResult<Option<NetworkAttachment>> {
    if !image.application.networking() {
        return Ok(None);
    }
    validate_provider(vm, image)?;
    let py = vm.py();
    let upstream = vm.getattr("netvm")?;
    if !upstream.call_method0("is_running")?.is_truthy()? {
        return Err(crate::exception(
            py,
            "QubesException",
            "firewall upstream is not running",
        ));
    }
    let provider = upstream
        .getattr("name")?
        .extract::<String>()?
        .parse()
        .map_err(|error| crate::exception(py, "QubesException", error))?;
    let xid = upstream.getattr("xid")?.extract::<u16>()?;
    if xid == 0 || xid >= 0x7ff0 {
        return Err(crate::exception(
            py,
            "QubesException",
            "invalid upstream Xen identity",
        ));
    }
    let address = vm
        .getattr("ip")?
        .str()?
        .to_str()?
        .parse()
        .map_err(|error| crate::exception(py, "QubesException", error))?;
    let ip6 = vm.getattr("ip6")?;
    let address6 = if ip6.is_none() {
        None
    } else {
        Some(
            ip6.str()?
                .to_str()?
                .parse()
                .map_err(|error| crate::exception(py, "QubesException", error))?,
        )
    };
    Ok(Some(NetworkAttachment {
        provider,
        xid,
        mac: vm.getattr("mac")?.extract()?,
        address,
        address6,
    }))
}

/// Check an actual client before its upstream-controlled lifecycle creates a vif.
fn validate_client(
    client: &Bound<'_, PyAny>,
    provider: &Bound<'_, PyAny>,
    hermit_type: &Bound<'_, PyType>,
) -> PyResult<()> {
    if provider.is_none() || !provider.is_instance(hermit_type)? {
        return Ok(());
    }
    let image = artifact(provider)?;
    let declared = contract(provider, &image)?;
    let name = client.getattr("name")?.extract::<String>()?;
    if !declared
        .clients
        .iter()
        .any(|client| client.as_str() == name)
    {
        return Err(crate::exception(
            client.py(),
            "QubesException",
            "client is outside the native firewall's reviewed generation",
        ));
    }
    Ok(())
}

/// Instance pre-events run before Qubes' class-level NetVM handlers. Halted
/// property changes may stage configuration; startup always checks it afresh.
fn invoke(
    name: &str,
    args: &Bound<'_, PyTuple>,
    kwargs: Option<&Bound<'_, PyDict>>,
) -> PyResult<Py<PyAny>> {
    let py = args.py();
    let extension = crate::argument(args, 0)?;
    let vm = crate::argument(args, 1)?;
    let hermit_type = extension.getattr("_hermit_type")?.cast_into::<PyType>()?;
    if name == "on_load" {
        for (event, method) in [
            ("domain-pre-start", "on_start"),
            ("domain-pre-spawn", "on_start"),
            ("property-pre-set:netvm", "on_set"),
            ("property-pre-reset:netvm", "on_reset"),
            ("domain-start", "on_upstream_started"),
        ] {
            vm.call_method1("add_handler", (event, extension.getattr(method)?))?;
        }
        if vm.is_instance(&hermit_type)? && vm.call_method0("is_running")?.is_truthy()? {
            super::recovery::observe_running(&vm, &artifact(&vm)?)?;
        }
    } else if name == "on_upstream_started" {
        super::recovery::upstream_started(&vm, &hermit_type)?;
    } else {
        if name != "on_start" && vm.call_method0("is_halted")?.is_truthy()? {
            return Ok(py.None());
        }
        let provider = match name {
            "on_start" => vm.getattr("netvm")?,
            "on_reset" => vm.call_method1("property_get_default", ("netvm",))?,
            "on_set" => kwargs
                .and_then(|kwargs| kwargs.get_item("newvalue").transpose())
                .transpose()?
                .ok_or_else(|| pyo3::exceptions::PyTypeError::new_err("missing NetVM value"))?,
            _ => return Err(pyo3::exceptions::PyAttributeError::new_err(name.to_owned())),
        };
        if name != "on_start" && vm.is_instance(&hermit_type)? {
            let image = artifact(&vm)?;
            let valid = if image.application.networking() {
                !provider.is_none()
                    && provider.getattr("name")?.extract::<String>()?
                        == contract(&vm, &image)?.provider.as_str()
            } else {
                provider.is_none()
            };
            if !valid {
                return Err(crate::exception(
                    py,
                    "QubesException",
                    "live Hermit upstream differs from its reviewed generation",
                ));
            }
        }
        validate_client(&vm, &provider, &hermit_type)?;
    }
    Ok(py.None())
}

/// Register relationship guards and bounded native recovery on upstream Qubes events.
pub(super) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = module.py();
    let extension = py.import("qubes.ext")?;
    let namespace = PyDict::new(py);
    // Retain the actual registered Python subclass, including for subclass checks.
    namespace.set_item(
        "_hermit_type",
        module.getattr("HermitVM")?.cast_into::<PyType>()?,
    )?;
    for name in ["on_start", "on_set", "on_reset", "on_upstream_started"] {
        namespace.set_item(name, descriptor::method(py, name, invoke, false)?)?;
    }
    let method = descriptor::method(py, "on_load", invoke, false)?;
    let decorate = extension
        .getattr("handler")?
        .call(PyTuple::new(py, ["domain-init", "domain-load"])?, None)?;
    namespace.set_item("on_load", decorate.call1((method,))?)?;
    module.add(
        "HermitNetworking",
        descriptor::subclass(
            py,
            "HermitNetworking",
            extension.getattr("Extension")?,
            &namespace,
        )?,
    )?;
    Ok(())
}
