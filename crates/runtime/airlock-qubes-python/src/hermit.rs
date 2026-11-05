//! Hermit lifecycle with an optional, explicitly admitted encrypted scratch disk.
//! The feature holding the executable is installed by the checked configuration plan.
//! For networking guests, the root-controlled `airlock-hermit-log-filter` feature
//! supplies an upstream `RUST_LOG`/kernel filter at next boot, for example
//! `info,airlock_sys_firewall=debug,xen_transport=debug`. Omission defaults to info;
//! trace includes packet lengths, never payloads. Logging grants no control rights.

use crate::argument;
use airlock_nix_core::hermit_artifact::{AuthorityMode, Descriptor, ScratchDisk};
use airlock_qubes::descriptor;
use airlock_qubes_network::{READY_PATH, config::MAX_CLIENTS};
use pyo3::{
    prelude::*,
    types::{PyDict, PyTuple},
};

mod network;

mod recovery;

/// Decode the exact image identity retained in the VM's approved configuration.
fn artifact(vm: &Bound<'_, PyAny>) -> PyResult<Descriptor> {
    let value = vm
        .getattr("features")?
        .get_item("airlock-hermit-artifact")?
        .extract::<String>()?;
    serde_json::from_str(&value).map_err(|error| crate::exception(vm.py(), "QubesException", error))
}

/// Decode only the scratch feature derived from an admitted backend by setup.
fn scratch(vm: &Bound<'_, PyAny>) -> PyResult<Option<ScratchDisk>> {
    let value = vm
        .getattr("features")?
        .call_method1("get", ("airlock-hermit-scratch", ""))?
        .extract::<String>()?;
    if value.is_empty() {
        return Ok(None);
    }
    let disk: ScratchDisk =
        serde_json::from_str(&value).map_err(|e| crate::exception(vm.py(), "QubesException", e))?;
    disk.validate()
        .map_err(|e| crate::exception(vm.py(), "QubesException", e))?;
    Ok(Some(disk))
}

/// Admit one reset-on-start, freshly encrypted volume through upstream storage.
/// Initialization creates metadata only; Qubes' authorized start performs I/O.
fn prepare_scratch(
    vm: &Bound<'_, PyAny>,
    disk: Option<ScratchDisk>,
    initialize: bool,
) -> PyResult<()> {
    let py = vm.py();
    let volumes = vm.getattr("volumes")?;
    if volumes.len()? != 0 {
        // Reconcile only our canonical ephemeral metadata, after upstream stop
        // has removed both its file and encryption mapping. No disk is deleted
        // here, and active/exported volumes cannot be replaced during rollback.
        validate_scratch(vm, None)?;
        let volume = volumes.get_item("volatile")?;
        let current = volume.getattr("size")?.extract::<u64>()?;
        if disk.is_none_or(|disk| disk.bytes != current) {
            let name: airlock_nix_core::identity::GuestName = vm
                .getattr("name")?
                .extract::<String>()?
                .parse()
                .map_err(|e| crate::exception(py, "QubesException", e))?;
            let source = ScratchDisk { bytes: current }.device_path(&name);
            let path = volume.getattr("path")?.extract::<String>()?;
            let inactive = initialize
                && vm.call_method0("is_halted")?.is_truthy()?
                && !volume.call_method0("is_running")?.is_truthy()?
                && !std::path::Path::new(&path).try_exists()?
                && !std::path::Path::new(&source).try_exists()?;
            if !inactive {
                return Err(crate::exception(
                    py,
                    "QubesException",
                    "scratch contract may change only after storage cleanup",
                ));
            }
            // FilePool's public list exposes its metadata cache. Retire the
            // same object without invoking remove(), which performs disk I/O.
            volume
                .getattr("pool")?
                .call_method0("list_volumes")?
                .call_method1("remove", (&volume,))?;
            volumes.del_item("volatile")?;
            vm.getattr("volume_config")?.del_item("volatile")?;
        }
    }
    let Some(disk) = disk else {
        return Ok(());
    };
    if volumes.len()? == 0 {
        if !initialize || !vm.call_method0("is_halted")?.is_truthy()? {
            return Err(crate::exception(
                py,
                "QubesException",
                "scratch may only be initialized before an authorized start",
            ));
        }
        let config = PyDict::new(py);
        for (key, value) in [
            ("rw", true),
            ("snap_on_start", false),
            ("save_on_stop", false),
            ("ephemeral", true),
        ] {
            config.set_item(key, value)?;
        }
        config.set_item("size", disk.bytes)?;
        config.set_item("revisions_to_keep", 0)?;
        vm.getattr("storage")?
            .call_method1("init_volume", ("volatile", &config))?;
        vm.getattr("volume_config")?.set_item("volatile", config)?;
    }
    validate_scratch(vm, Some(disk.bytes))
}

/// Validate identity and flags before querying paths or size from a volume.
fn validate_scratch(vm: &Bound<'_, PyAny>, bytes: Option<u64>) -> PyResult<()> {
    let py = vm.py();
    let volumes = vm.getattr("volumes")?;
    if volumes.len()? != 1 || !volumes.contains("volatile")? {
        return Err(crate::exception(
            py,
            "QubesException",
            "Hermit requires its sole declared scratch volume",
        ));
    }
    let volume = volumes.get_item("volatile")?;
    let name = vm.getattr("name")?.extract::<String>()?;
    // Hermit is not a TemplateVM: upstream FilePool owns this canonical VID.
    let expected_vid = format!("appvms/{name}/volatile");
    let valid = volume.getattr("name")?.extract::<String>()? == "volatile"
        && volume.getattr("vid")?.extract::<String>()? == expected_vid
        && volume
            .getattr("pool")?
            .getattr("driver")?
            .extract::<String>()?
            == "file"
        && volume.getattr("source")?.is_none()
        && volume.getattr("domain")?.is_none()
        && volume.getattr("rw")?.is_truthy()?
        && volume.getattr("ephemeral")?.is_truthy()?
        && !volume.getattr("save_on_stop")?.is_truthy()?
        && !volume.getattr("snap_on_start")?.is_truthy()?
        && volume.getattr("revisions_to_keep")?.extract::<u64>()? == 0
        && {
            let size = volume.getattr("size")?.extract::<u64>()?;
            ScratchDisk { bytes: size }.validate().is_ok()
                && bytes.is_none_or(|bytes| bytes == size)
        };
    if !valid {
        return Err(crate::exception(
            py,
            "QubesException",
            "Hermit scratch volume differs from the admitted ephemeral contract",
        ));
    }
    Ok(())
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

/// Bind one boot to the live relationships appropriate to its application.
/// Qubes 4.3.44 starts netvm between pre-start and pre-spawn, so a network
/// application captures its upstream only at pre-spawn. Clipboard keeps its
/// existing earlier authority/scratch preparation ordering.
fn prepare_boot(vm: &Bound<'_, PyAny>, image: &Descriptor) -> PyResult<()> {
    let py = vm.py();
    let name = vm.getattr("name")?.extract::<String>()?;
    let generation = vm
        .getattr("features")?
        .get_item("airlock-hermit-generation")?
        .extract::<String>()?;
    let authority = authority(vm, image)?;
    let upstream = network::attachment(vm, image)?;
    let nonce = py
        .detach(|| {
            if let Some(upstream) = upstream {
                airlock_dom0_service::hermit::preparing_with_network(
                    &name,
                    image,
                    &generation,
                    upstream,
                )
            } else {
                airlock_dom0_service::hermit::preparing_with_authority(
                    &name,
                    image,
                    &generation,
                    authority,
                )
            }
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
    Ok(())
}

/// Complete the native control startup handoff on Qubes' own event loop.
/// Guest readiness selects no clients or rules: the protected boot record and
/// current upstream NetVM relationships determine the normal policy rewrites.
/// Calls are synchronous, bounded by the supported client count and idempotent
/// within a boot. A qubesd restart may safely repeat the upstream replacement.
fn refresh_control_policies(vm: &Bound<'_, PyAny>) -> PyResult<()> {
    let py = vm.py();
    if !artifact(vm)?.application.networking()
        || !vm.getattr("provides_network")?.is_truthy()?
        || !vm.call_method0("is_running")?.is_truthy()?
    {
        return Ok(());
    }
    let value = vm
        .getattr("untrusted_qdb")?
        .call_method1("read", (READY_PATH,))?
        .extract::<Option<Vec<u8>>>()?;
    let Some(value) = value else {
        return Ok(());
    };
    let Ok(challenge) = String::from_utf8(value) else {
        return Ok(());
    };
    if challenge.len() != 36 {
        return Ok(());
    }
    let xid = vm.getattr("xid")?.extract::<u32>()?;
    if vm.hasattr("_airlock_hermit_control_refreshed")? {
        let previous = vm.getattr("_airlock_hermit_control_refreshed")?;
        if !previous.is_none() && previous.extract::<(u32, String)>()? == (xid, challenge.clone()) {
            return Ok(());
        }
    }
    let name = vm.getattr("name")?.extract::<String>()?;
    let image = artifact(vm)?;
    if !airlock_dom0_service::hermit::control_boot_matches(&name, &image, xid, challenge.as_bytes())
        .map_err(|error| crate::exception(py, "QubesException", error))?
    {
        return Ok(());
    }

    // Bound collection before the first rewrite. Never select an arbitrary
    // subset when the configured topology exceeds the guest's capacity.
    let mut clients = Vec::new();
    for client in vm.getattr("connected_vms")?.try_iter()? {
        let client = client?;
        if clients.len() == MAX_CLIENTS {
            return Err(crate::exception(
                py,
                "QubesException",
                "native Hermit firewall client capacity exceeded",
            ));
        }
        clients.push(client);
    }
    for client in clients {
        if client.getattr("netvm")?.is(vm) && client.call_method0("is_running")?.is_truthy()? {
            vm.call_method1("reload_firewall_for_vm", (client,))?;
        }
    }
    vm.setattr("_airlock_hermit_control_refreshed", (xid, challenge))?;
    vm.getattr("log")?.call_method1(
        "info",
        ("airlock-hermit native-control=synchronized policies=refreshed",),
    )?;
    Ok(())
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
        "shutdown" | "kill" => {
            recovery::requested_stop(&vm)?;
            return Ok(py
                .import("qubes.vm.qubesvm")?
                .getattr("QubesVM")?
                .getattr(name)?
                .call(args, kwargs)?
                .unbind());
        }
        "_prepare_scratch" => prepare_scratch(&vm, scratch(&vm)?, true)?,
        "__init__" => {
            vm.setattr("volume_config", PyDict::new(py))?;
            py.import("qubes.vm.qubesvm")?
                .getattr("QubesVM")?
                .getattr("__init__")?
                .call(args, kwargs)?;
            // Upstream installs/reinstalls this watch before resuming the guest.
            // Registration also works when loading an already-running domain.
            vm.call_method1("watch_qdb_path", (READY_PATH,))?;
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
            recovery::guard(&vm, true)?;
            // A failed preflight must not reuse a previous boot's cleanup authority.
            vm.setattr("_airlock_hermit_scratch", "")?;
            vm.setattr("_airlock_hermit_control_refreshed", py.None())?;
            let image = artifact(&vm)?;
            network::validate_provider(&vm, &image)?;
            let memory = vm.getattr("memory")?.extract::<u64>()?;
            let valid = vm.getattr("virt_mode")?.extract::<String>()? == "pvh"
                && vm.getattr("vcpus")?.extract::<u64>()? == 1
                && vm.getattr("maxmem")?.extract::<u64>()? == memory
                && vm.getattr("kernel")?.extract::<String>()?.is_empty()
                && (image.application.networking() != vm.getattr("netvm")?.is_none())
                && (image.application.networking()
                    == vm.getattr("provides_network")?.is_truthy()?)
                && vm.getattr("guivm")?.is_none()
                && vm.getattr("audiovm")?.is_none()
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
            let disk = scratch(&vm)?;
            prepare_scratch(&vm, disk, true)?;
            vm.setattr(
                "_airlock_hermit_scratch",
                serde_json::to_string(&disk)
                    .map_err(|e| crate::exception(py, "QubesException", e))?,
            )?;
            vm.setattr("_airlock_hermit_nonce", "")?;
            if !image.application.networking() {
                prepare_boot(&vm, &image)?;
            }
        }
        "on_pre_spawn" => {
            recovery::guard(&vm, false)?;
            let image = artifact(&vm)?;
            if image.application.networking() {
                prepare_boot(&vm, &image)?;
            }
        }
        "create_config_file" => {
            recovery::guard(&vm, false)?;
            let disk = scratch(&vm)?;
            prepare_scratch(&vm, disk, false)?;
            let encoded = serde_json::to_string(&disk)
                .map_err(|e| crate::exception(py, "QubesException", e))?;
            if vm.getattr("_airlock_hermit_scratch")?.extract::<String>()? != encoded {
                return Err(crate::exception(
                    py,
                    "QubesException",
                    "scratch contract changed during boot",
                ));
            }
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
            let name: airlock_nix_core::identity::GuestName = vm
                .getattr("name")?
                .extract::<String>()?
                .parse()
                .map_err(|e| crate::exception(py, "QubesException", e))?;
            let upstream = network::attachment(&vm, &image)?;
            let xml = if let Some(upstream) = upstream {
                if !airlock_dom0_service::hermit::network_boot_matches(
                    name.as_str(),
                    &image,
                    &nonce,
                    &upstream,
                )
                .map_err(|error| crate::exception(py, "QubesException", error))?
                {
                    return Err(crate::exception(
                        py,
                        "QubesException",
                        "upstream changed during firewall startup",
                    ));
                }
                let log_filter = vm
                    .getattr("features")?
                    .call_method1("get", ("airlock-hermit-log-filter",))?
                    .extract::<Option<String>>()?;
                airlock_dom0_service::hermit::boot_xml_with_network(
                    &xml,
                    &image,
                    memory,
                    &nonce,
                    &upstream,
                    log_filter.as_deref(),
                )
            } else {
                airlock_dom0_service::hermit::boot_xml_with_scratch(
                    &xml,
                    &image,
                    memory,
                    &nonce,
                    authority,
                    disk.as_ref().map(|disk| (disk, &name)),
                )
            }
            .map_err(|error| crate::exception(py, "QubesException", error))?;
            recovery::guard(&vm, false)?;
            return Ok(xml.into_pyobject(py)?.into_any().unbind());
        }
        "on_started" => {
            let name = vm.getattr("name")?.extract::<String>()?;
            let xid = vm.getattr("xid")?.extract::<u32>()?;
            airlock_dom0_service::hermit::started(&name, xid)
                .map_err(|error| crate::exception(py, "QubesException", error))?;
            recovery::observe_running(&vm, &artifact(&vm)?)?;
            vm.getattr("log")?
                .call_method1("info", ("airlock-hermit state=started xid=%s", xid))?;
            // A fast guest can notify before domain-start records its xid. The
            // read here closes that race without another guest request/replay.
            refresh_control_policies(&vm)?;
        }
        "on_control_ready" => refresh_control_policies(&vm)?,
        "on_lifecycle_guard" => recovery::guard(&vm, false)?,
        "on_stopped" | "on_start_failed" => {
            let vm_name = vm.getattr("name")?.extract::<String>()?;
            airlock_dom0_service::hermit::stopped(&vm_name)
                .map_err(|error| crate::exception(py, "QubesException", error))?;
            if name == "on_stopped" {
                recovery::check(&vm);
            }
            vm.getattr("log")?.call_method1(
                "info",
                ("airlock-hermit state=stopped execution-evidence=removed",),
            )?;
            if name == "on_start_failed" {
                // Qubes does not stop storage when start_encrypted fails before
                // domain creation. Await its own cleanup before allowing a retry;
                // otherwise FileVolume retains its running/export lock. Never
                // operate on a live domain or metadata outside this boot's contract.
                let captured = if vm.hasattr("_airlock_hermit_scratch")? {
                    vm.getattr("_airlock_hermit_scratch")?.extract::<String>()?
                } else {
                    String::new()
                };
                if !captured.is_empty() && vm.call_method0("is_halted")?.is_truthy()? {
                    let disk: Option<ScratchDisk> = serde_json::from_str(&captured)
                        .map_err(|e| crate::exception(py, "QubesException", e))?;
                    if let Some(disk) = disk {
                        validate_scratch(&vm, Some(disk.bytes))?;
                        return Ok(vm.getattr("storage")?.call_method0("stop")?.unbind());
                    }
                }
                return Ok(py.import("asyncio")?.call_method1("sleep", (0,))?.unbind());
            }
        }
        _ => return Err(pyo3::exceptions::PyAttributeError::new_err(name.to_owned())),
    }
    Ok(py.None())
}

/// Register a QubesVM subclass with no Linux volumes and optional encrypted scratch.
pub(super) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = module.py();
    let namespace = PyDict::new(py);
    namespace.set_item(
        "__init__",
        descriptor::method(py, "__init__", invoke, false)?,
    )?;
    namespace.set_item(
        "_prepare_scratch",
        descriptor::method(py, "_prepare_scratch", invoke, false)?,
    )?;
    namespace.set_item(
        "create_config_file",
        descriptor::method(py, "create_config_file", invoke, false)?,
    )?;
    for name in ["shutdown", "kill"] {
        let method = descriptor::method(py, name, invoke, false)?;
        py.import("inspect")?
            .call_method1("markcoroutinefunction", (&method,))?;
        namespace.set_item(name, method)?;
    }
    for name in ["kernel_path", "initramfs_path"] {
        namespace.set_item(name, descriptor::property(py, name, invoke)?)?;
    }
    let ready_event = format!("domain-qdb-change:{READY_PATH}");
    for (name, events) in [
        ("on_pre_start", vec!["domain-pre-start"]),
        ("on_pre_spawn", vec!["domain-pre-spawn"]),
        ("on_started", vec!["domain-start"]),
        (
            "on_lifecycle_guard",
            vec!["domain-pre-shutdown", "domain-pre-unpaused"],
        ),
        ("on_stopped", vec!["domain-stopped"]),
        ("on_start_failed", vec!["domain-start-failed"]),
        (
            "on_control_ready",
            vec![ready_event.as_str(), "domain-load"],
        ),
    ] {
        let method = descriptor::method(py, name, invoke, false)?;
        if name == "on_start_failed" {
            // Return the original Python storage coroutine, letting Qubes await
            // it on its existing event loop. Native code performs no async I/O.
            py.import("inspect")?
                .call_method1("markcoroutinefunction", (&method,))?;
        }
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

/// Register reviewed relationship guards and bounded network recovery on Qubes events.
pub(super) fn register_network(module: &Bound<'_, PyModule>) -> PyResult<()> {
    network::register(module)
}
