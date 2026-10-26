//! Implement Qubes callbacks with typed in-process engine calls.
//! Upstream kwargs remain Python objects; only Airlock metadata crosses into native policy.

use crate::{argument, keyword, native};
use airlock_dom0_service::storage_plugin::{
    self as engine, Action, Definition, GenerationIdentity, LifecycleRequest, Metadata,
    NormalizationInput, ViewKind,
};
use airlock_qubes::descriptor;
use pyo3::{
    prelude::*,
    types::{PyBool, PyDict, PyInt, PyTuple},
};
use std::{
    num::NonZeroU64,
    path::{Path, PathBuf},
};

mod operation;

/// Report malformed adapter inputs through upstream's storage exception family.
fn invalid(py: Python<'_>, message: impl std::fmt::Display) -> PyErr {
    crate::exception(py, "StoragePoolException", message)
}

/// Extract an optional string while preserving Python None.
fn text(value: &Bound<'_, PyAny>) -> PyResult<Option<String>> {
    if value.is_none() {
        Ok(None)
    } else {
        value
            .extract()
            .map(Some)
            .map_err(|error| invalid(value.py(), error))
    }
}

/// Accept the existing persisted decimal spelling or a positive Python integer.
fn number(value: &Bound<'_, PyAny>) -> PyResult<Option<NonZeroU64>> {
    if value.is_none() {
        return Ok(None);
    }
    if value.is_instance_of::<PyBool>() {
        return Err(invalid(
            value.py(),
            "storage size/generation must not be boolean",
        ));
    }
    let number = if let Ok(text) = value.extract::<String>() {
        text.parse::<u64>()
            .map_err(|error| invalid(value.py(), error))?
    } else {
        if !value.is_instance_of::<PyInt>() {
            return Err(invalid(
                value.py(),
                "storage size/generation must be an integer or decimal string",
            ));
        }
        value
            .extract::<u64>()
            .map_err(|error| invalid(value.py(), error))?
    };
    NonZeroU64::new(number)
        .map(Some)
        .ok_or_else(|| invalid(value.py(), "storage size/generation must be positive"))
}

/// Extract a path without transporting it through JSON.
fn path(value: &Bound<'_, PyAny>) -> PyResult<Option<PathBuf>> {
    Ok(text(value)?.map(PathBuf::from))
}

/// Preserve upstream string path fields; this interface accepts UTF-8 configuration paths.
fn path_text(value: &Path) -> PyResult<&str> {
    value
        .to_str()
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("non-UTF-8 storage path"))
}

/// Remove one Airlock-owned constructor field, preserving absence as Python None.
fn take<'py>(config: &Bound<'py, PyDict>, name: &str) -> PyResult<Bound<'py, PyAny>> {
    let value = config
        .get_item(name)?
        .unwrap_or(config.py().None().into_bound(config.py()));
    if config.contains(name)? {
        config.del_item(name)?;
    }
    Ok(value)
}

/// Reject unknown view implementations using the production verified parser.
fn kind(value: &Bound<'_, PyAny>) -> PyResult<ViewKind> {
    let name: String = value
        .extract()
        .map_err(|error| invalid(value.py(), error))?;
    ViewKind::parse(&name).ok_or_else(|| invalid(value.py(), "unsupported storage view kind"))
}

/// Preserve strict boolean constructor semantics rather than accepting truthy Python objects.
fn flag(config: &Bound<'_, PyDict>, name: &str) -> PyResult<bool> {
    match config.get_item(name)? {
        None => Ok(false),
        Some(value) if value.is_instance_of::<PyBool>() => value.extract(),
        Some(_) => Err(invalid(
            config.py(),
            "immutable volume flag must be boolean",
        )),
    }
}

/// Collect observed view metadata directly into the shared Rust definition.
fn definition(object: &Bound<'_, PyAny>) -> PyResult<Definition> {
    Ok(Definition {
        view_kind: kind(&object.getattr("view_kind")?)?,
        view_path: path(&object.getattr("path")?)?,
        blob_map_path: path(&object.getattr("blob_map_path")?)?,
        blob_logical_size: number(&object.getattr("blob_logical_size")?)?,
        manifest_path: path(&object.getattr("manifest_path")?)?,
    })
}

/// Build upstream metadata fields at the Python edge, without an intermediate JSON record.
fn metadata_fields<'py>(py: Python<'py>, metadata: &Metadata) -> PyResult<Bound<'py, PyDict>> {
    let fields = PyDict::new(py);
    fields.set_item("domain_name", &metadata.domain_name)?;
    fields.set_item(
        "generation",
        metadata.generation.map(|value| value.to_string()),
    )?;
    fields.set_item("closure_hash", &metadata.closure_hash)?;
    let view = &metadata.definition;
    fields.set_item("view_kind", view.view_kind.name())?;
    fields.set_item(
        "view_path",
        view.view_path.as_deref().map(path_text).transpose()?,
    )?;
    fields.set_item(
        "blob_map_path",
        view.blob_map_path.as_deref().map(path_text).transpose()?,
    )?;
    fields.set_item(
        "blob_logical_size",
        view.blob_logical_size.map(NonZeroU64::get),
    )?;
    fields.set_item(
        "manifest_path",
        view.manifest_path.as_deref().map(path_text).transpose()?,
    )?;
    Ok(fields)
}

/// Snapshot one lifecycle request on Qubes' thread; workers receive no upstream objects.
fn lifecycle_request(object: &Bound<'_, PyAny>, action: Action) -> PyResult<LifecycleRequest> {
    let domain = text(&object.getattr("domain_name")?)?;
    let generation = number(&object.getattr("generation")?)?;
    let identity = domain
        .zip(generation)
        .map(|(domain, generation)| GenerationIdentity { domain, generation });

    Ok(LifecycleRequest {
        action,
        root: PathBuf::from(
            object
                .getattr("pool")?
                .getattr("root_dir")?
                .extract::<String>()?,
        ),
        identity,
        name: object.getattr("name")?.extract()?,
        definition: definition(object)?,
    })
}

/// Prepare pool creation lazily after any preceding pool operation completes.
fn prepare_pool(object: &Bound<'_, PyAny>, name: &str) -> PyResult<operation::Work> {
    let root = PathBuf::from(object.getattr("root_dir")?.extract::<String>()?);

    Ok(operation::Work {
        label: format!("pool {name}: {root}", root = root.display()),
        run: if name == "destroy" {
            Box::new(|| Ok(None))
        } else {
            Box::new(move || engine::pool_root(&root, true).map(|_| None))
        },
    })
}

/// Prepare an owned request only after the preceding volume callback has published its path.
fn prepare_volume(object: &Bound<'_, PyAny>, name: &str) -> PyResult<operation::Work> {
    let label = format!(
        "volume {name}: {vid}",
        vid = object.getattr("vid")?.extract::<String>()?
    );
    let run: Box<dyn FnOnce() -> anyhow::Result<Option<PathBuf>> + Send + Sync> =
        if name == "remove" {
            Box::new(|| Ok(None))
        } else if name == "verify_definition" {
            let view = definition(object)?;
            Box::new(move || engine::verify(&view).map(|_| None))
        } else {
            let action = if matches!(name, "verify" | "export") {
                Action::Verify
            } else {
                Action::parse(name)
                    .ok_or_else(|| invalid(object.py(), "unsupported volume lifecycle action"))?
            };
            let request = lifecycle_request(object, action)?;
            Box::new(move || engine::lifecycle(request))
        };

    Ok(operation::Work { label, run })
}

/// Apply a completed engine result on Qubes' thread and preserve each upstream return contract.
fn finish(
    object: &Bound<'_, PyAny>,
    name: &str,
    result: Result<Option<PathBuf>, String>,
) -> PyResult<Py<PyAny>> {
    let py = object.py();
    let path = result.map_err(|error| invalid(py, error))?;

    if name == "remove" {
        let volumes = object.getattr("pool")?.getattr("_volumes")?;
        let key = object.getattr("vid")?;
        if volumes.contains(&key)? {
            volumes.del_item(key)?;
        }
    } else if !matches!(name, "setup" | "destroy" | "verify_definition") {
        object.setattr("path", path.as_deref().map(path_text).transpose()?)?;
    }

    match name {
        "verify" | "verify_definition" => {
            Ok(true.into_pyobject(py)?.to_owned().into_any().unbind())
        }
        "export" => Ok(object.getattr("path")?.unbind()),
        _ => Ok(object.clone().unbind()),
    }
}

/// Forward pool callbacks while keeping upstream's own fields and object construction intact.
fn pool(
    name: &str,
    args: &Bound<'_, PyTuple>,
    kwargs: Option<&Bound<'_, PyDict>>,
) -> PyResult<Py<PyAny>> {
    let py = args.py();
    let object = argument(args, 0)?;
    match name {
        "__init__" => {
            let options = PyDict::new(py);
            options.set_item("name", keyword(kwargs, "name")?)?;
            options.set_item(
                "revisions_to_keep",
                kwargs
                    .and_then(|k| k.get_item("revisions_to_keep").transpose())
                    .transpose()?
                    .unwrap_or(0_u64.into_pyobject(py)?.into_any()),
            )?;
            options.set_item(
                "ephemeral_volatile",
                kwargs
                    .and_then(|k| k.get_item("ephemeral_volatile").transpose())
                    .transpose()?
                    .unwrap_or(false.into_pyobject(py)?.to_owned().into_any()),
            )?;
            py.import("qubes.storage")?.getattr("Pool")?.call_method(
                "__init__",
                (&object,),
                Some(&options),
            )?;
            let root = kwargs
                .and_then(|k| k.get_item("root_dir").transpose())
                .transpose()?
                .map(|value| value.extract::<String>())
                .transpose()?
                .unwrap_or_else(|| "/var/lib/airlock/closure-store".into());
            let root = PathBuf::from(root);
            let normalized = native(py, || engine::pool_root(&root, false))?;
            object.setattr("root_dir", path_text(&normalized)?)?;
            object.setattr("_volumes", PyDict::new(py))?;
            Ok(py.None())
        }
        "config" => {
            let fields = PyDict::new(py);
            for key in [
                "name",
                "root_dir",
                "revisions_to_keep",
                "ephemeral_volatile",
            ] {
                fields.set_item(key, object.getattr(key)?)?;
            }
            fields.set_item("driver", "airlock-closure")?;
            Ok(fields.into_any().unbind())
        }
        "setup" | "destroy" => operation::call(object, name, prepare_pool, finish),
        "init_volume" => {
            let vm = argument(args, 1)?;
            let config = argument(args, 2)?.cast_into::<PyDict>()?.copy()?;
            if config.contains("pool")? {
                config.del_item("pool")?;
            }
            config.set_item("pool", &object)?;
            config.set_item("_domain", vm.getattr("name")?)?;
            let volume = py
                .import("airlock_qubes")?
                .getattr("ClosureVolume")?
                .call((), Some(&config))?;
            object
                .getattr("_volumes")?
                .set_item(volume.getattr("vid")?, &volume)?;
            Ok(volume.unbind())
        }
        "list_volumes" => Ok(py
            .import("builtins")?
            .getattr("list")?
            .call1((object.getattr("_volumes")?.call_method0("values")?,))?
            .unbind()),
        "get_volume" => Ok(object
            .getattr("_volumes")?
            .get_item(argument(args, 1)?)?
            .unbind()),
        "size" | "usage" => {
            let root = PathBuf::from(object.getattr("root_dir")?.extract::<String>()?);
            let result = native(py, || engine::pool_stats(&root, name == "usage"))?;
            let value = if name == "size" {
                result.size
            } else {
                result
                    .usage
                    .ok_or_else(|| invalid(py, "pool usage was not collected"))?
            };
            Ok(value.into_pyobject(py)?.into_any().unbind())
        }
        _ => Err(pyo3::exceptions::PyAttributeError::new_err(name.to_owned())),
    }
}

/// Normalize constructor metadata while retaining unrelated upstream kwargs as Python objects.
fn initialize(object: &Bound<'_, PyAny>, kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<()> {
    let py = object.py();
    let pool = keyword(kwargs, "pool")?;
    let config = kwargs
        .ok_or_else(|| pyo3::exceptions::PyTypeError::new_err("missing volume configuration"))?
        .copy()?;
    config.del_item("pool")?;
    let domain = take(&config, "_domain")?;
    let domain = if domain.is_none() {
        None
    } else {
        Some(
            domain
                .extract::<String>()?
                .parse()
                .map_err(|error| invalid(py, error))?,
        )
    };
    let source = take(&config, "source")?;
    let name = config
        .get_item("name")?
        .map(|value| value.extract::<String>())
        .transpose()?
        .unwrap_or_else(|| "store".into());
    let writable = flag(&config, "rw")?;
    let snapshot = flag(&config, "snap_on_start")?;
    let view_kind = match config.get_item("view_kind")? {
        Some(value) => kind(&value)?,
        None => ViewKind::MetadataImage,
    };
    if config.contains("view_kind")? {
        config.del_item("view_kind")?;
    }
    let metadata = Metadata {
        domain_name: text(&take(&config, "domain_name")?)?,
        generation: number(&take(&config, "generation")?)?,
        closure_hash: text(&take(&config, "closure_hash")?)?,
        definition: Definition {
            view_kind,
            view_path: path(&take(&config, "view_path")?)?,
            blob_map_path: path(&take(&config, "blob_map_path")?)?,
            blob_logical_size: number(&take(&config, "blob_logical_size")?)?,
            manifest_path: path(&take(&config, "manifest_path")?)?,
        },
    };
    let input = NormalizationInput {
        domain,
        name,
        vid_supplied: config.contains("vid")?,
        writable,
        snapshot,
        has_source: !source.is_none(),
        metadata,
    };
    let result = native(py, || engine::normalize(input))?;
    config.set_item("rw", result.options().writable())?;
    config.set_item("snap_on_start", result.options().snapshot())?;
    config.set_item("save_on_stop", result.options().persistent())?;
    if let Some(vid) = result.generated_vid() {
        config.set_item("vid", vid)?;
    }
    config.set_item("pool", pool)?;
    py.import("qubes.storage")?.getattr("Volume")?.call_method(
        "__init__",
        (object,),
        Some(&config),
    )?;

    let fields = metadata_fields(py, result.metadata())?;
    let persisted = PyDict::new(py);
    for (key, value) in fields.iter() {
        let key: String = key.extract()?;
        object.setattr(if key == "view_path" { "path" } else { &key }, &value)?;
        if !value.is_none() {
            persisted.set_item(key, value)?;
        }
    }
    object.setattr("_persisted", persisted)
}

/// Dispatch upstream volume methods into typed normalization, lifecycle and accounting operations.
fn volume(
    name: &str,
    args: &Bound<'_, PyTuple>,
    kwargs: Option<&Bound<'_, PyDict>>,
) -> PyResult<Py<PyAny>> {
    let py = args.py();
    let object = argument(args, 0)?;
    match name {
        "__init__" => {
            initialize(&object, kwargs)?;
            Ok(py.None())
        }
        "config" => {
            let base = py
                .import("qubes.storage")?
                .getattr("Volume")?
                .getattr("config")?
                .call_method1("__get__", (&object, object.get_type()))?
                .cast_into::<PyDict>()?;
            base.update(
                object
                    .getattr("_persisted")?
                    .cast_into::<PyDict>()?
                    .as_mapping(),
            )?;
            Ok(base.into_any().unbind())
        }
        "definition" => {
            let fields = metadata_fields(
                py,
                &Metadata {
                    domain_name: None,
                    generation: None,
                    closure_hash: None,
                    definition: definition(&object)?,
                },
            )?;
            for key in ["domain_name", "generation", "closure_hash"] {
                fields.del_item(key)?;
            }
            Ok(fields.into_any().unbind())
        }
        "create" | "start" | "stop" | "verify" | "export" | "verify_definition" | "remove" => {
            operation::call(object, name, prepare_volume, finish)
        }
        "import_data" | "import_volume" | "resize" => {
            let request = lifecycle_request(&object, Action::Immutable)?;
            native(py, || engine::lifecycle(request))?;
            Ok(py.None())
        }
        "is_dirty" | "is_outdated" => Ok(false.into_pyobject(py)?.to_owned().into_any().unbind()),
        "block_device" => {
            if operation::pending(&object)?.is_some() {
                return Err(invalid(
                    py,
                    "await the pending storage operation before retrieving its block device",
                ));
            }
            // Qubes awaits start/verify before creating its libvirt XML. This synchronous
            // accessor must never attach a mapper or wait on the engine's admission lock.
            let view = definition(&object)?;
            native(py, || engine::verify(&view))?;
            if object.getattr("path")?.is_none() {
                return Err(invalid(
                    py,
                    "start or verify the volume before retrieving its block device",
                ));
            }
            Ok(py
                .import("qubes.storage")?
                .getattr("Volume")?
                .call_method1("block_device", (&object,))?
                .unbind())
        }
        "revisions" => Ok(PyDict::new(py).into_any().unbind()),
        "size" | "usage" => {
            let view = definition(&object)?;
            let fallback = object.getattr("_size")?.extract::<u64>()?;
            let result = native(py, || engine::volume_stats(&view, fallback))?;
            if name == "size" {
                object.setattr("_size", result.size)?;
            }
            let value = if name == "size" {
                result.size
            } else {
                result
                    .usage
                    .ok_or_else(|| invalid(py, "volume usage was not collected"))?
            };
            Ok(value.into_pyobject(py)?.into_any().unbind())
        }
        _ => Err(pyo3::exceptions::PyAttributeError::new_err(name.to_owned())),
    }
}

/// Publish genuine upstream subclasses with ordinary Python methods and property descriptors.
pub(super) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = module.py();
    let storage = py.import("qubes.storage")?;
    let namespace = PyDict::new(py);
    namespace.set_item("driver", "airlock-closure")?;
    for name in ["__init__", "init_volume", "list_volumes", "get_volume"] {
        namespace.set_item(name, descriptor::method(py, name, pool, false)?)?;
    }
    for name in ["setup", "destroy"] {
        namespace.set_item(name, descriptor::method(py, name, pool, false)?)?;
    }
    for name in ["config", "size", "usage"] {
        namespace.set_item(name, descriptor::property(py, name, pool)?)?;
    }
    module.add(
        "ClosurePool",
        descriptor::subclass(py, "ClosurePool", storage.getattr("Pool")?, &namespace)?,
    )?;

    let namespace = PyDict::new(py);
    for name in [
        "__init__",
        "definition",
        "is_dirty",
        "is_outdated",
        "block_device",
    ] {
        namespace.set_item(name, descriptor::method(py, name, volume, false)?)?;
    }
    for name in [
        "create",
        "remove",
        "export",
        "start",
        "stop",
        "verify_definition",
        "verify",
    ] {
        namespace.set_item(name, descriptor::method(py, name, volume, false)?)?;
    }
    for name in ["import_data", "import_volume", "resize"] {
        namespace.set_item(name, descriptor::method(py, name, volume, true)?)?;
    }
    for name in ["config", "revisions", "size", "usage"] {
        namespace.set_item(name, descriptor::property(py, name, volume)?)?;
    }
    module.add(
        "ClosureVolume",
        descriptor::subclass(py, "ClosureVolume", storage.getattr("Volume")?, &namespace)?,
    )?;
    Ok(())
}
