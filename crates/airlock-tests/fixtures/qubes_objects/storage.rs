//! Model the upstream storage object contract while exercising the real native Airlock plugin.

use super::{
    argument, class, collection, field, fields, keyword, module, path, plain, unknown, write,
};
use airlock_qubes::values;
use pyo3::{
    prelude::*,
    types::{PyDict, PyTuple},
};
use serde_json::{Value, json};

/// Initialize upstream pool fields and expose the configuration consumed by the native subclass.
fn pool(
    name: &str,
    args: &Bound<'_, PyTuple>,
    kwargs: Option<&Bound<'_, PyDict>>,
) -> PyResult<Py<PyAny>> {
    let py = args.py();
    let object = argument(args, 0)?;

    match name {
        "__init__" => {
            for (key, default) in [
                ("name", Value::Null),
                ("revisions_to_keep", json!(1)),
                ("ephemeral_volatile", json!(false)),
            ] {
                object.setattr(key, keyword(py, kwargs, key, default)?)?;
            }
        }
        "config" => {
            return Ok(values::python(
                py,
                &json!({
                    "name":field(&object, "name")?, "driver":field(&object, "driver")?,
                    "revisions_to_keep":field(&object, "revisions_to_keep")?,
                    "ephemeral_volatile":field(&object, "ephemeral_volatile")?,
                }),
            )?
            .unbind());
        }
        "init_volume" => {
            let vm = argument(args, 1)?;
            let config = argument(args, 2)?.cast_into::<PyDict>()?;
            config.set_item("pool", &object)?;
            let volume = py
                .import("qubes.storage")?
                .getattr("Volume")?
                .call((), Some(&config))?;
            vm.getattr("volumes")?
                .set_item(volume.getattr("name")?, &volume)?;
            return Ok(volume.unbind());
        }
        _ => return Err(unknown(name)),
    }
    Ok(py.None())
}

/// Supply upstream volume defaults and properties without reproducing native lifecycle policy.
fn volume(
    name: &str,
    args: &Bound<'_, PyTuple>,
    kwargs: Option<&Bound<'_, PyDict>>,
) -> PyResult<Py<PyAny>> {
    let py = args.py();
    let object = argument(args, 0)?;

    match name {
        "__init__" => {
            for (key, default) in [
                ("name", Value::Null),
                ("pool", Value::Null),
                ("vid", Value::Null),
                ("revisions_to_keep", json!(0)),
                ("rw", json!(false)),
                ("save_on_stop", json!(false)),
                ("size", json!(0)),
                ("snap_on_start", json!(false)),
                ("source", Value::Null),
            ] {
                let value = keyword(py, kwargs, key, default)?;
                object.setattr(if key == "size" { "_size" } else { key }, value)?;
            }
            if let Some(marker) = kwargs
                .map(|kwargs| kwargs.get_item("upstream_marker"))
                .transpose()?
                .flatten()
            {
                object.setattr("upstream_marker", marker)?;
            }
            if !object.getattr("vid")?.is_truthy()? {
                object.setattr("vid", object.getattr("name")?)?;
            }
        }
        "config" => {
            let mut config = serde_json::Map::new();
            for key in [
                "name",
                "pool",
                "vid",
                "size",
                "rw",
                "snap_on_start",
                "save_on_stop",
                "source",
                "revisions_to_keep",
            ] {
                config.insert(key.into(), field(&object, key)?);
            }
            for key in [
                "domain_name",
                "generation",
                "closure_hash",
                "view_kind",
                "view_path",
                "manifest_path",
                "blob_map_path",
                "blob_logical_size",
            ] {
                if object.hasattr(key)? {
                    config.insert(key.into(), field(&object, key)?);
                }
            }
            return Ok(values::python(py, &Value::Object(config))?.unbind());
        }
        "size" => return Ok(object.getattr("_size")?.unbind()),
        "create" => return Ok(object.unbind()),
        _ => return Err(unknown(name)),
    }
    Ok(py.None())
}

/// Resolve the configured pool and retain each initialized volume on its owning VM.
fn storage(
    name: &str,
    args: &Bound<'_, PyTuple>,
    _kwargs: Option<&Bound<'_, PyDict>>,
) -> PyResult<Py<PyAny>> {
    let object = argument(args, 0)?;

    match name {
        "__init__" => object.setattr("vm", argument(args, 1)?)?,
        "init_volume" => {
            let vm = object.getattr("vm")?;
            let name: String = argument(args, 1)?.extract()?;
            if std::env::var("AIRLOCK_FAKE_QUBES_INSTALL_FAIL_VOLUME").as_deref() == Ok(&name) {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "injected volume installation failure",
                ));
            }
            let config = argument(args, 2)?.cast_into::<PyDict>()?;
            let pool = vm
                .getattr("app")?
                .call_method1("get_pool", (config.get_item("pool")?,))?;
            let volume = pool.call_method1("init_volume", (&vm, config))?;
            vm.getattr("volumes")?
                .set_item(argument(args, 1)?, &volume)?;
            return Ok(volume.unbind());
        }
        _ => return Err(unknown(name)),
    }
    Ok(args.py().None())
}

/// Populate a stopped or running standalone with independent root and private disks or persisted native volumes.
fn vm(
    name: &str,
    args: &Bound<'_, PyTuple>,
    _kwargs: Option<&Bound<'_, PyDict>>,
) -> PyResult<Py<PyAny>> {
    let py = args.py();
    let object = argument(args, 0)?;

    match name {
        "__init__" => {
            let app = argument(args, 1)?;
            let data = argument(args, 3)?;
            object.setattr("app", &app)?;
            object.setattr("name", argument(args, 2)?)?;
            object.setattr(
                "features",
                keyword(py, data.cast::<PyDict>().ok(), "features", json!({}))?,
            )?;
            object.setattr("volumes", PyDict::new(py))?;
            let storage = py
                .import("qubes.storage")?
                .getattr("Storage")?
                .call1((&object,))?;
            object.setattr("storage", &storage)?;

            if data.is_none() {
                let configs = PyDict::new(py);
                for name in ["root", "private"] {
                    let config = values::python(
                        py,
                        &json!({
                            "name":name, "vid":name, "size":1024, "rw":true,
                            "snap_on_start":false, "save_on_stop":true, "source":null,
                            "revisions_to_keep":1,
                        }),
                    )?
                    .cast_into::<PyDict>()?;
                    config.set_item("pool", app.call_method1("get_pool", ("default",))?)?;
                    let volume = py
                        .import("qubes.storage")?
                        .getattr("Volume")?
                        .call((), Some(&config))?;
                    object.getattr("volumes")?.set_item(name, &volume)?;
                    configs.set_item(name, volume.getattr("config")?)?;
                }
                object.setattr("volume_config", configs)?;
            } else {
                let configs =
                    keyword(py, Some(data.cast::<PyDict>()?), "volume_config", json!({}))?;
                object.setattr("volume_config", &configs)?;
                let configs = configs.cast::<PyDict>()?;
                // Qubes preserves XML insertion order; a JSON object's sorted keys cannot model it.
                let order: Vec<String> = match data.cast::<PyDict>()?.get_item("volume_order")? {
                    Some(order) => order.extract()?,
                    None => configs.keys().extract()?,
                };
                for name in order {
                    let config = configs
                        .get_item(&name)?
                        .expect("persisted volume definition");
                    storage
                        .call_method1("init_volume", (name, config.cast::<PyDict>()?.copy()?))?;
                }
            }
        }
        "get_power_state" => {
            let state = std::env::var("AIRLOCK_FAKE_QUBES_POWER_STATE").unwrap_or_else(|_| {
                if matches!(
                    std::env::var("AIRLOCK_FAKE_QUBES_RUNNING").as_deref(),
                    Ok("1" | "true" | "yes")
                ) {
                    "Running".into()
                } else {
                    "Halted".into()
                }
            });
            return Ok(state.into_pyobject(py)?.into_any().unbind());
        }
        "is_running" => {
            let running = matches!(
                std::env::var("AIRLOCK_FAKE_QUBES_RUNNING").as_deref(),
                Ok("1" | "true" | "yes")
            );
            return Ok(running.into_pyobject(py)?.to_owned().into_any().unbind());
        }
        _ => return Err(unknown(name)),
    }
    Ok(py.None())
}

/// Restore pools through the real Airlock plugin and attach the requested fixture VM.
fn initialize(object: &Bound<'_, PyAny>) -> PyResult<()> {
    let py = object.py();
    let pools = PyDict::new(py);
    let options = PyDict::new(py);
    options.set_item("name", "default")?;
    pools.set_item(
        "default",
        py.import("qubes.storage")?
            .getattr("BasicPool")?
            .call((), Some(&options))?,
    )?;
    object.setattr("pools", &pools)?;

    let state = path("AIRLOCK_FAKE_QUBES_STATE_JSON")?;
    let data: Value = if state.exists() {
        serde_json::from_slice(&std::fs::read(state)?)
            .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))?
    } else {
        Value::Null
    };
    if let Some(configs) = data["pools"].as_object() {
        for (name, config) in configs {
            if config["driver"] == "airlock-closure" {
                let options = values::python(py, config)?.cast_into::<PyDict>()?;
                options.del_item("driver")?;
                pools.set_item(
                    name,
                    py.import("airlock_qubes")?
                        .getattr("ClosurePool")?
                        .call((), Some(&options))?,
                )?;
            }
        }
    }

    let domain = std::env::var("AIRLOCK_FAKE_QUBES_DOMAIN")
        .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))?;
    let config = if data.is_null() {
        Value::Null
    } else {
        data["domains"][&domain].clone()
    };
    let vm = py.import("qubes")?.getattr("VM")?.call1((
        object,
        &domain,
        values::python(py, &config)?,
    ))?;
    let domains = collection(py)?;
    domains.set_item(domain, vm)?;
    object.setattr("domains", domains)?;
    Ok(())
}

/// Persist native plugin configurations so separate worker processes observe generation changes.
fn save(object: &Bound<'_, PyAny>) -> PyResult<()> {
    let mut pools = serde_json::Map::new();
    for (name, pool) in object.getattr("pools")?.cast::<PyDict>()?.iter() {
        pools.insert(name.extract()?, field(&pool, "config")?);
    }

    let mut domains = serde_json::Map::new();
    for (name, vm) in object.getattr("domains")?.cast::<PyDict>()?.iter() {
        let mut volumes = serde_json::Map::new();
        let mut order = Vec::new();
        for (name, volume) in vm.getattr("volumes")?.cast::<PyDict>()?.iter() {
            let name: String = name.extract()?;
            order.push(name.clone());
            volumes.insert(name, field(&volume, "config")?);
        }
        domains.insert(
            name.extract()?,
            json!({"features":field(&vm, "features")?, "volume_config":volumes,"volume_order":order}),
        );
    }

    let payload = json!({"pools":pools, "domains":domains});
    write("AIRLOCK_FAKE_QUBES_SAVE_JSON", &payload)?;
    write("AIRLOCK_FAKE_QUBES_STATE_JSON", &payload)
}

/// Expose only the upstream calls used by the native storage object's transaction path.
fn app(
    name: &str,
    args: &Bound<'_, PyTuple>,
    kwargs: Option<&Bound<'_, PyDict>>,
) -> PyResult<Py<PyAny>> {
    let py = args.py();
    let object = argument(args, 0)?;

    match name {
        "__init__" => initialize(&object)?,
        "load" => {}
        "get_pool" => {
            return Ok(object
                .getattr("pools")?
                .get_item(argument(args, 1)?)?
                .unbind());
        }
        "add_pool" => {
            let config = kwargs
                .expect("native worker supplies named pool fields")
                .copy()?;
            if plain(&config.get_item("driver")?.expect("pool driver"))? != "airlock-closure" {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "unsupported fixture pool driver",
                ));
            }

            config.del_item("driver")?;
            let pool = py
                .import("airlock_qubes")?
                .getattr("ClosurePool")?
                .call((), Some(&config))?;
            let runner = py.import("asyncio")?.getattr("Runner")?.call0()?;
            airlock_qubes::storage::complete(pool.call_method0("setup")?, &runner)
                .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))?;
            runner.call_method0("close")?;

            object
                .getattr("pools")?
                .set_item(pool.getattr("name")?, &pool)?;
            return Ok(pool.unbind());
        }
        "save" => save(&object)?,
        "close" => {
            for vm in object.getattr("domains")?.try_iter()? {
                vm?.delattr("app")?;
            }
        }
        _ => return Err(unknown(name)),
    }
    Ok(py.None())
}

/// Install base classes and exception identity before importing the real native storage module.
pub(super) fn register(root: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = root.py();
    let exceptions = module(py, "qubes.exc")?;
    let exception = airlock_qubes::descriptor::subclass(
        py,
        "StoragePoolException",
        py.get_type::<pyo3::exceptions::PyException>().into_any(),
        &PyDict::new(py),
    )?;
    exceptions.add("StoragePoolException", exception)?;
    root.add("exc", exceptions)?;

    let storage_module = module(py, "qubes.storage")?;
    let base = class(
        &storage_module,
        "Pool",
        pool,
        &["__init__", "init_volume"],
        &[],
        &["config"],
    )?;
    base.setattr("driver", "fake")?;
    let namespace = PyDict::new(py);
    namespace.set_item("driver", "file")?;
    storage_module.add(
        "BasicPool",
        airlock_qubes::descriptor::subclass(py, "BasicPool", base, &namespace)?,
    )?;

    let base = class(
        &storage_module,
        "Volume",
        volume,
        &["__init__"],
        &["create"],
        &["size", "config"],
    )?;
    fields(
        &base,
        &json!({"devtype":"disk", "domain":null, "path":null}),
    )?;

    class(
        &storage_module,
        "Storage",
        storage,
        &["__init__", "init_volume"],
        &[],
        &[],
    )?;
    root.add("storage", storage_module)?;

    let vm = class(
        root,
        "VM",
        vm,
        &["__init__", "is_running", "get_power_state"],
        &[],
        &[],
    )?;
    vm.setattr("klass", "StandaloneVM")?;

    class(
        root,
        "Qubes",
        app,
        &["__init__", "load", "get_pool", "add_pool", "save", "close"],
        &[],
        &[],
    )?;
    Ok(())
}
