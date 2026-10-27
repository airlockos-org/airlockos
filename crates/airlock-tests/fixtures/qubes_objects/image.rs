//! Supply offline image objects and failure injection without implementing image assembly itself.

use super::{
    append, argument, class, collection, field, fields, keyword, module, plain, unknown, write,
};
use airlock_qubes::{descriptor, values};
use pyo3::{
    exceptions::{PyTypeError, PyValueError},
    prelude::*,
    types::{PyDict, PyTuple},
};
use serde_json::{Value, json};
use std::{fs, path::PathBuf};

/// Fail at one selected upstream boundary so the Rust image session must release its objects.
fn damage(phase: &str) -> PyResult<()> {
    if std::env::var("AIRLOCK_TEST_IMAGE_DAMAGE").as_deref() == Ok(phase) {
        return Err(PyValueError::new_err(format!("upstream {phase} failed")));
    }

    Ok(())
}

/// Retain the pool identity and original constructor configuration for snapshot serialization.
fn pool(
    _name: &str,
    args: &Bound<'_, PyTuple>,
    kwargs: Option<&Bound<'_, PyDict>>,
) -> PyResult<Py<PyAny>> {
    let object = argument(args, 0)?;
    let config = kwargs
        .expect("image pools use named configuration")
        .copy()?;
    if config.contains("root_dir")? {
        config.set_item("driver", "airlock-closure")?;
    }
    object.setattr("name", config.get_item("name")?)?;
    object.setattr("config", config)?;
    Ok(args.py().None())
}

/// Provide Qubes-selected volume paths and deferred sparse disk creation inside the fixture tree.
fn volume(
    name: &str,
    args: &Bound<'_, PyTuple>,
    _kwargs: Option<&Bound<'_, PyDict>>,
) -> PyResult<Py<PyAny>> {
    let py = args.py();
    let object = argument(args, 0)?;

    match name {
        "__init__" => {
            let vm = argument(args, 1)?;
            let name = argument(args, 2)?.extract::<String>()?;
            let config = argument(args, 3)?;
            let options = config.cast::<PyDict>()?;
            let path = vm
                .getattr("dir_path")?
                .extract::<PathBuf>()?
                .join(format!("{name}.img"));
            let observed_path = options
                .get_item("view_path")?
                .map(|value| value.extract::<String>())
                .transpose()?
                .unwrap_or_else(|| path.to_string_lossy().into_owned());
            object.setattr("path", observed_path)?;
            object.setattr("config", &config)?;
            let pool = keyword(py, Some(options), "pool", json!("varlibqubes"))?;
            object.setattr("pool", vm.getattr("app")?.getattr("pools")?.get_item(pool)?)?;
            object.setattr(
                "vid",
                options
                    .get_item("vid")?
                    .map(|value| value.extract::<String>())
                    .transpose()?
                    .unwrap_or(format!(
                        "appvms/{vm_name}/{name}",
                        vm_name = vm.getattr("name")?.extract::<String>()?
                    )),
            )?;
            for (key, default) in [
                ("rw", json!(true)),
                ("snap_on_start", json!(false)),
                ("save_on_stop", json!(true)),
                ("size", json!(4096)),
            ] {
                object.setattr(key, keyword(py, Some(options), key, default)?)?;
            }
            for field in ["generation", "closure_hash", "blob_map_path"] {
                if let Some(value) = options.get_item(field)? {
                    object.setattr(field, value)?;
                }
            }
            object.setattr("source", py.None())?;
        }
        "create" => {
            damage("volume")?;

            let path = object.getattr("path")?.extract::<PathBuf>()?;
            let size = object
                .getattr("config")?
                .get_item("size")?
                .extract::<u64>()?;
            fs::File::create(path)?.set_len(size)?;
        }
        _ => return Err(unknown(name)),
    }
    Ok(py.None())
}

/// Retain the VM and populate its initialized volumes in the same order the image code requests.
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
            let name = argument(args, 1)?;
            let volume = args.py().import("qubes")?.getattr("Volume")?.call1((
                &vm,
                &name,
                argument(args, 2)?,
            ))?;
            vm.getattr("volumes")?.set_item(name, &volume)?;
            return Ok(volume.unbind());
        }
        _ => return Err(unknown(name)),
    }
    Ok(args.py().None())
}

/// Expose a VM's upstream defaults and observe disk readiness when final GUI properties are set.
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
            let name = argument(args, 2)?.extract::<String>()?;
            let label = argument(args, 3)?.extract::<String>()?;
            object.setattr("app", &app)?;
            fields(
                &object,
                &json!({"klass":"StandaloneVM", "name":name, "features":{}, "volumes":{}}),
            )?;
            for entry in app.getattr("labels")?.call_method0("values")?.try_iter()? {
                let entry = entry?;
                if entry.getattr("name")?.extract::<String>()? == label {
                    object.setattr("label", entry)?;
                    break;
                }
            }
            object.setattr("uuid", argument(args, 4)?)?;
            object.setattr(
                "dir_path",
                app.getattr("root")?
                    .extract::<PathBuf>()?
                    .join("appvms")
                    .join(&name),
            )?;
            object.setattr(
                "storage",
                py.import("qubes")?.getattr("Storage")?.call1((&object,))?,
            )?;

            let configs = PyDict::new(py);
            for name in ["root", "private"] {
                let config = values::python(py, &json!({"name":name, "upstream":true}))?
                    .cast_into::<PyDict>()?;
                config.set_item("pool", app.getattr("pools")?.get_item("varlibqubes")?)?;
                configs.set_item(name, config)?;
            }
            object.setattr("volume_config", configs)?;
        }
        "is_running" => return Ok(false.into_pyobject(py)?.to_owned().into_any().unbind()),
        "get_power_state" => return Ok("Halted".into_pyobject(py)?.into_any().unbind()),
        "property_get_def" => {
            let key = argument(args, 1)?.extract::<String>()?;
            if key == "kernel" {
                damage("property")?;
            }

            if key == "guivm" && object.getattr("klass")?.extract::<String>()? != "HermitVM" {
                let directory = object.getattr("dir_path")?.extract::<PathBuf>()?;
                let features = object.getattr("features")?;
                features.set_item(
                    "fixture-root-ready",
                    if fs::read(directory.join("root.img"))? == b"fixture" {
                        "1"
                    } else {
                        ""
                    },
                )?;
                features.set_item(
                    "fixture-private-ready",
                    fs::metadata(directory.join("private.img"))?
                        .len()
                        .to_string(),
                )?;
            }
        }
        _ => return Err(unknown(name)),
    }
    Ok(py.None())
}

/// Construct upstream-shaped labels without assigning any Airlock image policy.
#[pyfunction]
fn label(py: Python<'_>, index: u32, color: &str, name: &str) -> PyResult<Py<PyAny>> {
    let fields = values::python(py, &json!({"index":index, "color":color, "name":name}))?
        .cast_into::<PyDict>()?;
    Ok(py
        .import("types")?
        .getattr("SimpleNamespace")?
        .call((), Some(&fields))?
        .unbind())
}

/// Create built-in labels and pools from the session's temporary upstream configuration.
fn initialize(object: &Bound<'_, PyAny>, store: &Bound<'_, PyAny>) -> PyResult<()> {
    let py = object.py();
    let config = py.import("qubes.config")?;
    if !store.is_instance_of::<pyo3::types::PyString>()
        || !config
            .getattr("qubes_base_dir")?
            .is_instance_of::<pyo3::types::PyString>()
    {
        return Err(PyTypeError::new_err(
            "Qubes requires string database and base-directory paths",
        ));
    }

    let path = store.extract::<PathBuf>()?;
    object.setattr(
        "root",
        path.parent().expect("fixture database has a parent"),
    )?;
    let labels = PyDict::new(py);
    labels.set_item(1, label(py, 1, "0x00ff00", "green")?)?;
    object.setattr("labels", labels)?;

    let pools = PyDict::new(py);
    for (name, config) in config
        .getattr("defaults")?
        .get_item("pool_configs")?
        .cast::<PyDict>()?
        .iter()
    {
        pools.set_item(
            name,
            py.import("qubes")?
                .getattr("Pool")?
                .call((), Some(config.cast::<PyDict>()?))?,
        )?;
    }
    object.setattr("pools", pools)?;
    object.setattr("domains", collection(py)?)?;
    fields(object, &json!({"closed":false, "saved":false}))
}

/// Serialize the supplied object observations for boot-cache tests, not an implementation of qubesd.
fn xml(snapshots: &[Value]) -> std::io::Result<Vec<u8>> {
    let mut writer = quick_xml::Writer::new(Vec::new());
    writer
        .create_element("qubes")
        .write_inner_content(|writer| {
            writer.create_element("labels").write_empty()?;
            writer.create_element("properties").write_empty()?;
            writer
                .create_element("pools")
                .write_inner_content(|writer| {
                    if let Some(snapshot) = snapshots.first() {
                        for (name, config) in snapshot["pools"].as_object().unwrap() {
                            let mut attrs = attributes(config);
                            attrs.insert("name".into(), name.clone());
                            writer
                                .create_element("pool")
                                .with_attributes(
                                    attrs
                                        .iter()
                                        .map(|(key, value)| (key.as_str(), value.as_str())),
                                )
                                .write_empty()?;
                        }
                    }
                    Ok(())
                })?;
            writer
                .create_element("domains")
                .write_inner_content(|writer| {
                    // Upstream saves dom0's fixed name implicitly, outside the guest snapshots.
                    writer
                        .create_element("domain")
                        .with_attribute(("id", "domain-0"))
                        .with_attribute(("class", "AdminVM"))
                        .write_inner_content(|writer| {
                            writer
                                .create_element("properties")
                                .write_inner_content(|writer| {
                                    writer
                                        .create_element("property")
                                        .with_attribute(("name", "label"))
                                        .write_text_content(quick_xml::events::BytesText::new(
                                            "black",
                                        ))?;
                                    Ok(())
                                })?;
                            Ok(())
                        })?;
                    for snapshot in snapshots {
                        writer
                            .create_element("domain")
                            .write_inner_content(|writer| {
                                writer.create_element("properties").write_inner_content(
                                    |writer| {
                                        writer
                                            .create_element("property")
                                            .with_attribute(("name", "name"))
                                            .write_text_content(
                                                quick_xml::events::BytesText::new(
                                                    snapshot["domain"].as_str().unwrap(),
                                                ),
                                            )?;
                                        Ok(())
                                    },
                                )?;
                                writer.create_element("features").write_inner_content(
                                    |writer| {
                                        for (key, value) in
                                            snapshot["features"].as_object().unwrap()
                                        {
                                            writer
                                                .create_element("feature")
                                                .with_attribute(("name", key.as_str()))
                                                .write_text_content(
                                                    quick_xml::events::BytesText::new(&scalar(
                                                        value,
                                                    )),
                                                )?;
                                        }
                                        Ok(())
                                    },
                                )?;
                                writer.create_element("tags").write_empty()?;
                                writer.create_element("volume-config").write_inner_content(
                                    |writer| {
                                        for volume in snapshot["volumes"].as_array().unwrap() {
                                            let mut attrs = attributes(&volume["config"]);
                                            for field in ["name", "pool", "vid", "size"] {
                                                attrs.insert(
                                                    field.into(),
                                                    volume[field]
                                                        .as_str()
                                                        .map(str::to_owned)
                                                        .unwrap_or_else(|| {
                                                            volume[field].to_string()
                                                        }),
                                                );
                                            }
                                            writer
                                                .create_element("volume")
                                                .with_attributes(attrs.iter().map(
                                                    |(key, value)| (key.as_str(), value.as_str()),
                                                ))
                                                .write_empty()?;
                                        }
                                        Ok(())
                                    },
                                )?;
                                Ok(())
                            })?;
                    }
                    Ok(())
                })?;
            Ok(())
        })?;
    Ok(writer.into_inner())
}

/// Encode both strings and scalar feature values as Qubes XML text.
fn scalar(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}

/// Preserve scalar upstream configuration fields in the disposable XML observation.
fn attributes(config: &Value) -> std::collections::BTreeMap<String, String> {
    config
        .as_object()
        .unwrap()
        .iter()
        .filter(|(_, value)| !value.is_null())
        .map(|(key, value)| (key.clone(), scalar(value)))
        .collect()
}

/// Write a minimal relocatable Qubes XML database and a separate object observation for assertions.
fn save(object: &Bound<'_, PyAny>) -> PyResult<()> {
    damage("save")?;

    object.setattr("saved", true)?;
    let root = object.getattr("root")?.extract::<PathBuf>()?;
    let mut snapshots = Vec::new();
    for vm in object.getattr("domains")?.try_iter()? {
        snapshots.push(
            airlock_qubes::snapshot::read(object, &vm?)
                .map_err(|error| PyValueError::new_err(format!("snapshot fixture: {error:#}")))?,
        );
    }
    if std::env::var_os("AIRLOCK_TEST_IMAGE_OBSERVED").is_some() {
        write("AIRLOCK_TEST_IMAGE_OBSERVED", &json!(snapshots))?;
    }
    fs::write(
        root.join("qubes.xml"),
        xml(&snapshots).map_err(|error| PyValueError::new_err(error.to_string()))?,
    )?;

    let mut domains = Vec::new();
    for vm in object.getattr("domains")?.try_iter()? {
        let vm = vm?;
        let volumes = vm
            .getattr("volume_config")?
            .cast_into::<PyDict>()?
            .iter()
            .map(|(_, config)| plain(&config))
            .collect::<PyResult<Vec<_>>>()?;
        domains.push(
            json!({"name":field(&vm, "name")?, "uuid":vm.getattr("uuid")?.str()?.to_str()?,
            "features":field(&vm, "features")?, "kernelopts":field(&vm, "kernelopts")?, "volumes":volumes,
            "netvm_inherited":!vm.hasattr("netvm")?, "guivm_inherited":!vm.hasattr("guivm")?}),
        );
    }
    write("AIRLOCK_TEST_IMAGE_PLAN", &json!({"domains":domains}))
}

/// Supply the image session's object calls and record save/close ordering across injected failures.
fn app(
    name: &str,
    args: &Bound<'_, PyTuple>,
    kwargs: Option<&Bound<'_, PyDict>>,
) -> PyResult<Py<PyAny>> {
    let py = args.py();
    let object = argument(args, 0)?;

    match name {
        "__init__" => initialize(&object, &argument(args, 1)?)?,
        "property_get_def" => {}
        "add_new_vm" => {
            let vm = py.import("qubes")?.getattr("VM")?.call1((
                &object,
                keyword(py, kwargs, "name", Value::Null)?,
                keyword(py, kwargs, "label", Value::Null)?,
                keyword(py, kwargs, "uuid", Value::Null)?,
            ))?;
            vm.getattr("features")?
                .set_item("fixture-class", argument(args, 1)?)?;
            vm.setattr("klass", argument(args, 1)?)?;
            if argument(args, 1)?.extract::<String>()? == "HermitVM" {
                vm.getattr("volume_config")?.call_method0("clear")?;
            }

            object
                .getattr("domains")?
                .set_item(vm.getattr("name")?, &vm)?;
            return Ok(vm.unbind());
        }
        "save" => save(&object)?,
        "close" => {
            object.setattr("closed", true)?;
            append(
                "AIRLOCK_TEST_IMAGE_CLOSES",
                &json!({"saved":field(&object, "saved")?}),
            )?;
        }
        _ => return Err(unknown(name)),
    }
    Ok(py.None())
}

/// Allocate an initial offline application and retain it for the simulated saved-database reload.
#[pyfunction]
fn create_empty_store(
    py: Python<'_>,
    store: Bound<'_, PyAny>,
    offline_mode: bool,
) -> PyResult<Py<PyAny>> {
    damage("adapter")?;

    let root = py.import("qubes")?;
    let app = root.getattr("App")?.call1((store,))?;
    app.setattr("offline", offline_mode)?;
    root.setattr("current", &app)?;
    Ok(app.unbind())
}

/// Reopen a shallow object graph only after observing whether the original graph was saved/closed.
fn reload(
    _name: &str,
    args: &Bound<'_, PyTuple>,
    kwargs: Option<&Bound<'_, PyDict>>,
) -> PyResult<Py<PyAny>> {
    damage("reload")?;

    let py = args.py();
    let root = py.import("qubes")?;
    let current = root.getattr("current")?;
    write(
        "AIRLOCK_TEST_IMAGE_RELOAD",
        &json!({
            "offline":plain(&keyword(py, kwargs, "offline_mode", Value::Null)?)?,
            "closed":field(&current, "closed")?, "saved":field(&current, "saved")?,
            "initial_offline":field(&current, "offline")?,
        }),
    )?;

    let app = py
        .import("builtins")?
        .getattr("object")?
        .call_method1("__new__", (root.getattr("App")?,))?;
    app.setattr(
        "__dict__",
        current.getattr("__dict__")?.cast::<PyDict>()?.copy()?,
    )?;
    app.setattr("closed", false)?;
    Ok(app.unbind())
}

/// Install image-specific modules and constructors before the real runtime preparer imports Qubes.
pub(super) fn register(root: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = root.py();
    class(root, "Pool", pool, &["__init__"], &[], &[])?;
    class(root, "Volume", volume, &["__init__"], &["create"], &[])?;
    class(
        root,
        "Storage",
        storage,
        &["__init__", "init_volume"],
        &[],
        &[],
    )?;
    class(
        root,
        "VM",
        vm,
        &[
            "__init__",
            "is_running",
            "get_power_state",
            "property_get_def",
        ],
        &[],
        &[],
    )?;
    class(
        root,
        "App",
        app,
        &[
            "__init__",
            "property_get_def",
            "add_new_vm",
            "save",
            "close",
        ],
        &[],
        &[],
    )?;
    root.add("Label", wrap_pyfunction!(label, root)?)?;

    let namespace = PyDict::new(py);
    namespace.set_item(
        "create_empty_store",
        py.import("builtins")?
            .getattr("staticmethod")?
            .call1((wrap_pyfunction!(create_empty_store, root)?,))?,
    )?;
    namespace.set_item(
        "__new__",
        py.import("builtins")?
            .getattr("staticmethod")?
            .call1((descriptor::method(py, "__new__", reload, false)?,))?,
    )?;
    root.add(
        "Qubes",
        descriptor::subclass(
            py,
            "Qubes",
            py.import("builtins")?.getattr("object")?,
            &namespace,
        )?,
    )?;

    let config = module(py, "qubes.config")?;
    fields(
        config.as_any(),
        &json!({
            "defaults":{"private_img_size":4096, "pool_configs":{}},
            "max_default_label":8,
            "qubes_base_dir":"/var/lib/qubes",
        }),
    )?;
    root.add("config", config)?;

    let ext = module(py, "qubes.ext")?;
    ext.add("get_extensions", py.import("builtins")?.getattr("set")?)?;
    root.add("ext", ext)?;

    let storage = module(py, "qubes.storage")?;
    storage.add("Volume", root.getattr("Volume")?)?;
    storage.add("Pool", root.getattr("Pool")?)?;
    root.add("storage", storage)?;

    let vm = module(py, "qubes.vm")?;
    vm.add("appvm", module(py, "qubes.vm.appvm")?)?;
    root.add("vm", vm)?;

    module(py, "airlock_qubes")?.add("ClosurePool", root.getattr("Pool")?)?;
    Ok(())
}
