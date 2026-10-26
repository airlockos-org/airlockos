//! Exercise actual Qubes Python interfaces from a native development-only process.
//! Scenario selection, observations and assertions remain in Rust.

#[path = "qubes_probe/events.rs"]
mod events;

#[path = "qubes_probe/transaction.rs"]
mod transaction;

use airlock_qubes::{gpu, values};
use anyhow::{Context, Result, ensure};
use pyo3::{
    prelude::*,
    types::{PyDict, PyTuple},
};
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    process::{Command, Stdio},
};

/// Construct an ordinary upstream object with named fields and no generated Python statements.
fn namespace<'py>(py: Python<'py>, fields: &Value) -> Result<Bound<'py, PyAny>> {
    let kwargs = values::python(py, fields)?
        .cast_into::<PyDict>()
        .map_err(PyErr::from)?;
    Ok(py
        .import("types")?
        .getattr("SimpleNamespace")?
        .call((), Some(&kwargs))?)
}

/// Observe the native plugin's properties, coroutine dispatch and upstream exception translation.
fn properties(py: Python<'_>, request: &Value) -> Result<Value> {
    let module = py.import("airlock_qubes")?;
    let object = py
        .import("builtins")?
        .getattr("object")?
        .call_method1("__new__", (module.getattr("ClosureVolume")?,))?;
    let mut fields = json!({
        "domain_name":"usr-home-runtime-store", "generation":"3", "name":"store-data", "vid":"test-volume",
        "path":null, "view_kind":"erofs-blob-map", "blob_map_path":request["map"],
        "blob_logical_size":4096, "manifest_path":null, "_size":4096,
    });
    if let Some(overrides) = request["fields"].as_object() {
        fields.as_object_mut().unwrap().extend(overrides.clone());
    }
    for (name, value) in fields.as_object().unwrap() {
        object.setattr(name, values::python(py, value)?)?;
    }
    let pool = namespace(py, &json!({"root_dir":request["pool"], "_volumes":{}}))?;
    object.setattr("pool", pool)?;

    let runner = py.import("asyncio")?.getattr("Runner")?.call0()?;
    runner.call_method0("__enter__")?;
    let result = (|| -> Result<Value> {
        match request["operation"]
            .as_str()
            .context("storage probe operation")?
        {
            "constructor" => {
                let options = PyDict::new(py);
                options.set_item("name", "typed-pool")?;
                options.set_item("root_dir", request["pool"].as_str().context("pool path")?)?;
                let pool = module.getattr("ClosurePool")?.call((), Some(&options))?;
                let mut config = json!({"name":"store-data", "_domain":"usr-home", "generation":"3",
                    "view_kind":"erofs-blob-map", "view_path":"/dev/mapper/stale",
                    "blob_map_path":request["map"], "blob_logical_size":"4096"});
                if let Some(overrides) = request["constructor"].as_object() {
                    config.as_object_mut().unwrap().extend(overrides.clone());
                }
                let kwargs = values::python(py, &config)?
                    .cast_into::<PyDict>()
                    .map_err(PyErr::from)?;
                kwargs.set_item("pool", pool)?;
                let marker = py.import("builtins")?.getattr("object")?.call0()?;
                kwargs.set_item("upstream_marker", &marker)?;
                let volume = module.getattr("ClosureVolume")?.call((), Some(&kwargs))?;
                let persisted = values::plain(&volume.getattr("_persisted")?)?;
                ensure!(
                    volume.getattr("upstream_marker")?.is(&marker),
                    "upstream kwargs lost Python object identity"
                );
                volume.setattr("path", "/dev/mapper/runtime")?;
                let saved = volume
                    .getattr("config")?
                    .cast_into::<PyDict>()
                    .map_err(PyErr::from)?;
                Ok(json!({"vid":volume.getattr("vid")?.extract::<String>()?,
                    "rw":volume.getattr("rw")?.extract::<bool>()?,
                    "snap_on_start":volume.getattr("snap_on_start")?.extract::<bool>()?,
                    "save_on_stop":volume.getattr("save_on_stop")?.extract::<bool>()?,
                    "persisted":persisted,"saved_transient_path":saved.contains("view_path")?,
                    "upstream_identity_preserved":true}))
            }
            "definition" => {
                let valid = object.call_method0("verify_definition")?;
                let valid = runner.call_method1("run", (valid,))?.extract::<bool>()?;
                Ok(json!({
                    "valid":valid, "size":object.getattr("size")?.extract::<u64>()?,
                    "usage":object.getattr("usage")?.extract::<u64>()?,
                }))
            }
            "callbacks" => {
                let create = object.call_method0("create")?;
                ensure!(
                    py.import("asyncio")?
                        .call_method1("iscoroutine", (&create,))?
                        .is_truthy()?,
                    "native callback is not a coroutine"
                );
                let created = runner.call_method1("run", (create,))?;
                ensure!(
                    created.is(&object),
                    "volume callback changed object identity"
                );
                let verify = object.call_method0("verify")?;
                ensure!(
                    runner.call_method1("run", (verify,))?.is_truthy()?,
                    "native verification did not complete"
                );
                let mutation = object.call_method1("resize", (1,))?;
                let error = runner
                    .call_method1("run", (mutation,))
                    .expect_err("immutable resize accepted");
                let exception = py.import("qubes.exc")?.getattr("StoragePoolException")?;
                ensure!(
                    error.value(py).is_instance(&exception)?,
                    "wrong native storage exception"
                );
                Ok(json!({"same":true, "immutable":error.to_string()}))
            }
            "pool-accounting" => {
                let kwargs = PyDict::new(py);
                kwargs.set_item("name", "test")?;
                kwargs.set_item("root_dir", request["pool"].as_str().context("pool path")?)?;
                let pool = module.getattr("ClosurePool")?.call((), Some(&kwargs))?;
                Ok(json!({
                    "size":pool.getattr("size")?.extract::<u64>()?,
                    "usage":pool.getattr("usage")?.extract::<u64>()?,
                }))
            }
            operation => anyhow::bail!("unsupported storage probe: {operation}"),
        }
    })();
    runner.call_method0("close")?;
    match result {
        Ok(value) => Ok(json!({"ok":value})),
        Err(error) => {
            let exception = error
                .downcast_ref::<PyErr>()
                .map(|error| error.get_type(py).name().map(|name| name.to_string()))
                .transpose()?;
            Ok(json!({"error":error.to_string(), "exception":exception}))
        }
    }
}

/// Query the real upstream policy parser using Rust-authored requests and domain identities.
fn policy(py: Python<'_>, request: &Value) -> Result<Value> {
    let parser = py.import("qrexec.policy.parser")?;
    let kwargs = PyDict::new(py);
    kwargs.set_item("policy", request["policy"].as_str().context("policy text")?)?;
    let policy = parser.getattr("StringPolicy")?.call((), Some(&kwargs))?;
    let mut domains = serde_json::Map::new();
    for (index, name) in request["domains"]
        .as_array()
        .context("policy domains")?
        .iter()
        .enumerate()
    {
        let name = name.as_str().context("policy domain name")?;
        domains.insert(
            name.into(),
            json!({
                "name":name, "type":"StandaloneVM", "tags":[],
                "uuid":index.to_string(), "power_state":"Running",
            }),
        );
    }
    let info = values::python(py, &json!({"domains":domains}))?;
    let denied = py.import("qrexec.exc")?.getattr("AccessDenied")?;
    let allowed = parser.getattr("AllowResolution")?;
    let mut outcomes = Vec::new();
    for query in request["queries"].as_array().context("policy queries")? {
        let args = query
            .as_array()
            .context("policy query arguments")?
            .iter()
            .map(|value| values::python(py, value))
            .collect::<PyResult<Vec<_>>>()?;
        let kwargs = PyDict::new(py);
        kwargs.set_item("system_info", &info)?;
        let request = parser
            .getattr("Request")?
            .call(PyTuple::new(py, args)?, Some(&kwargs))?;
        match policy.call_method1("evaluate", (request,)) {
            Ok(result) => outcomes.push(result.is_instance(&allowed)?),
            Err(error) if error.value(py).is_instance(&denied)? => outcomes.push(false),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(json!(outcomes))
}

/// Read one consistent Admin API inventory and project the existing bootstrap scenarios in Rust.
fn preflight(py: Python<'_>, payload: &Value) -> Result<Value> {
    let path = "/var/lib/qubes/qubes.xml";
    let before = fs::read(path)?;
    let app = py.import("qubesadmin")?.getattr("Qubes")?.call0()?;
    let selection = &payload["selection"];
    let topology = &payload["topology"];
    let inventory = gpu::observe(&app, selection["port"].as_str().unwrap_or(""))?;
    let validate =
        |selection: &Value, inventory: &Value| match airlock_dom0_service::gpu_request(json!({
            "operation":"check", "selection":selection, "topology":topology,
            "inventory":inventory, "phase":"bootstrap",
        })) {
            Ok(value) => json!({"result":value,"error":null}),
            Err(error) => json!({"result":null,"error":format!("{error:#}")}),
        };
    let actual = validate(selection, &inventory);
    let mut projected = inventory;
    projected["domains"]
        .as_array_mut()
        .context("inventory domains")?
        .retain(|vm| vm["name"] != "sys-gui");
    let projected_result = validate(selection, &projected);
    let mut wrong = selection.clone();
    wrong["vendor"] = json!("ffff");
    use sha2::{Digest, Sha256};
    Ok(
        json!({"actual":actual, "projected":projected_result, "wrong_vendor":validate(&wrong,&projected),
        "before":format!("{hash:x}",hash=Sha256::digest(before)),
        "after":format!("{hash:x}",hash=Sha256::digest(fs::read(path)?))}),
    )
}

/// Run event probes in a child with an isolated settings file, without changing process globals.
fn event_child() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let config = directory.path().join("amd-vbios.json");
    fs::write(
        &config,
        serde_json::to_vec(&json!({"domains":{"graphics":{"guestSlot":16}}}))?,
    )?;
    let output = Command::new(std::env::current_exe()?)
        .arg("gpu-event-objects")
        .env("AIRLOCK_AMD_VBIOS_CONFIG", config)
        .stdin(Stdio::null())
        .output()?;
    ensure!(
        output.status.success(),
        "upstream event probe failed: {error}",
        error = String::from_utf8_lossy(&output.stderr)
    );
    std::io::stdout().write_all(&output.stdout)?;
    Ok(())
}

/// Select a read-only upstream probe; no mode starts VMs or changes device assignments.
fn main() -> Result<()> {
    let mode = std::env::args()
        .nth(1)
        .context("expected a Qubes probe mode")?;
    if mode == "gpu-events" {
        return event_child();
    }
    let input = if matches!(mode.as_str(), "gpu-event-objects") {
        Value::Null
    } else {
        let mut bytes = Vec::new();
        std::io::stdin()
            .take(32 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 32 * 1024 * 1024, "probe input exceeds limit");
        serde_json::from_slice(&bytes)?
    };
    let value = Python::attach(|py| match mode.as_str() {
        "storage-properties" => properties(py, &input),
        "policy" => policy(py, &input),
        "storage-transaction" => transaction::observe(py),
        "store-lock" => transaction::locked(py, &input),
        "gpu-preflight" => preflight(py, &input),
        "gpu-event-objects" => events::observe(py),
        _ => anyhow::bail!("unknown Qubes probe: {mode}"),
    })?;
    println!("{value}");
    Ok(())
}
