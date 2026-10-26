//! Observe real Qubes file locking and persistence using a disposable offline database.

use airlock_deployment_core::attachment::CheckedInstallation;
use airlock_qubes::storage::Policy;
use airlock_qubes::{snapshot, storage, values};
use anyhow::{Context, Result, ensure};
use pyo3::{prelude::*, types::PyDict};
use serde_json::{Value, json};
use std::{
    cell::Cell,
    fs,
    io::Write,
    process::{Command, Stdio},
};

/// Attempt POSIX record locking from another process; same-process lock tests would be misleading.
pub(super) fn locked(py: Python<'_>, request: &Value) -> Result<Value> {
    let path = request["store"].as_str().context("Qubes lock probe path")?;
    let file = py
        .import("builtins")?
        .getattr("open")?
        .call1((path, "r+b"))?;
    let fcntl = py.import("fcntl")?;
    let flags =
        fcntl.getattr("LOCK_EX")?.extract::<i32>()? | fcntl.getattr("LOCK_NB")?.extract::<i32>()?;
    let result = fcntl.call_method1("lockf", (&file, flags));
    let held = match result {
        Ok(_) => false,
        Err(error) if error.is_instance_of::<pyo3::exceptions::PyBlockingIOError>(py) => true,
        Err(error) => return Err(error.into()),
    };
    file.call_method0("close")?;
    Ok(json!({"locked":held}))
}

/// Run the lock contender in a new process so it cannot inherit the caller's POSIX lock ownership.
fn contended(store: &str) -> Result<bool> {
    let mut child = Command::new(std::env::current_exe()?)
        .arg("store-lock")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .context("lock contender input")?
        .write_all(&serde_json::to_vec(&json!({"store":store}))?)?;
    let output = child.wait_with_output()?;
    ensure!(
        output.status.success(),
        "Qubes lock contender failed: {error}",
        error = String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice::<Value>(&output.stdout)?["locked"] == true)
}

/// Open a deliberately offline database through the actual upstream constructor.
fn open<'py>(py: Python<'py>, store: &str, load: bool) -> PyResult<Bound<'py, PyAny>> {
    let kwargs = PyDict::new(py);
    kwargs.set_item("offline_mode", true)?;
    kwargs.set_item("load", load)?;
    py.import("qubes")?
        .getattr("Qubes")?
        .call((store,), Some(&kwargs))
}

/// Compare resolved identities and properties; Qubes reloads raw XML configuration scalars as strings.
fn resolved(snapshot: &Value) -> Result<Vec<Value>> {
    snapshot["volumes"]
        .as_array()
        .context("upstream volume records")?
        .iter()
        .map(|volume| {
            let mut properties = volume
                .as_object()
                .context("upstream volume properties")?
                .clone();
            properties.remove("config");
            Ok(Value::Object(properties))
        })
        .collect()
}

/// Exercise production rejection under the real database lock and preserve writable state on reload.
pub(super) fn observe(py: Python<'_>) -> Result<Value> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().to_str().context("offline database root")?;
    let store = directory.path().join("qubes.xml");
    let store = store.to_str().context("offline database path")?;
    fs::create_dir(directory.path().join("vm-kernels"))?;
    let kernel = directory.path().join("vm-kernels/test-kernel");
    fs::create_dir(&kernel)?;
    for name in ["vmlinuz", "modules.img"] {
        fs::write(kernel.join(name), "fixture")?;
    }
    let config = py.import("qubes.config")?;
    config.setattr("qubes_base_dir", root)?;
    config.getattr("defaults")?.set_item(
        "pool_configs",
        values::python(
            py,
            &json!({
                "varlibqubes":{"name":"varlibqubes", "driver":"file", "dir_path":root},
                "linux-kernel":{
                    "name":"linux-kernel", "driver":"linux-kernel",
                    "dir_path":directory.path().join("vm-kernels"),
                },
            }),
        )?,
    )?;
    py.import("qubes.ext")?
        .setattr("get_extensions", py.import("builtins")?.getattr("set")?)?;
    py.import("qubes.vm.appvm")?;
    let runner = py.import("asyncio")?.getattr("Runner")?.call0()?;
    runner.call_method0("__enter__")?;
    let kwargs = PyDict::new(py);
    kwargs.set_item("offline_mode", true)?;
    let app = py.import("qubes")?.getattr("Qubes")?.call_method(
        "create_empty_store",
        (store,),
        Some(&kwargs),
    )?;
    app.setattr("events_enabled", false)?;
    app.setattr("default_kernel", "")?;
    app.setattr("default_template", py.None())?;
    let kwargs = PyDict::new(py);
    kwargs.set_item("name", "usr-home")?;
    kwargs.set_item("label", "green")?;
    let vm = app.call_method("add_new_vm", ("StandaloneVM",), Some(&kwargs))?;
    vm.setattr("events_enabled", false)?;
    vm.setattr("kernel", "")?;
    vm.setattr("netvm", py.None())?;
    vm.setattr("guivm", py.None())?;
    fs::create_dir_all(vm.getattr("dir_path")?.extract::<std::path::PathBuf>()?)?;
    app.call_method0("save")?;
    app.call_method0("close")?;

    let app = open(py, store, true)?;
    let vm = app.getattr("domains")?.get_item("usr-home")?;
    let empty_kernel =
        snapshot::read(&app, &vm).context("observe a newly created kernel-free VM")?;
    ensure!(
        empty_kernel["volumes"]
            .as_array()
            .context("volumes")?
            .iter()
            .all(|volume| volume["name"] != "kernel"),
        "unused kernel slot is not a backing resource"
    );
    let private = vm.getattr("volumes")?.get_item("private")?;
    let private_id = private.getattr("vid")?;
    private.setattr("vid", py.None())?;
    ensure!(
        snapshot::read(&app, &vm).is_err(),
        "missing writable backing identity was accepted"
    );
    private.setattr("vid", private_id)?;
    vm.setattr("events_enabled", false)?;
    vm.setattr("kernel", "test-kernel")?;
    app.setattr("default_kernel", "")?;
    app.call_method0("save")?;
    let before = snapshot::read(&app, &vm).context("read initial upstream storage objects")?;
    app.call_method0("close")?;
    let mut volume = before["volumes"]
        .as_array()
        .context("upstream volumes")?
        .iter()
        .find(|volume| volume["name"] == "private")
        .context("upstream private volume")?["config"]
        .clone();
    volume["size"] = json!(1048576);
    let request = json!({"operation":"install", "domain":"usr-home", "expected":before,
        "pool":{"name":"airlock-closure", "driver":"airlock-closure", "root_dir":root, "revisions_to_keep":0}, "volumes":[volume]});
    let private_rejected = airlock_dom0_service::storage_objects_request(request.clone()).is_err();
    ensure!(
        private_rejected,
        "worker decoded a writable private-volume request"
    );
    let mut volumes = Vec::new();
    for (index, name) in ["store", "store-data"].iter().enumerate() {
        let generation = index + 1;
        let mut config = json!({"name":name,"pool":"airlock-closure",
            "vid":format!("domains/usr-home-runtime-store/generations/{generation}/{name}"),
            "rw":false,"save_on_stop":true,"snap_on_start":false,"source":null,
            "revisions_to_keep":0,"domain_name":"usr-home-runtime-store",
            "generation":generation.to_string(),"closure_hash":"a".repeat(64),
            "manifest_path":"/pool/manifest.json","size":4096});
        if index == 0 {
            config["view_kind"] = json!("metadata-image");
            config["view_path"] = json!("/pool/metadata.img");
        } else {
            config["view_kind"] = json!("erofs-blob-map");
            config["blob_map_path"] = json!("/pool/map.json");
            config["blob_logical_size"] = json!(4096);
        }
        volumes.push(config);
    }
    let mut request = request;
    request["volumes"] = json!(volumes);
    let guards = Cell::new(0);
    /// Observe the actual upstream database lock while delegating to production policy.
    struct LockedPolicy<'a> {
        /// Disposable database used by the cross-process lock contender.
        store: &'a str,
        /// Number of authorization attempts made under the upstream lock.
        guards: &'a Cell<usize>,
    }

    impl Policy for LockedPolicy<'_> {
        fn authorize(
            &self,
            input: storage::InstallInput,
            observed: &Value,
        ) -> Result<CheckedInstallation> {
            ensure!(
                contended(self.store)?,
                "Qubes released its database lock before the native guard"
            );
            self.guards.set(self.guards.get() + 1);
            airlock_dom0_service::storage_objects_policy().authorize(input, observed)
        }

        fn verify(&self, installation: &CheckedInstallation, observed: &Value) -> Result<()> {
            airlock_dom0_service::storage_objects_policy().verify(installation, observed)
        }
    }
    let guard = LockedPolicy {
        store,
        guards: &guards,
    };
    let saved = fs::read(store)?;
    let app = open(py, store, false)?;
    let result = storage::on_app(
        &app,
        airlock_dom0_service::storage_objects_request(request.clone())?,
        &guard,
        &runner,
    );
    ensure!(
        guards.get() == 1,
        "storage rejected before the locked guard: {error:?}",
        error = result.as_ref().err()
    );
    let rejected_private = result.is_err();
    app.call_method0("close")?;
    ensure!(
        rejected_private && saved == fs::read(store)?,
        "immutable attachment changed private storage"
    );
    ensure!(
        !contended(store)?,
        "Qubes did not release its database lock"
    );

    let mut stale = request;
    stale["expected"]["running"] = json!(true);
    let app = open(py, store, false)?;
    let rejected = storage::on_app(
        &app,
        airlock_dom0_service::storage_objects_request(stale)?,
        &guard,
        &runner,
    )
    .is_err();
    app.call_method0("close")?;
    ensure!(
        rejected && saved == fs::read(store)?,
        "stale storage request changed the database"
    );
    let app = open(py, store, true)?;
    let vm = app.getattr("domains")?.get_item("usr-home")?;
    let persisted = snapshot::read(&app, &vm)?;
    app.call_method0("close")?;
    runner.call_method0("close")?;
    ensure!(
        resolved(&before)? == resolved(&persisted)?,
        "Qubes resolved volume properties changed on reload"
    );
    Ok(
        json!({"guards_under_lock":guards.get(), "private_unchanged":true, "private_effect_rejected":private_rejected,
        "stale_rejected":rejected, "lock_released":true}),
    )
}
