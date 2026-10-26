//! Hold Qubes' own database lock across native comparison, volume construction and save.

use super::snapshot;
use airlock_deployment_core::attachment::{
    CheckedInstallation, Definition, Pool, Slot, VolumeRequest,
};
use anyhow::{Context, Result, ensure};
use pyo3::{prelude::*, types::PyDict};
use serde_json::Value;

/// Await upstream APIs that may return either synchronous values or coroutine objects.
pub fn complete(value: Bound<'_, PyAny>, runner: &Bound<'_, PyAny>) -> Result<()> {
    let py = value.py();
    if py
        .import("inspect")?
        .call_method1("isawaitable", (&value,))?
        .is_truthy()?
    {
        let bounded = py
            .import("asyncio")?
            .call_method1("wait_for", (value, 120))?;
        runner
            .call_method0("get_loop")?
            .call_method1("run_until_complete", (bounded,))?;
    }
    Ok(())
}

/// Decoded worker input. This is data, not permission to modify Qubes.
pub enum Request {
    /// Inspect one VM without modifying its persisted definitions.
    Snapshot {
        /// Exact consuming VM resolved through the upstream collection.
        target: String,
    },
    /// Revalidate these declarations against a fresh locked observation.
    Install(
        /// Untrusted declarations requiring the installed policy's locked checks.
        InstallInput,
    ),
}

/// Typed declarations decoded at the isolated worker boundary.
pub struct InstallInput {
    /// Consuming VM whose state must match the locked observation.
    pub target: String,
    /// Closed immutable pool identity; upstream driver options are fixed.
    pub pool: Pool,
    /// Ordered semantic definitions, still requiring attachment authorization.
    pub definitions: Vec<Definition>,
    /// Full earlier upstream observation for the locked compare-and-swap check.
    pub expected: Value,
}

/// Native attachment policy invoked while upstream holds its database lock.
/// Only the opaque checked result may reach the mutating adapter. Observations
/// retain upstream fields for exact comparisons; they do not grant authority.
pub trait Policy {
    /// Revalidate declarations and the exact fresh observation before any volume changes.
    fn authorize(&self, input: InstallInput, observed: &Value) -> Result<CheckedInstallation>;

    /// Check installed state against the original checked request before database save.
    fn verify(&self, installation: &CheckedInstallation, observed: &Value) -> Result<()>;
}

/// Read or install exact native volume definitions through upstream Qubes objects.
/// The database lock covers comparison, installation and save. It does not fence
/// independent hypervisor activity; direct administrative starts remain external
/// interference, detected by the power checks when observable. Run this in a
/// short-lived worker because Qubes extension singletons are process-global.
pub fn execute(request: Request, policy: impl Policy) -> Result<Value> {
    Python::attach(|py| {
        let runner = py.import("asyncio")?.getattr("Runner")?.call0()?;
        runner.call_method0("__enter__")?;
        let result = with_app(py, request, &policy, &runner);
        let closed = runner
            .call_method0("close")
            .context("close Qubes storage event loop");
        match result {
            Ok(value) => {
                closed?;
                Ok(value)
            }
            Err(error) => {
                if let Err(close) = closed {
                    eprintln!("Qubes event loop cleanup: {close:#}");
                }
                Err(error)
            }
        }
    })
}

/// Open upstream objects, close them on every result, and retain upstream extension discovery.
fn with_app(
    py: Python<'_>,
    request: Request,
    policy: &impl Policy,
    runner: &Bound<'_, PyAny>,
) -> Result<Value> {
    let options = PyDict::new(py);
    if matches!(request, Request::Install(_)) {
        options.set_item("load", false)?;
    }
    let app = py
        .import("qubes")?
        .getattr("Qubes")?
        .call((), Some(&options))?;
    let result = on_app(&app, request, policy, runner);
    let closed = app
        .call_method0("close")
        .context("close Qubes storage objects");
    match result {
        Ok(value) => {
            closed?;
            Ok(value)
        }
        Err(error) => {
            if let Err(close) = closed {
                eprintln!("Qubes object cleanup: {close:#}");
            }
            Err(error)
        }
    }
}

/// Read or update caller-owned objects using upstream database locking.
/// The caller closes the object graph and event loop after success or failure.
pub fn on_app(
    app: &Bound<'_, PyAny>,
    request: Request,
    policy: &impl Policy,
    runner: &Bound<'_, PyAny>,
) -> Result<Value> {
    let py = app.py();
    let locked = PyDict::new(py);
    locked.set_item("lock", true)?;
    if matches!(request, Request::Install(_)) {
        app.call_method("load", (), Some(&locked))?;
    }
    let name = match &request {
        Request::Snapshot { target } => target,
        Request::Install(input) => &input.target,
    };
    let vm = app.getattr("domains")?.get_item(name)?;
    if vm.getattr("storage")?.is_none() {
        vm.setattr(
            "storage",
            py.import("qubes.storage")?
                .getattr("Storage")?
                .call1((&vm,))?,
        )?;
    }
    let before = snapshot::read(app, &vm)?;
    let Request::Install(input) = request else {
        return Ok(before);
    };
    let target = input.target.clone();
    let checked = policy.authorize(input, &before)?;
    ensure!(
        checked.plan().target() == target,
        "checked attachment names another VM"
    );

    install_pool(app, checked.pool(), runner)?;
    let mut dispatch = checked.dispatch();
    while let Some(request) = dispatch.next_request() {
        install_volume(app, request, runner)?;
    }
    let completed = dispatch
        .finish()
        .context("incomplete checked volume dispatch")?;
    let after = snapshot::read(app, &vm)?;
    policy.verify(completed, &after)?;
    app.call_method("save", (), Some(&locked))?;
    snapshot::read(app, &vm)
}

/// Create only the checked immutable pool; driver and retention settings are fixed.
fn install_pool(app: &Bound<'_, PyAny>, pool: &Pool, runner: &Bound<'_, PyAny>) -> Result<()> {
    if !app.getattr("pools")?.contains(pool.name())? {
        let options = PyDict::new(app.py());
        options.set_item("name", pool.name())?;
        options.set_item("driver", "airlock-closure")?;
        options.set_item("root_dir", pool.root())?;
        options.set_item("revisions_to_keep", 0)?;
        complete(app.call_method("add_pool", (), Some(&options))?, runner)?;
    }
    Ok(())
}

/// Convert one checked definition directly to upstream kwargs, without an intermediate JSON object.
/// Python construction and upstream execution are trusted adapter operations; Rust's
/// request selector preserves the exact target, definition and original order.
fn install_volume(
    app: &Bound<'_, PyAny>,
    request: VolumeRequest<'_>,
    runner: &Bound<'_, PyAny>,
) -> Result<()> {
    let py = app.py();
    let definition = request.definition();
    let name = definition.slot.name();
    let options = PyDict::new(py);
    options.set_item("name", name)?;
    options.set_item("pool", &definition.pool)?;
    options.set_item(
        "vid",
        format!(
            "domains/{domain}/generations/{generation}/{name}",
            domain = definition.domain,
            generation = definition.generation
        ),
    )?;
    options.set_item("rw", definition.writable)?;
    options.set_item("save_on_stop", definition.persistent)?;
    options.set_item("snap_on_start", definition.snap_on_start)?;
    options.set_item("source", py.None())?;
    options.set_item("revisions_to_keep", 0)?;
    options.set_item("domain_name", &definition.domain)?;
    options.set_item("generation", definition.generation.to_string())?;
    options.set_item("closure_hash", &definition.closure_hash)?;
    options.set_item("manifest_path", &definition.manifest)?;
    options.set_item("size", definition.size)?;
    match definition.slot {
        Slot::Store | Slot::BuilderStore => {
            options.set_item("view_kind", "metadata-image")?;
            options.set_item("view_path", &definition.path)?;
        }
        Slot::StoreData | Slot::BuilderData => {
            options.set_item("view_kind", "erofs-blob-map")?;
            options.set_item("blob_map_path", &definition.path)?;
            options.set_item("blob_logical_size", definition.size)?;
        }
    }

    let vm = app.getattr("domains")?.get_item(request.target())?;
    vm.getattr("volume_config")?.set_item(name, &options)?;
    let volume = vm
        .getattr("storage")?
        .call_method1("init_volume", (name, &options))?;
    complete(volume.call_method0("create")?, runner)
}
