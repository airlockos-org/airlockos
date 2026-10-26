//! Call Qubes' offline object API directly while retaining its Python-owned references.

use super::{Created, Defaults, Label, VmPlan};
use airlock_qubes::{snapshot, values};
use anyhow::{Context, Result};
use pyo3::{prelude::*, types::PyDict};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

/// An offline object graph and its event loop, with reversible process-global settings.
pub(super) struct Session<'py> {
    // Attached interpreter; Python objects never escape this assembly session.
    py: Python<'py>,
    // Upstream constructors and label types, loaded from the packaged Python environment.
    qubes: Bound<'py, PyModule>,
    // Shared upstream defaults changed only while constructing the image database.
    config: Bound<'py, PyModule>,
    // Extension discovery is disabled offline to avoid contacting QubesDB.
    extensions: Bound<'py, PyModule>,
    // Original extension discovery function restored after success or failure.
    original_extensions: Bound<'py, PyAny>,
    // Original Qubes data directory, independent of the image's temporary build directory.
    original_root: Bound<'py, PyAny>,
    // Original pool definitions restored before the interpreter is reused.
    original_pools: Bound<'py, PyAny>,
    // Owns one event loop for synchronous and asynchronous upstream volume APIs.
    runner: Bound<'py, PyAny>,
    // Live Qubes object graph; removed and closed before reopening the saved store.
    app: Option<Bound<'py, PyAny>>,
    // Fresh database path, used again by the upstream reload constructor.
    store: String,
    // Prevent duplicate shutdown after explicit cleanup has already attempted every resource.
    finished: bool,
}

impl<'py> Session<'py> {
    /// Open upstream objects with offline extensions and image-local default pools.
    pub(super) fn start(py: Python<'py>, root: &Path) -> Result<Self> {
        let qubes = py
            .import("qubes")
            .context("import packaged Qubes Python library")?;
        let config = py.import("qubes.config")?;
        let extensions = py.import("qubes.ext")?;
        // Qubes' StandaloneVM class expects AppVM mixins to be initialized first.
        py.import("qubes.vm.appvm")?;
        let runner = py.import("asyncio")?.getattr("Runner")?.call0()?;
        let mut session = Self {
            original_extensions: extensions.getattr("get_extensions")?,
            original_root: config.getattr("qubes_base_dir")?,
            original_pools: config.getattr("defaults")?.get_item("pool_configs")?,
            py,
            qubes,
            config,
            extensions,
            runner,
            app: None,
            store: root
                .join("qubes.xml")
                .to_str()
                .context("Qubes database path must be UTF-8")?
                .to_owned(),
            finished: false,
        };
        session.runner.call_method0("__enter__")?;

        session
            .extensions
            .setattr("get_extensions", py.import("builtins")?.getattr("set")?)?;
        // Qubes concatenates strings onto these paths rather than accepting PathLike objects.
        session.config.setattr(
            "qubes_base_dir",
            root.to_str()
                .context("Qubes data directory must be UTF-8")?,
        )?;
        let pools = json!({
            "varlibqubes": {
                "name": "varlibqubes", "driver": "file", "dir_path": root,
            },
            "linux-kernel": {
                "name": "linux-kernel", "driver": "linux-kernel",
                "dir_path": root.join("vm-kernels"),
            },
        });
        session
            .config
            .getattr("defaults")?
            .set_item("pool_configs", values::python(py, &pools)?)?;

        let options = PyDict::new(py);
        options.set_item("offline_mode", true)?;
        session.app = Some(session.qubes.getattr("Qubes")?.call_method(
            "create_empty_store",
            (&session.store,),
            Some(&options),
        )?);
        session.app()?.setattr("events_enabled", false)?;
        session.app_properties(&BTreeMap::from([
            ("default_kernel".into(), json!("")),
            ("default_template".into(), Value::Null),
        ]))?;

        Ok(session)
    }

    /// Require an open object graph before any property or storage operation.
    fn app(&self) -> Result<&Bound<'py, PyAny>> {
        self.app
            .as_ref()
            .context("offline Qubes database is closed")
    }

    /// Resolve a VM through Qubes' own domain collection and property semantics.
    fn vm(&self, name: &str) -> Result<Bound<'py, PyAny>> {
        Ok(self.app()?.getattr("domains")?.get_item(name)?)
    }

    /// Read Qubes' built-in label identities and default private disk size.
    pub(super) fn defaults(&self) -> Result<Defaults> {
        let labels = self
            .app()?
            .getattr("labels")?
            .call_method0("values")?
            .try_iter()?
            .map(|label| {
                let label = label?;
                Ok(Label {
                    index: label.getattr("index")?.extract()?,
                    name: label.getattr("name")?.extract()?,
                    color: label.getattr("color")?.extract()?,
                })
            })
            .collect::<PyResult<Vec<_>>>()?;

        Ok(Defaults {
            labels,
            maximum: self.config.getattr("max_default_label")?.extract()?,
            private_size: self
                .config
                .getattr("defaults")?
                .get_item("private_img_size")?
                .extract()?,
        })
    }

    /// Install an allocated custom label without changing upstream label indices.
    pub(super) fn add_label(&self, label: &Label) -> Result<()> {
        let value = self
            .qubes
            .getattr("Label")?
            .call1((label.index, &label.color, &label.name))?;
        self.app()?
            .getattr("labels")?
            .set_item(label.index, value)?;
        Ok(())
    }

    /// Register the existing Airlock storage plugin as an upstream pool object.
    pub(super) fn add_pool(&self, root: &str) -> Result<()> {
        let options = PyDict::new(self.py);
        options.set_item("name", "airlock-closure")?;
        options.set_item("root_dir", root)?;
        let pool = self
            .py
            .import("airlock_qubes")?
            .getattr("ClosurePool")?
            .call((), Some(&options))?;
        self.app()?
            .getattr("pools")?
            .set_item(pool.getattr("name")?, pool)?;
        Ok(())
    }

    /// Create an upstream StandaloneVM and return Qubes-selected disk configurations.
    pub(super) fn create_vm(&self, plan: &VmPlan) -> Result<Created> {
        let options = PyDict::new(self.py);
        options.set_item("name", &plan.name)?;
        options.set_item("label", &plan.label)?;
        options.set_item(
            "uuid",
            self.py
                .import("uuid")?
                .getattr("UUID")?
                .call1((&plan.uuid,))?,
        )?;
        let vm = self
            .app()?
            .call_method("add_new_vm", (&plan.class,), Some(&options))?;
        vm.setattr("events_enabled", false)?;
        properties(&vm, &BTreeMap::from([("netvm".into(), Value::Null)]))?;

        Ok(Created {
            directory: vm.getattr("dir_path")?.extract()?,
            volumes: serde_json::from_value(values::plain(&vm.getattr("volume_config")?)?)?,
        })
    }

    /// Set a VM's validated properties through upstream descriptors.
    pub(super) fn vm_properties(&self, name: &str, values: &BTreeMap<String, Value>) -> Result<()> {
        properties(&self.vm(name)?, values).with_context(|| format!("set properties for {name}"))
    }

    /// Restore Qubes inheritance after temporarily clearing the network during disk creation.
    pub(super) fn inherit_netvm(&self, name: &str) -> Result<()> {
        self.vm(name)?.delattr("netvm")?;
        Ok(())
    }

    /// Set machine-wide preferences through upstream descriptors.
    pub(super) fn app_properties(&self, values: &BTreeMap<String, Value>) -> Result<()> {
        properties(self.app()?, values)
    }

    /// Publish the Rust-planned feature map without changing Qubes' feature representation.
    pub(super) fn features(&self, vm: &VmPlan) -> Result<()> {
        self.vm(&vm.name)?
            .getattr("features")?
            .call_method1("update", (&vm.features,))?;
        Ok(())
    }

    /// Register a volume, optionally awaiting disk creation on this session's event loop.
    pub(super) fn volume(
        &self,
        vm: &str,
        name: &str,
        config: &Value,
        create: bool,
    ) -> Result<Option<PathBuf>> {
        let vm = self.vm(vm)?;
        // Upstream constructors may mutate their argument; keep the persisted copy independent.
        vm.getattr("volume_config")?
            .set_item(name, values::python(self.py, config)?)?;
        let volume = vm
            .getattr("storage")?
            .call_method1("init_volume", (name, values::python(self.py, config)?))?;
        if !create {
            return Ok(None);
        }

        let result = volume.call_method0("create")?;
        if self
            .py
            .import("inspect")?
            .call_method1("isawaitable", (&result,))?
            .is_truthy()?
        {
            let bounded = self
                .py
                .import("asyncio")?
                .call_method1("wait_for", (result, 120))?;
            self.runner
                .call_method0("get_loop")?
                .call_method1("run_until_complete", (bounded,))?;
        }

        Ok(Some(volume.getattr("path")?.extract()?))
    }

    /// Save through Qubes and release its handles before any reload verification.
    pub(super) fn save(&mut self) -> Result<()> {
        self.app()?
            .call_method0("save")
            .context("save offline Qubes database")?;
        self.close_app()
    }

    /// Reopen the saved database offline and observe its real labels, identities and storage.
    pub(super) fn inspect(&mut self, plans: &[VmPlan]) -> Result<Value> {
        anyhow::ensure!(
            self.app.is_none(),
            "close the original Qubes objects before reload"
        );
        let options = PyDict::new(self.py);
        options.set_item("offline_mode", true)?;
        self.app = Some(
            self.qubes
                .getattr("Qubes")?
                .call((&self.store,), Some(&options))
                .context("reload offline Qubes database")?,
        );

        let mut observations = serde_json::Map::new();
        for plan in plans {
            let vm = self.vm(&plan.name)?;
            let label = vm.getattr("label")?;
            observations.insert(plan.name.clone(), json!({
                "label": label.getattr("name")?.extract::<String>()?,
                "color": label.getattr("color")?.extract::<String>()?,
                "root_source": vm.getattr("features")?.get_item("airlock-root-source")?.extract::<String>()?,
                "snapshot": snapshot::read(self.app()?, &vm)?,
            }));
        }

        Ok(Value::Object(observations))
    }

    /// Release database handles, including on initialization and assembly errors.
    fn close_app(&mut self) -> Result<()> {
        if let Some(app) = self.app.take() {
            app.call_method0("close")
                .context("close offline Qubes database")?;
        }
        Ok(())
    }

    /// Require the reloaded database to close successfully before accepting the image.
    pub(super) fn finish(&mut self) -> Result<()> {
        self.cleanup()
    }

    /// Attempt every release and restoration, returning the first failure to the caller.
    fn cleanup(&mut self) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;

        // Attempt every cleanup even when an earlier close fails; preserve the original error.
        let cleanup = [
            self.close_app(),
            self.runner
                .call_method0("close")
                .map(|_| ())
                .map_err(Into::into),
            self.extensions
                .setattr("get_extensions", &self.original_extensions)
                .map_err(Into::into),
            self.config
                .setattr("qubes_base_dir", &self.original_root)
                .map_err(Into::into),
            self.config
                .getattr("defaults")
                .and_then(|defaults| defaults.set_item("pool_configs", &self.original_pools))
                .map_err(Into::into),
        ];
        let mut errors = cleanup.into_iter().filter_map(Result::err);
        if let Some(first) = errors.next() {
            for error in errors {
                eprintln!("offline Qubes cleanup: {error:#}");
            }
            return Err(first);
        }
        Ok(())
    }
}

impl Drop for Session<'_> {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("offline Qubes cleanup: {error:#}");
        }
    }
}

/// Validate each property name before invoking its upstream setter.
fn properties(target: &Bound<'_, PyAny>, values: &BTreeMap<String, Value>) -> Result<()> {
    for (name, value) in values {
        target.call_method1("property_get_def", (name,))?;
        target.setattr(name, values::python(target.py(), value)?)?;
    }
    Ok(())
}
