//! Observe reloaded upstream storage objects for the native image verifier.

use super::values::{identity, optional, plain};
use anyhow::{Context, Result, ensure};
use pyo3::{prelude::*, types::PyDict};
use serde_json::{Value, json};

/// Qubes keeps a kernel slot even when no kernel is selected; that slot has no backing object.
/// Reject missing identities on every other volume, especially writable root/private storage.
fn backed(volume: &Bound<'_, PyAny>) -> Result<bool> {
    let identity = volume.getattr("vid")?;
    if !identity.is_none() && !identity.extract::<String>()?.is_empty() {
        return Ok(true);
    }
    let kernel = volume
        .py()
        .import("qubes.storage.kernels")?
        .getattr("LinuxModules")?;
    ensure!(
        volume.is_instance(&kernel)?
            && !volume.getattr("rw")?.is_truthy()?
            && volume.getattr("source")?.is_none()
            && volume.getattr("path")?.is_none(),
        "missing backing identity on a real Qubes volume"
    );
    Ok(false)
}

/// Read each volume's persisted configuration and resolved upstream metadata.
fn volumes(vm: &Bound<'_, PyAny>) -> Result<Vec<Value>> {
    let configurations = vm
        .getattr("volume_config")?
        .cast_into::<PyDict>()
        .map_err(PyErr::from)?;
    let volumes = vm
        .getattr("volumes")?
        .cast_into::<PyDict>()
        .map_err(PyErr::from)?;
    volumes
        .iter()
        .filter_map(|(name, volume)| match backed(&volume) {
            Ok(true) => Some(Ok((name, volume))),
            Ok(false) => None,
            Err(error) => Some(Err(error)),
        })
        .map(|entry| {
            let (name, volume) = entry?;
            let name: String = name.extract()?;
            let config = configurations
                .get_item(&name)?
                .context("missing volume configuration")?;
            let source = volume.getattr("source")?;
            let source = if source.is_none() {
                Value::Null
            } else {
                identity(&source)?
            };
            let generation = optional(&volume, "generation")?;
            let generation = if generation.is_none() {
                Value::Null
            } else {
                json!(generation.str()?.to_str()?)
            };

            Ok(json!({
                "name": name,
                "pool": volume.getattr("pool")?.getattr("name")?.extract::<String>()?,
                "vid": volume.getattr("vid")?.extract::<String>()?,
                "rw": volume.getattr("rw")?.is_truthy()?,
                "snap_on_start": volume.getattr("snap_on_start")?.is_truthy()?,
                "save_on_stop": volume.getattr("save_on_stop")?.is_truthy()?,
                "source": source,
                "generation": generation,
                "closure_hash": plain(&optional(&volume, "closure_hash")?)?,
                "path": plain(&optional(&volume, "path")?)?,
                "blob_map_path": plain(&optional(&volume, "blob_map_path")?)?,
                "size": volume.getattr("size")?.extract::<u64>()?,
                "config": plain(&config)?,
            }))
        })
        .collect()
}

/// Capture the same Qubes identities checked by native generation and attachment policy.
pub fn read(app: &Bound<'_, PyAny>, vm: &Bound<'_, PyAny>) -> Result<Value> {
    let name: String = vm.getattr("name")?.extract()?;
    let mut references = Vec::new();
    for other in app.getattr("domains")?.try_iter()? {
        let other = other?;
        let other_name: String = other.getattr("name")?.extract()?;
        if other_name == name || other_name == "dom0" {
            continue;
        }

        for volume in other
            .getattr("volumes")?
            .call_method0("values")?
            .try_iter()?
        {
            let volume = volume?;
            if !backed(&volume)? {
                continue;
            }
            let source = volume.getattr("source")?;
            let mut reference = identity(&volume)?;
            reference["domain"] = json!(other_name);
            reference["source"] = if source.is_none() {
                Value::Null
            } else {
                identity(&source)?
            };
            references.push(reference);
        }
    }

    let pools = app
        .getattr("pools")?
        .cast_into::<PyDict>()
        .map_err(PyErr::from)?
        .iter()
        .map(|(name, pool)| Ok((name.extract::<String>()?, plain(&pool.getattr("config")?)?)))
        .collect::<Result<serde_json::Map<_, _>>>()?;
    let features = vm
        .py()
        .import("builtins")?
        .getattr("dict")?
        .call1((vm.getattr("features")?,))?;
    let klass = optional(vm, "klass")?;
    let klass = if klass.is_none() {
        vm.get_type().name()?.to_string()
    } else {
        klass.extract()?
    };

    Ok(json!({
        "domain": name,
        "klass": klass,
        "running": vm.call_method0("is_running")?.is_truthy()?,
        "power_state": vm.call_method0("get_power_state")?.extract::<String>()?,
        "features": plain(&features)?,
        "volumes": volumes(vm)?,
        "pools": pools,
        "references": references,
    }))
}
