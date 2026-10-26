//! Native methods installed on upstream Qubes storage and extension subclasses.
//! Python retains its object model and event dispatcher; Airlock behavior lives in Rust.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

mod gpu;

mod storage;

use pyo3::{
    prelude::*,
    types::{PyDict, PyTuple},
};

/// Translate an engine rejection into Qubes' own exception family.
fn exception(py: Python<'_>, class: &str, error: impl std::fmt::Display) -> PyErr {
    match py
        .import("qubes.exc")
        .and_then(|module| module.getattr(class))
        .and_then(|class| class.call1((error.to_string(),)))
    {
        Ok(value) => PyErr::from_value(value),
        Err(import) => import,
    }
}

/// Call the storage engine in-process, preserving upstream exception types.
fn native<T: Send>(
    py: Python<'_>,
    operation: impl FnOnce() -> anyhow::Result<T> + Send,
) -> PyResult<T> {
    py.detach(operation)
        .map_err(|error| exception(py, "StoragePoolException", format!("{error:#}")))
}

/// Resolve one required positional argument with a Python-compatible error.
fn argument<'py>(args: &Bound<'py, PyTuple>, index: usize) -> PyResult<Bound<'py, PyAny>> {
    args.get_item(index)
}

/// Read a named constructor argument with its native Python type intact.
fn keyword<'py>(kwargs: Option<&Bound<'py, PyDict>>, name: &str) -> PyResult<Bound<'py, PyAny>> {
    kwargs
        .and_then(|kwargs| kwargs.get_item(name).transpose())
        .transpose()?
        .ok_or_else(|| {
            pyo3::exceptions::PyTypeError::new_err(format!("missing keyword argument: {name}"))
        })
}

/// Register both plugins in one native module so Qubes can discover ordinary entry points.
#[pymodule]
fn airlock_qubes(module: &Bound<'_, PyModule>) -> PyResult<()> {
    storage::register(module)?;
    module.add_function(wrap_pyfunction!(__getattr__, module)?)?;
    Ok(())
}

/// Load GPU event registration only when Qubes requests that extension entry point.
#[pyfunction]
fn __getattr__(py: Python<'_>, name: &str) -> PyResult<Py<PyAny>> {
    if name != "AMDVBIOS" {
        return Err(pyo3::exceptions::PyAttributeError::new_err(name.to_owned()));
    }
    let module = py.import("airlock_qubes")?;
    gpu::register(&module)?;
    Ok(module.getattr(name)?.unbind())
}
