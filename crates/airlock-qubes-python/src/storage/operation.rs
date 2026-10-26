//! Await owned storage work without occupying Qubes' asyncio thread.
//! A per-object completion future survives cancellation and retains Python updates until the worker settles.

use pyo3::{
    exceptions::{PyAttributeError, PyRuntimeError, PyStopIteration, PyTypeError},
    prelude::*,
};
use std::{mem, path::PathBuf, time::Instant};

#[cfg(test)]
mod tests;

const PENDING: &str = "_airlock_storage_pending";

/// Filesystem/device work captures owned Rust inputs, never a Qubes Python object.
pub(super) struct Work {
    /// Trusted operation/volume identity included in bounded diagnostic records.
    pub(super) label: String,
    /// The existing engine owns its locks and cleanup for the entire call.
    pub(super) run: Box<dyn FnOnce() -> anyhow::Result<Option<PathBuf>> + Send + Sync>,
}

/// Read upstream fields on the event-loop thread immediately before dispatch.
type Prepare = for<'py> fn(&Bound<'py, PyAny>, &str) -> PyResult<Work>;

/// Apply an owned result to upstream objects on the event-loop thread.
type Finish =
    for<'py> fn(&Bound<'py, PyAny>, &str, Result<Option<PathBuf>, String>) -> PyResult<Py<PyAny>>;

/// Keep diagnostics single-line and bounded even when an external tool reports an error.
fn detail(value: impl std::fmt::Display) -> String {
    value
        .to_string()
        .chars()
        .filter(|c| !c.is_control())
        .take(512)
        .collect()
}

/// Native result crossing from the executor; it contains no Qubes/Python references.
#[pyclass(module = "airlock_qubes")]
struct WorkerResult {
    // Typed engine output or bounded error, interpreted on the event-loop thread.
    result: Result<Option<PathBuf>, String>,
}

/// Python's existing executor owns and joins this callable's thread.
#[pyclass(module = "airlock_qubes")]
struct Worker {
    // Taken exactly once, after submission to asyncio's executor.
    work: Option<Work>,
    // Queue time is distinct from time spent waiting for engine locks and I/O.
    queued: Instant,
}

#[pymethods]
impl Worker {
    /// Execute only owned Rust work, releasing the GIL for the complete engine operation.
    fn __call__(&mut self, py: Python<'_>) -> PyResult<WorkerResult> {
        let work = self
            .work
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("storage worker reused"))?;

        let queue_ms = self.queued.elapsed().as_millis();
        let started = Instant::now();
        let result = py
            .detach(work.run)
            .map_err(|error| detail(format!("{error:#}")));

        let record = serde_json::json!({
            "event":"airlock.storage-operation", "operation":detail(work.label),
            "queue_ms":queue_ms, "elapsed_ms":started.elapsed().as_millis(),
            "status":if result.is_ok() { "passed" } else { "failed" },
            "error":result.as_ref().err(),
        });
        eprintln!("{record}");
        Ok(WorkerResult { result })
    }
}

/// Future values retain errors without generating unobserved-Future exception warnings after close.
#[pyclass(module = "airlock_qubes")]
struct Completion {
    // Upstream return value or exception, created only after main-thread finalization.
    value: PyResult<Py<PyAny>>,
}

/// The executor's completion callback retains its target even when the original awaiter is closed.
#[pyclass(module = "airlock_qubes")]
struct Finalize {
    // Upstream pool/volume whose fields are updated before releasing its pending marker.
    target: Py<PyAny>,
    // Official Qubes callback whose return contract must be preserved.
    name: String,
    // Main-thread adapter for the completed native result.
    finish: Finish,
    // Shared completion barrier used by this call and later callbacks on the same object.
    completed: Py<PyAny>,
}

#[pymethods]
impl Finalize {
    /// Update Python state before making this object's next storage operation eligible to run.
    fn __call__(&self, py: Python<'_>, future: &Bound<'_, PyAny>) -> PyResult<()> {
        let mut value = (|| {
            let result = future.call_method0("result")?;
            let result = result.extract::<PyRef<'_, WorkerResult>>()?.result.clone();
            (self.finish)(self.target.bind(py), &self.name, result)
        })();

        let target = self.target.bind(py);
        let cleanup = (|| -> PyResult<()> {
            if pending(target)?.is_some_and(|future| future.is(self.completed.bind(py))) {
                target.delattr(PENDING)?;
            }
            Ok(())
        })();

        if let Err(error) = cleanup {
            value = Err(error);
        }
        if let Err(error) = &value {
            eprintln!(
                "airlock storage completion {name}: {error}",
                name = self.name,
                error = detail(error)
            );
        }
        self.completed
            .bind(py)
            .call_method1("set_result", (Completion { value },))?;
        Ok(())
    }
}

/// Distinguish waiting for a predecessor from a worker this coroutine has already started.
enum WaitingFor {
    // Cancelling before dispatch must not start another native operation.
    Predecessor,
    // Cancellation must drain the operation and its Python completion first.
    Own,
}

/// One shielded iterator can be replaced after cancellation without cancelling the shared future.
struct Waiting {
    // Uncancelled completion barrier retained independently of the shield.
    future: Py<PyAny>,
    // Standard asyncio Future iterator, preserving its scheduling protocol.
    iterator: Py<PyAny>,
    // Whether native work has already been dispatched for this coroutine.
    kind: WaitingFor,
}

/// An unawaited call has no filesystem or device effects.
enum State {
    // Inputs are read only when first resumed on the owning event loop.
    Fresh,
    // Asyncio owns the suspension; no Rust thread waits on the event-loop thread.
    Waiting(Waiting),
    // Success, failure or explicit close prevents reuse.
    Finished,
}

/// Native coroutine consumed by Qubes' existing coro_maybe/asyncio task machinery.
#[pyclass(module = "airlock_qubes")]
struct Operation {
    // Only this coroutine and its main-thread completion callback access the Qubes object.
    target: Py<PyAny>,
    // Official lifecycle method retained through deferred preparation and finalization.
    name: String,
    // Main-thread snapshot adapter.
    prepare: Prepare,
    // Main-thread result adapter.
    finish: Finish,
    // Current suspension or terminal state.
    state: State,
    // First interruption is propagated after dispatched work settles; repeated cancellation cannot detach it.
    interruption: Option<PyErr>,
}

impl Operation {
    /// Queue behind a previous callback, taking a fresh snapshot only after its Python updates complete.
    fn begin(&mut self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let target = self.target.bind(py);
        if let Some(previous) = pending(target)? {
            return self.wait(py, previous.unbind(), WaitingFor::Predecessor);
        }

        let work = (self.prepare)(target, &self.name)?;
        let event_loop = py.import("asyncio")?.call_method0("get_running_loop")?;
        let completed = event_loop.call_method0("create_future")?;
        let worker = Py::new(
            py,
            Worker {
                work: Some(work),
                queued: Instant::now(),
            },
        )?;
        let finalize = Py::new(
            py,
            Finalize {
                target: self.target.clone_ref(py),
                name: self.name.clone(),
                finish: self.finish,
                completed: completed.clone().unbind(),
            },
        )?;

        target.setattr(PENDING, &completed)?;
        let future = match event_loop.call_method1("run_in_executor", (py.None(), worker)) {
            Ok(future) => future,
            Err(error) => {
                target.delattr(PENDING)?;
                return Err(error);
            }
        };
        future.call_method1("add_done_callback", (finalize,))?;

        self.wait(py, completed.unbind(), WaitingFor::Own)
    }

    /// Yield a standard shield so task cancellation cannot cancel the native completion barrier.
    fn wait(&mut self, py: Python<'_>, future: Py<PyAny>, kind: WaitingFor) -> PyResult<Py<PyAny>> {
        let iterator = py
            .import("asyncio")?
            .call_method1("shield", (future.bind(py),))?
            .call_method0("__await__")?
            .unbind();

        self.poll(
            py,
            Waiting {
                future,
                iterator,
                kind,
            },
            py.None(),
        )
    }

    /// Advance asyncio's own iterator and apply the completed callback's return contract.
    fn poll(&mut self, py: Python<'_>, waiting: Waiting, value: Py<PyAny>) -> PyResult<Py<PyAny>> {
        match waiting.iterator.bind(py).call_method1("send", (value,)) {
            Ok(value) => {
                self.state = State::Waiting(waiting);
                Ok(value.unbind())
            }
            Err(error) if error.is_instance_of::<PyStopIteration>(py) => match waiting.kind {
                WaitingFor::Predecessor => self.begin(py),
                WaitingFor::Own => {
                    let result = waiting.future.bind(py).call_method0("result")?;
                    let completion = result.extract::<PyRef<'_, Completion>>()?;
                    if let Some(error) = self.interruption.take() {
                        return Err(error);
                    }

                    let value = completion
                        .value
                        .as_ref()
                        .map(|value| value.clone_ref(py))
                        .map_err(|error| error.clone_ref(py))?;
                    Err(PyStopIteration::new_err((value,)))
                }
            },
            Err(error) => Err(error),
        }
    }
}

#[pymethods]
impl Operation {
    /// Return the coroutine iterator used by await and Qubes' coroutine adapter.
    fn __await__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    /// Preserve Python's coroutine iterator protocol.
    fn __iter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    /// Resume with the initial None value.
    fn __next__(&mut self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        self.send(py, py.None())
    }

    /// Start lazily or resume the standard asyncio future without blocking its event loop.
    fn send(&mut self, py: Python<'_>, value: Py<PyAny>) -> PyResult<Py<PyAny>> {
        match mem::replace(&mut self.state, State::Finished) {
            State::Fresh => {
                if !value.bind(py).is_none() {
                    return Err(PyTypeError::new_err(
                        "cannot send a non-None value to a new coroutine",
                    ));
                }
                self.begin(py)
            }
            State::Waiting(waiting) => self.poll(py, waiting, value),
            State::Finished => Err(PyRuntimeError::new_err(
                "cannot reuse an awaited storage coroutine",
            )),
        }
    }

    /// Cancel undispatched work immediately; drain dispatched work before propagating interruption.
    #[pyo3(signature = (error, value=None, _traceback=None))]
    fn throw(
        &mut self,
        py: Python<'_>,
        error: Bound<'_, PyAny>,
        value: Option<Bound<'_, PyAny>>,
        _traceback: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        let error = if error.is_callable() {
            match value {
                Some(value) => error.call1((value,))?,
                None => error.call0()?,
            }
        } else {
            error
        };
        let error = PyErr::from_value(error);

        match mem::replace(&mut self.state, State::Finished) {
            State::Waiting(Waiting {
                future,
                kind: WaitingFor::Own,
                ..
            }) => {
                if self.interruption.is_none() {
                    self.interruption = Some(error);
                }
                self.wait(py, future, WaitingFor::Own)
            }
            _ => Err(error),
        }
    }

    /// Close the awaiter; any dispatched work retains its target and completion barrier until settled.
    fn close(&mut self) {
        self.state = State::Finished;
    }
}

/// Existing synchronous getters must not attach a mapper or wait on a worker's pool lock.
pub(super) fn pending<'py>(target: &Bound<'py, PyAny>) -> PyResult<Option<Bound<'py, PyAny>>> {
    match target.getattr(PENDING) {
        Ok(future) => Ok(Some(future)),
        Err(error) if error.is_instance_of::<PyAttributeError>(target.py()) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Construct a lazy callback; only owned Rust data crosses into the executor.
pub(super) fn call(
    target: Bound<'_, PyAny>,
    name: &str,
    prepare: Prepare,
    finish: Finish,
) -> PyResult<Py<PyAny>> {
    let py = target.py();
    py.import("collections.abc")?
        .getattr("Coroutine")?
        .call_method1("register", (py.get_type::<Operation>(),))?;

    Ok(Py::new(
        py,
        Operation {
            target: target.unbind(),
            name: name.into(),
            prepare,
            finish,
            state: State::Fresh,
            interruption: None,
        },
    )?
    .into_any())
}
