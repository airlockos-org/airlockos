//! Exercise the native coroutine against a real asyncio loop and controlled worker barriers.

use super::*;
use pyo3::{exceptions::PyValueError, types::PyDict};
use std::{
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, ThreadId},
    time::Duration,
};

/// Shared observations contain no Python references and can safely cross the worker boundary.
struct Harness {
    // Python snapshots and completions must stay on this loop's thread.
    owner: ThreadId,
    // The worker signals entry before the probe tests event-loop responsiveness.
    entered: AtomicBool,
    // A condition variable prevents arbitrary sleeps and always has a finite hang guard.
    released: Mutex<bool>,
    // Wakes the controlled native operation after the event-loop probe succeeds.
    release: Condvar,
    // Distinguish snapshot, native work and Python completion ordering.
    trace: Mutex<Vec<String>>,
}

impl Harness {
    /// Record cross-thread observations without retaining an upstream object.
    fn record(&self, event: String) {
        self.trace.lock().unwrap().push(event);
    }

    /// Release native work on success or while unwinding a failed assertion.
    fn unblock(&self) {
        *self.released.lock().unwrap() = true;
        self.release.notify_all();
    }
}

/// Qubes-shaped mutable state; the worker captures only its separate native harness.
#[pyclass(dict)]
struct Target {
    // Owned Rust synchronization fixture shared with the native worker.
    harness: Arc<Harness>,
}

/// Snapshot the preceding callback's result, asserting Python access stays on the loop thread.
fn prepare(target: &Bound<'_, PyAny>, name: &str) -> PyResult<Work> {
    let harness = target.extract::<PyRef<'_, Target>>()?.harness.clone();
    assert_eq!(thread::current().id(), harness.owner);
    let path: String = target.getattr("path")?.extract()?;
    harness.record(format!("prepare {name}: {path}"));
    let name = name.to_owned();
    Ok(Work {
        label: name.clone(),
        run: Box::new(move || {
            assert_ne!(thread::current().id(), harness.owner);
            harness.record(format!("worker {name}"));
            if name == "start" {
                harness.entered.store(true, Ordering::Release);
                let (_guard, timed) = harness
                    .release
                    .wait_timeout_while(
                        harness.released.lock().unwrap(),
                        Duration::from_secs(5),
                        |released| !*released,
                    )
                    .unwrap();
                anyhow::ensure!(
                    !timed.timed_out(),
                    "event loop did not release storage barrier"
                );
                return Ok(Some(PathBuf::from("attached")));
            }
            anyhow::ensure!(name != "fail", "native storage failure");
            anyhow::ensure!(
                path == "attached",
                "queued snapshot missed preceding completion"
            );
            Ok(None)
        }),
    })
}

/// Publish native results on the loop thread, including when the original awaiter was cancelled.
fn finish(
    target: &Bound<'_, PyAny>,
    name: &str,
    result: Result<Option<PathBuf>, String>,
) -> PyResult<Py<PyAny>> {
    let harness = target.extract::<PyRef<'_, Target>>()?.harness.clone();
    assert_eq!(thread::current().id(), harness.owner);
    harness.record(format!("finish {name}"));
    let path = result.map_err(PyValueError::new_err)?;
    target.setattr(
        "path",
        path.map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default(),
    )?;
    Ok(target.clone().unbind())
}

/// Loop callback observes a blocked worker, exercises cancellation, then releases native work.
#[pyclass]
struct Probe {
    // The loop reschedules this callback without sleeping while the worker starts.
    event_loop: Py<PyAny>,
    // Cancel an already-dispatched operation twice without releasing its completion barrier.
    first: Option<Py<PyAny>>,
    // Must remain suspended behind the first operation's Python finalization.
    next: Py<PyAny>,
    // A cancelled queued call must never prepare native work or interfere with its predecessor.
    skipped: Option<Py<PyAny>>,
    // Native barrier and ordering observations.
    harness: Arc<Harness>,
    // Cancellation delivery needs one subsequent event-loop turn before checking its state.
    cancelled: bool,
}

#[pymethods]
impl Probe {
    /// An unrelated callback must run while storage is still held at the native barrier.
    fn __call__(mut slf: PyRefMut<'_, Self>, py: Python<'_>) -> PyResult<()> {
        if !slf.harness.entered.load(Ordering::Acquire) {
            let event_loop = slf.event_loop.clone_ref(py);
            event_loop
                .bind(py)
                .call_method1("call_soon", (slf.into_pyobject(py)?,))?;
            return Ok(());
        }
        if !slf.cancelled {
            slf.first
                .as_ref()
                .unwrap()
                .bind(py)
                .call_method0("cancel")?;
            if let Some(skipped) = &slf.skipped {
                skipped.bind(py).call_method0("cancel")?;
            }
            slf.cancelled = true;
            let event_loop = slf.event_loop.clone_ref(py);
            event_loop
                .bind(py)
                .call_method1("call_soon", (slf.into_pyobject(py)?,))?;
            return Ok(());
        }

        let result = (|| -> PyResult<()> {
            if let Some(first) = &slf.first {
                assert!(!first.bind(py).call_method0("done")?.extract::<bool>()?);
                first.bind(py).call_method0("cancel")?;
            }
            assert!(!slf.next.bind(py).call_method0("done")?.extract::<bool>()?);
            assert_eq!(
                *slf.harness.trace.lock().unwrap(),
                ["prepare start: initial", "worker start"]
            );
            slf.harness.record("loop responsive".into());
            Ok(())
        })();
        slf.harness.unblock();
        result
    }
}

/// Each test owns its asyncio loop; shutdown joins the standard executor before dropping it.
fn with_loop(
    test: impl FnOnce(Python<'_>, &Bound<'_, PyAny>, &Bound<'_, PyAny>, Arc<Harness>) -> PyResult<()>,
) {
    Python::initialize();
    Python::attach(|py| -> PyResult<()> {
        let asyncio = py.import("asyncio")?;
        let event_loop = asyncio.call_method0("new_event_loop")?;
        asyncio.call_method1("set_event_loop", (&event_loop,))?;
        let harness = Arc::new(Harness {
            owner: thread::current().id(),
            entered: AtomicBool::new(false),
            released: Mutex::new(false),
            release: Condvar::new(),
            trace: Mutex::new(Vec::new()),
        });
        let target = Py::new(
            py,
            Target {
                harness: harness.clone(),
            },
        )?
        .into_any()
        .into_bound(py);
        target.setattr("path", "initial")?;
        let result = test(py, &event_loop, &target, harness.clone());
        harness.unblock();
        event_loop.call_method1(
            "run_until_complete",
            (event_loop.call_method0("shutdown_default_executor")?,),
        )?;
        event_loop.call_method0("close")?;
        asyncio.call_method1("set_event_loop", (py.None(),))?;
        result
    })
    .unwrap();
}

/// A blocked engine must yield control, drain repeated cancellation and serialize a later snapshot.
#[test]
fn blocked_work_keeps_loop_responsive_and_drains_cancellation() {
    with_loop(|py, event_loop, target, harness| {
        let first = event_loop.call_method1(
            "create_task",
            (call(target.clone(), "start", prepare, finish)?,),
        )?;
        let next = event_loop.call_method1(
            "create_task",
            (call(target.clone(), "stop", prepare, finish)?,),
        )?;
        let skipped = event_loop.call_method1(
            "create_task",
            (call(target.clone(), "must not start", prepare, finish)?,),
        )?;
        let probe = Py::new(
            py,
            Probe {
                event_loop: event_loop.clone().unbind(),
                first: Some(first.clone().unbind()),
                next: next.clone().unbind(),
                skipped: Some(skipped.clone().unbind()),
                harness: harness.clone(),
                cancelled: false,
            },
        )?;
        event_loop.call_method1("call_soon", (probe,))?;
        let options = PyDict::new(py);
        options.set_item("return_exceptions", true)?;
        let gathered = py.import("asyncio")?.call_method(
            "gather",
            (&first, &next, &skipped),
            Some(&options),
        )?;
        let values = event_loop.call_method1("run_until_complete", (gathered,))?;
        assert!(
            values
                .get_item(0)?
                .is_instance(&py.import("asyncio")?.getattr("CancelledError")?)?
        );
        assert!(values.get_item(1)?.is(target));
        assert!(
            values
                .get_item(2)?
                .is_instance(&py.import("asyncio")?.getattr("CancelledError")?)?
        );
        assert!(pending(target)?.is_none());
        assert_eq!(
            *harness.trace.lock().unwrap(),
            [
                "prepare start: initial",
                "worker start",
                "loop responsive",
                "finish start",
                "prepare stop: attached",
                "worker stop",
                "finish stop",
            ]
        );
        Ok(())
    });
}

/// Start and explicitly close an awaiter inside a running loop, then queue its successor.
#[pyclass]
struct CloseAwaiter {
    // Owning event loop used to dispatch the successor and probe.
    event_loop: Py<PyAny>,
    // Qubes-shaped object retained by native completion after close.
    target: Py<PyAny>,
    // Return the successor task to the outer test without driving a nested loop.
    launched: Py<PyAny>,
    // Native barrier used to prove close does not detach Python finalization.
    harness: Arc<Harness>,
}

#[pymethods]
impl CloseAwaiter {
    /// Closing the coroutine must retain its completion barrier until the worker has settled.
    fn __call__(&self, py: Python<'_>) -> PyResult<()> {
        let operation = call(self.target.bind(py).clone(), "start", prepare, finish)?;
        operation.bind(py).call_method1("send", (py.None(),))?;
        operation.bind(py).call_method0("close")?;
        assert!(pending(self.target.bind(py))?.is_some());

        let next = self.event_loop.bind(py).call_method1(
            "create_task",
            (call(self.target.bind(py).clone(), "stop", prepare, finish)?,),
        )?;
        let probe = Py::new(
            py,
            Probe {
                event_loop: self.event_loop.clone_ref(py),
                first: None,
                next: next.clone().unbind(),
                skipped: None,
                harness: self.harness.clone(),
                cancelled: true,
            },
        )?;
        self.event_loop
            .bind(py)
            .call_method1("call_soon", (probe,))?;
        self.launched.bind(py).call_method1("set_result", (next,))?;
        Ok(())
    }
}

/// An explicit coroutine close cannot release exclusion or discard the worker's Python updates.
#[test]
fn closed_awaiter_retains_completion_before_following_operation() {
    with_loop(|py, event_loop, target, harness| {
        let launched = event_loop.call_method0("create_future")?;
        let launch = Py::new(
            py,
            CloseAwaiter {
                event_loop: event_loop.clone().unbind(),
                target: target.clone().unbind(),
                launched: launched.clone().unbind(),
                harness: harness.clone(),
            },
        )?;
        event_loop.call_method1("call_soon", (launch,))?;
        let next = event_loop.call_method1("run_until_complete", (launched,))?;
        let value = event_loop.call_method1("run_until_complete", (next,))?;
        assert!(value.is(target));
        assert!(pending(target)?.is_none());
        assert_eq!(
            *harness.trace.lock().unwrap(),
            [
                "prepare start: initial",
                "worker start",
                "loop responsive",
                "finish start",
                "prepare stop: attached",
                "worker stop",
                "finish stop",
            ]
        );
        Ok(())
    });
}

/// Engine errors clear pending state; closing or cancelling an unstarted call has no native effects.
#[test]
fn failure_and_undispatched_cancellation_leave_no_pending_work() {
    with_loop(|py, event_loop, target, harness| {
        let unused = call(target.clone(), "start", prepare, finish)?;
        unused.bind(py).call_method0("close")?;
        let cancelled = event_loop.call_method1(
            "create_task",
            (call(target.clone(), "start", prepare, finish)?,),
        )?;
        cancelled.call_method0("cancel")?;
        let error = event_loop
            .call_method1("run_until_complete", (cancelled,))
            .unwrap_err();
        assert!(error.is_instance(py, &py.import("asyncio")?.getattr("CancelledError")?));
        assert!(harness.trace.lock().unwrap().is_empty());

        let error = event_loop
            .call_method1(
                "run_until_complete",
                (call(target.clone(), "fail", prepare, finish)?,),
            )
            .unwrap_err();
        assert!(error.is_instance_of::<PyValueError>(py));
        assert!(error.to_string().contains("native storage failure"));
        assert!(pending(target)?.is_none());
        target.setattr("path", "attached")?;
        let value = event_loop.call_method1(
            "run_until_complete",
            (call(target.clone(), "stop", prepare, finish)?,),
        )?;
        assert!(value.is(target));
        assert_eq!(
            *harness.trace.lock().unwrap(),
            [
                "prepare fail: initial",
                "worker fail",
                "finish fail",
                "prepare stop: attached",
                "worker stop",
                "finish stop",
            ]
        );
        Ok(())
    });
}
