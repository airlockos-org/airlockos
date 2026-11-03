//! Restart a native firewall through ordinary Qubes lifecycle operations when
//! its upstream incarnation changes. Asyncio supplies tasks and locks; the
//! verified planner supplies consuming transition tickets. No guest transport
//! is reopened, no client is reassigned and no independent daemon is added.
//!
//! One task per VM remains owned until its Qubes operation settles. Explicit
//! shutdown/kill requests revoke intent but do not cancel uncertain effects.
//! Qubes' startup lock prevents replacing the domain while an automatic stop
//! is outstanding. Its start/pre-spawn/XML/unpause boundaries recheck queued
//! activation, including cancellation and a changed reviewed generation.

use super::{artifact, network};
use airlock_machine_planning::network_recovery::{Binding, Power, Recovery, Stage, Ticket};
use airlock_nix_core::hermit_artifact::Descriptor;
use pyo3::{
    prelude::*,
    types::{PyDict, PyType},
};

/// Private runtime state, separate from persistent Qubes features and policy.
const ATTRIBUTE: &str = "_airlock_native_network_recovery";

/// Snapshot observations accompanying the verified transition, never standalone permission.
struct Context {
    /// Exact registered guest identity in the reviewed topology.
    name: String,
    /// Authenticated executable/capability selected by that generation.
    image: Descriptor,
    /// Protected topology path selecting the original relationships.
    generation: String,
    /// Weak reference prevents retaining a removed provider through the VM collection.
    provider: Py<PyAny>,
    /// Protected original challenge distinguishes reuse of a numeric domain ID.
    challenge: String,
}

impl Context {
    /// Copy observations for one owned asynchronous attempt, without copying its ticket.
    fn snapshot(&self, py: Python<'_>) -> Self {
        Self {
            name: self.name.clone(),
            image: self.image.clone(),
            generation: self.generation.clone(),
            provider: self.provider.clone_ref(py),
            challenge: self.challenge.clone(),
        }
    }

    /// Recheck registration, generation, artifact and exact provider object at an effect boundary.
    fn peer(&self, vm: &Bound<'_, PyAny>) -> PyResult<u16> {
        let provider = self.provider.bind(vm.py()).call0()?;
        if provider.is_none()
            || vm.getattr("name")?.extract::<String>()? != self.name
            || !vm
                .getattr("app")?
                .getattr("domains")?
                .get_item(&self.name)?
                .is(vm)
            || !vm.getattr("netvm")?.is(&provider)
            || generation(vm)? != self.generation
            || artifact(vm)? != self.image
        {
            return Ok(0);
        }
        network::validate_provider(vm, &self.image)?;
        Ok(match power(&provider)? {
            Power::Running { xid } => xid,
            _ => 0,
        })
    }

    /// A live domain must still carry the original protected challenge before it is stopped.
    fn original_power(&self, vm: &Bound<'_, PyAny>) -> PyResult<Power> {
        let observed = power(vm)?;
        if let Power::Running { xid } = observed {
            let boot = airlock_dom0_service::hermit::running_network_boot(
                &self.name,
                &self.image,
                &self.generation,
                u32::from(xid),
            )
            .map_err(|error| crate::exception(vm.py(), "QubesException", error))?;
            if boot.is_none_or(|boot| boot.challenge != self.challenge) {
                return Ok(Power::Unavailable);
            }
        }
        Ok(observed)
    }
}

/// Distinguish waiting for a lock from actually owning one through teardown.
enum Effect {
    /// Asyncio has not yet transferred ownership of this startup lock.
    Acquire(
        /// Qubes startup lock whose acquisition is owned by the pending standard Task.
        Py<PyAny>,
    ),
    /// This exact lock remains held until Qubes finishes its stop operation.
    Stop(
        /// Successfully acquired lock released only after this stop operation settles.
        Py<PyAny>,
    ),
    /// Qubes' own start owns the startup lock and checks the activation guards.
    Start,
}

/// One retained operation; callback identity, ticket and lock ownership cannot drift apart.
struct Pending {
    /// Exact stdlib asyncio Task completing this operation.
    task: Py<PyAny>,
    /// Sole consuming permission for the verified transition.
    ticket: Ticket,
    /// Original generation/provider/boot observations for this attempt.
    context: Context,
    /// Actual resource ownership appropriate to the operation.
    effect: Effect,
}

/// Per-VM event-loop state; a weak VM reference avoids a permanent Python reference cycle.
#[pyclass(module = "airlock_qubes")]
struct Coordinator {
    /// Original Qubes VM object, accessed only on its owning asyncio thread.
    vm: Py<PyAny>,
    /// Last authenticated boot, or no inferred running intent.
    context: Option<Context>,
    /// Verified running intent, replay prevention and restart sequencing.
    state: Recovery,
    /// At most one task, retained even after explicit cancellation of intent.
    pending: Option<Pending>,
}

/// Native callback registered on a standard asyncio Task.
#[pyclass(module = "airlock_qubes")]
struct Complete {
    /// Own the coordinator until its dispatched effect has settled.
    owner: Py<Coordinator>,
}

/// Translate the current Qubes state without treating pause or uncertainty as halt.
fn power(vm: &Bound<'_, PyAny>) -> PyResult<Power> {
    match vm
        .call_method0("get_power_state")?
        .extract::<String>()?
        .as_str()
    {
        "Halted" => Ok(Power::Halted),
        "Running" => {
            let xid = vm.getattr("xid")?.extract::<u16>()?;
            Ok(if xid > 0 && xid < 0x7ff0 {
                Power::Running { xid }
            } else {
                Power::Unavailable
            })
        }
        _ => Ok(Power::Unavailable),
    }
}

/// Read the same protected-generation feature used by normal native boot preparation.
fn generation(vm: &Bound<'_, PyAny>) -> PyResult<String> {
    vm.getattr("features")?
        .get_item("airlock-hermit-generation")?
        .extract()
}

/// Obtain existing state without manufacturing running intent for a halted VM.
fn coordinator(vm: &Bound<'_, PyAny>) -> PyResult<Option<Py<Coordinator>>> {
    if !vm.hasattr(ATTRIBUTE)? {
        return Ok(None);
    }
    Ok(Some(vm.getattr(ATTRIBUTE)?.extract()?))
}

/// Identify callbacks inside the owned Qubes operation, including upstream's failure cleanup.
fn own_task(owner: &Py<Coordinator>, py: Python<'_>) -> PyResult<bool> {
    let task = owner
        .borrow(py)
        .pending
        .as_ref()
        .map(|pending| pending.task.clone_ref(py));
    let Some(task) = task else {
        return Ok(false);
    };
    let current = match py.import("asyncio")?.call_method0("current_task") {
        Ok(current) => current,
        Err(error) if error.is_instance_of::<pyo3::exceptions::PyRuntimeError>(py) => {
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    Ok(task.bind(py).is(&current))
}

/// Record bounded diagnostic detail without introducing another string codec.
fn report(vm: &Bound<'_, PyAny>, outcome: &str, detail: impl std::fmt::Display) -> PyResult<()> {
    let message = detail.to_string();
    vm.getattr("log")?.call_method1(
        "info",
        (
            "airlock-hermit recovery=%s detail=%s",
            outcome,
            format!("{message:.512}"),
        ),
    )?;
    Ok(())
}

/// Restore running intent only from this host boot's protected execution record.
pub(super) fn observe_running(vm: &Bound<'_, PyAny>, image: &Descriptor) -> PyResult<()> {
    if !image.application.networking() {
        return Ok(());
    }
    if let Some(owner) = coordinator(vm)? {
        // The completion callback authenticates and arms its own new boot.
        if own_task(&owner, vm.py())? {
            return Ok(());
        }
    }
    arm(vm, image)
}

/// Capture the original upstream, including when loading an already-running domain.
fn arm(vm: &Bound<'_, PyAny>, image: &Descriptor) -> PyResult<()> {
    let py = vm.py();
    let Power::Running { xid } = power(vm)? else {
        return Ok(());
    };
    let name = vm.getattr("name")?.extract::<String>()?;
    let generation = generation(vm)?;
    let Some(boot) = airlock_dom0_service::hermit::running_network_boot(
        &name,
        image,
        &generation,
        u32::from(xid),
    )
    .map_err(|error| crate::exception(py, "QubesException", error))?
    else {
        return Ok(());
    };
    let Some(binding) = Binding::new(xid, boot.upstream) else {
        return Ok(());
    };
    network::validate_provider(vm, image)?;
    let owner = match coordinator(vm)? {
        Some(owner) => owner,
        None => {
            let weak = py.import("weakref")?.call_method1("ref", (vm,))?;
            let owner = Py::new(
                py,
                Coordinator {
                    vm: weak.unbind(),
                    context: None,
                    state: Recovery::inactive(),
                    pending: None,
                },
            )?;
            vm.setattr(ATTRIBUTE, owner.bind(py))?;
            owner
        }
    };
    let provider = py
        .import("weakref")?
        .call_method1("ref", (vm.getattr("netvm")?,))?;
    {
        let mut state = owner.borrow_mut(py);
        state.context = Some(Context {
            name,
            image: image.clone(),
            generation,
            provider: provider.unbind(),
            challenge: boot.challenge,
        });
        state.state.arm(binding);
    }
    drive(&owner, py)
}

/// Explicit shutdown/kill requests revoke intent; upstream's internal cleanup keeps its ticket.
pub(super) fn requested_stop(vm: &Bound<'_, PyAny>) -> PyResult<()> {
    if let Some(owner) = coordinator(vm)?
        && !own_task(&owner, vm.py())?
    {
        owner.borrow_mut(vm.py()).state.cancel();
    }
    Ok(())
}

/// Recheck after a lifecycle observation without aborting Qubes' own event.
/// A broken recovery observation or log sink must not kill a healthy upstream.
pub(super) fn check(vm: &Bound<'_, PyAny>) {
    let checked = (|| -> PyResult<()> {
        if let Some(owner) = coordinator(vm)? {
            drive(&owner, vm.py())?;
        }
        Ok(())
    })();
    if let Err(error) = checked
        && let Err(logging) = report(vm, "blocked", error)
    {
        logging.print(vm.py());
    }
}

/// Reject a queued automatic activation after stop, replacement, or another upstream change.
/// Normal requested starts cancel stale recovery intent and retain Qubes' usual validation.
pub(super) fn guard(vm: &Bound<'_, PyAny>, manual_start: bool) -> PyResult<()> {
    let Some(owner) = coordinator(vm)? else {
        return Ok(());
    };
    if !own_task(&owner, vm.py())? {
        if manual_start {
            owner.borrow_mut(vm.py()).state.cancel();
        }
        return Ok(());
    }
    let allowed = {
        let state = owner.borrow(vm.py());
        match state.pending.as_ref() {
            Some(pending) => {
                let step = match pending.effect {
                    Effect::Start => Stage::Start,
                    Effect::Stop(_) => Stage::Stop,
                    Effect::Acquire(_) => Stage::Lock,
                };
                let peer = pending.context.peer(vm)?;
                peer != 0 && state.state.permits(&pending.ticket, step, peer)
            }
            None => false,
        }
    };
    if !allowed {
        return Err(crate::exception(
            vm.py(),
            "QubesException",
            "native network recovery was revoked or superseded",
        ));
    }
    Ok(())
}

/// Check a provider's reviewed native downstreams after its ordinary domain-start event.
pub(super) fn upstream_started(
    provider: &Bound<'_, PyAny>,
    hermit_type: &Bound<'_, PyType>,
) -> PyResult<()> {
    if !provider.getattr("provides_network")?.is_truthy()? {
        return Ok(());
    }
    for client in provider.getattr("connected_vms")?.try_iter()? {
        let client = client?;
        if client.is_instance(hermit_type)? {
            check(&client);
        }
    }
    Ok(())
}

/// Queue one lock acquisition; completion rechecks the VM rather than trusting this snapshot.
fn drive(owner: &Py<Coordinator>, py: Python<'_>) -> PyResult<()> {
    let vm = owner.borrow(py).vm.bind(py).call0()?;
    if vm.is_none() || owner.borrow(py).pending.is_some() {
        return Ok(());
    }
    // qubesd loads running VM objects before starting its existing event loop.
    let event_loop = py.import("asyncio")?.call_method0("get_event_loop")?;
    if !event_loop.call_method0("is_running")?.is_truthy()? {
        let check = Py::new(
            py,
            Complete {
                owner: owner.clone_ref(py),
            },
        )?;
        event_loop.call_method1("call_soon", (check,))?;
        return Ok(());
    }
    let context = match owner.borrow(py).context.as_ref() {
        Some(context) => context.snapshot(py),
        None => return Ok(()),
    };
    let peer = context.peer(&vm)?;
    let observed = context.original_power(&vm)?;
    let ticket = owner.borrow_mut(py).state.begin(observed, peer);
    let Some(ticket) = ticket else {
        return Ok(());
    };
    let serial = ticket.sequence();
    let prepared = (|| {
        let lock = vm.getattr("startup_lock")?;
        let waiting = lock.call_method0("acquire")?;
        let args = PyDict::new(py);
        args.set_item("timeout", 30)?;
        let waiting = py
            .import("asyncio")?
            .call_method("wait_for", (waiting,), Some(&args))?;
        report(&vm, "queued", peer)?;
        Ok((lock.unbind(), waiting.unbind()))
    })();
    let (lock, waiting) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            owner.borrow_mut(py).state.fail_active(serial);
            return Err(error);
        }
    };
    schedule(owner, py, context, ticket, Effect::Acquire(lock), waiting)
}

/// Retain a standard deferred Task before it can execute a Qubes operation.
/// Direct Task construction avoids an optional eager task factory running before
/// callback identity is installed. CPython/asyncio owns scheduling and cancellation.
fn schedule(
    owner: &Py<Coordinator>,
    py: Python<'_>,
    context: Context,
    ticket: Ticket,
    effect: Effect,
    coroutine: Py<PyAny>,
) -> PyResult<()> {
    let serial = ticket.sequence();
    let prepared = (|| {
        let asyncio = py.import("asyncio")?;
        let args = PyDict::new(py);
        args.set_item("loop", asyncio.call_method0("get_running_loop")?)?;
        let callback = Py::new(
            py,
            Complete {
                owner: owner.clone_ref(py),
            },
        )?;
        let task = asyncio
            .getattr("Task")?
            .call((coroutine.bind(py),), Some(&args))?;
        Ok((task, callback))
    })();
    let (task, callback) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            owner.borrow_mut(py).state.fail_active(serial);
            let closed = coroutine.bind(py).call_method0("close");
            if let Effect::Stop(lock) = effect {
                lock.bind(py).call_method0("release")?;
            }
            closed?;
            return Err(error);
        }
    };
    owner.borrow_mut(py).pending = Some(Pending {
        task: task.clone().unbind(),
        ticket,
        context,
        effect,
    });
    if let Err(error) = task.call_method1("add_done_callback", (callback,)) {
        owner.borrow_mut(py).state.fail_active(serial);
        // This stdlib Task is still deferred; no coroutine effect has run yet.
        task.call_method0("cancel")?;
        let pending = owner.borrow_mut(py).pending.take();
        if let Some(Pending {
            effect: Effect::Stop(lock),
            ..
        }) = pending
        {
            lock.bind(py).call_method0("release")?;
        }
        return Err(error);
    }
    Ok(())
}

/// Use Qubes' base coroutine while keeping explicit user-facing methods cancellative.
fn lifecycle(
    vm: &Bound<'_, PyAny>,
    name: &str,
    kwargs: Option<&Bound<'_, PyDict>>,
) -> PyResult<Py<PyAny>> {
    Ok(vm
        .py()
        .import("qubes.vm.qubesvm")?
        .getattr("QubesVM")?
        .getattr(name)?
        .call((vm,), kwargs)?
        .unbind())
}

#[pymethods]
impl Complete {
    /// Consume only the original Task's result and release every acquired lock explicitly.
    #[pyo3(signature = (task=None))]
    fn __call__(&self, py: Python<'_>, task: Option<&Bound<'_, PyAny>>) -> PyResult<()> {
        let Some(task) = task else {
            return drive(&self.owner, py);
        };
        let pending = {
            let mut owner = self.owner.borrow_mut(py);
            if !owner
                .pending
                .as_ref()
                .is_some_and(|pending| pending.task.bind(py).is(task))
            {
                return Ok(());
            }
            owner.pending.take()
        };
        let Some(pending) = pending else {
            return Ok(());
        };
        let serial = pending.ticket.sequence();
        let result = task.call_method0("result");
        let mut held = match &pending.effect {
            Effect::Acquire(lock) if result.is_ok() => Some(lock.clone_ref(py)),
            Effect::Stop(lock) => Some(lock.clone_ref(py)),
            _ => None,
        };
        let vm_result = self.owner.borrow(py).vm.bind(py).call0();
        let vm = match vm_result {
            Ok(vm) => vm,
            Err(error) => {
                self.owner.borrow_mut(py).state.fail_active(serial);
                if let Some(lock) = held {
                    lock.bind(py).call_method0("release")?;
                }
                return Err(error);
            }
        };
        let advanced = if vm.is_none() {
            self.owner.borrow_mut(py).state.fail(pending.ticket);
            Ok(())
        } else {
            advance(&self.owner, py, &vm, pending, result, &mut held)
        };
        if let Some(lock) = held {
            lock.bind(py).call_method0("release")?;
        }
        if let Err(error) = advanced {
            self.owner.borrow_mut(py).state.fail_active(serial);
            if !vm.is_none() {
                report(&vm, "failed", error)?;
            }
        }
        if !vm.is_none() {
            drive(&self.owner, py)?;
        }
        Ok(())
    }
}

/// Advance a completed standard operation with fresh protected and Qubes observations.
fn advance(
    owner: &Py<Coordinator>,
    py: Python<'_>,
    vm: &Bound<'_, PyAny>,
    pending: Pending,
    result: PyResult<Bound<'_, PyAny>>,
    held: &mut Option<Py<PyAny>>,
) -> PyResult<()> {
    let peer = pending.context.peer(vm)?;
    match pending.effect {
        Effect::Acquire(_) => {
            if !result?.extract::<bool>()? {
                return Err(crate::exception(
                    py,
                    "QubesException",
                    "startup lock was not acquired",
                ));
            }
            if held.is_none() {
                owner.borrow_mut(py).state.fail(pending.ticket);
                return Ok(());
            }
            let observed = pending.context.original_power(vm)?;
            let next = owner
                .borrow_mut(py)
                .state
                .locked(pending.ticket, observed, peer);
            if let Some((ticket, step)) = next {
                if step == Stage::Stop {
                    let args = PyDict::new(py);
                    args.set_item("force", true)?;
                    args.set_item("wait", true)?;
                    args.set_item("timeout", 30)?;
                    let coroutine = lifecycle(vm, "shutdown", Some(&args))?;
                    report(vm, "stopping", peer)?;
                    let Some(lock) = held.take() else {
                        return Err(crate::exception(
                            py,
                            "QubesException",
                            "missing recovery startup lock",
                        ));
                    };
                    schedule(
                        owner,
                        py,
                        pending.context,
                        ticket,
                        Effect::Stop(lock),
                        coroutine,
                    )?;
                } else {
                    start(owner, py, vm, pending.context, ticket, held)?;
                }
            }
        }
        Effect::Stop(_) => {
            if let Err(error) = result {
                let missing = py.import("qubes.exc")?.getattr("QubesVMNotStartedError")?;
                if !error.value(py).is_instance(&missing)? {
                    return Err(error);
                }
            }
            let halted = matches!(power(vm)?, Power::Halted);
            let next = owner
                .borrow_mut(py)
                .state
                .stopped(pending.ticket, halted, peer);
            if let Some(ticket) = next {
                start(owner, py, vm, pending.context, ticket, held)?;
            }
        }
        Effect::Start => {
            result?;
            let Power::Running { xid } = power(vm)? else {
                return Err(crate::exception(
                    py,
                    "QubesException",
                    "recovery start did not produce a running domain",
                ));
            };
            let boot = airlock_dom0_service::hermit::running_network_boot(
                &pending.context.name,
                &pending.context.image,
                &pending.context.generation,
                u32::from(xid),
            )
            .map_err(|error| crate::exception(py, "QubesException", error))?;
            let Some(boot) = boot else {
                return Err(crate::exception(
                    py,
                    "QubesException",
                    "recovery start has no protected boot evidence",
                ));
            };
            if boot.challenge == pending.context.challenge || boot.upstream != peer {
                return Err(crate::exception(
                    py,
                    "QubesException",
                    "recovery start is stale",
                ));
            }
            let Some(binding) = Binding::new(xid, boot.upstream) else {
                return Err(crate::exception(
                    py,
                    "QubesException",
                    "invalid recovery domain identity",
                ));
            };
            if owner.borrow_mut(py).state.complete(pending.ticket, binding) {
                let mut context = pending.context;
                context.challenge = boot.challenge;
                owner.borrow_mut(py).context = Some(context);
                report(vm, "started", xid)?;
            }
        }
    }
    Ok(())
}

/// Release the old startup lock before Qubes' start acquires it normally.
fn start(
    owner: &Py<Coordinator>,
    py: Python<'_>,
    vm: &Bound<'_, PyAny>,
    context: Context,
    ticket: Ticket,
    held: &mut Option<Py<PyAny>>,
) -> PyResult<()> {
    if let Some(lock) = held.take() {
        lock.bind(py).call_method0("release")?;
    }
    let args = PyDict::new(py);
    args.set_item("start_guid", false)?;
    let coroutine = lifecycle(vm, "start", Some(&args))?;
    schedule(owner, py, context, ticket, Effect::Start, coroutine)
}
