//! Pushed subscriptions and local convergence share one event loop, with bounded retry timers.

use super::{
    Config,
    assets::Assets,
    mapping,
    settings::{Baseline, Settings},
    state::{Paths, Status},
    xsettings::Provider,
};
use airlock_desktop_preferences::{FrameDecoder, Snapshot};
use anyhow::{Context, Result};
use gio::{glib, prelude::*};
use std::cell::{Cell, RefCell};
use std::path::{Path, PathBuf};
use std::rc::{Rc, Weak};
use std::time::Duration;

/// One stream from the configured source; cancelling it never sends a settings request back.
struct Subscription {
    /// Existing upstream qrexec client, with stdin closed and stdout read asynchronously.
    process: gio::Subprocess,
    /// Cancels a pending read when the source is reassigned or the session stops.
    cancel: gio::Cancellable,
    /// Validates complete bounded snapshots before any adapter sees them.
    decoder: FrameDecoder,
}

/// Per-session convergence and timers. Remote desired state is intentionally never persisted.
struct Agent {
    /// Machine-owned file watched for disable/reassignment; payloads cannot select it.
    config_path: PathBuf,
    /// Current validated deployment binding, or none after a configuration error.
    config: Option<Config>,
    /// Local recovery journal, status and private provider configuration.
    paths: Paths,
    /// Ordinary guest-session GSettings handles.
    settings: Settings,
    /// Original local settings captured before the first managed write.
    baseline: Option<Baseline>,
    /// Local asset inventory for predictable fallbacks.
    assets: Assets,
    /// Last validated source snapshot, valid only within this session and GUI association.
    desired: Option<Snapshot>,
    /// Last snapshot for which available adapters converged; cleared on partial failure.
    applied: Option<Snapshot>,
    /// Owned upstream XSettings provider; never replaces another manager.
    provider: Option<Provider>,
    /// Property-change observation; no periodic XSettings polling during steady state.
    provider_events: Option<glib::SourceId>,
    /// Current qrexec process and incremental frame decoder.
    subscription: Option<Subscription>,
    /// Invalidates callbacks from a prior connection or GUI association.
    generation: u64,
    /// Retry backoff for unavailable transport, capped at thirty seconds.
    backoff: u64,
    /// Pending reconnect timer, absent while subscribed.
    reconnect: Option<glib::SourceId>,
    /// Deadline for the first snapshot of the current connection.
    first_frame: Option<glib::SourceId>,
    /// Maximum five-minute retention after losing the source connection.
    expiry: Option<glib::SourceId>,
    /// Retry only when adapters have not converged, never a preference poll.
    retry: Option<glib::SourceId>,
    /// Initial launch budget, independent of reconnect attempts or partial failures.
    startup: Option<glib::SourceId>,
    /// Whether a converged state or bounded fallback decision is available to launchers.
    ready: bool,
    /// Local asset/capability limitations from the last convergence attempt.
    limitations: Vec<String>,
    /// Last failure or transport interruption, separately from applied state.
    error: Option<String>,
    /// Coalesces local settings/property drift without borrowing the agent in synchronous callbacks.
    queued: Rc<Cell<bool>>,
}

/// Cancel a timer exactly once; executing one-shot callbacks first take their own handle.
fn remove(timer: &mut Option<glib::SourceId>) {
    if let Some(timer) = timer.take() {
        timer.remove();
    }
}

/// Keep timers from extending the session lifetime after its owner has stopped.
fn later(
    state: &Rc<RefCell<Agent>>,
    seconds: u64,
    action: impl FnOnce(Rc<RefCell<Agent>>) + 'static,
) -> glib::SourceId {
    let weak = Rc::downgrade(state);
    glib::timeout_add_local_once(Duration::from_secs(seconds), move || {
        if let Some(state) = weak.upgrade() {
            action(state);
        }
    })
}

/// Queue convergence after synchronous GSettings notifications have returned to the event loop.
fn notify(weak: Weak<RefCell<Agent>>, queued: Rc<Cell<bool>>) -> Rc<dyn Fn()> {
    Rc::new(move || {
        if queued.replace(true) {
            return;
        }

        let (weak, queued) = (weak.clone(), queued.clone());
        glib::idle_add_local_once(move || {
            queued.set(false);
            if let Some(state) = weak.upgrade() {
                reconcile(&state);
            }
        });
    })
}

impl Agent {
    /// Publish desired/applied/error separately, including retained last-known state during outages.
    fn report(&self) {
        let phase = if self.config.as_ref().is_some_and(|config| !config.enabled) {
            "disabled"
        } else if self.applied.is_some() && self.error.is_none() && self.limitations.is_empty() {
            "applied"
        } else if self.ready {
            "degraded"
        } else {
            "waiting"
        };
        let status = Status {
            config: self.config.clone(),
            ready: self.ready,
            phase: phase.into(),
            desired: self.desired.clone(),
            applied: self.applied.clone(),
            limitations: self.limitations.clone(),
            error: self
                .error
                .as_ref()
                .map(|error| error.chars().take(512).collect()),
        };
        if let Err(error) = self.paths.status(&status) {
            eprintln!("desktop preferences status: {error}");
        }
    }

    /// Cancel only our transport and its pending first-frame deadline.
    fn disconnect(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        if let Some(subscription) = self.subscription.take() {
            subscription.cancel.cancel();
            subscription.process.force_exit();
        }
        remove(&mut self.first_frame);
    }

    /// Restore owned fields before clearing a source binding or capturing a new baseline.
    fn restore(&mut self) -> Result<()> {
        remove(&mut self.provider_events);
        self.provider = None;
        self.desired = None;
        self.applied = None;
        self.settings.restore_saved(&self.paths)?;
        self.baseline = None;
        Ok(())
    }
}

/// Reconfigure only after restoring the former source; a malformed configuration revokes the stream.
fn reload(state: &Rc<RefCell<Agent>>) {
    let restore_failed;
    {
        let mut agent = state.borrow_mut();
        agent.disconnect();
        remove(&mut agent.reconnect);
        remove(&mut agent.expiry);
        remove(&mut agent.retry);
        remove(&mut agent.startup);
        agent.config = None;
        agent.ready = false;
        agent.error = None;
        let restored = agent.restore();
        restore_failed = restored.is_err();
        let result = restored.and_then(|()| Config::read(&agent.config_path));
        match result {
            Ok(config) => {
                agent.ready = !config.enabled;
                agent.config = Some(config);
                agent.backoff = 1;
            }
            Err(error) => {
                agent.error = Some(error.to_string());
                agent.ready = true;
            }
        }
        agent.report();
    }

    if restore_failed {
        retry(state);
        return;
    }
    if state
        .borrow()
        .config
        .as_ref()
        .is_some_and(|config| config.enabled)
    {
        let timer = later(state, 10, |state| {
            let mut agent = state.borrow_mut();
            agent.startup.take();
            agent.ready = true;
            if agent.applied.is_none() {
                agent.error =
                    Some("initial convergence unavailable; using bounded fallback".into());
            }
            agent.report();
        });
        state.borrow_mut().startup = Some(timer);
        connect(state);
    }
}

/// Back off transport failures while retaining at most five minutes of last-known desired state.
fn lost(state: &Rc<RefCell<Agent>>, reason: String) {
    let delay;
    let needs_expiry;
    {
        let mut agent = state.borrow_mut();
        agent.disconnect();
        agent.error = Some(reason);
        delay = agent.backoff;
        agent.backoff = (agent.backoff * 2).min(30);
        needs_expiry = agent.desired.is_some() && agent.expiry.is_none();
        agent.report();
    }

    if needs_expiry {
        let timer = later(state, 300, |state| {
            state.borrow_mut().expiry.take();
            // Revoke the old snapshot before restoration; a failed restore must
            // never reapply expired state. A new subscription requires recovery.
            reload(&state);
        });
        state.borrow_mut().expiry = Some(timer);
    }

    let timer = later(state, delay, |state| {
        state.borrow_mut().reconnect.take();
        connect(&state);
    });
    state.borrow_mut().reconnect = Some(timer);
}

/// Start exactly one fixed qrexec service against the machine-owned GUI association.
fn connect(state: &Rc<RefCell<Agent>>) {
    let result = {
        let agent = state.borrow();
        let Some(config) = agent.config.as_ref().filter(|config| config.enabled) else {
            return;
        };
        let client =
            std::env::var_os("AIRLOCK_QREXEC_CLIENT").unwrap_or_else(|| "qrexec-client-vm".into());
        gio::Subprocess::newv(
            &[
                client.as_os_str(),
                "--".as_ref(),
                config.gui_domain.as_str().as_ref(),
                "airlock.DesktopPreferences".as_ref(),
            ],
            gio::SubprocessFlags::STDOUT_PIPE,
        )
    };

    match result {
        Err(error) => lost(state, error.to_string()),
        Ok(process) => {
            state.borrow_mut().subscription = Some(Subscription {
                process,
                cancel: gio::Cancellable::new(),
                decoder: FrameDecoder::default(),
            });
            let timer = later(state, 10, |state| {
                state.borrow_mut().first_frame.take();
                lost(&state, "publisher supplied no initial snapshot".into());
            });
            state.borrow_mut().first_frame = Some(timer);
            read_next(state);
        }
    }
}

/// Issue one asynchronous bounded read. A generation check rejects callbacks from reassigned streams.
fn read_next(state: &Rc<RefCell<Agent>>) {
    let (input, cancel, generation) = {
        let agent = state.borrow();
        let Some(subscription) = &agent.subscription else {
            return;
        };
        (
            subscription.process.stdout_pipe().unwrap(),
            subscription.cancel.clone(),
            agent.generation,
        )
    };
    let weak = Rc::downgrade(state);
    input.read_bytes_async(
        4096,
        glib::Priority::DEFAULT,
        Some(&cancel),
        move |result| {
            let Some(state) = weak.upgrade() else {
                return;
            };
            if state.borrow().generation != generation {
                return;
            }
            let result = result.map_err(anyhow::Error::from).and_then(|bytes| {
                anyhow::ensure!(!bytes.is_empty(), "preferences stream ended");
                let mut input = bytes.as_ref();
                let mut latest = None;
                let mut agent = state.borrow_mut();
                while !input.is_empty() {
                    if let Some(snapshot) = agent
                        .subscription
                        .as_mut()
                        .unwrap()
                        .decoder
                        .decode(&mut input)?
                    {
                        latest = Some(snapshot);
                    }
                }
                if let Some(snapshot) = latest {
                    remove(&mut agent.first_frame);
                    remove(&mut agent.expiry);
                    agent.backoff = 1;
                    if agent.desired.as_ref() != Some(&snapshot) {
                        agent.desired = Some(snapshot);
                        agent.applied = None;
                    }
                    agent.error = None;
                }
                Ok(())
            });
            match result {
                Ok(()) => {
                    reconcile(&state);
                    read_next(&state);
                }
                Err(error) => lost(&state, error.to_string()),
            }
        },
    );
}

/// Apply local state idempotently; partial failure keeps desired state and retries convergence.
fn reconcile(state: &Rc<RefCell<Agent>>) {
    if state.borrow().desired.is_none() {
        return;
    }

    let result = (|| -> Result<Option<gio::Subprocess>> {
        let mut agent = state.borrow_mut();
        let config = agent.config.clone().context("no GUI association")?;
        if agent.baseline.is_none() {
            let baseline = agent.settings.capture(config.gui_domain);
            agent.paths.save(&baseline)?;
            agent.baseline = Some(baseline);
        }
        let mut baseline = agent.baseline.take().unwrap();
        agent.settings.refresh_unmanaged(&mut baseline);
        agent.baseline = Some(baseline);
        let plan = mapping::plan(
            agent.desired.as_ref().unwrap(),
            agent.baseline.as_ref().unwrap(),
            config.window_scale,
            &agent.assets,
        );
        agent
            .baseline
            .as_mut()
            .unwrap()
            .managed
            .extend(plan.managed.iter().copied());
        agent.paths.save(agent.baseline.as_ref().unwrap())?;
        agent.limitations = plan.limitations;
        let unavailable = agent.settings.apply(&plan.settings)?;
        agent.limitations.extend(unavailable);
        agent.baseline.as_mut().unwrap().managed = plan.managed;
        agent.paths.save(agent.baseline.as_ref().unwrap())?;

        if agent.provider.is_none() {
            agent.provider = Some(Provider::new(&agent.paths.runtime)?);
        }
        let process = agent.provider.as_mut().unwrap().apply(&plan.xsettings)?;
        if agent.provider_events.is_none() {
            let weak = Rc::downgrade(state);
            let wakeup = notify(weak.clone(), agent.queued.clone());
            let fd = agent.provider.as_ref().unwrap().descriptor();
            agent.provider_events = Some(glib::source::unix_fd_add_local(
                fd,
                glib::IOCondition::IN | glib::IOCondition::HUP | glib::IOCondition::ERR,
                move |_, condition| {
                    let Some(state) = weak.upgrade() else {
                        return glib::ControlFlow::Break;
                    };
                    let failed = condition
                        .intersects(glib::IOCondition::HUP | glib::IOCondition::ERR)
                        || state
                            .borrow()
                            .provider
                            .as_ref()
                            .is_none_or(|provider| provider.drain().is_err());
                    if failed {
                        let mut agent = state.borrow_mut();
                        agent.provider_events.take();
                        agent.provider = None;
                        agent.applied = None;
                    }
                    wakeup();
                    if failed {
                        glib::ControlFlow::Break
                    } else {
                        glib::ControlFlow::Continue
                    }
                },
            ));
        }

        agent.applied = agent.desired.clone();
        agent.ready = true;
        // Keep transport loss explicit even when local retries have converged.
        if agent.subscription.is_some() {
            agent.error = None;
        }
        remove(&mut agent.retry);
        remove(&mut agent.startup);
        agent.report();
        Ok(process)
    })();

    match result {
        Ok(Some(process)) => {
            let weak = Rc::downgrade(state);
            let finished = process.clone();
            process.wait_async(gio::Cancellable::NONE, move |_| {
                let Some(state) = weak.upgrade() else {
                    return;
                };
                let mut agent = state.borrow_mut();
                if agent
                    .provider
                    .as_ref()
                    .and_then(|provider| provider.process.as_ref())
                    != Some(&finished)
                {
                    return;
                }
                agent.provider.as_mut().unwrap().exited();
                agent.applied = None;
                agent.error = Some("XSettings provider exited; convergence pending".into());
                agent.report();
                drop(agent);
                retry(&state);
            });
        }
        Ok(None) => {}
        Err(error) => {
            let mut agent = state.borrow_mut();
            agent.applied = None;
            agent.error = Some(error.to_string());
            agent.report();
            drop(agent);
            retry(state);
        }
    }
}

/// Failed adapters retry on a deadline; normal operation uses notifications only.
fn retry(state: &Rc<RefCell<Agent>>) {
    if state.borrow().retry.is_none() {
        let timer = later(state, 2, |state| {
            state.borrow_mut().retry.take();
            if state.borrow().config.is_none() {
                reload(&state);
            } else {
                reconcile(&state);
            }
        });
        state.borrow_mut().retry = Some(timer);
    }
}

/// Own one graphical-session agent and restore state on graceful stop or configuration revocation.
pub(super) fn run(config_path: &Path, paths: Paths) -> Result<()> {
    paths.clear_status()?;
    let settings = Settings::new()?;
    let assets = Assets::discover().unwrap_or_else(|error| {
        eprintln!("desktop preferences assets: {error}");
        Assets::empty()
    });
    let state = Rc::new(RefCell::new(Agent {
        config_path: config_path.to_owned(),
        config: None,
        paths,
        settings,
        baseline: None,
        assets,
        desired: None,
        applied: None,
        provider: None,
        provider_events: None,
        subscription: None,
        generation: 0,
        backoff: 1,
        reconnect: None,
        first_frame: None,
        expiry: None,
        retry: None,
        startup: None,
        ready: false,
        limitations: Vec::new(),
        error: None,
        queued: Rc::new(Cell::new(false)),
    }));
    let wakeup = notify(Rc::downgrade(&state), state.borrow().queued.clone());
    state.borrow().settings.observe(wakeup);

    let file = gio::File::for_path(config_path.parent().context("configuration parent")?);
    let monitor = file.monitor_directory(gio::FileMonitorFlags::NONE, gio::Cancellable::NONE)?;
    let weak = Rc::downgrade(&state);
    monitor.connect_changed(move |_, file, other, _| {
        if let Some(state) = weak.upgrade() {
            let path = state.borrow().config_path.clone();
            if (file.path().as_ref() == Some(&path)
                || other.and_then(|file| file.path()).as_ref() == Some(&path))
                && Config::read(&path).ok() != state.borrow().config
            {
                reload(&state);
            }
        }
    });
    let running = glib::MainLoop::new(None, false);
    let mut signals = Vec::new();
    for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        let running = running.clone();
        signals.push(glib::source::unix_signal_add_local(signal, move || {
            running.quit();
            glib::ControlFlow::Continue
        }));
    }

    reload(&state);
    running.run();

    monitor.cancel();
    for signal in signals {
        signal.remove();
    }
    let mut agent = state.borrow_mut();
    agent.disconnect();
    remove(&mut agent.reconnect);
    remove(&mut agent.expiry);
    remove(&mut agent.retry);
    remove(&mut agent.startup);
    // Revoke readiness even when restoring a damaged/unwritable backend fails.
    let cleared = agent.paths.clear_status();
    let restored = agent.restore();
    cleared.and(restored)
}
