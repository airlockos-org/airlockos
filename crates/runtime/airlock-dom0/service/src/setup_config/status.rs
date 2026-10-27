//! Best-effort boot-console progress; this renderer never performs setup operations.

use std::{
    fs,
    path::PathBuf,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

/// One owned renderer; dropping it stops periodic writes before desktop handover.
pub(super) struct Display {
    /// Optional worker shutdown sender; absence means console rendering is disabled.
    stop: Option<mpsc::Sender<()>>,
    /// Worker joined before a new message replaces it or the invocation exits.
    worker: Option<thread::JoinHandle<()>>,
    /// Optional console chosen by the boot unit; deferred setup never opens it.
    device: Option<PathBuf>,
    /// Detailed log path shown for diagnosis after a setup failure.
    log: PathBuf,
    /// Monotonic start time shared across all displayed stages.
    started: Instant,
}

impl Display {
    /// Keep progress disabled unless a console is explicitly configured for this scope.
    pub fn new(scope: &str, log: PathBuf) -> Self {
        Self {
            stop: None,
            worker: None,
            device: (scope != "deferred")
                .then(|| {
                    std::env::var_os("AIRLOCK_SETUP_CONFIG_STATUS_DEVICE")
                        .filter(|path| !path.is_empty())
                        .map(PathBuf::from)
                })
                .flatten(),
            log,
            started: Instant::now(),
        }
    }

    /// Stop and join the previous renderer so stale messages cannot overwrite the next stage.
    fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }

    /// Refresh the selected stage once a second while setup work is in progress.
    pub fn show(&mut self, phase: usize, title: &str, detail: &str) {
        self.stop();
        let Some(device) = self.device.clone() else {
            return;
        };
        let title = title.to_owned();
        let detail = detail.to_owned();
        let log = self.log.clone();
        let started = self.started;
        let (send, receive) = mpsc::channel();
        self.stop = Some(send);
        self.worker = Some(thread::spawn(move || {
            loop {
                render(
                    &device,
                    &log,
                    started.elapsed(),
                    phase,
                    &title,
                    &detail,
                    "working",
                );
                if receive.recv_timeout(Duration::from_secs(1))
                    != Err(mpsc::RecvTimeoutError::Timeout)
                {
                    break;
                }
            }
        }));
    }

    /// Leave an actionable failure message rather than a stale working indicator.
    pub fn failed(&mut self, reason: &str) {
        self.stop();
        if let Some(device) = &self.device {
            render(
                device,
                &self.log,
                self.started.elapsed(),
                4,
                "Setup stopped",
                reason,
                "failed",
            );
        }
    }

    /// Finish the configuration stage without claiming VM health checks have passed.
    pub fn complete(&mut self) {
        self.stop();
        if let Some(device) = &self.device {
            render(
                device,
                &self.log,
                self.started.elapsed(),
                5,
                "Topology configured; verifying required VMs next",
                "Startup VM configuration is ready; required hardware and VM checks still need to finish.",
                "configured",
            );
        }
    }
}

impl Drop for Display {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Render the fixed startup steps, keeping all console errors informational.
fn render(
    device: &std::path::Path,
    log: &std::path::Path,
    elapsed: Duration,
    phase: usize,
    title: &str,
    detail: &str,
    state: &str,
) {
    use std::io::Write;
    let mut output = String::from("\x1b[H\x1b[K\n\x1b[K  Airlock | Startup\n\x1b[K\n");
    for (index, name) in [
        "Check system and VM configuration",
        "Prepare system images",
        "Prepare startup VMs",
        "Save topology before VM health checks",
    ]
    .iter()
    .enumerate()
    {
        let marker = if index + 1 < phase {
            "[done]"
        } else if index + 1 == phase {
            if state == "failed" {
                "[failed]"
            } else {
                "[working]"
            }
        } else {
            "[ ]"
        };
        output.push_str(&format!("\x1b[K  {marker:<9} {name}\n"));
    }
    output.push_str(&format!("\x1b[K\n\x1b[K  Elapsed: {minutes}m {seconds:02}s\n\x1b[K\n\x1b[K  {title}\n\x1b[K  {detail}\n", minutes = elapsed.as_secs() / 60, seconds = elapsed.as_secs() % 60));
    if state == "failed" {
        output.push_str("\x1b[K  Startup configuration could not finish. Switch to a console with Ctrl+Alt+F2.\n\x1b[K  Log in and inspect: sudo journalctl -b -u airlock-setup-config\n");
    }
    output.push_str(&format!(
        "\x1b[K\n\x1b[K  Startup configuration log: {log}\n\x1b[J",
        log = log.display()
    ));
    if let Ok(mut file) = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(device)
    {
        let _ = file.write_all(output.as_bytes());
    }
}
