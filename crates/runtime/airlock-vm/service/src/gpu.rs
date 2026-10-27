//! Read-only GPU observation reports API enumeration without claiming rendering or isolation.
//! Hardware recovery and PCI ownership changes belong to the VM that owns those operations.

use anyhow::{Result, ensure};
use serde::Serialize;
use serde_json::json;
use std::{
    collections::BTreeSet,
    fs,
    io::{self, Read},
    os::fd::AsFd,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

/// Bounded diagnostic outcome; missing tools and timeouts remain visible in the report.
#[derive(Serialize)]
pub struct Observation {
    /// Executable and arguments actually passed, without shell interpretation.
    pub command: Vec<String>,
    /// Exit code only after the helper returned with complete, bounded output.
    pub returncode: Option<i32>,
    /// Standard output truncated at one MiB and decoded with replacement characters.
    pub stdout: String,
    /// Standard error with the same independent bound.
    pub stderr: String,
    /// Spawn, capture-limit or timeout failure, rather than an invented exit status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// True when execution exceeded its deadline; kernel work may still be pending.
    pub timeout: bool,
    /// Child identity for diagnosing a helper that did not finish within its deadline.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
}

struct Helper {
    // Unreaped leader keeps its process-group identity safe to cancel.
    child: Child,
    // Reaped children must never be signalled by a potentially reused PID.
    reaped: bool,
}

impl Helper {
    fn exited(&self) -> io::Result<bool> {
        match rustix::process::waitid(
            rustix::process::WaitId::Pid(rustix::process::Pid::from_child(&self.child)),
            rustix::process::WaitIdOptions::EXITED
                | rustix::process::WaitIdOptions::NOHANG
                | rustix::process::WaitIdOptions::NOWAIT,
        ) {
            Ok(status) => Ok(status.is_some()),
            Err(rustix::io::Errno::INTR) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    fn status(&mut self) -> io::Result<Option<ExitStatus>> {
        let status = self.child.try_wait()?;
        if status.is_some() {
            self.reaped = true;
        }
        Ok(status)
    }

    fn cancel(&mut self) {
        if !self.reaped {
            let _ = rustix::process::kill_process_group(
                rustix::process::Pid::from_child(&self.child),
                rustix::process::Signal::KILL,
            );
            let _ = self.child.kill();
        }
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        self.cancel();
        // Error paths also cancel, without introducing a blocking destructor.
        if !self.reaped {
            let _ = self.status();
        }
    }
}

struct Capture<T> {
    // Nonblocking pipe, closed after EOF or when the cleanup deadline expires.
    pipe: Option<T>,
    // At most one MiB of output; pipes provide backpressure without filling a disk.
    bytes: Vec<u8>,
}

impl<T: Read + AsFd> Capture<T> {
    fn new(pipe: T) -> io::Result<Self> {
        let flags = rustix::fs::fcntl_getfl(&pipe)?;
        rustix::fs::fcntl_setfl(&pipe, flags | rustix::fs::OFlags::NONBLOCK)?;
        Ok(Self {
            pipe: Some(pipe),
            bytes: Vec::new(),
        })
    }

    fn read_ready(&mut self) -> io::Result<bool> {
        let Some(pipe) = &mut self.pipe else {
            return Ok(false);
        };
        let mut buffer = [0u8; 65536];
        match pipe.read(&mut buffer) {
            Ok(0) => self.pipe = None,
            Ok(size) => {
                let remaining = (1024 * 1024) - self.bytes.len();
                self.bytes.extend_from_slice(&buffer[..size.min(remaining)]);
                return Ok(size > remaining);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(error),
        }
        Ok(false)
    }
}

/// Run an observational helper with bounded capture and no blocking wait after timeout.
/// A killed task stuck in a kernel driver may outlive this caller; callers must not
/// interpret the timeout as permission to retry a hardware mutation. Oversized or
/// incomplete output never reports a successful exit code. Exited leaders retain
/// their process-group identity until their remaining helpers have been cancelled.
pub fn observe(command: &mut Command, timeout: Duration) -> Result<Observation> {
    let argv = std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(|s| s.to_string_lossy().into_owned())
        .collect();
    let mut result = Observation {
        command: argv,
        returncode: None,
        stdout: String::new(),
        stderr: String::new(),
        error: None,
        timeout: false,
        pid: None,
    };
    let child = command
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn();
    let child = match child {
        Ok(child) => child,
        Err(error) => {
            result.error = Some(error.to_string());
            return Ok(result);
        }
    };
    let mut child = Helper {
        child,
        reaped: false,
    };
    let mut out = Capture::new(child.child.stdout.take().expect("piped stdout"))?;
    let mut err = Capture::new(child.child.stderr.take().expect("piped stderr"))?;
    let deadline = Instant::now() + timeout;
    loop {
        let oversized = out.read_ready()? | err.read_ready()?;
        if oversized {
            result.error = Some("helper exceeded capture limit".into());
            break;
        }
        if child.exited()? {
            break;
        }
        if Instant::now() >= deadline {
            result.timeout = true;
            result.error = Some("helper timed out; kernel work may still be running".into());
            break;
        }

        let mut fds = Vec::new();
        if let Some(pipe) = &out.pipe {
            fds.push(rustix::event::PollFd::new(
                pipe,
                rustix::event::PollFlags::IN,
            ));
        }
        if let Some(pipe) = &err.pipe {
            fds.push(rustix::event::PollFd::new(
                pipe,
                rustix::event::PollFlags::IN,
            ));
        }
        match rustix::event::poll(
            &mut fds,
            Some(&rustix::event::Timespec::try_from(Duration::from_millis(
                20,
            ))?),
        ) {
            Ok(_) | Err(rustix::io::Errno::INTR) => {}
            Err(error) => return Err(error.into()),
        }
    }

    // Cancel before releasing the leader PID, even after a normal exit. A
    // diagnostic tool may have left a child holding either output pipe open.
    child.cancel();
    let cleanup = Instant::now() + Duration::from_millis(100);
    let mut status = None;
    loop {
        if out.read_ready()? | err.read_ready()? {
            result.error = Some("helper exceeded capture limit".into());
        }
        if !child.reaped {
            status = child.status()?;
        }
        if child.reaped && out.pipe.is_none() && err.pipe.is_none() {
            break;
        }
        if Instant::now() >= cleanup {
            result.error.get_or_insert_with(|| {
                "helper cleanup incomplete; kernel work may still be running".into()
            });
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    if result.error.is_none() {
        result.returncode = status.and_then(|s| s.code());
        if result.returncode.is_none() {
            result.error = Some(format!(
                "helper terminated without an exit code: {status:?}"
            ));
        }
    } else {
        result.pid = Some(child.child.id());
    }
    result.stdout = String::from_utf8_lossy(&out.bytes).into_owned();
    result.stderr = String::from_utf8_lossy(&err.bytes).into_owned();
    Ok(result)
}

fn read(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().into())
}

/// Print local display inventory and API results, optionally requiring a hardware Vulkan device.
/// Enumeration alone never marks rendering, cross-VM graphics or exclusive ownership verified.
pub fn inspect(require_hardware: bool) -> Result<()> {
    let pci = std::env::var_os("AIRLOCK_GPU_PCI")
        .map(PathBuf::from)
        .unwrap_or_else(|| "/sys/bus/pci/devices".into());
    let drm = std::env::var_os("AIRLOCK_GPU_DRM")
        .map(PathBuf::from)
        .unwrap_or_else(|| "/dev/dri".into());
    let mut devices = Vec::new();
    if let Ok(entries) = fs::read_dir(pci) {
        let mut paths = entries
            .map(|p| p.map(|p| p.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        paths.sort();
        for path in paths {
            let class = read(&path.join("class"));
            if !class.as_deref().is_some_and(|s| s.starts_with("0x03")) {
                continue;
            }
            devices.push(json!({"address":path.file_name().and_then(|s|s.to_str()),"vendor":read(&path.join("vendor")),"device":read(&path.join("device")),"class":class,"driver":fs::read_link(path.join("driver")).ok().and_then(|p|p.file_name().map(|s|s.to_string_lossy().into_owned()))}));
        }
    }
    let mut nodes = Vec::new();
    if let Ok(entries) = fs::read_dir(drm) {
        for entry in entries {
            nodes.push(entry?.path());
        }
    }
    nodes.sort();

    let mut vulkan = Command::new(crate::support::tool("AIRLOCK_VULKANINFO", "vulkaninfo"));
    let vulkan = observe(vulkan.arg("--summary"), Duration::from_secs(30))?;
    let mut types = BTreeSet::new();
    if vulkan.returncode == Some(0) {
        for line in vulkan.stdout.lines() {
            if let Some((key, value)) = line.split_once('=')
                && key.trim() == "deviceType"
                && let Some(value) = value.trim().strip_prefix("PHYSICAL_DEVICE_TYPE_")
                && !value.is_empty()
                && value.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
            {
                types.insert(value.to_owned());
            }
        }
    }
    let initialized = types.contains("INTEGRATED_GPU") || types.contains("DISCRETE_GPU");
    let mut egl = Command::new(crate::support::tool("AIRLOCK_EGLINFO", "eglinfo"));
    let egl = observe(
        egl.args(["-B", "-p", "surfaceless"]),
        Duration::from_secs(30),
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"schema":"airlock.gpu-probe.v1","hostname":read(Path::new("/proc/sys/kernel/hostname")),"kernel":read(Path::new("/proc/sys/kernel/osrelease")),"pci_display_devices":devices,"drm_nodes":nodes,"vulkan_device_types":types,"hardware_api_initialized":initialized,"rendering_verified":false,"exclusive_ownership_verified":false,"cross_vm_graphics_verified":false,"probes":{"vulkan":vulkan,"egl":egl}})
        )?
    );
    ensure!(
        !require_hardware || initialized,
        "no hardware Vulkan device initialized"
    );
    Ok(())
}
