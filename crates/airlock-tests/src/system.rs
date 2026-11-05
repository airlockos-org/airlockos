//! Explicit system-test jobs retain unbounded build logs on disk and own process-group cancellation.

use anyhow::{Result, ensure};
use serde_json::json;
use std::{
    fs::{self, File},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

/// Own a long-running test process until it exits or its entire group is cancelled.
pub struct Job {
    // Leader remains unreaped until cancellation or explicit completion.
    child: Child,
}

impl Job {
    /// Start one explicit job with independent on-disk output streams; no build output is buffered in memory.
    pub fn spawn(command: &mut Command, logs: &Path) -> Result<Self> {
        Self::spawn_input(command, logs, Stdio::null())
    }

    /// Supply an explicit fixture input stream, retaining the same bounded wait and cancellation ownership.
    pub fn spawn_input(command: &mut Command, logs: &Path, input: Stdio) -> Result<Self> {
        fs::create_dir_all(logs)?;
        fs::write(logs.join("command.txt"), format!("{command:?}\n"))?;
        let child = command
            .stdin(input)
            .stdout(File::create(logs.join("stdout.log"))?)
            .stderr(File::create(logs.join("stderr.log"))?)
            .process_group(0)
            .spawn()?;
        Ok(Self { child })
    }

    /// Take a piped input stream while retaining ownership and cancellation of the process group.
    pub fn take_stdin(&mut self) -> Option<std::process::ChildStdin> {
        self.child.stdin.take()
    }

    /// Observe liveness while retaining cancellation ownership.
    pub fn running(&mut self) -> Result<bool> {
        Ok(self.child.try_wait()?.is_none())
    }

    /// Wait under a finite deadline; cancellation remains guaranteed on error or panic.
    pub fn wait(&mut self, timeout: Duration) -> Result<ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Ok(status);
            }
            ensure!(Instant::now() < deadline, "system test job timed out");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = rustix::process::kill_process_group(
                rustix::process::Pid::from_child(&self.child),
                rustix::process::Signal::KILL,
            );
            let _ = self.child.wait();
        }
    }
}

/// Resolve the explicitly selected evidence directory without changing deployed state.
pub fn logs(name: &str) -> Result<PathBuf> {
    let base = airlock_dev_paths::path("AIRLOCK_LOG_DIR", "logs")?;
    let path = base.join(name);
    fs::create_dir_all(&path)?;
    Ok(path)
}

/// Execute a selected long-running check and retain its command, exit status and complete output streams.
pub fn run(command: &mut Command, logs: &Path, timeout: Duration) -> Result<()> {
    println!("system test evidence: {path}", path = logs.display());
    let mut job = Job::spawn(command, logs)?;
    let result = job.wait(timeout);
    let report = match &result {
        Ok(status) => json!({"success": status.success(), "exit_code": status.code()}),
        Err(error) => json!({"success": false, "error": error.to_string()}),
    };
    fs::write(
        logs.join("result.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    ensure!(
        result?.success(),
        "system test failed; inspect {path}",
        path = logs.display()
    );
    Ok(())
}

/// Report optional host capabilities without installing tools, probing Qubes control APIs or changing system state.
pub fn capabilities() -> serde_json::Value {
    use std::os::unix::fs::PermissionsExt;

    let tool = |name: &str| -> Option<PathBuf> {
        std::env::split_paths(&std::env::var_os("PATH")?)
            .map(|path| path.join(name))
            .find(|path| {
                path.metadata().is_ok_and(|metadata| {
                    metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
                })
            })
    };
    let output = |name: &str, args: &[&str]| -> String {
        let Some(path) = tool(name) else {
            return String::new();
        };
        airlock_vm_service::support::run(
            Command::new(path).args(args),
            None,
            Duration::from_secs(2),
        )
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_default()
    };
    let read = |name: &str| {
        fs::read_to_string(name)
            .unwrap_or_default()
            .trim()
            .to_owned()
    };
    let cpu = read("/proc/cpuinfo");
    let flags = cpu
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            ["flags", "Features"]
                .contains(&name.trim())
                .then_some(value)
        })
        .unwrap_or("")
        .split_whitespace()
        .collect::<std::collections::BTreeSet<_>>();
    let xen = read("/proc/xen/capabilities");
    let nested = [
        "/sys/module/kvm_intel/parameters/nested",
        "/sys/module/kvm_amd/parameters/nested",
    ]
    .into_iter()
    .find_map(|path| fs::read_to_string(path).ok())
    .unwrap_or_default();
    json!({"schema": "airlock.host-capabilities.v1", "host": {"kernel": read("/proc/sys/kernel/osrelease"), "architecture": std::env::consts::ARCH, "virtualization": output("systemd-detect-virt", &[])},
        "nix": {"available": tool("nix").is_some(), "version": output("nix", &["--version"])},
        "xen": {"proc_xen": Path::new("/proc/xen").exists(), "control_domain": xen.split_whitespace().any(|word| word == "control_d"), "capabilities": xen},
        "hardware_virtualization": {"vmx": flags.contains("vmx"), "svm": flags.contains("svm"), "ept": flags.contains("ept"), "npt": flags.contains("npt"),
            "iommu_groups": fs::read_dir("/sys/kernel/iommu_groups").is_ok_and(|mut entries| entries.next().is_some()), "kvm_nested": nested.trim()},
        "qubes_tools": {"qvm_run": tool("qvm-run").is_some(), "qvm_create": tool("qvm-create").is_some(), "qubes_prefs": tool("qubes-prefs").is_some()}})
}
