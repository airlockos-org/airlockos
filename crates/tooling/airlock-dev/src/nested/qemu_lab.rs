//! Persistent QEMU lab desktops reuse the nested image builder and QEMU command.
//! Only QEMU lifecycle and observation live here; guest behavior stays in Airlock services.

mod qmp;

use super::*;
use clap::Args as ClapArgs;
use rustix::fs::{FlockOperation, flock};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    net::TcpListener,
    os::unix::{fs::FileTypeExt, process::CommandExt},
};

/// Workstation operations on one named QEMU lab desktop.
#[derive(ClapArgs)]
pub(crate) struct Args {
    /// Instance identity within this worktree; each instance owns its disk and monitor.
    #[arg(long, default_value = "default", global = true)]
    instance: String,
    /// Requested lifecycle operation; guest deployment uses the normal Airlock workflow.
    #[command(subcommand)]
    command: Action,
}

/// Explicit operations never run as an installation or build side effect.
#[derive(Subcommand)]
enum Action {
    /// Build the selected image, or resume the existing instance without rebuilding it.
    Start {
        /// Reuse the instance's previously selected image without evaluating or building it.
        #[arg(long)]
        reuse: bool,
        /// Keep the display hidden while retaining SSH, monitor and serial observation.
        #[arg(long)]
        headless: bool,
        /// Loopback SSH port; concurrent instances must choose different ports.
        #[arg(long, default_value_t = 2342)]
        ssh_port: u16,
        /// Outer guest memory in MiB, including dom0 and all nested VMs.
        #[arg(long, default_value_t = 32768)]
        memory: u32,
        /// Outer virtual CPU allocation.
        #[arg(long, default_value_t = 8)]
        cpus: u16,
    },
    /// Report QEMU state and the image/source selected for this instance as JSON.
    Status,
    /// Request a guest shutdown and wait for QEMU to exit.
    Stop {
        /// Quit QEMU immediately, discarding any unflushed guest writes.
        #[arg(long)]
        force: bool,
    },
    /// Discard a stopped instance's writable disk and firmware; retain its logs and image.
    Reset,
    /// Connect to this instance's recorded loopback SSH endpoint.
    Ssh {
        /// Guest command or SSH arguments forwarded without local shell interpretation.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        arguments: Vec<OsString>,
    },
}

/// One instance's owned state and logs, isolated from other worktrees and nested tests.
struct Instance {
    /// Existing native helpers bound to the caller's application source.
    context: Context,
    /// Persistent overlay, firmware, monitor and launch receipt directory.
    directory: PathBuf,
    /// QEMU name checked before issuing any monitor command.
    name: String,
}

const IMAGE: &str = "airlock-qemu-lab-image";

impl Instance {
    /// Validate a simple identity and derive a stable directory from the canonical worktree path.
    fn new(root: &Path, instance: &str) -> Result<Self> {
        ensure!(
            valid_name(instance),
            "instance must be 1–24 ASCII letters, digits, underscores or hyphens"
        );
        let root = fs::canonicalize(root)?;
        let digest = Sha256::digest(root.as_os_str().as_encoded_bytes());
        let key = format!("{digest:x}");
        let key = &key[..12];
        let data = path("AIRLOCK_DATA_ROOT", root.join(".airlock"));
        let directory = data.join("qemu-lab").join(key).join(instance);
        ensure!(
            directory
                .join("qmp.sock")
                .as_os_str()
                .as_encoded_bytes()
                .len()
                < 108,
            "QEMU lab path is too long for a Unix socket; select a shorter AIRLOCK_DATA_ROOT"
        );
        ensure!(
            !directory.to_string_lossy().contains(','),
            "QEMU lab path cannot contain a comma"
        );
        fs::create_dir_all(&directory)?;
        let logs = root.join(".airlock-logs/qemu-lab").join(instance);
        fs::create_dir_all(&logs)?;
        Ok(Self {
            context: Context { root, logs },
            directory,
            name: format!("airlock-qemu-lab-{key}-{instance}"),
        })
    }

    /// Read the durable launch description without inventing defaults for an existing instance.
    fn record(&self) -> Result<Value> {
        support::json(&self.directory.join("instance.json"))
    }

    /// Reuse the existing runner with an explicit image and instance-owned state.
    fn runner(&self, record: &Value) -> Result<Command> {
        let mut command = self.context.native(&["nested", "run"])?;
        command.envs([
            ("AIRLOCK_VM_IMAGE_ATTR", IMAGE.to_owned()),
            ("AIRLOCK_VM_DIR", self.directory.display().to_string()),
            (
                "AIRLOCK_RESULT_LINK_DIR",
                self.directory.join("result-links").display().to_string(),
            ),
            (
                "AIRLOCK_VM_BACKING_IMAGE",
                record["backing_image"]
                    .as_str()
                    .context("backing image")?
                    .to_owned(),
            ),
            ("AIRLOCK_VM_SKIP_BASE_BUILD", "1".into()),
            ("AIRLOCK_VM_FRESH", "0".into()),
            ("AIRLOCK_VM_MANAGED", "1".into()),
            ("AIRLOCK_VM_NAME", self.name.clone()),
            (
                "AIRLOCK_VM_DISPLAY",
                record["display"].as_str().context("display")?.to_owned(),
            ),
            ("AIRLOCK_VM_SSH_PORT", record["ssh_port"].to_string()),
            ("AIRLOCK_VM_MEMORY", record["memory_mib"].to_string()),
            ("AIRLOCK_VM_SMP", record["cpus"].to_string()),
            ("AIRLOCK_VM_SYSNET_NIC", "1".into()),
            ("AIRLOCK_VM_IOMMU", "1".into()),
            ("AIRLOCK_LOG_DIR", self.context.logs.display().to_string()),
        ]);
        Ok(command)
    }

    /// Connect only to the expected QEMU process; an absent socket means the instance is stopped.
    fn monitor(&self) -> Result<Option<qmp::Monitor>> {
        qmp::Monitor::connect(&self.directory.join("qmp.sock"), &self.name)
    }

    /// Remove only an abandoned Unix socket after verifying QEMU is unavailable.
    fn clear_monitor(&self) -> Result<()> {
        let socket = self.directory.join("qmp.sock");
        match fs::symlink_metadata(&socket) {
            Ok(metadata) => {
                ensure!(
                    metadata.file_type().is_socket(),
                    "refusing to remove a non-socket QMP path"
                );
                fs::remove_file(socket)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    /// Report QEMU's own execution state alongside the pinned disk source.
    fn status(&self) -> Result<Value> {
        let mut record = match self.record() {
            Ok(record) => record,
            Err(error) if !self.directory.join("instance.json").exists() => {
                let _ = error;
                json!({"schema":"airlock.qemu-lab.v1"})
            }
            Err(error) => return Err(error),
        };
        record["directory"] = json!(self.directory);
        record["logs"] = json!(self.context.logs);
        record["qemu"] = match self.monitor()? {
            Some(mut monitor) => monitor.command("query-status")?,
            None => json!({"status":"stopped","running":false}),
        };
        Ok(record)
    }

    /// Freeze a selected source image before launching, preserving an existing disk's backing image.
    fn start(&self, reuse: bool, headless: bool, port: u16, memory: u32, cpus: u16) -> Result<()> {
        ensure!(self.monitor()?.is_none(), "instance is already running");
        ensure!(
            port > 0 && memory >= 32768 && cpus > 0,
            "lab requires a nonzero port/CPU count and at least 32768 MiB"
        );
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
            .context("SSH port is already in use; choose --ssh-port")?;
        self.clear_monitor()?;
        let overlay = self.directory.join(format!("{IMAGE}.qcow2"));
        let existing = self.record().ok();
        let mut record = if reuse {
            existing.context("no image is recorded; start once without --reuse")?
        } else {
            let source = airlock_nix_core::runtime::protocol::identity(&self.context.root)?;
            crate::repository::check_image_source(&self.context.root)?;
            let (machine, machine_revision) = crate::repository::local(&self.context.root)?;
            let seed = self.directory.join("machine-source.tar.gz");
            crate::source::seed(&machine, &seed, true)?;
            let archive_log = self.context.logs.join("input-archive.log");
            let archive = self
                .context
                .nix(&[
                    "flake",
                    "archive",
                    "--no-update-lock-file",
                    "--json",
                    &format!(
                        "path:{root}/airlock-machine",
                        root = self.context.root.display()
                    ),
                ])?
                .stderr(File::create(&archive_log)?)
                .output()?;
            ensure!(
                archive.status.success(),
                "input archiving failed ({status}); see {log}",
                status = archive.status,
                log = archive_log.display()
            );
            let offline = self.directory.join("offline-inputs.json");
            crate::source::offline_archive(&machine, &offline, &archive.stdout)?;
            let candidate_root = self.directory.join("result-links/candidate-image");
            fs::create_dir_all(candidate_root.parent().context("image root directory")?)?;
            let mut build = self.context.nix(&[
                "build",
                &format!("{root}#{IMAGE}", root = self.context.root.display()),
                "--impure",
                "--out-link",
                candidate_root.to_str().context("image root path")?,
                "--print-out-paths",
                "--print-build-logs",
            ])?;
            build
                .env("AIRLOCK_MACHINE_SEED_ARCHIVE", seed)
                .env("AIRLOCK_MACHINE_OFFLINE_INPUTS", offline);
            let log = self.context.logs.join("image-build.log");
            let result = build.stderr(File::create(&log)?).output()?;
            ensure!(
                result.status.success(),
                "image build failed ({status}); see {log}",
                status = result.status,
                log = log.display()
            );
            ensure!(
                airlock_nix_core::runtime::protocol::identity(&self.context.root)? == source,
                "source changed during image build; retry from a stable commit"
            );
            let output = String::from_utf8(result.stdout)?;
            let output = PathBuf::from(output.lines().last().context("image output")?);
            let logical = output.clone();
            let selected = super::run::disk(&environment::physical(&output))?;
            let backing = logical.join(selected.file_name().context("image filename")?);
            if overlay.exists() {
                ensure!(
                    existing
                        .as_ref()
                        .is_some_and(|old| old["backing_image"] == json!(backing)),
                    "image changed; stop and reset this instance, or use --reuse to keep its disk"
                );
            }
            json!({
                "schema":"airlock.qemu-lab.v1",
                "image":IMAGE,
                "image_output":output,
                "backing_image":backing,
                "source_revision":source.revision,
                "source_lock_hash":source.lock_hash,
                "source_dirty":false,
                "machine_revision":machine_revision,
            })
        };
        record["display"] = json!(if headless { "none" } else { "gtk" });
        record["ssh_port"] = json!(port);
        record["memory_mib"] = json!(memory);
        record["cpus"] = json!(cpus);
        let output = Path::new(record["image_output"].as_str().context("image output")?);
        let image_root = self.directory.join(format!("{IMAGE}-result"));
        support::output(&mut self.context.nix(&[
            "build",
            output.to_str().context("image output path")?,
            "--out-link",
            image_root.to_str().context("image root path")?,
        ])?)?;
        support::record(&self.directory.join("instance.json"), &record)?;
        let log = File::create(self.context.logs.join("qemu.log"))?;
        let mut command = self.runner(&record)?;
        command
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .process_group(0);
        drop(listener);
        let mut child = command.spawn()?;
        let deadline = Instant::now() + Duration::from_secs(180);
        loop {
            if self.monitor()?.is_some() {
                println!(
                    "{status}",
                    status = serde_json::to_string_pretty(&self.status()?)?
                );
                return Ok(());
            }
            if let Some(status) = child.try_wait()? {
                anyhow::bail!(
                    "QEMU launcher exited ({status}); see {log}",
                    log = self.context.logs.join("qemu.log").display()
                );
            }
            if Instant::now() >= deadline {
                if let Some(pid) = rustix::process::Pid::from_raw(i32::try_from(child.id())?) {
                    let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
                }
                let _ = child.wait();
                anyhow::bail!("QEMU did not expose its monitor within 180 seconds; see qemu.log");
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// Shut down through ACPI, or explicitly quit QEMU when the caller accepts abrupt termination.
    fn stop(&self, force: bool) -> Result<()> {
        let Some(mut monitor) = self.monitor()? else {
            return Ok(());
        };
        monitor.command(if force { "quit" } else { "system_powerdown" })?;
        drop(monitor);
        let deadline = Instant::now() + Duration::from_secs(90);
        while self.monitor()?.is_some() {
            ensure!(
                Instant::now() < deadline,
                "guest is still shutting down; inspect status or explicitly use stop --force"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
        self.clear_monitor()
    }

    /// Reset only generated writable state while the owned QEMU monitor is unavailable.
    fn reset(&self) -> Result<()> {
        ensure!(
            self.monitor()?.is_none(),
            "stop the instance before resetting its disk"
        );
        for suffix in [".qcow2", "-OVMF_VARS.fd"] {
            super::run::remove(&self.directory.join(format!("{IMAGE}{suffix}")))?;
        }
        self.clear_monitor()
    }
}

/// Restrict identities to one short directory component without traversal or QEMU separators.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 24
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
}

/// Serialize operations per instance and reuse the existing SSH adapter for guest commands.
pub(crate) fn execute(root: &Path, args: Args) -> Result<u8> {
    let instance = Instance::new(root, &args.instance)?;
    let lock = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(instance.directory.join("operation.lock"))?;
    if matches!(&args.command, Action::Status) {
        let busy = match flock(&lock, FlockOperation::NonBlockingLockShared) {
            Ok(()) => false,
            Err(rustix::io::Errno::WOULDBLOCK) => true,
            Err(error) => return Err(error.into()),
        };
        let mut status = instance.status()?;
        status["operation_active"] = json!(busy);
        println!("{status}", status = serde_json::to_string_pretty(&status)?);
        return Ok(0);
    }
    flock(&lock, FlockOperation::NonBlockingLockExclusive)
        .context("another lab operation is running")?;
    match args.command {
        Action::Start {
            reuse,
            headless,
            ssh_port,
            memory,
            cpus,
        } => instance.start(reuse, headless, ssh_port, memory, cpus)?,
        Action::Status => println!(
            "{status}",
            status = serde_json::to_string_pretty(&instance.status()?)?
        ),
        Action::Stop { force } => instance.stop(force)?,
        Action::Reset => instance.reset()?,
        Action::Ssh { arguments } => {
            ensure!(instance.monitor()?.is_some(), "instance is stopped");
            let record = instance.record()?;
            let mut command = instance.context.native(&["nested", "ssh"])?;
            command
                .env("AIRLOCK_VM_SSH_PORT", record["ssh_port"].to_string())
                .args(arguments);
            drop(lock);
            return Ok(command.status()?.code().unwrap_or(1).try_into()?);
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::valid_name;

    /// Instance names cannot escape their directory or inject QEMU option separators.
    #[test]
    fn instance_names_are_single_components() {
        assert!(valid_name("desktop_2"));
        for invalid in [
            "",
            ".",
            "..",
            "../desktop",
            "desktop/2",
            "desk,top",
            "desktop\n",
            "abcdefghijklmnopqrstuvwxyz",
        ] {
            assert!(!valid_name(invalid), "accepted {invalid:?}");
        }
    }
}
