//! Own each sender through cancellation and reaping without blocking unrelated hotplug work.

use super::model::Node;
use airlock_nix_core::identity::GuestName;
use rustix::process::{Pid, Signal, WaitId, WaitIdOptions};
use std::{
    collections::BTreeMap,
    io,
    os::unix::process::CommandExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

struct Sender {
    // Unreaped transport leader; cleared only after process-group cancellation and wait.
    child: Option<Child>,
}

impl Sender {
    fn exited(&self) -> io::Result<bool> {
        let Some(child) = &self.child else {
            return Ok(true);
        };

        match rustix::process::waitid(
            WaitId::Pid(Pid::from_child(child)),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        ) {
            Ok(status) => Ok(status.is_some()),
            Err(rustix::io::Errno::INTR) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    fn cancel(&self) {
        if let Some(child) = &self.child {
            let _ = rustix::process::kill_process_group(Pid::from_child(child), Signal::KILL);
            let _ = rustix::process::kill_process(Pid::from_child(child), Signal::KILL);
        }
    }

    fn finish(&mut self) -> io::Result<bool> {
        if !self.exited()? {
            return Ok(false);
        }

        // The leader remains ours until wait: cancellation can never target a
        // reused group ID, even when a failed transport left its sender alive.
        self.cancel();
        if let Some(child) = &mut self.child {
            child.wait()?;
        }
        self.child = None;
        Ok(true)
    }
}

impl Drop for Sender {
    fn drop(&mut self) {
        self.cancel();
        // A blocked kernel task must not stall another device's remove event.
        let _ = self.finish();
    }
}

/// A node is retried only after removal and replug; cancellation retains ownership until exit.
enum Device {
    Forwarding(Sender),
    Failed,
    Stopping {
        // Cancelled transport whose PID cannot yet be released or replaced.
        sender: Sender,
        // An explicit add/change after removal requested a new attempt once cleanup finishes.
        replug: bool,
    },
}

impl Device {
    fn sender(&mut self) -> Option<&mut Sender> {
        match self {
            Self::Forwarding(sender) | Self::Stopping { sender, .. } => Some(sender),
            Self::Failed => None,
        }
    }
}

/// Independent sender lifecycles prevent a failed pointer from disabling a working keyboard.
pub(super) struct Forwarder {
    // Policy-selected GUI VM name, supplied as data rather than shell code.
    target: GuestName,
    // Fixed absolute dom0 Qubes transport selected by system configuration.
    qrexec: PathBuf,
    // UTF-8 sender path safely quoted inside qrexec's local command.
    sender: PathBuf,
    // Failed attempts and still-owned processes, indexed by their validated event nodes.
    devices: BTreeMap<Node, Device>,
}

fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

impl Forwarder {
    /// Prepare an empty owner with fixed absolute transport and sender executables.
    pub(super) fn new(target: GuestName, qrexec: PathBuf, sender: PathBuf) -> io::Result<Self> {
        if !qrexec.is_absolute() || !sender.is_absolute() || sender.to_str().is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "input transport must be absolute and sender must be an absolute UTF-8 path",
            ));
        }

        Ok(Self {
            target,
            qrexec,
            sender,
            devices: BTreeMap::new(),
        })
    }

    /// Attempt once; a replug waits for its old transport to exit before replacement.
    pub(super) fn add(&mut self, node: Node) -> io::Result<()> {
        if let Some(device) = self.devices.get_mut(&node) {
            if let Device::Stopping { replug, .. } = device {
                *replug = true;
            }
            return Ok(());
        }

        self.devices.insert(node.clone(), Device::Failed);
        let command = format!(
            "{} {}",
            quote(self.sender.to_str().expect("validated sender")),
            quote(node.path().to_str().expect("validated node"))
        );
        let child = Command::new(&self.qrexec)
            .args([
                "-d",
                self.target.as_str(),
                "-l",
                &command,
                "DEFAULT:QUBESRPC airlock.InputDevice dom0",
            ])
            .stdin(Stdio::null())
            .process_group(0)
            .spawn()?;

        eprintln!("forwarding {} to {}", node.path().display(), self.target);
        self.devices
            .insert(node, Device::Forwarding(Sender { child: Some(child) }));
        Ok(())
    }

    /// Request cancellation independently; only reaping permits a later replacement.
    pub(super) fn remove(&mut self, node: &Node) {
        if let Some(Device::Forwarding(sender) | Device::Stopping { sender, .. }) =
            self.devices.remove(node)
        {
            sender.cancel();
            self.devices.insert(
                node.clone(),
                Device::Stopping {
                    sender,
                    replug: false,
                },
            );
            eprintln!("releasing input {}", node.path().display());
        }
    }

    /// Reap exited transports and run only replacement attempts requested by a replug.
    pub(super) fn reap(&mut self) {
        let mut finished = Vec::new();
        for (node, device) in &mut self.devices {
            let Some(sender) = device.sender() else {
                continue;
            };
            match sender.finish() {
                Ok(true) => finished.push(node.clone()),
                Ok(false) => {}
                Err(error) => eprintln!("cannot reap input {}: {error}", node.path().display()),
            }
        }

        for node in finished {
            match self.devices.remove(&node) {
                Some(Device::Forwarding(_)) => {
                    eprintln!("input forwarding exited for {}", node.path().display());
                    self.devices.insert(node, Device::Failed);
                }
                Some(Device::Stopping { replug: true, .. }) => {
                    // One disappeared or broken sender must not abort other devices.
                    if let Err(error) = self.add(node.clone()) {
                        eprintln!(
                            "cannot forward replugged {}: {error}",
                            node.path().display()
                        );
                    }
                }
                _ => {}
            }
        }
    }
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        // Cancel all devices before waiting, and share one shutdown budget.
        for device in self.devices.values_mut() {
            if let Some(sender) = device.sender() {
                sender.cancel();
            }
        }

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let mut remaining = 0;
            for device in self.devices.values_mut() {
                if let Some(sender) = device.sender()
                    && !matches!(sender.finish(), Ok(true))
                {
                    remaining += 1;
                }
            }
            if remaining == 0 {
                break;
            }
            if Instant::now() >= deadline {
                eprintln!(
                    "{remaining} input transports still stopping; systemd retains their control-group cleanup"
                );
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}
