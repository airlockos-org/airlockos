//! Consume Qubes' NUL-framed admin.Events stream without a Python dispatcher.
//! Only the selected GUI VM can trigger the fixed local input systemd units.

use super::tool;
use crate::process::Runner;
use airlock_nix_core::identity::GuestName;
use anyhow::{Context, Result, ensure};
use std::{
    io::{Read, Write},
    net::Shutdown,
    os::unix::net::UnixStream,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const CONNECT: &str = "airlock-gui-input-connect.service";

const INPUT: &str = "airlock-gui-input.target";

// Upstream framing: https://github.com/QubesOS/qubes-core-admin-client/blob/main/qubesadmin/events/__init__.py
struct Decoder {
    // Bytes in the current partial NUL-delimited protocol field.
    field: Vec<u8>,
    // Fields in one event, bounded independently of the lifetime of the stream.
    fields: Vec<String>,
    // Total bytes in the current event, including discarded keyword arguments.
    size: usize,
}

impl Decoder {
    fn new() -> Self {
        Self {
            field: Vec::new(),
            fields: Vec::new(),
            size: 0,
        }
    }

    fn byte(&mut self, byte: u8) -> Result<Option<(String, String)>> {
        self.size += 1;
        ensure!(self.size <= 64 * 1024, "Qubes input event exceeds limit");
        if byte != 0 {
            self.field.push(byte);
            return Ok(None);
        }
        let field = String::from_utf8(std::mem::take(&mut self.field))?;
        let count = self.fields.len();
        if count == 0 {
            ensure!(field == "1", "non-event received on Qubes event stream");
        }
        if count >= 3 && count % 2 == 1 && field.is_empty() {
            let subject = self.fields[1].clone();
            let event = self.fields[2].clone();
            self.fields.clear();
            self.size = 0;
            return Ok(Some((subject, event)));
        }
        ensure!(
            self.fields.len() < 1024,
            "too many Qubes input event fields"
        );
        self.fields.push(field);
        Ok(None)
    }
}

fn systemctl(action: &str) -> Result<()> {
    let mut args = vec!["--no-block".into(), action.into(), CONNECT.into()];
    if action == "stop" {
        args.push(INPUT.into());
    }
    Runner::default().run(
        tool("AIRLOCK_INPUT_SYSTEMCTL", "systemctl"),
        &args,
        Duration::from_secs(10),
        &[],
    )?;
    Ok(())
}

fn running(socket: &PathBuf, target: &GuestName, stop: &AtomicBool) -> Result<bool> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.set_read_timeout(Some(Duration::from_millis(250)))?;
    stream.write_all(format!("admin.vm.CurrentState+ dom0 name {target}\0").as_bytes())?;
    stream.shutdown(Shutdown::Write)?;

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        if stop.load(Ordering::Relaxed) {
            return Ok(false);
        }
        ensure!(
            Instant::now() < deadline,
            "Qubes running-state request timed out"
        );
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => bytes.extend_from_slice(&buffer[..count]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error.into()),
        }
        ensure!(
            bytes.len() <= 8192,
            "Qubes running-state reply exceeds limit"
        );
    }

    ensure!(
        bytes.starts_with(b"0\0"),
        "Qubes running-state request failed"
    );
    let text = std::str::from_utf8(&bytes[2..])?;
    let power = text
        .split_whitespace()
        .find_map(|v| v.strip_prefix("power_state="))
        .context("missing Qubes power state")?;
    // Match upstream QubesVM.is_running(), including paused/startup states.
    // The existing readiness RPC remains the gate before any device is forwarded.
    Ok(!matches!(power, "Halted" | "NA"))
}

fn listen(socket: &PathBuf, target: &GuestName, stop: &AtomicBool) -> Result<()> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.set_read_timeout(Some(Duration::from_millis(250)))?;
    stream.write_all(b"admin.Events+ dom0 name dom0\0")?;
    stream.shutdown(Shutdown::Write)?;

    let confirmation_deadline = Instant::now() + Duration::from_secs(10);
    let mut confirmed = false;
    let mut decoder = Decoder::new();
    let mut buffer = [0u8; 4096];
    while !stop.load(Ordering::Relaxed) {
        ensure!(
            confirmed || Instant::now() < confirmation_deadline,
            "Qubes input subscription was not confirmed"
        );
        let count = match stream.read(&mut buffer) {
            Ok(0) => anyhow::bail!("Qubes input event connection closed"),
            Ok(count) => count,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        for byte in &buffer[..count] {
            if stop.load(Ordering::Relaxed) {
                return Ok(());
            }
            if let Some((subject, event)) = decoder.byte(*byte)? {
                if event == "connection-established" && subject.is_empty() {
                    // Subscription is active before checking existing state. Startup
                    // and reconnect cannot miss a VM that was already running.
                    confirmed = true;
                    let active = running(socket, target, stop)?;
                    if stop.load(Ordering::Relaxed) {
                        return Ok(());
                    }
                    let action = if active { "start" } else { "stop" };
                    if let Err(error) = systemctl(action) {
                        eprintln!("cannot {action} physical input: {error:#}");
                    }
                } else if subject == target.as_str() {
                    match event.as_str() {
                        "domain-start" => {
                            if let Err(error) = systemctl("start") {
                                eprintln!("cannot connect physical input: {error:#}");
                            }
                        }
                        "domain-shutdown" | "domain-stopped" | "domain-start-failed" => {
                            if let Err(error) = systemctl("stop") {
                                eprintln!("cannot release physical input: {error:#}");
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    Ok(())
}

pub(super) fn run(target: GuestName, stop: Arc<AtomicBool>) -> Result<()> {
    let socket = PathBuf::from(tool("AIRLOCK_INPUT_QUBES_SOCKET", "/var/run/qubesd.sock"));
    ensure!(
        socket.is_absolute(),
        "Qubes input socket path must be absolute"
    );
    // A second observer must never release the first observer's live senders.
    let _guard = super::runtime_lock("events", &target)?;

    // A previous observer may have died without stopping its transports.
    systemctl("stop")?;

    while !stop.load(Ordering::Relaxed) {
        if let Err(error) = listen(&socket, &target, &stop) {
            eprintln!("input Qubes listener: {error:#}; reconnecting in 5 seconds");
            // Lifecycle observation was lost. Release old senders and require
            // fresh receiver readiness before reconnecting them to a VM instance.
            if let Err(error) = systemctl("stop") {
                eprintln!("cannot release unobserved physical input: {error:#}");
            }
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while !stop.load(Ordering::Relaxed) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(100));
        }
    }

    // Intentional listener shutdown also ends lifecycle observation.
    systemctl("stop")
}
