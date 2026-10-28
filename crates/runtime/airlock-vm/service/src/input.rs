//! Observe input receivers and accept dom0's explicit graphical startup handoff.

use airlock_machine_core::input::{Device, Receiver, Schema};
use airlock_nix_core::runtime::process;
use anyhow::{Context, Result, ensure};
use clap::Args;
use std::{
    fs,
    os::unix::fs::{FileTypeExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

/// Fixed local device and handler paths supplied by the installed input RPC wrapper.
#[derive(Args)]
pub(crate) struct Request {
    /// Kernel uinput device; alternate paths support explicitly scoped local diagnostics.
    #[arg(long, default_value = "/dev/uinput")]
    uinput: PathBuf,
    /// Kernel input-class directory; override only for explicitly scoped local diagnostics.
    #[arg(long, default_value = "/sys/class/input")]
    sys_input: PathBuf,
    /// Event nodes corresponding to the observed kernel interfaces.
    #[arg(long, default_value = "/dev/input")]
    dev_input: PathBuf,
    /// Every handler required by the installed keyboard/mouse/tablet receiver composition.
    #[arg(long = "handler", required = true)]
    handlers: Vec<PathBuf>,
}

/// Guest-local startup message, independent of keyboard presence.
#[derive(Args)]
pub(crate) struct Startup {
    // Guest-local boot console remains visible until the display manager can start.
    #[arg(long, default_value = "/dev/tty1")]
    status_device: PathBuf,
}

/// Fixed local adapter for dom0's input initialization handoff.
#[derive(Args)]
pub(crate) struct Initialization {
    // Exact systemd executable supplied by the installed RPC wrapper.
    #[arg(long)]
    systemctl: PathBuf,
    // Console used only while the login target has not been released.
    #[command(flatten)]
    startup: Startup,
}

/// Display progress in the GUI VM; diagnostic details remain in its journal.
fn progress(path: &Path, message: &str) {
    let text = format!(
        "\x1b[H\x1b[J
  Airlock | Starting desktop

  {message}
"
    );
    if let Err(error) = fs::write(path, text) {
        eprintln!("cannot update startup console: {error}");
    }
}

/// Show progress once; dom0 explicitly activates the login target after initialization.
pub(crate) fn startup(request: Startup) {
    progress(&request.status_device, "Initializing input forwarding…");
}

/// Accept dom0's closed status protocol; only completion activates the fixed login target.
/// Repeated completion is idempotent, and later transport retries leave an active login alone.
pub(crate) fn initialization(request: Initialization) -> Result<()> {
    ensure!(
        std::env::var("QREXEC_REMOTE_DOMAIN").as_deref() == Ok("dom0"),
        "input initialization is restricted to dom0"
    );
    let argument = std::env::var("QREXEC_SERVICE_ARGUMENT").unwrap_or_default();
    ensure!(
        matches!(argument.as_str(), "ready" | "retrying"),
        "invalid input initialization status"
    );
    let target = "airlock-input-initialized.target";
    let run = |args: &[&str]| {
        process::run(
            Command::new(&request.systemctl).args(args),
            None,
            Some(Duration::from_secs(10)),
        )
    };
    if argument == "ready" {
        // GDM can require the startup message service. Never block its qrexec
        // caller on graphical startup, which may itself need further RPCs.
        run(&["--no-block", "start", target])?
            .checked("release login after input initialization")?;
    } else if !run(&["is-active", "--quiet", target])?.status.success() {
        progress(
            &request.startup.status_device,
            "Input forwarding failed. Retrying automatically…",
        );
    }
    Ok(())
}

/// Accept only dom0's argument-free readiness RPC and observe device/handler accessibility.
pub(crate) fn ready(request: Request) -> Result<()> {
    ensure!(
        std::env::var("QREXEC_REMOTE_DOMAIN").as_deref() == Ok("dom0"),
        "airlock.InputReceiverReady is restricted to dom0"
    );
    ensure!(
        std::env::var_os("QREXEC_SERVICE_ARGUMENT").is_none_or(|value| value.is_empty()),
        "airlock.InputReceiverReady does not accept arguments"
    );

    println!("{}", serde_json::to_string(&observe(&request)?)?);
    Ok(())
}

/// Observe existing kernel receivers without changing their device or service state.
fn observe(request: &Request) -> Result<Receiver> {
    ensure!(
        fs::metadata(&request.uinput).is_ok_and(|metadata| metadata.file_type().is_char_device())
            && rustix::fs::access(&request.uinput, rustix::fs::Access::WRITE_OK).is_ok(),
        "/dev/uinput is not ready"
    );
    // access(2) alone can succeed when the driver rejects opening the device.
    // Opening creates no virtual device; UI_DEV_CREATE remains the receiver's responsibility.
    let _device = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&request.uinput)
        .context("cannot open the input receiver device")?;
    for handler in &request.handlers {
        ensure!(
            rustix::fs::access(handler, rustix::fs::Access::EXEC_OK).is_ok(),
            "input receiver is unavailable: {handler}",
            handler = handler.display()
        );
    }

    let mut devices = Vec::new();
    for entry in fs::read_dir(&request.sys_input)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(number) = name.to_str().and_then(|name| name.strip_prefix("event")) else {
            continue;
        };
        if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let path = entry.path().join("device");
        let name = fs::read_to_string(path.join("name"))?
            .trim_end_matches('\n')
            .to_owned();
        if !name.starts_with("dom0: ") {
            continue;
        }
        // Kernel registration alone must not acknowledge a device whose event
        // node is still unavailable to the guest's input stack.
        let node = request.dev_input.join(entry.file_name());
        if !fs::metadata(&node).is_ok_and(|metadata| metadata.file_type().is_char_device())
            || fs::OpenOptions::new()
                .read(true)
                .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32)
                .open(&node)
                .is_err()
        {
            continue;
        }
        let keys = fs::read_to_string(path.join("capabilities/key"))?;
        let relative = fs::read_to_string(path.join("capabilities/rel"))?;
        let absolute = fs::read_to_string(path.join("capabilities/abs"))?;
        // Linux evdev codes: A/Z/Enter distinguish typing from multimedia keys;
        // movement can use REL_X/Y, ABS_X/Y or multitouch-only ABS_MT_POSITION_X/Y.
        devices.push(Device {
            name,
            keyboard: bit(&keys, 30)? && bit(&keys, 44)? && bit(&keys, 28)?,
            pointer: (bit(&relative, 0)? && bit(&relative, 1)?)
                || (bit(&absolute, 0)? && bit(&absolute, 1)?)
                || (bit(&absolute, 53)? && bit(&absolute, 54)?),
        });
        ensure!(devices.len() <= 1024, "too many forwarded input interfaces");
    }
    Ok(Receiver {
        schema: Schema::V1,
        devices,
    })
}

/// Linux prints the highest nonzero native unsigned-long bitmap word first on this x86_64 target.
fn bit(bitmap: &str, index: usize) -> Result<bool> {
    let Some(word) = bitmap.split_whitespace().rev().nth(index / 64) else {
        return Ok(false);
    };
    Ok(
        u64::from_str_radix(word, 16).context("invalid kernel input capability bitmap")?
            & (1_u64 << (index % 64))
            != 0,
    )
}
