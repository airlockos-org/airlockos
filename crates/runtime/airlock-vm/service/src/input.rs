//! Observe existing root input receivers without creating devices or injecting events.

use airlock_machine_core::input::{Device, Receiver, Schema};
use anyhow::{Context, Result, ensure};
use clap::Args;
use std::{fs, os::unix::fs::FileTypeExt, path::PathBuf};

/// Fixed local device and handler paths supplied by the installed input RPC wrapper.
#[derive(Args)]
pub(crate) struct Request {
    /// Kernel uinput device; alternate paths support explicitly scoped local diagnostics.
    #[arg(long, default_value = "/dev/uinput")]
    uinput: PathBuf,
    /// Kernel input-class directory; override only for explicitly scoped local diagnostics.
    #[arg(long, default_value = "/sys/class/input")]
    sys_input: PathBuf,
    /// Every handler required by the installed keyboard/mouse/tablet receiver composition.
    #[arg(long = "handler", required = true)]
    handlers: Vec<PathBuf>,
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
    for handler in request.handlers {
        ensure!(
            rustix::fs::access(&handler, rustix::fs::Access::EXEC_OK).is_ok(),
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
    println!(
        "{}",
        serde_json::to_string(&Receiver {
            schema: Schema::V1,
            devices
        })?
    );
    Ok(())
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
