//! Service-specific observation over the shared bounded process transport.

pub(crate) use airlock_nix_core::runtime::process::{LIMIT, OwnedChild, output, rpc, run, text};
use airlock_nix_core::runtime::{Result, decode, require};
use std::{process::Command, time::Duration};

/// A failed deployment phase is a successful status observation. Preserve its
/// diagnostic `error` field rather than treating it as a failed RPC operation.
pub(crate) fn machine_status() -> Result<serde_json::Value> {
    let bytes = serde_json::to_vec(
        &serde_json::json!({"schema":"airlock.machine-control.v1","action":"status"}),
    )?;

    let result = run(
        Command::new("qrexec-client-vm").args(["dom0", "airlock.Ctrl.MachineControl"]),
        Some([bytes, vec![b'\n']].concat()),
        Some(Duration::from_secs(20)),
    )?;

    let raw = result.checked("observe machine status")?;
    let value: serde_json::Value = decode(&raw)?;
    require(
        value.is_object()
            && value
                .get("phase")
                .and_then(serde_json::Value::as_str)
                .is_some(),
        "machine observation has no deployment phase",
    )?;
    Ok(value)
}
