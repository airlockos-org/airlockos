//! Submit source through sys-ctrl and return after its human review decision.

use airlock_nix_core::identity::{GuestName, JobId};
use airlock_nix_core::runtime::{
    Result, decode, emit,
    process::{self, OwnedChild},
    protocol::{Action, Header, RequestSchema},
};
use serde_json::json;
use std::{
    io::{self, Write},
    path::PathBuf,
    process::{Command, Stdio},
    time::Duration,
};

/// Read one controller job's feedback without contacting dom0 or changing state.
pub(crate) fn review_status(request_id: JobId) -> Result<u8> {
    let mut request = serde_json::to_vec(&json!({"request_id":request_id}))?;
    request.push(b'\n');

    let result = process::run(
        Command::new("qrexec-client-vm").args(["sys-ctrl", "airlock.Ctrl.ReviewStatus"]),
        Some(request),
        Some(Duration::from_secs(30)),
    )?;
    let code = result.status.code().unwrap_or(1) as u8;
    let value: serde_json::Value = decode(&result.stdout)?;
    emit(&value)?;
    Ok(code)
}

/// Upload committed source and wait for the human decision; approval is not deployment success.
pub(crate) fn source(
    action: Action,
    target: Option<GuestName>,
    repo: Option<PathBuf>,
) -> Result<u8> {
    let repo = match repo {
        Some(repo) => repo,
        None => airlock_nix_core::runtime::home()?.join("airlockos-machine"),
    };
    let temp = tempfile::Builder::new()
        .prefix("airlock-nix-submit-")
        .tempdir()?;

    let (source, mut archive) =
        airlock_nix_core::runtime::source::source_archive(&repo, temp.path())?;
    let header = Header {
        schema: RequestSchema::V1,
        action,
        target,
        revision: source.revision,
        lock_hash: source.lock_hash,
        archive_bytes: archive.metadata()?.len(),
    };
    header.candidate()?;

    let mut child = OwnedChild(
        Command::new("qrexec-client-vm")
            .args(["sys-ctrl", "airlock.Ctrl.GuestDeploy"])
            .stdin(Stdio::piped())
            .spawn()?,
    );

    let mut stdin = child.0.stdin.take().expect("piped stdin");
    let sent = (|| -> Result<()> {
        serde_json::to_writer(&mut stdin, &header)?;
        stdin.write_all(b"\n")?;
        io::copy(&mut archive, &mut stdin)?;
        Ok(())
    })();
    drop(stdin);

    let status = child.0.wait()?;
    // Preserve an early rejection's feedback when it closes a large upload.
    if status.success() {
        sent?;
    }

    Ok(status.code().unwrap_or(1) as u8)
}
