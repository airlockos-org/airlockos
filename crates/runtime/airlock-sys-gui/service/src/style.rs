//! Persist declarative GUI borders and signal only verified running Qubes GUI daemons.

use airlock_nix_core::identity::GitRevision;
use airlock_vm_service::support;
use anyhow::{Context, Result, ensure};
use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    // Exact version of the narrowly scoped border-style request.
    schema: String,
    // Visible border width in pixels, constrained to 1 through 16.
    color_width: u8,
    // Source revision authorizing a runtime change; absent for the boot default.
    revision: Option<GitRevision>,
}

#[derive(Serialize)]
struct Record {
    // Request version retained with the applied selection.
    schema: String,
    // Border width persisted before any reload signal is sent.
    color_width: u8,
    // Committed source identity, absent only for generation-provided defaults.
    revision: Option<GitRevision>,
    // Current immutable NixOS system associated with this style selection.
    system: std::path::PathBuf,
    // Fractional Unix time for diagnostic ordering.
    time: f64,
    // Number of verified daemons whose process handles were pinned.
    daemon_count: usize,
    // Whether publication is prepared, reload-requested or a boot default.
    status: &'static str,
}

fn atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().context("style file has no directory")?;
    support::directory(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|e| e.error)?;
    support::sync(parent)
}

pub(crate) fn execute(boot: bool) -> Result<()> {
    ensure!(
        rustix::process::geteuid().is_root(),
        "GUI style requires the existing administrator transport"
    );
    let mut bytes = Vec::new();
    std::io::stdin().lock().take(8193).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 8192, "GUI style request is too large");
    let request: Request =
        airlock_nix_core::state::parse_json(&bytes, Path::new("<style request>"))?;
    ensure!(
        request.schema == "airlock.gui-style.v1" && (1..=16).contains(&request.color_width),
        "invalid GUI style schema or color width"
    );
    ensure!(
        boot || request.revision.is_some(),
        "a committed source revision is required"
    );
    let root = Path::new("/rw/airlock");
    support::directory(root)?;
    let _guard = support::lock(
        root,
        "gui-style",
        "publish and reload the selected GUI border width",
    )?;

    let mut handles = Vec::new();
    if !boot {
        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|v| v.parse().ok())
                .and_then(Pid::from_raw)
            else {
                continue;
            };
            let executable = match fs::read_link(entry.path().join("exe")) {
                Ok(path) => path,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            if executable.file_name().is_none_or(|v| v != "qubes-guid") {
                continue;
            }
            ensure!(
                executable
                    .parent()
                    .and_then(Path::parent)
                    .is_some_and(|p| p.join("share/airlock/gui-border-reload-v1").is_file()),
                "running GUI daemon lacks reload support"
            );
            let handle = match pidfd_open(pid, PidfdFlags::empty()) {
                Ok(fd) => fd,
                Err(rustix::io::Errno::SRCH) => continue,
                Err(error) => return Err(error.into()),
            };
            // Opening a pidfd pins identity; a second lookup rejects PID replacement during the scan.
            if fs::read_link(entry.path().join("exe")).ok().as_ref() != Some(&executable) {
                continue;
            }
            handles.push(handle);
        }
        ensure!(
            !handles.is_empty(),
            "no running GUI daemons; start a graphical session first"
        );
    }

    let time = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let mut record = Record {
        schema: request.schema,
        color_width: request.color_width,
        revision: request.revision,
        system: fs::canonicalize("/run/current-system")?,
        time: time.as_secs_f64(),
        daemon_count: handles.len(),
        status: "prepared",
    };
    let history = root.join("gui-style-history");
    support::directory(&history)?;
    let receipt = history.join(format!("{}.json", time.as_nanos()));
    support::save(&receipt, &record)?;
    atomic(
        &root.join("gui-border-width"),
        format!("{}\n", record.color_width).as_bytes(),
        0o644,
    )?;
    for handle in &handles {
        pidfd_send_signal(handle, Signal::HUP)?;
    }
    record.status = if handles.is_empty() {
        "boot-default"
    } else {
        "reload-requested"
    };
    support::save(&receipt, &record)?;
    support::save(&root.join("gui-style-selection.json"), &record)?;
    println!("{}", serde_json::to_string(&record)?);
    Ok(())
}
