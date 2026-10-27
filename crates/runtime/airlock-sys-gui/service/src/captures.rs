//! Queue completed GNOME captures and stream them through the existing narrow Qubes RPCs.
//! Failed deliveries retain both the original capture and a durable retry record.

use airlock_machine_core::services::{CaptureOperation, CaptureSenderConfig};
use airlock_nix_core::identity::GuestName;
use airlock_sys_gui_service::command::CaptureAction as Action;
use airlock_vm_service::{
    capture::{self, Header, Kind, Receipt},
    support,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, Metadata},
    io::Seek,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

#[derive(Serialize, Deserialize)]
struct Job {
    // Stable identity incorporating path, final length and nanosecond modification time.
    id: String,
    // Protocol category determining the permitted capture extensions.
    kind: Kind,
    // Original local file retained after successful or failed delivery.
    source: PathBuf,
    // Final size recorded at the completion notification.
    size: u64,
    // Nanosecond timestamp recorded at completion, rejecting later file changes.
    mtime: i128,
}

fn modification(metadata: &Metadata) -> i128 {
    metadata.mtime() as i128 * 1_000_000_000 + metadata.mtime_nsec() as i128
}

fn identity(path: &Path, metadata: &Metadata) -> String {
    format!(
        "{:x}",
        Sha256::digest(
            format!(
                "{}\0{}\0{}",
                path.display(),
                metadata.len(),
                modification(metadata)
            )
            .as_bytes()
        )
    )
}

fn source(kind: Kind, path: &Path) -> Result<(PathBuf, File)> {
    let path = std::path::absolute(path)?;
    let file = capture::open_file(&path)?;
    ensure!(kind.accepts(&path), "unexpected capture format");
    ensure!(
        fs::canonicalize(path.parent().context("capture has no parent")?)?
            == fs::canonicalize(capture::directory(kind)?)?,
        "capture must be in GNOME's capture directory"
    );
    Ok((path, file))
}

fn sender_root(target: &GuestName) -> Result<PathBuf> {
    // Queues, acknowledgements and backfill progress belong to one receiving VM.
    // A different --target must never redirect pending work or reuse its receipts.
    Ok(capture::state_root()?
        .join("outgoing")
        .join(target.as_str()))
}

fn enqueue(kind: Kind, filename: &Path, target: &GuestName) -> Result<String> {
    let (path, file) = source(kind, filename)?;
    let metadata = file.metadata()?;
    let id = identity(&path, &metadata);
    let root = sender_root(target)?;
    if !root.join("sent").join(format!("{id}.json")).try_exists()? {
        support::save(
            &root.join("pending").join(format!("{id}.json")),
            &Job {
                id: id.clone(),
                kind,
                source: path,
                size: metadata.len(),
                mtime: modification(&metadata),
            },
        )?;
    }
    Ok(id)
}

fn transport(target: &GuestName, service: &str) -> Command {
    let mut command = Command::new(support::tool(
        "AIRLOCK_QREXEC_CLIENT_VM",
        "qrexec-client-vm",
    ));
    command.arg(target.as_str()).arg(service);
    command
}

fn deliver(job: &Job, target: &GuestName) -> Result<Receipt> {
    capture::digest_id(&job.id)?;
    let (path, mut file) = source(job.kind, &job.source)?;
    let metadata = file.metadata()?;
    ensure!(
        identity(&path, &metadata) == job.id
            && metadata.len() == job.size
            && modification(&metadata) == job.mtime,
        "capture changed after completion; retaining it locally"
    );
    let digest = capture::hash(&mut file)?;
    ensure!(
        modification(&file.metadata()?) == job.mtime && file.metadata()?.len() == job.size,
        "capture changed while hashing"
    );
    file.rewind()?;
    let header = Header {
        schema: "airlock.capture.v1".into(),
        id: job.id.clone(),
        name: path
            .file_name()
            .context("capture has no filename")?
            .to_str()
            .context("capture filename is not UTF-8")?
            .into(),
        size: metadata.len(),
        sha256: digest.clone(),
    };
    header.validate(job.kind)?;
    let mut bytes = serde_json::to_vec(&header)?;
    bytes.push(b'\n');
    let input = support::Input::file(bytes, file, metadata.len())?;
    let service = CaptureOperation::Import.request(job.kind);
    let output = support::run(
        &mut transport(target, &service),
        Some(input),
        Duration::from_secs(300),
    )?
    .checked()?;
    let receipt: Receipt =
        airlock_nix_core::state::parse_json(&output, Path::new("<capture acknowledgement>"))?;
    ensure!(
        receipt.id == job.id
            && receipt.sha256 == digest
            && receipt.kind == job.kind
            && receipt.path.is_absolute(),
        "receiver did not acknowledge this exact capture"
    );
    Ok(receipt)
}

fn notify(message: &str) {
    eprintln!("{message}");
    let _ = support::run(
        crate::notifications::command().args(["--", "Screen capture", message]),
        None,
        Duration::from_secs(10),
    );
}

fn pending(root: &Path) -> Result<Vec<PathBuf>> {
    let directory = root.join("pending");
    if !directory.try_exists()? {
        return Ok(Vec::new());
    }
    let mut paths = fs::read_dir(directory)?
        .map(|v| v.map(|v| v.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.retain(|v| v.extension().is_some_and(|v| v == "json"));
    paths.sort();
    Ok(paths)
}

fn drain(target: &GuestName) -> Result<()> {
    let root = sender_root(target)?;
    let _guard = support::lock(&root, "sender", "deliver pending completed captures")?;
    let mut failed = false;
    for path in pending(&root)? {
        let result = (|| -> Result<()> {
            let job: Job = support::read(&path)?.context("pending capture disappeared")?;
            capture::digest_id(&job.id)?;
            ensure!(
                path.file_stem().and_then(|v| v.to_str()) == Some(&job.id),
                "capture job identity mismatch"
            );
            let sent = root.join("sent").join(format!("{}.json", job.id));
            if let Some(receipt) = support::read::<Receipt>(&sent)? {
                ensure!(
                    receipt.id == job.id && receipt.kind == job.kind,
                    "invalid saved acknowledgement"
                );
            } else {
                support::save(&sent, &deliver(&job, target)?)?;
            }
            fs::remove_file(&path)?;
            support::sync(path.parent().context("pending record has no directory")?)
        })();
        if let Err(error) = result {
            failed = true;
            eprintln!("{}: {error:#}", path.display());
        }
    }
    if failed {
        notify(&format!(
            "Some captures could not be delivered to {target}. They remain in sys-gui; retry at next login or capture."
        ));
    }
    Ok(())
}

fn backfill(target: &GuestName) -> Result<()> {
    let root = sender_root(target)?;
    let _guard = support::lock(&root, "backfill", "queue existing completed captures once")?;
    let marker = root.join("backfill.json");
    if marker.try_exists()? {
        return Ok(());
    }
    for kind in [Kind::Image, Kind::Video] {
        let directory = capture::directory(kind)?;
        if !directory.try_exists()? {
            continue;
        }
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() || !kind.accepts(&entry.path()) {
                continue;
            }
            if kind == Kind::Video {
                let probe = support::run(
                    Command::new(support::tool("AIRLOCK_FFPROBE", "ffprobe"))
                        .args([
                            "-v",
                            "error",
                            "-show_entries",
                            "format=duration",
                            "-of",
                            "json",
                        ])
                        .arg(entry.path()),
                    None,
                    Duration::from_secs(30),
                );
                if probe.is_err() || probe.is_ok_and(|v| !v.status.success()) {
                    continue;
                }
            }
            enqueue(kind, &entry.path(), target)?;
        }
    }
    support::save(&marker, &serde_json::json!({"complete":true}))
}

fn open(kind: Kind, filename: PathBuf, target: GuestName, action: &str) -> Result<()> {
    let (path, file) = source(kind, &filename)?;
    let id = identity(&path, &file.metadata()?);
    drain(&target)?;
    let receipt: Option<Receipt> = support::read(
        &sender_root(&target)?
            .join("sent")
            .join(format!("{id}.json")),
    )?;
    if receipt.is_none_or(|v| v.id != id || v.kind != kind) {
        notify(
            "This capture has not been delivered. Completed captures remain in sys-gui for retry.",
        );
        return Ok(());
    }
    let mut bytes = serde_json::to_vec(&serde_json::json!({"id":id,"action":action}))?;
    bytes.push(b'\n');
    support::run(
        &mut transport(&target, &CaptureOperation::Open.request(kind)),
        Some(support::Input::bytes(bytes)),
        // Allow the receiver to wait for its session before launching the local opener.
        Duration::from_secs(75),
    )?
    .checked()?;
    Ok(())
}

/// Loads a generation's contract before any operation; malformed input never falls back.
fn configuration(path: Option<&Path>) -> Result<CaptureSenderConfig> {
    let Some(path) = path else {
        return Ok(CaptureSenderConfig::default());
    };

    let bytes =
        fs::read(path).with_context(|| format!("read capture configuration {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid capture configuration {}", path.display()))
}

/// Applies the installed sender contract; explicit CLI destinations must agree with it.
pub(crate) fn execute(action: Action, path: Option<&Path>) -> Result<()> {
    let config = configuration(path)?;
    let destination = |target: Option<GuestName>| -> Result<GuestName> {
        if path.is_some()
            && let Some(target) = &target
        {
            ensure!(
                *target == config.target,
                "explicit target conflicts with the installed capture connection"
            );
        }
        Ok(target.unwrap_or_else(|| config.target.clone()))
    };

    match action {
        Action::CheckConfig => {
            println!("{}", serde_json::to_string(&config)?);
            Ok(())
        }
        Action::Enqueue {
            kind,
            filename,
            target,
        } => {
            let target = destination(target)?;
            enqueue(kind, &filename, &target)?;
            drain(&target)
        }
        Action::Retry { target } => {
            let target = destination(target)?;
            backfill(&target)?;
            drain(&target)
        }
        Action::Open {
            kind,
            filename,
            target,
        } => open(kind, filename, destination(target)?, "open"),
        Action::Show {
            kind,
            filename,
            target,
        } => open(kind, filename, destination(target)?, "show"),
    }
}
