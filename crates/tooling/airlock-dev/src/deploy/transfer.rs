//! Separate binary closure transfer from the small, framed development control channel.

use crate::{
    support::{self, join, quote},
    transport::{self, Session},
};
use airlock_nix_core::{runtime::process::OwnedChild, store_path::StorePath};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};

pub(super) fn send(
    root: &Path,
    target: &str,
    bridge: &str,
    release: &str,
    session: &mut Session,
) -> Result<()> {
    let value = super::nix(root, &["path-info", "--recursive", "--json", release])?;
    let mut paths = BTreeMap::new();
    match value {
        Value::Array(entries) => {
            for entry in entries {
                let path = entry["path"]
                    .as_str()
                    .context("Nix path metadata")?
                    .to_owned();
                paths.insert(path, entry);
            }
        }
        Value::Object(entries) => paths.extend(entries),
        _ => anyhow::bail!("invalid Nix closure metadata"),
    }
    let inventory = session.run(
        "nix --extra-experimental-features nix-command path-info --all",
        Duration::from_secs(120),
    )?;
    let valid: BTreeSet<_> = inventory.lines().collect();
    let mut missing = Vec::new();
    let mut needed = 0u64;
    for (path, entry) in paths {
        let _: StorePath = path.parse()?;
        if !valid.contains(path.as_str()) {
            needed = needed
                .checked_add(entry["narSize"].as_u64().context("missing NAR size")?)
                .context("closure size overflow")?;
            missing.push(path);
        }
    }
    if missing.is_empty() {
        return Ok(());
    }

    let required = needed
        .checked_mul(2)
        .and_then(|n| n.checked_add(2 * 1024 * 1024 * 1024))
        .context("transfer size overflow")?;
    let dom0 = session.run("stat -f -c '%a %S' /nix/store", Duration::from_secs(60))?;
    ensure!(
        space(&dom0)? >= required,
        "dom0 has insufficient free space to safely stage this release. No VMs or partitions changed"
    );
    let report =
        support::text(Command::new("ssh").args(["--", target, "stat -f -c '%a %S' /home/user"]))?;
    ensure!(
        space(&report)?
            >= needed
                .checked_add(512 * 1024 * 1024)
                .context("bridge space overflow")?,
        "usr-assistant needs more private-volume space for the compressed closure transfer"
    );

    let nonce = transport::nonce()?;
    let remote = format!("/home/user/.cache/airlock-deploy/{nonce}.nar.gz");
    let incoming = format!("/var/lib/airlock/machine/incoming-{nonce}.nar.gz");
    eprintln!(
        "Transferring {} missing Nix paths through {target}…",
        missing.len()
    );
    let mut export = OwnedChild(
        Command::new("nix-store")
            .arg("--export")
            .args(&missing)
            .stdout(Stdio::piped())
            .spawn()?,
    );
    let mut gzip = OwnedChild(
        Command::new("gzip")
            .arg("-1c")
            .stdin(Stdio::from(
                export.0.stdout.take().context("export output")?,
            ))
            .stdout(Stdio::piped())
            .spawn()?,
    );
    let script = format!(
        "umask 077; mkdir -p /home/user/.cache/airlock-deploy && cat > {}",
        quote(&remote)
    );
    let mut upload = OwnedChild(
        Command::new("ssh")
            .args([
                "-oServerAliveInterval=30",
                "-oServerAliveCountMax=3",
                "--",
                target,
                &script,
            ])
            .stdin(Stdio::piped())
            .spawn()?,
    );
    let mut digest = Sha256::new();
    let mut bytes = [0; 65536];
    let input = gzip.0.stdout.as_mut().context("gzip output")?;
    let output = upload.0.stdin.as_mut().context("upload input")?;
    loop {
        let size = input.read(&mut bytes)?;
        if size == 0 {
            break;
        }
        digest.update(&bytes[..size]);
        output.write_all(&bytes[..size])?;
    }
    drop(upload.0.stdin.take());
    let statuses = [export.0.wait()?, gzip.0.wait()?, upload.0.wait()?];
    ensure!(
        statuses.iter().all(|s| s.success()),
        "Nix closure upload failed"
    );
    let checksum = format!("{:x}", digest.finalize());
    let fetch = join(&["qrexec-client", "-d", bridge, &format!("user:cat {remote}")]);
    let script = format!(
        "umask 077; mkdir -p /var/lib/airlock/machine; {fetch} > {incoming}; printf '%s\\n' '{checksum}  {incoming}' | sha256sum -c -; gzip -dc {incoming} | nix-store --import > /var/lib/airlock/machine/import.log; rm -- {incoming}"
    );
    let result = session.run(&script, Duration::from_secs(3600));
    let cleanup = Command::new("ssh")
        .args(["--", target, &format!("rm -f -- {}", quote(&remote))])
        .status();
    result?;
    ensure!(
        cleanup?.success(),
        "could not remove transferred closure from usr-assistant"
    );
    Ok(())
}

fn space(report: &str) -> Result<u64> {
    let values = report
        .split_whitespace()
        .map(str::parse::<u64>)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("invalid filesystem space report")?;
    ensure!(
        values.len() == 2 && values[1] > 0,
        "invalid filesystem space report"
    );
    values[0]
        .checked_mul(values[1])
        .context("filesystem space overflow")
}

pub(super) fn receipt(target: &str, path: &str) -> Result<Value> {
    ensure!(
        path.starts_with('/') && !path.contains(['\n', '\r', '\0']),
        "receipt must be an absolute path"
    );
    let bytes =
        support::output(Command::new("ssh").args(["--", target, &join(&["cat", "--", path])]))?;
    let value: Value = airlock_nix_core::runtime::decode(&bytes)?;
    ensure!(
        value.is_object(),
        "usr-assistant admission receipt is not a JSON object"
    );
    Ok(value)
}

pub(super) fn install_receipt(session: &mut Session, value: &Value) -> Result<String> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    ensure!(
        bytes.len() <= 4 * 1024 * 1024,
        "admission receipt exceeds limit"
    );
    let digest = support::digest(&bytes);
    let encoded = STANDARD.encode(bytes);
    let destination = format!("/var/lib/airlock/machine/receipts/{digest}.json");
    let temporary = format!("{destination}.new-{}", transport::nonce()?);
    session.run(
        &format!(
            "umask 077; mkdir -p /var/lib/airlock/machine/receipts; : > {}",
            quote(&temporary)
        ),
        Duration::from_secs(60),
    )?;
    for chunk in encoded.as_bytes().chunks(1024) {
        let chunk = std::str::from_utf8(chunk)?;
        session.run(
            &format!(
                "printf %s {} | base64 -d >> {}",
                quote(chunk),
                quote(&temporary)
            ),
            Duration::from_secs(60),
        )?;
    }
    session.run(
        &format!(
            "printf '%s\\n' {} | sha256sum -c - >/dev/null; mv -- {} {}",
            quote(&format!("{digest}  {temporary}")),
            quote(&temporary),
            quote(&destination)
        ),
        Duration::from_secs(60),
    )?;
    Ok(destination)
}

#[cfg(test)]
mod regression;
