//! Probe native VM storage, runtime identity and private-home persistence.

use super::{Session, common};
use anyhow::{Result, ensure};
use std::fs;

/// Assert the native backend identity and read-only Qubes store volume before guest startup.
pub(super) fn backend(session: &mut Session, guest: &str, label: &str) -> Result<()> {
    let classes = session.command(
        "qvm-ls",
        &["--raw-data", "--fields", "NAME,CLASS", "--no-spinner"],
        "config-vms-classes.log",
    )?;
    ensure!(
        classes
            .lines()
            .any(|line| line == format!("{guest}|StandaloneVM")),
        "{guest} is not a StandaloneVM"
    );
    let mut evidence = "class=StandaloneVM\n".to_owned();
    for (field, feature, expected) in [
        ("backend", "airlock-backend", "nix-closure"),
        ("store_device", "airlock-store-device", "/dev/xvde"),
        ("store_read_only", "airlock-store-read-only", "True"),
    ] {
        let value = session.command("qvm-features", &[guest, feature], "config-vms-feature.log")?;
        evidence.push_str(&format!("{field}={value}\n"));
        ensure!(value == expected, "{guest} has unexpected {field}: {value}");
    }
    let netvm = session.command("qvm-prefs", &[guest, "netvm"], "config-vms-netvm.log")?;
    evidence.push_str(&format!("netvm={netvm}\n"));
    ensure!(
        ["", "none", "None"].contains(&netvm.as_str()),
        "{guest} unexpectedly has a NetVM"
    );
    fs::write(
        session.file(&format!("config-vms-{label}-backend.log")),
        evidence,
    )?;
    let volume = session.command(
        "qvm-volume",
        &["info", &format!("{guest}:store")],
        &format!("config-vms-{label}-store-volume.log"),
    )?;
    ensure!(
        volume.lines().any(|line| {
            let mut words = line.split_whitespace();
            words.next() == Some("rw") && words.next() == Some("False")
        }),
        "{guest} store volume is not read-only"
    );
    Ok(())
}

/// Check a private-home marker across a complete upstream shutdown/start cycle.
pub(super) fn persistence(
    session: &mut Session,
    guest: &str,
    label: &str,
    message: &str,
) -> Result<()> {
    let user = common::setting("AIRLOCK_QUBE_USER", "user");
    let marker = format!("/home/{user}/.airlock-persistence-{guest}");
    session.remote(
        guest,
        "tee",
        &[&marker],
        Some(format!("{message}\n").into_bytes()),
        &format!("config-vms-{guest}-persistence-write.log"),
    )?;
    session.remote(guest, "sync", &[], None, "config-vms-sync.log")?;
    session.restart(guest)?;
    session.runtime_store(
        guest,
        &format!("config-vms-{guest}-store-mount-after-restart.log"),
    )?;
    let observed = session.remote(
        guest,
        "cat",
        &[&marker],
        None,
        &format!("config-vms-{label}-persistence.log"),
    )?;
    ensure!(
        observed == message,
        "{guest} persistent home state did not survive restart"
    );
    Ok(())
}
