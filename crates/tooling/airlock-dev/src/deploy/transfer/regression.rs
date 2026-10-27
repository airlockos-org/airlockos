//! Exercise private control and transfer paths through ordinary Cargo tests and real local shell framing.

use super::*;
use airlock_tests::{process::run, repository::Repository};
use serde_json::json;
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

/// Reexecute one Cargo case with child-local fixture environment instead of mutating the multithreaded harness.
fn child(fixture: &Repository, name: &str) -> Result<()> {
    let mut command = Command::new(std::env::current_exe()?);
    command.args([
        "--exact",
        &format!("deploy::transfer::regression::{name}"),
        "--nocapture",
    ]);
    fixture.environment(&mut command);
    command.env("AIRLOCK_TEST_TRANSPORT_CHILD", "1");
    run(&mut command, None)?.checked()?;
    Ok(())
}

/// Framing preserves literal shell data, separates stderr and remains usable for repeated commands and large receipts.
#[test]
fn control_frames_and_receipts() -> Result<()> {
    if std::env::var_os("AIRLOCK_TEST_TRANSPORT_CHILD").is_none() {
        let fixture = Repository::new()?;
        fixture.configure(json!({"shell": true}))?;
        return child(&fixture, "control_frames_and_receipts");
    }
    let mut session = Session::connect("fixture")?;
    let expected = "text-'\"$()";
    assert_eq!(
        session.run(
            &format!("printf %s {text}; printf noise >&2", text = quote(expected)),
            Duration::from_secs(5)
        )?,
        expected
    );
    assert_eq!(
        session.run("printf second", Duration::from_secs(5))?,
        "second"
    );

    let value =
        json!({"schema": "admission", "timings": {"details": "payload-'`$()".repeat(1000)}});
    let remote = install_receipt(&mut session, &value)?;
    let root = PathBuf::from(std::env::var_os("AIRLOCK_TEST_WORKSTATION").context("fixture root")?);
    let destination = root
        .join("receipts")
        .join(Path::new(&remote).file_name().unwrap());
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&destination)?)?,
        value
    );
    assert_eq!(destination.metadata()?.permissions().mode() & 0o777, 0o600);
    assert_eq!(fs::read_dir(root.join("receipts"))?.count(), 1);
    Ok(())
}

/// Command failure, deadline expiry and oversized control requests cannot return successful output.
#[test]
fn failed_control_never_reports_success() -> Result<()> {
    if std::env::var_os("AIRLOCK_TEST_TRANSPORT_CHILD").is_none() {
        let fixture = Repository::new()?;
        fixture.configure(json!({"shell": true}))?;
        return child(&fixture, "failed_control_never_reports_success");
    }
    for (script, expected, timeout) in [
        (
            "printf failed >&2; exit 7".to_owned(),
            "failed (7)",
            Duration::from_secs(5),
        ),
        (
            "sleep 0.3".to_owned(),
            "timed out",
            Duration::from_millis(30),
        ),
        ("x".repeat(4000), "too large", Duration::from_secs(5)),
    ] {
        let mut session = Session::connect("fixture")?;
        let error = session.run(&script, timeout).unwrap_err();
        assert!(error.to_string().contains(expected), "{error:#}");
    }
    Ok(())
}

/// Existing remote closures skip export; capacity or malformed filesystem reports stop before any binary transfer.
#[test]
fn closure_inventory_and_capacity_guard_transfer() -> Result<()> {
    let release = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-release";
    if std::env::var_os("AIRLOCK_TEST_TRANSPORT_CHILD").is_none() {
        let fixture = Repository::new()?;
        for (key, value, error) in [
            ("inventory", release, ""),
            ("dom0_space", "262144 4096", "dom0 has insufficient"),
            ("bridge_space", "262144 4096", "private-volume space"),
            ("bridge_space", "-1 4096", "invalid filesystem"),
        ] {
            fixture.configure(json!({"shell": true, "release": release, (key): value}))?;
            let mut command = Command::new(std::env::current_exe()?);
            command.args([
                "--exact",
                "deploy::transfer::regression::closure_inventory_and_capacity_guard_transfer",
                "--nocapture",
            ]);
            fixture.environment(&mut command);
            command
                .env("AIRLOCK_TEST_TRANSPORT_CHILD", "1")
                .env("AIRLOCK_TEST_TRANSFER_ERROR", error);
            run(&mut command, None)?.checked()?;
        }
        assert!(fixture.calls("nix-store")?.is_empty());
        return Ok(());
    }
    let mut session = Session::connect("fixture")?;
    let root = PathBuf::from(std::env::var_os("AIRLOCK_TEST_WORKSTATION").context("fixture root")?);
    let result = send(&root, "fixture", "usr-assistant", release, &mut session);
    let expected = std::env::var("AIRLOCK_TEST_TRANSFER_ERROR")?;
    if expected.is_empty() {
        result?;
    } else {
        let error = result.unwrap_err();
        assert!(error.to_string().contains(&expected), "{error:#}");
    }
    Ok(())
}
