//! Explicit configuration-VM preflight, source staging, apply and post-apply checks in native Rust.

#[path = "config/guests.rs"]
mod guests;

#[path = "config/host.rs"]
mod host;

#[path = "config/post_apply.rs"]
mod post_apply;

#[path = "config/report.rs"]
mod report;

#[path = "config/scenario.rs"]
mod scenario;

#[path = "config/settings.rs"]
mod settings;

#[path = "config/verification.rs"]
mod verification;

use super::common::{self, Session};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use settings::Scenario;
use std::fs;

/// Append a typed smoke source and inputs as data, then commit them with existing guest tools.
pub(super) fn stage(
    session: &mut Session,
    guest: &str,
    inputs: &Value,
    message: &str,
) -> Result<()> {
    let user = common::setting("AIRLOCK_QUBE_USER", "user");
    ensure!(
        !user.is_empty()
            && user
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte)),
        "invalid smoke user"
    );
    let repo = format!("/home/{user}/airlock-config");
    let source = common::path("AIRLOCK_CONFIG_SMOKE_SOURCE", "");
    common::save(
        &session.file("config-vms-config-staging-update.json"),
        &json!({"source":source,"inputs":inputs,"commit_message":message}),
    )?;
    ensure!(
        source.is_file(),
        "missing Rust candidate source for smoke update"
    );
    session.remote(
        guest,
        "tee",
        &[&format!("{repo}/src/main.rs")],
        Some(fs::read(&source)?),
        "config-vms-staging-source.log",
    )?;
    session.remote(
        guest,
        "tee",
        &[&format!("{repo}/smoke-inputs.json")],
        Some(serde_json::to_vec(inputs)?),
        "config-vms-staging-inputs.log",
    )?;
    session.remote(
        guest,
        "nix",
        &[
            "--extra-experimental-features",
            "nix-command",
            "--extra-experimental-features",
            "flakes",
            "flake",
            "lock",
            "--impure",
            "--offline",
            &format!("path:{repo}"),
        ],
        None,
        "config-vms-config-staging-update.log",
    )?;
    session.remote(
        guest,
        "git",
        &[
            "-C",
            &repo,
            "add",
            "src",
            "Cargo.toml",
            "Cargo.lock",
            ".cargo",
            "config-inputs.json",
            "flake.lock",
            "smoke-inputs.json",
        ],
        None,
        "config-vms-staging-add.log",
    )?;
    session.remote(
        guest,
        "git",
        &[
            "-C",
            &repo,
            "-c",
            "user.name=Airlock Config Smoke",
            "-c",
            "user.email=airlock-config-smoke@localhost",
            "commit",
            "-m",
            message,
        ],
        None,
        "config-vms-config-staging-update.log",
    )?;
    Ok(())
}

/// Run the requested mode and retain diagnostics even when a phase fails.
pub(super) fn execute() -> Result<()> {
    let mut session = Session::new("config-vms-smoke", None, false)?;
    let scenario = Scenario::from_environment();
    let mut record = scenario.record();
    let result = scenario.run(&mut session, &mut record);

    report::diagnostics(&mut session, &scenario)?;
    report::evidence(&session, &scenario, &mut record);
    session.finish(&result, record)?;
    result
}
