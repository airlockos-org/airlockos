//! Explicit shared-closure generation, isolation, retention and rollback scenarios through upstream adapters.

#[path = "closure/generations.rs"]
mod generations;

#[path = "closure/probes.rs"]
mod probes;

#[path = "closure/report.rs"]
mod report;

#[path = "closure/scenario.rs"]
mod scenario;

#[path = "closure/settings.rs"]
mod settings;

use super::common::{self, Session};
use anyhow::{Context, Result};
use serde_json::Value;
use settings::Scenario;
use std::path::PathBuf;

/// Map a logical artifact through the explicitly selected private workstation store when present.
fn physical(source: &str) -> PathBuf {
    if std::env::var("AIRLOCK_USE_HOST_NIX_STORE").as_deref() != Ok("1")
        && source.starts_with("/nix/store/")
        && let Some(root) =
            std::env::var_os("AIRLOCK_NIX_ROOT").filter(|root| !root.is_empty() && root != "/")
    {
        return PathBuf::from(root).join(source.trim_start_matches('/'));
    }
    source.into()
}

/// Require one JSON field rather than accepting null as an identity or a zero count.
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .context(format!("missing {key} in shared-store report"))
}

/// Run the explicitly selected generation/isolation scenario; ordinary tests exercise inert peers only.
pub(super) fn execute() -> Result<()> {
    let scenario = Scenario::from_environment()?;
    let mut session = Session::new("nix-closure-domain-smoke", None, false)?;
    let mut record = scenario.record();
    let result = scenario.run(&mut session, &mut record);

    report::diagnostics(&mut session, &scenario.domain, &scenario.peer);
    report::evidence(&session, &mut record)?;
    session.finish(&result, record)?;
    result
}
