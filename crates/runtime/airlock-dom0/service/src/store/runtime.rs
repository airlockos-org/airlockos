//! Kernel observations preserve runtime pins unless a complete query establishes absence.
//! Callers hold admission exclusion across observing, tracing and releasing references.

use super::{fs::*, tracing};
use airlock_deployment_core::retention::runtime::{Observation, Phase, ReleaseRequest};
use airlock_deployment_core::retention::tracing::Extent;
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{fs, path::Path, process::Command, time::Duration};

/// Required identity, lifecycle and physical pins from one validated runtime record.
pub(super) struct Reference {
    /// Original mapper identity, equal to the record's filename.
    pub(super) name: String,
    /// Known lifecycle; an unknown state refuses maintenance.
    pub(super) phase: Phase,
    /// Physical ranges retained even when logical generations no longer exist.
    pub(super) pins: Vec<Extent>,
}

/// Airlock names use the subset that dmsetup reports without escaping or whitespace loss.
fn mapper_name(name: &str) -> Result<&str> {
    ensure!(
        name.starts_with("airlock-")
            && name.len() < 128
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "_.+-".contains(c)),
        "invalid Airlock mapper name"
    );
    Ok(name)
}

/// Reject unknown schemas, lifecycles and filename/mapper disagreements before using any pins.
pub(super) fn load(root: &Path, path: &Path) -> Result<Reference> {
    pool_path(root, path)?;
    let value: Value = read(path)?;
    ensure!(
        value["schema"] == "airlock.closure-store.runtime-view-ref.v1",
        "invalid runtime reference"
    );
    let name = text(&value, "dm_name")?;
    mapper_name(&name)?;
    ensure!(
        path.file_name().and_then(|s| s.to_str()) == Some(format!("{name}.json").as_str()),
        "runtime reference identity mismatch"
    );
    let phase =
        Phase::decode(&text(&value, "status")?).context("unknown runtime reference phase")?;
    let pins = tracing::extents(
        value["physical_references"]
            .as_array()
            .context("runtime reference lacks physical pins")?,
    )?;
    ensure!(!pins.is_empty(), "runtime reference has no physical pins");

    Ok(Reference { name, phase, pins })
}

/// Decode the complete report, rejecting partial rows, diagnostics and ambiguous identities.
fn names(bytes: &[u8]) -> Result<Vec<String>> {
    let report = std::str::from_utf8(bytes)?;
    // Upstream _process_all emits this exact message for a successful empty inventory.
    // Rows include numeric fields, so a mapping with that name cannot mimic the sentinel.
    if report == "No devices found\n" || report.is_empty() {
        return Ok(Vec::new());
    }
    ensure!(report.ends_with('\n'), "incomplete mapper inventory");
    let mut output = Vec::new();
    for line in report.lines() {
        let fields: Vec<_> = line.split('|').map(str::trim).collect();
        ensure!(fields.len() == 3, "invalid mapper inventory row");
        let name = fields[0];
        ensure!(
            !name.is_empty() && !name.chars().any(|c| c.is_control() || c == '/'),
            "invalid mapper inventory name"
        );
        ensure!(
            fields[1].parse::<u32>()? > 0 && fields[2].parse::<u32>().is_ok(),
            "invalid mapper inventory device number"
        );
        ensure!(
            !output.iter().any(|prior| prior == name),
            "duplicate mapper inventory name"
        );
        output.push(name.to_owned());
    }
    Ok(output)
}

/// Enumerate every mapping; a failed point query cannot distinguish absence from an ioctl error.
fn inventory() -> Result<Vec<String>> {
    let output = airlock_nix_core::runtime::process::run(
        Command::new(tool("dmsetup", "AIRLOCK_DMSETUP"))
            .args([
                "info",
                "--columns",
                "--noheadings",
                "--unquoted",
                "--manglename",
                "hex",
                "--separator",
                "|",
                "--options",
                "name,major,minor",
            ])
            .env("LC_ALL", "C"),
        None,
        Some(Duration::from_secs(10)),
    )?;
    ensure!(output.status.success(), "mapper inventory query failed");
    ensure!(
        output.stderr.is_empty(),
        "mapper inventory contains diagnostics"
    );
    names(&output.stdout)
}

/// Failed spawn, timeout, nonzero exit or invalid output never supplies an empty inventory.
pub(super) fn observe(name: &str) -> Observation {
    let inventory = match mapper_name(name).and_then(|_| inventory()) {
        Ok(names) => Some(names),
        Err(error) => {
            eprintln!("cannot establish mapper presence for {name}: {error:#}");
            None
        }
    };
    Observation::from_inventory(name.to_owned(), inventory)
}

/// Consume the original permission; no separate pool or mapper name can change the unlink target.
pub(super) fn release(request: ReleaseRequest) -> Result<()> {
    let root = Path::new(request.pool());
    let name = mapper_name(request.name())?;
    let directory = root.join("runtime");
    let path = directory.join(format!("{name}.json"));
    pool_path(root, &path)?;
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    sync_dir(&directory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use airlock_deployment_core::retention::runtime::Context as ReleaseContext;

    #[test]
    fn complete_inventory_rows_and_explicit_empty_reports() {
        assert_eq!(
            names(b"  airlock-one|253|0\n  other|253|1\n").unwrap(),
            ["airlock-one", "other"]
        );
        assert!(names(b"No devices found\n").unwrap().is_empty());
        assert!(names(b"").unwrap().is_empty());
        for invalid in [
            b"airlock-one|253|0".as_slice(),
            b"broken\n",
            b"\n",
            b"airlock-one|0|0\n",
            b"airlock-one|253|bad\n",
            b"|253|0\n",
            b"airlock-one|253|0\nairlock-one|253|1\n",
            b"\xff|253|0\n",
            b"No devices found\nairlock-one|253|0\n",
        ] {
            assert!(names(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn release_consumes_original_coordinates_and_never_removes_a_directory() -> Result<()> {
        let fixture = tempfile::tempdir()?;
        let pool = fixture.path().join("pool");
        let other = fixture.path().join("other");
        for root in [&pool, &other] {
            fs::create_dir_all(root.join("runtime"))?;
            fs::write(root.join("runtime/airlock-one.json"), b"original")?;
            fs::write(root.join("runtime/airlock-two.json"), b"sibling")?;
        }
        for _ in 0..2 {
            let request = Observation::from_inventory("airlock-one".into(), Some(vec![]))
                .release(
                    pool.to_str().unwrap().into(),
                    Phase::Active,
                    ReleaseContext::Reconciliation,
                )
                .unwrap();
            release(request)?;
        }
        assert!(!pool.join("runtime/airlock-one.json").exists());
        assert_eq!(fs::read(pool.join("runtime/airlock-two.json"))?, b"sibling");
        assert_eq!(
            fs::read(other.join("runtime/airlock-one.json"))?,
            b"original"
        );

        fs::create_dir(pool.join("runtime/airlock-one.json"))?;
        fs::write(pool.join("runtime/airlock-one.json/keep"), b"preserve")?;
        let request = Observation::from_inventory("airlock-one".into(), Some(vec![]))
            .release(
                pool.to_str().unwrap().into(),
                Phase::Active,
                ReleaseContext::Reconciliation,
            )
            .unwrap();
        assert!(release(request).is_err());
        assert_eq!(
            fs::read(pool.join("runtime/airlock-one.json/keep"))?,
            b"preserve"
        );
        Ok(())
    }
}
