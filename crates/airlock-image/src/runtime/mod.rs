//! Prepare initial VM state without contacting a live Qubes daemon.

pub(crate) mod model;

mod plan;

pub(crate) mod qubes;

pub(crate) mod xml;

use model::{Topology, validate};

use crate::support::{atomic_json, json, read, run};
use anyhow::{Result, ensure};
use clap::Parser;
use plan::{plan, storage};
use serde_json::json;
use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

const POOL: &str = "/var/lib/airlock/closure-store";

#[derive(Parser)]
#[command(about = "Prepare initial Qubes runtime state offline", version)]
struct Args {
    // Declarative VM definitions already evaluated by Nix.
    topology: PathBuf,
    // Prepared immutable store accessed during image construction.
    pool: PathBuf,
    // Fresh output directory; an existing output is never overwritten.
    output: PathBuf,
}

pub(crate) fn main() -> Result<()> {
    let args = Args::parse();
    let inputs = airlock_machine_core::boot::BootInputs::new(json(&args.topology)?)?;
    let topology: Topology = serde_json::from_value(inputs.raw().clone())?;
    validate(&topology)?;
    ensure!(
        !args.output.try_exists()? && !args.output.is_symlink(),
        "runtime output must not already exist"
    );

    let handoff: serde_json::Value = serde_json::from_str(&crate::support::output(
        Command::new("airlock-dom0-service")
            .args(["storage", "image", "verify-handoff"])
            .arg(&args.topology)
            .arg(&args.pool),
    )?)?;
    ensure!(
        handoff["schema"] == "airlock.boot-handoff.v1" && handoff["status"] == "passed",
        "invalid prepared boot handoff"
    );

    let plans = topology
        .domains
        .iter()
        .map(|(name, domain)| plan(name, domain, &args.pool))
        .collect::<Result<Vec<_>>>()?;

    for plan in &plans {
        ensure!(
            handoff["generations"][&plan.name]
                .as_u64()
                .map(|generation| generation.to_string())
                .as_deref()
                == plan
                    .features
                    .get("airlock-store-generation")
                    .map(String::as_str),
            "image plan differs from checked boot generation: {name}",
            name = plan.name
        );
    }

    fs::create_dir_all(
        args.output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?;
    fs::create_dir(&args.output)?;
    let root = fs::canonicalize(&args.output)?.join("qubes");
    fs::create_dir_all(root.join("vm-kernels"))?;
    for (name, kernel) in &topology.kernels {
        let target = root.join("vm-kernels").join(name);
        ensure!(kernel.source.is_dir(), "kernel bundle is not a directory");
        fs::create_dir(&target)?;
        run(Command::new("cp")
            .args(["-a", "--"])
            .arg(kernel.source.join("."))
            .arg(&target))?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755))?;
        let mut marker = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(target.join("MANAGED_BY_AIRLOCK"))?;
        marker.write_all(
            format!(
                "source={}\nschema=airlock.qubes-kernel.v1\n",
                kernel.source.display()
            )
            .as_bytes(),
        )?;
    }

    let snapshots = qubes::assemble(&root, &plans, &topology.prefs)?;

    for vm in &plans {
        let observed = &snapshots[&vm.name];
        ensure!(
            observed["label"] == vm.label,
            "label did not survive reload: {}",
            vm.name
        );
        if let Some(color) = &vm.color {
            ensure!(
                observed["color"]
                    .as_str()
                    .is_some_and(|c| c.to_lowercase().replace('#', "0x") == color.to_lowercase()),
                "custom label colour did not survive reload: {}",
                vm.name
            );
        }
        if vm.class == "HermitVM" {
            ensure!(
                observed["snapshot"]["volumes"]
                    .as_array()
                    .is_some_and(|volumes| volumes.is_empty()),
                "Hermit acquired Linux storage"
            );
            continue;
        }
        ensure!(
            observed["root_source"] == vm.features["airlock-root-source"],
            "root identity did not survive reload: {}",
            vm.name
        );
        storage(
            &["domain", "verify-snapshot", &vm.name, "--request", "-"],
            &json!({"snapshot":observed["snapshot"],"volumes":vm.volumes,"source":vm.source}),
        )?;

        let selection = args
            .output
            .join("pool-selections/domains")
            .join(format!("{name}-runtime-store", name = vm.name));
        fs::create_dir_all(&selection)?;
        std::os::unix::fs::symlink(
            format!("generations/{}", vm.features["airlock-store-generation"]),
            selection.join("current"),
        )?;
    }

    let xml = root.join("qubes.xml");
    let text = String::from_utf8(read(&xml, 32 * 1024 * 1024)?)?;
    crate::support::atomic(&xml, &self::xml::installed(&text, &root)?)?;

    atomic_json(
        &args.output.join("receipt.json"),
        &json!({"schema":"airlock.prepared-runtime.v2","domains":topology.domains.keys().collect::<Vec<_>>(),"boot_handoff":handoff,"hardware_assignments":"deferred-to-boot"}),
    )
}
