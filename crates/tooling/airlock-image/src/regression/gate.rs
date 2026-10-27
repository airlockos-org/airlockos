//! Exercise the actual offline acceptance command with inert tools and private source snapshots.

use airlock_tests::{
    dialogue::Dialogue,
    process::{binary, peer_link, run},
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

/// Keep source identity, fake store inputs, evidence and publication destinations in one owned tree.
struct Gate {
    // Removes every fixture input and output when the scenario finishes.
    temporary: tempfile::TempDir,
    // Logical closure identity accepted by the native input parser.
    closure: String,
    // Logical executable selected from the physical input store.
    nix: String,
}

impl Gate {
    /// Commit a minimal source and prepare its generated configuration without evaluating Nix.
    fn new() -> Result<Self> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path();
        fs::create_dir(root.join("tools"))?;
        for name in ["nix", "nix-store", "bwrap", "image-builder"] {
            peer_link(&root.join("tools"), name)?;
        }
        fs::create_dir(root.join("machine"))?;
        fs::write(
            root.join("machine/source.rs"),
            "// committed declarations\n",
        )?;
        fs::write(root.join("machine/flake.lock"), "{}\n")?;
        let git = |args: &[&str]| -> Result<Vec<u8>> {
            run(
                Command::new("git")
                    .arg("-C")
                    .arg(root.join("machine"))
                    .args(args),
                None,
            )?
            .checked()
        };
        git(&["init", "-q"])?;
        git(&["add", "."])?;
        git(&[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ])?;
        let revision = String::from_utf8(git(&["rev-parse", "HEAD"])?)?
            .trim()
            .to_owned();

        let module = root.join("prepared/generated/machine/usr-home.nix");
        fs::create_dir_all(module.parent().unwrap())?;
        let artifact = rusix::nixos::compile_module(&rusix::nixos::NixosModule::empty())
            .map_err(|error| anyhow::anyhow!(error.render(Path::new("."))))?;
        fs::write(module, artifact.module.source)?;
        fs::copy(
            root.join("machine/flake.lock"),
            root.join("prepared/flake.lock"),
        )?;
        fs::write(
            root.join("prepared/airlock-source.json"),
            serde_json::to_vec(&json!({"revision": revision, "dirty": false}))?,
        )?;

        let logical =
            |hash: &str, name: &str| format!("/nix/store/{hash}-{name}", hash = hash.repeat(32));
        let closure = logical("a", "closure");
        let flake = logical("b", "flake");
        let nix = logical("c", "nix");
        let bash = logical("f", "bash-5.3");
        let physical = |logical: &str| root.join("store").join(logical.trim_start_matches('/'));
        fs::create_dir_all(physical(&closure))?;
        fs::write(
            physical(&closure).join("store-paths"),
            format!("{flake}\n{nix}\n{bash}\n"),
        )?;
        fs::write(
            physical(&closure).join("registration"),
            "registered closure\n",
        )?;
        fs::create_dir_all(physical(&flake))?;
        for executable in [format!("{nix}/bin/nix"), format!("{bash}/bin/bash")] {
            let path = physical(&executable);
            fs::create_dir_all(path.parent().unwrap())?;
            fs::write(path, "fixture executable")?;
        }
        let lock_hash = format!(
            "{hash:x}",
            hash = Sha256::digest(fs::read(root.join("machine/flake.lock"))?)
        );
        fs::write(
            root.join("inputs.json"),
            serde_json::to_vec(&json!({
                "schema": "airlock.sys-agent-offline-inputs.v1",
                "revision": revision, "lock_hash": lock_hash, "inputs": {"nixpkgs": flake}
            }))?,
        )?;
        fs::write(root.join("seed.tar.gz"), b"committed machine source")?;
        Ok(Self {
            temporary,
            closure,
            nix,
        })
    }

    /// Resolve only paths below the owned fixture directory.
    fn path(&self, name: &str) -> PathBuf {
        self.temporary.path().join(name)
    }

    /// Run real acceptance logic while confining every tool's effects to the fixture.
    fn command(&self, image: bool) -> Command {
        self.command_extra(image, &[])
    }

    /// Keep acceptance options before the variadic image-builder argument boundary.
    fn command_extra(&self, image: bool, extra: &[&str]) -> Command {
        let mut command = Command::new(binary("AIRLOCK_IMAGE_CHECK_BIN", "airlock-image-check"));
        command.current_dir(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .parent()
                .unwrap(),
        );
        command.args(["--closure", &self.closure]);
        for (option, path) in [
            ("--machine", "machine"),
            ("--prepared-machine", "prepared"),
            ("--manifest", "inputs.json"),
            ("--seed-archive", "seed.tar.gz"),
            ("--source-store-root", "store"),
            ("--log-dir", "logs"),
            ("--cache-dir", "cache"),
            ("--temporary-root", ""),
        ] {
            command.arg(option).arg(self.path(path));
        }
        command.args(["--nix-bin", &format!("{nix}/bin/nix", nix = self.nix)]);
        command.env("AIRLOCK_TEST_IMAGE_GATE", self.temporary.path());
        let mut paths = vec![self.path("tools")];
        paths.extend(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        ));
        command.env("PATH", std::env::join_paths(paths).unwrap());
        command.args(extra);
        if image {
            command
                .arg("--image-command")
                .arg(self.path("tools/image-builder"));
            command.arg("--out-link").arg(self.path("image"));
        }
        command
    }

    /// Decode the persisted report independently of command exit status.
    fn report(&self) -> Result<Value> {
        Ok(serde_json::from_slice(&fs::read(
            self.path("logs/report.json"),
        )?)?)
    }

    /// Capture failures as well as successful receipts from the actual command.
    fn invoke(&self, image: bool, extra: &[&str]) -> Result<(bool, Value)> {
        let result = run(&mut self.command_extra(image, extra), None)?;
        if self.path("input-roots.json").exists() {
            let roots: Vec<(PathBuf, String)> =
                serde_json::from_slice(&fs::read(self.path("input-roots.json"))?)?;
            for (link, _) in roots {
                ensure!(
                    !link.parent().context("builder root directory")?.exists(),
                    "builder roots survived command exit"
                );
            }
        }
        let report = self.report().with_context(|| {
            format!(
                "gate output: {errors}",
                errors = String::from_utf8_lossy(&result.stderr)
            )
        })?;
        Ok((result.status.success(), report))
    }

    /// Count durable trial or image-builder calls without requiring a file on rejected requests.
    fn calls(&self, name: &str) -> Result<Vec<String>> {
        if !self.path(name).exists() {
            return Ok(Vec::new());
        }
        Ok(fs::read_to_string(self.path(name))?
            .lines()
            .map(str::to_owned)
            .collect())
    }
}

/// Successful evidence is reused only for identical inputs; corrupt receipts and changed seeds invalidate it.
#[test]
fn cached_acceptance_is_bound_to_exact_prepared_inputs() -> Result<()> {
    let gate = Gate::new()?;
    let (success, first) = gate.invoke(true, &[])?;
    assert!(success, "{first}");
    assert_eq!(first["cache"], "miss");
    assert_eq!(gate.calls("trials")?, ["etc-marker", "service-setting"]);
    assert!(gate.path("image").is_symlink());
    let roots: Vec<(PathBuf, String)> =
        serde_json::from_slice(&fs::read(gate.path("input-roots.json"))?)?;
    let closure = gate
        .path("store")
        .join(gate.closure.trim_start_matches('/'));
    let mut expected = fs::read_to_string(closure.join("store-paths"))?
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    expected.insert(0, gate.closure.clone());
    assert_eq!(
        roots
            .into_iter()
            .map(|(_, target)| target)
            .collect::<Vec<_>>(),
        expected
    );
    let build: Value = serde_json::from_str(&gate.calls("builds")?[0])?;
    assert!(build["seed"].as_str().unwrap().ends_with("/seed.tar.gz"));
    assert!(build["inputs"].as_str().unwrap().ends_with("/inputs.json"));
    assert_eq!(gate.invoke(true, &[])?.1["cache"], "hit");
    assert_eq!(gate.calls("trials")?.len(), 2);
    assert_eq!(gate.calls("builds")?.len(), 2);

    fs::write(gate.path("seed.tar.gz"), "changed prepared seed")?;
    let changed = gate.invoke(false, &[])?.1;
    assert_eq!(changed["cache"], "miss");
    fs::write(changed["receipt"].as_str().context("receipt")?, "{}")?;
    assert_eq!(gate.invoke(false, &[])?.1["cache"], "miss");
    let manifest = fs::read_to_string(gate.path("inputs.json"))?;
    fs::write(gate.path("inputs.json"), format!("{manifest} "))?;
    assert_eq!(gate.invoke(false, &[])?.1["cache"], "miss");
    assert_eq!(gate.calls("trials")?.len(), 8);
    Ok(())
}

/// Forced trials revoke old success before execution, retain diagnostics and prevent image publication on failure.
#[test]
fn forced_failure_revokes_old_receipt() -> Result<()> {
    let gate = Gate::new()?;
    let (success, report) = gate.invoke(false, &[])?;
    assert!(success);
    let receipt = PathBuf::from(report["receipt"].as_str().context("receipt")?);
    fs::write(gate.path("fail"), "")?;
    let (success, report) = gate.invoke(true, &["--force"])?;
    assert!(!success);
    assert_eq!(report["status"], "failed");
    assert!(!receipt.exists());
    assert!(gate.calls("builds")?.is_empty());
    /// Find preserved tool diagnostics beneath the per-trial evidence directory.
    fn diagnostic(path: &Path) -> Result<bool> {
        for entry in fs::read_dir(path)? {
            let path = entry?.path();
            if path.is_dir() {
                if diagnostic(&path)? {
                    return Ok(true);
                }
            } else if path
                .extension()
                .is_some_and(|extension| extension == "stderr")
                && fs::read_to_string(path)?.contains("trial failed")
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
    assert!(diagnostic(&gate.path("logs"))?);
    Ok(())
}

/// A partially failed root registration releases its links before returning and never starts trials.
#[test]
fn failed_input_rooting_releases_roots_before_trials() -> Result<()> {
    let gate = Gate::new()?;
    fs::write(gate.path("fail-roots"), "")?;
    let (success, report) = gate.invoke(true, &[])?;
    assert!(!success);
    assert!(
        report["error"]
            .as_str()
            .unwrap()
            .contains("input rooting failed")
    );
    assert!(gate.calls("trials")?.is_empty());
    assert!(gate.calls("builds")?.is_empty());
    assert!(!gate.path("image").is_symlink());
    Ok(())
}

/// Dirty sources, stale manifests and files changed after input capture cannot receive evidence or launch a build.
#[test]
fn changing_source_or_captured_inputs_stops_before_trials() -> Result<()> {
    for damage in ["dirty", "stale", "manifest", "paths"] {
        let gate = Gate::new()?;
        let expected = match damage {
            "dirty" => {
                fs::write(gate.path("machine/uncommitted"), "new work")?;
                "must be committed"
            }
            "stale" => {
                let mut manifest: Value =
                    serde_json::from_slice(&fs::read(gate.path("inputs.json"))?)?;
                manifest["revision"] = json!("0".repeat(40));
                fs::write(gate.path("inputs.json"), serde_json::to_vec(&manifest)?)?;
                "differs from machine revision"
            }
            _ => {
                let target = if damage == "manifest" {
                    gate.path("inputs.json")
                } else {
                    gate.path("store")
                        .join(gate.closure.trim_start_matches('/'))
                        .join("store-paths")
                };
                fs::write(gate.path("mutate"), target.as_os_str().as_encoded_bytes())?;
                "changed during offline acceptance"
            }
        };
        let (success, report) = gate.invoke(true, &[])?;
        assert!(!success, "{damage}");
        assert!(
            report["error"].as_str().unwrap().contains(expected),
            "{damage}: {report}"
        );
        assert!(gate.calls("trials")?.is_empty());
        assert!(gate.calls("builds")?.is_empty());
    }
    Ok(())
}

/// A build cannot publish when its captured inputs change, even after successful offline trials.
#[test]
fn changed_build_snapshot_cannot_publish() -> Result<()> {
    let gate = Gate::new()?;
    fs::write(gate.path("tamper"), "")?;
    let (success, report) = gate.invoke(true, &[])?;
    assert!(!success);
    assert!(
        report["error"]
            .as_str()
            .unwrap()
            .contains("snapshot changed")
    );
    assert!(!gate.path("image").is_symlink());
    Ok(())
}

/// Kernel-backed evidence locks identify their owner rather than allowing concurrent cache replacement.
#[test]
fn held_evidence_lock_reports_its_owner() -> Result<()> {
    let gate = Gate::new()?;
    assert!(gate.invoke(false, &[])?.0);
    let lock = fs::read_dir(gate.path("cache"))?
        .find_map(|entry| {
            let path = entry.ok()?.path();
            (path.extension()?.to_str()? == "lock").then_some(path)
        })
        .context("evidence lock")?;
    let held = File::options().read(true).write(true).open(&lock)?;
    rustix::fs::flock(&held, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
    let (success, report) = gate.invoke(false, &[])?;
    assert!(!success);
    assert!(report["error"].as_str().unwrap().contains("owns"));
    let owner: Value = serde_json::from_slice(&fs::read(lock)?)?;
    assert_eq!(owner["entity"], "airlock-image-check");
    assert!(!owner["reason"].as_str().unwrap().is_empty());
    Ok(())
}

/// Output locking excludes contenders across independent log/cache directories and preserves the owner's timeout report.
#[test]
fn competing_image_runs_cannot_replace_owner_evidence() -> Result<()> {
    let gate = Gate::new()?;
    fs::write(gate.path("sleep"), "")?;
    let mut owner = Dialogue::spawn(&mut gate.command_extra(true, &["--timeout", "2"]))?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while gate.calls("trials")?.is_empty() {
        ensure!(
            owner.running()? && Instant::now() < deadline,
            "owner never entered trial: {errors}",
            errors = owner.errors()?
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    for different_logs in [false, true] {
        let mut contender = gate.command(true);
        if different_logs {
            // Replace the original values instead of introducing duplicate CLI options.
            let args: Vec<_> = contender.get_args().map(|arg| arg.to_owned()).collect();
            let mut args = args;
            for (flag, target) in [("--log-dir", "other-logs"), ("--cache-dir", "other-cache")] {
                let index = args.iter().position(|arg| arg == flag).unwrap();
                args[index + 1] = gate.path(target).into_os_string();
            }
            let environments: Vec<_> = contender
                .get_envs()
                .map(|(key, value)| (key.to_owned(), value.map(|value| value.to_owned())))
                .collect();
            contender = Command::new(contender.get_program());
            contender.args(args);
            for (key, value) in environments {
                if let Some(value) = value {
                    contender.env(key, value);
                }
            }
        }
        let result = run(&mut contender, None)?;
        assert!(!result.status.success());
        let errors = String::from_utf8_lossy(&result.stderr);
        assert!(errors.to_lowercase().contains("locked"), "{errors}");
        assert!(errors.contains("airlock-image-check"), "{errors}");
    }
    assert!(!owner.finish()?.success());
    assert!(
        gate.report()?["error"]
            .as_str()
            .unwrap()
            .contains("timed out")
    );
    assert_eq!(gate.calls("trials")?, ["etc-marker"]);
    assert!(gate.calls("builds")?.is_empty());
    assert!(!gate.path("image").is_symlink());
    Ok(())
}

/// Ambiguous publication destinations are rejected before trials, while a changed alias retains the locked parent.
#[test]
fn publication_is_bound_to_one_locked_parent() -> Result<()> {
    let gate = Gate::new()?;
    for extra in [vec!["--out-link", "other"], vec!["--out-link=other"]] {
        let result = run(gate.command(true).args(extra), None)?;
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("--out-link"));
        assert!(gate.calls("trials")?.is_empty());
    }

    fs::create_dir(gate.path("first"))?;
    fs::create_dir(gate.path("second"))?;
    symlink(gate.path("first"), gate.path("alias"))?;
    fs::write(
        gate.path("retarget.json"),
        serde_json::to_vec(&json!({"alias": gate.path("alias"), "target": gate.path("second")}))?,
    )?;
    let mut command = gate.command(false);
    command
        .arg("--image-command")
        .arg(gate.path("tools/image-builder"));
    command.arg("--out-link").arg(gate.path("alias/image"));
    run(&mut command, None)?.checked()?;
    assert!(gate.path("first/image").is_symlink());
    assert!(!gate.path("second/image").exists());
    Ok(())
}
