//! Disposable source repositories and native workstation peers keep deployment tests away from real targets.

use crate::process::{binary, peer_link, run};
use anyhow::Result;
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

/// Own a parent repository, its real machine submodule and an isolated upstream with local tool peers.
pub struct Repository {
    // Deletes source repositories, prepared artifacts and tool observations together.
    temporary: tempfile::TempDir,
    /// Parent checkout deliberately contains spaces to exercise command and URI quoting.
    pub root: PathBuf,
    /// Bare machine upstream used only by tests that exercise publication checks.
    pub upstream: PathBuf,
}

/// Execute Git in a selected disposable repository and preserve failure diagnostics.
pub fn git(root: &Path, args: &[&str]) -> Result<String> {
    let bytes = run(Command::new("git").arg("-C").arg(root).args(args), None)?.checked()?;
    Ok(String::from_utf8(bytes)?.trim().to_owned())
}

impl Repository {
    /// Create committed repositories and a real Git submodule without accessing the network.
    pub fn new() -> Result<Self> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().join("parent with spaces");
        let machine = temporary.path().join("machine");
        for checkout in [&root, &machine] {
            fs::create_dir(checkout)?;
            git(checkout, &["init", "--quiet", "--initial-branch=main"])?;
            git(checkout, &["config", "user.name", "Fixture"])?;
            git(
                checkout,
                &["config", "user.email", "fixture@example.invalid"],
            )?;
            fs::write(checkout.join("README"), "initial\n")?;
            fs::write(checkout.join("flake.lock"), "{}\n")?;
            fs::write(checkout.join(".gitignore"), ".airlock-logs/\n/target/\n")?;
            git(checkout, &["add", "."])?;
            git(checkout, &["commit", "-qm", "Initial"])?;
        }
        let upstream = temporary.path().join("upstream.git");
        git(
            &machine,
            &[
                "clone",
                "--quiet",
                "--bare",
                machine.to_str().unwrap(),
                upstream.to_str().unwrap(),
            ],
        )?;
        git(
            &root,
            &[
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "add",
                "--quiet",
                upstream.to_str().unwrap(),
                "airlock-machine",
            ],
        )?;
        git(&root, &["commit", "-qam", "Pin machine"])?;
        let machine = root.join("airlock-machine");
        git(&machine, &["config", "user.name", "Fixture"])?;
        git(
            &machine,
            &["config", "user.email", "fixture@example.invalid"],
        )?;

        let tools = temporary.path().join("tools");
        fs::create_dir(&tools)?;
        for name in [
            "cargo",
            "nix",
            "nix-store",
            "ssh",
            "sudo",
            "bash",
            "stat",
            "systemd-run",
            "native-dom0",
            "cat",
        ] {
            peer_link(&tools, name)?;
        }
        let bash = run(Command::new("sh").args(["-c", "command -v bash"]), None)?.checked()?;
        let bash = String::from_utf8(bash)?.trim().to_owned();
        let fixture = Self {
            temporary,
            root,
            upstream,
        };
        let cat = run(Command::new("sh").args(["-c", "command -v cat"]), None)?.checked()?;
        let cat = String::from_utf8(cat)?.trim().to_owned();
        fixture.configure(json!({"bash": bash, "cat": cat}))?;
        Ok(fixture)
    }

    /// Resolve auxiliary files outside the committed parent and machine checkouts.
    pub fn path(&self, name: &str) -> PathBuf {
        self.temporary.path().join(name)
    }

    /// Replace finite peer responses while preserving the host shell selected before PATH redirection.
    pub fn configure(&self, mut value: Value) -> Result<()> {
        if let Ok(bytes) = fs::read(self.path("peer.json")) {
            let existing: Value = serde_json::from_slice(&bytes)?;
            for key in ["bash", "cat"] {
                if value.get(key).is_none() {
                    value[key] = existing[key].clone();
                }
            }
        }
        fs::write(self.path("peer.json"), serde_json::to_vec(&value)?)?;
        Ok(())
    }

    /// Give a child local tool peers and explicitly select a private development store.
    pub fn environment(&self, command: &mut Command) {
        let mut paths = vec![self.path("tools")];
        paths.extend(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        ));
        command.env("PATH", std::env::join_paths(paths).unwrap());
        command.env("AIRLOCK_TEST_WORKSTATION", self.temporary.path());
        // Preparation now maintains a real compiler mirror even with an inert
        // Cargo peer. Keep that output outside both committed fixture checkouts.
        command.env("CARGO_TARGET_DIR", self.path("cargo-target"));
        command.env("AIRLOCK_NIX_CONFIGURED", "1");
        command.env(
            "NIX_CONFIG",
            format!(
                "store = {path}",
                path = self.path("fixture-nix-root").display()
            ),
        );
        command.env("AIRLOCK_PREPARED_CACHE", self.path("prepared"));
    }

    /// Invoke the prepared workstation CLI with an explicit source root from any working directory.
    pub fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(binary("AIRLOCK_DEV_BIN", "airlock-dev"));
        command.arg("--repository-root").arg(&self.root).args(args);
        self.environment(&mut command);
        command
    }

    /// Decode durable peer call observations, returning no calls after an early rejection.
    pub fn calls(&self, name: &str) -> Result<Vec<Value>> {
        let path = self.path(&format!("{name}.jsonl"));
        if !path.exists() {
            return Ok(Vec::new());
        }
        fs::read_to_string(path)?
            .lines()
            .map(|line| Ok(serde_json::from_str(line)?))
            .collect()
    }

    /// Advance the machine commit and its parent gitlink without publishing to the fixture upstream.
    pub fn advance_machine(&self) -> Result<String> {
        let machine = self.root.join("airlock-machine");
        git(&machine, &["switch", "--quiet", "-c", "feature"])?;
        fs::write(machine.join("README"), "unpublished feature\n")?;
        git(&machine, &["commit", "-qam", "Feature"])?;
        git(&self.root, &["commit", "-qam", "Pin feature"])?;
        git(&machine, &["rev-parse", "HEAD"])
    }
}
