//! Explicit disposable nested-VM development commands; never installed into production guests.

mod image;

mod run;

mod warm;

mod smoke;

mod baseline;

mod evidence;

use crate::{environment, support};
use airlock_nix_core::runtime::process::{self, OwnedChild};
use anyhow::{Context as AnyhowContext, Result, ensure};
use clap::Subcommand;
use serde_json::Value;
use std::{
    ffi::OsString,
    fs::{self, File},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

/// Explicit workstation operations replacing the nested-VM shell entry points.
#[derive(Subcommand)]
pub(crate) enum Action {
    /// Resolve a stable immutable image output and publish its result link.
    Image {
        /// Image attribute, defaulting to the configuration development image.
        attribute: Option<String>,
        /// Optional result-link override.
        link: Option<PathBuf>,
    },
    /// Launch the configured disposable QEMU VM in the foreground.
    Run,
    /// Connect to the loopback development SSH endpoint.
    Ssh {
        /// SSH arguments forwarded without local shell interpretation.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        arguments: Vec<OsString>,
    },
    /// Import explicitly built tools into a running disposable nested VM.
    Sync,
    /// Run the selected nested live smoke scenarios.
    Smoke,
    /// Prepare or reuse an immutable, cleanly shut down VM baseline.
    Baseline,
    /// Stage and boot a new host generation using one stable writable overlay.
    BootFlow,
}

/// Resolve nonempty string overrides with the original installed defaults.
fn setting(key: &str, fallback: &str) -> String {
    std::env::var(key)
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| fallback.into())
}

/// Read a path override without interpreting its bytes as shell syntax.
fn path(key: &str, fallback: impl AsRef<Path>) -> PathBuf {
    std::env::var_os(key)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| fallback.as_ref().into())
}

/// Reject invalid toggle spellings before starting live work.
fn toggle(key: &str, fallback: bool) -> Result<bool> {
    match setting(key, if fallback { "1" } else { "0" }).as_str() {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        _ => anyhow::bail!("invalid {key} toggle"),
    }
}

/// Read a bounded integer setting used for a deadline or retention limit.
fn number(key: &str, fallback: u64) -> Result<u64> {
    setting(key, &fallback.to_string())
        .parse()
        .with_context(|| format!("invalid {key}"))
}

/// Fixed test evidence locations selected only by the explicit caller.
struct Context {
    /// Parent source checkout, independent of the caller's working directory.
    root: PathBuf,
    /// Selected local evidence directory.
    logs: PathBuf,
}

impl Context {
    /// Load the already selected workstation environment and evidence directory.
    fn new(root: &Path) -> Result<Self> {
        let logs = path("AIRLOCK_LOG_DIR", root.join(".airlock-logs"));
        fs::create_dir_all(&logs)?;
        Ok(Self {
            root: root.into(),
            logs,
        })
    }

    /// Reinvoke a native subcommand with exact arguments and the same source checkout.
    fn native(&self, args: &[&str]) -> Result<Command> {
        let mut command = Command::new(std::env::current_exe()?);
        command.arg("--repository-root").arg(&self.root).args(args);
        Ok(command)
    }

    /// Run Nix through the established local-machine-source wrapper.
    fn nix(&self, args: &[&str]) -> Result<Command> {
        self.native(&[["nix"].as_slice(), args].concat())
    }

    /// Execute an immutable store program using the existing private-store adapter.
    fn store(&self, program: &Path) -> Result<Command> {
        let mut command = self.native(&["environment", "run-store"])?;
        command.arg(program);
        Ok(command)
    }

    /// Construct only loopback test SSH/SCP transport; this is never a production transport.
    fn connection(&self, scp: bool) -> Result<Command> {
        let mut command = self.nix(&[
            "shell",
            "nixpkgs#sshpass",
            "-c",
            "sshpass",
            "-e",
            if scp { "scp" } else { "ssh" },
        ])?;
        command.env("SSHPASS", setting("AIRLOCK_VM_SSH_PASSWORD", "airlock"));
        command.args([
            "-F",
            "/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "NumberOfPasswordPrompts=1",
            "-o",
            "PubkeyAuthentication=no",
            if scp { "-P" } else { "-p" },
            &setting("AIRLOCK_VM_SSH_PORT", "2222"),
        ]);
        if !scp {
            command.arg(format!(
                "{user}@127.0.0.1",
                user = setting("AIRLOCK_VM_SSH_USER", "airlock")
            ));
        }
        Ok(command)
    }

    /// Execute one quoted guest command; orchestration and conditionals stay in Rust.
    fn remote(&self, args: &[&str]) -> Result<String> {
        let joined = args
            .iter()
            .map(|word| support::quote(word))
            .collect::<Vec<_>>()
            .join(" ");
        support::text(self.connection(false)?.arg(joined))
    }

    /// Transfer one file with upstream SCP, preserving failure status.
    fn send(&self, source: &Path, destination: &str) -> Result<()> {
        support::output(self.connection(true)?.arg(source).arg(format!(
            "{user}@127.0.0.1:{destination}",
            user = setting("AIRLOCK_VM_SSH_USER", "airlock")
        )))?;
        Ok(())
    }

    /// Build one declared attribute, retaining the existing explicit build logs.
    fn build(&self, attribute: &str, link: Option<&Path>) -> Result<String> {
        let mut command = self.nix(&[
            "build",
            &format!("{root}#{attribute}", root = self.root.display()),
            "--print-out-paths",
            "--print-build-logs",
            "--show-trace",
        ])?;
        if let Some(link) = link {
            command.arg("--out-link").arg(link);
        } else {
            command.arg("--no-link");
        }
        let output = support::text(&mut command)?;
        let source = output
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .context("Nix build did not return an output path")?;
        ensure!(
            source.starts_with("/nix/store/"),
            "unexpected Nix output path"
        );
        Ok(source.into())
    }

    /// Record informational JSON evidence atomically.
    fn save(&self, name: &str, value: &Value) -> Result<()> {
        support::atomic(&self.logs.join(name), &serde_json::to_vec_pretty(value)?)
    }

    /// Copy remote evidence without allowing a missing diagnostic to change the test result.
    fn collect(&self, source: &str, name: &str) {
        if let Ok(text) = self.remote(&["sudo", "-n", "cat", source]) {
            let _ = fs::write(self.logs.join(name), text);
        }
    }
}

/// Stream large NAR/archive transfers through files rather than bounded text captures.
fn files(command: &mut Command, input: Option<&Path>, output: &Path) -> Result<()> {
    let diagnostics = output.with_extension("stderr.log");
    let mut child = OwnedChild(
        command
            .stdin(match input {
                Some(input) => Stdio::from(File::open(input)?),
                None => Stdio::null(),
            })
            .stdout(File::create(output)?)
            .stderr(File::create(&diagnostics)?)
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(14400);
    loop {
        if let Some(status) = child.0.try_wait()? {
            ensure!(
                status.success(),
                "transfer failed ({status}); see {diagnostics}",
                diagnostics = diagnostics.display()
            );
            return Ok(());
        }
        ensure!(Instant::now() < deadline, "file transfer timed out");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Safely replace only a symlink or a plain file, never an actual directory.
fn link(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination.parent().context("result link parent")?)?;
    if let Ok(metadata) = fs::symlink_metadata(destination) {
        ensure!(
            !metadata.is_dir(),
            "refusing to replace a directory: {destination}",
            destination = destination.display()
        );
        fs::remove_file(destination)?;
    }
    std::os::unix::fs::symlink(source, destination)?;
    Ok(())
}

/// Keep native operation selection explicit; installation never launches QEMU or SSH.
pub(crate) fn execute(root: &Path, action: Action) -> Result<u8> {
    let context = Context::new(root)?;
    match action {
        Action::Image { attribute, link } => println!(
            "{source}",
            source = image::resolve(&context, attribute.as_deref(), link.as_deref())?.display()
        ),
        Action::Run => return run::execute(&context),
        Action::Ssh { arguments } => {
            return Ok(context
                .connection(false)?
                .args(arguments)
                .status()?
                .code()
                .unwrap_or(1)
                .try_into()?);
        }
        Action::Sync => warm::execute(&context)?,
        Action::Smoke => smoke::execute(&context)?,
        Action::Baseline => baseline::execute(&context)?,
        Action::BootFlow => baseline::boot_flow(&context)?,
    }
    Ok(0)
}
