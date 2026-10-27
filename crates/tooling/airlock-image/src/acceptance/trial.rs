//! Isolated trial stores expose only the selected, read-only builder inputs.

use super::change::TrialChange;
use super::{Args, Inputs, MODULE, TrialResult, input_reference, physical, store_root};
use crate::support::captured;
use airlock_nix_core::store_path::StorePath;
use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{Seek, SeekFrom},
    os::unix::{fs::symlink, process::CommandExt},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub(crate) fn prepare_store(
    store: &Path,
    source: &Path,
    paths: &BTreeSet<String>,
    registration: &str,
    flake_sources: &BTreeSet<String>,
) -> Result<()> {
    let target = store.join("nix/store");
    fs::create_dir_all(&target)?;
    for logical in paths {
        let original = physical(source, logical)?;
        let info = fs::symlink_metadata(&original)
            .with_context(|| format!("pinned input is absent from the build store: {logical}"))?;
        let staged = target.join(
            Path::new(logical)
                .file_name()
                .context("missing store name")?,
        );
        ensure!(
            !flake_sources.contains(logical) || original.is_dir(),
            "flake input is not a directory: {logical}"
        );
        if info.is_symlink() {
            symlink(fs::read_link(&original)?, staged)?;
        } else if info.is_dir() {
            fs::create_dir(staged)?;
        } else if info.is_file() {
            File::create(staged)?;
        } else {
            anyhow::bail!("unsupported pinned input type: {logical}");
        }
    }

    let result = captured(
        Command::new("nix-store")
            .arg("--store")
            .arg(store)
            .arg("--load-db"),
        Some(registration.as_bytes().to_vec()),
    )?;
    ensure!(
        result.status.success(),
        "trial store registration failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(())
}

pub(crate) fn checkout(
    machine: &Path,
    target: &Path,
    change: TrialChange,
    revision: &str,
) -> Result<()> {
    ensure!(
        !machine.join(".git").exists(),
        "offline trials require a prepared tree"
    );
    let identity = crate::support::json(&machine.join("airlock-source.json"))?;
    ensure!(
        identity["revision"] == revision,
        "prepared trial source revision mismatch"
    );
    let mut archive = tempfile::tempfile()?;
    {
        let mut builder = tar::Builder::new(&mut archive);
        builder.follow_symlinks(false);
        builder.append_dir_all(".", machine)?;
        builder.finish()?;
    }
    archive.seek(SeekFrom::Start(0))?;
    fs::create_dir(target)?;
    tar::Archive::new(archive).unpack(target)?;

    let module = target.join(MODULE);
    let baseline = module.with_file_name("usr-home-offline-baseline.nix");
    ensure!(
        !baseline.try_exists()? && !baseline.is_symlink(),
        "offline trial baseline already exists"
    );
    ensure!(
        module.is_file() && !module.is_symlink(),
        "offline trial module is not a regular prepared file"
    );
    fs::rename(&module, &baseline)?;
    fs::write(module, change.module()?)?;
    Ok(())
}

pub(crate) fn prepare_etc(target: &Path, source: &Path) -> Result<()> {
    fs::create_dir(target)?;
    for name in ["passwd", "group", "nsswitch.conf"] {
        fs::copy(source.join(name), target.join(name))?;
    }
    fs::write(target.join("hosts"), "127.0.0.1 localhost\n::1 localhost\n")?;
    fs::write(target.join("resolv.conf"), "")?;
    Ok(())
}

fn shell(root: &Path, paths: &BTreeSet<String>) -> Result<String> {
    for path in paths {
        let name = Path::new(path)
            .file_name()
            .context("store name")?
            .to_str()
            .context("non-UTF-8 store path")?;
        if name
            .get(33..)
            .and_then(|s| s.strip_prefix("bash-"))
            .is_some_and(|v| v.as_bytes().first().is_some_and(u8::is_ascii_digit))
        {
            let shell = format!("{path}/bin/bash");
            if physical(root, &shell)?.is_file() {
                return Ok(shell);
            }
        }
    }
    anyhow::bail!("the pinned builder closure lacks Bash for /bin/sh")
}

struct ChildGuard {
    // Retain an unreaped group leader while cancellation can still signal it.
    child: std::process::Child,
    // Whether wait has already released the PID, preventing later group signals.
    reaped: bool,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.reaped {
            if let Some(pid) = rustix::process::Pid::from_raw(self.child.id() as i32) {
                let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn logged(command: &mut Command, stdout: &Path, stderr: &Path, timeout: Duration) -> Result<()> {
    let child = command
        .stdin(Stdio::null())
        .stdout(File::create(stdout)?)
        .stderr(File::create(stderr)?)
        .process_group(0)
        .spawn()?;
    let mut owned = ChildGuard {
        child,
        reaped: false,
    };
    let pid =
        rustix::process::Pid::from_raw(owned.child.id() as i32).context("invalid trial PID")?;
    let deadline = Instant::now()
        .checked_add(timeout)
        .context("trial timeout is too large")?;
    loop {
        let exited = match rustix::process::waitid(
            rustix::process::WaitId::Pid(pid),
            rustix::process::WaitIdOptions::EXITED
                | rustix::process::WaitIdOptions::NOHANG
                | rustix::process::WaitIdOptions::NOWAIT,
        ) {
            Ok(value) => value.is_some(),
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        };
        if exited {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
            let status = owned.child.wait()?;
            owned.reaped = true;
            ensure!(
                status.success(),
                "offline build failed with {status}; see {}",
                stderr.display()
            );
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "offline build timed out after {}s; see {}",
            timeout.as_secs(),
            stderr.display()
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

pub(super) fn run(
    args: &Args,
    name: &str,
    change: TrialChange,
    inputs: &Inputs,
    logs: &Path,
    temporary: &Path,
) -> Result<TrialResult> {
    let paths = &inputs.paths;
    let registration = &inputs.registration;
    let sources = &inputs.sources;
    let trial = temporary.join(name);
    fs::create_dir(&trial)?;
    let store = trial.join("store");
    let flake_sources = sources
        .values()
        .map(|s| store_root(s))
        .collect::<Result<_>>()?;
    prepare_store(
        &store,
        &args.source_store_root,
        paths,
        registration,
        &flake_sources,
    )?;

    let source = trial.join("machine");
    checkout(&args.prepared_machine, &source, change, &inputs.revision)?;
    for name in ["home", "cache", "tmp"] {
        fs::create_dir(trial.join(name))?;
    }
    prepare_etc(&trial.join("etc"), Path::new("/etc"))?;

    let shell = shell(&args.source_store_root, paths)?;
    let mut command = Command::new("bwrap");
    command
        .args([
            "--die-with-parent",
            "--unshare-net",
            "--ro-bind",
            "/",
            "/",
            "--bind",
        ])
        .arg(&trial)
        .arg(&trial)
        .arg("--bind")
        .arg(store.join("nix"))
        .arg("/nix");
    for path in paths {
        let original = physical(&args.source_store_root, path)?;
        if !original.is_symlink() {
            command.arg("--ro-bind").arg(original).arg(path);
        }
    }
    command
        .arg("--ro-bind")
        .arg(trial.join("etc"))
        .arg("/etc")
        .args([
            "--dev-bind",
            "/dev",
            "/dev",
            "--proc",
            "/proc",
            "--clearenv",
        ]);
    for (key, value) in [
        ("HOME", trial.join("home")),
        ("XDG_CACHE_HOME", trial.join("cache")),
        ("TMPDIR", trial.join("tmp")),
    ] {
        command.arg("--setenv").arg(key).arg(value);
    }
    command
        .args([
            "--setenv",
            "NIX_CONFIG",
            "store = /\nsubstituters = \n",
            "--",
        ])
        .arg(&args.nix_bin)
        .args([
            "--extra-experimental-features",
            "nix-command flakes",
            "--store",
            "/",
            "--option",
            "build-hook",
            "",
            "--option",
            "sandbox",
            "true",
            "--option",
            "sandbox-fallback",
            "false",
            "--option",
            "sandbox-paths",
        ])
        .arg(format!("/bin/sh={shell}"))
        .args([
            "--option",
            "extra-sandbox-paths",
            "",
            "build",
            "--offline",
            "--no-write-lock-file",
        ]);
    for (key, path) in sources {
        command
            .arg("--override-input")
            .arg(key)
            .arg(input_reference(path)?);
    }
    command
        .arg(format!(
            "path:{}#nixosConfigurations.airlock-domain-usr-home.config.system.build.toplevel",
            source.display()
        ))
        .args(["--no-link", "--json"]);
    ensure!(
        command.get_args().count() < 9000,
        "{name} needs too many bubblewrap arguments for {} pinned store paths",
        paths.len()
    );

    let started = Instant::now();
    let stdout = logs.join(format!("{name}.stdout"));
    let stderr = logs.join(format!("{name}.stderr"));
    logged(
        &mut command,
        &stdout,
        &stderr,
        Duration::from_secs(args.timeout),
    )?;
    let result = crate::support::json(&stdout)?;
    let system: StorePath = result[0]["outputs"]["out"]
        .as_str()
        .context("offline trial returned no system path")?
        .parse()?;
    ensure!(
        !paths.contains(system.as_str()),
        "{name} reused a preseeded final system: {system}"
    );

    for path in paths {
        let staged = physical(&store, path)?;
        let original = physical(&args.source_store_root, path)?;
        let info = fs::symlink_metadata(&staged)?;
        let unchanged = if original.is_symlink() {
            info.is_symlink() && fs::read_link(&staged)? == fs::read_link(&original)?
        } else if original.is_dir() {
            info.is_dir() && fs::read_dir(&staged)?.next().is_none()
        } else {
            info.is_file() && info.len() == 0
        };
        ensure!(unchanged, "{name} replaced a pinned input: {path}");
    }

    Ok(TrialResult {
        system,
        elapsed_seconds: (started.elapsed().as_secs_f64() * 100.0).round() / 100.0,
    })
}
