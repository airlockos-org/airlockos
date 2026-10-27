//! Keep image builds unprivileged while a separately authenticated USB helper waits on a private pipe.

use crate::{repository, support};
use airlock_image::provisioning::{BuildOutcome, BuildRun, CompletedBuild, READY};
use airlock_nix_core::runtime::process::OwnedChild;
use airlock_nix_core::store_path::StorePath;
use anyhow::{Context, Result, ensure};
use clap::Args as ClapArgs;
use std::{
    fs,
    io::{self, BufRead, BufReader, Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{ChildStdin, ChildStdout, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

/// Workstation paths are supplied by Make; credentials are collected only by the USB helper.
#[derive(ClapArgs)]
pub(crate) struct Args {
    /// Explicitly prepared provisioning executable; never rebuilt while it is waiting.
    #[arg(long)]
    usb_bin: PathBuf,
    /// Exact hardware identity whose contents this operation will replace.
    #[arg(long)]
    serial: String,
    /// Public SSH key installed during offline personalization.
    #[arg(long)]
    public_key: PathBuf,
    /// Physical root of the private Nix store, omitted when using the host store explicitly.
    #[arg(long)]
    nix_root: Option<PathBuf>,
    /// Parent for this run's private image result link and GC root.
    #[arg(long)]
    result_link_dir: PathBuf,
    /// Off-USB destination for partition-table recovery records.
    #[arg(long)]
    resize_backup_dir: PathBuf,
    /// Optional machine-local AMD firmware supplied to ordinary personalization.
    #[arg(long)]
    amd_vfct: Option<PathBuf>,
    /// Explicit development convenience, preserving the ordinary provisioning option.
    #[arg(long)]
    insecure_dev_password: bool,
}

/// Closing the request pipe cancels a prepared helper, including on errors before the build starts.
struct Helper {
    /// One completion message may be sent; EOF alone always cancels.
    input: Option<ChildStdin>,
    /// Preparation messages and provisioning progress forwarded to the user's terminal.
    output: BufReader<ChildStdout>,
    /// Sudo remains alive with its already authenticated child throughout the build.
    child: OwnedChild,
}

impl Helper {
    /// Start sudo without consuming the request pipe for its password; sudo uses the terminal.
    fn start(command: &mut Command) -> Result<Self> {
        let mut child = OwnedChild(
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()?,
        );
        Ok(Self {
            input: child.0.stdin.take(),
            output: BufReader::new(child.0.stdout.take().context("USB helper output")?),
            child,
        })
    }

    /// Forward preparation output until the helper confirms every credential is collected.
    fn prepared(&mut self) -> Result<()> {
        loop {
            let mut line = Vec::new();
            let bytes = (&mut self.output)
                .take(64 * 1024)
                .read_until(b'\n', &mut line)?;
            ensure!(
                bytes > 0,
                "USB preparation failed or was cancelled; image build was not started."
            );
            ensure!(bytes < 64 * 1024, "USB helper output line exceeds limit");
            if line == READY {
                return Ok(());
            }
            io::stdout().write_all(&line)?;
            io::stdout().flush()?;
        }
    }

    /// Signal success only when requested, then drain progress and wait for the same helper.
    fn finish(mut self, completed: Option<&CompletedBuild>) -> Result<ExitStatus> {
        if let Some(completed) = completed {
            completed.write(self.input.as_mut().context("USB helper input")?)?;
        }
        drop(self.input.take());
        io::copy(&mut self.output, &mut io::stdout())?;
        Ok(self.child.0.wait()?)
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        drop(self.input.take());
        // Let EOF clean up the helper's credentials and private source snapshot
        // before the process guard terminates a helper that did not respond.
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.child.0.try_wait().is_ok_and(|status| status.is_none())
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(20));
        }
    }
}

/// Authenticate and prepare first, run the existing image target as the caller, then authorize provisioning.
pub(crate) fn run(root: &Path, args: Args) -> Result<u8> {
    ensure!(
        !rustix::process::geteuid().is_root(),
        "Run the combined image command as your normal user, without sudo."
    );
    ensure!(
        !args.serial.trim().is_empty(),
        "Supply USB_SERIAL before building."
    );
    repository::check_image_source(root)?;
    ensure!(
        args.nix_root.is_some()
            || std::env::var("AIRLOCK_USE_HOST_NIX_STORE").as_deref() == Ok("1"),
        "Supply --nix-root for the private Airlock store."
    );
    let (machine, machine_revision) = repository::local(root)?;
    let revision = support::git(root, &["rev-parse", "HEAD"])?;
    let usb = fs::canonicalize(&args.usb_bin).context("prepare image tools before provisioning")?;
    let public_key = fs::canonicalize(&args.public_key).context("SSH public key is missing")?;
    fs::create_dir_all(&args.result_link_dir)?;
    let result_directory = fs::canonicalize(&args.result_link_dir)?;
    let run = tempfile::Builder::new()
        .prefix("usb-build-provision-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(&result_directory)?;
    let result_link = run.path().join("usb-dev-image");
    let build_run = BuildRun::new(
        result_link.clone(),
        revision.parse()?,
        machine_revision.parse()?,
    )?;
    let mut command = Command::new("sudo");
    command
        .arg("--")
        .arg(usb)
        .arg("provision-after-build")
        .arg("--serial")
        .arg(&args.serial)
        .arg("--result-link")
        .arg(&result_link)
        .arg("--repo")
        .arg(root)
        .arg("--application-revision")
        .arg(&revision)
        .arg("--machine-revision")
        .arg(&machine_revision)
        .arg("--public-key")
        .arg(public_key)
        .arg("--resize-backup-dir")
        .arg(&args.resize_backup_dir)
        .current_dir(root);
    if let Some(nix_root) = &args.nix_root {
        command.arg("--nix-root").arg(nix_root);
    }
    if let Some(firmware) = &args.amd_vfct {
        command.arg("--amd-vfct").arg(firmware);
    }
    if args.insecure_dev_password {
        command.arg("--insecure-dev-password");
    }

    eprintln!(
        "Preparing USB provisioning now; sudo and dom0 password prompts precede the image build."
    );
    let mut helper = Helper::start(&mut command)?;
    helper.prepared()?;
    ensure!(
        support::git(root, &["rev-parse", "HEAD"])? == revision
            && support::git(&machine, &["rev-parse", "HEAD"])? == machine_revision,
        "Committed source changed during USB preparation; USB was not written."
    );
    eprintln!(
        "Credentials collected. Building the USB image as the current user; provisioning follows automatically on success."
    );
    let status = Command::new("make")
        .current_dir(root)
        .args(["--no-print-directory", "usb-dev-image"])
        .arg(format!(
            "AIRLOCK_RESULT_LINK_DIR={path}",
            path = run.path().display()
        ))
        .stdin(Stdio::null())
        .env("GIT_TERMINAL_PROMPT", "0")
        // This Rust recipe is not a Make jobserver participant. Caller settings
        // remain in exported variables, but its closed jobserver FDs must not leak.
        .env_remove("MAKEFLAGS")
        .env_remove("MFLAGS")
        .status()?;
    if !status.success() {
        let _ = helper.finish(None);
        eprintln!("Image build failed; USB was not written.");
        return Ok(status.code().unwrap_or(1).try_into().unwrap_or(1));
    }
    ensure!(
        support::git(root, &["rev-parse", "HEAD"])? == revision
            && support::git(&machine, &["rev-parse", "HEAD"])? == machine_revision,
        "Committed source changed during the image build; USB was not written."
    );
    ensure!(
        fs::symlink_metadata(&result_link).is_ok(),
        "Build succeeded without publishing this run's image; USB was not written."
    );

    // Keep the ordinary retry command on the newly built image. The waiting
    // helper continues using its private link even if another build updates this one.
    let image: StorePath = fs::read_link(&result_link)?
        .to_str()
        .context("non-UTF-8 image result")?
        .parse()?;
    let latest = result_directory.join("usb-dev-image");
    support::output(
        Command::new("nix-store")
            .arg("--store")
            .arg(args.nix_root.as_deref().unwrap_or(Path::new("/")))
            .arg("--add-root")
            .arg(&latest)
            .args(["--indirect", "--realise"])
            .arg(image.as_str()),
    )?;
    ensure!(
        fs::read_link(&latest)? == Path::new(image.as_str()),
        "Unexpected published image result; USB was not written."
    );

    eprintln!("Image build succeeded. Provisioning the USB with the collected credentials.");
    let completed = CompletedBuild::check(
        &build_run,
        if status.success() {
            BuildOutcome::Success
        } else {
            BuildOutcome::Failed
        },
        &support::git(root, &["rev-parse", "HEAD"])?.parse()?,
        &support::git(&machine, &["rev-parse", "HEAD"])?.parse()?,
        &result_link,
        Some(image),
    )?;
    let status = helper.finish(Some(&completed))?;
    ensure!(status.success(), "USB provisioning failed: {status}");
    eprintln!("USB build and provisioning completed.");
    Ok(0)
}
