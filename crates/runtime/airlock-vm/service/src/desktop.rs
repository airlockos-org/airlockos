//! Native session and development-terminal adapters around upstream graphical and Qubes tools.
//! Caller checks remain at the RPC boundary, and administrative sessions retain normal sudo.

use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Subcommand};
use std::{
    env,
    ffi::OsString,
    fs::{self, OpenOptions},
    io,
    os::unix::process::{CommandExt, ExitStatusExt},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Args)]
pub(crate) struct Request {
    /// Fixed session operation selected by an installed launcher.
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Own the GUI login lock until display-manager termination or relay disconnect.
    GuiSession {
        /// Installed systemd controller used for session lifetime operations.
        #[arg(long)]
        systemctl: PathBuf,
        /// Installed journal reader used on unexpected session failure.
        #[arg(long)]
        journalctl: PathBuf,
    },
    /// Wait for the physical X display and replace this process with the nested X server.
    LoginXserver {
        /// Display availability probe supplied by the package.
        #[arg(long)]
        probe: PathBuf,
        /// Existing upstream Xephyr executable.
        #[arg(long)]
        server: PathBuf,
        /// Qubes shared-memory preload library.
        #[arg(long)]
        preload: PathBuf,
        /// LightDM's original argument vector.
        #[arg(last = true)]
        args: Vec<OsString>,
    },
    /// Forward the local terminal to the existing development RPC and restore its attributes.
    TerminalClient {
        /// Upstream Qubes client installed in the calling VM.
        #[arg(long)]
        qrexec: PathBuf,
    },
    /// Admit the development RPC under the existing unprivileged dom0 account.
    TerminalHandler {
        /// Space-separated names from the development caller option.
        #[arg(long)]
        callers: String,
        /// Required dom0 account, checked against the actual execution identity.
        #[arg(long)]
        user: String,
        /// Upstream PTY program retaining PAM and normal sudo behavior.
        #[arg(long)]
        script: PathBuf,
        /// System logger for stage messages only, never terminal contents.
        #[arg(long)]
        logger: PathBuf,
        /// Trusted identity query executable.
        #[arg(long)]
        id: PathBuf,
        /// Fixed, store-owned login setup executable.
        #[arg(long)]
        shell: PathBuf,
        /// RPC-supplied arguments, required to be absent or one empty argument.
        #[arg(last = true)]
        args: Vec<OsString>,
    },
    /// Configure the existing terminal environment and execute the login shell.
    TerminalShell {
        /// Interactive shell selected by the image.
        #[arg(long)]
        shell: PathBuf,
        /// Upstream terminal sizing command.
        #[arg(long)]
        stty: PathBuf,
        /// Store-owned terminal capability database.
        #[arg(long)]
        terminfo: PathBuf,
    },
    /// Open an HTTP or HTTPS URL admitted through the sys-gui RPC.
    OpenUrl {
        /// Upstream desktop opener.
        #[arg(long)]
        gio: PathBuf,
        /// Upstream shell used only to import the installed profile environment.
        #[arg(long)]
        shell: PathBuf,
    },
    /// Pass one literal URL through the existing application-launch command.
    UrlLauncher {
        /// Installed launcher retaining readiness and workspace policy.
        #[arg(long)]
        launcher: PathBuf,
        /// Configured application VM.
        #[arg(long)]
        target: String,
        /// Exactly one literal URL received from the desktop handler.
        #[arg(last = true)]
        args: Vec<OsString>,
    },
    /// Dispatch halt through the existing dom0 RPC; other actions remain upstream logout.
    #[command(name = "power-action")]
    Power {
        /// Upstream Qubes application client.
        #[arg(long)]
        qvm_run: PathBuf,
        /// Existing desktop logout executable.
        #[arg(long)]
        logout: PathBuf,
        /// Original desktop action arguments.
        #[arg(last = true)]
        args: Vec<OsString>,
    },
    /// Clear stale readiness before upstream imports the graphical environment.
    AppSession {
        /// Patched upstream Qubes session executable.
        #[arg(long)]
        session: PathBuf,
        /// Integer scale exported before session startup.
        #[arg(long)]
        scale: String,
        /// Cursor size derived from the same scale.
        #[arg(long)]
        cursor_size: String,
    },
}

/// Register cleanup signals without altering process authority or interpreting input streams.
fn stopping() -> Result<Arc<AtomicBool>> {
    let stop = Arc::new(AtomicBool::new(false));
    for signal in [
        signal_hook::consts::SIGHUP,
        signal_hook::consts::SIGINT,
        signal_hook::consts::SIGTERM,
    ] {
        signal_hook::flag::register(signal, stop.clone())?;
    }
    Ok(stop)
}

/// Keep terminal restoration attached to all ordinary returns and error paths.
struct Terminal {
    /// Attributes captured before switching the caller's terminal to raw mode.
    saved: rustix::termios::Termios,
}

impl Drop for Terminal {
    fn drop(&mut self) {
        let _ = rustix::termios::tcsetattr(
            io::stdin(),
            rustix::termios::OptionalActions::Now,
            &self.saved,
        );
    }
}

/// Request display-manager shutdown on disconnect, including errors during startup.
struct DisplayManager {
    /// Fixed system controller inherited from the package contract.
    systemctl: PathBuf,
}

impl Drop for DisplayManager {
    fn drop(&mut self) {
        let _ = Command::new(&self.systemctl)
            .args(["stop", "--no-block", "display-manager.service"])
            .status();
    }
}

/// Preserve a helper's status through the service's existing error reporting boundary.
fn finish(status: std::process::ExitStatus) -> Result<()> {
    let code = status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1));
    if code == 0 {
        Ok(())
    } else {
        Err(crate::HelperExit { code: code as u8 }.into())
    }
}

/// Replace this process with an upstream executable, retaining signal and stream semantics.
fn exec(command: &mut Command) -> Result<()> {
    Err(command.exec().into())
}

pub(crate) fn execute(request: Request) -> Result<()> {
    match request.action {
        Action::GuiSession {
            systemctl,
            journalctl,
        } => {
            ensure!(
                env::var("QREXEC_REMOTE_DOMAIN").as_deref() == Ok("dom0"),
                "GUI login may only be started by dom0"
            );
            let lock = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .open("/run/airlock-gui-login.lock")?;
            rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
            let stop = stopping()?;
            let _manager = DisplayManager {
                systemctl: systemctl.clone(),
            };
            finish(
                Command::new(&systemctl)
                    .args(["start", "display-manager.service"])
                    .status()?,
            )?;
            loop {
                if stop.load(Ordering::Relaxed) {
                    return Ok(());
                }
                if !Command::new(&systemctl)
                    .args(["is-active", "--quiet", "display-manager.service"])
                    .status()?
                    .success()
                {
                    break;
                }
                for _ in 0..20 {
                    if stop.load(Ordering::Relaxed) {
                        return Ok(());
                    }
                    thread::sleep(Duration::from_millis(100));
                }
            }
            let _ = Command::new(journalctl)
                .args(["-u", "display-manager.service", "-n", "30", "--no-pager"])
                .stdout(Stdio::from(io::stderr()))
                .status();
            bail!("GUI display manager stopped unexpectedly")
        }
        Action::LoginXserver {
            probe,
            server,
            preload,
            args,
        } => {
            let deadline = Instant::now() + Duration::from_secs(60);
            loop {
                let budget = deadline.saturating_duration_since(Instant::now());
                if budget.is_zero() {
                    return Err(crate::HelperExit { code: 124 }.into());
                }
                if airlock_vm_service::support::run(
                    Command::new(&probe)
                        .args(["-display", ":1"])
                        .env("DISPLAY", ":1")
                        .env_remove("XAUTHORITY"),
                    None,
                    budget.min(Duration::from_secs(2)),
                )
                .is_ok_and(|output| output.status.success())
                {
                    break;
                }
                thread::sleep(budget.min(Duration::from_secs(1)));
            }
            let mut kept = Vec::new();
            let mut args = args.into_iter();
            while let Some(argument) = args.next() {
                let text = argument.to_string_lossy();
                if text == "-logfile" || text == "-seat" {
                    args.next().context("missing LightDM option value")?;
                } else if text == "-novtswitch"
                    || text
                        .strip_prefix("vt")
                        .is_some_and(|suffix| suffix.starts_with(|c: char| c.is_ascii_digit()))
                {
                } else {
                    kept.push(argument);
                }
            }
            exec(
                Command::new(server)
                    .args(["-sw-cursor", "-no-host-grab", "-output", "DUMMY0"])
                    .args(kept)
                    .env("DISPLAY", ":1")
                    .env_remove("XAUTHORITY")
                    .env("LD_PRELOAD", preload),
            )
        }
        Action::TerminalClient { qrexec } => {
            let stop = stopping()?;
            let terminal = Terminal {
                saved: rustix::termios::tcgetattr(io::stdin())?,
            };
            println!("Connecting to dom0 through Qubes...");
            let mut raw = terminal.saved.clone();
            raw.make_raw();
            rustix::termios::tcsetattr(io::stdin(), rustix::termios::OptionalActions::Now, &raw)?;
            let mut child = Command::new(qrexec)
                .args([
                    "--no-filter-escape-chars-stdout",
                    "--no-filter-escape-chars-stderr",
                    "dom0",
                    "airlock.DevDom0Shell",
                ])
                .spawn()?;
            let status = loop {
                if let Some(status) = child.try_wait()? {
                    break status;
                }
                if stop.load(Ordering::Relaxed) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(crate::HelperExit { code: 1 }.into());
                }
                thread::sleep(Duration::from_millis(50));
            };
            drop(terminal);
            println!(
                "\nDom0 connection ended (exit code {code}).",
                code = status.code().unwrap_or(1)
            );
            if !status.success() {
                println!(
                    "Please report the messages above. If no handler message appeared, inspect dom0 qrexec logs."
                );
            }
            println!("You can close this window.");
            finish(status)
        }
        Action::TerminalHandler {
            callers,
            user,
            script,
            logger,
            id,
            shell,
            args,
        } => {
            rustix::stdio::dup2_stderr(io::stdout())?;
            let stage = |message: &str| {
                println!("dom0-terminal: {message}");
                let _ = Command::new(&logger)
                    .args(["-t", "airlock-dev-dom0-terminal", "--", message])
                    .status();
            };
            stage("handler reached");
            let remote = env::var("QREXEC_REMOTE_DOMAIN").unwrap_or_default();
            ensure!(
                !remote.is_empty() && callers.split_whitespace().any(|name| name == remote),
                "caller is not an enabled development domain"
            );
            ensure!(
                env::var_os("QREXEC_SERVICE_ARGUMENT").is_none_or(|value| value.is_empty())
                    && (args.is_empty() || (args.len() == 1 && args[0].is_empty())),
                "this service accepts no arguments"
            );
            let identity = Command::new(id).arg("-un").output()?;
            ensure!(
                identity.status.success() && String::from_utf8(identity.stdout)?.trim() == user,
                "unexpected dom0 execution user"
            );
            stage("starting the dom0 user PTY session");
            // util-linux script interprets its command through a shell; quote the fixed store path.
            let shell = shell.to_str().context("non-UTF-8 login executable")?;
            let shell = format!("'{path}'", path = shell.replace('\'', "'\\''"));
            exec(Command::new(script).args([
                "--quiet",
                "--return",
                "--flush",
                "--command",
                &shell,
                "/dev/null",
            ]))
        }
        Action::TerminalShell {
            shell,
            stty,
            terminfo,
        } => {
            let home = env::var_os("HOME").context("HOME is not set")?;
            env::set_current_dir(home)?;
            finish(
                Command::new(stty)
                    .args(["rows", "30", "cols", "100"])
                    .status()?,
            )?;
            println!("DEVELOPMENT: dom0 shell. Use sudo for administration; exit to disconnect.");
            exec(
                Command::new(shell)
                    .arg("-l")
                    .env("TERM", "xterm-256color")
                    .env("TERMINFO_DIRS", terminfo),
            )
        }
        Action::OpenUrl { gio, shell } => {
            ensure!(
                env::var("QREXEC_REMOTE_DOMAIN").as_deref() == Ok("sys-gui"),
                "URL opening is restricted to sys-gui"
            );
            let url = env::var("QREXEC_SERVICE_ARGUMENT").context("URL is missing")?;
            ensure!(
                url.starts_with("http://") || url.starts_with("https://"),
                "airlock.OpenUrl accepts only http and https URLs"
            );
            // The profile is an upstream shell interface. Only its environment import remains shell.
            exec(
                Command::new(shell)
                    .args([
                        "-c",
                        "if [ -r /etc/profile ]; then . /etc/profile; fi; exec \"$@\"",
                        "airlock-open-url",
                    ])
                    .arg(gio)
                    .arg("open")
                    .arg(url),
            )
        }
        Action::UrlLauncher {
            launcher,
            target,
            args,
        } => {
            ensure!(args.len() == 1, "URL launcher requires one URL");
            let url = args[0].to_str().context("URL is not UTF-8")?;
            exec(
                Command::new(launcher)
                    .arg("Web link")
                    .arg(target)
                    .arg(format!("airlock.OpenUrl+{url}")),
            )
        }
        Action::Power {
            qvm_run,
            logout,
            args,
        } => {
            if args.first().is_some_and(|argument| argument == "--halt") {
                exec(Command::new(qvm_run).args([
                    "--pass-io",
                    "--no-gui",
                    "--service",
                    "dom0",
                    "airlock.Dom0Poweroff",
                ]))
            } else {
                exec(Command::new(logout).args(args))
            }
        }
        Action::AppSession {
            session,
            scale,
            cursor_size,
        } => {
            let runtime = env::var_os("XDG_RUNTIME_DIR")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    PathBuf::from(format!(
                        "/run/user/{uid}",
                        uid = rustix::process::getuid().as_raw()
                    ))
                });
            match fs::remove_file(runtime.join("airlock-app-session-ready")) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            exec(
                Command::new(session)
                    .env("GDK_SCALE", scale)
                    .env("GDK_DPI_SCALE", "1")
                    .env("XCURSOR_SIZE", cursor_size),
            )
        }
    }
}
