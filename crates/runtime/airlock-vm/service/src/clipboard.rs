//! Graphical clipboard endpoints and the GUI's separate trusted connection provisioner.

mod desktop;

use airlock_machine_core::services::{ClipboardConnection, ClipboardEndpoint};
use airlock_nix_core::runtime::process;
use airlock_sys_clipboard::shared::{self, Reply, Request};
use anyhow::{Context, Result, bail, ensure};
use clap::{Args as ClapArgs, Subcommand};
use std::{
    fs,
    io::{Read, Write},
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};
use xen_transport::{Channel, Offer, Peer, linux::Linux};

/// Clipboard operation and immutable machine-derived connection contract.
#[derive(ClapArgs)]
pub struct Args {
    /// Installed configuration generated from the typed clipboard relationship.
    #[arg(long, default_value = "/etc/airlock/clipboard.json")]
    config: PathBuf,
    /// Role-specific entry point, installed only on its intended endpoint.
    #[command(subcommand)]
    action: Action,
}

/// The user endpoint and the two root-only provisioning operations.
#[derive(Subcommand)]
enum Action {
    /// Import graphical session credentials and activate its supervised user service.
    Activate,
    /// Attach this graphical session's clipboard to the shared service.
    Session {
        /// Use the GUI's local endpoint; qrexec cannot connect a VM to itself.
        #[arg(long)]
        local: bool,
    },
    /// Provision authenticated peers through the boot-bound Hermit control channel.
    Authority,
    /// Serve a Qubes-authenticated connection request through the local authority.
    Connect,
}

/// Private root-owned socket; applications never access the authority protocol directly.
const CONTROL: &str = "/run/airlock-clipboard/authority.sock";

/// Group-readable GUI endpoint which can provision only the local GUI principal.
const SESSION: &str = "/run/airlock-clipboard/session.sock";

/// Own one channel and its monotonic request sequence.
struct Client {
    /// Exclusively owned transport mapping restricted to the admitted Hermit peer.
    channel: Channel<Linux>,
    /// Last request identity, never wrapped or reused in this connection lifetime.
    sequence: u64,
}

impl Client {
    /// Map a trusted provisioning result; endpoint coordinates themselves confer no identity.
    fn open(endpoint: &ClipboardEndpoint) -> Result<Self> {
        ensure!(
            endpoint.domain > 0 && endpoint.domain < 0x7ff0 && endpoint.epoch > 0,
            "invalid clipboard endpoint"
        );
        let backend = Linux::open(
            Peer {
                domain: endpoint.domain,
            },
            Offer {
                port: endpoint.port,
                grant: endpoint.grant,
                session: endpoint.epoch,
            },
        )
        .map_err(|e| anyhow::anyhow!("clipboard mapping: {e:?}"))?;
        Ok(Self {
            channel: Channel::new(backend),
            sequence: 0,
        })
    }

    /// Exchange one bounded operation, preserving policy and transport failure categories.
    fn request(&mut self, request: Request) -> Result<Reply> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .context("clipboard request sequence exhausted")?;
        match shared::exchange(&mut self.channel, self.sequence, &request)
            .map_err(|e| anyhow::anyhow!("clipboard transport: {e:?}"))?
        {
            Reply::Error(error) => bail!("clipboard operation rejected: {error:?}"),
            reply => Ok(reply),
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self
            .channel
            .close(self.channel.deadline_after(1_000_000_000));
    }
}

/// Read a small trusted JSON contract or provisioning response with an explicit bound.
fn json<T: serde::de::DeserializeOwned>(reader: impl Read) -> Result<T> {
    let mut bytes = Vec::new();
    reader.take(16 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 16 * 1024, "oversized clipboard contract");
    Ok(serde_json::from_slice(&bytes)?)
}

/// Ask a configured Qubes endpoint; arguments never come from clipboard bytes.
fn rpc(target: &str, service: &str) -> Result<ClipboardEndpoint> {
    let output = process::run(
        Command::new("qrexec-client-vm").args(["--", target, service]),
        None,
        Some(Duration::from_secs(15)),
    )?;
    ensure!(
        output.status.success(),
        "clipboard provisioning unavailable"
    );
    json(output.stdout.as_slice())
}

/// Dispatch the installed endpoint under its existing Qubes/user permissions.
pub fn run(args: Args) -> Result<()> {
    let config: ClipboardConnection = json(fs::File::open(&args.config)?)?;
    ensure!(config.validate(), "invalid clipboard membership contract");
    match args.action {
        Action::Activate => {
            ensure!(
                Command::new("systemctl")
                    .args(["--user", "unset-environment", "DISPLAY", "XAUTHORITY"])
                    .status()?
                    .success(),
                "cannot clear old clipboard session credentials"
            );
            let mut import = Command::new("systemctl");
            import.args(["--user", "import-environment"]);
            for name in ["DISPLAY", "XAUTHORITY"] {
                if std::env::var_os(name).is_some() {
                    import.arg(name);
                }
            }
            ensure!(
                import.status()?.success(),
                "cannot import clipboard session credentials"
            );
            ensure!(
                Command::new("systemctl")
                    .args(["--user", "restart", "airlock-clipboard.service"])
                    .status()?
                    .success(),
                "cannot activate clipboard session"
            );
            Ok(())
        }
        Action::Session { local } => {
            let endpoint = if local {
                let socket = UnixStream::connect(SESSION)?;
                socket.set_read_timeout(Some(Duration::from_secs(15)))?;
                socket.shutdown(std::net::Shutdown::Write)?;
                json(socket)?
            } else {
                rpc(config.gui.as_str(), "airlock.ClipboardConnect")?
            };
            ensure!(
                endpoint.principal > 0,
                "authority endpoint cannot serve a desktop"
            );
            desktop::run(Client::open(&endpoint)?)
        }
        Action::Authority => authority(&config),
        Action::Connect => {
            ensure!(
                rustix::process::geteuid().is_root(),
                "clipboard provisioner must run as root"
            );
            let caller = std::env::var("QREXEC_REMOTE_DOMAIN")?;
            ensure!(
                config.principal(&caller).is_some(),
                "clipboard caller is not a participant"
            );
            let mut socket = UnixStream::connect(CONTROL)?;
            socket.set_read_timeout(Some(Duration::from_secs(15)))?;
            socket.set_write_timeout(Some(Duration::from_secs(15)))?;
            socket.write_all(caller.as_bytes())?;
            socket.shutdown(std::net::Shutdown::Write)?;
            let endpoint: ClipboardEndpoint = json(socket)?;
            serde_json::to_writer(std::io::stdout().lock(), &endpoint)?;
            Ok(())
        }
    }
}

/// Resolve a current Xen identity through the existing Qubes administration client.
fn domain(name: &str) -> Result<u16> {
    let output = process::run(
        Command::new("qvm-prefs").args(["--", name, "xid"]),
        None,
        Some(Duration::from_secs(10)),
    )?;
    ensure!(
        output.status.success(),
        "clipboard participant is not running"
    );
    let domain: u16 = std::str::from_utf8(&output.stdout)?.trim().parse()?;
    ensure!(
        domain > 0 && domain < 0x7ff0,
        "invalid clipboard participant domain"
    );
    Ok(domain)
}

/// Own the GUI control channel; participant payloads use independent Xen connections.
fn authority(config: &ClipboardConnection) -> Result<()> {
    ensure!(
        rustix::process::geteuid().is_root(),
        "clipboard authority must run as root"
    );
    // A new authority lifetime requires a fresh guest and new grant capabilities.
    // These calls are restricted by generated Qubes policy to this one service.
    let _ = process::run(
        Command::new("qvm-kill").args(["--", config.service.as_str()]),
        None,
        Some(Duration::from_secs(15)),
    )?;
    ensure!(
        process::run(
            Command::new("qvm-start").args(["--skip-if-running", "--", config.service.as_str()]),
            None,
            Some(Duration::from_secs(60))
        )?
        .status
        .success(),
        "cannot start clipboard service"
    );
    let start = Instant::now();
    let endpoint = loop {
        match rpc("dom0", "airlock.ClipboardEndpoint") {
            Ok(endpoint) => break endpoint,
            Err(error) if start.elapsed() >= Duration::from_secs(30) => return Err(error),
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    };
    ensure!(
        endpoint.principal == 0,
        "clipboard bootstrap is not an authority endpoint"
    );
    let mut client = Client::open(&endpoint)?;
    ensure!(
        matches!(client.request(Request::Offer)?, Reply::Ok),
        "clipboard authority handshake failed"
    );

    let directory = Path::new(CONTROL).parent().unwrap();
    fs::create_dir_all(directory)?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o750))?;
    for path in [CONTROL, SESSION] {
        match fs::remove_file(path) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    let listener = UnixListener::bind(CONTROL)?;
    fs::set_permissions(CONTROL, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let local = UnixListener::bind(SESSION)?;
    fs::set_permissions(SESSION, fs::Permissions::from_mode(0o660))?;
    local.set_nonblocking(true)?;
    let mut heartbeat = Instant::now();
    loop {
        for (listener, local) in [(&listener, false), (&local, true)] {
            match listener.accept() {
                Ok((mut socket, _)) => {
                    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
                    socket.set_write_timeout(Some(Duration::from_secs(2)))?;
                    // The root-only socket accepts QREXEC_REMOTE_DOMAIN from the RPC
                    // wrapper. The user socket always binds to the local GUI, ignoring
                    // request bytes so a local application cannot impersonate another VM.
                    let outcome = (|| -> Result<()> {
                        let mut caller = String::new();
                        if local {
                            caller = config.gui.to_string();
                        } else {
                            (&mut socket).take(33).read_to_string(&mut caller)?;
                        }
                        let principal = config
                            .principal(&caller)
                            .context("caller outside clipboard membership")?;
                        let xid = domain(&caller)?;
                        match client.request(Request::Connect {
                            principal,
                            domain: xid,
                        })? {
                            Reply::Connected { epoch, port, grant } => serde_json::to_writer(
                                &mut socket,
                                &ClipboardEndpoint {
                                    domain: endpoint.domain,
                                    epoch,
                                    port,
                                    grant,
                                    principal,
                                },
                            )?,
                            _ => bail!("invalid clipboard provisioning reply"),
                        }
                        Ok(())
                    })();
                    if outcome.is_err() {
                        eprintln!("clipboard provisioning request failed");
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => (),
                Err(error) => return Err(error.into()),
            }
        }
        if heartbeat.elapsed() >= Duration::from_secs(1) {
            ensure!(
                matches!(client.request(Request::Offer)?, Reply::Ok),
                "clipboard authority disconnected"
            );
            heartbeat = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}
