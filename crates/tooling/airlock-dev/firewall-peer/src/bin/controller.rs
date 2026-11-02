//! Application-specific acceptance controller inside the existing disposable Xen lab.
//! QubesDB, Linux netif drivers, dnsmasq and xl retain their ordinary protocols.

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, UdpSocket},
    path::Path,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const NAME: &str = "pvh-smoke";
const REMOTE: &str = "10.139.0.1";
const EXTERNAL: &str = "10.139.0.2";
const CHALLENGE: &str = "12345678-1234-4234-8234-123456789abc";

/// Immutable tools and Linux guest artifacts selected by the Rust-authored build.
#[derive(Deserialize)]
struct Settings {
    /// Official QubesDB daemon linked against the lab Xen SDK.
    daemon: String,
    /// Native QubesDB CLI directory.
    database: String,
    /// Linux command used only for static isolated link configuration.
    ip: String,
    /// Maintained DNS implementation used as the actual upstream resolver.
    dnsmasq: String,
    /// Linux PVH kernel matching the frontend modules in the initrd.
    kernel: String,
    /// Minimal native Linux client initrd, unrelated to production VM images.
    initrd: String,
}

/// Run a normal Linux/toolstack command and retain a useful failure diagnostic.
fn command(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program).args(args).output()?;
    ensure!(output.status.success(), "{program} {args:?}: {output:?}");
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Query the real daemon's local socket with its upstream CLI.
fn db(settings: &Settings, operation: &str, args: &[&str]) -> Result<String> {
    let mut options = vec!["-d", NAME];
    options.extend_from_slice(args);
    command(
        &format!(
            "{database}/bin/qubesdb-{operation}",
            database = settings.database
        ),
        &options,
    )
}

/// Wait on observed state, bounded by the controller's global deadline.
fn wait(
    deadline: Instant,
    description: &str,
    mut ready: impl FnMut() -> Result<bool>,
) -> Result<()> {
    eprintln!("FW_WAIT {description}");
    while !ready()? {
        let guest = console(NAME);
        ensure!(
            !guest.contains("AIRLOCK_FIREWALL_STOP") && !guest.contains("panicked at"),
            "firewall stopped: {guest}"
        );
        ensure!(
            Instant::now() < deadline,
            "timed out waiting for {description}"
        );
        thread::sleep(Duration::from_millis(100));
    }
    eprintln!("FW_READY {description}");
    Ok(())
}

/// The exact console belongs to a toolstack-created domain in this disposable lab.
fn console(name: &str) -> String {
    fs::read_to_string(format!("/lab/xen-console/guest-{name}.log")).unwrap_or_default()
}

/// Always destroy the controller's two Linux guests before returning to lab teardown.
struct Clients;

impl Drop for Clients {
    /// Destruction is best-effort here; the outer lab then tears down the whole VM.
    fn drop(&mut self) {
        if let Ok(tree) = command("xenstore-ls", &["-fp"]) {
            let _ = fs::write("/lab/firewall-xenstore-before-cleanup.txt", tree);
        }
        for name in ["fw-client-a", "fw-client-b"] {
            let _ = Command::new("xl").args(["destroy", name]).status();
        }
        for name in ["fw-dns", "fw-qdb"] {
            let _ = Command::new("systemctl").args(["stop", name]).status();
        }
    }
}

/// Start a fixed number of real TCP servers; denied ports are listening too.
fn tcp_server(port: u16, phase: Arc<AtomicBool>, denied: Arc<AtomicUsize>) -> Result<()> {
    let listener = TcpListener::bind((REMOTE, port))?;
    thread::spawn(move || {
        for connection in listener.incoming().take(16) {
            let Ok(mut socket) = connection else {
                break;
            };
            if port == 18081 {
                denied.fetch_add(1, Ordering::Relaxed);
            }
            if socket
                .peer_addr()
                .is_ok_and(|peer| peer.ip().to_string() != EXTERNAL)
            {
                denied.fetch_add(1, Ordering::Relaxed);
                eprintln!("FW_BAD_NAT_SOURCE");
            }
            let phase = phase.clone();
            thread::spawn(move || {
                let _ = socket.set_read_timeout(Some(Duration::from_secs(12)));
                if port == 18082 {
                    let _ = socket.write_all(if phase.load(Ordering::Acquire) {
                        b"tightened"
                    } else {
                        b"pending"
                    });
                    return;
                }
                let mut bytes = [0; 256];
                while let Ok(length) = socket.read(&mut bytes) {
                    if length == 0 || socket.write_all(&bytes[..length]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    Ok(())
}

/// Standard Linux UDP endpoints distinguish filtered traffic from absent services.
fn udp_server(port: u16, denied: Arc<AtomicUsize>) -> Result<()> {
    let socket = UdpSocket::bind((REMOTE, port))?;
    thread::spawn(move || {
        let mut bytes = [0; 256];
        while let Ok((length, peer)) = socket.recv_from(&mut bytes) {
            if port == 19091
                || &bytes[..length] == b"spoofed-source"
                || peer.ip().to_string() != EXTERNAL
            {
                denied.fetch_add(1, Ordering::Relaxed);
            }
            let _ = socket.send_to(&bytes[..length], peer);
        }
    });
    Ok(())
}

/// Publish ordinary ordered Qubes rules and the final empty completion marker.
fn policy(settings: &Settings, ip: &str, tightened: bool) -> Result<()> {
    let rules = [
        if tightened {
            "action=drop proto=tcp dstports=18080"
        } else {
            "action=accept proto=tcp dsthost=allowed.airlock.test dstports=18080"
        },
        "action=accept proto=tcp dstports=18082",
        "action=accept proto=udp dstports=19090",
        "action=accept proto=udp specialtarget=dns dstports=53",
        "action=accept proto=icmp",
    ];
    let root = format!("/qubes-firewall/{ip}");
    db(settings, "write", &[&format!("{root}/policy"), "drop"])?;
    for (index, rule) in rules.iter().enumerate() {
        db(settings, "write", &[&format!("{root}/{index:04}"), rule])?;
    }
    db(settings, "write", &[&root, ""])?;
    Ok(())
}

/// Create a normal Linux PVH frontend attached only to the supplied Hermit owner.
fn client(settings: &Settings, backend: u16, role: &str) -> Result<()> {
    let ip = if role == "a" {
        "10.137.0.10"
    } else {
        "10.137.0.11"
    };
    let suffix = if role == "a" { "10" } else { "11" };
    let name = format!("fw-client-{role}");
    let config = format!(
        r#"
name = '{name}'
type = 'pvh'
kernel = '{kernel}'
ramdisk = '{initrd}'
memory = 512
vcpus = 1
on_poweroff = 'preserve'
on_crash = 'preserve'
extra = 'console=hvc0 rdinit=/init firewall.client={role}'
vif = ['backend={backend},mac=00:16:3e:00:00:{suffix},ip={ip},script=/etc/xen/scripts/true']
"#,
        kernel = settings.kernel,
        initrd = settings.initrd
    );
    let path = format!("/lab/{name}.cfg");
    fs::write(&path, config)?;
    command("xl", &["create", &path])?;
    Ok(())
}

/// Set up real control/network services while the production guest is paused.
fn run() -> Result<()> {
    let settings: Settings = serde_json::from_slice(&fs::read("/etc/airlock-firewall-lab.json")?)?;
    let backend: u16 = std::env::args()
        .nth(1)
        .context("missing paused guest domain")?
        .parse()?;
    ensure!(backend > 0, "invalid firewall domain");
    let deadline = Instant::now() + Duration::from_secs(100);
    let _clients = Clients;
    fs::create_dir_all("/run/qubes")?;
    command(
        "systemd-run",
        &[
            "--unit=fw-qdb",
            "--no-block",
            "--property=Type=notify",
            "--property=TimeoutStartSec=20",
            &settings.daemon,
            &backend.to_string(),
            NAME,
        ],
    )?;
    wait(deadline, "QubesDB server", || {
        Ok(db(&settings, "list", &["/"]).is_ok())
    })?;
    let values = [
        ("/qubes-ip", EXTERNAL),
        ("/qubes-gateway", REMOTE),
        ("/qubes-netmask", "255.255.255.0"),
        ("/qubes-primary-dns", REMOTE),
        ("/qubes-secondary-dns", REMOTE),
        ("/qubes-mac", "00:16:3e:00:00:99"),
        ("/qubes-netvm-network", "10.137.0.0"),
        ("/qubes-netvm-gateway", "10.137.0.1"),
        ("/qubes-netvm-netmask", "255.255.255.0"),
        ("/qubes-netvm-primary-dns", "10.139.1.1"),
        ("/qubes-netvm-secondary-dns", "10.139.1.2"),
        ("/connected-ips", "10.137.0.10 10.137.0.11"),
        ("/connected-ips6", ""),
    ];
    for (key, value) in values {
        db(&settings, "write", &[key, value])?;
    }
    // Kernel backend preparation completes independently of the paused frontend.
    command("xl", &["unpause", NAME])?;
    let interface = format!("vif{backend}.0");
    wait(deadline, "Linux upstream netdev", || {
        Ok(Path::new(&format!("/sys/class/net/{interface}")).exists())
    })?;
    command(
        &settings.ip,
        &["address", "add", "10.139.0.1/24", "dev", &interface],
    )?;
    command(&settings.ip, &["link", "set", &interface, "up"])?;
    // The isolated link has no bridge hotplug script. Publish the same standard
    // completion as the existing lab's Linux netback fixture after configuring it.
    command(
        "xenstore-write",
        &[
            &format!("/local/domain/0/backend/vif/{backend}/0/hotplug-status"),
            "connected",
        ],
    )?;
    command(
        "systemd-run",
        &[
            "--unit=fw-dns",
            "--property=Type=exec",
            &settings.dnsmasq,
            "--no-daemon",
            "--no-hosts",
            "--no-resolv",
            "--bind-interfaces",
            "--listen-address=10.139.0.1",
            "--address=/allowed.airlock.test/10.139.0.1",
            "--local=/airlock.test/",
            "--local-ttl=60",
            "--user=root",
        ],
    )?;
    let phase = Arc::new(AtomicBool::new(false));
    let denied = Arc::new(AtomicUsize::new(0));
    for port in [18080, 18081, 18082] {
        tcp_server(port, phase.clone(), denied.clone())?;
    }
    for port in [19090, 19091] {
        udp_server(port, denied.clone())?;
    }
    wait(deadline, "current boot policy refresh", || {
        Ok(db(&settings, "read", &["/airlock-network-control-ready"])
            .is_ok_and(|value| value == CHALLENGE))
    })?;
    for ip in ["10.137.0.10", "10.137.0.11"] {
        policy(&settings, ip, false)?;
    }
    client(&settings, backend, "b")?;
    wait(deadline, "second Linux client", || {
        let text = console("fw-client-b");
        ensure!(
            !text.contains("FW_CLIENT_FAIL"),
            "Linux client failed: {text}"
        );
        Ok(text.contains("FW_CLIENT_B_READY"))
    })?;
    client(&settings, backend, "a")?;
    wait(deadline, "baseline forwarding", || {
        let text = console("fw-client-a");
        ensure!(
            !text.contains("FW_CLIENT_FAIL"),
            "Linux client failed: {text}"
        );
        Ok(text.contains("FW_CLIENT_A_BASELINE_PASS"))
    })?;
    let key = "/qubes-firewall-handled/10.137.0.10";
    let before = db(&settings, "read", &[key])?;
    policy(&settings, "10.137.0.10", true)?;
    wait(deadline, "new policy admission barrier", || {
        Ok(db(&settings, "read", &[key]).is_ok_and(|value| value != before))
    })?;
    phase.store(true, Ordering::Release);
    wait(deadline, "established-flow revocation", || {
        let text = console("fw-client-a");
        ensure!(
            !text.contains("FW_CLIENT_FAIL"),
            "Linux client failed: {text}"
        );
        Ok(text.contains("FW_CLIENT_A_PASS"))
    })?;
    ensure!(
        denied.load(Ordering::Relaxed) == 0,
        "forbidden service received traffic"
    );
    ensure!(
        !console("fw-client-b").contains("FW_CLIENT_B_ISOLATION_BREACH"),
        "second client received cross-client traffic"
    );
    let console = console(NAME);
    ensure!(
        !console.contains("Fallback to a naive"),
        "weak entropy fallback was used"
    );
    ensure!(
        !console.contains("AIRLOCK_FIREWALL_STOP"),
        "production firewall stopped: {console}"
    );
    println!(
        "AIRLOCK_FIREWALL_LAB_PASS dns=ok tcp=ok udp=ok icmp=ok deny=ok isolation=ok spoof=ok tightening=ok"
    );
    Ok(())
}

/// Propagate genuine integration failures to the existing host controller.
fn main() {
    if let Err(error) = run() {
        eprintln!("AIRLOCK_FIREWALL_LAB_FAIL error={error:#}");
        std::process::exit(1);
    }
}
