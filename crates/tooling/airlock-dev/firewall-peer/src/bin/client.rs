//! Linux PID 1 for the existing Xen lab's isolated firewall clients.
//! Standard Linux networking and BusyBox exercise the unchanged production ELF.

use anyhow::{Context, Result, ensure};
use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const REMOTE: &str = "10.139.0.1";
const MESSAGE: &[u8] = b"airlock-firewall-live-probe";

/// Execute one installed Linux utility, preserving its actual failure output.
fn command(program: &str, args: &[&str]) -> Result<String> {
    // PID 1 mounts /dev itself. Inherit its already-open console instead of
    // Command::output's default attempt to open a not-yet-existing /dev/null.
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::inherit())
        .output()
        .with_context(|| format!("spawn {program} {args:?}"))?;
    ensure!(output.status.success(), "{program} {args:?}: {output:?}");
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// A successful echo requires both directions through the real NAT mapping.
fn tcp(port: u16) -> Result<()> {
    let address: SocketAddr = format!("{REMOTE}:{port}").parse()?;
    let mut socket = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    socket.write_all(MESSAGE)?;
    let mut bytes = [0; MESSAGE.len()];
    socket.read_exact(&mut bytes)?;
    ensure!(bytes == MESSAGE, "TCP response changed");
    Ok(())
}

/// Test the Linux UDP path, optionally using an intentionally forged source.
fn udp(source: &str, port: u16) -> Result<()> {
    let socket = UdpSocket::bind((source, 0))?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    let message = if source == "10.137.0.11" {
        b"spoofed-source".as_slice()
    } else {
        MESSAGE
    };
    socket.send_to(message, (REMOTE, port))?;
    let mut bytes = [0; 64];
    let (length, _) = socket.recv_from(&mut bytes)?;
    ensure!(&bytes[..length] == message, "UDP response changed");
    Ok(())
}

/// Wait for the controller's policy update using an independently allowed flow.
fn phase() -> Result<String> {
    let address: SocketAddr = format!("{REMOTE}:18082").parse()?;
    let mut socket = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut phase = String::new();
    socket.read_to_string(&mut phase)?;
    Ok(phase)
}

/// Configure one static Linux frontend and run its distinct client role.
fn run() -> Result<()> {
    for (source, target, kind) in [
        ("proc", "/proc", "proc"),
        ("sysfs", "/sys", "sysfs"),
        ("devtmpfs", "/dev", "devtmpfs"),
    ] {
        fs::create_dir_all(target)?;
        command("/bin/mount", &["-t", kind, source, target])?;
    }
    let line = fs::read_to_string("/proc/cmdline")?;
    let role = line
        .split_whitespace()
        .find_map(|value| value.strip_prefix("firewall.client="))
        .context("missing client role")?;
    ensure!(matches!(role, "a" | "b"), "invalid client role");
    let ip = if role == "a" {
        "10.137.0.10"
    } else {
        "10.137.0.11"
    };
    command("/sbin/modprobe", &["xen-netfront"])?;
    let deadline = Instant::now() + Duration::from_secs(80);
    while !std::path::Path::new("/sys/class/net/eth0").exists() {
        ensure!(Instant::now() < deadline, "Linux frontend never appeared");
        thread::sleep(Duration::from_millis(50));
    }
    command("/sbin/ip", &["link", "set", "lo", "up"])?;
    command("/sbin/ip", &["link", "set", "eth0", "up"])?;
    command(
        "/sbin/ip",
        &["address", "add", &format!("{ip}/32"), "dev", "eth0"],
    )?;
    command("/sbin/ip", &["route", "add", "10.137.0.1", "dev", "eth0"])?;
    command(
        "/sbin/ip",
        &["route", "add", "default", "via", "10.137.0.1"],
    )?;
    while tcp(18080).is_err() {
        ensure!(
            Instant::now() < deadline,
            "allowed TCP never became available"
        );
        thread::sleep(Duration::from_millis(100));
    }
    if role == "b" {
        let server = TcpListener::bind((ip, 18080))?;
        println!("FW_CLIENT_B_READY");
        // Its listener makes A's isolation check meaningful. The controller owns
        // this guest's finite lifetime and destroys it after the result is read.
        server.set_nonblocking(true)?;
        while Instant::now() < deadline {
            if let Ok((mut socket, _)) = server.accept() {
                eprintln!("FW_CLIENT_B_ISOLATION_BREACH");
                let _ = socket.write_all(MESSAGE);
            }
            thread::sleep(Duration::from_millis(10));
        }
        return Ok(());
    }
    let lookup = command(
        "/bin/nslookup",
        &["-type=A", "allowed.airlock.test", "10.139.1.1"],
    )?;
    ensure!(
        lookup.contains(REMOTE),
        "DNS redirection returned no expected address: {lookup}"
    );
    udp(ip, 19090)?;
    command("/bin/ping", &["-c", "1", "-W", "2", REMOTE])?;
    ensure!(tcp(18081).is_err(), "forbidden TCP reached a live listener");
    ensure!(
        udp(ip, 19091).is_err(),
        "forbidden UDP reached a live listener"
    );
    let sibling: SocketAddr = "10.137.0.11:18080".parse()?;
    ensure!(
        TcpStream::connect_timeout(&sibling, Duration::from_secs(2)).is_err(),
        "cross-client connection escaped isolation"
    );
    command(
        "/sbin/ip",
        &["address", "add", "10.137.0.11/32", "dev", "eth0"],
    )?;
    ensure!(
        udp("10.137.0.11", 19090).is_err(),
        "other client's forged source was accepted"
    );
    command(
        "/sbin/ip",
        &["address", "del", "10.137.0.11/32", "dev", "eth0"],
    )?;
    // Keep a live connection across tightening, rather than checking only a new SYN.
    let address: SocketAddr = format!("{REMOTE}:18080").parse()?;
    let mut existing = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    existing.set_read_timeout(Some(Duration::from_secs(2)))?;
    existing.write_all(MESSAGE)?;
    let mut reply = [0; MESSAGE.len()];
    existing.read_exact(&mut reply)?;
    println!("FW_CLIENT_A_BASELINE_PASS");
    while !phase().is_ok_and(|value| value == "tightened") {
        ensure!(
            Instant::now() < deadline,
            "tightened policy never became usable"
        );
        thread::sleep(Duration::from_millis(100));
    }
    let _ = existing.write_all(MESSAGE);
    ensure!(
        existing.read_exact(&mut reply).is_err(),
        "established TCP survived a deny update"
    );
    ensure!(tcp(18080).is_err(), "new TCP survived a deny update");
    udp(ip, 19090)?;
    println!(
        "FW_CLIENT_A_PASS dns=ok tcp=ok udp=ok icmp=ok deny=ok isolation=ok spoof=ok tightening=ok"
    );
    Ok(())
}

/// PID 1 reports failures on the captured Xen console and never silently succeeds.
fn main() {
    let result = run();
    if let Err(error) = &result {
        eprintln!("FW_CLIENT_FAIL error={error:#}");
    }
    let _ = Command::new("/bin/poweroff").arg("-f").status();
    if let Err(error) = result {
        bail_exit(error);
    }
}

/// Preserve an error outcome if the kernel did not complete poweroff.
fn bail_exit(error: anyhow::Error) -> ! {
    eprintln!("{error:#}");
    std::process::exit(1)
}
