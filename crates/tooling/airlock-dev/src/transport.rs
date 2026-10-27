//! Text-only development PTY control; binary artifacts use a separate SSH stream.

use crate::support::{join, quote};
use airlock_nix_core::runtime::process::OwnedChild;
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fs::{OFlags, fcntl_getfl, fcntl_setfl},
};
use std::{
    fs::File,
    io::{Read, Write},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub(crate) fn target(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && !value.starts_with('-')
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"@._-:[]".contains(&b)),
        "invalid SSH target"
    );
    Ok(())
}

pub(crate) fn nonce() -> Result<String> {
    let mut bytes = [0; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

pub(crate) struct Session {
    // SSH process is killed and reaped if control fails or the caller returns early.
    child: OwnedChild,
    // Partial terminal output retained across token boundaries, bounded at 32 MiB.
    buffer: Vec<u8>,
}

impl Session {
    pub(crate) fn connect(host: &str) -> Result<Self> {
        target(host)?;

        let child = Command::new("ssh")
            .args(["-tt", "--", host, "airlock-dom0-shell"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let output = child.stdout.as_ref().context("missing SSH output")?;
        fcntl_setfl(output, fcntl_getfl(output)? | OFlags::NONBLOCK)?;
        let mut session = Self {
            child: OwnedChild(child),
            buffer: Vec::new(),
        };
        session.until(&["DEVELOPMENT: dom0 shell."], Duration::from_secs(60))?;
        let token = nonce()?;
        session.send(&format!(
            "stty -echo; printf '%s%s\\n' '{}' '{}'",
            &token[..16],
            &token[16..]
        ))?;
        session.until(&[&token], Duration::from_secs(30))?;

        let prompt = nonce()?;
        let ready = nonce()?;
        let script = format!("printf '%s\\n' {ready}; exec bash --noprofile --norc");
        session.send(&format!("sudo -S -p {prompt} bash -c {}", quote(&script)))?;
        for attempt in 0..4 {
            let (index, _) = session.until(&[&prompt, &ready], Duration::from_secs(60))?;
            if index == 1 {
                return Ok(session);
            }
            ensure!(attempt < 3, "dom0 sudo authentication failed");
            let answer = Command::new("systemd-ask-password")
                .args(["--timeout=0", "--echo=no", "dom0 sudo password:"])
                .stdin(File::open("/dev/tty")?)
                .output()?;
            ensure!(answer.status.success(), "sudo authentication cancelled");
            let password = String::from_utf8(answer.stdout)?;
            let password = password.trim_end_matches(['\n', '\r']);
            ensure!(
                !password.contains(['\n', '\r', '\0']),
                "unsupported password control character"
            );
            session.send(password)?;
        }
        anyhow::bail!("dom0 authentication did not complete")
    }

    fn send(&mut self, line: &str) -> Result<()> {
        let input = self.child.0.stdin.as_mut().context("SSH input closed")?;
        input.write_all(line.as_bytes())?;
        input.write_all(b"\n")?;
        input.flush()?;
        Ok(())
    }

    fn until(&mut self, tokens: &[&str], timeout: Duration) -> Result<(usize, Vec<u8>)> {
        let deadline = Instant::now() + timeout;
        loop {
            for (index, token) in tokens.iter().enumerate() {
                if let Some(position) = self
                    .buffer
                    .windows(token.len())
                    .position(|w| w == token.as_bytes())
                {
                    let preceding = self.buffer[..position].to_vec();
                    self.buffer.drain(..position + token.len());
                    return Ok((index, preceding));
                }
            }
            ensure!(
                Instant::now() < deadline,
                "dom0 control command timed out; reconnect and inspect status"
            );
            let output = self.child.0.stdout.as_mut().context("SSH output closed")?;
            let mut bytes = [0; 65536];
            match output.read(&mut bytes) {
                Ok(0) => anyhow::bail!("dom0 connection closed; reconnect and inspect status"),
                Ok(size) => {
                    ensure!(
                        self.buffer.len() + size <= 32 * 1024 * 1024,
                        "dom0 control output exceeded limit"
                    );
                    self.buffer.extend_from_slice(&bytes[..size]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    let delay = Timespec {
                        tv_sec: 0,
                        tv_nsec: 100_000_000,
                    };
                    poll(&mut [PollFd::new(output, PollFlags::IN)], Some(&delay))?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
    }

    pub(crate) fn run(&mut self, script: &str, timeout: Duration) -> Result<String> {
        let token = nonce()?;
        let payload = STANDARD.encode(format!("set -euo pipefail; {script}"));
        // A subshell scopes temporary files and its EXIT trap to one command.
        // Framing uses only coreutils already present in dom0, never Python.
        let line = format!(
            "(umask 077; d=$(mktemp -d); trap 'rm -rf -- \"$d\"' EXIT; printf %s {payload} | base64 -d | bash >\"$d/out\" 2>\"$d/err\"; r=$?; printf '\\n{token}%s:' \"$r\"; base64 -w0 <\"$d/out\"; printf ':'; base64 -w0 <\"$d/err\"; printf '{token}\\n')"
        );
        ensure!(
            line.len() <= 3500,
            "control message too large for PTY; use artifact transfer"
        );

        self.send(&line)?;
        self.until(&[&token], timeout)?;
        let (_, bytes) = self.until(&[&token], timeout)?;

        let frame = std::str::from_utf8(&bytes)?;
        let fields: Vec<_> = frame.split(':').collect();
        ensure!(fields.len() == 3, "invalid dom0 control frame");
        let code: u32 = fields[0].parse()?;
        let stdout = STANDARD.decode(fields[1])?;
        let stderr = STANDARD.decode(fields[2])?;
        ensure!(
            code == 0,
            "dom0 command failed ({code}): {}",
            String::from_utf8_lossy(&stderr)
                .chars()
                .take(4096)
                .collect::<String>()
        );

        Ok(String::from_utf8(stdout)?.trim().to_owned())
    }

    pub(crate) fn command(&mut self, words: &[&str]) -> Result<String> {
        self.run(&join(words), Duration::from_secs(900))
    }
}
