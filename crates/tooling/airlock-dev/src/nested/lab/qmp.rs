//! Minimal QMP client for lifecycle operations on an explicitly named QEMU process.

use super::*;
use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
};

/// One negotiated QMP connection; event messages may arrive between command replies.
pub(super) struct Monitor {
    /// Bounded line reader over the owned QEMU monitor socket.
    input: BufReader<UnixStream>,
}

impl Monitor {
    /// Negotiate QMP and verify ownership by name before allowing any operation.
    pub(super) fn connect(path: &Path, name: &str) -> Result<Option<Self>> {
        let socket = match UnixStream::connect(path) {
            Ok(socket) => socket,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        };
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        socket.set_write_timeout(Some(Duration::from_secs(5)))?;
        let mut monitor = Self {
            input: BufReader::new(socket),
        };
        ensure!(
            monitor.message()?.get("QMP").is_some(),
            "invalid QMP greeting"
        );
        monitor.command("qmp_capabilities")?;
        ensure!(
            monitor.command("query-name")?["name"] == name,
            "QEMU monitor belongs to another instance"
        );
        Ok(Some(monitor))
    }

    /// Execute one argument-free lifecycle command, ignoring asynchronous event notifications.
    pub(super) fn command(&mut self, operation: &str) -> Result<Value> {
        serde_json::to_writer(self.input.get_mut(), &json!({"execute":operation}))?;
        self.input.get_mut().write_all(b"\n")?;
        loop {
            let reply = self.message()?;
            if let Some(error) = reply.get("error") {
                anyhow::bail!("QMP {operation}: {error}");
            }
            if let Some(result) = reply.get("return") {
                return Ok(result.clone());
            }
            ensure!(
                reply.get("event").is_some(),
                "unexpected QMP message: {reply}"
            );
        }
    }

    /// Bound monitor messages so an unexpected peer cannot grow the workstation's memory indefinitely.
    fn message(&mut self) -> Result<Value> {
        use std::io::Read;
        let mut message = String::new();
        let count = self.input.by_ref().take(65537).read_line(&mut message)?;
        ensure!(
            count > 0 && count <= 65536,
            "missing or oversized QMP reply"
        );
        Ok(serde_json::from_str(&message)?)
    }
}
