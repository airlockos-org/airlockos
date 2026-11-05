//! Reuse xsettingsd, verifying its observable X11 state before reporting convergence.

use super::mapping::XValue;
use anyhow::{Context, Result, bail, ensure};
use std::collections::BTreeMap;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use x11rb::{
    connection::Connection,
    protocol::xproto::{ConnectionExt, EventMask},
    rust_connection::RustConnection,
};

/// One private upstream provider, with no permission to replace another XSettings owner.
pub(super) struct Provider {
    /// Local X11 connection for ownership and applied-property observation.
    connection: RustConnection,
    /// Default X screen already selected by DISPLAY.
    screen: usize,
    /// Standard manager selection for this screen.
    selection: u32,
    /// Standard property holding the effective XSettings values.
    property: u32,
    /// Private native configuration, atomically replaced before SIGHUP.
    config: PathBuf,
    /// GLib owns/reaps the process and preserves its identity across asynchronous exit.
    pub(super) process: Option<gio::Subprocess>,
    /// Selection window observed after our provider successfully claimed the empty selection.
    owner: Option<u32>,
}

impl Provider {
    /// Connect only to the guest's existing X server; create no replacement display or settings bus.
    pub(super) fn new(directory: &Path) -> Result<Self> {
        let (connection, screen) = x11rb::connect(None)?;
        let selection = connection
            .intern_atom(false, format!("_XSETTINGS_S{screen}").as_bytes())?
            .reply()?
            .atom;
        let property = connection
            .intern_atom(false, b"_XSETTINGS_SETTINGS")?
            .reply()?
            .atom;
        Ok(Self {
            connection,
            screen,
            selection,
            property,
            config: directory.join("xsettings.conf"),
            process: None,
            owner: None,
        })
    }

    /// Expose the local X event descriptor to the agent's event loop, without a periodic poll.
    pub(super) fn descriptor(&self) -> i32 {
        self.connection.stream().as_raw_fd()
    }

    /// Drain already available property/ownership events with a finite work budget.
    pub(super) fn drain(&self) -> Result<()> {
        for _ in 0..64 {
            if self.connection.poll_for_event()?.is_none() {
                break;
            }
        }
        Ok(())
    }

    /// Reap/forget an exited provider before attempting a fresh ownership check.
    pub(super) fn exited(&mut self) {
        self.process = None;
        self.owner = None;
    }

    /// Observe the current manager and decode only a bounded standard XSettings property.
    fn observed(&self) -> Result<(u32, BTreeMap<String, XValue>)> {
        let owner = self
            .connection
            .get_selection_owner(self.selection)?
            .reply()?
            .owner;
        if owner == 0 {
            return Ok((0, BTreeMap::new()));
        }
        let reply = self
            .connection
            .get_property(false, owner, self.property, self.property, 0, 16384)?
            .reply()?;
        ensure!(
            reply.bytes_after == 0,
            "XSettings property exceeds local bound"
        );
        if reply.value.is_empty() {
            return Ok((owner, BTreeMap::new()));
        }
        ensure!(reply.format == 8, "invalid XSettings property type");
        Ok((owner, decode(&reply.value)?))
    }

    /// Update our provider and wait at most one second for the actual X property to converge.
    /// Returns the newly started process so the caller can register its exit notification.
    pub(super) fn apply(
        &mut self,
        desired: &BTreeMap<String, XValue>,
    ) -> Result<Option<gio::Subprocess>> {
        let result = self.converge(desired);
        if result.is_err() {
            if let Some(process) = self.process.take() {
                process.force_exit();
            }
            self.owner = None;
        }
        result
    }

    /// Verify ownership and effective values; the caller retires our process on any failure.
    fn converge(&mut self, desired: &BTreeMap<String, XValue>) -> Result<Option<gio::Subprocess>> {
        let (owner, observed) = self.observed()?;
        if self.process.is_some() {
            ensure!(
                self.owner == Some(owner) && owner != 0,
                "XSettings ownership changed"
            );
            if observed == *desired {
                return Ok(None);
            }
        } else {
            ensure!(
                owner == 0,
                "another XSettings provider already owns this screen"
            );
        }

        let mut file = tempfile::NamedTempFile::new_in(self.config.parent().unwrap())?;
        file.write_all(render(desired)?.as_bytes())?;
        file.persist(&self.config)?;
        let mut started = None;
        if let Some(process) = &self.process {
            process.send_signal(signal_hook::consts::SIGHUP);
        } else {
            let executable = std::env::var_os("AIRLOCK_XSETTINGSD")
                .context("installed non-replacing xsettingsd is not configured")?;
            let screen = self.screen.to_string();
            let process = gio::Subprocess::newv(
                &[
                    executable.as_os_str(),
                    "-c".as_ref(),
                    self.config.as_os_str(),
                    "-s".as_ref(),
                    screen.as_ref(),
                ],
                gio::SubprocessFlags::STDOUT_SILENCE,
            )?;
            self.process = Some(process.clone());
            started = Some(process);
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let (owner, observed) = self.observed()?;
            if owner != 0 && observed == *desired {
                if self.owner.is_none() {
                    self.connection
                        .change_window_attributes(
                            owner,
                            &x11rb::protocol::xproto::ChangeWindowAttributesAux::new().event_mask(
                                EventMask::PROPERTY_CHANGE | EventMask::STRUCTURE_NOTIFY,
                            ),
                        )?
                        .check()?;
                    self.connection.flush()?;
                    self.owner = Some(owner);
                }
                ensure!(
                    self.owner == Some(owner),
                    "XSettings owner changed during reload"
                );
                return Ok(started);
            }
            if Instant::now() >= deadline {
                // Retire an unverified process; never treat writing a config as successful application.
                if let Some(process) = self.process.take() {
                    process.force_exit();
                }
                self.owner = None;
                bail!("XSettings provider did not converge within its startup/reload budget");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Provider {
    fn drop(&mut self) {
        if let Some(process) = &self.process {
            process.force_exit();
        }
        let _ = std::fs::remove_file(&self.config);
    }
}

/// Escape native string syntax; never concatenate a value into shell syntax.
pub(super) fn render(values: &BTreeMap<String, XValue>) -> Result<String> {
    let mut output = String::new();
    for (name, value) in values {
        let value = match value {
            XValue::Integer(value) => value.to_string(),
            XValue::Text(value) => {
                ensure!(
                    !value.chars().any(char::is_control),
                    "control character in XSettings value"
                );
                format!(
                    "\"{value}\"",
                    value = value.replace('\\', "\\\\").replace('"', "\\\"")
                )
            }
        };
        output.push_str(&format!("{name} {value}\n"));
    }
    Ok(output)
}

/// Decode the upstream wire property for confirmation, not as another preference authority.
fn decode(bytes: &[u8]) -> Result<BTreeMap<String, XValue>> {
    ensure!(
        bytes.len() >= 12 && matches!(bytes[0], 0 | 1),
        "invalid XSettings header"
    );
    let little = bytes[0] == 0;
    let number = |value: &[u8]| -> u32 {
        let value: [u8; 4] = value.try_into().unwrap();
        if little {
            u32::from_le_bytes(value)
        } else {
            u32::from_be_bytes(value)
        }
    };
    let count = number(&bytes[8..12]);
    ensure!(count <= 256, "too many XSettings entries");
    let mut cursor = 12;
    let mut values = BTreeMap::new();
    for _ in 0..count {
        let header = take(bytes, &mut cursor, 4)?;
        let kind = header[0];
        let length = if little {
            u16::from_le_bytes([header[2], header[3]])
        } else {
            u16::from_be_bytes([header[2], header[3]])
        } as usize;
        let name = std::str::from_utf8(take(bytes, &mut cursor, length)?)?.to_owned();
        cursor = (cursor + 3) & !3;
        take(bytes, &mut cursor, 4)?; // last-change serial
        let value = match kind {
            0 => XValue::Integer(number(take(bytes, &mut cursor, 4)?) as i32),
            1 => {
                let length = number(take(bytes, &mut cursor, 4)?) as usize;
                let text = std::str::from_utf8(take(bytes, &mut cursor, length)?)?.to_owned();
                cursor = (cursor + 3) & !3;
                XValue::Text(text)
            }
            _ => bail!("unexpected XSettings value type"),
        };
        ensure!(
            values.insert(name, value).is_none(),
            "duplicate XSettings name"
        );
    }
    ensure!(cursor == bytes.len(), "trailing XSettings data");
    Ok(values)
}

/// Advance a bounded property cursor, rejecting truncated or overflowing lengths.
fn take<'a>(bytes: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8]> {
    let end = cursor
        .checked_add(length)
        .context("XSettings length overflow")?;
    let value = bytes
        .get(*cursor..end)
        .context("truncated XSettings property")?;
    *cursor = end;
    Ok(value)
}
