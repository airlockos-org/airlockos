//! Attribute X11 windows only when XRes identifies the installed Qubes GUI daemon as their owner.
//! Window properties alone never establish VM provenance.

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{fs, os::unix::fs::MetadataExt, path::PathBuf, sync::mpsc, time::Duration};
use x11rb::protocol::{
    res::{ClientIdMask, ClientIdSpec, ConnectionExt as _},
    xproto::{AtomEnum, ConnectionExt as _},
};

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum Kind {
    Unknown,
    Absent,
    Local,
    Vm,
}

#[derive(Serialize)]
struct Identity {
    // Whether the window is a verified forwarded VM, local client or unavailable identity.
    kind: Kind,
    // Plain label consumed by Shell; markup and arbitrary remote names are rejected.
    name: String,
    // Optional trusted 24-bit RGB value encoded for desktop presentation.
    color: Option<String>,
}

impl Identity {
    fn unknown() -> Self {
        Self {
            kind: Kind::Unknown,
            name: "Unknown VM".into(),
            color: None,
        }
    }
}

fn read(xid: u32, guid: PathBuf) -> Result<Identity> {
    let (connection, _) = x11rb::connect(None)?;
    connection.get_window_attributes(xid)?.reply()?;
    let names = [
        ("_QUBES_VMNAME", AtomEnum::STRING, 8),
        ("_QUBES_LABEL", AtomEnum::CARDINAL, 8),
        ("_QUBES_LABEL_COLOR", AtomEnum::CARDINAL, 32),
    ];
    let mut properties = Vec::new();
    let mut any_properties = false;
    for (name, expected, format) in names {
        let atom = connection.intern_atom(true, name.as_bytes())?.reply()?.atom;
        if atom == 0 {
            properties.push(None);
            continue;
        }
        let value = connection
            .get_property(false, xid, atom, AtomEnum::ANY, 0, 64)?
            .reply()?;
        if value.type_ == 0 {
            properties.push(None);
            continue;
        }
        any_properties = true;
        properties.push(
            (value.type_ == u32::from(expected)
                && value.format == format
                && value.bytes_after == 0)
                .then_some(value),
        );
    }
    let ids = connection
        .res_query_client_ids(&[ClientIdSpec {
            client: xid,
            mask: ClientIdMask::LOCAL_CLIENT_PID,
        }])?
        .reply()?;
    let mut peer = None;
    for value in ids.ids {
        if value.spec.mask.contains(ClientIdMask::LOCAL_CLIENT_PID) && value.value.len() == 1 {
            let pid = value.value[0];
            if pid != 0
                && fs::metadata(format!("/proc/{pid}"))?.uid() == rustix::process::getuid().as_raw()
            {
                peer = Some(fs::read_link(format!("/proc/{pid}/exe"))?);
            }
        }
    }
    if peer.as_ref() != Some(&guid) {
        return Ok(if !any_properties && peer.is_some() {
            Identity {
                kind: Kind::Local,
                name: "sys-gui".into(),
                color: None,
            }
        } else {
            Identity::unknown()
        });
    }
    if !any_properties {
        return Ok(Identity {
            kind: Kind::Absent,
            name: "Unknown VM".into(),
            color: None,
        });
    }
    let name = properties[0].as_ref().context("invalid VM name property")?;
    let name = std::str::from_utf8(&name.value)?;
    ensure!(
        !name.is_empty()
            && name.len() <= 31
            && name.as_bytes()[0].is_ascii_alphabetic()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
        "invalid window VM name"
    );
    let label = properties[1].as_ref().context("invalid label property")?;
    ensure!(
        label.value.len() == 1 && label.value[0] != 0,
        "invalid window label"
    );
    let color = properties[2]
        .as_ref()
        .and_then(|p| p.value32())
        .and_then(|mut values| {
            let value = values.next()?;
            (values.next().is_none() && value <= 0xffffff).then(|| format!("#{value:06x}"))
        });
    Ok(Identity {
        kind: Kind::Vm,
        name: name.into(),
        color,
    })
}

pub(crate) fn execute(xid: &str, guid: PathBuf) -> Result<()> {
    let xid = u32::from_str_radix(xid.trim_start_matches("0x"), 16)?;
    ensure!(xid > 0, "invalid XID");
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(read(xid, guid));
    });
    let identity = receiver
        .recv_timeout(Duration::from_secs(2))
        .ok()
        .and_then(Result::ok)
        .unwrap_or_else(Identity::unknown);
    println!("{}", serde_json::to_string(&identity)?);
    Ok(())
}
