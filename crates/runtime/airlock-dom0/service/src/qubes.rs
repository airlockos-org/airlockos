//! Narrow calls to Qubes' existing local admin API for persistent-volume operations.
//! Dom0 remains the caller; this module introduces no RPC service or guest authority.

pub(crate) mod pci;

use crate::model::BootId;
use airlock_nix_core::identity::{GuestName, VmName};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::Shutdown,
    os::unix::net::UnixStream,
    time::Duration,
};

pub use airlock_machine_core::model::Volume;

/// VM and volume identity retained before overwriting a replacement's private disk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateIdentity {
    /// Registered Qubes VM whose private data is involved.
    pub domain: GuestName,
    /// Qubes registration UUID, detecting VM replacement under the same name.
    pub uuid: BootId,
    /// Pool holding the independent private disk.
    pub pool: String,
    /// Private-volume identifier within that pool.
    pub vid: String,
}

fn call(domain: &VmName, method: &'static str, argument: &str, payload: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        argument.is_ascii() && argument.bytes().all(|b| b.is_ascii_graphic())
            || argument.is_empty(),
        "invalid Qubes admin argument"
    );
    let mut stream = UnixStream::connect("/var/run/qubesd.sock")?;
    stream.set_read_timeout(Some(Duration::from_secs(300)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    stream.write_all(format!("{method}+{argument} dom0 name {domain}\0").as_bytes())?;
    stream.write_all(payload)?;
    stream.shutdown(Shutdown::Write)?;
    let mut response = Vec::new();
    stream
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut response)?;
    ensure!(
        response.len() <= 4 * 1024 * 1024,
        "Qubes admin reply exceeds limit"
    );
    ensure!(
        response.starts_with(b"0\0"),
        "Qubes admin call {method} failed: {}",
        String::from_utf8_lossy(&response).replace('\0', " ")
    );
    Ok(response[2..].to_vec())
}

/// Narrow local setup exception: labels and read-only dom0 PCI inventory, never volume cloning.
pub(crate) fn setup_dom0(method: &'static str, argument: &str, payload: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        matches!(
            method,
            "admin.label.List"
                | "admin.label.Get"
                | "admin.label.Create"
                | "admin.vm.device.pci.Available"
        ),
        "unsupported dom0 setup API"
    );
    call(&"dom0".parse()?, method, argument, payload)
}

pub fn volume(domain: &GuestName, name: &str) -> Result<(Volume, u64)> {
    let bytes = call(&domain.as_str().parse()?, "admin.vm.volume.Info", name, &[])?;
    let mut values = BTreeMap::new();
    for line in std::str::from_utf8(&bytes)?.lines() {
        let (k, v) = line.split_once('=').context("invalid Qubes volume info")?;
        ensure!(
            values.insert(k, v).is_none(),
            "duplicate Qubes volume field"
        );
    }
    let text = |key| {
        values
            .get(key)
            .copied()
            .context("missing Qubes volume field")
    };
    let boolean = |key| -> Result<bool> {
        match text(key)? {
            "True" => Ok(true),
            "False" => Ok(false),
            _ => anyhow::bail!("invalid Qubes volume boolean"),
        }
    };
    let source = text("source")?;
    Ok((
        Volume {
            pool: text("pool")?.into(),
            vid: text("vid")?.into(),
            source: if source.is_empty() {
                None
            } else {
                Some(source.into())
            },
            rw: boolean("rw")?,
            save_on_stop: boolean("save_on_stop")?,
            snap_on_start: boolean("snap_on_start")?,
        },
        text("size")?.parse()?,
    ))
}

pub fn volumes(domain: &GuestName) -> Result<BTreeMap<String, Volume>> {
    let bytes = call(&domain.as_str().parse()?, "admin.vm.volume.List", "", &[])?;
    std::str::from_utf8(&bytes)?
        .lines()
        .map(|name| Ok((name.to_owned(), volume(domain, name)?.0)))
        .collect()
}

pub(crate) fn clone_private(request: airlock_deployment_core::copy::CopyRequest<'_>) -> Result<()> {
    let source = request.source();
    let target = request.target();
    let token = call(
        &source.parse()?,
        "admin.vm.volume.CloneFrom",
        "private",
        &[],
    )?;
    ensure!(
        !token.is_empty() && token.len() <= 65536,
        "invalid Qubes volume clone token"
    );
    call(
        &target.parse()?,
        "admin.vm.volume.CloneTo",
        "private",
        &token,
    )?;
    Ok(())
}

/// Decode Qubes' quoted device properties, including apostrophes in human descriptions.
pub(crate) fn properties(mut text: &str) -> Result<BTreeMap<String, String>> {
    let mut fields = BTreeMap::new();
    while !text.trim().is_empty() {
        text = text.trim_start();
        let (key, rest) = text
            .split_once("='")
            .context("invalid Qubes device property")?;
        ensure!(
            !key.is_empty() && key.bytes().all(|b| b.is_ascii_graphic()),
            "invalid device property key"
        );
        let mut value = String::new();
        let mut chars = rest.char_indices().peekable();
        let mut end = None;
        while let Some((index, ch)) = chars.next() {
            if ch == '\\' && chars.peek().is_some_and(|(_, next)| *next == '\'') {
                chars.next();
                value.push('\'');
            } else if ch == '\'' {
                end = Some(index + 1);
                break;
            } else {
                ensure!(
                    ch.is_ascii() && !ch.is_ascii_control(),
                    "invalid device property value"
                );
                value.push(ch);
            }
        }
        let end = end.context("unterminated Qubes device property")?;
        ensure!(
            fields.insert(key.to_owned(), value).is_none(),
            "duplicate device property"
        );
        text = &rest[end..];
        ensure!(
            text.is_empty() || text.starts_with(' '),
            "invalid device property separator"
        );
    }
    Ok(fields)
}
