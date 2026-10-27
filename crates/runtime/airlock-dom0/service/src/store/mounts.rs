//! Recursive cleanup must never enter a kernel mount left by interrupted boot work.
//! Read the current mount namespace before deleting any part of a cleanup tree.

use anyhow::{Context, Result, ensure};
use std::{ffi::OsString, os::unix::ffi::OsStringExt, path::Path};

pub(super) fn ensure_unmounted(path: &Path) -> Result<()> {
    let table = std::fs::read("/proc/self/mountinfo")?;
    for line in table
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let encoded = line
            .split(|byte| *byte == b' ')
            .nth(4)
            .context("invalid kernel mount record")?;
        let mut decoded = Vec::with_capacity(encoded.len());
        let mut offset = 0;
        while offset < encoded.len() {
            if encoded[offset] == b'\\' {
                let escape = encoded
                    .get(offset + 1..offset + 4)
                    .context("truncated kernel mount escape")?;
                ensure!(
                    escape.iter().all(|b| (b'0'..=b'7').contains(b)),
                    "invalid kernel mount escape"
                );
                let byte = (escape[0] - b'0') as u16 * 64
                    + (escape[1] - b'0') as u16 * 8
                    + (escape[2] - b'0') as u16;
                decoded.push(u8::try_from(byte)?);
                offset += 4;
            } else {
                decoded.push(encoded[offset]);
                offset += 1;
            }
        }

        let mount = std::path::PathBuf::from(OsString::from_vec(decoded));
        ensure!(
            !mount.starts_with(path),
            "refusing cleanup of mounted path {}",
            mount.display()
        );
    }
    Ok(())
}
