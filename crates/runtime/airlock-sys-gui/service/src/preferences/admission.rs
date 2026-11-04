//! Fixed-size admission slots, acquired before touching guest input or starting a sandbox.

use super::feed;
use airlock_nix_core::identity::GuestName;
use anyhow::{Result, bail};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

/// One active exporter per authenticated Qubes source and at most this many in total.
const SLOTS: usize = 64;

/// Claim a bounded slot under a short nonblocking admission lock.
///
/// Slot files persist, but there are only 64. A crashed exporter releases its
/// kernel lock; its stale identity is ignored and overwritten by the next owner.
/// No guest bytes supply the caller identity: QREXEC_REMOTE_DOMAIN is supplied by
/// the Qubes agent after policy authorization. This is resource control, not policy.
pub(super) fn acquire(root: &Path, caller: &GuestName) -> Result<File> {
    let directory = root.join("admission");
    feed::private_directory(&directory)?;
    let guard = feed::lock_file(&directory.join("guard"))?;
    guard.try_lock()?;
    let mut available = None;
    for index in 0..SLOTS {
        let mut slot = feed::lock_file(&directory.join(format!("slot-{index}")))?;
        match slot.try_lock() {
            Ok(()) => {
                if available.is_none() {
                    available = Some(slot);
                }
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                let mut name = String::new();
                (&mut slot).take(64).read_to_string(&mut name)?;
                if name == caller.as_str() {
                    bail!("preferences subscription already active for caller");
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    let mut slot =
        available.ok_or_else(|| anyhow::anyhow!("preferences subscriber limit reached"))?;
    slot.seek(SeekFrom::Start(0))?;
    slot.set_len(0)?;
    slot.write_all(caller.as_str().as_bytes())?;
    Ok(slot)
}
