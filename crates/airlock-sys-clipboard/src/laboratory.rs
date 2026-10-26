//! Controlled dom0 authority for disposable Xen tests, never a production policy.
//!
//! The entire endpoint is trusted: it may impersonate a caller and install policy
//! decisions. Only a channel provisioned specifically to dom0 may call `serve`.
//! A production VM must never be connected to this control/data multiplex.

use airlock_clipboard_core::{Action, Authorization, Caller, Clipboard, Error, Response};
use xen_transport::{Backend, Channel, Error as TransportError, Kind, MAX_PAYLOAD, Wire};

use crate::protocol::{Operation, Reply};

/// Explicit laboratory-only control operation, outside the ordinary request schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provision {
    /// Monotonic trusted decision ID.
    pub id: u64,
    /// Simulated stable VM identity authenticated by the controlled authority.
    pub principal: u64,
    /// Approved operation and exact source content generation for paste.
    pub action: Action,
    /// Lifetime from receipt, bounded again by the core policy.
    pub lifetime_ns: u64,
}

impl Wire for Provision {
    const KIND: Kind = Kind::Request;

    fn encode(&self, out: &mut [u8; MAX_PAYLOAD]) -> Result<usize, TransportError> {
        out[..3].copy_from_slice(&[1, 128, if self.action == Action::Copy { 0 } else { 1 }]);
        out[3..11].copy_from_slice(&self.id.to_le_bytes());
        out[11..19].copy_from_slice(&self.principal.to_le_bytes());
        out[19..27].copy_from_slice(&self.lifetime_ns.to_le_bytes());
        let content = match self.action {
            Action::Copy => 0,
            Action::Paste { content } => content,
        };
        out[27..35].copy_from_slice(&content.to_le_bytes());
        Ok(35)
    }

    fn decode(bytes: &[u8]) -> Result<Self, TransportError> {
        if bytes.len() != 35 || bytes[..2] != [1, 128] {
            return Err(TransportError::Malformed);
        }
        let number = |at| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
        let content = number(27);
        let action = match bytes[2] {
            0 if content == 0 => Action::Copy,
            1 => Action::Paste { content },
            _ => return Err(TransportError::Malformed),
        };
        Ok(Self {
            id: number(3),
            principal: number(11),
            action,
            lifetime_ns: number(19),
        })
    }
}

/// Serve one already authenticated lab channel, erasing state before teardown.
/// Uses PV-backed backend deadlines, blocking until data, expiry or liveness check.
/// Returns failures after cleanup; callers must not print a success marker on error.
pub fn serve<B: Backend>(channel: &mut Channel<B>, epoch: u64) -> Result<(), TransportError> {
    let mut clipboard = Clipboard::new();
    let mut caller = Caller {
        principal: 0,
        epoch,
    };
    let mut sequence = 0;
    let mut last_activity = channel.now_ns();
    let outcome = (|| {
        loop {
            let now = channel.now_ns();
            clipboard.tick(now).map_err(|_| TransportError::Corrupt)?;
            // Bounded liveness timeout also handles a peer that died without closing
            // its shared page. Normal idle waits still block in the Xen backend.
            let liveness = last_activity.saturating_add(10_000_000_000);
            if now >= liveness {
                println!("{{\"event\":\"clipboard_peer_timeout\"}}");
                break;
            }
            let deadline = clipboard.deadline().unwrap_or(liveness).min(liveness);
            let message = match channel.recv(deadline) {
                Ok(message) => message,
                Err(TransportError::Timeout) => continue,
                Err(TransportError::Closed) => {
                    println!("{{\"event\":\"clipboard_peer_closed\"}}");
                    break;
                }
                Err(TransportError::Malformed) => {
                    clipboard.clear();
                    channel.send_typed(
                        0,
                        &Reply(Err(Error::Malformed)),
                        channel.deadline_after(1_000_000_000),
                    )?;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let now = channel.now_ns();
            last_activity = now;
            let mut shutdown = false;
            let result = if message.id <= sequence {
                Err(Error::Replay)
            } else {
                sequence = message.id;
                match message.kind {
                    Kind::Close if message.payload().is_empty() => {
                        shutdown = true;
                        Ok(Response::Ok)
                    }
                    Kind::Request if message.payload().get(1) == Some(&128) => {
                        match Provision::decode(message.payload()) {
                            Ok(provision) => {
                                let identity = Caller {
                                    principal: provision.principal,
                                    epoch,
                                };
                                let expires =
                                    now.checked_add(provision.lifetime_ns).ok_or(Error::Bounds);
                                expires
                                    .and_then(|expires| {
                                        clipboard.authorize(
                                            now,
                                            Authorization {
                                                id: provision.id,
                                                caller: identity,
                                                action: provision.action,
                                                expires,
                                            },
                                        )
                                    })
                                    .map(|()| {
                                        caller = identity;
                                        Response::Ok
                                    })
                            }
                            Err(_) => {
                                clipboard.clear();
                                Err(Error::Malformed)
                            }
                        }
                    }
                    Kind::Request => match Operation::decode(message.payload()) {
                        Ok(operation) => clipboard.handle(now, caller, message.id, operation.0),
                        Err(_) => {
                            clipboard.clear();
                            Err(Error::Malformed)
                        }
                    },
                    _ => {
                        clipboard.clear();
                        Err(Error::Malformed)
                    }
                }
            };
            // Only numeric IDs and categories are observable, never content bytes.
            if let Err(error) = result {
                println!(
                    "{{\"event\":\"clipboard_rejected\",\"request\":{id},\"reason\":\"{error:?}\"}}",
                    id = message.id
                );
            }
            channel.send_typed(
                message.id,
                &Reply(result),
                channel.deadline_after(1_000_000_000),
            )?;
            if shutdown {
                break;
            }
        }
        Ok(())
    })();

    clipboard.clear();
    println!("{{\"event\":\"clipboard_erased\"}}");
    let closed = channel.close(channel.deadline_after(2_000_000_000));
    outcome.and(closed)
}
